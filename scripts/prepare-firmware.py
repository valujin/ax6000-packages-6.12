#!/usr/bin/env python3
"""Prepare a pinned AX6000 stock-layout firmware build and export its actual ABI."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

import prepare
import no_asu
import mediatek_mesh
import firmware_layouts
from publish import read_control


def sibling_module(name):
    """Load opt-in helpers from this recipe, even with importlib-based callers."""
    prepare.require(name in {"asu_client", "imagebuilder", "monitor", "package_format", "apk_world"}, "unsupported native helper")
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("ax6000_native_" + name, path)
    prepare.require(spec is not None and spec.loader is not None, "native helper unavailable: " + name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def asu_policy(profile):
    if "asu" not in profile:
        return None
    helper = sibling_module("asu_client")
    policy = helper.policy(profile)
    expected = "612-" + profile["channel"] if profile.get("channel") else "66"
    prepare.require(policy["cohort"] == expected, "ASU cohort differs from source firmware channel")
    required = set(helper.REQUIRED_PACKAGES)
    prepare.require(required <= set(profile.get("packages", []))
                    and required <= set(profile.get("image_packages", [])),
                    "ASU client packages must be requested and installed in the image")
    return policy


def asu_symbols(profile):
    policy = asu_policy(profile)
    if policy is None:
        return {}
    values = {"IB": "y", "IB_STANDALONE": "y", "SIGNATURE_CHECK": "y"}
    # 6.6 BUILDBOT overrides standalone and silently drops most native packages.
    if policy["cohort"] == "66":
        values["BUILDBOT"] = "n"
        values.update({"PACKAGE_opkg": "y", "USE_APK": "n"})
        values.update({"PACKAGE_" + name: "n" for name in ("apk", "apk-mbedtls", "apk-openssl")})
    return values


def verify_asu(profile, source):
    if asu_policy(profile) is None:
        return
    config = (source / ".config").read_text()
    for symbol, value in asu_symbols(profile).items():
        active = re.findall(r"^CONFIG_" + re.escape(symbol) + r"=(.+)$", config, re.M)
        prepare.require(active == [value] if value != "n" else not active,
                        f"ASU configuration requires {symbol}={value}")
    sibling_module("asu_client").configure(profile, source, check_only=True)


def native_seed(profile):
    """Pre-build seed: source profile, recipe fingerprint and fixed contract; no SDK cycle.

    Canonical UTF-8 JSON uses sorted keys and compact separators. Only asu.seed
    is omitted. This is called on source profiles while SDK and kernel ABI are
    null; monitor.recipe_digest binds scripts, workflows and ASU assets. The
    generated profile later binds the seed to actual SDK/IB identities.
    """
    inputs = copy.deepcopy(profile)
    inputs["asu"].pop("seed", None)
    payload = {"recipe_contract": "ax6000-native-asu-v1", "source_profile": inputs,
               "recipe_sha256": sibling_module("monitor").recipe_digest()}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode("utf-8")).hexdigest()


def firmware_bank_assets(archive):
    """The SDK carries images, never the separately exported native ImageBuilder."""
    return [asset for asset in sorted(archive.parent.iterdir())
            if asset.is_file() and asset != archive and not asset.name.endswith(".partial")
            and asset.name not in {"sha256sums", "SHA256SUMS"}
            and "imagebuilder" not in asset.name.lower()]


def firmware_asset_url(profile, filename):
    if profile.get("channel") is not None:
        return firmware_layouts.firmware_release_url(profile, filename)
    publication = profile.get("publication", {})
    prepare.require(publication.get("repository") == "valujin/ax6000-packages"
                    and publication.get("firmware_assets") == "github-release",
                    "ASU firmware requires the approved immutable Release repository")
    build_id = profile.get("build_id", "")
    prepare.require(isinstance(build_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,180}", build_id),
                    "invalid ASU firmware build ID")
    prepare.require(Path(filename).name == filename and filename not in {"", ".", ".."}, "invalid firmware asset name")
    return f"https://github.com/valujin/ax6000-packages/releases/download/firmware-{build_id}/{filename}"


def export_imagebuilder(generated, source, helper=None):
    if asu_policy(generated) is None:
        return
    target = source / "bin/targets/mediatek/filogic"
    archives = sorted(path for path in target.iterdir()
                      if "imagebuilder" in path.name.lower() and ".tar" in path.name.lower())
    prepare.require(len(archives) == 1, "native ASU build must produce exactly one ImageBuilder archive")
    archive = archives[0]
    prepare.require(archive.is_file() and not archive.is_symlink()
                    and archive.resolve().is_relative_to(source.resolve())
                    and not any(parent.is_symlink() for parent in archive.parents
                                if parent != source and parent.is_relative_to(source)),
                    "native ImageBuilder archive must be a regular source file")
    prepare.require(re.fullmatch(r"immortalwrt-imagebuilder(?:-[A-Za-z0-9_.+-]+)?-mediatek-filogic\.Linux-x86_64\.tar\.(?:xz|gz|zst)", archive.name),
                    "unrecognized native ImageBuilder archive filename")
    url = firmware_asset_url(generated, archive.name)
    helper = helper or sibling_module("imagebuilder")
    apk = generated.get("package_manager", "opkg") == "apk"
    extra = {"public_apk_key": Path(__file__).resolve().parents[1] / "keys/repository-apk.pem",
             "apk": source / "staging_dir/host/bin/apk"} if apk else {}
    result = helper.export_archive(generated, source, archive,
                                   public_key=Path(__file__).resolve().parents[1] / "keys/repository.pub",
                                   signing_key=source / ("private-key.pem" if apk else "key-build"),
                                   native_public_key=source / ("public-key.pem" if apk else "key-build.pub"),
                                   usign=source / "staging_dir/host/bin/usign", normalizer=normalize_local_sdk, **extra)
    generated["imagebuilder"] = {"url": url,
                                 "sha256": result["sha256"], "size": result["size"]}
    helper.validate_artifact(target, generated)


def validate(profile, lock):
    prepare.require(isinstance(profile, dict) and profile.get("enabled") is True,
                    "source firmware profile must be enabled")
    source = profile.get("build_source")
    prepare.require(isinstance(source, dict), "build_source is required for a firmware build")
    defconfig = source.get("defconfig")
    prepare.require(isinstance(defconfig, str) and not PurePosixPath(defconfig).is_absolute()
                    and ".." not in PurePosixPath(defconfig).parts and bool(defconfig),
                    "build_source.defconfig must be a relative path inside pinned source")
    firmware_layouts.validate_devices(profile)
    firmware = profile.get("firmware", {})
    prepare.require((firmware.get("target"), firmware.get("subtarget"), firmware.get("architecture")) ==
                    ("mediatek", "filogic", "aarch64_cortex-a53"), "source firmware target must be mediatek/filogic AX6000")
    prepare.require(firmware.get("kernel_version") is None or prepare.KERNEL_PACKAGE.fullmatch(firmware.get("kernel_version", "")),
                    "new firmware kernel_version must be null until built, or its exact built ABI")
    # Reuse the strict pin and package validation without claiming an existing SDK/ABI.
    surrogate = copy.deepcopy(profile)
    surrogate["firmware"]["kernel_version"] = "0.0.0~00000000000000000000000000000000-r0"
    surrogate["sdk"] = {"url": "https://invalid.example/source-build-only.tar.xz", "sha256": "0" * 64}
    prepare.validate(surrogate, lock)
    prepare.require(not any(feed["name"] == "base" for feed in profile["feeds"]),
                    "full source builds supply base packages directly; omit the base feed")
    image = profile.get("image_packages", [])
    prepare.require(isinstance(image, list) and all(name in profile["packages"] for name in image),
                    "image_packages must be a subset of requested packages")
    if profile.get("channel") is not None:
        directory = Path(__file__).resolve().parents[1] / "patches/firmware-6.12" / profile["channel"]
        reviewed = json.loads((directory / "manifest.json").read_text())
        pins = prepare.feed_pins(profile, lock)
        for patch in reviewed["patches"]:
            if "feed_name" in patch:
                prepare.require(pins.get(patch["feed_name"]) == patch["feed_commit"],
                                f"source build {patch['feed_name']} pin differs from reviewed patch input")
    ssl_symbols(profile)
    policy = asu_policy(profile)
    if policy is not None and profile.get("sdk", {}).get("url") is None:
        prepare.require(policy["seed"] == native_seed(profile), "ASU source profile seed differs from its reviewed recipe inputs")
    return profile


def configure(profile, lock, source):
    validate(profile, lock)
    if profile.get("package_manager") == "apk":
        sibling_module("apk_world").configure_source(profile, source)
    repository_files(source, profile=profile)
    pins = prepare.feed_pins(profile, lock)
    (source / "feeds.conf").write_text("".join(
        f"src-git {feed['name']} {feed['url']}^{pins[feed['name']]}\n" for feed in profile["feeds"]))
    baseline = source / profile["build_source"]["defconfig"]
    prepare.require(baseline.is_file(), "pinned source does not contain the requested vendor defconfig")
    config = baseline.read_text()
    config = re.sub(r"^(?:# )?CONFIG_TARGET_(?:mediatek(?:_[A-Za-z0-9_-]+)?|DEVICE_[^= ]+|DEVICE_PACKAGES_[^= ]+|MULTI_PROFILE|PER_DEVICE_ROOTFS|ALL_PROFILES)(?:=.*| is not set)\n?", "", config, flags=re.M)
    config = re.sub(r"^(?:# )?CONFIG_(?:SDK|DEVEL|ALL_KMODS|ALL|ALL_NONSHARED|SIGNED_PACKAGES|SIGNATURE_CHECK)(?:=.*| is not set)\n?", "", config, flags=re.M)
    config += ("\nCONFIG_TARGET_mediatek=y\nCONFIG_TARGET_mediatek_filogic=y\n"
               "CONFIG_TARGET_MULTI_PROFILE=y\nCONFIG_TARGET_PER_DEVICE_ROOTFS=y\n"
               "# CONFIG_TARGET_ALL_PROFILES is not set\n"
               "CONFIG_TARGET_DEVICE_mediatek_filogic_DEVICE_xiaomi_redmi-router-ax6000-stock=y\n"
               'CONFIG_TARGET_DEVICE_PACKAGES_mediatek_filogic_DEVICE_xiaomi_redmi-router-ax6000-stock="-kmod-mt7915e -kmod-mt7986-firmware"\n'
               "CONFIG_ALL_KMODS=y\nCONFIG_DEVEL=y\nCONFIG_SDK=y\n"
               "# CONFIG_ALL is not set\n# CONFIG_ALL_NONSHARED is not set\n"
               "CONFIG_SIGNED_PACKAGES=y\nCONFIG_SIGNATURE_CHECK=y\n")
    values = ssl_symbols(profile)
    devices = firmware_layouts.validate_devices(profile)
    for device in devices:
        values["TARGET_DEVICE_mediatek_filogic_DEVICE_" + device] = "y"
        values["TARGET_DEVICE_PACKAGES_mediatek_filogic_DEVICE_" + device] = '"-kmod-mt7915e -kmod-mt7986-firmware"'
    values.update(source_symbols(profile))
    values.update(asu_symbols(profile))
    if profile.get("exclude_asu"):
        values.update(no_asu.symbols(config))
        no_asu.configure(profile, source)
    (source / ".config").write_text(set_symbols(config, values))
    mediatek_mesh.configure(profile, source, native=True)
    if asu_policy(profile) is not None:
        sibling_module("asu_client").configure(profile, source)


def source_symbols(profile):
    """Required 25.12 vendor image and opkg choices; never change kernel options."""
    if profile.get("channel") is None:
        return {}
    installed = {"kmod-mt_wifi", "kmod-conninfra", "kmod-warp", "kmod-mediatek_hnat",
                 "kmod-leds-ws2812b", "mtwifi-cfg-ucode", "iwinfo-ucode", "ucode-mod-iwinfo",
                 "ucode-mod-datconf", "ucode-mod-l1parser", "wifi-dats", "libiwinfo",
                 "luci-app-mtwifi-cfg"}
    apk = profile.get("package_manager", "opkg") == "apk"
    prepare.require(profile.get("package_manager", "opkg") in {"opkg", "apk"}, "unsupported native package manager")
    installed.update({"apk-openssl", "openwrt-keyring", "usign"} if apk else {"opkg"})
    disabled = {"iwinfo", "mtwifi-cfg", "apk", "apk-mbedtls"} | ({"opkg"} if apk else {"apk-openssl"})
    values = {"PACKAGE_" + name: "y" for name in installed}
    values.update({"PACKAGE_" + name: "n" for name in disabled})
    values.update(mediatek_mesh.symbols(profile))
    values.update({"WIFI_SCRIPTS_UCODE": "y", "USE_APK": "y" if apk else "n", "CLEAN_IPKG": "n",
                   "TARGET_ROOTFS_SQUASHFS": "y", "TARGET_ROOTFS_INITRAMFS": "y",
                   "TARGET_ROOTFS_INITRAMFS_SEPARATE": "y", "TARGET_INITRAMFS_COMPRESSION_XZ": "y"})
    for symbol in ("TARGET_ROOTFS_EXT4FS", "TARGET_ROOTFS_JFFS2", "TARGET_ROOTFS_EROFS", "TARGET_ROOTFS_TARGZ",
                   "TARGET_ROOTFS_CPIOGZ", "TARGET_INITRAMFS_COMPRESSION_NONE", "TARGET_INITRAMFS_COMPRESSION_GZIP",
                   "TARGET_INITRAMFS_COMPRESSION_BZIP2", "TARGET_INITRAMFS_COMPRESSION_LZMA",
                   "TARGET_INITRAMFS_COMPRESSION_LZO", "TARGET_INITRAMFS_COMPRESSION_LZ4", "TARGET_INITRAMFS_COMPRESSION_ZSTD"):
        values[symbol] = "n"
    return values


def apk_repository_files(profile):
    """Tag public userspace feeds; native world pins protect the installed stack."""
    firmware_layouts.validate_devices(profile)
    prepare.require(sibling_module("package_format").manager(profile) == "apk", "APK overlay requires its explicit cohort")
    root = Path(__file__).resolve().parents[1]
    public = (root / "keys/repository-apk.pem").read_bytes()
    prepare.require(hashlib.sha256(public).hexdigest() == profile.get("apk_key_sha256"),
                    "APK public key differs from reviewed source profile")
    prepare.require(public.startswith(b"-----BEGIN PUBLIC KEY-----\n") and public.endswith(b"-----END PUBLIC KEY-----\n"),
                    "APK repository key must contain public PEM bytes only")
    installer = (root / "scripts/install-feed-apk.sh").read_bytes()
    default = b"base=${PACKAGE_REPOSITORY_URL:-https://valujin.github.io/ax6000-packages-6.12/channels/recommended}"
    prepare.require(installer.count(default) == 1, "bundled APK installer default URL differs from reviewed template")
    base = "https://valujin.github.io/ax6000-packages-6.12/channels/" + profile["channel"]
    installer = installer.replace(default, b"base=${PACKAGE_REPOSITORY_URL:-" + base.encode() + b"}")
    feeds = ("# Public userspace packages; explicitly select with @public.\n"
             "# Core, kernel and vendor packages stay bound to this image.\n")
    feeds += "".join("@public https://downloads.immortalwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/"
                     + feed + "/packages.adb\n" for feed in ("base", "luci", "packages", "routing", "telephony"))
    return {
        "files/etc/apk/repositories.d/distfeeds.list": feeds.encode(),
        "files/etc/apk/repositories.d/customfeeds.list":
            b"# The signed matching AX6000 APK repository is installed by ax6000-install-feed.\n",
        "files/etc/apk/keys/repository-apk.pem": public,
        "files/etc/ax6000/repository.pub": (root / "keys/repository.pub").read_bytes(),
        "files/usr/sbin/ax6000-install-feed": installer,
    }


def repository_files(source, check_only=False, profile=None):
    """Override moving official feeds; connect the verified feed with install-feed.sh."""
    if profile is not None and profile.get("package_manager") == "apk":
        files = apk_repository_files(profile)
    else:
        public = (Path(__file__).resolve().parents[1] / "keys/repository.pub").read_bytes()
        lines = public.decode("ascii").splitlines()
        prepare.require(len(lines) == 2 and lines[0].startswith("untrusted comment:"), "invalid repository public key")
        data = base64.b64decode(lines[1], validate=True)
        prepare.require(len(data) == 42 and data[:2] == b"Ed", "invalid repository public key")
        fingerprint = data[2:10].hex()
        installer = (Path(__file__).resolve().parent / "install-feed.sh").read_bytes()
        prepare.require(b"expected_fingerprint=" + fingerprint.encode() + b"\n" in installer,
                        "bundled installer signing key differs from repository key")
        if profile is not None and profile.get("channel") is not None:
            firmware_layouts.validate_devices(profile)
            default = b"base=${PACKAGE_REPOSITORY_URL:-https://valujin.github.io/ax6000-packages}"
            prepare.require(installer.count(default) == 1, "bundled installer default URL differs from reviewed template")
            base = profile["publication"]["site_url"].rstrip("/") + "/channels/" + profile["channel"]
            prepare.require(base == "https://valujin.github.io/ax6000-packages-6.12/channels/" + profile["channel"],
                            "untrusted channel installer URL")
            installer = installer.replace(default, b"base=${PACKAGE_REPOSITORY_URL:-" + base.encode() + b"}")
        files = {
            "files/etc/opkg/distfeeds.conf":
                b"# Packages for this firmware require its exact kernel ABI.\n"
                b"# Connect the signed matching repository with ax6000-install-feed.\n"
                b"# Moving official snapshot feeds are deliberately not configured.\n",
            "files/etc/opkg/keys/" + fingerprint: public,
            "files/usr/sbin/ax6000-install-feed": installer,
        }
    for relative, content in files.items():
        target = source / relative
        prepare.require(target.resolve().is_relative_to(source.resolve()) and not target.is_symlink()
                        and not any(parent.is_symlink() for parent in target.parents
                                    if parent != source and parent.is_relative_to(source)),
                        f"repository overlay is outside source or a symlink: {relative}")
        prepare.require(not target.exists() or (target.is_file() and target.read_bytes() == content),
                        f"repository overlay differs from reviewed defaults: {relative}")
        mode = 0o755 if relative == "files/usr/sbin/ax6000-install-feed" else 0o644
        prepare.require(not target.exists() or target.stat().st_mode & 0o777 == mode,
                        f"repository overlay permissions differ: {relative}")
        prepare.require(not check_only or target.is_file(), f"repository overlay is missing: {relative}")
    if not check_only:
        for relative, content in files.items():
            target = source / relative
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                target.chmod(0o755 if relative == "files/usr/sbin/ax6000-install-feed" else 0o644)


def set_symbols(config, values):
    config = re.sub(r"^(?:# )?CONFIG_([^= ]+)(?:=.*| is not set)\n?",
                    lambda match: "" if match.group(1) in values else match.group(0), config, flags=re.M)
    return config.rstrip() + "\n" + "".join(
        f"CONFIG_{symbol}={value}\n" if value != "n" else f"# CONFIG_{symbol} is not set\n"
        for symbol, value in sorted(values.items()))


def ssl_symbols(profile):
    """Install the collection's SSL provider; keep the alternative as an IPK."""
    image = set(profile.get("image_packages", []))
    collections = image & {"luci-ssl", "luci-ssl-openssl"}
    prepare.require(len(collections) <= 1, "image SSL collections luci-ssl and luci-ssl-openssl conflict")
    if not collections:
        return {}
    openssl = "luci-ssl-openssl" in collections
    return {"PACKAGE_libustream-openssl": "y" if openssl else "m",
            "PACKAGE_libustream-mbedtls": "m" if openssl else "y"}


def ssl_selection(profile, source):
    """Repair userspace provider selection without repeating kernel selection."""
    values = ssl_symbols(profile)
    if values:
        config = source / ".config"
        root = source.resolve()
        prepare.require(config.is_file() and not config.is_symlink()
                        and config.resolve().is_relative_to(root), "SSL configuration is missing or a symlink")
        updated = set_symbols(config.read_text(), values)
        inactive = next(symbol.removeprefix("PACKAGE_libustream-")
                        for symbol, value in values.items() if value == "m")
        staging = source / "staging_dir"
        prepare.require(not staging.is_symlink(), "SSL install stamp staging directory is a symlink")
        stale = []
        # A y recipe's image list reads every built variant. Demoting one variant
        # to m does not run prepare-package-install to clear its old y stamp.
        for info in sorted(staging.glob("target-*/pkginfo")):
            prepare.require(info.is_dir() and info.resolve().is_relative_to(root)
                            and not info.is_symlink()
                            and not any(parent.is_symlink() for parent in info.parents
                                        if parent != source and parent.is_relative_to(source)),
                            f"SSL install stamp directory is outside source or a symlink: {info}")
            stamp = info / f"ustream-ssl.{inactive}.install"
            for path in (stamp, stamp.with_name(stamp.name + ".flags")):
                if path.exists() or path.is_symlink():
                    prepare.require(path.is_file() and not path.is_symlink()
                                    and path.resolve().is_relative_to(root),
                                    f"SSL install stamp is not a regular source file: {path}")
                    if path == stamp:
                        prepare.require(path.read_bytes() == f"libustream-{inactive}\n".encode(),
                                        f"SSL install stamp has unexpected packages: {path}")
                    stale.append(path)
        # Complete preflight before changing either the config or cached metadata.
        for path in stale:
            path.unlink()
        config.write_text(updated)


def verify_ssl(profile, config):
    values = ssl_symbols(profile)
    providers = set(re.findall(r"^CONFIG_PACKAGE_libustream-(openssl|mbedtls|wolfssl)=y$", config, re.M))
    prepare.require(len(providers) <= 1, "multiple image SSL providers install /lib/libustream-ssl.so")
    for symbol, value in values.items():
        prepare.require(f"CONFIG_{symbol}={value}\n" in config,
                        f"SSL provider selection requires {symbol}={value}")


def package_only_stamps(profile, source):
    """Preflight exact recipe/variant image stamps; never touch package archives."""
    packages = prepare.package_only_packages(profile)
    if not packages:
        return []
    root = source.resolve()
    metadata = source / "tmp/.packageinfo"
    prepare.require(metadata.is_file() and not metadata.is_symlink()
                    and metadata.resolve().is_relative_to(root), "package_only metadata is missing or outside source")
    owners = {}
    recipe, name, variant = None, None, "default"
    def record():
        if name not in packages:
            return
        path = PurePosixPath(recipe or "")
        prepare.require(path.as_posix() == recipe and not path.is_absolute() and ".." not in path.parts
                        and path.name == "Makefile" and prepare.NAME.fullmatch(path.parent.name)
                        and prepare.NAME.fullmatch(variant), "package_only recipe/variant is unsafe")
        stamp = path.parent.name + "." + variant + ".install"
        prepare.require(not any(name in names for names in owners.values()), "package_only metadata has duplicate package owners")
        owners.setdefault(stamp, set()).add(name)
    for line in metadata.read_text().splitlines():
        if line.startswith("Source-Makefile:"):
            record(); recipe = line.split(":", 1)[1].strip(); name = None; variant = "default"
        elif line.startswith("Package:"):
            record(); name = line.split(":", 1)[1].strip(); variant = "default"
        elif line.startswith("Build-Variant:"):
            variant = line.split(":", 1)[1].strip() or "default"
    record()
    prepare.require(set().union(*owners.values()) == packages if owners else False,
                    "package_only requested package has no native recipe metadata")
    staging = source / "staging_dir"
    prepare.require(not staging.is_symlink(), "package_only staging directory is a symlink")
    stale = []
    for target in sorted(staging.glob("target-*")):
        prepare.require(target.is_dir() and not target.is_symlink() and target.resolve().is_relative_to(root),
                        "package_only target staging directory is outside source or a symlink")
        info = target / "pkginfo"
        if not info.exists() and not info.is_symlink():
            continue
        prepare.require(info.is_dir() and not info.is_symlink() and info.resolve().is_relative_to(root),
                        "package_only install stamp directory is outside source or a symlink")
        for filename, expected in sorted(owners.items()):
            stamp = info / filename
            for path in (stamp, stamp.with_name(stamp.name + ".flags")):
                if not path.exists() and not path.is_symlink():
                    continue
                prepare.require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root)
                                and path.stat().st_size <= 65536, "package_only install stamp is not a bounded regular source file")
                if path == stamp:
                    data = path.read_bytes()
                    lines = data.splitlines()
                    prepare.require(bool(lines) and data == b"\n".join(lines) + b"\n"
                                    and len(lines) == len(set(lines)) and set(lines) <= {p.encode() for p in expected},
                                    "package_only install stamp has unexpected package owners")
                stale.append(path)
    return stale


def package_only_selection(profile, source):
    packages = prepare.package_only_packages(profile)
    if not packages:
        return
    config = source / ".config"
    prepare.require(not source.is_symlink() and config.is_file() and not config.is_symlink()
                    and config.resolve().is_relative_to(source.resolve()), "package_only configuration is missing or a symlink")
    updated = set_symbols(config.read_text(), {"PACKAGE_" + name: "m" for name in packages})
    stale = package_only_stamps(profile, source)
    # All owners, paths and the replacement config pass preflight before mutation.
    for path in stale:
        path.unlink()
    config.write_text(updated)


def verify_package_only(profile, source):
    packages = prepare.package_only_packages(profile)
    if not packages:
        return
    config = (source / ".config").read_text()
    for name in packages:
        values = re.findall(r"^CONFIG_PACKAGE_" + re.escape(name) + r"=([my])$", config, re.M)
        prepare.require(values == ["m"], f"package_only requires PACKAGE_{name}=m after defconfig")
    prepare.require(not package_only_stamps(profile, source), "package_only has stale native image install stamps")


def apply_source_patch(source, spec, patch, check_only=False):
    """Apply only the reviewed source revision; an exact patched file is idempotent."""
    relative = Path(spec["path"])
    target = source / relative
    prepare.require(not relative.is_absolute() and ".." not in relative.parts
                    and target.resolve().is_relative_to(source.resolve())
                    and not target.is_symlink()
                    and not any(parent.is_symlink() for parent in target.parents
                                if parent != source and parent.is_relative_to(source)),
                    f"vendor patch target is absent or outside source: {spec['path']}")
    operation = spec.get("operation", "modify")
    prepare.require(operation in {"modify", "add"}, "vendor patch operation is unsupported")
    if operation == "add":
        prepare.require(spec["before_sha256"] is None, "new vendor patch requires a null before hash")
    else:
        prepare.require(target.is_file(), f"vendor patch target is absent or outside source: {spec['path']}")
    prepare.require(hashlib.sha256(patch.read_bytes()).hexdigest() == spec["sha256"],
                    f"vendor patch hash differs: {spec['patch']}")
    if target.exists():
        prepare.require(target.is_file(), f"vendor patch source hash differs: {spec['path']}")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if digest == spec["after_sha256"]:
            return
        prepare.require(operation == "modify" and digest == spec["before_sha256"],
                        f"vendor patch source hash differs: {spec['path']}")
    prepare.require(not check_only, f"required vendor patch is not applied: {spec['patch']}")
    command = ["git", "apply", "--whitespace=nowarn"]
    subprocess.run(command + ["--check", str(patch.resolve())], cwd=source, check=True)
    subprocess.run(command + [str(patch.resolve())], cwd=source, check=True)
    prepare.require(hashlib.sha256(target.read_bytes()).hexdigest() == spec["after_sha256"],
                    f"vendor patch produced an unexpected source hash: {spec['path']}")


def vendor_fixes(profile, source, check_only=False):
    directory = Path(__file__).resolve().parents[1] / "patches/firmware"
    if profile.get("channel") is not None:
        firmware_layouts.validate_devices(profile)
        directory = directory.parent / "firmware-6.12" / profile["channel"]
    manifest = json.loads((directory / "manifest.json").read_text())
    target = source / "target/linux/mediatek/Makefile"
    series = re.findall(r"^KERNEL_PATCHVER\s*:?=\s*(\S+)\s*$", target.read_text(), re.M)
    prepare.require(series == [manifest["kernel_series"]], "vendor patches require the reviewed kernel series " + manifest["kernel_series"])
    prepare.require(profile["firmware"]["commit"] == manifest["source_commit"],
                    "vendor patches require the reviewed firmware source commit")
    for spec in manifest["patches"]:
        if "feed_name" in spec:
            pins = [feed.get("commit") for feed in profile.get("feeds", [])
                    if feed.get("name") == spec["feed_name"]]
            prepare.require(pins == [spec["feed_commit"]],
                            f"vendor patch feed {spec['feed_name']} pin differs from the reviewed recipe")
    for spec in manifest["patches"]:
        apply_source_patch(source, spec, directory / spec["patch"], check_only=check_only)
    record = source / "firmware-source-patches.json"
    if check_only:
        prepare.require(record.is_file() and json.loads(record.read_text()) == manifest,
                        "vendor patch provenance is absent or differs from the reviewed patches")
    else:
        record.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        selection = source / "build-selection.json"
        if selection.is_file():
            report = json.loads(selection.read_text())
            report["source_patches"] = manifest["patches"]
            selection.write_text(json.dumps(report, indent=2) + "\n")
    return manifest["patches"]


def overrides(profile, lock, source):
    vendor_fixes(profile, source)
    prepare.apply_overrides(lock, source, profile)


def reset_cached_images(profile, source, receipt):
    """Remove only the stock factory outputs/catalog that an ignored copy could retain."""
    source = Path(source).absolute()
    prepare.require(source.is_dir() and source == source.resolve(), "image cache source has symlink ancestors")
    channel = profile.get("channel")
    prepare.require(channel in ("recommended", "latest"), "image cache cleanup requires a reviewed 6.12 channel")
    devices = firmware_layouts.validate_devices(profile)
    firmware = profile["firmware"]
    reviewed = json.loads((Path(__file__).resolve().parents[1] /
                           "patches/firmware-6.12" / channel / "manifest.json").read_text())
    prepare.require(profile.get("enabled") is True and isinstance(profile.get("build_source"), dict)
                    and firmware["commit"] == reviewed["source_commit"]
                    and devices.get("xiaomi_redmi-router-ax6000-stock") == "stock"
                    and firmware["architecture"] == "aarch64_cortex-a53"
                    and firmware["target"] == "mediatek" and firmware["subtarget"] == "filogic",
                    "image cache cleanup requires the reviewed stock source profile")
    actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    prepare.require(actual == firmware["commit"], "image cache source HEAD differs from pinned channel")
    prepare.require(receipt is not None, "--cleanup-receipt is required")
    receipt = Path(receipt).absolute()
    prepare.require(not receipt.resolve().is_relative_to(source), "cleanup receipt must be outside source")
    prepare.require(receipt.parent.is_dir() and receipt.parent == receipt.parent.resolve()
                    and not receipt.is_symlink(), "cleanup receipt has symlink ancestors or missing parent")
    name = "immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-stock-initramfs-factory.ubi"
    build = Path("build_dir/target-aarch64_cortex-a53_musl")
    relative = [Path("bin/targets/mediatek/filogic") / name,
                build / "linux-mediatek_filogic/tmp" / name,
                build / "json_info_files" / (name + ".json"),
                Path("bin/targets/mediatek/filogic/profiles.json")]
    files = {}
    targets = []
    for path in relative:
        target = source / path
        prepare.require(not any(parent.is_symlink() for parent in (target, *target.parents)),
                        f"image cache contains symlink: {path}")
        if not target.exists():
            continue
        prepare.require(target.is_file() and target.stat().st_size <= 128 * 1024**2,
                        f"unexpected image cache file: {path}")
        with target.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        files[path.as_posix()] = {"sha256": digest, "size": target.stat().st_size}
        targets.append(target)
    report = {"schema_version": 1, "operation": "reset-stock-factory-cache",
              "source_commit": firmware["commit"], "source_dir": str(source), "channel": channel,
              "devices": profile["firmware"]["devices"], "files": files}
    if receipt.exists():
        prepare.require(receipt.is_file() and receipt.stat().st_size <= 16384,
                        "unexpected cleanup receipt")
        previous = json.loads(receipt.read_text())
        prepare.require(isinstance(previous, dict)
                        and {k: previous.get(k) for k in report if k != "files"}
                        == {k: v for k, v in report.items() if k != "files"}
                        and isinstance(previous.get("files"), dict)
                        and set(previous["files"]) <= {p.as_posix() for p in relative}
                        and all(isinstance(item, dict) and set(item) == {"sha256", "size"}
                                and isinstance(item["sha256"], str) and prepare.SHA256.fullmatch(item["sha256"])
                                and type(item["size"]) is int and 0 <= item["size"] <= 128 * 1024**2
                                for item in previous["files"].values()),
                        "foreign cleanup receipt")
        prepare.require(not targets, "cleanup receipt already exists; use a fresh receipt for a new rebuild")
        return previous
    # Reserve and write the external receipt before deleting any source output.
    # A denied receipt write leaves every cached artifact intact.
    with receipt.open("x") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for target in targets:
        target.unlink()
    return report


def select(profile, source):
    available = prepare.available_packages(source)
    requested = set(profile["packages"])
    prepare.require(not requested - available,
                    "requested firmware packages absent from pinned feeds: " + ", ".join(sorted(requested - available)))
    config_path = source / ".config"
    config = config_path.read_text()
    # Enable only the reviewed device layouts; unrelated source profiles stay disabled.
    target_info = (source / "tmp/.config-target.in").read_text()
    devices = set(re.findall(r"^(?:menu)?config\s+(TARGET_DEVICE_\S+)", target_info, re.M))
    desired = {"TARGET_DEVICE_mediatek_filogic_DEVICE_" + device for device in firmware_layouts.validate_devices(profile)}
    prepare.require(desired <= devices, "pinned source is missing a requested AX6000 device layout")
    values = {device: ("y" if device in desired else "n") for device in devices}
    values.update({"SIGNED_PACKAGES": "y", "SIGNATURE_CHECK": "y"})
    values.update(prepare.luci_language_symbols(profile, source, "y"))
    baseline_y = set(re.findall(r"^CONFIG_PACKAGE_(.+)=y$", config, re.M))
    kmods = sorted(name for name in available if name.startswith("kmod-")) if profile.get("all_kmods", True) else []
    for name in sorted(requested | set(kmods)):
        values["PACKAGE_" + name] = "y" if name in baseline_y or name in profile.get("image_packages", []) else "m"
    required = source_symbols(profile)
    installed = {symbol.removeprefix("PACKAGE_") for symbol, value in required.items()
                 if symbol.startswith("PACKAGE_") and value == "y"}
    prepare.require(installed <= available, "pinned source is missing vendor/opkg packages: " + ", ".join(sorted(installed - available)))
    values.update(required)
    values.update(ssl_symbols(profile))
    values.update(asu_symbols(profile))
    values.update({"PACKAGE_" + name: "m" for name in prepare.package_only_packages(profile)})
    if profile.get("exclude_asu"):
        values.update(no_asu.symbols(config, available))
        no_asu.configure(profile, source)
    config_path.write_text(set_symbols(config, values))
    report = {"profile": profile["id"], "requested": sorted(requested), "candidate_kmods": kmods,
              "source_commit": profile["firmware"]["commit"], "device": profile["build_source"]["device"],
              "luci_languages": {name: "y" for name in profile.get("luci_languages", [])},
              "baseline_vendor_drivers": sorted(name for name in baseline_y if name in
                                                 {"kmod-mt_wifi", "kmod-conninfra", "kmod-warp", "kmod-mediatek_hnat"})}
    if profile.get("channel") is not None:
        report["channel"] = profile["channel"]
        report["devices"] = profile["firmware"]["devices"]
    patches = source / "firmware-source-patches.json"
    if patches.is_file():
        report["source_patches"] = json.loads(patches.read_text())["patches"]
    if profile.get("package_manager") == "apk":
        guard = sibling_module("apk_world")
        guard.configure_policy(profile, source)
        report["apk_world"] = {**guard.configure_source(profile, source, check_only=True),
                               "policy_sha256": hashlib.sha256((source / "ax6000-apk-world-policy.json").read_bytes()).hexdigest()}
    (source / "build-selection.json").write_text(json.dumps(report, indent=2) + "\n")


def verify(profile, source):
    repository_files(source, check_only=True, profile=profile)
    patches = vendor_fixes(profile, source, check_only=True)
    report = prepare.verify_selection(profile, source)
    prepare.require(report.get("source_patches") == patches, "selection report omits vendor patch provenance")
    config = (source / ".config").read_text()
    verify_ssl(profile, config)
    verify_package_only(profile, source)
    verify_asu(profile, source)
    if profile.get("exclude_asu"):
        no_asu.verify_config(config)
        no_asu.configure(profile, source, check_only=True)
    if profile.get("package_manager") == "apk":
        guard = sibling_module("apk_world")
        guard.configure_source(profile, source, check_only=True)
        guard.configure_policy(profile, source, check_only=True)
    enabled = set(re.findall(r"^CONFIG_TARGET_DEVICE_(.+)=y$", config, re.M))
    expected = {"mediatek_filogic_DEVICE_" + device for device in firmware_layouts.validate_devices(profile)}
    prepare.require(enabled == expected, "firmware selection includes another device or omits a requested AX6000 layout")
    if profile.get("channel") is not None:
        prepare.require(report.get("devices") == profile["firmware"]["devices"] and report.get("channel") == profile["channel"],
                        "selection report device/channel identity mismatch")
        for symbol, value in source_symbols(profile).items():
            if value == "y":
                prepare.require(f"CONFIG_{symbol}=y\n" in config, f"firmware configuration dropped {symbol}")
            else:
                prepare.require(not re.search(r"^CONFIG_" + re.escape(symbol) + r"=[my]$", config, re.M),
                                f"firmware configuration enabled incompatible {symbol}")
        for name in ("kmod-mt7915e", "kmod-mt7986-firmware"):
            prepare.require(f"CONFIG_PACKAGE_{name}=y\n" not in config, f"native WiFi package {name} was installed with vendor radio")
        for device in firmware_layouts.validate_devices(profile):
            expected_override = f'CONFIG_TARGET_DEVICE_PACKAGES_mediatek_filogic_DEVICE_{device}="-kmod-mt7915e -kmod-mt7986-firmware"'
            prepare.require(expected_override + "\n" in config, f"device WiFi exclusion dropped for {device}")
        for symbol in ("TARGET_MULTI_PROFILE", "TARGET_PER_DEVICE_ROOTFS"):
            prepare.require(f"CONFIG_{symbol}=y\n" in config, f"firmware configuration dropped {symbol}")
        prepare.require("CONFIG_TARGET_ALL_PROFILES=y\n" not in config, "all unrelated device profiles were enabled")
    for symbol in ("TARGET_mediatek", "TARGET_mediatek_filogic", "SDK", "DEVEL", "ALL_KMODS", "SIGNED_PACKAGES", "SIGNATURE_CHECK"):
        prepare.require(f"CONFIG_{symbol}=y\n" in config, f"firmware configuration dropped {symbol}")
    prepare.require('CONFIG_TARGET_ARCH_PACKAGES="aarch64_cortex-a53"' in config,
                    "firmware architecture does not match AX6000 profile")
    for name in report["baseline_vendor_drivers"]:
        prepare.require(f"CONFIG_PACKAGE_{name}=y\n" in config, f"vendor firmware driver {name} was removed from image")
    for name in profile.get("image_packages", []):
        prepare.require(f"CONFIG_PACKAGE_{name}=y\n" in config, f"required image package {name} dropped from firmware image")
    return report


def core_kmod_names(source):
    result = set()
    recipe = ""
    for line in (source / "tmp/.packageinfo").read_text().splitlines():
        if line.startswith("Source-Makefile:"):
            recipe = line.split(":", 1)[1].strip()
        elif line.startswith("Package:") and recipe.startswith("package/") and not recipe.startswith("package/feeds/"):
            name = line.split(":", 1)[1].strip()
            if name.startswith("kmod-"):
                result.add(name)
    return result


def dependency_groups(value, label):
    """Read opkg comma groups and alternatives, keeping version syntax intact."""
    if not value.strip():
        return []
    result = []
    for group in value.split(","):
        names = set()
        for alternative in group.split("|"):
            match = re.fullmatch(r"\s*([A-Za-z0-9][A-Za-z0-9_.+:\-]*)"
                                 r"(?:\s*\((?:>=|<=|>>|<<|!=|=|>|<)\s*[^\s()]+\))?\s*", alternative)
            prepare.require(match is not None, f"invalid {label}: {alternative!r}")
            names.add(match[1])
        result.append(names)
    return result


def runtime_dependency_closure(controls, roots):
    """Preserve built providers conservatively; final IPK controls are authoritative."""
    packages = {}
    providers = {}
    apk = any("APK-Name" in control for _, control in controls)
    def groups(value, label):
        return prepare.native_dependency_groups(value, label, apk=True) if apk else dependency_groups(value, label)
    for _, control in controls:
        name = control["Package"]
        prepare.require(name not in packages, f"duplicate built package in SDK dependency baseline: {name}")
        packages[name] = control
        provided = {name}
        for group in groups(control.get("Provides", ""), f"Provides for {name}"):
            provided.update(group)
        for virtual in provided:
            providers.setdefault(virtual, set()).add(name)
    closure, pending = set(), set(roots)
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        prepare.require(name in packages, f"missing built baseline package: {name}")
        closure.add(name)
        for group in groups(packages[name].get("Depends", ""), f"Depends for {name}"):
            candidates = set().union(*(providers.get(dependency, set()) for dependency in group))
            prepare.require(bool(candidates), f"built module baseline dependency unavailable: {name} -> "
                            + " | ".join(sorted(group)))
            pending.update(candidates - closure)
    return closure


def normalize_local_sdk(archive, destination, source):
    """Replace reviewed local builder links; downloaded SDK validation stays strict."""
    prepare.require(not destination.exists() and not destination.is_symlink(),
                    "normalized SDK destination already exists")
    same = ("which gzip realpath rsync bash egrep wget seq git diff file perl grep "
            "getopt unzip cp install stat g++").split()
    tools = {name: ("/usr/bin/" + name, "/usr/bin/" + name) for name in same}
    tools.update({"gcc": ("/usr/bin/cc", "/usr/bin/cc"),
                  "python": ("/usr/bin/python3.12", "/usr/bin/python3"),
                  "python3": ("/usr/bin/python3.12", "/usr/bin/python3"),
                  "awk": ("/usr/bin/gawk", "/usr/bin/gawk")})
    scripts = {"xxd": "xxdi.pl", "ldconfig": "noop.sh"}
    source = source.absolute()
    replacements = {}
    with tarfile.open(archive, "r:*") as original:
        members = original.getmembers()
        prepare.require(bool(members), "local SDK archive is empty")
        paths, roots = {}, set()
        for member in members:
            path = PurePosixPath(member.name)
            canonical = member.name.rstrip("/") if member.isdir() else member.name
            prepare.require(path.parts and not path.is_absolute() and ".." not in path.parts
                            and canonical == str(path), f"unsafe local SDK archive path: {member.name}")
            prepare.require(str(path) not in paths, f"duplicate local SDK archive path: {member.name}")
            prepare.require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                            f"unsupported local SDK archive member: {member.name}")
            paths[str(path)] = member
            roots.add(path.parts[0])
        prepare.require(len(roots) == 1, "local SDK archive needs exactly one top-level directory")
        for name, member in paths.items():
            path = PurePosixPath(name)
            for parent in path.parents:
                if str(parent) in paths:
                    prepare.require(paths[str(parent)].isdir(),
                                    f"local SDK archive parent is not a directory: {name}")
            if not (member.issym() or member.islnk()):
                continue
            if member.linkname.startswith("/"):
                prepare.require(member.issym() and path.parts[1:-1] == ("staging_dir", "host", "bin"),
                                f"unreviewed absolute local SDK link: {name}")
                tool = path.name
                if tool in tools:
                    expected, target = tools[tool]
                    prepare.require(member.linkname == expected, f"local SDK tool link target differs: {name}")
                    replacements[name] = (f'#!/bin/sh\nexec {target} "$@"\n'.encode(), 0o755)
                else:
                    prepare.require(tool in scripts, f"unreviewed absolute local SDK link: {name}")
                    script = source / "scripts" / scripts[tool]
                    prepare.require(member.linkname == str(script), f"local SDK script link target differs: {name}")
                    prepare.require(source.resolve() == source and not (source / "scripts").is_symlink()
                                    and not script.is_symlink() and script.is_file(),
                                    f"local SDK source script is not a regular pinned source file: {name}")
                    info = script.stat()
                    prepare.require(0 < info.st_size <= 1024 * 1024 and info.st_mode & 0o7777 == 0o755,
                                    f"local SDK source script size or executable mode differs: {name}")
                    replacements[name] = (script.read_bytes(), info.st_mode & 0o777)
            else:
                target = posixpath.join(str(path.parent), member.linkname) if member.issym() else member.linkname
                normalized = PurePosixPath(posixpath.normpath(target))
                prepare.require(normalized.parts and normalized.parts[0] == path.parts[0]
                                and ".." not in normalized.parts,
                                f"local SDK archive link escapes its root: {name}")
        # All archive and source-script checks finish before creating output.
        with tarfile.open(destination, "w") as rewritten:
            for member in members:
                replacement = replacements.get(str(PurePosixPath(member.name)))
                if replacement is None:
                    rewritten.addfile(member, original.extractfile(member) if member.isfile() else None)
                else:
                    data, mode = replacement
                    regular = copy.copy(member)
                    regular.pax_headers = {key: value for key, value in member.pax_headers.items()
                                           if key not in {"linkpath", "size"}}
                    regular.type, regular.linkname = tarfile.REGTYPE, ""
                    regular.size, regular.mode = len(data), mode
                    rewritten.addfile(regular, io.BytesIO(data))


def augment_sdk(profile, source, archive, controls, abi):
    """Keep the full successful package inventory; refresh requested external packages."""
    match = prepare.KERNEL_PACKAGE.fullmatch(abi)
    version, vermagic, _ = match.groups()
    trees = [path.parent for path in (source / "build_dir").glob("target-*/linux-*/linux-*/.vermagic")
             if path.read_text().strip() == vermagic]
    prepare.require(len(trees) == 1, "cannot identify built prepared kernel context for SDK")
    kernel = trees[0]
    prepare.require((kernel / "include/config/kernel.release").read_text().strip() == version,
                    "built kernel source release differs from its kernel ipk")
    core = core_kmod_names(source)
    prepare.require("kmod-amneziawg" not in core, "external AmneziaWG must be rebuilt rather than frozen as a core module")
    built_modules = {control["Package"] for _, control in controls
                     if control.get("Package", "").startswith("kmod-")}
    refreshed = set(profile["packages"]) - core
    frozen = built_modules - refreshed
    apk = profile.get("package_manager", "opkg") == "apk"
    protected = {"kernel", "libc", "base-files", "busybox", "apk", "apk-openssl", "apk-mbedtls"} if apk else {"kernel", "libc", "base-files", "busybox", "opkg"}
    built_names = {control["Package"] for _, control in controls}
    retained = (built_names - refreshed - protected) | {"kernel"}
    protected_packages = set()
    if apk:
        guard = sibling_module("apk_world")
        source_roots = set(guard.core_recipe_roots((source / "tmp/.packageinfo").read_text()))
        source_roots.update(guard.VENDOR)
        protected_roots = (source_roots | protected | {"libgcc", "libstdcpp"}) & built_names
        protected_packages = runtime_dependency_closure(controls, protected_roots)
        refreshed.difference_update(protected_packages)
        retained.update(protected_packages)
    # Keep every offered full-build package, including vendor GUI/tools and
    # auto-selected translations. Protected identities are retained only when
    # required by this closure; the publisher never offers them as upgrades.
    frozen_packages = runtime_dependency_closure(controls, retained) - refreshed
    baseline = [(path, control) for path, control in controls
                if control.get("Package") in frozen_packages]
    prepare.require(bool(core), "source metadata did not identify any core kernel modules for SDK baseline")
    with tempfile.TemporaryDirectory(prefix="ax6000-sdk-", dir=source.parent) as temporary:
        temporary = Path(temporary)
        compressed = archive.name.endswith(".zst")
        unpack_archive = archive
        if compressed:
            unpack_archive = temporary / "sdk.tar"
            with unpack_archive.open("wb") as stream:
                subprocess.run(["zstd", "-d", "-c", "--", str(archive)], stdout=stream, check=True)
        normalized = temporary / "sdk-normalized.tar"
        normalize_local_sdk(unpack_archive, normalized, source)
        sdk = prepare.extract_sdk(normalized, temporary / "extracted")
        sdk_kernel = sdk / kernel.relative_to(source)
        for required in (".config", "Makefile", "Module.symvers", "include/generated/autoconf.h", "include/config/kernel.release"):
            prepare.require((sdk_kernel / required).is_file(), f"generated SDK lacks prepared kernel file {required}")
        for identity in (".config", "Module.symvers"):
            prepare.require((sdk_kernel / identity).read_bytes() == (kernel / identity).read_bytes(),
                            f"generated SDK kernel {identity} differs from the built source context")
        prepare.require((kernel / "modules.builtin.modinfo").is_file(),
                        "built prepared kernel lacks modules.builtin.modinfo required by the SDK kernel package")
        shutil.copy2(kernel / "modules.builtin.modinfo", sdk_kernel / "modules.builtin.modinfo")
        for filename in (".vermagic", ".config.set"):
            if (kernel / filename).is_file():
                shutil.copy2(kernel / filename, sdk_kernel / filename)
        snapshot = sdk / "ax6000-baseline"
        if snapshot.exists():
            shutil.rmtree(snapshot)
        bank = "apks" if apk else "ipks"
        (snapshot / bank).mkdir(parents=True)
        mediatek_mesh.export_sdk_uapi(profile, source, kernel, sdk)
        tool_manifest = {}
        if apk:
            host_apk = sdk / "staging_dir/host/bin/apk"
            native_apk = source / "staging_dir/host/bin/apk"
            # The native SDK bundles and strips host executables. Authenticate
            # the exact reviewed wrapper, hidden ELF and complete loader/library
            # context; bind the source ELF separately from its portable export.
            host_context = prepare.optional_package_module("host_apk_bundle").describe(
                sdk, native_apk, source / "scripts/bundle-libraries.sh")
            context = {}
            for relative in (".config", "Module.symvers", "include/generated/autoconf.h", "include/config/kernel.release"):
                path = sdk_kernel / relative
                prepare.require(path.read_bytes() == (kernel / relative).read_bytes(),
                                "APK SDK kernel context differs from native build: " + relative)
                context[relative] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}
            tool_manifest = {"package_manager": "apk", "protected_packages": sorted(protected_packages), "host_apk": host_context,
                "kernel_context": {"path": kernel.relative_to(source).as_posix(), "files": context}}
        files = []
        for path, control in baseline:
            target = snapshot / bank / path.name
            prepare.require(not target.exists(), "duplicate frozen baseline package filename")
            shutil.copy2(path, target)
            with target.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            files.append({"package": control["Package"], "version": control["Version"],
                          "path": bank + "/" + path.name, "sha256": digest})
        baseline_manifest = {"schema_version": 1, "source_commit": profile["firmware"]["commit"],
             "kernel_version": abi, "architecture": profile["firmware"]["architecture"],
             "source_patches": json.loads((source / "firmware-source-patches.json").read_text())["patches"]
             if (source / "firmware-source-patches.json").is_file() else [],
             "frozen_kmods": sorted(frozen), "frozen_packages": sorted(frozen_packages),
             "refreshed_kmods": sorted(refreshed & built_modules), "files": files, **tool_manifest}
        if profile.get("mediatek_mesh"):
            baseline_manifest["mediatek_mesh"] = mediatek_mesh.verify(profile, source, native=True)
        baseline_bytes = (json.dumps(baseline_manifest, indent=2, sort_keys=True) + "\n").encode()
        (snapshot / "manifest.json").write_bytes(baseline_bytes)
        # Carry immutable images and build metadata into daily SDK exports. The SDK
        # itself is added from the verified download later, avoiding archive recursion.
        firmware_assets = snapshot / "firmware"
        firmware_assets.mkdir()
        for asset in firmware_bank_assets(archive):
            shutil.copy2(asset, firmware_assets / asset.name)
        # Validate the augmented context without changing its original configuration/hash.
        sdk_profile = copy.deepcopy(profile)
        sdk_profile["firmware"]["kernel_version"] = abi
        prepare.check_kernel(sdk_profile, sdk)
        partial = archive.with_name(archive.name + ".partial")
        if compressed:
            with partial.open("wb") as stream:
                process = subprocess.Popen(["zstd", "-T1", "-6", "-c"], stdin=subprocess.PIPE, stdout=stream)
                try:
                    with tarfile.open(fileobj=process.stdin, mode="w|") as tar:
                        tar.add(sdk, arcname=sdk.name)
                finally:
                    process.stdin.close()
                prepare.require(process.wait() == 0, "failed to compress augmented SDK")
        else:
            mode = "w:xz" if archive.name.endswith(".xz") else "w:gz" if archive.name.endswith(".gz") else "w"
            with tarfile.open(partial, mode) as tar:
                tar.add(sdk, arcname=sdk.name)
        partial.replace(archive)
        return baseline_bytes


def native_package_controls(profile, source):
    if profile.get("package_manager", "opkg") != "apk":
        return [(path, read_control(path)) for path in sorted((source / "bin").rglob("*.ipk"))]
    helper = sibling_module("package_format")
    prepare.require(helper.manager(profile) == "apk", "APK source must identify its native cohort")
    prepare.require(not list((source / "bin").rglob("*.ipk")), "APK native output contains foreign IPKs")
    controls = []
    for path in sorted((source / "bin").rglob("*.apk")):
        control = helper.read_control(path, apk=source / "staging_dir/host/bin/apk")
        actual = control["Package"]
        control["Package"] = control["Base-Package"]
        if actual != control["Package"]:
            alias = actual + " (= " + control["Version"] + ")"
            control["Provides"] = ", ".join(filter(None, (control.get("Provides", ""), alias)))
        controls.append((path, control))
    return controls


def export(profile, lock, source, output):
    prepare.require(not output.exists(), "firmware output directory already exists")
    if profile.get("package_manager") == "apk":
        guard = sibling_module("apk_world")
        guard.configure_source(profile, source, check_only=True)
        guard.configure_policy(profile, source, check_only=True)
    controls = native_package_controls(profile, source)
    kernel = [control for _, control in controls if control.get("Package") == "kernel"]
    prepare.require(len(kernel) == 1, "build must produce exactly one kernel ipk to discover actual firmware ABI")
    abi = kernel[0].get("Version", "")
    prepare.require(prepare.KERNEL_PACKAGE.fullmatch(abi), "built kernel ipk has invalid ABI version")
    if profile.get("channel") is not None:
        expected_version = prepare.CHANNEL_SOURCES[profile["channel"]][1]
        prepare.require(abi.startswith(expected_version + "~"), "built kernel version differs from pinned 6.12 channel")
    prepare.require(kernel[0].get("Architecture") == profile["firmware"]["architecture"], "built kernel architecture mismatch")
    for path, control in controls:
        if control.get("Package", "").startswith("kmod-"):
            dependencies = re.findall(r"(?:^|,)\s*kernel\s*\(\s*=\s*([^\s)]+)\s*\)", control.get("Depends", ""))
            prepare.require(dependencies == [abi], f"built module {path.name} has another kernel ABI")
    built = {control.get("Package") for _, control in controls}
    if profile.get("exclude_asu"):
        no_asu.assert_absent(built, {})
    prepare.require(set(profile["packages"]) <= built,
                    "build omitted requested packages: " + ", ".join(sorted(set(profile["packages"]) - built)))
    report = json.loads((source / "build-selection.json").read_text())
    missing_kmods = sorted(set(report["selected_kmods"]) - built)
    prepare.require(not missing_kmods,
                    "build omitted selected kernel modules: " + ", ".join(missing_kmods))
    target = source / "bin/targets/mediatek/filogic"
    for device, layout in firmware_layouts.validate_devices(profile).items():
        suffix = "squashfs-sysupgrade.itb" if layout == "ubootmod" else "squashfs-sysupgrade.bin"
        images = sorted(target.glob(f"*-{device}-{suffix}"))
        prepare.require(len(images) == 1 and images[0].is_file() and not images[0].is_symlink(),
                        f"build must produce one Redmi AX6000 {layout} sysupgrade image")
    sdks = sorted(target.glob("*sdk*.tar.*"))
    prepare.require(len(sdks) == 1, "build must produce one matching SDK archive")
    signer = source / "staging_dir/host/bin/usign"
    prepare.require(signer.is_file() and os_access_executable(signer), "built host usign is unavailable")
    generated = copy.deepcopy(profile)
    generated["firmware"]["kernel_version"] = abi
    baseline_bytes = augment_sdk(profile, source, sdks[0], controls, abi)
    # Daily SDK builds keep the kernel configuration fixed and reuse frozen modules.
    generated["all_kmods"] = False
    base_feed = {"name": "base", "url": profile["firmware"]["repository"], "commit": profile["firmware"]["commit"]}
    if profile.get("channel") is not None:
        base_feed["root"] = "package"
    generated["feeds"].insert(0, base_feed)
    with sdks[0].open("rb") as stream:
        sdk_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    build_id = f"{profile['id']}-{profile['firmware']['commit'][:12]}-{sdk_hash[:12]}"
    generated["build_id"] = build_id
    site_url = profile["build_source"].get("publication_url", "https://valujin.github.io/ax6000-packages")
    url_base = site_url.rstrip("/") + "/firmware/" + build_id
    prepare.https_url(url_base, "firmware publication URL")
    generated["sdk"] = {"url": firmware_layouts.firmware_release_url(generated, sdks[0].name)
                        if profile.get("channel") is not None else url_base.rstrip("/") + "/" + sdks[0].name,
                        "sha256": sdk_hash}
    export_imagebuilder(generated, source)
    output.mkdir(parents=True)
    shutil.copytree(source / "bin", output / "bin", symlinks=True)
    exported_target = output / "bin/targets/mediatek/filogic"
    checksums = []
    for asset in sorted(exported_target.iterdir()):
        if asset.is_file() and asset.name not in {"sha256sums", "SHA256SUMS"}:
            with asset.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            checksums.append(f"{digest}  {asset.name}\n")
    for filename in ("sha256sums", "SHA256SUMS"):
        (exported_target / filename).write_text("".join(checksums))
    shutil.copy2(signer, output / "usign")
    if generated.get("package_manager") == "apk":
        apk = source / "staging_dir/host/bin/apk"
        shutil.copy2(apk, output / "apk")
        source_provenance = json.loads(baseline_bytes)["host_apk"]["native_source"]
        prepare.require(source_provenance["sha256"] == hashlib.sha256(apk.read_bytes()).hexdigest()
                        and source_provenance["size"] == apk.stat().st_size,
                        "native RAW APK differs from SDK bundle source provenance")
        proof = {"schema_version": 1, "kind": "native-elf-v1", "native_source": source_provenance,
                 "path": "apk", "size": apk.stat().st_size,
                 "sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
                 "sdk_sha256": generated["sdk"]["sha256"], "sdk_url": generated["sdk"]["url"],
                 "source_relative_path": "staging_dir/host/bin/apk",
                 "baseline_manifest_sha256": hashlib.sha256(baseline_bytes).hexdigest()}
        (output / "host-apk-proof.json").write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    report["firmware"] = generated["firmware"]
    report["built_packages"] = sorted(built)
    (output / "build-selection.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "profile.json").write_text(json.dumps(generated, indent=2, sort_keys=True) + "\n")
    generated_lock = copy.deepcopy(lock)
    generated_lock["firmware"] = generated["firmware"]
    generated_lock["sdk"] = generated["sdk"]
    if generated.get("package_manager") == "apk":
        generated_lock["package_manager"] = "apk"
        generated_lock["apk_key_sha256"] = generated["apk_key_sha256"]
    generated_lock.setdefault("feeds", {})["base"] = profile["firmware"]["commit"]
    generated_lock["profile_sha256"] = hashlib.sha256((output / "profile.json").read_bytes()).hexdigest()
    (output / "lock.json").write_text(json.dumps(generated_lock, indent=2, sort_keys=True) + "\n")
    shutil.copy2(source / ".config", output / "build.config")
    manifest = []
    for path in sorted((output / "bin").rglob("*")):
        if path.is_file():
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            manifest.append({"path": str(path.relative_to(output)), "sha256": digest, "size": path.stat().st_size})
    recipe_commit = os.environ.get("AX6000_RECIPE_COMMIT")
    if not recipe_commit:
        try:
            recipe_commit = subprocess.check_output(["git", "-C", str(Path(__file__).resolve().parents[1]),
                                                     "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
        except subprocess.CalledProcessError:
            recipe_commit = None
    prepare.require(recipe_commit is None or prepare.COMMIT.fullmatch(recipe_commit), "invalid build recipe commit provenance")
    firmware_manifest = {"build_id": build_id, "kernel_version": abi, "recipe_commit": recipe_commit,
                         "source_commit": profile["firmware"]["commit"], "source_patches": report.get("source_patches", []),
                         "files": manifest}
    if profile.get("mediatek_mesh"):
        firmware_manifest["mediatek_mesh"] = mediatek_mesh.verify(profile, source, native=True)
    if profile.get("package_manager") == "apk":
        firmware_manifest.update({"package_manager": "apk", "apk_key_sha256": generated["apk_key_sha256"],
                                  "apk_world": report["apk_world"]})
    if profile.get("channel") is not None:
        firmware_manifest.update({"channel": profile["channel"], "devices": profile["firmware"]["devices"]})
        assets = firmware_layouts.collect_firmware_assets(output, generated, firmware_manifest)
        catalog = {"schema_version": 1, "channel": generated["channel"], "profile_id": generated["id"],
                   "build_id": build_id, "firmware": generated["firmware"], "sdk": generated["sdk"],
                   "assets": [{**{key: value for key, value in asset.items() if key != "path"},
                               "url": firmware_layouts.firmware_release_url(generated, asset["filename"])} for asset in assets]}
        if generated.get("package_manager") == "apk":
            catalog.update({"package_manager": "apk", "apk_key_sha256": generated["apk_key_sha256"]})
        if asu_policy(generated) is not None:
            catalog["imagebuilder"] = generated["imagebuilder"]
        firmware_layouts.validate_download_catalog(catalog, generated)
        (output / "downloads.json").write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")
    (output / "firmware-manifest.json").write_text(json.dumps(firmware_manifest, indent=2) + "\n")
    print(f"Exported matching firmware, SDK and packages with kernel ABI {abi} to {output}")


def os_access_executable(path):
    return os.access(path, os.X_OK)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--cleanup-receipt", type=Path)
    parser.add_argument("--phase", choices=("validate", "configure", "repository-files", "check-feeds", "vendor-fixes", "overrides", "reset-cached-images", "select", "ssl-selection", "package-only-selection", "verify", "export"), default="validate")
    args = parser.parse_args()
    try:
        profile, lock = json.loads(args.profile.read_text()), json.loads(args.lock.read_text())
        validate(profile, lock)
        if args.phase == "validate":
            print(f"Validated new-firmware source profile {profile['id']}; ABI will be discovered after build")
            return
        prepare.require(args.source_dir is not None and args.source_dir.is_dir(), "--source-dir is required")
        if args.phase == "export":
            repository_files(args.source_dir, check_only=True, profile=profile)
            vendor_fixes(profile, args.source_dir, check_only=True)
            prepare.require(args.output_dir is not None, "--output-dir is required")
            export(profile, lock, args.source_dir, args.output_dir)
        else:
            actions = {"configure": lambda: configure(profile, lock, args.source_dir),
                       "repository-files": lambda: repository_files(args.source_dir, profile=profile),
                       "check-feeds": lambda: prepare.verify_feeds(profile, lock, args.source_dir),
                       "vendor-fixes": lambda: vendor_fixes(profile, args.source_dir),
                       "overrides": lambda: overrides(profile, lock, args.source_dir),
                       "reset-cached-images": lambda: reset_cached_images(profile, args.source_dir, args.cleanup_receipt),
                       "select": lambda: select(profile, args.source_dir),
                       "ssl-selection": lambda: ssl_selection(profile, args.source_dir),
                       "package-only-selection": lambda: package_only_selection(profile, args.source_dir),
                       "verify": lambda: verify(profile, args.source_dir)}
            actions[args.phase]()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"prepare-firmware: {error}\n")


if __name__ == "__main__":
    main()
