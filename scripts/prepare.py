#!/usr/bin/env python3
"""Validate exact-firmware SDK inputs and prepare package-only selections."""
import argparse
import hashlib
import importlib.util
from functools import lru_cache
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
from urllib.parse import urlsplit

COMMIT = re.compile(r"[0-9a-fA-F]{40}\Z")
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+.-]*\Z")
KERNEL_PACKAGE = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)~([0-9a-f]{32})-r([0-9]+)\Z")
CHANNEL_SOURCES = {
    "recommended": ("ae65e1de69971b5a2e3cf7e39390ee93f274d488", "6.12.108"),
    "latest": ("a99b0888b88f134f56bcb2a7d93027b5d20638a9", "6.12.112"),
}


@lru_cache(maxsize=5)
def optional_package_module(name):
    # prepare.py is also imported by filename from publication tools/tests.
    # Resolve the sibling explicitly instead of relying on global sys.path.
    if name not in ('pbr_sources', 'vendor_country', 'asu_client', 'package_format', 'host_apk_bundle', 'tailscale_source', 'no_asu', 'mediatek_mesh'):
        raise ValueError('Unsupported optional package module')
    spec = importlib.util.spec_from_file_location('_ax6000_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pbr_source_module():
    return optional_package_module('pbr_sources')


def validate_package_hooks(profile):
    if 'mediatek_mesh' in profile:
        optional_package_module('mediatek_mesh').validate(profile)
    if 'exclude_asu' in profile:
        optional_package_module('no_asu').validate(profile)
    if 'vendor_country_db' in profile:
        require(type(profile['vendor_country_db']) is bool, 'vendor_country_db must be boolean')
    if profile.get('asu') is not None:
        return optional_package_module('asu_client').policy(profile)
    return None


def require(condition, message):
    if not condition:
        raise ValueError(message)


def package_manager(profile):
    value = profile.get('package_manager', 'opkg')
    require(isinstance(value, str) and value in ('opkg', 'apk'), 'unsupported package_manager')
    if value == 'apk':
        return optional_package_module('package_format').manager(profile)
    return value


def read_package_control(path, apk=None):
    if Path(path).suffix == '.apk':
        control = dict(optional_package_module('package_format').read_control(path, apk=apk))
        actual = control['Package']
        control['APK-Name'] = actual
        control['Package'] = control['Base-Package']
        if actual != control['Package']:
            provided = actual + ' (= ' + control['Version'] + ')'
            control['Provides'] = ', '.join(filter(None, (control.get('Provides', ''), provided)))
        return control
    from publish import read_control
    return read_control(path)


def sdk_apk(profile, sdk):
    """Return only the ABI-bound SDK's verified native HOST decoder, never a target apk."""
    if package_manager(profile) != 'apk':
        return None
    manifest_path = sdk / 'ax6000-baseline/manifest.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink(), 'APK SDK requires its native baseline manifest')
    manifest = json.loads(manifest_path.read_text())
    require(manifest.get('package_manager') == 'apk', 'SDK baseline package manager differs from APK profile')
    proof = manifest.get('host_apk')
    return optional_package_module('host_apk_bundle').verify(sdk, proof)



def package_only_packages(profile):
    """Packages built as IPKs but explicitly excluded from native images."""
    packages = profile.get("package_only", [])
    require(isinstance(packages, list) and all(isinstance(name, str) and NAME.fullmatch(name)
            for name in packages) and len(set(packages)) == len(packages),
            "package_only must be a unique list of package names")
    requested = set(profile.get("packages", []))
    require(set(packages) <= requested, "package_only must be a subset of requested packages")
    require(not set(packages) & set(profile.get("image_packages", [])),
            "package_only and image_packages must be disjoint")
    protected = {"kernel", "libc", "base-files", "busybox", "opkg", "procd", "fstools", "netifd",
                 "ubox", "ubus", "usign", "openwrt-keyring", "mtwifi-cfg", "mtwifi-cfg-ucode",
                 "iwinfo", "iwinfo-ucode", "ucode-mod-iwinfo", "ucode-mod-datconf",
                 "ucode-mod-l1parser", "wifi-dats", "libiwinfo", "luci-app-mtwifi-cfg"}
    require(not any(name.startswith("kmod-") or name in protected for name in packages),
            "package_only cannot demote kernel, vendor or required base packages")
    return set(packages)


def https_url(value, label):
    require(isinstance(value, str) and not re.search(r"[\s'\"\\^;]", value),
            f"{label} must be an unambiguous HTTPS URL")
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username
            and not parsed.password and not parsed.fragment, f"{label} must use HTTPS")


def feed_pins(profile, lock):
    updates = lock.get("feeds", {})
    require(isinstance(updates, dict), "lock feeds must be an object")
    names = {feed["name"] for feed in profile["feeds"]}
    require(not (updates.keys() - names), "lock contains feeds absent from the profile")
    result = {}
    for feed in profile["feeds"]:
        pin = updates.get(feed["name"], feed["commit"])
        require(isinstance(pin, str) and COMMIT.fullmatch(pin),
                f"feed {feed['name']} needs a full 40-character commit")
        result[feed["name"]] = pin.lower()
    return result


def validate_channel_inputs(profile, pins):
    """Keep the two issued firmware generations fixed during package refreshes."""
    channel = profile.get("channel")
    if channel is None:
        require("devices" not in profile["firmware"], "multi-layout firmware requires a 6.12 channel")
        return
    require(isinstance(channel, str) and channel in CHANNEL_SOURCES, "invalid 6.12 channel")
    require(profile["id"] == "redmi-ax6000-612-" + channel, "profile id differs from channel")
    firmware = profile["firmware"]
    commit, version = CHANNEL_SOURCES[channel]
    require(firmware["repository"] == "https://github.com/chasey-dev/immortalwrt-mt798x-rebase.git"
            and firmware["commit"] == commit, "channel differs from its pinned vendor source")
    require((firmware["target"], firmware["subtarget"], firmware["architecture"]) ==
            ("mediatek", "filogic", "aarch64_cortex-a53"), "channel requires the AX6000 target")
    from firmware_layouts import validate_devices
    validate_devices(profile)
    require(firmware.get("device") == "xiaomi_redmi-router-ax6000-stock", "primary firmware device must be stock")
    publication = profile.get("publication")
    require(isinstance(publication, dict) and publication.get("repository") == "valujin/ax6000-packages-6.12"
            and publication.get("site_url") == "https://valujin.github.io/ax6000-packages-6.12"
            and publication.get("firmware_assets") == "github-release", "invalid channel publication site or policy")
    source = profile.get("build_source")
    if source is not None:
        require(isinstance(source, dict) and source.get("device") == firmware["device"]
                and source.get("publication_url") == publication["site_url"] + "/channels/" + channel,
                "source overlay publication URL differs from channel")
    sdk = profile["sdk"]
    surrogate = (isinstance(source, dict) and firmware["kernel_version"] == "0.0.0~" + "0" * 32 + "-r0"
                 and sdk == {"url": "https://invalid.example/source-build-only.tar.xz", "sha256": "0" * 64}
                 and "build_id" not in profile)
    if not surrogate:
        require(firmware["kernel_version"].startswith(version + "~"), "kernel version differs from channel source")
        build_id = profile["id"] + "-" + commit[:12] + "-" + sdk["sha256"][:12]
        require(profile.get("build_id") == build_id, "channel build id must identify its exact SDK")
        prefix = "https://github.com/" + publication["repository"] + "/releases/download/firmware-" + build_id + "/"
        filename = sdk["url"].removeprefix(prefix)
        require(sdk["url"].startswith(prefix) and NAME.fullmatch(filename) and filename.endswith(".tar.zst"),
                "channel SDK URL must identify its immutable firmware Release asset")
    base = [feed for feed in profile["feeds"] if feed["name"] == "base"]
    require(surrogate or len(base) == 1, "channel SDK requires the pinned base root feed")
    if base:
        require(base[0].get("root") == "package" and base[0]["url"] == firmware["repository"]
                and base[0]["commit"] == commit and pins["base"] == commit
                and not base[0].get("monitor_ref"), "channel base root feed must remain at the firmware commit")


def validate(profile, lock):
    require(isinstance(profile, dict), "profile must be an object")
    package_manager(profile)
    require(profile.get("enabled") is True,
            "profile is disabled: collect the router ABI and exact firmware SDK before enabling")
    require(profile.get("schema_version") == 1, "unsupported profile schema_version")
    require(isinstance(profile.get("id"), str) and NAME.fullmatch(profile["id"]), "invalid profile id")
    firmware = profile.get("firmware", {})
    require(isinstance(firmware, dict), "firmware must be an object")
    https_url(firmware.get("repository"), "firmware repository")
    require(isinstance(firmware.get("commit"), str) and COMMIT.fullmatch(firmware["commit"]),
            "firmware commit needs a full 40-character commit")
    for field in ("kernel_version", "target", "subtarget", "architecture"):
        value = firmware.get(field)
        pattern = KERNEL_PACKAGE if field == "kernel_version" else NAME
        require(isinstance(value, str) and pattern.fullmatch(value), f"invalid firmware {field}")
    sdk = profile.get("sdk")
    require(isinstance(sdk, dict), "exact firmware SDK URL and SHA256 are required")
    https_url(sdk.get("url"), "SDK URL")
    require(isinstance(sdk.get("sha256"), str) and SHA256.fullmatch(sdk["sha256"]),
            "SDK SHA256 needs 64 hexadecimal characters")
    feeds = profile.get("feeds")
    require(isinstance(feeds, list) and feeds, "at least one pinned feed is required")
    names = set()
    for feed in feeds:
        require(isinstance(feed, dict), "feed must be an object")
        name = feed.get("name")
        require(isinstance(name, str) and NAME.fullmatch(name) and name not in names,
                "invalid or duplicate feed name")
        names.add(name)
        https_url(feed.get("url"), f"feed {name} URL")
        require(isinstance(feed.get("commit"), str) and COMMIT.fullmatch(feed["commit"]),
                f"feed {name} profile pin needs a full 40-character commit")
        if "root" in feed:
            require(name == "base" and feed["root"] == "package", "only the base feed may use root=package")
            require(feed["url"] == firmware["repository"] and feed["commit"] == firmware["commit"]
                    and not feed.get("monitor_ref"), "base root feed must use the fixed firmware source")
    packages = profile.get("packages")
    require(isinstance(packages, list) and packages and all(
        isinstance(name, str) and NAME.fullmatch(name) for name in packages),
        "packages must be a nonempty list of OpenWrt package names")
    require(len(set(packages)) == len(packages), "duplicate requested package")
    package_only_packages(profile)
    require(isinstance(profile.get("all_kmods", True), bool), "all_kmods must be boolean")
    languages = profile.get("luci_languages", [])
    require(isinstance(languages, list) and all(isinstance(language, str) and
            re.fullmatch(r"[a-z]{2,3}(?:_[A-Za-z]{2,8})?", language) for language in languages)
            and len(set(languages)) == len(languages), "luci_languages must be a unique list of LuCI language codes")
    require(isinstance(lock, dict), "lock must be an object")
    if 'package_manager' in lock:
        require(lock['package_manager'] == package_manager(profile), 'lock package manager differs from its profile')
    validate_package_hooks(profile)
    if 'pbr_source' in profile or 'pbr' in lock:
        pbr_source_module().validate(profile, lock)
    pins = feed_pins(profile, lock)
    validate_channel_inputs(profile, pins)
    overrides = package_overrides(lock)
    for name, override in overrides.items():
        require(isinstance(name, str) and NAME.fullmatch(name), "invalid package override name")
        require(isinstance(override, dict), f"override {name} must be an object")
        require(isinstance(override.get("version"), str)
                and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", override["version"]),
                f"override {name} needs a numeric release version")
        require(isinstance(override.get("sha256"), str) and SHA256.fullmatch(override["sha256"]),
                f"override {name} needs source SHA256")
        if name == "tailscale":
            require(firmware["architecture"].startswith("aarch64_"), "Tailscale requires an ARM64 firmware profile")
            if override.get("artifact") == "static":
                # Existing signed locks remain reproducible; new monitor locks use source.
                require(override.get("url") == f"https://pkgs.tailscale.com/stable/tailscale_{override['version']}_arm64.tgz",
                        "Tailscale static URL must name the matching official ARM64 release archive")
            else:
                optional_package_module('tailscale_source').validate(override)
    return profile


def package_overrides(lock):
    overrides = lock.get("packages", {})
    require(isinstance(overrides, dict), "lock packages must be an object")
    overrides = dict(overrides)
    if "tailscale" in lock:
        require("tailscale" not in overrides, "duplicate Tailscale override")
        overrides["tailscale"] = lock["tailscale"]
    return overrides


def configure_feeds(profile, lock, sdk):
    validate(profile, lock)
    pins = feed_pins(profile, lock)
    (sdk / "feeds.conf").write_text("".join(
        f"src-git {'--root=package ' if feed.get('root') == 'package' else ''}"
        f"{feed['name']} {feed['url']}^{pins[feed['name']]}\n" for feed in profile["feeds"]))


def verify_feeds(profile, lock, sdk):
    feeds = {feed["name"]: feed for feed in profile["feeds"]}
    for name, expected in feed_pins(profile, lock).items():
        directory = sdk / "feeds" / name
        if "root" in feeds[name]:
            require(name == "base" and feeds[name]["root"] == "package", "invalid feed root")
            clone = sdk / "feeds/base_root"
            require(not (sdk / "feeds").is_symlink() and clone.is_dir() and not clone.is_symlink()
                    and (clone / ".git").is_dir() and not (clone / ".git").is_symlink(),
                    "base root clone must be a local Git directory")
            require(directory.is_symlink() and os.readlink(directory) == "base_root/package"
                    and (clone / "package").is_dir() and not (clone / "package").is_symlink()
                    and directory.resolve() == clone.resolve() / "package", "base root feed link differs from package root")
            directory = clone
        actual = subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
        require(actual == expected, f"feed {name} checkout {actual} differs from locked {expected}")


def static_tailscale_recipe(override):
    return """include $(TOPDIR)/rules.mk

PKG_NAME:=tailscale
PKG_VERSION:=""" + override["version"] + """
PKG_RELEASE:=2
PKG_SOURCE:=tailscale_$(PKG_VERSION)_arm64.tgz
PKG_SOURCE_URL:=https://pkgs.tailscale.com/stable
PKG_HASH:=""" + override["sha256"] + """
PKG_BUILD_DIR:=$(BUILD_DIR)/tailscale_$(PKG_VERSION)_arm64
PKG_LICENSE:=BSD-3-Clause

include $(INCLUDE_DIR)/package.mk

# Preserve the verified official prebuilt Go executable bytes; native sstrip
# processing can corrupt Go ELF section headers.
RSTRIP:=:

define Package/tailscale
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Tailscale official static ARM64 release
  URL:=https://tailscale.com
  DEPENDS:=@aarch64 +ca-bundle +kmod-tun
  PROVIDES:=tailscaled
endef

define Package/tailscale/conffiles
/etc/config/tailscale
/etc/tailscale/
endef

define Build/Configure
endef
define Build/Compile
endef

define Package/tailscale/install
\t$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
\t$(INSTALL_BIN) $(PKG_BUILD_DIR)/tailscale $(1)/usr/sbin/tailscale
\t$(INSTALL_BIN) $(PKG_BUILD_DIR)/tailscaled $(1)/usr/sbin/tailscaled
\t$(INSTALL_BIN) ./files/tailscale.init $(1)/etc/init.d/tailscale
\t$(INSTALL_DATA) ./files/tailscale.conf $(1)/etc/config/tailscale
endef

$(eval $(call BuildPackage,tailscale))
"""


def apply_overrides(lock, sdk, profile):
    """Copy a pinned recipe, never rewrite the feed or global Go compiler."""
    asu_policy = validate_package_hooks(profile)
    if profile.get('mediatek_mesh'):
        optional_package_module('mediatek_mesh').configure(profile, sdk, native=(sdk / '.git').exists())
    if 'pbr_source' in profile or 'pbr' in lock:
        pbr_source_module().apply(profile, lock, sdk)
    if profile.get('vendor_country_db') is True:
        optional_package_module('vendor_country').apply_vendor_country_patch(sdk)
    if asu_policy is not None:
        optional_package_module('asu_client').apply(profile, sdk)
    for name, override in package_overrides(lock).items():
        # Full source trees have feeds/base -> package and package/feeds aliases.
        # Count actual files once, while still rejecting two distinct recipes.
        recipes = sorted({path.resolve() for path in (sdk / "feeds").glob(f"*/**/{name}/Makefile")})
        require(len(recipes) == 1, f"override {name} needs one unambiguous feed recipe")
        source = recipes[0]
        require(source.is_relative_to(sdk.resolve()), f"override {name} feed recipe escapes the build tree")
        text = source.read_text()
        target = sdk / "package/ax6000-overrides" / name
        require(not target.exists(), f"override directory already exists: {target}")
        if name == "tailscale":
            require(profile["firmware"]["architecture"].startswith("aarch64_"), "Tailscale override requires the ARM64 profile")
            if override.get("artifact") != "static":
                optional_package_module('tailscale_source').validate(override)
            require((source.parent / "files/tailscale.init").is_file() and
                    (source.parent / "files/tailscale.conf").is_file(),
                    "pinned Tailscale service and config wrappers are required")
            target.mkdir(parents=True)
            shutil.copytree(source.parent / "files", target / "files", symlinks=True)
            if override.get("artifact") == "static":
                (target / "Makefile").write_text(static_tailscale_recipe(override))
            else:
                helper = optional_package_module('tailscale_source')
                (target / "Makefile").write_text(helper.recipe(override))
                shutil.copyfile(Path(__file__).with_name('tailscale_source.py'), target / 'files/tailscale_source.py')
                (target / 'files/source-lock.json').write_text(json.dumps(override, indent=2, sort_keys=True) + '\n')
            for link in (sdk / "package/feeds").glob("*/tailscale"):
                require(link.is_symlink(), f"refusing to replace non-symlink feed package {link}")
                link.unlink()
            continue
        require(re.search(r"^PKG_VERSION\s*:?=", text, re.M) and
                re.search(r"^PKG_HASH\s*:?=\s*[0-9a-fA-F]{64}\s*$", text, re.M),
                f"override {name} needs a versioned archive recipe with PKG_HASH")
        require("$(PKG_VERSION)" in text and not re.search(r"^PKG_SOURCE_PROTO\s*:?=", text, re.M),
                f"override {name} source recipe cannot be safely version-bumped")
        shutil.copytree(source.parent, target, symlinks=True)
        for variable, value in (("PKG_VERSION", override["version"]), ("PKG_HASH", override["sha256"]),
                                ("PKG_RELEASE", "1")):
            text, count = re.subn(rf"^{variable}\s*:?=.*$", f"{variable}:={value}", text, flags=re.M)
            require(count == 1, f"override {name} requires exactly one {variable}")
        # Resolve relative include paths from the copied recipe against its pinned feed.
        def relocate(match):
            path = match.group(2)
            original = (source.parent / path).resolve()
            require(original.is_relative_to(sdk.resolve()), "recipe include escapes SDK")
            return match.group(1) + "$(TOPDIR)/" + str(original.relative_to(sdk.resolve()))
        text = re.sub(r"^(\s*include\s+)(\.{1,2}/[^\s]+)\s*$", relocate, text, flags=re.M)
        (target / "Makefile").write_text(text)
        # The SDK feed installer uses package/feeds links; the local overlay wins explicitly.
        for link in (sdk / "package/feeds").glob(f"*/{name}"):
            require(link.is_symlink(), f"refusing to replace non-symlink feed package {link}")
            link.unlink()


def check_kernel(profile, sdk):
    """A userspace SDK alone is insufficient to build matching kernel modules."""
    if not (profile.get("all_kmods", True) or any(name.startswith("kmod-") for name in profile["packages"])):
        return
    match = KERNEL_PACKAGE.fullmatch(profile["firmware"]["kernel_version"])
    require(match is not None, "exact kernel package version including ABI hash is required")
    expected_version, expected_vermagic, _ = match.groups()
    trees = [path.parent for path in (sdk / "build_dir").glob("target-*/linux-*/linux-*/Makefile")]
    prepared = [path for path in trees if (path / ".config").is_file()
                and (path / "include/generated/autoconf.h").is_file()
                and (path / "include/config/kernel.release").is_file()]
    require(len(prepared) == 1,
            "kernel module builds require one exact prepared kernel source tree in the SDK; "
            "generic userspace SDKs or headers alone cannot reproduce installed kmods")
    tree = prepared[0]
    if (tree / ".vermagic").is_file():
        vermagic = (tree / ".vermagic").read_text().strip()
    else:
        # OpenWrt SDKs omit .vermagic but bake the original value into kernel.mk.
        kernel_mk = (sdk / "include/kernel.mk").read_text()
        baked = re.findall(r"^\s*LINUX_VERMAGIC\s*:?=.*[, ]([0-9a-f]{32})\)?\s*$", kernel_mk, re.M)
        require(len(baked) == 1, "SDK has no unambiguous baked kernel ABI hash")
        vermagic = baked[0]
    require((tree / "include/config/kernel.release").read_text().strip() == expected_version
            and vermagic == expected_vermagic,
            "SDK prepared kernel ABI differs from the running firmware; never force vermagic")
    if package_manager(profile) == 'apk':
        manifest_path = sdk / 'ax6000-baseline/manifest.json'
        require(manifest_path.is_file() and not manifest_path.is_symlink(), 'APK SDK requires a native kernel context manifest')
        context = json.loads(manifest_path.read_text()).get('kernel_context')
        required = {'.config', 'Module.symvers', 'include/generated/autoconf.h', 'include/config/kernel.release'}
        require(isinstance(context, dict) and context.get('path') == tree.relative_to(sdk).as_posix()
                and isinstance(context.get('files'), dict) and set(context['files']) == required,
                'APK SDK kernel context must bind the exact native tree and all four inputs')
        for relative, expected in context['files'].items():
            path = tree / relative
            require(isinstance(expected, dict) and type(expected.get('size')) is int
                    and isinstance(expected.get('sha256'), str) and SHA256.fullmatch(expected['sha256'])
                    and path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(tree.resolve())
                    and path.stat().st_size == expected['size'], 'APK SDK kernel context input differs: ' + relative)
            with path.open('rb') as stream:
                checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
            require(checksum == expected['sha256'], 'APK SDK kernel context checksum differs: ' + relative)


def extract_sdk(archive, destination):
    require(not destination.exists(), "SDK extraction destination already exists; use a fresh work directory")
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        require(bool(members), "SDK archive is empty")
        roots = set()
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and bool(path.parts),
                    f"unsafe SDK archive path: {member.name}")
            roots.add(path.parts[0])
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                    f"unsupported SDK archive member: {member.name}")
            if member.issym() or member.islnk():
                require(not member.linkname.startswith("/"), f"absolute SDK archive link: {member.name}")
                link = (posixpath.join(str(path.parent), member.linkname)
                        if member.issym() else member.linkname)
                normalized = PurePosixPath(posixpath.normpath(link))
                require(normalized.parts and normalized.parts[0] == path.parts[0]
                        and ".." not in normalized.parts, f"SDK archive link escapes its root: {member.name}")
        require(len(roots) == 1, "SDK archive needs exactly one top-level directory")
        require(hasattr(tarfile, "data_filter"), "Python with tarfile data_filter is required (3.12 recommended)")
        destination.mkdir(parents=True)
        tar.extractall(destination, members=members, filter="data")
    sdk = destination / next(iter(roots))
    require((sdk / "Makefile").is_file(), "archive does not contain an SDK Makefile")
    return sdk


def available_packages(sdk):
    info, symbols = sdk / "tmp/.packageinfo", sdk / "tmp/.config-package.in"
    require(info.is_file() and symbols.is_file(), "run SDK make defconfig to generate package metadata first")
    packages = set(re.findall(r"^Package:\s*(\S+)", info.read_text(), re.M))
    config = set(re.findall(r"^\s*(?:menu)?config\s+PACKAGE_(\S+)", symbols.read_text(), re.M))
    return packages & config


def luci_language_symbols(profile, sdk, value):
    languages = profile.get("luci_languages", [])
    if not languages:
        return {}
    metadata = (sdk / "tmp/.config-package.in").read_text()
    available = set(re.findall(r"^\s*(?:menu)?config\s+LUCI_LANG_(\S+)", metadata, re.M))
    require(set(languages) <= available, "requested LuCI languages absent from pinned feeds: "
            + ", ".join(sorted(set(languages) - available)))
    return {"LUCI_LANG_" + language: value for language in languages}


def check_sdk_identity(profile, sdk):
    config = (sdk / ".config").read_text()
    if package_manager(profile) == 'apk':
        require(re.search(r'^CONFIG_USE_APK=y$', config, re.M), 'APK SDK must retain native CONFIG_USE_APK=y')
        sdk_apk(profile, sdk)
    expected = {"TARGET_BOARD": profile["firmware"]["target"],
                "TARGET_SUBTARGET": profile["firmware"]["subtarget"],
                "TARGET_ARCH_PACKAGES": profile["firmware"]["architecture"]}
    for symbol, value in expected.items():
        require(f'CONFIG_{symbol}="{value}"' in config, f"SDK {symbol} does not match exact firmware profile")
    version = (sdk / "include/version.mk").read_text()
    # getver.sh uses r<upstream>+<local commits>-<hash> for fork/detached builds.
    revision = re.findall(r"^REVISION\s*:?=\s*r[0-9]+(?:\+[0-9]+)?-([0-9a-f]{7,40})\s*$", version, re.M)
    require(len(revision) == 1 and profile["firmware"]["commit"].startswith(revision[0]),
            "SDK baked source revision does not match the firmware commit")


def baseline_packages(profile, sdk):
    directory = sdk / "ax6000-baseline"
    if not directory.exists():
        return {}
    from publish import validate_package
    manifest = json.loads((directory / "manifest.json").read_text())
    manager = package_manager(profile)
    require(manifest.get('package_manager', 'opkg') == manager, 'SDK baseline package manager differs from the exact profile')
    apk = sdk_apk(profile, sdk)
    require(manifest.get("schema_version") == 1 and manifest.get("source_commit") == profile["firmware"]["commit"]
            and manifest.get("kernel_version") == profile["firmware"]["kernel_version"]
            and manifest.get("architecture") == profile["firmware"]["architecture"],
            "SDK module baseline differs from the exact firmware identity")
    frozen = manifest.get("frozen_kmods", manifest.get("core_kmods", []))
    require(isinstance(frozen, list) and all(isinstance(name, str) and name.startswith("kmod-") for name in frozen)
            and len(frozen) == len(set(frozen)), "invalid frozen module baseline list")
    frozen_packages = manifest.get("frozen_packages", ["kernel"] + frozen)
    require(isinstance(frozen_packages, list) and all(isinstance(name, str) and NAME.fullmatch(name)
            for name in frozen_packages) and len(frozen_packages) == len(set(frozen_packages))
            and set(frozen) <= set(frozen_packages), "invalid frozen package baseline list")
    if manager == 'apk':
        protected = manifest.get('protected_packages')
        require(isinstance(protected, list) and all(isinstance(name, str) and NAME.fullmatch(name) for name in protected)
                and len(protected) == len(set(protected)) and set(protected) <= set(frozen_packages)
                and 'kernel' in protected, 'APK baseline must identify its protected native package bank')
    result = {}
    for entry in manifest["files"]:
        relative = PurePosixPath(entry["path"])
        require(not relative.is_absolute() and ".." not in relative.parts, "unsafe baseline package path")
        path = directory / relative
        if manager == 'apk':
            require(path.suffix == '.apk', 'APK baseline contains a foreign package format')
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(directory.resolve()),
                "baseline package is missing or escapes SDK")
        with path.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        require(checksum == entry["sha256"], f"baseline checksum mismatch: {path.name}")
        control = read_package_control(path, apk=apk)
        require(control["Package"] == entry["package"] and control["Version"] == entry["version"],
                f"baseline package identity mismatch: {path.name}")
        validate_package(control, profile)
        if control["Package"] == "kernel":
            require(control["Version"] == profile["firmware"]["kernel_version"], "baseline kernel identity version mismatch")
        require(control["Package"] not in result, "duplicate baseline package")
        require(control["Package"] in frozen_packages,
                "baseline contains a package outside the frozen allowlist")
        result[control["Package"]] = path
    require(set(frozen) <= result.keys(), "baseline manifest omits listed frozen modules")
    if "frozen_packages" in manifest:
        require(set(frozen_packages) == result.keys(), "baseline manifest omits listed frozen packages")
    return result


def baseline_protected_packages(profile, sdk):
    if package_manager(profile) != 'apk':
        return set()
    manifest = json.loads((sdk / 'ax6000-baseline/manifest.json').read_text())
    return set(manifest['protected_packages'])


def sdk_refresh_defaults(profile, sdk, baseline, selected):
    """Preflight an SDK-local default override without changing its baked snapshot."""
    snapshot = sdk / "Config-build.in"
    require(not snapshot.is_symlink(), "SDK build snapshot must not be a symlink")
    if not snapshot.exists():
        return None
    require(snapshot.is_file() and sdk.absolute() == sdk.resolve(),
            "SDK build snapshot must be a regular file inside SDK")
    config = sdk / "Config.in"
    output = sdk / "ax6000-refresh-defaults.in"
    require(config.is_file() and not config.is_symlink() and not output.is_symlink()
            and (not output.exists() or output.is_file()),
            "SDK refresh configuration must use regular files inside SDK")
    text = config.read_text()
    original = 'source "Config-build.in"'
    include = 'source "ax6000-refresh-defaults.in"'
    source_lines = re.findall(r'''^[ \t]*source[ \t]+["']Config-build\.in["'][^\n]*$''', text, re.M)
    require(source_lines == [original], "SDK must contain one exact build snapshot source")
    includes = re.findall(r'''^[ \t]*source[ \t]+["']ax6000-refresh-defaults\.in["'][^\n]*$''', text, re.M)
    require(not includes or (includes == [include] and include + "\n" + original in text
                            and output.is_file()), "SDK refresh source is duplicated, misplaced or missing its file")
    baked = set(re.findall(r"^config PACKAGE_(\S+)\s*$", snapshot.read_text(), re.M))
    require(all(NAME.fullmatch(name) for name in baked), "invalid SDK baked package symbol")
    packages = set(re.findall(r"^Package:\s*(\S+)", (sdk / "tmp/.packageinfo").read_text(), re.M)) | set(baseline)
    baked_packages = baked & packages
    header = "# Generated by ax6000-packages SDK package selection; do not edit.\n"
    def declarations(names):
        return "".join(f"config PACKAGE_{name}\n\tdefault n\n\n" for name in sorted(names))
    if output.exists():
        previous = output.read_text()
        names = re.findall(r"^config PACKAGE_(\S+)\n\tdefault n\n\n", previous, re.M)
        require(set(names) <= baked_packages and len(names) == len(set(names))
                and previous == header + declarations(names), "refusing foreign SDK refresh defaults file")
    # Frozen modules stay in the exported bank; their baked defaults must not
    # schedule unrelated driver builds. Requested modules and dependency closure
    # remain exempt through the explicit requested/selected sets.
    protected_defaults = baseline_protected_packages(profile, sdk) - {
        name for name in baseline if name.startswith("kmod-")}
    unwanted = baked_packages - set(profile["packages"]) - set(selected) - {"kernel"} - protected_defaults
    if not includes:
        text = re.sub(r'^source "Config-build\.in"$', include + "\n" + original, text, flags=re.M)
    return output, header + declarations(unwanted), config, text


def select_packages(profile, sdk):
    available = available_packages(sdk)
    requested = set(profile["packages"])
    baseline = baseline_packages(profile, sdk)
    missing = sorted(requested - available - baseline.keys())
    require(not missing, "requested packages absent from pinned SDK feeds: " + ", ".join(missing))
    kmods = sorted(name for name in available if name.startswith("kmod-")) if profile.get("all_kmods", True) else []
    # Frozen dependency packages remain available as fallback, but requested
    # userland packages must still refresh. Modules keep the exact prepared ABI.
    frozen_kmods = {name for name in baseline if name.startswith("kmod-")}
    protected = baseline_protected_packages(profile, sdk)
    selected = sorted((requested | set(kmods)) - frozen_kmods - protected - {"kernel"})
    config = sdk / ".config"
    require(config.is_file() and not config.is_symlink() and config.resolve().is_relative_to(sdk.resolve()),
            "SDK package configuration must be a regular file inside SDK")
    report_path = sdk / "build-selection.json"
    require(not report_path.is_symlink() and (not report_path.exists() or report_path.is_file()),
            "SDK selection report must be a regular file inside SDK")
    text = config.read_text()
    language_symbols = luci_language_symbols(profile, sdk, "m")
    refresh = sdk_refresh_defaults(profile, sdk, baseline, selected)
    # The SDK's generated build snapshot can declare image packages/languages
    # as bool even when refreshed feed metadata declares them as tristate.
    # Honor that baked type without rewriting the snapshot or kernel context.
    snapshot = sdk / "Config-build.in"
    boolean_symbols = set(re.findall(
        r"^config ((?:PACKAGE_|LUCI_LANG_)[^\s]+)\n[ \t]+bool[ \t]*(?:\n|$)",
        snapshot.read_text() if snapshot.is_file() else "", re.M))
    language_symbols = {symbol: "y" if symbol in boolean_symbols else value
                        for symbol, value in language_symbols.items()}
    package_values = {name: "y" if "PACKAGE_" + name in boolean_symbols else "m"
                      for name in selected}
    text = re.sub(r"^(?:# )?CONFIG_(LUCI_LANG_[^= ]+)(?:=.*| is not set)\n?",
                  lambda match: "" if match.group(1) in language_symbols else match.group(0), text, flags=re.M)
    # Preserve target/toolchain config, clear preselected package defaults and firmware build output.
    text = re.sub(r"^(?:CONFIG_PACKAGE_.*|# CONFIG_PACKAGE_.*)\n?", "", text, flags=re.M)
    if profile.get("channel") is not None:
        text = re.sub(r"^(?:CONFIG_USE_APK=.*|# CONFIG_USE_APK is not set)\n?", "", text, flags=re.M)
        text += "\nCONFIG_USE_APK=y\n" if package_manager(profile) == 'apk' else "\n# CONFIG_USE_APK is not set\n"
    text = re.sub(r"^(?:CONFIG_(?:SDK|ALL|ALL_KMODS|ALL_NONSHARED|SIGNED_PACKAGES|BUILD_LOG|BUILDBOT|TARGET_ROOTFS_[A-Z0-9_]+)=.*|# CONFIG_(?:SDK|ALL|ALL_KMODS|ALL_NONSHARED|SIGNED_PACKAGES|BUILD_LOG|BUILDBOT|TARGET_ROOTFS_[A-Z0-9_]+) is not set)\n?", "", text, flags=re.M)
    if refresh:
        refresh_path, defaults, config_in, refreshed = refresh
        refresh_path.write_text(defaults)
        config_in.write_text(refreshed)
    config.write_text(text.rstrip() + "\nCONFIG_SDK=y\n# CONFIG_ALL is not set\n"
                      "# CONFIG_ALL_KMODS is not set\n# CONFIG_ALL_NONSHARED is not set\n"
                      "# CONFIG_SIGNED_PACKAGES is not set\n"
                      + "".join(f"CONFIG_{symbol}={value}\n" for symbol, value in sorted(language_symbols.items()))
                      + "".join(f"# CONFIG_PACKAGE_{name} is not set\n" for name in sorted(available - set(selected)))
                      + "".join(f"CONFIG_PACKAGE_{name}={package_values[name]}\n" for name in selected))
    report = {"profile": profile["id"], "requested": sorted(requested), "candidate_kmods": kmods,
              "baseline_kmods": sorted(name for name in baseline if name.startswith("kmod-")),
              "luci_languages": {name: language_symbols["LUCI_LANG_" + name]
                                 for name in profile.get("luci_languages", [])}}
    (sdk / "build-selection.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def native_dependency_groups(value, label, *, apk=False):
    groups = []
    if not value.strip():
        return groups
    for group in value.split(","):
        names = set()
        for alternative in group.split("|"):
            conflict = apk and alternative.strip().startswith('!')
            if conflict:
                require('|' not in group and 'Provides' not in label,
                        'APK conflict cannot be a dependency alternative or provider')
                alternative = alternative.strip()[1:]
            name_pattern = r'[A-Za-z0-9][A-Za-z0-9_.+:\-]*' if apk else r'[A-Za-z0-9][A-Za-z0-9_.+\-]*'
            operators = r'>=|<=|>>|<<|!=|=|>|<|~' if apk else r'>=|<=|>>|<<|!=|=|>|<'
            match = re.fullmatch(r'\s*(' + name_pattern + r')(?:\s*\((?:' + operators + r')\s*[^\s()]+\))?\s*', alternative)
            require(match is not None, f"invalid native {label}: {alternative!r}")
            if conflict:
                # APK conflicts constrain the solver but are not runtime dependency edges.
                continue
            names.add(match[1])
        if names:
            groups.append(names)
    return groups


def required_native_kmods(baseline, config, *, apk=None):
    """Follow final verified controls: SDK menus omit native dependency edges."""
    controls = {name: read_package_control(path, apk=apk) for name, path in baseline.items()}
    providers = {}
    for name, control in controls.items():
        provided = {name}
        for group in native_dependency_groups(control.get("Provides", ""), f"Provides for {name}", apk=apk is not None):
            provided.update(group)
        for provided_name in provided:
            providers.setdefault(provided_name, set()).add(name)
    selected = set(re.findall(r"^CONFIG_PACKAGE_(.+)=[my]$", config, re.M))
    pending = {name for name in selected & baseline.keys() if name.startswith("kmod-")}
    closure = set()
    # These packages describe the fixed SDK toolchain/kernel; never refresh them
    # through a native module dependency selection.
    fixed = {"kernel", "libc", "libgcc", "libpthread", "librt"}
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        closure.add(name)
        for group in native_dependency_groups(controls[name].get("Depends", ""), f"Depends for {name}", apk=apk is not None):
            if group & fixed:
                continue
            candidates = set().union(*(providers.get(dependency, set()) for dependency in group))
            require(bool(candidates), f"native dependency unavailable: {name} -> " + " | ".join(sorted(group)))
            # Keep all verified alternatives conservatively, as the SDK baseline
            # does when retaining its immutable runtime dependency inventory.
            pending.update(candidates - closure - fixed)
    return {name for name in closure if name.startswith("kmod-")}


def close_native(profile, sdk):
    baseline = baseline_packages(profile, sdk)
    if not baseline:
        return False
    config = sdk / ".config"
    report_path = sdk / "build-selection.json"
    require(config.is_file() and not config.is_symlink() and report_path.is_file()
            and not report_path.is_symlink(), "native closure configuration/report must be regular SDK files")
    text = config.read_text()
    selected = set(re.findall(r"^CONFIG_PACKAGE_(.+)=[my]$", text, re.M))
    required = required_native_kmods(baseline, text, apk=sdk_apk(profile, sdk))
    refresh = sdk_refresh_defaults(profile, sdk, baseline, selected | required)
    snapshot = sdk / "Config-build.in"
    booleans = set(re.findall(r"^config (PACKAGE_[^\s]+)\n[ \t]+bool[ \t]*(?:\n|$)",
                             snapshot.read_text() if snapshot.is_file() else "", re.M))
    changed = False
    for name in sorted(required):
        if name in selected:
            continue
        value = "y" if "PACKAGE_" + name in booleans else "m"
        text = re.sub(r"^(?:# )?CONFIG_PACKAGE_" + re.escape(name) + r"(?:=.*| is not set)\n?", "", text, flags=re.M)
        text = text.rstrip() + f"\nCONFIG_PACKAGE_{name}={value}\n"
        changed = True
    report = json.loads(report_path.read_text())
    report["required_native_kmods"] = sorted(required)
    if refresh:
        path, defaults, config_in, refreshed = refresh
        if not path.exists() or path.read_text() != defaults or config_in.read_text() != refreshed:
            changed = True
            path.write_text(defaults)
            config_in.write_text(refreshed)
    if changed:
        config.write_text(text)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return changed


def verify_selection(profile, sdk):
    report = json.loads((sdk / "build-selection.json").read_text())
    config = (sdk / ".config").read_text()
    if profile.get("mediatek_mesh"):
        optional_package_module("mediatek_mesh").verify(profile, sdk, native=(sdk / ".git").exists())
    if profile.get("exclude_asu"):
        optional_package_module("no_asu").verify_config(config)
    if profile.get("channel") is not None:
        if package_manager(profile) == 'apk':
            require(bool(re.search(r'^CONFIG_USE_APK=y$', config, re.M))
                    and '# CONFIG_USE_APK is not set\n' not in config, '6.12 APK SDK package manager changed after defconfig')
        else:
            require("# CONFIG_USE_APK is not set\n" in config and not re.search(r"^CONFIG_USE_APK=[my]$", config, re.M),
                    "6.12 SDK must retain opkg/IPK; APK was enabled after defconfig")
    selected = set(re.findall(r"^CONFIG_PACKAGE_(.+)=[my]$", config, re.M))
    baseline = baseline_packages(profile, sdk)
    # Fresh native source trees have no exported SDK package bank to decode yet.
    required = required_native_kmods(baseline, config, apk=sdk_apk(profile, sdk)) if baseline else set()
    require(required <= selected, "native dependency selection unresolved after defconfig: "
            + ", ".join(sorted(required - selected)))
    missing = sorted(set(profile["packages"]) - selected - baseline.keys())
    require(not missing, "requested packages unresolved after defconfig: " + ", ".join(missing))
    for language in profile.get("luci_languages", []):
        expected = report.get("luci_languages", {}).get(language)
        require(expected in {"m", "y"} and f"CONFIG_LUCI_LANG_{language}={expected}\n" in config,
                f"requested LuCI language {language} unresolved after defconfig")
    report["selected_packages"] = sorted(selected)
    report["selected_kmods"] = sorted(set(report["candidate_kmods"]) & selected)
    report["incompatible_kmods"] = sorted(set(report["candidate_kmods"]) - selected)
    report["firmware"] = profile["firmware"]
    report["required_native_kmods"] = sorted(required)
    (sdk / "build-selection.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def export_packages(profile, lock, sdk, output, sdk_archive=None):
    """Merge exact frozen modules with fresh packages in the explicitly selected format."""
    from publish import validate_package
    require(not output.exists(), "SDK output directory already exists")
    baseline = baseline_packages(profile, sdk)
    manager = package_manager(profile)
    apk = sdk_apk(profile, sdk)
    extension = 'apk' if manager == 'apk' else 'ipk'
    built = list((sdk / "bin").rglob('*.' + extension))
    require(bool(built), 'SDK produced no .' + extension + ' packages')
    if apk is not None:
        require(not list((sdk / 'bin').rglob('*.ipk')), 'APK SDK output contains foreign IPK packages')
    packages = dict(baseline)
    protected = baseline_protected_packages(profile, sdk)
    for path in sorted(built):
        control = read_package_control(path, apk=apk)
        validate_package(control, profile)
        name = control["Package"]
        if name in baseline and (name.startswith("kmod-") or name == "kernel"
                                 or name in protected):
            continue
        packages[name] = path
    require(set(profile["packages"]) <= packages.keys(),
            "SDK produced no output for requested packages: " + ", ".join(sorted(set(profile["packages"]) - packages.keys())))
    signer = sdk / "staging_dir/host/bin/usign"
    require(signer.is_file() and os.access(signer, os.X_OK), "SDK host usign is unavailable for repository signing")
    package_dir = output / "bin/packages"
    package_dir.mkdir(parents=True)
    for path in packages.values():
        shutil.copy2(path, package_dir / path.name)
    shutil.copy2(signer, output / "usign")
    if apk is not None:
        shutil.copy2(apk, output / 'apk')
        baseline_manifest = sdk / 'ax6000-baseline/manifest.json'
        proof = json.loads(baseline_manifest.read_text())['host_apk']
        proof = dict(proof, sdk_sha256=profile['sdk']['sha256'], sdk_url=profile['sdk']['url'],
                     baseline_manifest_sha256=hashlib.sha256(baseline_manifest.read_bytes()).hexdigest(),
                     bundle_path='host-apk-bundle', exported_entrypoint_data_path='apk',
                     executable_entrypoint_path=('apk' if proof['kind'] == 'native-elf-v1'
                                                 else 'host-apk-bundle/' + proof['path']))
        bundle = output / proof['bundle_path']
        for entry in proof['files']:
            target = bundle / entry['path']; target.parent.mkdir(parents=True, exist_ok=True)
            if entry['type'] == 'symlink':
                target.symlink_to(entry['target'])
            else:
                shutil.copy2(sdk / entry['path'], target)
        (output / 'host-apk-proof.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    shutil.copy2(sdk / "build-selection.json", output / "build-selection.json")
    firmware_assets = sdk / "ax6000-baseline/firmware"
    if firmware_assets.is_dir():
        require(sdk_archive is not None and sdk_archive.is_file(),
                "SDK with frozen firmware requires its verified --sdk-archive for complete daily publication")
        with sdk_archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        require(digest == profile["sdk"]["sha256"], "downloaded SDK hash changed before daily export")
        target = output / "bin/targets" / profile["firmware"]["target"] / profile["firmware"]["subtarget"]
        shutil.copytree(firmware_assets, target, symlinks=True)
        sdk_name = PurePosixPath(urlsplit(profile["sdk"]["url"]).path).name
        require(bool(sdk_name) and NAME.fullmatch(sdk_name), "invalid published SDK archive filename")
        shutil.copy2(sdk_archive, target / sdk_name)
        checksums = []
        for asset in sorted(target.iterdir()):
            if asset.is_file() and asset.name not in {"sha256sums", "SHA256SUMS"}:
                with asset.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                checksums.append(f"{digest}  {asset.name}\n")
        for filename in ("sha256sums", "SHA256SUMS"):
            (target / filename).write_text("".join(checksums))
    (output / "profile.json").write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n")
    generated_lock = dict(lock)
    if manager == 'apk':
        generated_lock['package_manager'] = 'apk'
        if 'apk_key_sha256' in profile:
            generated_lock['apk_key_sha256'] = profile['apk_key_sha256']
    generated_lock["profile_sha256"] = hashlib.sha256((output / "profile.json").read_bytes()).hexdigest()
    (output / "lock.json").write_text(json.dumps(generated_lock, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--sdk-dir", type=Path)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--sdk-archive", type=Path)
    parser.add_argument("--phase", choices=("validate", "feeds", "check-feeds", "overrides", "check-sdk", "check-kernel", "select", "close-native", "verify", "export"), default="feeds")
    parser.add_argument("--inspect-sdk", choices=("url", "sha256", "id"))
    parser.add_argument("--extract", type=Path)
    parser.add_argument("--extract-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.extract:
            require(args.extract_dir is not None, "--extract-dir is required")
            print(extract_sdk(args.extract, args.extract_dir))
            return
        require(args.profile is not None and args.lock is not None, "--profile and --lock are required")
        profile, lock = json.loads(args.profile.read_text()), json.loads(args.lock.read_text())
        validate(profile, lock)
        if args.inspect_sdk:
            print(profile["id"] if args.inspect_sdk == "id" else profile["sdk"][args.inspect_sdk])
            return
        if args.phase == "validate":
            print(f"Validated enabled profile {profile['id']} and locked SDK inputs")
            return
        require(args.sdk_dir is not None and args.sdk_dir.is_dir(), "--sdk-dir must be an extracted SDK")
        if args.phase == "export":
            require(args.output_dir is not None, "--output-dir is required")
            export_packages(profile, lock, args.sdk_dir, args.output_dir, args.sdk_archive)
            return
        actions = {"feeds": lambda: configure_feeds(profile, lock, args.sdk_dir),
                   "check-feeds": lambda: verify_feeds(profile, lock, args.sdk_dir),
                   "overrides": lambda: apply_overrides(lock, args.sdk_dir, profile),
                   "check-kernel": lambda: check_kernel(profile, args.sdk_dir),
                   "check-sdk": lambda: check_sdk_identity(profile, args.sdk_dir),
                   "select": lambda: select_packages(profile, args.sdk_dir),
                   "close-native": lambda: close_native(profile, args.sdk_dir),
                   "verify": lambda: verify_selection(profile, args.sdk_dir)}
        result = actions[args.phase]()
        if result is not None:
            print(json.dumps(result, indent=2))
    except (ValueError, OSError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"prepare: {error}\n")


if __name__ == "__main__":
    main()
