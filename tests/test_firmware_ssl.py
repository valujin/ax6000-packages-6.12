"""Image SSL providers are exclusive; package alternatives preserve the kernel."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("firmware_ssl", ROOT / "scripts/prepare-firmware.py")
firmware = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(firmware)

PROTECTED = (
    "CONFIG_KERNEL_ARM64=y\n"
    "CONFIG_KERNEL_PREEMPT_NONE=y\n"
    "CONFIG_ALL_KMODS=y\n"
    "CONFIG_PACKAGE_kmod-mt_wifi=y\n"
    "CONFIG_PACKAGE_kmod-conninfra=y\n"
    "CONFIG_PACKAGE_kmod-warp=y\n"
    "CONFIG_PACKAGE_kmod-mediatek_hnat=y\n"
    "CONFIG_PACKAGE_kmod-amneziawg=m\n"
    "CONFIG_PACKAGE_libopenssl=y\n"
    "CONFIG_PACKAGE_libopenssl-conf=y\n"
    "CONFIG_PACKAGE_libopenssl-legacy=y\n"
)
BASE = (PROTECTED +
        "CONFIG_TARGET_mediatek=y\nCONFIG_TARGET_mediatek_filogic=y\n"
        "CONFIG_TARGET_DEVICE_mediatek_filogic_DEVICE_xiaomi_redmi-router-ax6000-stock=y\n"
        'CONFIG_TARGET_ARCH_PACKAGES="aarch64_cortex-a53"\n'
        "CONFIG_SDK=y\nCONFIG_DEVEL=y\n"
        "CONFIG_SIGNED_PACKAGES=y\nCONFIG_SIGNATURE_CHECK=y\n"
        "CONFIG_PACKAGE_luci-ssl=y\n"
        "CONFIG_DEFAULT_libustream-openssl=y\n"
        "CONFIG_PACKAGE_libustream-openssl=y\n"
        "CONFIG_PACKAGE_libustream-mbedtls=y\n")


class FirmwareSSLTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name)
        self.profile = {
            "schema_version": 1, "id": "ssl-fixture", "enabled": True,
            "firmware": {"repository": "https://example.com/firmware.git",
                         "commit": "a" * 40, "kernel_version": None,
                         "target": "mediatek", "subtarget": "filogic",
                         "architecture": "aarch64_cortex-a53"},
            "sdk": {"url": None, "sha256": None},
            "build_source": {"defconfig": "vendor.config",
                             "device": "xiaomi_redmi-router-ax6000-stock"},
            "feeds": [{"name": "packages", "url": "https://example.com/packages.git",
                       "commit": "c" * 40}],
            "packages": ["luci-ssl", "kmod-amneziawg"],
            "image_packages": ["luci-ssl"], "all_kmods": True,
        }
        self.lock = {"feeds": {"packages": "c" * 40}}
        (self.source / ".config").write_text(BASE)
        (self.source / "vendor.config").write_text(BASE)
        (self.source / "tmp").mkdir()
        packages = self.profile["packages"] + ["libustream-openssl", "libustream-mbedtls"]
        (self.source / "tmp/.packageinfo").write_text("".join(f"Package: {name}\n" for name in packages))
        (self.source / "tmp/.config-package.in").write_text("".join(f"config PACKAGE_{name}\n" for name in packages))
        (self.source / "tmp/.config-target.in").write_text(
            "config TARGET_DEVICE_mediatek_filogic_DEVICE_xiaomi_redmi-router-ax6000-stock\n")

    def assert_mbedtls_image(self):
        config = (self.source / ".config").read_text()
        self.assertIn("CONFIG_PACKAGE_libustream-mbedtls=y\n", config)
        self.assertIn("CONFIG_PACKAGE_libustream-openssl=m\n", config)
        self.assertNotIn("CONFIG_PACKAGE_libustream-openssl=y\n", config)
        for line in PROTECTED.splitlines():
            self.assertIn(line + "\n", config)

    def test_configure_overrides_vendor_default_without_demoting_openssl_libraries(self):
        firmware.configure(self.profile, self.lock, self.source)
        self.assert_mbedtls_image()

    def test_select_keeps_requested_luci_ssl_and_both_package_alternatives(self):
        firmware.select(self.profile, self.source)
        self.assert_mbedtls_image()
        self.assertIn("CONFIG_PACKAGE_luci-ssl=y\n", (self.source / ".config").read_text())

    def test_resume_ssl_selection_changes_only_provider_lines_and_preserves_kernel_files(self):
        kernel = self.source / "build_dir/kernel"
        kernel.mkdir(parents=True)
        frozen = {".config": b"CONFIG_ARM64=y\n", ".vermagic": b"6ea4b96ad26e951cc0b4fa9296a521d3\n",
                  "Module.symvers": b"0x12345678\tsymbol\tvmlinux\tEXPORT_SYMBOL\n"}
        for name, data in frozen.items():
            (kernel / name).write_bytes(data)
        firmware.ssl_selection(self.profile, self.source)
        self.assertEqual((self.source / ".config").read_text(), BASE.replace(
            "CONFIG_PACKAGE_libustream-openssl=y\n", "").replace(
            "CONFIG_PACKAGE_libustream-mbedtls=y\n", "") +
            "CONFIG_PACKAGE_libustream-mbedtls=y\nCONFIG_PACKAGE_libustream-openssl=m\n")
        for name, data in frozen.items():
            self.assertEqual((kernel / name).read_bytes(), data)
        original = (self.source / ".config").read_bytes()
        firmware.ssl_selection(self.profile, self.source)
        self.assertEqual((self.source / ".config").read_bytes(), original)

    def test_openssl_collection_selects_inverse_provider_without_changing_vpn_libraries(self):
        self.profile["image_packages"] = ["luci-ssl-openssl"]
        firmware.ssl_selection(self.profile, self.source)
        config = (self.source / ".config").read_text()
        self.assertIn("CONFIG_PACKAGE_libustream-openssl=y\n", config)
        self.assertIn("CONFIG_PACKAGE_libustream-mbedtls=m\n", config)
        for line in PROTECTED.splitlines():
            self.assertIn(line + "\n", config)

    def test_validate_refuses_both_image_ssl_collections(self):
        self.profile["packages"].append("luci-ssl-openssl")
        self.profile["image_packages"].append("luci-ssl-openssl")
        with self.assertRaisesRegex(ValueError, "SSL collections"):
            firmware.validate(self.profile, self.lock)

    def test_profile_without_image_ssl_preserves_provider_selection(self):
        self.profile["image_packages"] = []
        info = self.pkginfo()
        stamp = info / "ustream-ssl.openssl.install"
        stamp.write_text("libustream-openssl\n")
        firmware.ssl_selection(self.profile, self.source)
        self.assertEqual((self.source / ".config").read_text(), BASE)
        self.assertEqual(stamp.read_text(), "libustream-openssl\n")

    def pkginfo(self, target="target-fixture"):
        info = self.source / "staging_dir" / target / "pkginfo"
        info.mkdir(parents=True)
        return info

    def install_list(self, info):
        # package/Makefile reads ALL selected variants for a recipe in package-y,
        # including stale metadata for a variant whose package was demoted to m.
        result = subprocess.run(["make", "--no-print-directory", "-f", "-"],
            input=f'''variants := mbedtls openssl
all:
\t@printf '%s\\n' "$(shell cat $(foreach v,$(variants),{info}/ustream-ssl.$(v).install) 2>/dev/null)"
''', text=True, capture_output=True, check=True, timeout=5)
        return result.stdout.split()

    def test_stale_variant_cleanup_prevents_shared_recipe_rootfs_clash_and_retains_ipks(self):
        info = self.pkginfo()
        protected = {info / "ustream-ssl.mbedtls.install": b"libustream-mbedtls\n",
                     info / "ustream-ssl.mbedtls.install.flags": b"activeflag\n",
                     info / "other.default.install": b"other\n",
                     self.source / "alternative.ipk": b"built OpenSSL alternative IPK",
                     self.source / "build_dir/kernel/.config": b"CONFIG_ARM64=y\n",
                     self.source / "build_dir/kernel/.vermagic": b"6ea4b96ad26e951cc0b4fa9296a521d3\n",
                     self.source / "build_dir/kernel/Module.symvers": b"frozen kernel symbols\n"}
        for path, content in protected.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        inactive = info / "ustream-ssl.openssl.install"
        inactive.write_text("libustream-openssl\n")
        flags = inactive.with_name(inactive.name + ".flags")
        flags.write_text("\n")
        self.assertEqual(self.install_list(info), ["libustream-mbedtls", "libustream-openssl"])
        firmware.ssl_selection(self.profile, self.source)
        self.assertEqual(self.install_list(info), ["libustream-mbedtls"])
        self.assertFalse(inactive.exists())
        self.assertFalse(flags.exists())
        for path, content in protected.items():
            self.assertEqual(path.read_bytes(), content)
        self.assert_mbedtls_image()
        firmware.ssl_selection(self.profile, self.source)
        self.assertEqual(self.install_list(info), ["libustream-mbedtls"])

    def test_openssl_image_cleans_only_stale_mbedtls_variant_and_orphaned_flags(self):
        self.profile["image_packages"] = ["luci-ssl-openssl"]
        info = self.pkginfo()
        active = info / "ustream-ssl.openssl.install"
        active.write_text("libustream-openssl\n")
        inactive = info / "ustream-ssl.mbedtls.install"
        inactive.write_text("libustream-mbedtls\n")
        flags = inactive.with_name(inactive.name + ".flags")
        flags.write_text("\n")
        firmware.ssl_selection(self.profile, self.source)
        self.assertEqual(self.install_list(info), ["libustream-openssl"])
        self.assertFalse(flags.exists())
        flags.write_text("\n")
        firmware.ssl_selection(self.profile, self.source)
        self.assertFalse(flags.exists())
        self.assertEqual(active.read_text(), "libustream-openssl\n")

    def test_unexpected_inactive_stamp_refuses_before_config_or_any_other_stamp_changes(self):
        first, second = self.pkginfo("target-first"), self.pkginfo("target-second")
        first_stamp = first / "ustream-ssl.openssl.install"
        first_stamp.write_text("libustream-openssl\n")
        second_stamp = second / "ustream-ssl.openssl.install"
        for content in ("unexpected-package\n", "libustream-openssl\nother\n", ""):
            with self.subTest(content=content):
                second_stamp.write_text(content)
                with self.assertRaisesRegex(ValueError, "SSL.*stamp"):
                    firmware.ssl_selection(self.profile, self.source)
                self.assertEqual((self.source / ".config").read_text(), BASE)
                self.assertEqual(first_stamp.read_text(), "libustream-openssl\n")
                self.assertEqual(second_stamp.read_text(), content)

    def test_ssl_stamp_symlink_or_directory_refuses_before_mutation(self):
        info = self.pkginfo()
        stamp = info / "ustream-ssl.openssl.install"
        stamp.write_text("libustream-openssl\n")
        outside = self.source / "outside-stamp"
        outside.write_text("libustream-openssl\n")
        flags = info / "ustream-ssl.openssl.install.flags"
        flags.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "SSL.*stamp"):
            firmware.ssl_selection(self.profile, self.source)
        self.assertEqual((self.source / ".config").read_text(), BASE)
        self.assertEqual(stamp.read_text(), "libustream-openssl\n")
        self.assertEqual(outside.read_text(), "libustream-openssl\n")
        flags.unlink()
        stamp.unlink()
        stamp.mkdir()
        with self.assertRaisesRegex(ValueError, "SSL.*stamp"):
            firmware.ssl_selection(self.profile, self.source)
        self.assertEqual((self.source / ".config").read_text(), BASE)

    def test_ssl_stamp_parent_symlink_is_refused_even_when_it_stays_inside_source(self):
        info = self.pkginfo()
        relocated = self.source / "relocated-pkginfo"
        info.rename(relocated)
        info.symlink_to(relocated, target_is_directory=True)
        stamp = relocated / "ustream-ssl.openssl.install"
        stamp.write_text("libustream-openssl\n")
        with self.assertRaisesRegex(ValueError, "SSL.*stamp"):
            firmware.ssl_selection(self.profile, self.source)
        self.assertEqual((self.source / ".config").read_text(), BASE)
        self.assertEqual(stamp.read_text(), "libustream-openssl\n")

    def test_ssl_stamp_target_symlink_escape_is_refused_before_config_write(self):
        external = tempfile.TemporaryDirectory()
        self.addCleanup(external.cleanup)
        outside = Path(external.name)
        (outside / "pkginfo").mkdir()
        stamp = outside / "pkginfo/ustream-ssl.openssl.install"
        stamp.write_text("libustream-openssl\n")
        staging = self.source / "staging_dir"
        staging.mkdir()
        (staging / "target-escaped").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "SSL.*stamp"):
            firmware.ssl_selection(self.profile, self.source)
        self.assertEqual((self.source / ".config").read_text(), BASE)
        self.assertEqual(stamp.read_text(), "libustream-openssl\n")

    def test_ssl_selection_refuses_symlink_configuration_before_removing_stamps(self):
        info = self.pkginfo()
        stamp = info / "ustream-ssl.openssl.install"
        stamp.write_text("libustream-openssl\n")
        config = self.source / ".config"
        replacement = self.source / "other.config"
        config.rename(replacement)
        config.symlink_to(replacement)
        with self.assertRaisesRegex(ValueError, "SSL configuration"):
            firmware.ssl_selection(self.profile, self.source)
        self.assertEqual(replacement.read_text(), BASE)
        self.assertEqual(stamp.read_text(), "libustream-openssl\n")

    def test_ssl_selection_cli_preserves_profile_and_lock(self):
        profile_path, lock_path = self.source / "profile.json", self.source / "lock.json"
        profile_path.write_text(json.dumps(self.profile))
        lock_path.write_text(json.dumps(self.lock))
        profile_bytes, lock_bytes = profile_path.read_bytes(), lock_path.read_bytes()
        result = subprocess.run([
            sys.executable, str(ROOT / "scripts/prepare-firmware.py"),
            "--profile", str(profile_path), "--lock", str(lock_path),
            "--source-dir", str(self.source), "--phase", "ssl-selection",
        ], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_mbedtls_image()
        self.assertEqual(profile_path.read_bytes(), profile_bytes)
        self.assertEqual(lock_path.read_bytes(), lock_bytes)

    def test_resume_normalizes_ssl_before_verification_and_world(self):
        # Only git/build/feed operations are simulated; execute the real resume shell
        # and real profile validation/provider repair against an isolated fixture.
        work = self.source / "work"
        work.mkdir()
        tree = work / "source"
        tree.mkdir()
        (tree / ".config").write_text(BASE)
        profile_path, lock_path = work / "profile.json", work / "lock.json"
        profile_path.write_text(json.dumps(self.profile))
        lock_path.write_text(json.dumps(self.lock))
        (work / "prepared-inputs.json").write_text(json.dumps({
            "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        }))
        scripts = self.source / "scripts"
        scripts.mkdir()
        shutil.copy2(ROOT / "scripts/build-firmware.sh", scripts / "build-firmware.sh")
        (scripts / "prepare-firmware.py").write_text('''import argparse, importlib.util, json, os, pathlib, subprocess, sys
p = argparse.ArgumentParser()
for name in ("profile", "lock", "source-dir", "output-dir", "cleanup-receipt", "phase"):
    p.add_argument("--" + name)
a = p.parse_args()
real = pathlib.Path(os.environ["REAL_FIRMWARE_PREPARE"])
sys.path.insert(0, str(real.parent))
spec = importlib.util.spec_from_file_location("real_firmware", real)
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
source = pathlib.Path(a.source_dir) if a.source_dir else None
if a.phase in ("validate", "repository-files", "ssl-selection"):
    subprocess.run([sys.executable, str(real)] + sys.argv[1:], check=True)
elif a.phase == "check-feeds":
    pass
elif a.phase == "verify":
    if not (source / "normalized").is_file():
        raise SystemExit("verify ran before defconfig")
    f.verify_ssl(json.loads(pathlib.Path(a.profile).read_text()), (source / ".config").read_text())
    (source / "verified").touch()
elif a.phase == "reset-cached-images":
    if not (source / "verified").is_file():
        raise SystemExit("cache reset ran before verification")
    (source / "cache-reset").touch()
elif a.phase == "export":
    if not (source / "world-complete").is_file():
        raise SystemExit("export ran before world")
    pathlib.Path(a.output_dir).mkdir()
else:
    raise SystemExit("unexpected resume phase " + a.phase)
''')
        tools = self.source / "tools"
        tools.mkdir()
        (tools / "git").write_text("#!/usr/bin/env python3\nprint('" + "a" * 40 + "')\n")
        (tools / "make").write_text('''#!/usr/bin/env python3
import pathlib, sys
config = pathlib.Path(".config").read_text()
assert "CONFIG_PACKAGE_libustream-openssl=m\\n" in config
assert "CONFIG_PACKAGE_libustream-mbedtls=y\\n" in config
if "defconfig" in sys.argv:
    pathlib.Path("normalized").touch()
elif "world" in sys.argv:
    assert pathlib.Path("verified").is_file()
    assert pathlib.Path("cache-reset").is_file()
    pathlib.Path("world-complete").touch()
else:
    raise SystemExit("unexpected build target")
''')
        for tool in tools.iterdir():
            tool.chmod(0o755)
        output = work / "raw"
        result = subprocess.run([
            "bash", str(scripts / "build-firmware.sh"), "--profile", str(profile_path),
            "--lock", str(lock_path), "--work-dir", str(work), "--output-dir", str(output),
            "--min-free-gib", "1", "--resume",
        ], text=True, capture_output=True, timeout=20, env={**os.environ,
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "REAL_FIRMWARE_PREPARE": str(ROOT / "scripts/prepare-firmware.py"),
            "AX6000_LIMITED_FIRMWARE_BUILD": "1", "BUILD_JOBS": "1",
            "AX6000_BUILD_LOCK": str(work / "build.lock"),
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(output.is_dir())
        for line in PROTECTED.splitlines():
            self.assertIn(line + "\n", (tree / ".config").read_text())

    def verify(self, config):
        (self.source / ".config").write_text(config)
        report = {"requested": self.profile["packages"], "candidate_kmods": ["kmod-amneziawg"],
                  "source_patches": [], "baseline_vendor_drivers": ["kmod-mt_wifi", "kmod-conninfra",
                                                                           "kmod-warp", "kmod-mediatek_hnat"]}
        (self.source / "build-selection.json").write_text(json.dumps(report))
        # Reviewed vendor patches and overlays have their own production-fixture tests.
        with mock.patch.object(firmware, "vendor_fixes", return_value=[]), \
             mock.patch.object(firmware, "repository_files"):
            return firmware.verify(self.profile, self.source)

    def test_verify_accepts_correct_provider_with_alternative_as_module(self):
        self.verify(BASE.replace("CONFIG_PACKAGE_libustream-openssl=y", "CONFIG_PACKAGE_libustream-openssl=m"))

    def test_verify_refuses_multiple_image_providers_including_wolfssl(self):
        for config in (BASE, BASE.replace("CONFIG_PACKAGE_libustream-openssl=y",
                                         "CONFIG_PACKAGE_libustream-openssl=m") +
                       "CONFIG_PACKAGE_libustream-wolfssl=y\n"):
            with self.subTest(config=config), self.assertRaisesRegex(ValueError, "SSL provider"):
                self.verify(config)

    def test_verify_refuses_wrong_provider_or_unbuilt_alternative(self):
        for config in (BASE.replace("CONFIG_PACKAGE_libustream-mbedtls=y", "CONFIG_PACKAGE_libustream-mbedtls=m"),
                       BASE.replace("CONFIG_PACKAGE_libustream-openssl=y\n", "")):
            with self.subTest(config=config), self.assertRaisesRegex(ValueError, "SSL provider"):
                self.verify(config)


if __name__ == "__main__":
    unittest.main()
