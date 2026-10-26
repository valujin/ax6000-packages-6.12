"""Native APK export retains exact core context and a separate immutable IB."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from test_package_format import make_apk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('native_apk_fixture', ROOT / 'scripts/prepare-firmware.py')
firmware = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(firmware)
APK = os.environ.get('AX6000_HOST_APK') or os.environ.get('AX6000_APK') or os.environ.get('APK') or shutil.which('apk')


class NativeApkPolicy(unittest.TestCase):
    def test_overlay_tags_only_public_userspace_and_preserves_trust_and_cohort(self):
        from test_verify_firmware import verify
        base = 'https://downloads.immortalwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/'
        expected_urls = ['@public ' + base + feed + '/packages.adb'
                         for feed in ('base', 'luci', 'packages', 'routing', 'telephony')]
        for channel in ('recommended', 'latest'):
            with self.subTest(channel=channel), tempfile.TemporaryDirectory() as directory:
                profile = json.loads((ROOT / ('profiles/redmi-ax6000-612-' + channel + '-new.json')).read_text())
                source = Path(directory)
                firmware.repository_files(source, profile=profile)
                firmware.repository_files(source, profile=profile, check_only=True)
                feeds = (source / 'files/etc/apk/repositories.d/distfeeds.list').read_text()
                urls = [line for line in feeds.splitlines() if line and not line.startswith('#')]
                self.assertEqual(urls, expected_urls)
                self.assertNotIn('/video/', feeds)
                self.assertTrue(feeds.endswith('\n'))
                # The independent rootfs inspector must expect the complete same
                # rendered overlay, including both original production public keys.
                inspected, _ = verify.apk_repository_expected(ROOT, profile)
                for target, (data, _) in inspected.items():
                    self.assertEqual((source / 'files' / target).read_bytes(), data)
                self.assertEqual((source / 'files/etc/apk/keys/repository-apk.pem').read_bytes(), (ROOT / 'keys/repository-apk.pem').read_bytes())
                self.assertEqual((source / 'files/etc/ax6000/repository.pub').read_bytes(), (ROOT / 'keys/repository.pub').read_bytes())
                self.assertIn('channels/' + channel + '}', (source / 'files/usr/sbin/ax6000-install-feed').read_text())
                self.assertFalse((source / 'files/etc/opkg').exists())
                # This is the downloadable APK feed list, not source build feeds.
                self.assertIn('video', [item['name'] for item in profile['feeds']])
                (source / 'files/etc/apk/repositories.d/customfeeds.list').write_text('https://foreign.example/packages.adb\n')
                with self.assertRaisesRegex(ValueError, 'overlay differs'):
                    firmware.repository_files(source, profile=profile, check_only=True)

    def test_actual_new_source_profiles_validate_against_pinned_author_pair(self):
        lock_path = ROOT / 'tests/fixtures/pbr-612-native-inputs.json'
        self.assertEqual(hashlib.sha256(lock_path.read_bytes()).hexdigest(),
                         '24ef5943dd0d555cd14c47704928b68d6abb48ccc9ff8989faa8be82663b4317')
        lock = json.loads(lock_path.read_text())
        for channel in ('recommended', 'latest'):
            profile = json.loads((ROOT / ('profiles/redmi-ax6000-612-' + channel + '-new.json')).read_text())
            self.assertEqual(profile['package_manager'], 'apk')
            if channel == 'recommended':
                self.assertIs(profile['exclude_asu'], True); self.assertNotIn('asu', profile)
            else:
                self.assertIs(profile['enabled'], False)
                continue
            self.assertEqual(profile['pbr_source'], 'mossdef-stable')
            self.assertIs(profile['vendor_country_db'], True)
            self.assertIn('tailscale', profile['package_only'])
            self.assertNotIn('tailscale', profile['image_packages'])
            firmware.validate(profile, lock)

    def test_actual_source_configures_apk_without_asu_ib_or_cohort_before_feeds(self):
        profile = json.loads((ROOT / 'profiles/redmi-ax6000-612-recommended-new.json').read_text())
        # This minimal source fixture isolates APK/no-ASU policy; mesh has its own pinned-source tests.
        profile.pop('mediatek_mesh', None)
        lock = json.loads((ROOT / 'tests/fixtures/pbr-612-native-inputs.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            baseline = source / profile['build_source']['defconfig']; baseline.parent.mkdir(parents=True)
            baseline.write_text('CONFIG_PACKAGE_opkg=y\n# CONFIG_USE_APK is not set\nCONFIG_KERNEL_NATIVE=y\n')
            (source / 'include').mkdir()
            (source / 'include/rootfs.mk').write_bytes((ROOT / 'tests/fixtures/apk-rootfs.mk').read_bytes())
            firmware.configure(profile, lock, source)
            config = (source / '.config').read_text()
            for line in ['# CONFIG_IB is not set', '# CONFIG_IB_STANDALONE is not set', 'CONFIG_SIGNED_PACKAGES=y',
                         'CONFIG_SIGNATURE_CHECK=y', 'CONFIG_USE_APK=y', 'CONFIG_PACKAGE_apk-openssl=y',
                         'CONFIG_PACKAGE_openwrt-keyring=y', 'CONFIG_PACKAGE_usign=y',
                         '# CONFIG_PACKAGE_opkg is not set', 'CONFIG_KERNEL_NATIVE=y']:
                self.assertIn(line + '\n', config)
            self.assertFalse((source / 'files/etc/asu-cohort.json').exists())
            firmware.no_asu.verify_config(config)
            firmware.no_asu.configure(profile, source, check_only=True)
            firmware.verify_asu(profile, source)
            firmware.sibling_module('apk_world').configure_source(profile, source, check_only=True)

    def test_wrong_apk_key_fails_before_any_overlay_write(self):
        profile = json.loads((ROOT / 'profiles/redmi-ax6000-612-recommended-new.json').read_text())
        profile['apk_key_sha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            with self.assertRaisesRegex(ValueError, 'APK public key'):
                firmware.repository_files(source, profile=profile)
            self.assertEqual(list(source.iterdir()), [])


@unittest.skipUnless(APK, 'set AX6000_APK to the trusted host apk-tools 3 binary')
class NativeApkSdk(unittest.TestCase):
    def test_actual_apk_controls_augment_sdk_with_core_provider_and_kernel_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.mkdir()
            profile = json.loads((ROOT / 'tests/fixtures/legacy612-recommended-source-profile.json').read_text())
            profile['package_manager'] = 'apk'; profile['packages'] = ['pbr', 'apk-openssl']
            abi = '6.12.108~' + 'a' * 32 + '-r1'
            bank = source / 'bin/packages/base'; bank.mkdir(parents=True)
            specifications = [('kernel', abi, None, None), ('libc', '1-r1', None, None),
                              ('libgcc', '1-r1', ['libc'], None),
                              ('libstdcpp2026', '1-r1', ['libc'], ['openwrt:abiversion=2026']),
                              ('base-files', '1-r1', ['libc'], None), ('busybox', '1-r1', ['libc'], None),
                              ('apk-openssl', '1-r1', ['libc', '!opkg'], None),
                              ('kmod-native', '1-r1', ['kernel=' + abi, 'libstdcpp2026~1'], None),
                              ('pbr', '1.2.4-r2', ['libc'], None)]
            for name, version, depends, tags in specifications:
                make_apk(APK, bank, name, version, depends=depends, tags=tags)
            host_apk = source / 'staging_dir/host/bin/apk'; host_apk.parent.mkdir(parents=True)
            shutil.copy2(APK, host_apk)
            bundler = source / 'scripts/bundle-libraries.sh'; bundler.parent.mkdir()
            bundler.write_bytes((ROOT / 'tests/fixtures/apk-bundle-libraries.sh').read_bytes())
            bundled = root / 'portable-sdk'; bundled_entry = bundled / 'staging_dir/host/bin/apk'
            bundled_entry.parent.mkdir(parents=True); shutil.copy2(APK, bundled_entry)
            subprocess.run(['bash', str(bundler), str(bundled / 'staging_dir/host'), str(bundled_entry)],
                           check=True, capture_output=True)
            # target/sdk/Makefile strips host executables and .so files after bundling.
            for item in (bundled / 'staging_dir/host').rglob('*'):
                if item.is_file() and not item.is_symlink() and item.read_bytes().startswith(b'\x7fELF'):
                    subprocess.run(['strip', str(item)], check=True, capture_output=True)
            self.assertTrue(bundled_entry.read_bytes().startswith(b'#!/usr/bin/env bash\n'))
            target = source / 'bin/targets/mediatek/filogic'; target.mkdir(parents=True)
            imagebuilder = target / 'immortalwrt-imagebuilder-mediatek-filogic.Linux-x86_64.tar.gz'
            imagebuilder.write_bytes(b'separate immutable native IB')
            (target / 'firmware.bin').write_bytes(b'native image')
            kernel_relative = Path('build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/linux-6.12.108')
            kernel = source / kernel_relative
            inputs = {'Makefile': b'all:', '.config': b'CONFIG_FIXED=y\n', 'Module.symvers': b'native symbols\n',
                      '.vermagic': ('a' * 32 + '\n').encode(), 'modules.builtin.modinfo': b'builtin\x00',
                      'include/generated/autoconf.h': b'#define CONFIG_FIXED 1\n',
                      'include/config/kernel.release': b'6.12.108\n'}
            for name, data in inputs.items():
                path = kernel / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            (source / 'tmp').mkdir()
            (source / 'tmp/.packageinfo').write_text('Source-Makefile: package/kernel/linux/Makefile\nPackage: kmod-native\n')
            archive = target / 'immortalwrt-sdk-mediatek-filogic.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                for name, data in {'Makefile': b'all:', '.config': b'CONFIG_USE_APK=y\n',
                                   **{str(kernel_relative / name): data for name, data in inputs.items()}}.items():
                    member = tarfile.TarInfo('sdk/' + name); member.size = len(data); tar.addfile(member, io.BytesIO(data))
                tar.add(bundled / 'staging_dir/host', arcname='sdk/staging_dir/host')
            controls = firmware.native_package_controls(profile, source)
            normalized = {control['Package']: control for _, control in controls}
            self.assertEqual(normalized['libstdcpp']['APK-Name'], 'libstdcpp2026')
            self.assertIn('libstdcpp2026 (= 1-r1)', normalized['libstdcpp']['Provides'])
            manifest_bytes = firmware.augment_sdk(profile, source, archive, controls, abi)
            manifest = json.loads(manifest_bytes)
            self.assertEqual(manifest['package_manager'], 'apk')
            self.assertEqual(manifest['host_apk']['kind'], 'openwrt-bundle-v1')
            self.assertEqual(manifest['host_apk']['native_source']['sha256'], hashlib.sha256(Path(APK).read_bytes()).hexdigest())
            self.assertNotEqual(manifest['host_apk']['sha256'], manifest['host_apk']['native_source']['sha256'])
            self.assertEqual(manifest['kernel_context']['path'], str(kernel_relative))
            self.assertEqual(set(manifest['kernel_context']['files']), {'.config', 'Module.symvers', 'include/generated/autoconf.h', 'include/config/kernel.release'})
            for name in ['kernel', 'libc', 'libgcc', 'libstdcpp', 'base-files', 'busybox', 'apk-openssl']:
                self.assertIn(name, manifest['protected_packages']); self.assertIn(name, manifest['frozen_packages'])
            self.assertNotIn('pbr', manifest['frozen_packages'])
            with tarfile.open(archive) as tar:
                names = tar.getnames()
                self.assertNotIn('sdk/ax6000-baseline/firmware/' + imagebuilder.name, names)
                self.assertEqual(tar.extractfile('sdk/ax6000-baseline/firmware/firmware.bin').read(), b'native image')
                self.assertEqual(tar.extractfile('sdk/ax6000-baseline/apks/apk-openssl-1-r1.apk').read(), (bank / 'apk-openssl-1-r1.apk').read_bytes())
            sdk = firmware.prepare.extract_sdk(archive, root / 'decoded-sdk')
            entry = firmware.prepare.sdk_apk(profile, sdk)
            self.assertIn(b'apk-tools 3.0.5', subprocess.check_output([str(entry), '--version']))
            hidden = sdk / 'staging_dir/host/bin/.apk.bin'
            hidden.write_bytes(hidden.read_bytes() + b'tampered')
            with self.assertRaisesRegex(ValueError, 'bundle member'):
                firmware.prepare.sdk_apk(profile, sdk)
            self.assertEqual(imagebuilder.read_bytes(), b'separate immutable native IB')
            (bank / 'foreign.ipk').write_bytes(b'foreign')
            with self.assertRaisesRegex(ValueError, 'foreign IPKs'):
                firmware.native_package_controls(profile, source)


if __name__ == '__main__': unittest.main()
