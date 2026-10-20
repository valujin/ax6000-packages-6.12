"""Keep requested userland IPKs while excluding them from native firmware."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('firmware_package_only', ROOT / 'scripts/prepare-firmware.py')
firmware = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(firmware)

PROTECTED = ('CONFIG_KERNEL_ARM64=y\nCONFIG_PACKAGE_kmod-mt_wifi=y\n'
             'CONFIG_PACKAGE_kmod-conninfra=y\nCONFIG_PACKAGE_kmod-warp=y\n'
             'CONFIG_PACKAGE_kmod-mediatek_hnat=y\nCONFIG_ALL_KMODS=y\n')
BASE = PROTECTED + 'CONFIG_PACKAGE_curl=y\nCONFIG_PACKAGE_tailscale=y\n'


class PackageOnlyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.profile = {'schema_version': 1, 'id': 'package-only-fixture', 'enabled': True,
                        'firmware': {'repository': 'https://example.org/source.git', 'commit': 'a' * 40,
                                     'kernel_version': None, 'target': 'mediatek', 'subtarget': 'filogic',
                                     'architecture': 'aarch64_cortex-a53'},
                        'sdk': {'url': None, 'sha256': None},
                        'build_source': {'defconfig': 'vendor.config', 'device': 'xiaomi_redmi-router-ax6000-stock'},
                        'feeds': [{'name': 'packages', 'url': 'https://example.org/packages.git', 'commit': 'c' * 40}],
                        'packages': ['tailscale', 'curl'], 'image_packages': ['curl'],
                        'package_only': ['tailscale'], 'all_kmods': True}
        self.lock = {'feeds': {'packages': 'c' * 40}}
        (self.source / '.config').write_text(BASE)
        (self.source / 'tmp').mkdir()
        (self.source / 'tmp/.packageinfo').write_text(
            'Source-Makefile: package/ax6000-overrides/tailscale/Makefile\n\nPackage: tailscale\n\n'
            'Source-Makefile: feeds/packages/net/curl/Makefile\n\nPackage: curl\n')
        (self.source / 'tmp/.config-package.in').write_text('config PACKAGE_tailscale\nconfig PACKAGE_curl\n')
        (self.source / 'tmp/.config-target.in').write_text(
            'config TARGET_DEVICE_mediatek_filogic_DEVICE_xiaomi_redmi-router-ax6000-stock\n')

    def require_policy(self):
        self.assertTrue(hasattr(firmware, 'package_only_selection'), 'Missing native package-only selection phase')

    def info(self, name='target-fixture'):
        path = self.source / 'staging_dir' / name / 'pkginfo'; path.mkdir(parents=True)
        return path

    def test_select_overrides_vendor_baseline_y_but_retains_requested_ipk_and_kernel(self):
        firmware.select(self.profile, self.source)
        config = (self.source / '.config').read_text()
        self.assertIn('CONFIG_PACKAGE_tailscale=m\n', config)
        self.assertNotIn('CONFIG_PACKAGE_tailscale=y\n', config)
        self.assertIn('CONFIG_PACKAGE_curl=y\n', config)
        for line in PROTECTED.splitlines(): self.assertIn(line + '\n', config)
        report = json.loads((self.source / 'build-selection.json').read_text())
        self.assertIn('tailscale', report['requested'])

    def test_policy_rejects_conflicts_duplicates_unknown_and_protected_packages(self):
        cases = ['tailscale', ['tailscale', 'tailscale'], ['unrequested'], ['curl'],
                 ['kernel'], ['kmod-mt_wifi'], ['mtwifi-cfg-ucode'], ['opkg']]
        for value in cases:
            with self.subTest(value=value):
                profile = copy.deepcopy(self.profile)
                if isinstance(value, list):
                    profile['packages'] += [name for name in value if name not in profile['packages']]
                    if value == ['unrequested']: profile['packages'].remove('unrequested')
                profile['package_only'] = value
                with self.assertRaises(ValueError): firmware.validate(profile, self.lock)

    def test_cached_y_stamp_is_removed_and_ipks_and_all_kernel_contexts_stay_exact(self):
        self.require_policy()
        info = self.info(); stamp = info / 'tailscale.default.install'; flags = info / 'tailscale.default.install.flags'
        stamp.write_bytes(b'tailscale\n'); flags.write_bytes(b'\n')
        protected = {self.source / 'tail.ipk': b'official Tailscale IPK', info / 'curl.default.install': b'curl\n'}
        for name in ('.config', '.config.set', '.vermagic', 'Module.symvers', 'Image', 'include/generated/autoconf.h', 'include/config/kernel.release'):
            protected[self.source / 'build_dir/kernel' / name] = ('kernel-context:' + name).encode()
        for path, data in protected.items(): path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        self.assertEqual(stamp.read_bytes(), b'tailscale\n')
        firmware.package_only_selection(self.profile, self.source)
        self.assertFalse(stamp.exists()); self.assertFalse(flags.exists())
        self.assertEqual((self.source / '.config').read_text(), BASE.replace('CONFIG_PACKAGE_tailscale=y', 'CONFIG_PACKAGE_tailscale=m'))
        for path, data in protected.items(): self.assertEqual(path.read_bytes(), data)
        firmware.verify_package_only(self.profile, self.source)
        original = (self.source / '.config').read_bytes()
        firmware.package_only_selection(self.profile, self.source)
        self.assertEqual((self.source / '.config').read_bytes(), original)

    def test_verification_rejects_reselected_y_or_any_stale_stamp(self):
        self.require_policy()
        with self.assertRaises(ValueError): firmware.verify_package_only(self.profile, self.source)
        firmware.package_only_selection(self.profile, self.source)
        stamp = self.info() / 'tailscale.default.install'; stamp.write_text('tailscale\n')
        with self.assertRaises(ValueError): firmware.verify_package_only(self.profile, self.source)

    def test_all_stamp_owners_are_preflighted_before_any_mutation(self):
        self.require_policy()
        first = self.info('target-first') / 'tailscale.default.install'; first.write_text('tailscale\n')
        second = self.info('target-second') / 'tailscale.default.install'; second.write_text('tailscale\nother\n')
        with self.assertRaises(ValueError): firmware.package_only_selection(self.profile, self.source)
        self.assertEqual((self.source / '.config').read_text(), BASE)
        self.assertEqual(first.read_text(), 'tailscale\n'); self.assertEqual(second.read_text(), 'tailscale\nother\n')

    def test_symlink_stamp_or_target_directory_is_rejected_without_config_changes(self):
        self.require_policy()
        info = self.info(); outside = self.source / 'outside'; outside.write_text('tailscale\n')
        stamp = info / 'tailscale.default.install'; stamp.symlink_to(outside)
        with self.assertRaises(ValueError): firmware.package_only_selection(self.profile, self.source)
        self.assertEqual((self.source / '.config').read_text(), BASE); self.assertEqual(outside.read_text(), 'tailscale\n')
        stamp.unlink(); stamp.write_text('tailscale\n')
        moved = info.parent.with_name('actual-target'); info.parent.rename(moved)
        info.parent.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError): firmware.package_only_selection(self.profile, self.source)
        self.assertEqual((self.source / '.config').read_text(), BASE)

    def test_absent_policy_leaves_source_config_and_install_stamps_untouched(self):
        self.require_policy()
        profile = copy.deepcopy(self.profile); profile.pop('package_only')
        stamp = self.info() / 'tailscale.default.install'; stamp.write_text('tailscale\n')
        firmware.package_only_selection(profile, self.source)
        firmware.verify_package_only(profile, self.source)
        self.assertEqual((self.source / '.config').read_text(), BASE); self.assertEqual(stamp.read_text(), 'tailscale\n')

    @unittest.skipUnless(shutil.which('cc'), 'Native C compiler required')
    def test_real_native_conf_keeps_tail_m_and_other_image_and_kernel_symbols_y(self):
        self.require_policy()
        tools = self.source / 'tools'; tools.mkdir()
        with tarfile.open(ROOT / 'tests/fixtures/openwrt-kconfig-tools-ec9ef10.tar.gz') as archive:
            manifest = json.load(archive.extractfile('fixture-manifest.json'))
            for name, digest in manifest['files'].items():
                data = archive.extractfile(name).read(); self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                target = tools / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        code = tools / 'scripts/config'; conf = tools / 'conf'
        subprocess.run(['cc', '-O0', '-I', str(code), '-o', str(conf)] + [str(code / name) for name in
                        ('conf.c', 'confdata.c', 'expr.c', 'lexer.lex.c', 'menu.c', 'parser.tab.c', 'preprocess.c', 'symbol.c', 'util.c')],
                       check=True, capture_output=True, timeout=30)
        kconfig = self.source / 'Kconfig'
        kconfig.write_text('config MODULES\n\tbool\n\tmodules\n\tdefault y\n' +
            ''.join('config ' + symbol + '\n\tbool\n\tdefault y\n' for symbol in
                    ('KERNEL_ARM64', 'PACKAGE_kmod-mt_wifi', 'PACKAGE_kmod-conninfra', 'PACKAGE_kmod-warp', 'PACKAGE_kmod-mediatek_hnat', 'ALL_KMODS')) +
            'config PACKAGE_curl\n\ttristate "curl"\n\tdefault y\nconfig PACKAGE_tailscale\n\ttristate "Tailscale"\n\tdefault y\n')
        firmware.package_only_selection(self.profile, self.source)
        result = subprocess.run([str(conf), '--olddefconfig', str(kconfig)], cwd=self.source,
                                env={**os.environ, 'KCONFIG_CONFIG': str(self.source / '.config')},
                                check=True, capture_output=True, text=True, timeout=10)
        self.assertNotIn('invalid', result.stderr.lower())
        firmware.verify_package_only(self.profile, self.source)
        values = dict(re.findall(r'^CONFIG_([^=]+)=([my])$', (self.source / '.config').read_text(), re.M))
        self.assertEqual(values['PACKAGE_tailscale'], 'm'); self.assertEqual(values['PACKAGE_curl'], 'y')
        for symbol in ('KERNEL_ARM64', 'PACKAGE_kmod-mt_wifi', 'ALL_KMODS'): self.assertEqual(values[symbol], 'y')


if __name__ == '__main__': unittest.main()
