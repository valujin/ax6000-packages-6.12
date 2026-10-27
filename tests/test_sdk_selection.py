"""SDK baked boolean declarations must survive real Kconfig normalization."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sdk_selection', ROOT / 'scripts/prepare.py')
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


@unittest.skipUnless(shutil.which('cc'), 'host C compiler is required')
class SdkKconfigSelectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools_temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tools_temp.cleanup)
        tools = Path(cls.tools_temp.name)
        with tarfile.open(ROOT / 'tests/fixtures/openwrt-kconfig-tools-ec9ef10.tar.gz', 'r:gz') as archive:
            manifest = json.load(archive.extractfile('fixture-manifest.json'))
            assert manifest['source_commit'] == 'ec9ef10efc65da1e6d1de4e2c043c0e13d08eed8'
            for name, digest in manifest['files'].items():
                data = archive.extractfile(name).read()
                assert hashlib.sha256(data).hexdigest() == digest
                path = tools / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        sources = tools / 'scripts/config'
        cls.conf = tools / 'conf'
        subprocess.run(['cc', '-O0', '-I', str(sources), '-o', str(cls.conf)] +
                       [str(sources / name) for name in ('conf.c', 'confdata.c', 'expr.c',
                        'lexer.lex.c', 'menu.c', 'parser.tab.c', 'preprocess.c', 'symbol.c', 'util.c')],
                       check=True, capture_output=True, timeout=30)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.sdk = Path(self.temporary.name)
        (self.sdk / 'tmp').mkdir()
        self.profile = {'id': 'router', 'packages': ['tailscale', 'wireguard-tools', 'kmod-amneziawg'],
                        'luci_languages': ['ru'], 'all_kmods': False, 'firmware': {}}
        metadata = ''.join(f'config PACKAGE_{name}\n\ttristate "{name}"\n'
                           for name in self.profile['packages'])
        metadata += 'config LUCI_LANG_ru\n\ttristate "Russian"\n'
        metadata += ('config PACKAGE_kmod-mac80211\n\ttristate\n'
                     'config PACKAGE_kmod-dahdi\n\ttristate\n'
                     'config PACKAGE_kmod-crypto-aead\n\ttristate\n')
        metadata = metadata.replace('tristate "kmod-amneziawg"',
                                    'tristate "kmod-amneziawg"\n\tselect PACKAGE_kmod-crypto-aead')
        (self.sdk / 'tmp/.config-package.in').write_text(metadata)
        (self.sdk / 'tmp/.packageinfo').write_text(''.join(
            f'Package: {name}\n\n' for name in self.profile['packages'] +
            ['kmod-mac80211', 'kmod-dahdi', 'kmod-crypto-aead']))
        (self.sdk / '.config').write_text('CONFIG_MODULES=y\nCONFIG_TARGET_mediatek=y\n')
        self.context = {}
        for name, data in [('build_dir/linux/.config', b'CONFIG_ARM64=y\n'),
                           ('build_dir/linux/.vermagic', b'6ea4b96ad26e951cc0b4fa9296a521d3\n'),
                           ('build_dir/linux/Module.symvers', b'0x123\tfixture\tvmlinux\n'),
                           ('build_dir/linux/include/generated/autoconf.h', b'#define CONFIG_ARM64 1\n')]:
            path = self.sdk / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.context[path] = data

    def configure_top(self, baked):
        top = ('config MODULES\n\tbool\n\tmodules\n\tdefault y\n'
               'config SDK\n\tbool\nconfig TARGET_mediatek\n\tbool\n'
               'config ALL\n\tbool\nconfig ALL_KMODS\n\tbool\n'
               'config ALL_NONSHARED\n\tbool\nconfig SIGNED_PACKAGES\n\tbool\n')
        if baked:
            top += 'source "Config-build.in"\n'
        top += 'source "tmp/.config-package.in"\n'
        (self.sdk / 'Config.in').write_text(top)

    def normalize(self, baked):
        result = subprocess.run([str(self.conf), '--olddefconfig', 'Config.in'], cwd=self.sdk,
                                env={**os.environ, 'KCONFIG_CONFIG': '.config'},
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('symbol value', result.stderr)
        self.assertNotIn('invalid', result.stderr)

    def test_baked_sdk_booleans_are_selected_y_and_other_packages_remain_modules(self):
        baked = ('config PACKAGE_tailscale\n\tbool\n\tdefault y\n\n'
                 'config PACKAGE_wireguard-tools\n\tbool\n\tdefault y\n\n'
                 'config LUCI_LANG_ru\n\tbool\n\tdefault y\n\n'
                 'config PACKAGE_kmod-amneziawg\n\ttristate\n\tdefault m\n'
                 'config PACKAGE_kmod-mac80211\n\ttristate\n\tdefault m\n'
                 'config PACKAGE_kmod-dahdi\n\ttristate\n\tdefault m\n'
                 'config PACKAGE_kmod-crypto-aead\n\ttristate\n\tdefault m\n'
                 'config PACKAGE_MAC80211_FOO\n\tbool\n\tdefault y\n')
        snapshot = self.sdk / 'Config-build.in'
        snapshot.write_text(baked)
        self.context[snapshot] = baked.encode()
        self.configure_top(True)
        prepare.select_packages(self.profile, self.sdk)
        selected = (self.sdk / '.config').read_text()
        self.assertIn('CONFIG_PACKAGE_tailscale=y\n', selected)
        self.assertIn('CONFIG_PACKAGE_wireguard-tools=y\n', selected)
        self.assertIn('CONFIG_LUCI_LANG_ru=y\n', selected)
        self.assertIn('CONFIG_PACKAGE_kmod-amneziawg=m\n', selected)
        self.normalize(True)
        normalized = (self.sdk / '.config').read_text()
        self.assertIn('CONFIG_PACKAGE_tailscale=y\n', normalized)
        self.assertIn('CONFIG_PACKAGE_wireguard-tools=y\n', normalized)
        self.assertIn('CONFIG_PACKAGE_kmod-amneziawg=m\n', normalized)
        self.assertIn('CONFIG_PACKAGE_MAC80211_FOO=y\n', normalized)
        self.assertNotIn('config PACKAGE_MAC80211_FOO',
                         (self.sdk / 'ax6000-refresh-defaults.in').read_text())
        report = prepare.verify_selection(self.profile, self.sdk)
        self.assertEqual(report['luci_languages'], {'ru': 'y'})
        self.assertEqual(set(report['selected_packages']), set(self.profile['packages']) | {'kmod-crypto-aead', 'MAC80211_FOO'})
        self.assertNotIn('CONFIG_PACKAGE_kmod-mac80211=m', normalized)
        self.assertNotIn('CONFIG_PACKAGE_kmod-dahdi=m', normalized)
        for path, before in self.context.items():
            self.assertEqual(path.read_bytes(), before)

    def test_frozen_apk_kmods_do_not_restore_requested_or_unrequested_baked_defaults(self):
        self.profile.update(id='redmi-ax6000-612-recommended', channel='recommended',
                            package_manager='apk')
        self.profile['packages'].append('kmod-tun')
        metadata = self.sdk / 'tmp/.config-package.in'
        metadata.write_text(metadata.read_text() +
            'config PACKAGE_kmod-ath9k-common\n\ttristate\n'
            'config PACKAGE_kmod-tun\n\tbool\n'
            'config PACKAGE_apk-openssl\n\tbool\n')
        baked = ('config PACKAGE_kmod-ath9k-common\n\ttristate\n\tdefault m\n'
                 'config PACKAGE_kmod-crypto-aead\n\ttristate\n\tdefault m\n'
                 'config PACKAGE_kmod-tun\n\tbool\n\tdefault y\n'
                 'config PACKAGE_apk-openssl\n\tbool\n\tdefault y\n')
        snapshot = self.sdk / 'Config-build.in'; snapshot.write_text(baked)
        self.context[snapshot] = baked.encode()
        self.configure_top(True)
        baseline = {'kernel': None, 'apk-openssl': None, 'kmod-ath9k-common': None,
                    'kmod-crypto-aead': None, 'kmod-tun': None}
        bank = self.sdk / 'ax6000-baseline'; bank.mkdir()
        (bank / 'manifest.json').write_text(json.dumps({'protected_packages': sorted(baseline)}))
        selected = {'tailscale', 'wireguard-tools', 'kmod-amneziawg'}
        refresh, defaults, config, top = prepare.sdk_refresh_defaults(
            self.profile, self.sdk, baseline, selected)
        refresh.write_text(defaults); config.write_text(top)
        (self.sdk / '.config').write_text('CONFIG_MODULES=y\n' + ''.join(
            f'CONFIG_PACKAGE_{name}=m\n' for name in sorted(selected)))
        self.normalize(True)
        actual = (self.sdk / '.config').read_text()
        self.assertNotIn('CONFIG_PACKAGE_kmod-ath9k-common=m', actual)
        self.assertNotIn('CONFIG_PACKAGE_kmod-ath9k-common=y', actual)
        self.assertIn('CONFIG_PACKAGE_kmod-amneziawg=m\n', actual)
        self.assertIn('CONFIG_PACKAGE_kmod-crypto-aead=m\n', actual)
        self.assertNotIn('CONFIG_PACKAGE_kmod-tun=y\n', actual)
        self.assertNotIn('CONFIG_PACKAGE_kmod-tun=m\n', actual)
        self.assertIn('CONFIG_PACKAGE_apk-openssl=y\n', actual)
        for path, before in self.context.items():
            self.assertEqual(path.read_bytes(), before)

    def test_ordinary_sdk_uses_modules_and_reports_actual_language_selection(self):
        self.configure_top(False)
        prepare.select_packages(self.profile, self.sdk)
        self.normalize(False)
        config = (self.sdk / '.config').read_text()
        for name in self.profile['packages']:
            self.assertIn(f'CONFIG_PACKAGE_{name}=m\n', config)
        self.assertIn('CONFIG_LUCI_LANG_ru=m\n', config)
        self.assertEqual(prepare.verify_selection(self.profile, self.sdk)['luci_languages'], {'ru': 'm'})
        self.assertFalse((self.sdk / 'ax6000-refresh-defaults.in').exists())
        for path, before in self.context.items():
            self.assertEqual(path.read_bytes(), before)

    def baked_fixture(self):
        (self.sdk / 'Config-build.in').write_text(
            'config PACKAGE_tailscale\n\tbool\n\tdefault y\n'
            'config PACKAGE_kmod-mac80211\n\ttristate\n\tdefault m\n')
        self.configure_top(True)

    def test_refresh_defaults_are_idempotent_and_update_for_new_requested_set(self):
        self.baked_fixture()
        prepare.select_packages(self.profile, self.sdk)
        outputs = [self.sdk / 'Config.in', self.sdk / 'ax6000-refresh-defaults.in']
        before = [p.read_bytes() for p in outputs]
        prepare.select_packages(self.profile, self.sdk)
        self.assertEqual([p.read_bytes() for p in outputs], before)
        self.profile['packages'].append('kmod-mac80211')
        prepare.select_packages(self.profile, self.sdk)
        self.assertNotIn('config PACKAGE_kmod-mac80211\n', outputs[1].read_text())
        self.assertEqual(outputs[0].read_text().count('source "ax6000-refresh-defaults.in"'), 1)

    def test_explicit_all_kmods_selection_retains_requested_hidden_candidates(self):
        self.baked_fixture()
        self.profile['all_kmods'] = True
        prepare.select_packages(self.profile, self.sdk)
        self.normalize(True)
        report = prepare.verify_selection(self.profile, self.sdk)
        self.assertIn('kmod-mac80211', report['selected_kmods'])
        self.assertNotIn('config PACKAGE_kmod-mac80211\n',
                         (self.sdk / 'ax6000-refresh-defaults.in').read_text())

    def test_foreign_refresh_file_or_symlink_refuses_before_any_config_changes(self):
        self.baked_fixture()
        output = self.sdk / 'ax6000-refresh-defaults.in'
        for kind in ['foreign', 'symlink']:
            with self.subTest(kind=kind):
                if kind == 'foreign':
                    output.write_text('foreign Kconfig contents\n')
                else:
                    output.symlink_to(self.sdk / 'tmp/.config-package.in')
                before = {p: p.read_bytes() for p in [self.sdk / '.config', self.sdk / 'Config.in',
                                                     self.sdk / 'Config-build.in']}
                with self.assertRaises(ValueError):
                    prepare.select_packages(self.profile, self.sdk)
                self.assertEqual({p: p.read_bytes() for p in before}, before)
                output.unlink()

    def test_config_or_report_symlink_refuses_before_refresh_outputs_are_written(self):
        self.baked_fixture()
        original = (self.sdk / '.config').read_bytes()
        config_in = (self.sdk / 'Config.in').read_bytes()
        for name in ['.config', 'Config.in', 'Config-build.in', 'build-selection.json']:
            with self.subTest(name=name):
                path = self.sdk / name
                saved = path.read_bytes() if path.exists() else None
                if path.exists():
                    path.unlink()
                path.symlink_to(self.sdk / 'tmp/.config-package.in')
                with self.assertRaises(ValueError):
                    prepare.select_packages(self.profile, self.sdk)
                self.assertFalse((self.sdk / 'ax6000-refresh-defaults.in').exists())
                path.unlink()
                if saved is not None:
                    path.write_bytes(saved)
                self.assertEqual((self.sdk / '.config').read_bytes(), original)
                self.assertEqual((self.sdk / 'Config.in').read_bytes(), config_in)

    def test_ambiguous_or_misplaced_sources_refuse_without_creating_refresh_file(self):
        self.baked_fixture()
        original = (self.sdk / 'Config.in').read_text()
        cases = [original + 'source "Config-build.in"\n',
                 'source "ax6000-refresh-defaults.in"\n' + original,
                 original.replace('source "Config-build.in"', "source 'Config-build.in'"),
                 original.replace('source "Config-build.in"', '')]
        for text in cases:
            with self.subTest(text=text):
                (self.sdk / 'Config.in').write_text(text)
                before = (self.sdk / '.config').read_bytes()
                with self.assertRaises(ValueError):
                    prepare.select_packages(self.profile, self.sdk)
                self.assertEqual((self.sdk / '.config').read_bytes(), before)
                self.assertEqual((self.sdk / 'Config.in').read_text(), text)
                self.assertFalse((self.sdk / 'ax6000-refresh-defaults.in').exists())

    def test_baked_language_still_requires_available_feed_language_metadata(self):
        (self.sdk / 'Config-build.in').write_text('config LUCI_LANG_ru\n\tbool\n\tdefault y\n')
        metadata = self.sdk / 'tmp/.config-package.in'
        metadata.write_text(metadata.read_text().replace('config LUCI_LANG_ru\n\ttristate "Russian"\n', ''))
        before = (self.sdk / '.config').read_bytes()
        with self.assertRaisesRegex(ValueError, 'LuCI languages absent'):
            prepare.select_packages(self.profile, self.sdk)
        self.assertEqual((self.sdk / '.config').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
