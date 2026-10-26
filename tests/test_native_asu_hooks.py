"""Native ASU hooks: enforce opt-in and retain independently published IB assets.

Seed provenance: SHA256 of canonical UTF-8 JSON containing recipe_contract
ax6000-native-asu-v1, monitor.recipe_digest() (scripts/workflows/ASU assets) and
the complete source profile with only asu.seed omitted.
The source SDK URL/hash and kernel ABI are still null; there is no SDK-hash cycle.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('native_asu_hooks', ROOT / 'scripts/prepare-firmware.py')
firmware = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(firmware)


class NativeAsuTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / 'source'; self.source.mkdir()
        self.profile = {'schema_version': 1, 'id': 'native-asu-fixture', 'enabled': True,
                        'firmware': {'repository': 'https://example.org/source.git', 'commit': 'a' * 40,
                                     'device': 'xiaomi_redmi-router-ax6000-stock',
                                     'kernel_version': None, 'target': 'mediatek', 'subtarget': 'filogic',
                                     'architecture': 'aarch64_cortex-a53'},
                        'sdk': {'url': None, 'sha256': None},
                        'build_source': {'defconfig': 'vendor.config', 'device': 'xiaomi_redmi-router-ax6000-stock'},
                        'feeds': [{'name': 'packages', 'url': 'https://example.org/packages.git', 'commit': 'c' * 40}],
                        'packages': ['tailscale', 'attendedsysupgrade-common', 'luci-app-attendedsysupgrade',
                                     'luci-i18n-attendedsysupgrade-ru'],
                        'image_packages': ['attendedsysupgrade-common', 'luci-app-attendedsysupgrade',
                                           'luci-i18n-attendedsysupgrade-ru'],
                        'package_only': ['tailscale'], 'all_kmods': True,
                        'publication': {'repository': 'valujin/ax6000-packages', 'firmware_assets': 'github-release'},
                        'asu': {'enabled': True, 'cohort': '66', 'server_url': 'https://asu.ezon.by/66', 'seed': 'd' * 64}}
        self.profile['asu']['seed'] = firmware.native_seed(self.profile)
        self.lock = {'feeds': {'packages': 'c' * 40}}
        self.baseline = ('CONFIG_BUILDBOT=y\n# CONFIG_IB is not set\n# CONFIG_IB_STANDALONE is not set\n'
                         'CONFIG_USE_APK=y\nCONFIG_PACKAGE_apk=y\nCONFIG_KERNEL_FIXED=y\n')
        (self.source / 'vendor.config').write_text(self.baseline)

    def test_configure_selects_standalone_signed_opkg_ib_and_writes_cohort(self):
        firmware.configure(self.profile, self.lock, self.source)
        config = (self.source / '.config').read_text()
        for line in ['CONFIG_IB=y', 'CONFIG_IB_STANDALONE=y', 'CONFIG_SIGNATURE_CHECK=y',
                     'CONFIG_PACKAGE_opkg=y', '# CONFIG_BUILDBOT is not set', '# CONFIG_USE_APK is not set',
                     '# CONFIG_PACKAGE_apk is not set', 'CONFIG_KERNEL_FIXED=y']:
            self.assertIn(line + '\n', config)
        identity = json.loads((self.source / 'files/etc/asu-cohort.json').read_text())
        self.assertEqual(identity, {'schema_version': 1, 'cohort': '66', 'package_manager': 'opkg', 'seed': self.profile['asu']['seed']})
        self.assertIn("https://asu.ezon.by/66", (self.source / 'files/etc/uci-defaults/99-ax6000-asu').read_text())
        firmware.verify_asu(self.profile, self.source)
        (self.source / '.config').write_text(config.replace('CONFIG_IB_STANDALONE=y', '# CONFIG_IB_STANDALONE is not set'))
        with self.assertRaisesRegex(ValueError, 'IB_STANDALONE'):
            firmware.verify_asu(self.profile, self.source)

    def test_missing_client_package_and_wrong_cohort_fail_before_configure(self):
        self.profile['image_packages'].remove('luci-i18n-attendedsysupgrade-ru')
        with self.assertRaisesRegex(ValueError, 'ASU.*packages'):
            firmware.configure(self.profile, self.lock, self.source)
        self.assertFalse((self.source / '.config').exists())
        self.profile['image_packages'].append('luci-i18n-attendedsysupgrade-ru')
        self.profile['asu'].update(cohort='612-latest', server_url='https://asu.ezon.by/612/latest')
        with self.assertRaisesRegex(ValueError, 'cohort'):
            firmware.configure(self.profile, self.lock, self.source)

    def test_changed_source_profile_requires_a_new_recipe_seed_before_writes(self):
        self.profile['all_kmods'] = False
        with self.assertRaisesRegex(ValueError, 'seed'):
            firmware.configure(self.profile, self.lock, self.source)
        self.assertFalse((self.source / '.config').exists())

    def test_apk_channel_configuration_selects_native_apk_and_keyring(self):
        profile = json.loads((ROOT / 'profiles/redmi-ax6000-612-recommended-new.json').read_text())
        profile['package_manager'] = 'apk'
        values = firmware.source_symbols(profile)
        config = firmware.set_symbols('CONFIG_PACKAGE_opkg=y\n# CONFIG_USE_APK is not set\n', values)
        for line in ['CONFIG_USE_APK=y', 'CONFIG_PACKAGE_apk-openssl=y', 'CONFIG_PACKAGE_openwrt-keyring=y',
                     '# CONFIG_PACKAGE_opkg is not set', '# CONFIG_PACKAGE_apk-mbedtls is not set']:
            self.assertIn(line + '\n', config)
        legacy = copy.deepcopy(profile); legacy.pop('package_manager')
        legacy.pop('mediatek_mesh', None)  # Historical opkg behavior has no mesh opt-in.
        self.assertEqual(firmware.source_symbols(legacy)['USE_APK'], 'n')
        self.assertEqual(firmware.source_symbols(legacy)['PACKAGE_opkg'], 'y')

    def test_legacy_profile_keeps_baseline_ib_and_package_manager_selection(self):
        del self.profile['asu']
        firmware.configure(self.profile, self.lock, self.source)
        config = (self.source / '.config').read_text()
        for line in self.baseline.splitlines():
            self.assertIn(line + '\n', config)
        self.assertFalse((self.source / 'files/etc/asu-cohort.json').exists())

    def test_sdk_firmware_bank_excludes_imagebuilder_without_removing_native_asset(self):
        target = self.source / 'bin/targets/mediatek/filogic'; target.mkdir(parents=True)
        names = ['immortalwrt-imagebuilder-mediatek-filogic.Linux-x86_64.tar.zst',
                 'firmware.bin', 'sdk.tar.xz', 'sha256sums', 'incomplete.partial']
        for name in names:
            (target / name).write_bytes(b'asset')
        selected = firmware.firmware_bank_assets(target / 'sdk.tar.xz')
        self.assertEqual([path.name for path in selected], ['firmware.bin'])
        self.assertTrue((target / names[0]).is_file())

    def test_export_records_actual_transformed_ib_and_immutable_generation_url(self):
        target = self.source / 'bin/targets/mediatek/filogic'; target.mkdir(parents=True)
        archive = target / 'immortalwrt-imagebuilder-mediatek-filogic.Linux-x86_64.tar.gz'
        archive.write_bytes(b'native imagebuilder')
        generated = copy.deepcopy(self.profile)
        generated.update(build_id='native-asu-abcdef123456')
        generated['firmware']['kernel_version'] = '6.6.1~' + 'a' * 32 + '-r0'
        def transform(profile, source, actual, **kwargs):
            self.assertEqual(profile['build_id'], 'native-asu-abcdef123456')
            self.assertEqual(actual, archive)
            self.assertEqual(kwargs['public_key'], ROOT / 'keys/repository.pub')
            self.assertEqual(kwargs['signing_key'], self.source / 'key-build')
            self.assertEqual(kwargs['native_public_key'], self.source / 'key-build.pub')
            self.assertIs(kwargs['normalizer'], firmware.normalize_local_sdk)
            actual.write_bytes(b'exported immutable imagebuilder')
            return {'sha256': hashlib.sha256(actual.read_bytes()).hexdigest(), 'size': actual.stat().st_size}
        helper = firmware.sibling_module('imagebuilder')
        with mock.patch.object(helper, 'export_archive', side_effect=transform):
            firmware.export_imagebuilder(generated, self.source, helper=helper)
        self.assertEqual(generated['imagebuilder'], {
            'url': 'https://github.com/valujin/ax6000-packages/releases/download/firmware-native-asu-abcdef123456/' + archive.name,
            'sha256': hashlib.sha256(b'exported immutable imagebuilder').hexdigest(), 'size': 31})
        (target / 'extra-imagebuilder.tar.gz').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            firmware.export_imagebuilder(generated, self.source, helper=helper)


if __name__ == '__main__':
    unittest.main()
