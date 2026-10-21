"""Optional package patches must validate before mutations and preserve legacy SDKs."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/prepare.py'
spec = importlib.util.spec_from_file_location('prepare_package_hook_test', SCRIPT)
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class OptionalPackageHookTests(unittest.TestCase):
    def profile(self):
        return {'schema_version': 1, 'id': 'router', 'enabled': True,
                'firmware': {'repository': 'https://example.com/firmware.git', 'commit': 'a' * 40,
                    'kernel_version': '6.6.133~' + 'b' * 32 + '-r1', 'target': 'mediatek',
                    'subtarget': 'filogic', 'architecture': 'aarch64_cortex-a53'},
                'sdk': {'url': 'https://example.com/sdk.tar.xz', 'sha256': 'c' * 64},
                'feeds': [{'name': 'packages', 'url': 'https://github.com/immortalwrt/packages.git',
                           'commit': 'd' * 40}], 'packages': ['pbr']}

    def test_legacy_validation_and_apply_do_not_load_optional_modules(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(prepare, 'optional_package_module') as load:
            prepare.validate(self.profile(), {})
            prepare.apply_overrides({}, Path(directory), self.profile())
            load.assert_not_called()

    def test_vendor_switch_requires_a_real_boolean_before_mutation(self):
        for value in ('true', 1, None, [], {}):
            profile = self.profile(); profile['vendor_country_db'] = value
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, 'vendor_country_db'):
                    prepare.validate(profile, {})
                with patch.object(prepare, 'optional_package_module') as load:
                    with self.assertRaisesRegex(ValueError, 'vendor_country_db'):
                        prepare.apply_overrides({}, Path(directory), profile)
                    load.assert_not_called()

    def test_disabled_vendor_switch_does_not_import_or_patch(self):
        profile = self.profile(); profile['vendor_country_db'] = False
        with tempfile.TemporaryDirectory() as directory, patch.object(prepare, 'optional_package_module') as load:
            prepare.validate(profile, {})
            prepare.apply_overrides({}, Path(directory), profile)
            load.assert_not_called()

    def test_asu_policy_is_validated_before_any_package_patch(self):
        profile = self.profile(); profile.update(asu={'enabled': False}, vendor_country_db=True)
        def reject(value): raise ValueError('invalid ASU enabled policy')
        module = SimpleNamespace(policy=reject)
        with patch.object(prepare, 'optional_package_module', return_value=module):
            with self.assertRaisesRegex(ValueError, 'ASU enabled'): prepare.validate(profile, {})
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, 'ASU enabled'):
                    prepare.apply_overrides({}, Path(directory), profile)

    def test_real_asu_policy_enabled_contract_is_checked_by_prepare(self):
        profile = self.profile()
        profile['asu'] = {'enabled': False, 'cohort': '66', 'server_url': 'https://asu.ezon.by/66',
                          'seed': 'a' * 64}
        with self.assertRaisesRegex(ValueError, 'enabled:true'): prepare.validate(profile, {})
        profile['asu']['enabled'] = True
        self.assertIs(prepare.validate(profile, {}), profile)

    def test_pbr_country_asu_apply_order_and_exact_arguments(self):
        profile = self.profile(); profile.update(pbr_source='mossdef-stable', vendor_country_db=True,
                                               asu={'enabled': True})
        events = []; sdk = Path('/fixture-sdk'); lock = {'fixture': True}
        pbr = SimpleNamespace(apply=lambda *args: events.append(('pbr', args)))
        country = SimpleNamespace(apply_vendor_country_patch=lambda *args: events.append(('country', args)))
        asu = SimpleNamespace(policy=lambda value: value['asu'],
                              apply=lambda *args: events.append(('asu', args)))
        with patch.object(prepare, 'pbr_source_module', return_value=pbr), patch.object(
                prepare, 'optional_package_module', side_effect=lambda name: {'vendor_country': country, 'asu_client': asu}[name]):
            prepare.apply_overrides(lock, sdk, profile)
        self.assertEqual(events, [('pbr', (profile, lock, sdk)), ('country', (sdk,)), ('asu', (profile, sdk))])

    def test_sibling_helpers_load_by_exact_path(self):
        for name in ('vendor_country', 'asu_client'):
            with self.subTest(name=name):
                module = prepare.optional_package_module(name)
                self.assertEqual(Path(module.__file__).resolve(), SCRIPT.with_name(name + '.py').resolve())
        with self.assertRaises(ValueError): prepare.optional_package_module('../foreign')


if __name__ == '__main__': unittest.main()
