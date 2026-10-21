"""Actual native keyring metadata; no packages, private keys or publication."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('keyring_publisher',ROOT/'scripts/publish.py')
publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)


class NativeKeyringProvider(unittest.TestCase):
    def setUp(self):
        self.control=json.loads((ROOT/'tests/fixtures/native-openwrt-keyring-control.json').read_text())['control']
        self.profile={'firmware':{'architecture':'aarch64_cortex-a53',
            'kernel_version':'6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1'}}

    def test_actual_keyring_compatibility_provider_is_accepted_without_global_grant(self):
        before=copy.deepcopy(self.control)
        try:
            names=publisher.native_provider_names(self.control,self.profile)
        except ValueError as error:
            self.fail('Actual native compatibility provider was rejected: '+str(error))
        self.assertEqual(names,{'openwrt-keyring','lede-keyring','openwrt-keyring-any'})
        self.assertEqual(self.control,before)
        self.assertNotIn('lede-keyring',publisher.APK_PROTECTED)

    def test_compatibility_alias_is_exact_and_only_for_its_native_base(self):
        other={**self.control,'Package':'usign','APK-Name':'usign','Base-Package':'usign'}
        with self.assertRaisesRegex(ValueError,'unrelated name'):
            publisher.native_provider_names(other,self.profile)
        for provided in ('foreign-keyring','lede-keyring-evil','lede-keyring-any','@lede-keyring'):
            with self.subTest(provided=provided),self.assertRaisesRegex(ValueError,'unrelated name'):
                publisher.native_provider_names({**self.control,'Provides':provided},self.profile)

    def test_existing_provider_grammar_identity_architecture_and_kernel_checks_remain(self):
        invalid=[{'Provides':'lede-keyring (= version with spaces)'}, {'Version':''},
                 {'Architecture':'x86_64'}, {'APK-Name':'different-keyring'}, {'ABIVersion':'1'},
                 {'Depends':'kernel (= 6.12.1~'+'0'*32+'-r1)'}]
        for changed in invalid:
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                publisher.native_provider_names({**self.control,**changed},self.profile)
        core={'Package':'kernel','Base-Package':'kernel','Version':'wrong','Architecture':'aarch64_cortex-a53'}
        with self.assertRaisesRegex(ValueError,'ABI mismatch'):
            publisher.native_provider_names(core,self.profile)


if __name__=='__main__':unittest.main()
