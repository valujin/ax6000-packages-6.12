"""Execute control integration with the real band helper and isolated vendor files."""
import unittest
import test_mesh_sae as sae_tests

class BandControl(unittest.TestCase):
    invoke = sae_tests.SaeControl.invoke

    def test_wireless_agent_band_is_applied_after_merge_on_initial_and_committed_prepare(self):
        for committed in (False,True):
            for band,priorities in ((None,('3','1','1')),('auto',('3','1','1')),('5g',('0','1','1')),('2g',('1','0','0'))):
                with self.subTest(committed=committed,band=band):
                    result,config,_=self.invoke('agent','sae','preflight; prepare; cat "$TEST_MAP"; cat "$TEST_WTS"',selected_band=band,committed=committed)
                    self.assertEqual(result.returncode,0,result.stderr)
                    for key,value in zip(('BhPriority2G','BhPriority5GL','BhPriority5GH'),priorities): self.assertIn(key+'='+value+'\n',result.stdout)
                    self.assertIn('KeepDefault=yes\n',result.stdout)
                    self.assertIn('BhProfile0AuthMode=WPA3PSK\n',result.stdout)
                    self.assertEqual(config['wireless.client0.ssid'],'Home0')
                    self.assertEqual(config['wireless.client1.ssid'],'Home1')
                    if committed: self.assertTrue(result.stdout.endswith('retained-fronthaul-and-backhaul\n'))

    def test_controller_and_wired_agent_do_not_restrict_backhaul_priorities(self):
        for role,backhaul in (('controller','wireless'),('agent','wired')):
            result,_,_=self.invoke(role,'sae','preflight; prepare; cat "$TEST_MAP"',selected_band='2g',backhaul=backhaul)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('BhPriority2G=3\n',result.stdout); self.assertIn('BhPriority5GL=1\n',result.stdout)

    def test_invalid_band_fails_before_any_apply_or_prepare_mutation(self):
        for action in ('apply_mesh','preflight; prepare'):
            for band in ('bad','', '5g;true'):
                result,config,seed=self.invoke('agent','sae',action,selected_band=band)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('Invalid wireless backhaul band.',result.stderr)
                self.assertNotIn('wireless.ax6000_mesh_ap1',config)
                self.assertEqual(seed,'')

    def test_extended_configure_cli_and_legacy_preservation(self):
        for optional,old_security,old_band,expected_security,expected_band in (
            ([],None,None,None,None),([], 'sae','2g','sae','2g'),
            (['psk2'],'sae','5g','psk2','5g'),(['sae','2g'],None,None,'sae','2g')):
            result,config,_=self.invoke('controller',old_security,'',selected_band=old_band,cli=['configure','agent','wireless',*optional])
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(config['ax6000_mesh.main.role'],'agent')
            self.assertEqual(config.get('ax6000_mesh.main.backhaul_security'),expected_security)
            self.assertEqual(config.get('ax6000_mesh.main.backhaul_band'),expected_band)

    def test_invalid_configure_values_leave_all_configuration_unchanged(self):
        for optional in (['open'],['sae','bad'],['sae',''],['sae','auto','extra']):
            result,config,seed=self.invoke('controller','psk2','',selected_band='auto',cli=['configure','agent','wireless',*optional])
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(config['ax6000_mesh.main.role'],'controller')
            self.assertEqual(config['ax6000_mesh.main.backhaul_security'],'psk2')
            self.assertEqual(config['ax6000_mesh.main.backhaul_band'],'auto')
            self.assertEqual(seed,'')
