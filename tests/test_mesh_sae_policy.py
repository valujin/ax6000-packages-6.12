"""A configured SAE agent needs both enrolled SAE credentials and live SAE proof."""
import os
import subprocess
import tempfile
from pathlib import Path
import unittest
import test_mesh_saved_profile as profile_tests

class StrictSavedProfile(unittest.TestCase):
    setUp = profile_tests.SavedBackhaulProfile.setUp
    tearDown = profile_tests.SavedBackhaulProfile.tearDown
    write_profile = profile_tests.SavedBackhaulProfile.write_profile
    check = profile_tests.SavedBackhaulProfile.check

    def policy(self, security, reply='sae=1', rc=0):
        uci=self.root/'bin/uci'
        uci.write_text('#!/bin/sh\nprintf "%s\\n" "$TEST_SECURITY"\n');uci.chmod(0o755)
        cli=self.root/'bin/mapd_cli'
        cli.write_text('#!/bin/sh\n[ "$*" = "/tmp/mapd_ctrl get bh_security" ] || exit 2\nprintf "%s\\n" "$TEST_LINK"\nexit "$TEST_LINK_RC"\n');cli.chmod(0o755)
        self.env.update(TEST_SECURITY=security, TEST_LINK=reply, TEST_LINK_RC=str(rc))

    def test_sae_rejects_wpa2_or_mixed_profile_even_with_sae_link(self):
        self.policy('sae')
        for auth in ('WPA2PSK','WPA2PSKWPA3PSK'):
            self.values['BhProfile0AuthMode']=auth;self.write_profile()
            self.assertNotEqual(self.check().returncode,0)

    def test_sae_requires_live_exact_positive_evidence(self):
        self.values['BhProfile0AuthMode']='WPA3PSK';self.write_profile()
        self.policy('sae'); self.assertEqual(self.check().returncode,0)
        for reply,rc in [('sae=0',0),('',0),('sae=1\nFAIL',0),('sae=1',1)]:
            self.policy('sae',reply,rc);result=self.check()
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout+result.stderr,'')

    def test_legacy_policy_accepts_existing_profiles_without_new_link_command(self):
        self.policy('psk2','',1)
        for auth in ('WPA2PSK','WPA2PSKWPA3PSK','WPA3PSK'):
            self.values['BhProfile0AuthMode']=auth;self.write_profile()
            self.assertEqual(self.check().returncode,0)

    def test_invalid_policy_fails_closed(self):
        self.policy('invalid')
        self.assertNotEqual(self.check().returncode,0)

    def test_saved_prestart_check_requires_sae_but_no_live_link(self):
        self.values['BhProfile0AuthMode']='WPA3PSK';self.write_profile()
        self.policy('sae','',1)
        result=subprocess.run(['sh',str(self.script),'saved'],env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.values['BhProfile0AuthMode']='WPA2PSK';self.write_profile()
        self.assertNotEqual(subprocess.run(['sh',str(self.script),'saved'],env=self.env,capture_output=True).returncode,0)

class StrictInit(unittest.TestCase):
    def invoke(self,role='agent',backhaul='wireless',security='sae',phase='committed',profile_rc=0):
        rootpath=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'bin').mkdir()
            (root/'lib/functions').mkdir(parents=True)
            (root/'lib/functions.sh').write_text('list_contains() { [ "$2" = start ]; }\n')
            (root/'lib/functions/service.sh').write_text('')
            (root/'lib/functions/procd.sh').write_text('''procd_open_service() { :; }
procd_open_instance() { printf 'INSTANCE=%s\\n' "$1"; }
procd_set_param() { [ "$1" != env ] || printf '%s\\n' "$2"; }
procd_close_instance() { :; }
procd_close_service() { :; }
''')
            uci=root/'bin/uci';uci.write_text('''#!/bin/sh
case "$*" in
 *main.enabled) echo 1;; *main.role) echo "$TEST_ROLE";; *main.backhaul) echo "$TEST_BH";;
 *main.backhaul_security) [ "$TEST_SECURITY" != missing ] || exit 1; echo "$TEST_SECURITY";;
esac
''');uci.chmod(0o755)
            marker=root/'phase';marker.write_text(phase+'\n')
            source=(rootpath/'files/mediatek-mesh/packages/ax6000-mesh/files/etc/init.d/ax6000-mesh').read_text()
            source=source.replace('/etc/ax6000-mesh/phase',str(marker))
            for name in ('transaction','control','hairpin','profile'):
                tool=root/name
                body='echo PROFILE=$1; exit "$TEST_PROFILE_RC"' if name=='profile' else 'exit 0'
                tool.write_text('#!/bin/sh\n'+body+'\n');tool.chmod(0o755)
                source=source.replace('/usr/libexec/ax6000-mesh-'+name,str(tool))
            script=root/'init';script.write_text(source)
            return subprocess.run(['busybox','ash',str(rootpath/'tests/fixtures/mesh-runtime/rc.common'),str(script),'start'],
                env={**os.environ,'IPKG_INSTROOT':str(root),'PATH':str(root/'bin')+':'+os.environ['PATH'],
                     'TEST_ROLE':role,'TEST_BH':backhaul,'TEST_SECURITY':security,'TEST_PROFILE_RC':str(profile_rc)},
                capture_output=True,text=True,timeout=5)

    def test_strict_restart_checks_saved_policy_before_any_daemon(self):
        result=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
        self.assertLess(result.stdout.index('PROFILE=saved'),result.stdout.index('INSTANCE=wapp'))
        self.assertIn('AX6000_MESH_BACKHAUL_SECURITY=sae',result.stdout)
        result=self.invoke(profile_rc=1)
        self.assertNotIn('INSTANCE=',result.stdout)

    def test_pending_enrollment_keeps_pbc_available_with_strict_mapd_policy(self):
        result=self.invoke(phase='pending',profile_rc=1)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('PROFILE=',result.stdout)
        self.assertIn('INSTANCE=wapp',result.stdout)
        self.assertIn('AX6000_MESH_BACKHAUL_SECURITY=sae',result.stdout)

    def test_legacy_wired_and_controller_start_without_strict_agent_policy(self):
        for options in ({'security':'missing'},{'security':'psk2'},{'backhaul':'wired'},{'role':'controller'}):
            result=self.invoke(**options)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn('PROFILE=',result.stdout)
            self.assertIn('AX6000_MESH_BACKHAUL_SECURITY=psk2',result.stdout)

    def test_invalid_strict_policy_starts_no_daemons(self):
        result=self.invoke(security='bogus')
        self.assertNotIn('INSTANCE=',result.stdout)
