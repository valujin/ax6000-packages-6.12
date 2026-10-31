"""Actual-UCI accepted overlay cleanup removes only validated bootstrap mutations."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_mesh_network_materialize import UCI
from test_mesh_slot_allocation import LIB, NATIVE

class BootstrapOverlay(unittest.TestCase):
 def setUp(self):
  if not Path(UCI).exists():self.skipTest('native UCI required')
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.state=self.root/'state';self.state.mkdir();self.journal=self.state/'ts-bootstrap';self.journal.mkdir(mode=0o700)
  self.overlay=self.root/'overlay';self.overlay.mkdir();self.bin=self.root/'bin';self.bin.mkdir();(self.bin/'uci').symlink_to(UCI)
  self.before="""config device 'brlan'
 option name 'br-lan'
 option type 'bridge'
 list ports 'lan2'
config interface 'lan'
 option device 'br-lan'
 option proto 'static'
config interface 'wan'
 option proto 'dhcp'
"""
  self.owned="""config bridge-vlan 'ax6000_mesh_management'
 option device 'br-lan'
 option vlan '1'
 option local '1'
 list ports 'lan2:u*'
 list ports 'ra1:u*'
"""
  self.candidate=self.before.replace(" option type 'bridge'"," option type 'bridge'\n option vlan_filtering '1'")+self.owned
  (self.journal/'before-network').write_text(self.before);(self.journal/'network').write_text(self.candidate)
  self.accepted=self.candidate.replace(" option proto 'dhcp'"," option proto 'pppoe'\n option username 'private-user'")+"config interface 'guest'\n option device 'br-lan.10'\n option proto 'static'\n option ipaddr '192.168.10.1'\n"
  (self.overlay/'network').write_text(self.accepted)
  for p in [*self.journal.iterdir(),self.overlay/'network']:p.chmod(0o600)
  validator=self.bin/'ax6000-mesh-managed-bootstrap';validator.write_text('#!/bin/sh\n[ "$1" = validate-journal ] && [ ! -f "$FIXTURE/invalid-journal" ]\n');validator.chmod(0o700)
  text=(LIB/'ax6000-mesh-transaction').read_text();text=text[text.index('strip_bootstrap_network() ('):text.index('adopt_controller_sync() {')]
  text=text.replace('/usr/libexec',str(self.bin)).replace('[ "$(stat -c %u "$input")" = 0 ]','[ "$(stat -c %u "$input")" = '+str(os.getuid())+' ]')
  self.helper=self.root/'helper';self.helper.write_text('set -eu\numask 077\nstate="$FIXTURE/state"\n'+text+'\nstrip_bootstrap_network "$FIXTURE/overlay"\n')
  self.env={**os.environ,'FIXTURE':str(self.root),'PATH':str(self.bin)+':'+os.environ['PATH'],'LD_LIBRARY_PATH':str(NATIVE/'lib')}
 def run_cleanup(self,ok=True):
  before={p.name:p.read_bytes() for p in self.journal.iterdir()};overlay_before=(self.overlay/'network').read_bytes()
  result=subprocess.run(['busybox','ash',str(self.helper)],env=self.env,capture_output=True,text=True)
  self.assertEqual(result.returncode==0,ok,result.stderr);self.assertEqual(before,{p.name:p.read_bytes() for p in self.journal.iterdir()})
  self.assertEqual(result.stdout,'');self.assertNotIn('private-user',result.stderr)
  if not ok:self.assertEqual(overlay_before,(self.overlay/'network').read_bytes())
  return subprocess.run([UCI,'-c',str(self.overlay),'show','network'],env=self.env,capture_output=True,text=True,check=True).stdout
 def test_owned_options_removed_and_guest_wan_edits_preserved(self):
  result=self.run_cleanup();self.assertNotIn('ax6000_mesh_management',result);self.assertNotIn('vlan_filtering',result)
  self.assertIn("network.wan.proto='pppoe'",result);self.assertIn("network.wan.username='private-user'",result)
  self.assertIn("network.guest.device='br-lan.10'",result);self.assertIn("network.guest.ipaddr='192.168.10.1'",result)
 def test_original_explicit_filter_zero_restored(self):
  p=self.journal/'before-network';p.write_text(self.before.replace(" option type 'bridge'"," option type 'bridge'\n option vlan_filtering '0'"))
  self.assertIn("network.brlan.vlan_filtering='0'",self.run_cleanup())
 def test_original_user_filter_one_retained(self):
  p=self.journal/'before-network';p.write_text(self.before.replace(" option type 'bridge'"," option type 'bridge'\n option vlan_filtering '1'"))
  self.assertIn("network.brlan.vlan_filtering='1'",self.run_cleanup())
 def test_user_changed_owned_vlan_section_is_conflict(self):
  p=self.overlay/'network';p.write_text(p.read_text().replace("option vlan '1'","option vlan '2'"));self.run_cleanup(False)
 def test_user_extra_owned_section_option_is_conflict(self):
  p=self.overlay/'network';p.write_text(p.read_text().replace(" option local '1'"," option local '1'\n option user_option 'keep'"));self.run_cleanup(False)
 def test_user_changed_filter_is_conflict(self):
  p=self.overlay/'network';p.write_text(p.read_text().replace("option vlan_filtering '1'","option vlan_filtering '0'"));self.run_cleanup(False)
 def test_invalid_journal_does_not_change_overlay(self):
  (self.root/'invalid-journal').touch();self.run_cleanup(False)
