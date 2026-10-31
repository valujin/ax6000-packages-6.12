"""Bootstrap derives private local contracts without creating packet evidence."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_mesh_slot_allocation import LIB,NATIVE

class Provision(unittest.TestCase):
 def setUp(self):
  if not (NATIVE/'bin/jshn').exists(): self.skipTest('native jshn required')
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)
  for name in ['state','bin','members']: (self.root/name).mkdir()
  self.state=self.root/'state'; self.bin=self.root/'bin'
  for name,text in [('state/phase','committed'),('state/role','agent'),('state/backhaul','wireless'),('role','agent'),('backhaul','wireless'),('boot','11111111-2222-3333-4444-555555555555'),('network',''),('vlans','[{"ifname":"br-lan","vlans":[{"vlan":1}]}]')]: (self.root/name).write_text(text)
  self.proof=self.root/'proof'; self.proof.write_text(json.dumps(dict(schema=2,quarantine_vid=4093,packet_tested=True))); self.proof.chmod(0o600)
  self.status=dict(topology_valid=True,connected=True,local_alid='02:00:00:00:00:01',controller_alid='02:00:00:00:00:ff')
  for member in ['lan2','ra0','rax0','apcli0']: (self.root/'members'/member).touch()
  stub=self.bin/'stub';stub.write_text('''#!/usr/bin/env python3
import os,sys,pathlib
r=pathlib.Path(os.environ['FIXTURE']); n=pathlib.Path(sys.argv[0]).name; a=sys.argv[1:]
with (r/'calls').open('a') as f:f.write(n+' '+' '.join(a)+'\\n')
if n=='ax6000-mesh-ts-capability':sys.exit(1 if (r/'proof-fail').exists() else 0)
if n=='ax6000-mesh-vendor':print((r/'status').read_text())
elif n=='bridge':print((r/'vlans').read_text())
elif n=='uci':
 if 'show' in a:print((r/'network').read_text())
 else:
  values={'ax6000_mesh.main.enabled':'1','ax6000_mesh.main.role':(r/'role').read_text(),'ax6000_mesh.main.backhaul':(r/'backhaul').read_text()}
  print(values.get(a[-1],''))
''');stub.chmod(0o700)
  for name in ['uci','bridge','ax6000-mesh-vendor','ax6000-mesh-ts-capability']:(self.bin/name).symlink_to(stub)
  text=(LIB/'ax6000-mesh-ts-provision').read_text()
  for old,new in [('/etc/ax6000-mesh-dataplane-capability.json',str(self.proof)),('/etc/ax6000-mesh',str(self.state)),('/usr/libexec',str(self.bin)),('/sys/class/net/br-lan/brif',str(self.root/'members')),('/proc/sys/kernel/random/boot_id',str(self.root/'boot')),('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh'))]:text=text.replace(old,new)
  text=text.replace('[ "$(id -u)" = 0 ]','[ "$(id -u)" = '+str(os.getuid())+' ]').replace('[ "$(stat -c %u "$1")" = 0 ]','[ "$(stat -c %u "$1")" = '+str(os.getuid())+' ]')
  text=text.replace('[ "$(stat -c %u "$proof")" = 0 ]','[ "$(stat -c %u "$proof")" = '+str(os.getuid())+' ]')
  self.helper=self.root/'helper';self.helper.write_text(text)
  self.env={**os.environ,'FIXTURE':str(self.root),'PATH':str(self.bin)+':'+str(NATIVE/'bin')+':'+os.environ['PATH'],'LD_LIBRARY_PATH':str(NATIVE/'lib')}
 def run_helper(self,ok=True):
  (self.root/'status').write_text(json.dumps(self.status)); proof=self.proof.read_bytes()
  p=subprocess.run(['busybox','ash',str(self.helper),'bootstrap'],env=self.env,capture_output=True,text=True)
  self.assertEqual(p.returncode==0,ok,p.stderr);self.assertEqual(p.stdout,'');self.assertEqual(self.proof.read_bytes(),proof)
  calls=(self.root/'calls').read_text().splitlines();self.assertEqual(calls[0],'ax6000-mesh-ts-capability ')
  self.assertTrue(all(not x.startswith('bridge ') or x=='bridge -j vlan show' for x in calls))
  return json.loads((self.state/'ts-transport.json').read_text()) if ok else None
 def test_agent_binding_and_idempotent_preservation(self):
  data=self.run_helper();self.assertEqual(data['trunk_ifnames'],['apcli0']);self.assertEqual(set(data['management_ifnames']),{'lan2','ra0','rax0','apcli0'})
  self.assertEqual(data['quarantine_vid'],4093)
  saved={name:(self.state/name).read_bytes() for name in ['ts-capabilities.json','ts-transport.json']}
  for name in saved:self.assertEqual((self.state/name).stat().st_mode&0o777,0o600)
  self.assertNotIn('packet_tested',(self.state/'ts-provision-binding.json').read_text())
  self.run_helper()
  for name,value in saved.items():self.assertEqual((self.state/name).read_bytes(),value)
 def test_release_failure_never_creates_contracts(self):
  (self.root/'proof-fail').touch();self.run_helper(False);self.assertFalse((self.state/'ts-transport.json').exists())
 def test_unknown_bridge_member_rejected(self):
  (self.root/'members/wan').touch();self.run_helper(False)
 def test_vlan_range_collision_rejected(self):
  (self.root/'vlans').write_text('[{"ifname":"lan2","vlans":[{"vlan":4090,"vlanEnd":4094}]}]');self.run_helper(False)
 def test_network_collision_rejected(self):
  (self.root/'network').write_text("network.guest.device='br-lan.4093'");self.run_helper(False)
 def test_disconnected_topology_rejected(self):
  self.status['connected']=False;self.run_helper(False)
 def test_existing_controller_binding_never_overwritten(self):
  self.run_helper();(self.state/'ts-provision-binding.json').unlink();old=(self.state/'ts-transport.json').read_bytes();self.status['controller_alid']='02:00:00:00:00:ee';self.run_helper(False)
  self.assertEqual((self.state/'ts-transport.json').read_bytes(),old)
 def test_changed_member_inventory_never_overwritten(self):
  self.run_helper();(self.state/'ts-provision-binding.json').unlink();old=(self.state/'ts-transport.json').read_bytes();(self.root/'members/lan3').touch();self.run_helper(False)
  self.assertEqual((self.state/'ts-transport.json').read_bytes(),old)
 def test_controller_uses_existing_backhaul_ap_trunk(self):
  (self.root/'role').write_text('controller');(self.state/'role').write_text('controller');self.status['local_alid']=self.status['controller_alid']
  (self.root/'members/apcli0').unlink();(self.root/'members/ra1').touch();self.assertEqual(self.run_helper()['trunk_ifnames'],['ra1'])
 def test_wired_enrollment_rejected(self):
  (self.root/'backhaul').write_text('wired');self.run_helper(False)

 def test_bound_reboot_without_native_topology_preserves_management_authority(self):
  self.run_helper();before={p.name:p.read_bytes() for p in self.state.iterdir()}
  (self.root/'boot').write_text('22222222-3333-4444-5555-666666666666');self.status['connected']=False
  for p in (self.root/'members').iterdir():p.unlink()
  (self.root/'calls').write_text('');self.run_helper()
  self.assertEqual(before,{p.name:p.read_bytes() for p in self.state.iterdir()});self.assertNotIn('ax6000-mesh-vendor',(self.root/'calls').read_text())
 def test_bound_active_guests_do_not_rebuild_transport(self):
  self.run_helper();old=(self.state/'ts-transport.json').read_bytes();(self.root/'members/ra2').touch();self.run_helper()
  self.assertEqual(old,(self.state/'ts-transport.json').read_bytes())
 def test_modified_bound_contract_is_rejected(self):
  self.run_helper();p=self.state/'ts-transport.json';p.write_text(p.read_text()+' ');self.run_helper(False)
 def test_modified_release_requires_new_binding(self):
  self.run_helper();self.proof.write_text(self.proof.read_text()+' ');self.run_helper(False)

 def test_public_readable_release_proof_accepted(self):
  self.proof.chmod(0o644);self.run_helper()
  self.assertEqual(self.proof.stat().st_mode&0o777,0o644)
  for name in ['ts-capabilities.json','ts-transport.json','ts-provision-binding.json']:
   self.assertEqual((self.state/name).stat().st_mode&0o777,0o600)
 def test_group_writable_release_proof_rejected(self):
  self.proof.chmod(0o664);self.run_helper(False)
