"""Real BusyBox coordinator and native UCI candidates; lifecycle commands isolated."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_mesh_slot_allocation import LIB,NATIVE
from test_mesh_network_materialize import UCI

@unittest.skipUnless(Path(UCI).exists() and (NATIVE/'bin/jshn').exists(),'Native host UCI/jshn required')
class ManagedBootstrap(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  for n in ['config','state','bin','bridge']:(self.root/n).mkdir()
  self.config=self.root/'config';self.state=self.root/'state';self.bin=self.root/'bin'
  (self.config/'network').write_text("config device 'bridge'\n option name 'br-lan'\n option type 'bridge'\n list ports 'lan1'\nconfig interface 'lan'\n option device 'br-lan'\n option proto 'static'\n option ipaddr '192.168.10.1'\n")
  (self.config/'ax6000_mesh').write_text("config mesh 'main'\n option enabled '1'\n option role 'controller'\n option backhaul 'wired'\n")
  (self.state/'phase').write_text('committed\n');(self.state/'original-network').write_text('immutable')
  for n in ['ts-capabilities.json','ts-dataplane-capability.json']:(self.state/n).write_text('{"schema":1}')
  (self.state/'ts-transport.json').write_text(json.dumps({'schema':2,'bridge':'br-lan','management_vid':1,'quarantine_vid':4090,'management_ifnames':['lan1','ra0','ra1'],'trunk_ifnames':['ra1'],'guest_ports':[],'cpu_guest_links':[]}))
  for p in [*self.state.iterdir(),*self.config.iterdir()]:p.chmod(0o600)
  (self.root/'bridge/vlan_filtering').write_text('0');(self.root/'bridge/default_pvid').write_text('1')
  (self.root/'calls').write_text('')
  u=self.bin/'uci';u.write_text('#!/bin/sh\nexec '+UCI+' -c '+str(self.config)+' -t '+str(self.root/'uci-delta')+' "$@"\n');u.chmod(0o700)
  stub=self.bin/'stub';stub.write_text(r'''#!/usr/bin/python3
import json,os,pathlib,subprocess,sys
r=pathlib.Path(os.environ['BOOTSTRAP_FIXTURE']);n=pathlib.Path(sys.argv[0]).name;a=sys.argv[1:]
with (r/'calls').open('a') as f:f.write(json.dumps([n,*a])+'\n')
if (r/('fail-'+n+'-'+(a[0] if a else ''))).exists():sys.exit(1)
if n=='ax6000-mesh-ts-capability' and (r/'no-proof').exists():sys.exit(1)
if n=='ax6000-mesh-bootstrap-bridge':
 if a[0] in ('plan','plan-recover'):
  t=json.loads(pathlib.Path(a[1]).read_text());pathlib.Path(a[2]).write_text(json.dumps({'schema':1,'transport':t,'identities':{k:{'ifindex':i} for i,k in enumerate(['br-lan','lan1','ra0','ra1'])}}));pathlib.Path(a[2]).chmod(0o600)
 elif a[0] in ('apply','rollback'):
  (r/'bridge/vlan_filtering').write_text('1' if a[0]=='apply' else '0');(r/'bridge/default_pvid').write_text('0' if a[0]=='apply' else '1')
elif n=='ax6000-mesh-transaction' and a[:1]==['adopt-managed-bootstrap']:
 p=subprocess.run(['busybox','ash',str(r/'helper'),'validate',*a[1:]],env=os.environ);sys.exit(p.returncode)
elif n in ['ax6000-mesh-controller-sync','ax6000-mesh-agent-sync'] and a==['once']:
 import fcntl
 with (r/'radio-lock').open('a') as lock:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 assert (r/'bridge/vlan_filtering').read_text()=='1'
 assert (r/'bridge/default_pvid').read_text()=='0'
 assert "option linux_ts '1'" in (r/'config/ax6000_mesh').read_text()
''');stub.chmod(0o700)
  for n in ['ax6000-mesh-ts-capability','ax6000-mesh-ts-provision','ax6000-mesh-ts-supervise','ax6000-mesh-bootstrap-bridge','ax6000-mesh-controller-sync','ax6000-mesh-agent-sync','ax6000-mesh-transaction','ax6000-mesh-ts-runtime','mesh-sync-service','wifi']:(self.bin/n).symlink_to(stub)
  text=(LIB/'ax6000-mesh-managed-bootstrap').read_text()
  for old,new in [('/etc/ax6000-mesh',str(self.state)),('/usr/libexec',str(self.bin)),('/etc/config',str(self.config)),('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh')),('/sys/class/net/br-lan/bridge',str(self.root/'bridge')),('/var/lock/ax6000-mesh.lock',str(self.root/'lock')),('/var/run/ax6000-mesh-managed-status.json',str(self.root/'status')),('/etc/init.d/ax6000-mesh-sync',str(self.bin/'mesh-sync-service')),('/sbin/wifi',str(self.bin/'wifi'))]:text=text.replace(old,new)
  text=text.replace('= 0:700 ]','= '+str(os.getuid())+':700 ]')
  text=text.replace('/var/lock/ax6000-mesh-bootstrap.lock',str(self.root/'bootstrap-lock')).replace('/var/lock/mtwifi.lock',str(self.root/'radio-lock'))
  text=text.replace('[ "$(id -u)" = 0 ]','[ "$(id -u)" = '+str(os.getuid())+' ]').replace('[ "$(stat -c %u "$1")" = 0 ]','[ "$(stat -c %u "$1")" = '+str(os.getuid())+' ]')
  self.helper=self.root/'helper';self.helper.write_text(text)
  self.env={**os.environ,'BOOTSTRAP_FIXTURE':str(self.root),'PATH':str(self.bin)+':'+str(NATIVE/'bin')+':'+os.environ['PATH'],'LD_LIBRARY_PATH':str(NATIVE/'lib')}
 def run_bootstrap(self,op='once',ok=True):
  p=subprocess.run(['busybox','ash',str(self.helper),op],env=self.env,capture_output=True,text=True,timeout=25)
  self.assertEqual(p.returncode==0,ok,p.stderr);self.assertEqual(p.stdout,'');self.assertEqual((self.state/'original-network').read_text(),'immutable')
  return [json.loads(x) for x in (self.root/'calls').read_text().splitlines()]
 def test_missing_proof_retains_working_enrollment(self):
  before={p.name:p.read_bytes() for p in self.config.iterdir()};(self.root/'no-proof').touch();calls=self.run_bootstrap()
  self.assertEqual(before,{p.name:p.read_bytes() for p in self.config.iterdir()});self.assertFalse((self.state/'ts-bootstrap').exists())
  self.assertEqual(json.loads((self.root/'status').read_text())['phase'],'unsupported')
  self.assertFalse(any(c[0] in ['ax6000-mesh-bootstrap-bridge','ax6000-mesh-controller-sync'] for c in calls))
 def test_complete_candidate_adopted_before_worker_and_no_ack_claim(self):
  calls=self.run_bootstrap();self.assertLess(calls.index(['ax6000-mesh-transaction','adopt-managed-bootstrap']),calls.index(['ax6000-mesh-controller-sync','once']))
  self.assertIn(['ax6000-mesh-controller-sync','preflight','4090'],calls)
  network=(self.config/'network').read_text();self.assertIn("option ipaddr '192.168.10.1'",network);self.assertIn("list ports 'lan1:u*'",network)
  self.assertNotIn('applied',json.loads((self.root/'status').read_text()));self.assertEqual((self.state/'ts-bootstrap/before-network').stat().st_mode&0o777,0o600)
 def test_failed_preflight_has_no_kernel_or_config_writes(self):
  before=(self.config/'network').read_bytes();(self.root/'fail-ax6000-mesh-controller-sync-preflight').touch();calls=self.run_bootstrap(ok=False)
  self.assertEqual(before,(self.config/'network').read_bytes());self.assertNotIn(['ax6000-mesh-bootstrap-bridge','apply',str(self.state/'ts-bootstrap/bridge-plan.json')],calls)
 def test_adoption_failure_restores_exact_files_and_bridge_before_pool(self):
  before={p.name:p.read_bytes() for p in self.config.iterdir()};(self.root/'fail-ax6000-mesh-transaction-adopt-managed-bootstrap').touch();calls=self.run_bootstrap(ok=False)
  self.assertEqual(before,{p.name:p.read_bytes() for p in self.config.iterdir()});self.assertEqual((self.root/'bridge/vlan_filtering').read_text(),'0');self.assertNotIn(['ax6000-mesh-controller-sync','once'],calls)
 def test_validate_rejects_unrelated_candidate_or_live_edit(self):
  self.run_bootstrap();p=self.state/'ts-bootstrap/network';p.write_text(p.read_text()+"\nconfig interface 'bad'\n option proto 'dhcp'\n")
  self.run_bootstrap('validate',False)
 def test_worker_failure_retains_managed_pending_for_existing_journal_recovery(self):
  (self.root/'fail-ax6000-mesh-controller-sync-once').touch();self.run_bootstrap(ok=False)
  self.assertIn("option linux_ts '1'",(self.config/'ax6000_mesh').read_text());self.assertEqual(json.loads((self.root/'status').read_text())['phase'],'pending')
  (self.root/'fail-ax6000-mesh-controller-sync-once').unlink();self.run_bootstrap()
 def test_pending_enrollment_is_noop(self):
  (self.state/'phase').write_text('pending');self.assertEqual(self.run_bootstrap(),[])

 def test_reboot_repairs_bridge_before_reload_and_existing_policy_worker(self):
  self.run_bootstrap();(self.root/'calls').write_text('');(self.root/'bridge/default_pvid').write_text('1')
  calls=self.run_bootstrap()
  repair=next(i for i,c in enumerate(calls) if c[:2]==['ax6000-mesh-bootstrap-bridge','apply'])
  self.assertLess(repair,calls.index(['wifi','reload']))
  self.assertLess(calls.index(['wifi','reload']),calls.index(['ax6000-mesh-controller-sync','once']))
 def test_repeated_healthy_managed_pass_does_not_restart_workers(self):
  self.run_bootstrap();(self.root/'calls').write_text('');calls=self.run_bootstrap()
  self.assertNotIn(['ax6000-mesh-controller-sync','once'],calls);self.assertNotIn(['wifi','reload'],calls)
 def test_source_trigger_is_passive_and_service_supervises_separate_worker(self):
  tree=LIB.parents[1]
  init=(tree/'etc/init.d/ax6000-mesh-managed').read_text()
  p=subprocess.run(['busybox','ash','-c',init+'\nprocd_open_instance() { :; }; procd_set_param() { printf "%s\\n" "$*"; }; procd_close_instance() { :; }; start_service\n'],capture_output=True,text=True)
  self.assertEqual(p.returncode,0,p.stderr);self.assertIn('command /usr/libexec/ax6000-mesh-managed-bootstrap monitor',p.stdout)
  hook=(tree/'etc/hotplug.d/net/95-ax6000-mesh-managed').read_text()
  self.assertNotIn('bridge vlan',hook);self.assertNotIn('ip link',hook);self.assertNotIn('uci set',hook)
 def test_unsafe_bridge_recovery_never_reloads_or_calls_policy_worker(self):
  self.run_bootstrap();(self.root/'calls').write_text('');(self.root/'bridge/default_pvid').write_text('1')
  (self.root/'fail-ax6000-mesh-bootstrap-bridge-plan-recover').touch();calls=self.run_bootstrap(ok=False)
  self.assertNotIn(['wifi','reload'],calls);self.assertNotIn(['ax6000-mesh-controller-sync','once'],calls)
  self.assertEqual(json.loads((self.root/'status').read_text())['reason'],'bridge_recovery_quarantined')
 def test_recovery_rejects_newer_config_instead_of_overwriting_it(self):
  self.run_bootstrap();(self.state/'ts-bootstrap/phase').write_text('publishing')
  (self.config/'network').write_text('user-newer-edit')
  self.run_bootstrap(ok=False);self.assertEqual((self.config/'network').read_text(),'user-newer-edit')
 def test_validate_journal_accepts_live_user_edits_without_adopting_them(self):
  self.run_bootstrap();live=self.config/'network';live.write_text(live.read_text()+"\nconfig interface 'user_guest'\n option proto 'static'\n")
  before=live.read_bytes();self.run_bootstrap('validate-journal');self.assertEqual(live.read_bytes(),before)
  self.run_bootstrap('validate',False)
 def test_validate_journal_still_rejects_tampered_candidate(self):
  self.run_bootstrap();p=self.state/'ts-bootstrap/network';p.write_text(p.read_text()+"\nconfig interface 'bad'\n option proto 'dhcp'\n")
  self.run_bootstrap('validate-journal',False)
