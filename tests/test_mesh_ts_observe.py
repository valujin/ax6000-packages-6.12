"""Native observation binding and externally supplied dataplane proof."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_mesh_slot_allocation import LIB, NATIVE

UCODE='/tmp/mesh-ucode-build/ucode'

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

class TSDeclare(unittest.TestCase):
 def setUp(self):
  if not Path(UCODE).exists(): self.skipTest('ucode required')
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.script=self.root/'declare'
  mock=self.root/'fs.uc';mock.write_text('import * as fs from "fs"; export const readfile=fs.readfile, open=fs.open; export function lstat(p) { let s=fs.lstat(p); if(s) s.uid=0; return s; };')
  self.script.write_text((LIB/'ax6000-mesh-ts-declare').read_text().replace('/sys/class/net/',str(self.root)+'/').replace("from 'fs'",'from '+json.dumps(str(mock))))
  for name,mac in [('ra2','02:00:00:00:00:22'),('rax2','02:00:00:00:00:32')]:
   (self.root/name).mkdir();(self.root/name/'address').write_text(mac+'\n')
  self.transport={'schema':2,'bridge':'br-lan','management_vid':1,'quarantine_vid':4093,'controller_alid':'02:00:00:00:00:ff','guest_ports':[],'cpu_guest_links':[]}
  self.obs={'schema':2,'primary_vid':1,'controller_alid':self.transport['controller_alid'],'fh':[{'bssid':'02:00:00:00:00:22','vid':10},{'bssid':'02:00:00:00:00:32','vid':10},{'bssid':'02:00:00:00:00:11','vid':4093}]}
 def call(self,ok=True):
  paths=[]
  for name,value in [('transport',self.transport),('obs',self.obs),('cpu',{'links':[]})]:
   p=self.root/name;p.write_text(json.dumps(value));p.chmod(0o600);paths.append(str(p))
  r=subprocess.run([UCODE,'-L','/tmp/mesh-ucode-build/*.so',str(self.script),*paths,str(self.root/'out')],capture_output=True,text=True)
  self.assertEqual(r.returncode==0,ok,r.stderr)
  return json.loads((self.root/'out').read_text()) if ok else None
 def test_actual_bssid_binding_and_placeholder_exclusion(self):
  result=self.call();self.assertEqual([p['ifname'] for p in result['guest_ports']],['ra2','rax2']);self.assertTrue(all(not p['enabled'] for p in result['guest_ports']))
 def test_unknown_slot_refused(self):
  self.obs['fh'][0]['bssid']='02:00:00:00:00:99';self.call(False)
 def test_wrong_controller_refused(self):
  self.obs['controller_alid']='02:00:00:00:00:aa';self.call(False)
 def test_duplicate_observation_refused(self):
  self.obs['fh'].append(self.obs['fh'][0]);self.call(False)
 def test_transport_cannot_embed_dynamic_ownership(self):
  self.transport['guest_ports']=[{}];self.call(False)

class TSCapability(unittest.TestCase):
 def setUp(self):
  if not (NATIVE/'bin/jshn').exists():self.skipTest('native jshn required')
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.state=self.root/'state';self.state.mkdir();self.helpers=self.root/'helpers';self.helpers.mkdir()
  self.abi=self.root/'abi';self.abi.write_text('abi');self.modules=self.root/'modules'/os.uname().release;self.modules.mkdir(parents=True)
  self.driver=self.modules/'mt_wifi.ko';self.driver.write_text('driver')
  self.board=self.root/'board';self.board.write_text('xiaomi,redmi-router-ax6000-stock')
  self.names='ts-capability ts-provision ts-declare ts-own ts-gate ts-runtime ts-reconcile ts-supervise ts-observe managed-bootstrap bootstrap-bridge controller-sync agent-sync normalize-networks allocate-slots stage-wts materialize-networks agent-slots control transaction vendor'.split()
  files=[]
  for name in self.names:
   p=self.helpers/('ax6000-mesh-'+name);p.write_text(name);files.append(p)
  self.extra=['/etc/init.d/ax6000-mesh','/etc/init.d/ax6000-mesh-sync','/etc/init.d/ax6000-mesh-managed','/lib/netifd/wireless/mtwifi.sh','/etc/hotplug.d/net/95-ax6000-mesh-managed','/usr/bin/wifi_config_save','/usr/share/ax6000-mesh/vendor.sh']
  for name in self.extra:
   p=(self.root/'native'/'wifi_config_save') if name=='/usr/bin/wifi_config_save' else self.root/name.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_text(name);files.append(p)
  native=[]
  for name in ['wapp','mapd','p1905_managerd']:
   p=self.root/'native'/name;p.parent.mkdir(exist_ok=True);p.write_text(name);native.append(p)
  self.proofpath=self.root/'release.json'
  script=(LIB/'ax6000-mesh-ts-capability').read_text().replace('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh')).replace('/etc/ax6000-mesh-abi.json',str(self.abi)).replace('/etc/ax6000-mesh-dataplane-capability.json',str(self.proofpath)).replace('/usr/libexec/',str(self.helpers)+'/').replace('/lib/modules/',str(self.root/'modules')+'/').replace('/tmp/sysinfo/board_name',str(self.board)).replace('/usr/bin/',str(self.root/'native')+'/')
  for prefix in ['/etc/init.d/','/lib/netifd/','/etc/hotplug.d/','/usr/share/ax6000-mesh/']:script=script.replace(prefix,str(self.root)+prefix)
  self.script=self.root/'capability';self.script.write_text(script.replace('stat -c',str(self.root/'stat')+' -c'))
  bundle=lambda paths:hashlib.sha256(''.join(digest(p)+'\n' for p in paths).encode()).hexdigest()
  self.proof={'schema':2,'packet_tested':True,'platform':'xiaomi,redmi-router-ax6000','topology':'wireless-tagged-br-lan-v1','capacity24':4,'capacity5':4,'management_vid':1,'quarantine_vid':4093,'abi_sha256':digest(self.abi),'driver_sha256':digest(self.driver),'implementation_sha256':bundle(files),'native_sha256':bundle(native)}
  stat=self.root/'stat';stat.write_text('#!/bin/sh\nif [ "$1 $2" = "-c %u" ]; then echo 0; else exec /usr/bin/stat "$@"; fi\n');stat.chmod(0o755)
  self.env={**os.environ,'PATH':str(NATIVE/'bin')+':'+os.environ['PATH'],'LD_LIBRARY_PATH':str(NATIVE/'lib')}
 def call(self,ok=True):
  self.proofpath.write_text(json.dumps(self.proof));self.proofpath.chmod(0o644)
  r=subprocess.run(['busybox','ash',str(self.script)],env=self.env,capture_output=True,text=True)
  self.assertEqual(r.returncode==0,ok,r.stderr)
 def test_exact_release_proof_accepted_without_perdevice_transport(self):self.call()
 def test_driver_change_revokes_proof(self):self.driver.write_text('other driver');self.call(False)
 def test_every_implementation_change_revokes_proof(self):
  for name in self.names:
   with self.subTest(name=name):
    p=self.helpers/('ax6000-mesh-'+name);before=p.read_text();p.write_text('changed');self.call(False);p.write_text(before)
 def test_native_binary_change_revokes_proof(self):
  for name in ['wapp','mapd','p1905_managerd']:
   with self.subTest(name=name):
    p=self.root/'native'/name;before=p.read_text();p.write_text('changed');self.call(False);p.write_text(before)
 def test_wrong_topology_refused(self):self.proof['topology']='unproven';self.call(False)
 def test_string_proof_not_boolean(self):self.proof['packet_tested']='1';self.call(False)
 def test_missing_implementation_refused(self):(self.helpers/'ax6000-mesh-ts-own').unlink();self.call(False)
 def test_wrong_platform_refused(self):self.board.write_text('other-device');self.call(False)

class TSObserverLifecycle(unittest.TestCase):
 def setUp(self):
  import time
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.state=self.root/'state';self.state.mkdir();self.bin=self.root/'bin';self.bin.mkdir();(self.root/'lock').mkdir()
  for name,data in [('ts-agent-current','a'*32),('ts-transport.json','{}'),('ts-dataplane-capability.json','{}')]:
   (self.state/name).write_text(data)
  self.obs=self.root/'obs';self.obs.write_text('{"sequence":1}')
  stub=self.bin/'stub';stub.write_text('''#!/usr/bin/env python3
import os,sys,json,signal,time
from pathlib import Path
r=Path(os.environ['OBSERVER_TEST']);n=Path(sys.argv[0]).name;a=sys.argv[1:]
def log(s):
 with (r/'log').open('a') as f:f.write(s+'\\n')
if n=='uci':
 print('agent' if a[-1].endswith('.role') else '1');sys.exit()
if n=='id':print(0);sys.exit()
if n=='jsonfilter':print('b'*32);sys.exit()
if n in ('ax6000-mesh-agent-sync','ax6000-mesh-controller-sync'):sys.exit(1 if (r/'policy-invalid').exists() else 0)
if n.endswith('ts-capability'):sys.exit(0 if (r/'proof-valid').exists() else 1)
if n.endswith('ts-declare'):
 Path(a[-1]).write_text('{}');log('declare');sys.exit()
if n.endswith('ts-own'):
 Path(a[-1]).write_text(json.dumps({'generation':'b'*32}));log('own');sys.exit()
if n.endswith('ts-runtime'):
 (r/'state/ts-ownership.json').write_text(Path(a[-1]).read_text());log('stage');sys.exit()
if n.endswith('ts-supervise'):
 p=r/'supervisor-pid'
 if a[0]=='stop':
  if p.exists():
   try:os.kill(int(p.read_text()),signal.SIGTERM)
   except ProcessLookupError:pass
   p.unlink(missing_ok=True)
  (r/'state/ts-dataplane-approved').unlink(missing_ok=True);log('stop');sys.exit()
 p.write_text(str(os.getpid()));log('run')
 while True:time.sleep(.1)
sys.exit(2)
''');stub.chmod(0o755)
  for name in ['uci','id','jsonfilter','ax6000-mesh-agent-sync','ax6000-mesh-controller-sync',*['ax6000-mesh-ts-'+s for s in ['capability','declare','own','runtime','supervise']]]:(self.bin/name).symlink_to(stub)
  script=(LIB/'ax6000-mesh-ts-observe').read_text().replace('/etc/ax6000-mesh-dataplane-capability.json',str(self.state/'ts-dataplane-capability.json')).replace('/etc/ax6000-mesh',str(self.state)).replace('/usr/libexec/ax6000-mesh',str(self.bin/'ax6000-mesh')).replace('/var/run/ax6000-mesh-ts.json',str(self.obs)).replace('/var/lock/',str(self.root/'lock')+'/').replace('sleep 1','sleep 0.05')
  self.script=self.root/'observer';self.script.write_text(script)
  self.process=None;self.addCleanup(self.stop)
 def start(self):
  self.process=subprocess.Popen(['/bin/sh',str(self.script),'monitor'],env={**os.environ,'PATH':str(self.bin)+':'+os.environ['PATH'],'OBSERVER_TEST':str(self.root)},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 def stop(self):
  if self.process and self.process.poll() is None:
   self.process.terminate();self.process.wait(timeout=5)
 def wait_for(self,predicate):
  import time
  deadline=time.monotonic()+5
  while time.monotonic()<deadline:
   if predicate():return
   if self.process and self.process.poll() is not None:self.fail('observer exited early')
   time.sleep(.03)
  self.fail('observer transition timed out')
 def log(self):return (self.root/'log').read_text().splitlines() if (self.root/'log').exists() else []
 def test_without_proof_only_stages_disabled(self):
  self.start();self.wait_for(lambda:'stage' in self.log());self.stop();self.assertNotIn('run',self.log());self.assertFalse((self.state/'ts-dataplane-approved').exists())
 def test_observation_removal_stops_forwarding_supervisor(self):
  (self.root/'proof-valid').touch();self.start();self.wait_for(lambda:'run' in self.log());self.obs.unlink();self.wait_for(lambda:not (self.root/'supervisor-pid').exists());self.assertFalse((self.state/'ts-dataplane-approved').exists())
 def test_implementation_proof_revocation_stops_supervisor(self):
  (self.root/'proof-valid').touch();self.start();self.wait_for(lambda:'run' in self.log());(self.root/'proof-valid').unlink();self.wait_for(lambda:not (self.root/'supervisor-pid').exists());self.assertFalse((self.state/'ts-dataplane-approved').exists())
 def test_native_policy_change_restarts_with_new_staging(self):
  (self.root/'proof-valid').touch();self.start();self.wait_for(lambda:'run' in self.log());self.obs.write_text('{"sequence":2}');self.wait_for(lambda:self.log().count('run')==2);self.assertEqual(self.log().count('stage'),2)

 def test_invalid_changed_uci_policy_stops_old_forwarding_until_accepted(self):
  (self.root/'proof-valid').touch();self.start();self.wait_for(lambda:'run' in self.log())
  (self.root/'policy-invalid').touch();self.wait_for(lambda:not (self.root/'supervisor-pid').exists())
  import time;time.sleep(.2)
  self.assertEqual(self.log().count('run'),1)
  self.assertFalse((self.state/'ts-dataplane-approved').exists())
  (self.root/'policy-invalid').unlink();self.wait_for(lambda:self.log().count('run')==2)
