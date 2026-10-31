"""Exercise runtime staging/monitor against the real reconciler and kernel model."""
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import test_mesh_ts_reconcile as rec
from test_mesh_slot_allocation import LIB, NATIVE


@unittest.skipUnless(Path(rec.UCODE).exists(), 'Real ucode required')
class Runtime(unittest.TestCase):
    def setUp(self):
        rec.MeshTSReconcile.setUp(self)
        self.reconciler = self.script
        self.state_dir = self.root / 'mesh-state'; self.state_dir.mkdir(mode=0o700)
        self.reconciler.write_text(self.reconciler.read_text().replace(str(self.root / 'etc/ts-dataplane-approved'), str(self.state_dir / 'ts-dataplane-approved')))
        for p, obj in [(self.ownership,self.owner),(self.observation,self.obs)]:
            p.write_text(json.dumps(obj)); p.chmod(0o600)
        wrapper=self.root/'reconcile';wrapper.write_text(f'#!/bin/sh\nexec {rec.UCODE} -L /tmp/mesh-ucode-build/\\*.so {self.reconciler} "$@"\n');wrapper.chmod(0o700)
        self.sysfs=self.root/'sysfs';self.sysfs.mkdir()
        (self.sysfs/'vlan_filtering').write_text('1');(self.sysfs/'default_pvid').write_text('0')
        uci=self.root/'uci';uci.write_text('#!/bin/sh\necho 1\n');uci.chmod(0o700)
        source=(LIB/'ax6000-mesh-ts-runtime').read_text()
        source=source.replace('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh'))
        source=source.replace('/etc/ax6000-mesh',str(self.state_dir)).replace('/var/run/ax6000-mesh-ts.json',str(self.observation))
        source=source.replace('/usr/libexec/ax6000-mesh-ts-reconcile',str(wrapper)).replace('/var/lock',str(self.root/'locks'))
        source=source.replace('/sys/class/net/br-lan/bridge/',str(self.sysfs)+'/').replace('ip link set',str(self.root/'ip')+' link set')
        source=source.replace('[ "$(id -u)" = 0 ]',f'[ "$(id -u)" = {os.getuid()} ]')
        source=source.replace('[ "$(stat -c %u "$1")" = 0 ]',f'[ "$(stat -c %u "$1")" = {os.getuid()} ]')
        self.runtime=self.root/'runtime';self.runtime.write_text(source)
        self.env.update(PATH=str(self.root)+':'+str(NATIVE/'bin')+':'+os.environ['PATH'],LD_LIBRARY_PATH=str(NATIVE/'lib'))

    def run_runtime(self,*args,success=True):
        r=subprocess.run(['busybox','ash',str(self.runtime),*args],env=self.env,text=True,capture_output=True,timeout=10)
        self.assertEqual(r.returncode==0,success,r.stdout+r.stderr)
        return r

    def test_stage_attaches_disabled_exact_guests_and_preserves_management(self):
        self.run_runtime('stage',str(self.ownership))
        state=json.loads(self.model.read_text())
        for n in ('ra2','rax2'):
            self.assertNotIn('UP',state['links'][n]['flags']);self.assertEqual(state['links'][n]['master'],'br-lan')
            self.assertEqual(state['vlans'][n],[{'vlan':10,'flags':['PVID','Egress Untagged']}])
        self.assertEqual(state['vlans']['lan2'],self.state['vlans']['lan2'])
        published=self.state_dir/'ts-ownership.json';self.assertTrue(published.exists());self.assertEqual(published.stat().st_mode&0o777,0o600)

    def test_missing_acceptance_cannot_activate(self):
        self.run_runtime('stage',str(self.ownership))
        self.run_runtime('monitor',self.owner['generation'],success=False)
        self.assertNotIn('UP',json.loads(self.model.read_text())['links']['ra2']['flags'])

    def test_no_default_pvid_guard_prevents_attachment(self):
        (self.sysfs/'default_pvid').write_text('1')
        self.run_runtime('stage',str(self.ownership),success=False)
        self.assertFalse((self.state_dir/'ts-ownership.json').exists())
        self.assertEqual(json.loads(self.model.read_text())['calls'],[])

    def test_monitor_missing_observation_quarantines_and_exits(self):
        self.run_runtime('stage',str(self.ownership))
        approval=self.state_dir/'ts-dataplane-approved';approval.write_text(self.owner['generation']);approval.chmod(0o600)
        proc=subprocess.Popen(['busybox','ash',str(self.runtime),'monitor',self.owner['generation']],env=self.env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        deadline=time.monotonic()+5
        up=False
        while time.monotonic()<deadline and proc.poll() is None:
            try:up='UP' in json.loads(self.model.read_text())['links']['ra2']['flags']
            except json.JSONDecodeError:pass
            if up:break
            time.sleep(.02)
        self.assertTrue(up,'Monitor never activated staged guests')
        self.observation.unlink()
        stdout,stderr=proc.communicate(timeout=5)
        self.assertNotEqual(proc.returncode,0,stdout+stderr)
        state=json.loads(self.model.read_text())
        for n in ('ra2','rax2'):
            self.assertNotIn('UP',state['links'][n]['flags'])
            self.assertNotIn('master',state['links'][n])
