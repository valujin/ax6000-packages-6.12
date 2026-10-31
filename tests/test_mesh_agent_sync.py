"""Real agent journal shell with isolated files and fault-injected lifecycle stubs."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_mesh_slot_allocation import LIB

class AgentSync(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for name in ['state','bin','config','map','bridge']: (self.root/name).mkdir()
        self.state=self.root/'state'; self.bin=self.root/'bin'; self.config=self.root/'config'; self.map=self.root/'map'
        for name,text in [('bridge/vlan_filtering','1'),('bridge/default_pvid','0'),('state/phase','committed'),
                          ('state/ts-capabilities.json','{"confirmed":true}'),('state/original-wireless','original-before-enrollment'),
                          ('config/network','agent-network'),('config/dhcp','agent-dhcp'),('config/firewall','agent-firewall'),('config/ax6000_mesh','agent-mesh'),
                          ('config/wireless','user-source-1'),('map/1905d.cfg','ALID=02:11:22:33:44:55\nbss_config_priority=old\n'),
                          ('role','agent'),('version','1'),('calls','')]:
            p=self.root/name; p.write_text(text); p.chmod(0o600)
        stub=self.bin/'stub'; stub.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
r=pathlib.Path(os.environ['FIXTURE']); n=pathlib.Path(sys.argv[0]).name; a=sys.argv[1:]
with (r/'calls').open('a') as f: f.write(json.dumps([n,*a])+'\\n')
if n=='uci':
 values={'ax6000_mesh.main.enabled':'1','ax6000_mesh.main.linux_ts':'1','ax6000_mesh.main.role':(r/'role').read_text()}
 print(values.get(a[-1],'')); sys.exit(0)
if n=='ax6000-mesh-agent-slots':
 if (r/'stage-fail').exists() or (r/'state/phase').read_text()!='committed': sys.exit(1)
 p=pathlib.Path(a[1]); p.mkdir(mode=0o700)
 (p/'wireless').write_text('materialized-'+(r/'version').read_text()); (p/'user-wireless').write_text((r/'config/wireless').read_text()); (p/'plan').write_text('{"primary_vid":1}')
 if (r/'edit-during-stage').exists(): (r/'config/wireless').write_text('concurrent-user-edit')
elif n=='ax6000-mesh-control':
 if a==['quiesce-radios']:
  # Snapshot at quiesce proves publication follows topology shutdown.
  (r/'at-quiesce').write_text((r/'config/wireless').read_text())
  if (r/'quiesce-fail').exists(): sys.exit(1)
 elif a==['restore-radios']:
  assert (r/'sealed').read_text()==(r/'config/wireless').read_text()
  if (r/'restore-fail').exists(): sys.exit(1)
elif n=='ax6000-mesh-transaction':
 assert a==['adopt-agent-slots']
 assert (r/'state/ts-agent-pending').exists()
 assert 'bss_config_priority=ra0;ra1;ra2;ra3;rax0;rax1;rax2;rax3;apcli0;apclix0' in (r/'map/1905d.cfg').read_text()
 if (r/'adopt-fail').exists(): sys.exit(1)
 (r/'sealed').write_text((r/'config/wireless').read_text())
elif n=='service' and a==['start']:
 assert (r/'sealed').read_text()==(r/'config/wireless').read_text()
 if (r/'start-fail').exists(): sys.exit(1)
elif n=='ax6000-mesh-ts-reconcile' and (r/'reconcile-fail').exists(): sys.exit(1)
'''); stub.chmod(0o700)
        for name in ['uci','ax6000-mesh-agent-slots','ax6000-mesh-ts-supervise','ax6000-mesh-ts-reconcile','ax6000-mesh-control','ax6000-mesh-transaction','service','sync']:
            (self.bin/name).symlink_to(stub)
        text=(LIB/'ax6000-mesh-agent-sync').read_text()
        for old,new in [('/etc/ax6000-mesh',str(self.state)),('/usr/libexec',str(self.bin)),('/etc/config',str(self.config)),('/etc/map',str(self.map)),('/etc/init.d/ax6000-mesh',str(self.bin/'service')),('/sys/class/net/br-lan/bridge',str(self.root/'bridge')),('/var/lock/ax6000-mesh.lock',str(self.root/'lock')),('/var/run/ax6000-mesh-sync-error',str(self.root/'error'))]:
            text=text.replace(old,new)
        text=text.replace('[ "$(id -u)" = 0 ]','[ "$(id -u)" = '+str(os.getuid())+' ]')
        self.helper=self.root/'agent-sync'; self.helper.write_text(text)
        self.env={**os.environ,'FIXTURE':str(self.root),'PATH':str(self.bin)+':'+os.environ['PATH']}
    def run_sync(self,op='once',ok=True):
        result=subprocess.run(['busybox','ash',str(self.helper),op],env=self.env,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode==0,ok,result.stderr); self.assertEqual(result.stdout,'')
        self.assertEqual((self.state/'original-wireless').read_text(),'original-before-enrollment')
        return [json.loads(line) for line in (self.root/'calls').read_text().splitlines()]
    def current(self): return (self.state/'ts-agent-current').read_text().strip()
    def clear_calls(self): (self.root/'calls').write_text('')
    def test_quiesce_then_publish_and_seal_before_each_restart(self):
        (self.state/'ts-ownership.json').write_text('{"owned":true}')
        calls=self.run_sync(); self.assertEqual((self.root/'at-quiesce').read_text(),'user-source-1')
        self.assertEqual((self.config/'wireless').read_text(),'materialized-1')
        lifecycle=[c for c in calls if c[0] not in ('uci','sync','ax6000-mesh-agent-slots')]
        self.assertEqual(lifecycle,[['ax6000-mesh-ts-supervise','stop'],['service','stop'],['ax6000-mesh-ts-reconcile','prepare',str(self.state/'ts-ownership.json')],['ax6000-mesh-control','quiesce-radios'],['ax6000-mesh-transaction','adopt-agent-slots'],['ax6000-mesh-control','restore-radios'],['ax6000-mesh-transaction','adopt-agent-slots'],['service','start'],['ax6000-mesh-transaction','adopt-agent-slots']])
        self.assertTrue((self.state/'ts-ownership.previous.json').exists()); self.assertFalse((self.state/'ts-agent-pending').exists())
        self.assertIn('ALID=02:11:22:33:44:55',(self.map/'1905d.cfg').read_text())
        self.run_sync('validate-current')
    def test_unchanged_does_not_restart_or_publish(self):
        self.run_sync(); generation=self.current(); self.clear_calls(); calls=self.run_sync()
        self.assertEqual(self.current(),generation)
        self.assertFalse(any(c[0] in ['service','ax6000-mesh-control','ax6000-mesh-transaction'] for c in calls))
        self.assertEqual(len(list((self.state/'ts-agent-generations').iterdir())),1)
    def test_quiesce_failure_preserves_source_and_resumes_same_journal(self):
        (self.root/'quiesce-fail').touch(); self.run_sync(ok=False)
        pending=(self.state/'ts-agent-pending').read_text().strip()
        self.assertEqual((self.config/'wireless').read_text(),'user-source-1'); self.assertFalse((self.state/'ts-agent-current').exists())
        (self.root/'quiesce-fail').unlink(); self.clear_calls(); calls=self.run_sync()
        self.assertEqual(self.current(),pending); self.assertFalse(any(c[0]=='ax6000-mesh-agent-slots' for c in calls))
    def test_start_failure_resumes_materialized_source(self):
        (self.root/'start-fail').touch(); self.run_sync(ok=False); pending=(self.state/'ts-agent-pending').read_text().strip()
        self.assertEqual((self.config/'wireless').read_text(),'materialized-1')
        (self.root/'start-fail').unlink(); self.run_sync(); self.assertEqual(self.current(),pending)
    def test_pending_refuses_newer_user_edits_before_shutdown(self):
        (self.root/'start-fail').touch(); self.run_sync(ok=False); (self.config/'wireless').write_text('newer-user-edit'); self.clear_calls()
        calls=self.run_sync(ok=False); self.assertEqual((self.config/'wireless').read_text(),'newer-user-edit')
        self.assertFalse(any(c[0] in ['service','ax6000-mesh-control'] for c in calls))
    def test_concurrent_staging_edit_is_retained_without_journal(self):
        (self.root/'edit-during-stage').touch(); calls=self.run_sync(ok=False)
        self.assertEqual((self.config/'wireless').read_text(),'concurrent-user-edit'); self.assertFalse((self.state/'ts-agent-pending').exists())
        self.assertFalse(any(c[0]=='service' for c in calls))
    def test_adoption_failure_blocks_restart_and_current_publication(self):
        (self.root/'adopt-fail').touch(); calls=self.run_sync(ok=False)
        self.assertFalse((self.state/'ts-agent-current').exists()); self.assertTrue((self.state/'ts-agent-pending').exists())
        self.assertNotIn(['ax6000-mesh-control','restore-radios'],calls); self.assertNotIn(['service','start'],calls)
    def test_bad_bridge_blocks_staging(self):
        (self.root/'bridge/default_pvid').write_text('1'); calls=self.run_sync(ok=False)
        self.assertFalse(any(c[0]!='uci' for c in calls)); self.assertEqual((self.config/'wireless').read_text(),'user-source-1')
    def test_wrong_role_is_noop(self):
        (self.root/'role').write_text('controller'); calls=self.run_sync(); self.assertFalse(any(c[0]!='uci' for c in calls))
    def test_capability_change_invalidates_current_and_republishes(self):
        self.run_sync(); generation=self.current(); (self.state/'ts-capabilities.json').write_text('{"confirmed":true,"revision":2}')
        self.run_sync('validate-current',False); self.run_sync(); self.assertNotEqual(self.current(),generation); self.run_sync('validate-current')
    def test_reconcile_failure_prevents_quiesce_and_publish(self):
        (self.state/'ts-ownership.json').write_text('{}'); (self.root/'reconcile-fail').touch(); calls=self.run_sync(ok=False)
        self.assertNotIn(['ax6000-mesh-control','quiesce-radios'],calls); self.assertEqual((self.config/'wireless').read_text(),'user-source-1')
        self.assertTrue((self.state/'ts-ownership.json').exists())

    def test_local_firewall_edit_invalidates_active_generation_and_is_not_adopted(self):
        self.run_sync(); before=self.current()
        (self.config/'firewall').write_text('unsafe-local-change')
        self.run_sync('validate-current',ok=False)
        self.run_sync(ok=False)
        self.assertEqual(self.current(),before)
