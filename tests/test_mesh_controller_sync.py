"""Controller generation journal integration against real shell/jshn/jsonfilter."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_mesh_slot_allocation import LIB, NATIVE

class ControllerSync(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source=NATIVE.parents[1]/'build_dir/target-aarch64_cortex-a53_musl'
        candidates=list(source.glob('jsonfilter-*/main.c'))
        if not candidates or not (NATIVE/'bin/jshn').exists() or not shutil.which('cc'):
            raise unittest.SkipTest('native SDK JSON libraries and generated jsonfilter C sources required')
        cls.native_tmp=tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.native_tmp.cleanup)
        cls.jsonfilter=Path(cls.native_tmp.name)/'jsonfilter'
        folder=candidates[0].parent
        subprocess.run(['cc','-D_GNU_SOURCE','-DJSONC','-I'+str(NATIVE/'include'),'-I'+str(NATIVE/'include/json-c'),
            *[str(folder/name) for name in ('main.c','ast.c','lexer.c','parser.c','matcher.c')],
            '-L'+str(NATIVE/'lib'),'-Wl,-rpath,'+str(NATIVE/'lib'),'-lubox','-ljson-c','-o',str(cls.jsonfilter)],check=True,capture_output=True)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)
        self.state=self.root/'state'; self.state.mkdir(); self.bin=self.root/'bin'; self.bin.mkdir()
        self.config=self.root/'config'; self.config.mkdir(); self.map=self.root/'map'; self.map.mkdir()
        self.bridge=self.root/'bridge'; self.bridge.mkdir()
        for p,text in [(self.bridge/'vlan_filtering','1'),(self.bridge/'default_pvid','0'),(self.state/'phase','committed'),
            (self.state/'backhaul-ssid','private-bh'),(self.state/'backhaul-key','private-bh-key'),
            (self.state/'original-wireless','source-1'),(self.state/'ts-capabilities.json','{"confirmed":true}'),
            (self.config/'wireless','source-1'),(self.map/'1905d.cfg','ALID=02:11:22:33:44:55\nbss_config_priority=old\n')]:
            p.write_text(text); p.chmod(0o600)
        
        for name in ('network','dhcp','firewall','ax6000_mesh'): (self.config/name).write_text(name+'-initial')
        (self.root/'linux_ts').write_text('1')
        (self.root/'version').write_text('1'); (self.root/'role').write_text('controller')
        stub=self.bin/'stub'; stub.write_text('''#!/usr/bin/env python3
import json,os,sys,pathlib
r=pathlib.Path(os.environ['FIXTURE']); n=pathlib.Path(sys.argv[0]).name; a=sys.argv[1:]
with (r/'calls').open('a') as f: f.write(json.dumps([n,*a])+'\\n')
if n=='uci':
 vals={'ax6000_mesh.main.enabled':'1','ax6000_mesh.main.linux_ts':(r/'linux_ts').read_text(),'ax6000_mesh.main.role':(r/'role').read_text(),'ax6000_mesh.main.backhaul_security':'sae','ax6000_mesh.main.quarantine_vid':'4090'}
 print(vals.get(a[-1],'')); sys.exit(0)
if n=='ax6000-mesh-normalize-networks':
 if (r/'normalize-fail').exists(): sys.exit(1)
 p=pathlib.Path(a[2]); p.mkdir();
 for name,obj in [('policy.json',{'version':(r/'version').read_text()}),('credentials.json',{'key':'private-user-key'}),('cpu_guest_links.json',{'links':[]}),('enrolled_agents.json',{'agents':['02:11:22:33:44:55']})]: (p/name).write_text(json.dumps(obj))
 (p/'quarantine_vid').write_text('4090')
elif n=='ax6000-mesh-allocate-slots': print(json.dumps({'state':{'schema':1,'slots':[]}}))
elif n=='ax6000-mesh-stage-wts': pathlib.Path(a[4]).write_text('private-wts-'+(r/'version').read_text())
elif n=='ax6000-mesh-materialize-networks':
 p=pathlib.Path(a[3]); p.mkdir();
 if (r/'edit-during-stage').exists(): (r/'config/wireless').write_text('concurrent-user-edit')
 if (r/'edit-network-during-stage').exists(): (r/'config/network').write_text('concurrent-network-edit')
 (p/'wireless').write_text('materialized-'+(r/'version').read_text()); (p/'user-wireless').write_text(pathlib.Path(a[2]).read_text())
elif n=='mapd_cli':
 assert (r/'map/wts_bss_info_config').read_text()=='private-wts-'+(r/'version').read_text()
 sys.exit(1 if (r/'renew-fail').exists() else 0)
elif n=='service' and a==['start'] and (r/'start-fail').exists(): sys.exit(1)
'''); stub.chmod(0o700)
        for name in ['uci','ax6000-mesh-normalize-networks','ax6000-mesh-allocate-slots','ax6000-mesh-stage-wts','ax6000-mesh-materialize-networks','ax6000-mesh-ts-supervise','ax6000-mesh-ts-reconcile','ax6000-mesh-control','ax6000-mesh-transaction','service','mapd_cli']:
            (self.bin/name).symlink_to(stub)
        (self.bin/'jsonfilter').symlink_to(self.jsonfilter)
        src=(LIB/'ax6000-mesh-controller-sync').read_text()
        for old,new in [('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh')),('/etc/ax6000-mesh',str(self.state)),('/usr/libexec',str(self.bin)),('/etc/config',str(self.config)),('/etc/map',str(self.map)),('/etc/init.d/ax6000-mesh',str(self.bin/'service')),('/sys/class/net/br-lan/bridge',str(self.bridge)),('/var/lock/ax6000-mesh.lock',str(self.root/'lock')),('/var/run/ax6000-mesh-sync-error',str(self.root/'error'))]: src=src.replace(old,new)
        src=src.replace('[ "$(id -u)" = 0 ]','[ "$(id -u)" = '+str(os.getuid())+' ]').replace('[ "$(stat -c %u "$1")" = 0 ]','[ "$(stat -c %u "$1")" = '+str(os.getuid())+' ]')
        self.helper=self.root/'sync'; self.helper.write_text(src)
        self.env={**os.environ,'FIXTURE':str(self.root),'PATH':str(self.bin)+':'+str(NATIVE/'bin')+':'+os.environ['PATH'],'LD_LIBRARY_PATH':str(NATIVE/'lib')}
    def run_sync(self,op='once',ok=True,extra=()):
        p=subprocess.run(['busybox','ash',str(self.helper),op,*extra],env=self.env,capture_output=True,text=True,timeout=30)
        self.assertEqual(p.returncode==0,ok,p.stderr); self.assertEqual(p.stdout,''); self.assertNotIn('private-',p.stderr)
        calls=(self.root/'calls').read_text(); self.assertNotIn('private-',calls)
        return [json.loads(x) for x in calls.splitlines()]
    def current(self): return (self.state/'ts-sync-current').read_text().strip()
    def status(self): return json.loads((self.state/'ts-sync-status.json').read_text())
    def test_publish_then_renew_records_pending_remote_ack(self):
        calls=self.run_sync(); self.assertEqual(self.status()['phase'],'renew_requested')
        self.assertEqual(self.status()['agents'][0]['applied_state'],'pending_unverified')
        self.assertIsNone(self.status()['agents'][0]['applied_generation'])
        self.assertLess(calls.index(['service','start']),calls.index(['mapd_cli','/tmp/mapd_ctrl','renew']))
        self.assertFalse((self.state/'ts-sync-pending').exists()); self.run_sync('validate-current')
        self.assertIn('ALID=02:11:22:33:44:55',(self.map/'1905d.cfg').read_text())
    def test_unchanged_retries_without_wifi_or_service_restart(self):
        (self.root/'renew-fail').touch(); self.run_sync(); generation=self.current(); self.assertEqual(self.status()['phase'],'retry_pending')
        (self.root/'calls').write_text(''); (self.root/'renew-fail').unlink(); calls=self.run_sync()
        self.assertEqual(self.current(),generation); self.assertFalse(any(c[0] in ('service','ax6000-mesh-control') for c in calls)); self.assertEqual(self.status()['phase'],'renew_requested')
    def test_changed_profile_publishes_new_generation(self):
        self.run_sync(); generation=self.current(); (self.root/'version').write_text('2'); (self.config/'wireless').write_text('source-2')
        self.run_sync(); self.assertNotEqual(generation,self.current()); self.assertEqual((self.config/'wireless').read_text(),'materialized-2')
    def test_interrupted_journal_resumes(self):
        (self.root/'start-fail').touch(); self.run_sync(ok=False); pending=(self.state/'ts-sync-pending').read_text().strip()
        (self.root/'start-fail').unlink(); self.run_sync(); self.assertEqual(self.current(),pending)
    def test_interrupted_journal_refuses_newer_user_edit(self):
        (self.root/'start-fail').touch(); self.run_sync(ok=False); (self.config/'wireless').write_text('newer-user-edit'); (self.root/'calls').write_text('')
        calls=self.run_sync(ok=False); self.assertEqual((self.config/'wireless').read_text(),'newer-user-edit'); self.assertFalse(any(c[0]=='service' for c in calls))
    def test_agent_role_does_not_publish(self):
        (self.root/'role').write_text('agent'); calls=self.run_sync(); self.assertFalse(any(c[0]!='uci' for c in calls)); self.assertFalse((self.state/'ts-sync-current').exists())
    def test_capability_change_requires_new_valid_generation(self):
        self.run_sync(); (self.state/'ts-capabilities.json').write_text('{"confirmed":true,"evidence":"new"}')
        self.run_sync(); self.run_sync('validate-current')
    def test_invalid_policy_preserves_previous_generation(self):
        self.run_sync(); generation=self.current(); (self.root/'normalize-fail').touch(); (self.root/'calls').write_text('')
        calls=self.run_sync(ok=False); self.assertEqual(generation,self.current()); self.assertFalse(any(c[0] in ('service','mapd_cli') for c in calls))
    def test_concurrent_user_edit_during_staging_is_not_overwritten(self):
        (self.root/'edit-during-stage').touch(); calls=self.run_sync(ok=False)
        self.assertEqual((self.config/'wireless').read_text(),'concurrent-user-edit'); self.assertFalse((self.state/'ts-sync-pending').exists())
        self.assertFalse(any(c[0]=='service' for c in calls))
    def test_preflight_before_linux_ts_or_filtering_without_writes(self):
        (self.root/'linux_ts').write_text('0'); (self.bridge/'vlan_filtering').write_text('0')
        before={str(p.relative_to(self.state)):p.read_bytes() for p in self.state.rglob('*') if p.is_file()}
        calls=self.run_sync('preflight',extra=('4089',))
        after={str(p.relative_to(self.state)):p.read_bytes() for p in self.state.rglob('*') if p.is_file()}
        self.assertEqual(before,after); self.assertEqual((self.config/'wireless').read_text(),'source-1')
        self.assertFalse(any(c[0] in ('service','mapd_cli','ax6000-mesh-control','ax6000-mesh-transaction') for c in calls))
    def test_preflight_invalid_policy_fails_without_writes(self):
        (self.root/'normalize-fail').touch(); self.run_sync('preflight',ok=False,extra=('4089',))
        self.assertFalse((self.state/'ts-quarantine-key').exists()); self.assertFalse(list(self.state.glob('.preflight.*')))
        self.assertFalse((self.state/'ts-sync-pending').exists()); self.assertEqual((self.config/'wireless').read_text(),'source-1')
    def test_network_edit_during_staging_aborts(self):
        (self.root/'edit-network-during-stage').touch(); calls=self.run_sync(ok=False)
        self.assertFalse(any(c[0]=='service' for c in calls)); self.assertFalse((self.state/'ts-sync-pending').exists())
    def test_network_edit_after_interruption_refuses_resume(self):
        (self.root/'start-fail').touch(); self.run_sync(ok=False); (self.config/'network').write_text('new-network')
        (self.root/'calls').write_text(''); calls=self.run_sync(ok=False); self.assertFalse(any(c[0]=='service' for c in calls))
    def test_network_edit_forces_new_generation_even_with_same_wts(self):
        self.run_sync(); generation=self.current(); (self.config/'network').write_text('new-network'); self.run_sync()
        self.assertNotEqual(self.current(),generation)
