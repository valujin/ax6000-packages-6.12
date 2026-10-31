"""Run the real reconciler against a persistent, isolated ip/bridge model."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from mesh_openwrt_layout import install_commands, sandbox_commands

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-ts-reconcile'
UCODE = os.environ.get('UCODE', '/tmp/mesh-ucode-build/ucode')
BOOT = '01234567-89ab-cdef-0123-456789abcdef'

MODEL = r'''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
p=Path(os.environ['TS_MODEL']);d=json.loads(p.read_text());a=sys.argv[1:]
tool=Path(sys.argv[0]).name
d['calls'].append([tool,*a])
def done(status=0,value=None):
 p.write_text(json.dumps(d))
 if value is not None:print(json.dumps(value))
 sys.exit(status)
if d.get('fail')==[tool,*a]:done(1)
if d.get('ignore')==[tool,*a]:done()
if tool=='uci' and a[:2]==['-q','get']:
 value=d.get('uci',{}).get(a[2]);p.write_text(json.dumps(d))
 if value is not None:print(value)
 sys.exit(1 if value is None else 0)
if tool=='uci' and a==['-q','-X','show','network']:
 p.write_text(json.dumps(d))
 for key,value in d.get('uci',{}).items():print(key+"='"+value+"'")
 sys.exit(0)
if tool=='ip' and a==['-j','-d','link','show']:done(value=list(d['links'].values()))
if tool=='bridge' and a==['-j','vlan','show']:done(value=[{'ifname':n,'vlans':v} for n,v in d['vlans'].items()])
if tool=='ip' and a[:4]==['link','set','dev',a[3]]:
 n=a[3]
 if n not in d['links']:done(1)
 if a[4] in ('up','down'):
  f=d['links'][n]['flags'];f[:]=[x for x in f if x!='UP']
  if a[4]=='up':f.append('UP')
 elif a[4]=='master':d['links'][n]['master']=a[5]
 elif a[4]=='nomaster':
  d['links'][n].pop('master',None);d['vlans'].pop(n,None)
 else:done(2)
 done()
if tool=='bridge' and a[:1]==['vlan'] and a[1] in ('add','del'):
 n=a[3];vid=int(a[5]);v=d['vlans'].setdefault(n,[])
 v[:]=[x for x in v if x['vlan']!=vid]
 if a[1]=='add':v.append({'vlan':vid,'flags':(['PVID'] if 'pvid' in a else [])+(['Egress Untagged'] if 'untagged' in a else [])})
 done()
done(2)
'''


@unittest.skipUnless(Path(UCODE).exists(), 'Real ucode runtime required')
class MeshTSReconcile(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mesh-ts-reconcile-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.model = self.root / 'model.json'
        links = {}
        for i, n in enumerate(['br-lan', 'lan2', 'ra0', 'apcli0', 'ra2', 'rax2', 'foreign0'], 1):
            links[n] = {'ifname': n, 'ifindex': i, 'address': '02:00:00:00:00:%02x' % i,
                        'flags': ['UP'], 'master': 'br-lan'}
        links['br-lan'].pop('master')
        links['br-lan']['linkinfo'] = {'info_kind': 'bridge', 'info_data': {'vlan_filtering': 1}}
        vlan = [{'vlan': 1, 'flags': ['PVID', 'Egress Untagged']}]
        self.state = {'links': links, 'vlans': {n: copy.deepcopy(vlan) for n in links}, 'calls': []}
        self.model.write_text(json.dumps(self.state))
        for n in ['ip', 'bridge', 'uci']:
            p = self.root / n; p.write_text(MODEL); p.chmod(0o755)
        (self.root / 'run').mkdir()
        (self.root / 'etc').mkdir()
        (self.root / 'proc/sys/kernel/random').mkdir(parents=True)
        (self.root / 'proc/sys/kernel/random/boot_id').write_text(BOOT + '\n')
        (self.root / 'proc/uptime').write_text('10.00 2.00\n')
        for pid, name, start in [(101, 'mapd', 900), (102, 'p1905_managerd', 901)]:
            p = self.root / 'proc' / str(pid); p.mkdir()
            (p / 'stat').write_text(str(pid) + ' (' + name + ') ' + ' '.join(['S'] + ['0'] * 18 + [str(start)] + ['0'] * 5))
            (p / 'comm').write_text(name + '\n')
        self.owner = {'schema': 2, 'boot_id': BOOT, 'generation': 'a' * 32, 'bridge': 'br-lan',
                      'management_vid': 1, 'quarantine_vid': 4093, 'management_ifnames': ['lan2', 'ra0', 'apcli0'],
                      'controller_alid': '02:00:00:00:00:ff', 'trunk_ifnames': ['apcli0'],
                      'cpu_guest_links': [],
                      'guest_ports': [{'ifname': n, 'actual_bssid': links[n]['address'], 'vid': 10, 'enabled': False}
                                      for n in ['ra2', 'rax2']],
                      'daemons': {'mapd': {'pid': 101, 'starttime': 900}, 'ieee1905': {'pid': 102, 'starttime': 901}},
                      'observation': {'connection_generation': 1, 'sequence': 1}}
        self.obs = {'schema': 2, 'boot_id': BOOT, 'producer_pid': 101, 'producer_start_ticks': 900,
                    'connection_generation': 1, 'controller_alid': self.owner['controller_alid'],
                    'monotonic_ms': 9000, 'sequence': 1, 'primary_vid': 1, 'primary_pcp': 0,
                    'allowed_vids': [1, 10], 'fh': [{'bssid': x['actual_bssid'], 'vid': x['vid']} for x in self.owner['guest_ports']]}
        self.ownership = self.root / 'owner.json'; self.observation = self.root / 'obs.json'
        # Only the filesystem owner attribute is virtualized. All JSON I/O,
        # command invocations and persisted kernel-model transitions are real.
        mock = self.root / 'fs.uc'
        mock.write_text('import * as fs from "fs";\n'
            'export const readfile=fs.readfile, popen=fs.popen, open=fs.open, rename=fs.rename, unlink=fs.unlink, mkdir=fs.mkdir, rmdir=fs.rmdir;\n'
            'export function lstat(path) { let s=fs.lstat(path); if(s) s.uid=0; return s; };\n')
        self.script = self.root / 'reconcile.uc'
        if HELPER.exists():
            text = HELPER.read_text().replace("from 'fs'", 'from ' + json.dumps(str(mock)))
            text = text.replace('/var/run/', str(self.root / 'run') + '/').replace('/proc/', str(self.root / 'proc') + '/')
            text = text.replace('/etc/ax6000-mesh/', str(self.root / 'etc') + '/')
            target=install_commands(self.root,{n:self.root/n for n in ['ip','bridge','uci']})
            self.assertFalse((target/'sbin/bridge').exists())
            text=sandbox_commands(text,target)
            self.script.write_text(text)
        self.env = {**os.environ, 'TS_MODEL': str(self.model)}

    def call(self, command, success=True):
        self.assertTrue(HELPER.exists(), 'Reconciler implementation is absent')
        for p, data in [(self.ownership, self.owner), (self.observation, self.obs)]:
            p.write_text(json.dumps(data)); p.chmod(0o600)
        args = [UCODE, '-L', '/tmp/mesh-ucode-build/*.so', str(self.script), command, str(self.ownership)]
        if command != 'prepare': args.append(str(self.observation))
        r = subprocess.run(args, env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
        self.state = json.loads(self.model.read_text())
        return r

    def assert_down(self):
        for n in ['ra2', 'rax2']: self.assertNotIn('UP', self.state['links'][n]['flags'])

    def attach_guests(self):
        # Separate provisioning stage, outside the reconciler, attaches only
        # already DOWN interfaces with the bridge's default PVID disabled.
        for n in ['ra2', 'rax2']:
            self.assertNotIn('UP', self.state['links'][n]['flags'])
            self.state['links'][n]['master'] = 'br-lan'
        self.model.write_text(json.dumps(self.state))

    def approve(self):
        proof = self.root / 'etc/ts-dataplane-approved'
        proof.write_text(self.owner['generation']); proof.chmod(0o600)

    def test_prepare_quarantines_only_owned_guests_and_allows_old_daemons(self):
        self.owner['daemons']['mapd']['starttime'] = 1
        before = copy.deepcopy(self.state)
        self.call('prepare'); self.assert_down()
        for n in ['ra2', 'rax2']: self.assertNotIn('master', self.state['links'][n])
        for n in ['br-lan', 'lan2', 'ra0', 'apcli0', 'foreign0']:
            self.assertEqual(self.state['links'][n], before['links'][n])
            self.assertEqual(self.state['vlans'][n], before['vlans'][n])

    def test_apply_disabled_stage_then_enable_after_exact_readback(self):
        self.call('prepare'); self.attach_guests(); self.call('apply'); self.assert_down()
        for n in ['ra2', 'rax2']:
            self.assertEqual(self.state['vlans'][n], [{'vlan': 10, 'flags': ['PVID', 'Egress Untagged']}])
        self.assertIn({'vlan': 10, 'flags': []}, self.state['vlans']['apcli0'])
        self.approve()
        for p in self.owner['guest_ports']: p['enabled'] = True
        self.call('apply'); self.call('verify')
        for n in ['ra2', 'rax2']: self.assertIn('UP', self.state['links'][n]['flags'])
        self.assertEqual(self.state['vlans']['foreign0'], [{'vlan': 1, 'flags': ['PVID', 'Egress Untagged']}])

    def test_invalid_lifecycle_observation_and_identity_fail_closed(self):
        for field, value in [('boot_id', 'ffffffff-ffff-ffff-ffff-ffffffffffff'), ('producer_pid', 999),
                             ('producer_start_ticks', 1), ('connection_generation', 2), ('sequence', 2),
                             ('controller_alid', '02:00:00:00:00:ee'), ('monotonic_ms', 11000)]:
            with self.subTest(field=field):
                self.call('prepare'); self.attach_guests(); old = self.obs[field]; self.obs[field] = value
                self.call('apply', False); self.assert_down(); self.obs[field] = old

    def test_command_failure_does_not_restore_forwarding_or_touch_management(self):
        self.call('prepare')
        self.attach_guests()
        self.state['fail'] = ['bridge', 'vlan', 'add', 'dev', 'rax2', 'vid', '10', 'pvid', 'untagged']
        self.model.write_text(json.dumps(self.state))
        for p in self.owner['guest_ports']: p['enabled'] = True
        self.call('apply', False); self.assert_down()
        self.assertIn('UP', self.state['links']['lan2']['flags'])
        self.assertEqual(self.state['vlans']['lan2'], [{'vlan': 1, 'flags': ['PVID', 'Egress Untagged']}])

    def test_unknown_vlan_port_or_missing_management_proof_rejected(self):
        self.call('prepare')
        self.attach_guests()
        self.state['vlans']['foreign0'].append({'vlan': 10, 'flags': []})
        self.model.write_text(json.dumps(self.state))
        self.call('apply', False); self.assert_down()

    def test_prepare_rejects_bssid_mismatch_without_touching_unknown_ports(self):
        self.owner['guest_ports'][0]['actual_bssid'] = '02:00:00:00:00:ee'
        self.call('prepare', False)
        self.assertIn('UP',self.state['links']['ra2']['flags'], 'The mismatched interface is not ours to mutate')
        self.assertNotIn('UP',self.state['links']['rax2']['flags'], 'Still-known ownership is quarantined')

    def test_missing_fields_private_files_and_symlink_inputs_are_rejected(self):
        for name in list(self.owner):
            with self.subTest(field=name):
                old = self.owner.pop(name); self.call('prepare', False); self.owner[name] = old
                self.assertEqual(self.state['calls'], [])
        self.ownership.write_text(json.dumps(self.owner)); self.ownership.chmod(0o644)
        result = subprocess.run([UCODE, '-L', '/tmp/mesh-ucode-build/*.so', str(self.script), 'prepare', str(self.ownership)],
                                env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.ownership.chmod(0o600)
        linked = self.root / 'linked'; linked.symlink_to(self.ownership)
        result = subprocess.run([UCODE, '-L', '/tmp/mesh-ucode-build/*.so', str(self.script), 'prepare', str(linked)],
                                env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_enable_requires_successfully_read_back_disabled_stage(self):
        self.call('prepare')
        self.attach_guests()
        for p in self.owner['guest_ports']: p['enabled'] = True
        self.call('apply', False); self.assert_down()
        for p in self.owner['guest_ports']: p['enabled'] = False
        self.state['ignore'] = ['bridge', 'vlan', 'add', 'dev', 'rax2', 'vid', '10', 'pvid', 'untagged']
        self.model.write_text(json.dumps(self.state))
        self.call('apply', False); self.assert_down()

    def test_verify_quarantines_enabled_guests_on_daemon_or_management_change(self):
        self.call('prepare'); self.attach_guests(); self.call('apply')
        self.approve()
        for p in self.owner['guest_ports']: p['enabled'] = True
        self.call('apply')
        self.state['links']['lan2']['flags'] = []
        self.model.write_text(json.dumps(self.state))
        self.call('verify', False); self.assert_down()

    def test_daemon_restart_and_disappearing_observation_quarantine_enabled_guests(self):
        self.call('prepare'); self.attach_guests(); self.call('apply')
        self.approve()
        for p in self.owner['guest_ports']: p['enabled'] = True
        self.call('apply')
        proc = self.root / 'proc/101/stat'; old = proc.read_text()
        proc.write_text(old.replace('900', '999'))
        self.call('verify', False); self.assert_down()
        proc.write_text(old); self.call('apply')
        self.observation.unlink()
        r = subprocess.run([UCODE, '-L', '/tmp/mesh-ucode-build/*.so', str(self.script), 'verify', str(self.ownership), str(self.observation)],
                           env=self.env, text=True, capture_output=True, timeout=10)
        self.assertNotEqual(r.returncode, 0)
        self.state = json.loads(self.model.read_text()); self.assert_down()

    def test_reused_guest_interface_is_not_treated_as_prepared_identity(self):
        self.call('prepare'); self.attach_guests()
        self.state['links']['ra2']['ifindex'] += 100
        self.model.write_text(json.dumps(self.state))
        self.call('apply', False); self.assert_down()

    def test_filtering_is_required_but_static_live_policy_is_not_a_heartbeat(self):
        self.call('prepare')
        self.attach_guests()
        self.state['links']['br-lan']['linkinfo']['info_data']['vlan_filtering'] = 0
        self.model.write_text(json.dumps(self.state)); self.call('apply', False); self.assert_down()
        self.state['links']['br-lan']['linkinfo']['info_data']['vlan_filtering'] = 1
        self.model.write_text(json.dumps(self.state))
        (self.root / 'proc/uptime').write_text('50.00 2.00\n')
        self.call('apply'); self.call('verify'); self.assert_down()

    def test_placeholder_policy_never_grants_quarantine_vid_membership(self):
        self.call('prepare'); self.attach_guests()
        self.obs['allowed_vids'].append(4093)
        self.obs['fh'].append({'bssid': '02:00:00:00:00:fe', 'vid': 4093})
        self.call('apply'); self.assert_down()
        self.state['vlans']['foreign0'].append({'vlan': 4093, 'flags': []})
        self.model.write_text(json.dumps(self.state))
        self.call('verify', False); self.assert_down()

    def controller(self):
        self.owner['cpu_guest_links'] = [{'ifname': 'br-lan.10', 'network': 'guest', 'vid': 10}]
        self.state['links']['br-lan.10'] = {'ifname':'br-lan.10','ifindex':20,'address':'02:00:00:00:00:01',
            'flags':['UP'],'link':'br-lan','linkinfo':{'info_kind':'vlan','info_data':{'id':10,'protocol':'802.1Q'}}}
        self.state['vlans']['br-lan'].append({'vlan':10,'flags':[]})
        self.state['uci'] = {'network.guest':'interface','network.guest.proto':'static','network.guest.device':'br-lan.10'}
        self.model.write_text(json.dumps(self.state))

    def test_explicit_existing_controller_cpu_vlan_and_network_are_preserved(self):
        self.controller()
        original = copy.deepcopy(self.state['links']['br-lan.10'])
        self.call('prepare'); self.attach_guests(); self.call('apply'); self.call('verify')
        self.approve()
        for p in self.owner['guest_ports']: p['enabled'] = True
        self.call('apply'); self.call('verify')
        self.assertEqual(self.state['links']['br-lan.10'], original)
        self.assertIn({'vlan':10,'flags':[]}, self.state['vlans']['br-lan'])
        self.assertFalse(any(c[0]=='uci' and 'set' in c for c in self.state['calls']))

    def test_controller_cpu_binding_changes_and_undeclared_cpu_membership_fail_closed(self):
        self.controller(); self.call('prepare'); self.attach_guests()
        self.state['uci']['network.guest.device'] = 'br-lan'
        self.model.write_text(json.dumps(self.state)); self.call('apply',False); self.assert_down()
        self.state['uci']['network.guest.device'] = 'br-lan.10'
        self.model.write_text(json.dumps(self.state))
        self.owner['cpu_guest_links'] = []
        self.call('prepare'); self.attach_guests(); self.call('apply',False); self.assert_down()

    def test_controller_cpu_device_cannot_also_be_assigned_to_another_network(self):
        self.controller(); self.call('prepare'); self.attach_guests()
        self.state['uci']['network.lan.device'] = 'br-lan.10'
        self.model.write_text(json.dumps(self.state))
        self.call('apply',False); self.assert_down()

    def test_reconciler_requires_exact_private_generation_approval_before_enable(self):
        self.call('prepare'); self.attach_guests(); self.call('apply')
        for p in self.owner['guest_ports']: p['enabled'] = True
        self.call('apply',False); self.assert_down()
        self.approve(); proof = self.root / 'etc/ts-dataplane-approved'
        proof.write_text('b'*32); self.call('apply',False); self.assert_down()
        self.approve(); proof.chmod(0o644); self.call('apply',False); self.assert_down()
        self.approve(); self.call('apply'); proof.unlink()
        self.call('verify',False); self.assert_down()
