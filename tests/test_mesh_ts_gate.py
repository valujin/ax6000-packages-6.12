import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_mesh_slot_allocation import LIB


class ManagedGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.net = self.base / 'net'; self.trace = self.base / 'trace'
        (self.net / 'br-lan/bridge').mkdir(parents=True)
        (self.net / 'br-lan/bridge/vlan_filtering').write_text('1')
        for name in ('ra2', 'ra3', 'rax2', 'rax3'):
            (self.net / name).mkdir(); (self.net / name / 'flags').write_text('0x1')
            (self.net / name / 'master').symlink_to(self.net / 'br-lan')
        self.cfg = {'ax6000_mesh.main.enabled': '1', 'ax6000_mesh.main.linux_ts': '1'}
        self.rows = []
        for radio, band in [('radio0', '2g'), ('radio1', '5g')]:
            self.rows.append(f'wireless.{radio}=wifi-device')
            self.cfg.update({f'wireless.{radio}.type':'mtwifi', f'wireless.{radio}.band':band})
            for slot in range(4):
                section=f'{radio}ap{slot}'; self.rows.append(f'wireless.{section}=wifi-iface')
                self.cfg.update({f'wireless.{section}.device':radio, f'wireless.{section}.mode':'ap',
                                 f'wireless.{section}.map_bss_type':'64' if slot==1 else '32',
                                 f'wireless.{section}.network':'lan' if slot<2 else '', f'wireless.{section}.isolate':'1'})
        uci=self.base/'uci';uci.write_text('''#!/usr/bin/python3
import os,json,sys
s=json.load(open(os.environ['GATE_CONFIG']));a=sys.argv
if 'get' in a:print(s['cfg'].get(a[-1],''))
elif 'show' in a:print('\\n'.join(s['rows']))
''');uci.chmod(0o700)
        self.reconcile=self.base/'reconcile';self.reconcile.write_text('#!/bin/sh\necho prepare >> "$GATE_TRACE"\nexit 0\n');self.reconcile.chmod(0o700)
        ip=self.base/'ip';ip.write_text('''#!/usr/bin/python3
import sys,os
from pathlib import Path
p=Path(os.environ['GATE_NET'])/sys.argv[4]
with open(os.environ['GATE_TRACE'],'a') as f:f.write(' '.join(sys.argv[1:])+'\\n')
if sys.argv[5]=='down':(p/'flags').write_text('0x0')
if sys.argv[5]=='nomaster':(p/'master').unlink()
''');ip.chmod(0o700)
        source=(LIB/'ax6000-mesh-ts-gate').read_text().replace('/sys/class/net/',str(self.net)+'/')
        source=source.replace('/usr/libexec/ax6000-mesh-ts-reconcile',str(self.reconcile))
        self.owner=self.base/'ownership';self.owner.write_text('{}')
        source=source.replace('/etc/ax6000-mesh/ts-ownership.json',str(self.owner))
        source=source.replace('ip link set',str(ip)+' link set')
        source=source.replace('[ "$(id -u)" = 0 ]', f'[ "$(id -u)" = {os.getuid()} ]')
        self.script=self.base/'gate';self.script.write_text(source)
        self.env={**os.environ,'PATH':str(self.base)+':'+os.environ['PATH'],'GATE_CONFIG':str(self.base/'config'),'GATE_TRACE':str(self.trace),'GATE_NET':str(self.net)}

    def gate(self, success=True):
        (self.base/'config').write_text(json.dumps(dict(cfg=self.cfg,rows=self.rows)))
        r=subprocess.run(['busybox','ash',str(self.script),'preattach'],env=self.env,text=True,capture_output=True,timeout=10)
        self.assertEqual(r.returncode==0,success,r.stderr)
        return self.trace.read_text() if self.trace.exists() else ''

    def test_all_unknown_and_declared_slots_down_and_unbridged(self):
        trace=self.gate()
        self.assertTrue(trace.startswith('prepare\n'))
        for name in ('ra2','ra3','rax2','rax3'):
            self.assertEqual((self.net/name/'flags').read_text(),'0x0')
            self.assertFalse((self.net/name/'master').exists())

    def test_bootstrap_without_owner_still_quarantines_all_slots(self):
        self.owner.unlink()
        trace=self.gate()
        self.assertNotIn('prepare',trace)
        for name in ('ra2','ra3','rax2','rax3'):
            self.assertEqual((self.net/name/'flags').read_text(),'0x0')
            self.assertFalse((self.net/name/'master').exists())

    def test_guest_lan_attachment_fails_before_any_command(self):
        self.cfg['wireless.radio0ap2.network']='lan'
        self.assertEqual(self.gate(False),'')

    def test_missing_reconciler_and_disabled_filter_fail(self):
        self.reconcile.unlink();self.assertEqual(self.gate(False),'')

    def test_legacy_mode_is_unchanged(self):
        self.cfg['ax6000_mesh.main.linux_ts']='0'
        self.assertEqual(self.gate(),'')

@unittest.skipUnless(Path('/tmp/mesh-ucode-build/ucode').exists(), 'Real ucode required')
class NetifdManagedHook(unittest.TestCase):
    def test_hook_orders_quarantine_before_driver_and_attachment(self):
        patch=Path(__file__).resolve().parents[1]/'files/mediatek-mesh/patches/mtwifi-mesh.patch'
        text=patch.read_text().split('+++ b/package/mtk/applications/mtwifi-cfg-ucode/files/lib/netifd/wireless/mtwifi.sh\n',1)[1].split('\n--- a/',1)[0]
        source='\n'.join(line[1:] for line in text.splitlines() if line[:1] in (' ','+'))
        function='function handle_setup(data)'+source.split('function handle_setup(data)',1)[1].split('//              TEARDOWN',1)[0]
        for enabled, preflight, preattach, expected in [(False,0,0,['driver','up']), (True,1,0,['preflight','failed']),
                                                      (True,0,1,['preflight','driver','preattach','failed']),
                                                      (True,0,0,['preflight','driver','preattach','up'])]:
            with self.subTest(enabled=enabled,preflight=preflight,preattach=preattach):
                prefix='''let calls=[]; let cur_devname='radio0';
const l1parser={open:()=>({getall:()=>({radio0:{ext_ifname:'ra'}}),close:()=>{}})};
const uci={cursor:()=>({load:()=>{},get:()=>ENABLED,foreach:()=>{}})};
const netifd={set_retry:()=>{},setup_failed:()=>push(calls,'failed'),set_vif:()=>{},set_up:()=>push(calls,'up')};
const cfg={setup:()=>push(calls,'driver')};const log={info:()=>{},debug:()=>{},warn:()=>{}};
function system(cmd){let phase=index(cmd,'preflight')>=0?'preflight':'preattach';push(calls,phase);return phase=='preflight'?PREFLIGHT:PREATTACH;}
'''.replace('ENABLED',json.dumps('1' if enabled else '0')).replace('PREFLIGHT',str(preflight)).replace('PREATTACH',str(preattach))
                r=subprocess.run(['/tmp/mesh-ucode-build/ucode','-e',prefix+function+'\nhandle_setup({config:{},interfaces:{}});printf("%J",calls);'],capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stderr)
                self.assertEqual(json.loads(r.stdout),expected)
