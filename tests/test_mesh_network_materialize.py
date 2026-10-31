"""Exercise offline materialization with the real native UCI parser."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_mesh_slot_allocation import LIB, NATIVE

UCI = os.environ.get('MESH_TEST_UCI') or shutil.which('uci') or '/tmp/mesh-materialize-uci-build/uci'

class Materialize(unittest.TestCase):
    def setUp(self):
        if not Path(UCI).exists() or not (NATIVE/'bin/jshn').exists():
            self.skipTest('native UCI and jshn required (MESH_TEST_UCI)')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'bin').mkdir(); (self.root/'bin/uci').symlink_to(UCI)
        self.env = {**os.environ, 'PATH':str(self.root/'bin')+':'+str(NATIVE/'bin')+':'+os.environ['PATH'], 'LD_LIBRARY_PATH':str(NATIVE/'lib')}
        self.source = self.root/'source'
        self.source.write_text("""config wifi-device 'radio5'
 option band '5g'
 option map_mode '1'
config wifi-device 'radio24'
 option band '2g'
 option map_agent '0'
config custom 'untouched'
 option value 'keep me'
config wifi-iface 'guest'
 option device 'radio24'
 option mode 'ap'
 option network 'guest'
 option ssid 'Guest'
 option key 'private-guest'
 option encryption 'psk2'
 option wmm '0'
 list custom_list 'hello'
 list custom_list 'world'
config wifi-iface 'main5'
 option device 'radio5'
 option mode 'ap'
 option network 'lan'
 option ssid 'Main'
 option key 'private-main'
 option encryption 'psk2'
config wifi-iface 'ax6000_mesh_ap2'
 option device 'radio5'
 option mode 'ap'
 option network 'lan'
 option ssid 'BH'
 option key 'private-bh'
 option encryption 'sae'
 option map_bss_type '64'
config wifi-iface 'main'
 option device 'radio24'
 option mode 'ap'
 option network 'lan'
 option ssid 'Main'
 option key 'private-main'
 option encryption 'psk2'
config wifi-iface 'ax6000_mesh_ap1'
 option device 'radio24'
 option mode 'ap'
 option network 'lan'
 option ssid 'BH'
 option key 'private-bh'
 option encryption 'sae'
 option map_bss_type '64'
""")
        self.source.chmod(0o600)
        self.plan = {'ok':True, 'schema':1,'phase':'proposed','primary_network':'lan','bsses':[
            dict(id='main',band='2g',slot=0,network='lan',ssid='Main',security='psk2',ifname='ra0'),
            dict(id='main5',band='5g',slot=0,network='lan',ssid='Main',security='psk2',ifname='rax0'),
            dict(id='guest',band='2g',slot=3,network='guest',ssid='Guest',security='psk2',ifname='ra3')]}
        for bss in self.plan['bsses']: bss.update(hidden=0,isolate=0)
        self.creds = dict(schema=1, quarantine_key="private-quo'te\\secret",keys=[dict(id='main',key='private-main'),dict(id='main5',key='private-main'),dict(id='guest',key='private-guest')])
        self.helper=self.root/'helper'
        self.helper.write_text((LIB/'ax6000-mesh-materialize-networks').read_text().replace('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh')))
    def run_helper(self,ok=True,source=None,out='out',original=None):
        for name,data in [('plan',self.plan),('credentials',self.creds)]:
            path=self.root/name; path.write_text(json.dumps(data)); path.chmod(0o600)
        src=source or self.source; before=src.read_bytes()
        argv=['busybox','ash',str(self.helper),str(self.root/'plan'),str(self.root/'credentials'),str(src),str(self.root/out)]
        if original: argv.append(str(original))
        result=subprocess.run(argv,env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode==0,ok,result.stderr)
        self.assertEqual(src.read_bytes(),before); self.assertEqual(result.stdout,''); self.assertNotIn('private-',result.stderr)
        if not ok: self.assertFalse((self.root/out).exists())
        return self.root/out
    def show(self,output,restore=False):
        config=self.root/'inspect'; config.mkdir(exist_ok=True)
        shutil.copyfile(output/('user-wireless' if restore else 'wireless'),config/'wireless')
        result=subprocess.run([UCI,'-c',str(config),'-X','show','wireless'],env=self.env,capture_output=True,text=True,check=True)
        return result.stdout
    def test_dense_slots_credentials_and_overlay(self):
        out=self.run_helper(); s=self.show(out)
        names=[line.split('.')[1].split('=')[0] for line in s.splitlines() if line.endswith('=wifi-iface')]
        self.assertEqual(names,['main','ax6000_mesh_ap1','ax6000_mesh_slot24_2','guest','main5','ax6000_mesh_ap2','ax6000_mesh_slot5_2','ax6000_mesh_slot5_3'])
        self.assertNotIn('wireless.guest.network=',s); self.assertIn("wireless.guest.mesh_network='guest'",s)
        self.assertIn("wireless.guest.custom_list='hello' 'world'",s)
        self.assertIn("wireless.ax6000_mesh_ap1.key='private-bh'",s)
        self.assertLess(s.index('wireless.radio5='),s.index('wireless.radio24='))
        self.assertIn("wireless.untouched.value='keep me'",s)
        # Read exact quoted credential through UCI to verify stdin escaping.
        key=subprocess.run([UCI,'-c',str(self.root/'inspect'),'get','wireless.ax6000_mesh_slot24_2.key'],env=self.env,capture_output=True,text=True,check=True).stdout.rstrip('\n')
        self.assertEqual(key,self.creds['quarantine_key'])
        restored=self.show(out,True); self.assertNotIn('ax6000_mesh_',restored); self.assertIn("wireless.guest.network='guest'",restored); self.assertNotIn('map_mode=',restored)
        self.assertEqual((out/'wireless').stat().st_mode & 0o777,0o600)
    def test_idempotent_with_tombstone_placeholder(self):
        out=self.run_helper(); second=self.run_helper(source=out/'wireless',out='second')
        self.assertEqual(self.show(out),self.show(second))
        self.assertIn("wireless.guest.network='guest'",self.show(second,True))
    def test_unplanned_disabled_ap_fails(self):
        with self.source.open('a') as f: f.write("config wifi-iface 'extra'\n option disabled '1'\n option mode 'ap'\n")
        self.run_helper(False)
    def test_source_credentials_changed(self):
        self.creds['keys'][2]['key']='private-different'; self.run_helper(False)
    def test_duplicate_slot_fails(self):
        self.plan['bsses'][2].update(slot=0,ifname='ra0'); self.run_helper(False)
    def test_original_owned_fields_restored(self):
        original=self.root/'original'; original.write_text("config wifi-device 'radio24'\n option map_agent '7'\nconfig wifi-iface 'guest'\n option map_bss_type '9'\n")
        out=self.run_helper(original=original); s=self.show(out,True)
        self.assertIn("wireless.radio24.map_agent='7'",s); self.assertIn("wireless.guest.map_bss_type='9'",s)
        self.assertIn("wireless.guest.ssid='Guest'",s)

    def test_flags_changed_after_normalization(self):
        self.plan['bsses'][2]['isolate']=1; self.run_helper(False)
    def test_reserved_placeholder_collision(self):
        with self.source.open('a') as f: f.write("config wifi-iface 'ax6000_mesh_slot24_2'\n option mode 'ap'\n")
        self.run_helper(False)

    def test_actual_network_overrides_stale_mesh_network(self):
        self.source.write_text(self.source.read_text().replace(" option network 'guest'", " option network 'guest'\n option mesh_network 'oldguest'"))
        out=self.run_helper(); self.assertIn("wireless.guest.network='guest'",self.show(out,True))

    def test_owned_station_overlays_follow_ap_bank(self):
        with self.source.open('a') as f:
            for i,device in [(1,'radio24'),(2,'radio5')]:
                f.write(f"config wifi-iface 'ax6000_mesh_bh{i}'\n option mode 'sta'\n option device '{device}'\n option ssid 'StationBH'\n option key 'private-station'\n option custom 'preserved'\n")
        out=self.run_helper(); shown=self.show(out)
        names=[line.split('.')[1].split('=')[0] for line in shown.splitlines() if line.endswith('=wifi-iface')]
        self.assertEqual(names[-2:],['ax6000_mesh_bh1','ax6000_mesh_bh2'])
        self.assertEqual(len(names),10)
        self.assertIn("wireless.ax6000_mesh_bh1.key='private-station'",shown)
        self.assertIn("wireless.ax6000_mesh_bh2.custom='preserved'",shown)
        self.assertNotIn('ax6000_mesh_bh',self.show(out,True))
    def test_unowned_station_rejected(self):
        with self.source.open('a') as f: f.write("config wifi-iface 'other_sta'\n option mode 'sta'\n")
        self.run_helper(False)
    def test_owned_station_name_wrong_mode_rejected(self):
        with self.source.open('a') as f: f.write("config wifi-iface 'ax6000_mesh_bh1'\n option mode 'ap'\n")
        self.run_helper(False)
