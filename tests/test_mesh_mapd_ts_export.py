"""Compile and execute the mapd TS event exporter against real patched source."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'files/mediatek-mesh/packages/mapd'
NATIVE = ROOT.parent / 'local-native-mesh-20261027/work/build/source/dl/mapd-6eca4331.tar.bz2'
HASH = '39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18'

class LocalTSObservation(unittest.TestCase):
    def setUp(self):
        archive = Path(os.environ.get('MAPD_SOURCE_ARCHIVE', str(NATIVE)))
        if not archive.exists(): self.skipTest('pinned mapd archive unavailable')
        cc = shutil.which('cc')
        if not cc: self.skipTest('host C compiler unavailable')
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), HASH)
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        with tarfile.open(archive) as tar: tar.extractall(root, filter='data')
        source = root / 'mapd'
        for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
            r = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.out = root / 'ts.json'; self.boot = root / 'boot'
        self.boot.write_text('12345678-1234-1234-1234-123456789abc\n')
        c = root / 'test.c'
        c.write_text(r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_VLAN_NUM 48
struct __attribute__((packed)) ts_fh_config { unsigned char itf_mac[6]; unsigned short vid; };
struct __attribute__((packed)) ts_fh_bss_setting { unsigned char itf_num; struct ts_fh_config fh_configs[0]; };
struct __attribute__((packed)) ts_common_setting { unsigned short primary_vid; unsigned char primary_pcp, policy_vid_num; unsigned short policy_vids[MAX_VLAN_NUM]; };
struct __attribute__((packed)) ts_setting { struct ts_common_setting common_setting; struct ts_fh_bss_setting fh_bss_setting; };
#include "mesh_ts_export.h"
int main(int argc,char **argv) {
 unsigned char buffer[sizeof(struct ts_setting)+2*sizeof(struct ts_fh_config)] = {0};
 unsigned char controller[6]={2,0,0,0,0,1};
 mesh_ts_connection_invalidate(); if(mesh_ts_connection_opened()) return 2;
 struct ts_setting *p=(struct ts_setting *)buffer;
 (void)argc;
 p->common_setting.primary_vid=1; p->common_setting.primary_pcp=0; p->common_setting.policy_vid_num=2;
 p->common_setting.policy_vids[0]=10; p->common_setting.policy_vids[1]=10;
 p->fh_bss_setting.itf_num=1; p->fh_bss_setting.fh_configs[0].itf_mac[0]=2;
 p->fh_bss_setting.fh_configs[0].itf_mac[5]=7; p->fh_bss_setting.fh_configs[0].vid=10;
 if (!strcmp(argv[1],"bad-vid")) p->fh_bss_setting.fh_configs[0].vid=20;
 if (!strcmp(argv[1],"bad-count")) p->common_setting.policy_vid_num=49;
 if (!strcmp(argv[1],"bad-mac")) p->fh_bss_setting.fh_configs[0].itf_mac[0]=1;
 if (!strcmp(argv[1],"truncated")) return mesh_ts_export(buffer,sizeof(*p),controller) == 0 ? 0 : 1;
 { int result=mesh_ts_export(buffer,sizeof(buffer),controller);
   if (!strcmp(argv[1],"pause")) sleep(2);
   return result == 0 ? 0 : 1; }
}
''')
        self.binary = root / 'test'
        r = subprocess.run([cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-I', str(source / 'src/1905_if'),
                            '-DMESH_TS_PATH="' + str(self.out) + '"', '-DMESH_TS_BOOT_ID="' + str(self.boot) + '"', str(c), '-o', str(self.binary)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_real_event_handler_stops_malformed_and_clear_before_driver(self):
        root = Path(self.tmp.name)
        source = root / 'mapd/src/1905_if/1905_if.c'
        text = source.read_text()
        case = text[text.index('\tcase _1905_SET_TRAFFIC_SEPARATION_SETTING_EVENT:'):text.index('\tcase _1905_SET_TRANSPARENT_VLAN_SETTING_EVENT:')]
        harness = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAP_R2 1
#define MAX_VLAN_NUM 48
#define _1905_SET_TRAFFIC_SEPARATION_SETTING_EVENT 1
#define WAPP_USER_SET_TRAFFIC_SEPARATION_SETTING 1
#define DEVICE_ROLE_CONTROLLER 1
#define DEVICE_ROLE_CONTRAGENT 3
#define err(...) ((void)0)
struct __attribute__((packed)) ts_fh_config { unsigned char itf_mac[6]; unsigned short vid; };
struct __attribute__((packed)) ts_fh_bss_setting { unsigned char itf_num; struct ts_fh_config fh_configs[0]; };
struct __attribute__((packed)) ts_common_setting { unsigned short primary_vid; unsigned char primary_pcp, policy_vid_num; unsigned short policy_vids[MAX_VLAN_NUM]; };
struct __attribute__((packed)) ts_setting { struct ts_common_setting common_setting; struct ts_fh_bss_setting fh_bss_setting; };
#include "mesh_ts_export.h"
struct __attribute__((packed)) msg { unsigned short type, mid, length; unsigned char buffer[0]; };
struct mapd_global { int unused; };
struct device { void *back_ptr; int device_role; unsigned char al_mac[6]; };
struct _1905_map_device { struct { unsigned char al_mac_addr[6]; } _1905_info; };
static struct _1905_map_device *topo_srv_get_controller_device(struct device *d) {(void)d;return NULL;}
static int stored, forwarded, force_no_controller;
static void map_store_local_ts_policy(void *x, void *buf, int len) { (void)x;(void)buf;(void)len;stored++; }
static int wlanif_issue_wapp_command(void *x,int a,int b,void *c,void *d,void *e,int f,int g,int h,int i) { (void)x;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;forwarded++;return 0; }
static void handle(struct msg *_1905_event, int len) {
 struct device dev={0}, *global=&dev; unsigned char *buf=_1905_event->buffer; int status=0,wapp_cmd_role=0;
 dev.device_role=force_no_controller ? 2 : DEVICE_ROLE_CONTROLLER;dev.al_mac[0]=2;
 switch (_1905_event->type) {
 /* CASE */
 }
 (void)status;
}
int main(void) {
 unsigned char data[sizeof(struct msg)+sizeof(struct ts_setting)+sizeof(struct ts_fh_config)]={0};
 struct msg *m=(struct msg *)data; struct ts_setting *p=(struct ts_setting *)m->buffer;
 m->type=1;m->length=sizeof(struct ts_setting)+sizeof(struct ts_fh_config);
 setenv("AX6000_MESH_LINUX_TS","1",1);
 mesh_ts_connection_invalidate();if(mesh_ts_connection_opened())return 6;
 p->common_setting.primary_vid=1;p->common_setting.policy_vid_num=1;p->common_setting.policy_vids[0]=10;
 p->fh_bss_setting.itf_num=1;p->fh_bss_setting.fh_configs[0].itf_mac[0]=2;p->fh_bss_setting.fh_configs[0].vid=10;
 handle(m,sizeof(data));if(stored!=0||forwarded!=0)return 1;
 p->fh_bss_setting.fh_configs[0].vid=20;handle(m,sizeof(data));if(stored!=0||forwarded!=0)return 2;
 p->common_setting.primary_vid=4095;p->common_setting.policy_vid_num=0;p->fh_bss_setting.fh_configs[0].vid=4095;
 handle(m,sizeof(data));if(stored!=0||forwarded!=0)return 3;
 m->length=0;handle(m,sizeof(data));if(stored!=0||forwarded!=0)return 4;
 /* A closed connection may not republish; a reopened one gets a new epoch. */
 mesh_ts_connection_invalidate();
 p->common_setting.primary_vid=1;p->common_setting.policy_vid_num=1;p->common_setting.policy_vids[0]=10;
 p->fh_bss_setting.fh_configs[0].vid=10;m->length=sizeof(struct ts_setting)+sizeof(struct ts_fh_config);
 handle(m,sizeof(data));if(!access(MESH_TS_PATH,F_OK))return 7;
 if(mesh_ts_connection_opened())return 8;
 handle(m,sizeof(data));
 { char result[4096]={0}; FILE *f=fopen(MESH_TS_PATH,"r");if(!f)return 9;
   if(!fgets(result,sizeof(result),f)){fclose(f);return 10;}fclose(f);
   if(!strstr(result,"\"connection_generation\":2") || !strstr(result,"\"sequence\":2"))return 11; }
 force_no_controller=1;handle(m,sizeof(data));if(!access(MESH_TS_PATH,F_OK))return 13;
 force_no_controller=0;
 mesh_ts_connection_invalidate();if(!access(MESH_TS_PATH,F_OK))return 12;
 unsetenv("AX6000_MESH_LINUX_TS"); m->length=sizeof(struct ts_setting); handle(m,sizeof(data));if(stored!=1||forwarded!=1)return 5;
 return 0;
}
""".replace('/* CASE */', case)
        c = root / 'handler.c'; c.write_text(harness)
        binary = root / 'handler'
        r = subprocess.run([shutil.which('cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-I', str(source.parent),
                            '-DMESH_TS_PATH="' + str(self.out) + '"', '-DMESH_TS_BOOT_ID="' + str(self.boot) + '"', str(c), '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run([str(binary)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.out.exists())

    def invoke(self, mode):
        return subprocess.run([str(self.binary), mode], capture_output=True, text=True)

    def test_process_identity_matches_live_producer(self):
        process = subprocess.Popen([str(self.binary), 'pause'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 1.5
            while not self.out.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            data = json.loads(self.out.read_text())
            fields = Path('/proc/%d/stat' % process.pid).read_text().rsplit(')', 1)[1].split()
            self.assertEqual(data['producer_pid'], process.pid)
            self.assertEqual(data['producer_start_ticks'], int(fields[19]))
            self.assertGreater(data['connection_generation'], 0)
        finally:
            process.terminate()
            process.communicate(timeout=3)

    def test_export_is_private_structured_and_invalid_event_removes_stale_file(self):
        self.assertEqual(self.invoke('valid').returncode, 0)
        data = json.loads(self.out.read_text())
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)
        self.assertEqual(data['schema'], 2)
        self.assertGreater(data['producer_pid'], 0)
        self.assertGreater(data['producer_start_ticks'], 0)
        self.assertEqual(data['connection_generation'], 1)
        self.assertEqual(data['controller_alid'], '02:00:00:00:00:01')
        self.assertEqual(data['allowed_vids'], [10])
        self.assertEqual(data['fh'], [{'bssid':'02:00:00:00:00:07','vid':10}])
        self.assertEqual(data['boot_id'], '12345678-1234-1234-1234-123456789abc')
        self.assertNotIn('ssid', data)
        self.assertNotIn('key', data)
        self.assertEqual(set(data['fh'][0]), {'bssid', 'vid'})
        for mode in ('bad-vid', 'bad-count', 'bad-mac', 'truncated'):
            with self.subTest(mode=mode):
                self.assertEqual(self.invoke('valid').returncode, 0)
                self.assertNotEqual(self.invoke(mode).returncode, 0)
                self.assertFalse(self.out.exists())
