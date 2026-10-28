"""Run vendor WPS completion, profile serialization and reboot profile reading.

The driver and parameter store are fixtures. Production C functions, credential
structures and constants come from the authenticated sources. No real keys or
device access are used. Set WAPP_SOURCE_ARCHIVE to the pinned vendor archive.
"""
import gzip
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from test_mesh_wapp_dispatch import function

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'files/mediatek-mesh/packages/wapp'
SOURCE_HASH = '73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462'
UAPI_HASH = '821fa92e0b2f044928af64e420a4f1735635e7567f312add971c9d715da13898'

HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define GNU_PACKED __attribute__((packed))
#define MAX_LEN_OF_SSID 32
#define MAC_ADDR_LEN 6
#define MAX_NUM_OF_RADIO 6
#define MAX_PROFILE_KEYLEN 65
#define MAP_SUPPORT 1
#define TRUE 1
#define FALSE 0
#define NON_DRIVER_PARAM 0
#define DBGPRINT(...) ((void)0)
#define os_memset memset
#define os_memcpy memcpy
#define os_strcmp strcmp
#define os_strlen strlen
#define os_snprintf snprintf
#define os_snprintf_error(len,ret) ((ret)<0 || (size_t)(ret)>=(len))
#define os_free free
#define min(a,b) ((a)<(b)?(a):(b))
#define os_alloc_mem(ctx,ptr,len) (*(ptr)=calloc(1,(len)))
static size_t os_strlcpy(char *dst,const char *src,size_t size) {
    size_t length=strlen(src);
    if(size) { size_t n=length<size-1?length:size-1;memcpy(dst,src,n);dst[n]=0; }
    return length;
}
/* TYPES_AND_CONSTANTS */
typedef struct { int unused; } wapp_event_data;
struct wapp_dev { int dev_type; char ifname[16]; };
struct wrapper { int config_valid; wsc_apcli_config apcli_config; char raid[8]; };
struct map_info { int TurnKeyEnable,my_map_dev_role; struct wrapper apcli_configs[MAX_NUM_OF_RADIO]; };
struct wifi_app { struct map_info *map; void *drv_data; int wsc_save_bh_profile,wps_on_controller_cli,wsc_configs_pending; };
struct entry { char name[65],value[200]; };
static struct entry store[64],base_store[64];
static int saved_count,base_count,driver_error,driver_length,sends;
static unsigned char driver_data[512],sent[1024];
static size_t sent_length;
static struct wapp_dev interface={.dev_type=WAPP_DEV_TYPE_STA,.ifname="apclix0"};
static struct wapp_dev *wapp_dev_list_lookup_by_ifindex(struct wifi_app *w,u32 index) { (void)w;return index==7?&interface:NULL; }
static int driver_wext_get_wsc_profiles(void *d,const char *name,char *data,int *length) {
    (void)d;assert(!strcmp(name,"apclix0"));memcpy(data,driver_data,sizeof(driver_data));*length=driver_length;return driver_error;
}
static const char *saved(const char *name) {
    for(int i=0;i<saved_count;i++) if(!strcmp(store[i].name,name)) return store[i].value;
    return "";
}
static void save_map_parameters(struct wifi_app *w,const char *name,char *value,int kind) {
    (void)w;(void)kind;
    int i;for(i=0;i<saved_count;i++) if(!strcmp(store[i].name,name)) break;
    assert(i<64 && strlen(name)<sizeof(store[i].name) && strlen(value)<sizeof(store[i].value));
    strcpy(store[i].name,name);strcpy(store[i].value,value);
    if(i==saved_count) saved_count++;
}
static void get_map_parameters(struct map_info *map,const char *name,char *value,int kind,size_t size) {
    (void)map;(void)kind;
    /* WAPP reads mapd_cfg; runtime prepare merges the durable user overlay. */
    const char *result="";
    for(int i=0;i<base_count;i++) if(!strcmp(base_store[i].name,name)) result=base_store[i].value;
    if(!strcmp(name,"role_detection_external")) result="0";
    if(!strcmp(name,"DeviceRole")) result="2";
    os_strlcpy(value,result,size);
}
static int wapp_send_1905_msg(struct wifi_app *w,int type,size_t length,void *data) {
    (void)w;assert(type==WAPP_MAP_BH_CONFIG && length<=sizeof(sent));
    memcpy(sent,data,length);sent_length=length;sends++;return 0;
}
/* FUNCTIONS */
static void setup(struct wifi_app *app,struct map_info *map,int count) {
    memset(app,0,sizeof(*app));memset(map,0,sizeof(*map));memset(store,0,sizeof(store));
    memset(base_store,0,sizeof(base_store));base_count=0;
    saved_count=driver_error=sends=0;map->TurnKeyEnable=1;map->my_map_dev_role=DEVICE_ROLE_AGENT;
    app->map=map;app->wsc_configs_pending=1;interface.dev_type=WAPP_DEV_TYPE_STA;
    memset(driver_data,0,sizeof(driver_data));
    wsc_apcli_config_msg *msg=(void *)driver_data;
    msg->profile_count=count;
    driver_length=sizeof(*msg)+count*sizeof(wsc_apcli_config);
    for(int i=0;i<count;i++) {
        wsc_apcli_config *p=&msg->apcli_config[i];
        snprintf(p->ssid,sizeof(p->ssid),"test=backhaul-%d",i);p->SsidLen=strlen(p->ssid);
        memset(p->Key,'a'+i,32);p->KeyLength=32;
        p->AuthType=WSC_AUTHTYPE_WPA2PSK;p->EncrType=WSC_ENCRTYPE_AES;
    }
}
int main(void) {
    struct wifi_app app;struct map_info map;
    setup(&app,&map,1);
    assert(!app.wsc_save_bh_profile && !app.wps_on_controller_cli);
    wdev_handle_wsc_config_write(&app,7,NULL);
    assert(saved_count>0); /* First enrollment must survive a reboot. */
    assert(!strcmp(saved("BhProfile0Valid"),"1"));
    assert(!strcmp(saved("BhProfile0AuthMode"),"WPA2PSK"));
    assert(!strcmp(saved("BhProfile0EncrypType"),"AES"));
    assert(strlen(saved("BhProfile0WpaPsk"))==32);
    assert(!strcmp(saved("BhProfile0Ssid"),"test\x1a" "backhaul-0"));
    assert(sends==1 && !app.wsc_configs_pending);
    /* Cold process: prepare first merges mapd_user.cfg into mapd_cfg. The
     * getter must not pretend WAPP reads the writable user file directly. */
    assert(!base_count);
    memset(map.apcli_configs,0,sizeof(map.apcli_configs));sends=0;
    read_backhaul_configs(&app);
    assert(sends==1 && !((wsc_apcli_config_msg *)sent)->profile_count);
    memcpy(base_store,store,sizeof(store));base_count=saved_count;
    memset(map.apcli_configs,0,sizeof(map.apcli_configs));sends=0;
    read_backhaul_configs(&app);
    wsc_apcli_config_msg *loaded=(void *)sent;
    assert(sends==1 && loaded->profile_count==1);
    assert(sent_length>=sizeof(*loaded)+sizeof(wsc_apcli_config));
    assert(!strcmp(loaded->apcli_config[0].ssid,"test=backhaul-0"));
    assert(loaded->apcli_config[0].KeyLength==32);
    assert(!memcmp(loaded->apcli_config[0].Key,((wsc_apcli_config_msg *)driver_data)->apcli_config[0].Key,32));
    setup(&app,&map,1);interface.dev_type=WAPP_DEV_TYPE_APCLI;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(saved_count>0);
    /* Legacy explicit-save/controller-client paths retain their behavior. */
    setup(&app,&map,1);map.my_map_dev_role=DEVICE_ROLE_CONTROLLER;app.wsc_save_bh_profile=1;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(saved_count>0 && !app.wsc_save_bh_profile);
    setup(&app,&map,1);map.my_map_dev_role=DEVICE_ROLE_CONTROLLER;app.wps_on_controller_cli=1;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(saved_count>0 && !app.wps_on_controller_cli);
    /* Ordinary controller/AP and non-managed completion do not acquire profiles. */
    setup(&app,&map,1);map.my_map_dev_role=DEVICE_ROLE_CONTROLLER;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(!saved_count);
    setup(&app,&map,1);interface.dev_type=WAPP_DEV_TYPE_AP;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(!saved_count);
    setup(&app,&map,1);map.TurnKeyEnable=0;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(!saved_count);
    setup(&app,&map,1);driver_error=-1;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(!saved_count && !sends);
    /* Truncated/oversized replies and inconsistent credential lengths cannot be saved. */
    const int bad_lengths[]={0,3,512+1};
    for(size_t i=0;i<sizeof(bad_lengths)/sizeof(bad_lengths[0]);i++) {
        setup(&app,&map,1);driver_length=bad_lengths[i];
        wdev_handle_wsc_config_write(&app,7,NULL);assert(!saved_count && !sends);
    }
    setup(&app,&map,1);driver_length--;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(!saved_count && !sends);
    setup(&app,&map,1);((wsc_apcli_config_msg *)driver_data)->profile_count=255;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(!saved_count && !sends);
    setup(&app,&map,1);((wsc_apcli_config_msg *)driver_data)->apcli_config[0].SsidLen=33;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(!saved_count && !sends);
    setup(&app,&map,1);((wsc_apcli_config_msg *)driver_data)->apcli_config[0].KeyLength=65;
    wdev_handle_wsc_config_write(&app,7,NULL);assert(!saved_count && !sends);
    setup(&app,&map,0);
    wdev_handle_wsc_config_write(&app,7,NULL);assert(!saved_count);
    setup(&app,&map,2);
    wdev_handle_wsc_config_write(&app,7,NULL);
    assert(!strcmp(saved("BhProfile1Valid"),"1"));
    assert(saved("BhProfile1WpaPsk")[0]=='b');
    return 0;
}
'''


class WappProfilePersistence(unittest.TestCase):
    def source(self):
        archive = os.environ.get('WAPP_SOURCE_ARCHIVE')
        if not archive:
            self.skipTest('set WAPP_SOURCE_ARCHIVE for pinned-source behavior checks')
        self.assertEqual(hashlib.sha256(Path(archive).read_bytes()).hexdigest(), SOURCE_HASH)
        scratch = tempfile.TemporaryDirectory(prefix='wapp-persistence-test-')
        self.addCleanup(scratch.cleanup)
        with tarfile.open(archive) as vendor:
            vendor.extractall(scratch.name, filter='data')
        return Path(scratch.name) / 'wappd'

    def execute(self, source):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('host C compiler required')
        header = gzip.decompress((ROOT / 'tests/fixtures/mesh-uapi/wapp_cmm_type.h.gz').read_bytes())
        self.assertEqual(hashlib.sha256(header).hexdigest(), UAPI_HASH)
        header = header.decode()
        start = header.index('typedef struct GNU_PACKED _wsc_apcli_config {')
        end = header.index('} wsc_apcli_config_msg, *p_wsc_apcli_config_msg;', start)
        types = header[start:end + len('} wsc_apcli_config_msg, *p_wsc_apcli_config_msg;')]
        wps_header = (source / 'include/wps.h').read_text()
        constants = '\n'.join(re.findall(r'^#define WSC_(?:AUTHTYPE|ENCRTYPE)_.*$', wps_header, re.M))
        constants += '\n' + '\n'.join(re.findall(
            r'^#define DEVICE_ROLE_(?:AGENT|CONTROLLER)\s+.*$',
            (source / 'include/map.h').read_text(), re.M))
        device_header = (source / 'include/wdev.h').read_text()
        start = device_header.rfind('typedef enum {', 0, device_header.index('WAPP_DEV_TYPE_AP ='))
        constants += '\n' + device_header[start:device_header.index('} WAPP_DEV_TYPE;', start) + len('} WAPP_DEV_TYPE;')]
        event_header = (source / 'include/interface.h').read_text()
        start = event_header.rfind('enum {', 0, event_header.index('WAPP_MAP_MIN_CMD'))
        constants += '\n' + event_header[start:event_header.index('};', start) + 2]
        wps = (source / 'wps/wps.c').read_text()
        implementation = '\n'.join(function(wps, name) for name in (
            'char *WscGetAuthTypeStr(', 'char *WscGetEncryTypeStr(',
            'unsigned int WscGetAuthType(', 'unsigned char WscGetEncrypType(',
            'void write_configs(', 'void read_backhaul_configs('))
        implementation += '\n' + function((source / 'common/wdev.c').read_text(), 'void wdev_handle_wsc_config_write(')
        harness = source / 'persistence-test.c'
        harness.write_text(HARNESS.replace('/* TYPES_AND_CONSTANTS */', types + '\n' + constants)
                           .replace('/* FUNCTIONS */', implementation))
        binary = source / 'persistence-test'
        build = subprocess.run([compiler, '-std=c99', '-Wall', '-Wextra', '-Wno-unused-parameter',
                                '-Wno-sign-compare', str(harness), '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(build.returncode, 0, build.stderr)
        return subprocess.run([str(binary)], capture_output=True, text=True)

    def test_pinned_source_drops_first_enrollment_persistence(self):
        result = self.execute(self.source())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('saved_count>0', result.stderr)

    def test_patched_completion_survives_cold_profile_read(self):
        source = self.source()
        for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
            result = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.execute(source)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
