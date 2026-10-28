"""Check existing mapd startup query and execute its saved-profile response path."""
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

SOURCE_HASH = '39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18'

HARNESS = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#define GNU_PACKED __attribute__((packed))
#define TRUE 1
#define ETH_ALEN 6
#define SUPPORT_MULTI_AP 1
#define MSG_OFF 0
#define WAPP_USER_GET_BH_WIRELESS_SETTING 1
#define WAPP_MAP_BH_CONFIG 2
#define os_free free
#define os_memcpy memcpy
#define os_memset memset
#define err(...) ((void)0)
#define mapd_printf(...) ((void)0)
/* DEFINITIONS */
struct msg { unsigned short type,length; char buffer[0]; };
struct own_1905_device {
    unsigned int bh_config_count;
    struct wsc_apcli_config bh_configs[6];
    unsigned char conn_attempted_mac[6];
    int wsc_save_bh_profile,current_bh_state,config_status;
};
struct mapd_global { struct own_1905_device dev; };
static unsigned char ZERO_MAC_ADDR[6];
static int resets,timers,delay,requests;
static void issue_connect_timeout_handle(void *a,void *b) { (void)a;(void)b; }
static void ap_selection_retrigger_scan(void *a,void *b) { (void)a;(void)b; }
static void ap_selection_reset_scan(struct own_1905_device *d) { (void)d;resets++; }
static void eloop_cancel_timeout(void (*fn)(void*,void*),void *a,void *b) { (void)fn;(void)a;(void)b; }
static void eloop_register_timeout(int sec,int usec,void (*fn)(void*,void*),void *a,void *b) {
    (void)usec;(void)a;(void)b;assert(fn==ap_selection_retrigger_scan);timers++;delay=sec;
}
static int wlanif_issue_wapp_command(struct mapd_global *g,int cmd,int event,void *b,void *s,void *data,int len,int from,int response,int role) {
    (void)g;(void)b;(void)s;(void)data;(void)len;(void)from;(void)role;
    assert(cmd==WAPP_USER_GET_BH_WIRELESS_SETTING && event==WAPP_MAP_BH_CONFIG);
    assert(response==0);requests++;return 0;
}
/* FUNCTIONS */
static struct msg *profile_event(unsigned int count) {
    struct msg *event=calloc(1,sizeof(*event)+sizeof(struct wsc_apcli_config_msg)+sizeof(struct wsc_apcli_config));
    struct wsc_apcli_config_msg *config=(void *)event->buffer;
    config->profile_count=count;
    if(count==1) { strcpy(config->apcli_config[0].ssid,"test-backhaul");config->apcli_config[0].SsidLen=13; }
    return event;
}
int main(void) {
    struct mapd_global g={0};
    g.dev.current_bh_state=BH_STATE_DEFAULT;
    assert(mapd_get_bh_config(&g,NULL,NULL,0)==0 && requests==1);
    assert(g.dev.current_bh_state==BH_STATE_DEFAULT && !g.dev.config_status);
    wlanif_handle_bh_config_event(&g,profile_event(1));
    assert(g.dev.bh_config_count==1 && !strcmp(g.dev.bh_configs[0].ssid,"test-backhaul"));
    assert(g.dev.current_bh_state==BH_STATE_WIFI_BOOTUP && timers==1 && resets==1 && delay==2);
    assert(!g.dev.config_status); /* Loading credentials cannot manufacture association. */
    const int established[]={BH_STATE_WIFI_LINKUP,BH_STATE_ETHERNET_PLUGGED};
    for(size_t i=0;i<sizeof(established)/sizeof(established[0]);i++) {
        g.dev.current_bh_state=established[i];timers=resets=0;
        wlanif_handle_bh_config_event(&g,profile_event(1));
        assert(g.dev.current_bh_state==established[i] && !timers && !resets);
    }
    g.dev.current_bh_state=BH_STATE_DEFAULT;timers=resets=0;
    wlanif_handle_bh_config_event(&g,profile_event(0));
    assert(!g.dev.bh_config_count && !timers && !resets && g.dev.current_bh_state==BH_STATE_DEFAULT);
    return 0;
}
'''


class MapdSavedProfileStartup(unittest.TestCase):
    def test_existing_startup_query_and_cold_response_trigger_scan_only(self):
        archive = os.environ.get('MAPD_SOURCE_ARCHIVE')
        if not archive:
            self.skipTest('set MAPD_SOURCE_ARCHIVE for pinned-source behavior checks')
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('host C compiler required')
        self.assertEqual(hashlib.sha256(Path(archive).read_bytes()).hexdigest(), SOURCE_HASH)
        with tempfile.TemporaryDirectory(prefix='mapd-profile-test-') as scratch:
            with tarfile.open(archive) as vendor:
                vendor.extractall(scratch, filter='data')
            source = Path(scratch) / 'mapd'
            topology = (source / 'src/topologySrv/topologySrv.c').read_text()
            startup = function(topology, 'int topo_srv_init_own_info(')
            self.assertRegex(startup, r'if \(!\(\(struct mapd_global \*\)ctx->back_ptr\)->params.Certification\)\s*'
                             r'wlanif_issue_wapp_command\([^;]*WAPP_USER_GET_BH_WIRELESS_SETTING,\s*'
                             r'WAPP_MAP_BH_CONFIG, NULL, NULL, NULL, 0, 0, 1, 0\);')
            main = function((source / 'mapd.c').read_text(), 'struct mapd_global * mapd_init(')
            self.assertLess(main.index('wlanif_register_wapp_events(global)'), main.index('topo_srv_init_own_info('))
            handler = function((source / 'src/dot11_if/wapp_if.c').read_text(), 'void wlanif_handle_bh_config_event(')
            getter = function((source / 'mapd.c').read_text(), 'int mapd_get_bh_config(')
            interface = (source / 'interface.h').read_text()
            start = interface.index('struct GNU_PACKED wsc_apcli_config {')
            end = interface.index('};', interface.index('struct GNU_PACKED wsc_apcli_config_msg {', start)) + 2
            definitions = interface[start:end] + '\n'
            definitions += '\n'.join(re.findall(r'^#define WSC_APCLI_CONFIG_MSG_.*$', interface, re.M))
            definitions += '\n' + '\n'.join(re.findall(r'^#define BH_STATE_.*$', (source / 'mapd_i.h').read_text(), re.M))
            harness = source / 'profile-test.c'
            harness.write_text(HARNESS.replace('/* DEFINITIONS */', definitions).replace('/* FUNCTIONS */', handler + '\n' + getter))
            binary = source / 'profile-test'
            build = subprocess.run([compiler, '-std=c99', '-Wall', '-Wextra', '-Wno-unused-parameter', str(harness), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
