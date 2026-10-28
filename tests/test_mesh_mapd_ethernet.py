"""Apply the pinned mapd patches and execute its real backhaul handlers.

Set MAPD_SOURCE_ARCHIVE to the mapd-6eca4331 vendor tarball. The host harness
stubs transport and topology storage, while compiling the actual handler and
connection-status function unchanged from that verified archive.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'files/mediatek-mesh/packages/mapd'
SOURCE_HASH = '39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18'


HARNESS = r'''
#include <assert.h>
#include <stddef.h>
#include <string.h>
#define FALSE 0
#define ETH_ALEN 6
#define AUTO_CONFIG_PREX ""
#define ETH_ONBOARDING_STATE_START 1
#define WIFI_ONBOARDING_STATE_START 2
#define DEVICE_ROLE_AGENT 2
#define DEVICE_ROLE_UNCONFIGURED 0
#define WAPP_USER_SET_DHCP_CTL_REQUEST 1
#define WAPP_APCLI_DISASSOCIATED 0
#define WAPP_APCLI_ASSOCIATED 1
#define BH_STATE_ETHERNET_PLUGGED 2
#define DEVICE_CONFIGURED 2
#define IEEE802_11_GROUP 256
#define MSG_ERROR 0
#define err(...) ((void)0)
#define always(...) ((void)0)
#define mapd_printf(...) ((void)0)
#define os_strcmp strcmp
#define SLIST_FOREACH_SAFE(v,h,f,t) \
    for ((v)=(h)->first; (v) && (((t)=(v)->f),1); (v)=(t))
struct bh_link_entry { struct bh_link_entry *next_bh_link; char ifname[16]; unsigned char bssid[6]; int bh_assoc_state; };
struct backhaul_link_info { struct backhaul_link_info *next_bh; unsigned char connected_iface_addr[6]; };
struct iface_info { int media_type; };
struct _1905_map_device;
struct map_neighbor_info { struct map_neighbor_info *next_neighbor; struct _1905_map_device *neighbor; struct { struct backhaul_link_info *first; } bh_head; };
struct _1905_map_device { int visited; struct { struct map_neighbor_info *first; } neighbors_entry; };
struct dhcp_ctl_req { int dhcp_server_enable, dhcp_client_enable; };
struct own_1905_device {
    int auto_bh_switch, current_bh_state, config_status, dhcp_ctl_enable, device_role;
    int bh_ready_expected, ThirdPartyConnection, ConnectThirdPartyVend;
    void *back_ptr; struct dhcp_ctl_req dhcp_req;
    struct bh_link_entry *bh_dup_entry;
    struct { struct bh_link_entry *first; } bh_link_head;
};
struct _1905_context { int unused; };
struct mapd_global { struct own_1905_device dev; struct _1905_context *_1905_ctrl; struct { int Certification; } params; };
struct bh_link_info { int type, trigger_autconf; char ifname[16]; unsigned char mac_addr[6], bssid[6]; };
static struct _1905_map_device own, remote;
static struct iface_info iface;
static struct bh_link_info forwarded;
static int forwards, notifications, dhcp_calls, timers, controller_path, iface_present;
static void map_1905_Set_Bh_Ready(struct _1905_context *c, struct bh_link_info *b) { (void)c; forwarded=*b; forwards++; }
static void mapd_send_onboardstatus_to_app(struct mapd_global *g,int state,int type) { (void)g;(void)state;(void)type;notifications++; }
#define wlanif_issue_wapp_command(...) (dhcp_calls++)
static void map_register_dhcp_timer(struct own_1905_device *c) { (void)c;timers++; }
static void topo_srv_update_upstream_device(struct own_1905_device *c,void *v,unsigned char *b) { (void)c;(void)v;(void)b; }
static struct _1905_map_device *topo_srv_get_next_1905_device(struct own_1905_device *c,void *v) { (void)c;(void)v;return &own; }
static void topo_serv_clear_visit_node(struct own_1905_device *c) { (void)c; }
static void hopcnt_to_controller(struct _1905_map_device *d,char *h,char *t) { (void)d;*h=1;*t=controller_path; }
static struct iface_info *topo_srv_get_iface(struct _1905_map_device *d,unsigned char *m) { (void)d;(void)m;return iface_present ? &iface : NULL; }
/* REAL_FUNCTIONS */
int main(void) {
    struct mapd_global g={0};
    struct bh_link_info event={.type=0,.ifname="wan",.mac_addr={2,0,0,0,0,9}};
    struct map_neighbor_info neighbor={.neighbor=&remote};
    struct backhaul_link_info link={0};
    char result=9;
    g.dev.back_ptr=&g;
    topo_srv_parse_wapp_bh_ready(&g,&event);
    assert(g.dev.current_bh_state==BH_STATE_ETHERNET_PLUGGED);
    assert(forwards==1 && notifications==1 && forwarded.trigger_autconf==1);
    assert(!strcmp(forwarded.ifname,"wan"));
    assert(!memcmp(forwarded.mac_addr,event.mac_addr,6));
    /* Receiving a ready event alone must never prove a connection. */
    mapd_Get_Bh_ConnectionStatus(&g.dev,&result,1); assert(result==0);
    own.neighbors_entry.first=&neighbor; neighbor.bh_head.first=&link;
    iface_present=controller_path=1;
    mapd_Get_Bh_ConnectionStatus(&g.dev,&result,1); assert(result==0);
    g.dev.config_status=DEVICE_CONFIGURED;
    mapd_Get_Bh_ConnectionStatus(&g.dev,&result,1); assert(result==1);
    controller_path=0;
    mapd_Get_Bh_ConnectionStatus(&g.dev,&result,1); assert(result==0);
    controller_path=1; iface_present=0;
    mapd_Get_Bh_ConnectionStatus(&g.dev,&result,1); assert(result==0);
    iface_present=1; iface.media_type=IEEE802_11_GROUP;
    mapd_Get_Bh_ConnectionStatus(&g.dev,&result,1); assert(result==0);
    /* Preserve existing auto-switch and certification ownership. */
    g.dev.current_bh_state=7; g.dev.auto_bh_switch=1;
    topo_srv_parse_wapp_bh_ready(&g,&event); assert(g.dev.current_bh_state==7);
    g.dev.auto_bh_switch=0; g.params.Certification=1;
    topo_srv_parse_wapp_bh_ready(&g,&event); assert(g.dev.current_bh_state==7);
    g.params.Certification=0; event.type=1;
    topo_srv_parse_wapp_bh_ready(&g,&event); assert(g.dev.current_bh_state==7);
    /* Existing Ethernet DHCP initialization must still run when requested. */
    event.type=0; g.dev.dhcp_ctl_enable=1; g.dev.device_role=DEVICE_ROLE_AGENT;
    topo_srv_parse_wapp_bh_ready(&g,&event);
    assert(dhcp_calls==1 && timers==1);
    assert(g.dev.dhcp_req.dhcp_server_enable==0 && g.dev.dhcp_req.dhcp_client_enable==1);
    return 0;
}
'''


def function(text, name):
    start = text.index(name)
    start = text.rfind('\n', 0, start) + 1
    opening = text.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


class MapdEthernetState(unittest.TestCase):
    def source(self):
        archive = os.environ.get('MAPD_SOURCE_ARCHIVE')
        if not archive:
            self.skipTest('set MAPD_SOURCE_ARCHIVE for pinned-source behavior checks')
        self.assertEqual(hashlib.sha256(Path(archive).read_bytes()).hexdigest(), SOURCE_HASH)
        scratch = tempfile.TemporaryDirectory(prefix='mapd-ethernet-test-')
        self.addCleanup(scratch.cleanup)
        with tarfile.open(archive) as vendor:
            vendor.extractall(scratch.name, filter='data')
        return Path(scratch.name) / 'mapd'

    def patched_source(self):
        source = self.source()
        getter_before = function((source / 'mapd.c').read_text(), 'int mapd_Get_Bh_ConnectionStatus(')
        for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
            apply = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, capture_output=True, text=True)
            self.assertEqual(apply.returncode, 0, apply.stdout + apply.stderr)
        self.assertEqual(function((source / 'mapd.c').read_text(), 'int mapd_Get_Bh_ConnectionStatus('), getter_before)
        return source

    def execute(self, source):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('host C compiler required')
        handler = function((source / 'src/topologySrv/wappEvent.c').read_text(), 'void topo_srv_parse_wapp_bh_ready(')
        getter = function((source / 'mapd.c').read_text(), 'int mapd_Get_Bh_ConnectionStatus(')
        harness = source / 'ethernet-test.c'
        harness.write_text(HARNESS.replace('/* REAL_FUNCTIONS */', handler + '\n' + getter))
        binary = source / 'ethernet-test'
        build = subprocess.run([compiler, '-std=c99', str(harness), '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(build.returncode, 0, build.stderr)
        return subprocess.run([str(binary)], capture_output=True, text=True)

    def test_pinned_source_reproduces_missing_ethernet_state(self):
        result = self.execute(self.source())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('current_bh_state', result.stderr)

    def test_patch_applies_and_preserves_strong_connection_checks(self):
        result = self.execute(self.patched_source())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_diagnostic_reply_is_bounded_numeric_and_read_only(self):
        source = self.patched_source()
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('host C compiler required')
        implementation = (source / 'mapd_interface/ctrl_iface.c').read_text()
        diagnostic = function(implementation, 'static int mapd_get_bh_state(')
        self.assertIn('os_strcmp(buf, "GET bh_state") == 0', implementation)
        harness = source / 'diagnostic-test.c'
        harness.write_text(r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define BH_STATE_ETHERNET_PLUGGED 2
#define DEVICE_CONFIGURED 2
#define os_snprintf snprintf
#define os_snprintf_error(size,len) ((len)<0 || (size_t)(len)>=(size))
struct mapd_global {
    struct { unsigned int current_bh_state, config_status, auto_bh_switch; } dev;
    struct { unsigned int Certification; } params;
};
''' + diagnostic + r'''
int main(void) {
    struct mapd_global global={{7,1,0},{0}}, before=global;
    char reply[256];
    struct { char small[8]; char canary[8]; } bounded;
    memset(&bounded,'x',sizeof(bounded));
    int len=mapd_get_bh_state(&global,reply,sizeof(reply));
    assert(len>0 && (size_t)len==strlen(reply));
    assert(!strcmp(reply,"bh_state=7 ethernet_state=2 config_status=1 configured_state=2 auto_switch=0 certification=0\n"));
    assert(!memcmp(&global,&before,sizeof(global)));
    assert(mapd_get_bh_state(&global,bounded.small,sizeof(bounded.small))==-1);
    assert(!memcmp(bounded.canary,"xxxxxxxx",8));
    assert(!memcmp(&global,&before,sizeof(global)));
    assert(mapd_get_bh_state(&global,NULL,0)==-1);
    assert(!memcmp(&global,&before,sizeof(global)));
    return 0;
}
''')
        binary = source / 'diagnostic-test'
        build = subprocess.run([compiler, '-std=c99', '-Wall', '-Wextra', '-Werror', str(harness), '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(build.returncode, 0, build.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
