"""Compile the real explicit-interface WAPP command and its ACK layers."""
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

HARNESS = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "include/list.h"
typedef unsigned char u8;
#define IFNAMSIZ 16
#define MAC_ADDR_LEN 6
#define WAPP_SUCCESS 0
#define WAPP_INVALID_ARG 1
#define WAPP_UNEXP 5
#define MAP_BH_ETH 0
#define MAP_BH_WIFI 1
#define MAP_DEFAULT_ETH_BH "eth2"
#define WAPP_SET_BH_TYPE 123
#define WAPP_DEV_TYPE_STA 2
#define DBGPRINT(...) ((void)0)
#define os_strcmp strcmp
#define os_strncmp strncmp
#define os_strlen strlen
#define os_memcmp memcmp
#define os_memset memset
#define os_memcpy memcpy
#define os_strncpy strncpy
#define os_sleep(...) ((void)0)
#define WAPP_VERSION "fixture"
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(a) (a)[0],(a)[1],(a)[2],(a)[3],(a)[4],(a)[5]
#define RED(a) a
#define MAP_GET_RADIO_IDNFER(r,id) memset(id,0,6)
struct wapp_dev { struct dl_list list; void *radio; int dev_type; char ifname[16]; u8 mac_addr[6]; };
struct wapp_conf { struct dl_list list; char iface[16]; };
struct map_info { int TurnKeyEnable, bh_type; struct wapp_dev *bh_wifi_dev; };
struct wifi_app { struct map_info *map; struct dl_list dev_list, conf_list; };
struct bh_type_info { u8 type; };
struct wapp_ctrl { int unused; };
static struct wifi_app global_app;
static struct map_info global_map;
static struct wapp_dev global_dev;
static int hw_error, send_error, ready_error, mac_queries, sends, readies, transport_error;
static u8 hw_mac[6];
static char ready_iface[16];
static u8 ready_mac[6];
static const char *ack_override;
static int is_zero_ether_addr(const u8 *m) { static const u8 zero[6]={0};return !memcmp(m,zero,6); }
static int is_multicast_ether_addr(const u8 *m) { return m[0]&1; }
static void AtoH(char *s,char *out,int n) { (void)s;memset(out,0,n); }
static int wapp_get_mac_addr_by_ifname(char *name,u8 *mac) {
    mac_queries++;if(strcmp(name,"wan")) fprintf(stderr,"Unexpected MAC lookup: %s\n",name);
    assert(!strcmp(name,"wan"));memcpy(mac,hw_mac,6);return hw_error;
}
static int wapp_send_1905_msg(struct wifi_app *app,int type,size_t len,char *data) {
    (void)app;assert(type==WAPP_SET_BH_TYPE && len==sizeof(struct bh_type_info));
    assert(((struct bh_type_info *)data)->type==MAP_BH_ETH);sends++;return send_error;
}
static int map_bh_ready(struct wifi_app *app,int type,u8 *name,u8 *mac,u8 *bssid) {
    assert(sends==1 && app->map->bh_type==MAP_BH_ETH && type==MAP_BH_ETH);
    assert(!memcmp(mac,bssid,6));strcpy(ready_iface,(char *)name);memcpy(ready_mac,mac,6);readies++;return ready_error;
}
static struct wapp_dev *wapp_dev_list_lookup_by_ifname(struct wifi_app *app,const char *name) { (void)app;return !strcmp(name,"ra0") ? &global_dev : NULL; }
/* HANDLER */
static struct {
    const char *cmd;
    int (*cmd_proc)(struct wifi_app *,const char *,u8,char **);
} map_cmd[]={{"set_bh_type",map_cmd_set_bh_type},{NULL,NULL}};
/* ROUTER */
/* SERVER */
/* PROCESS */
static int _wapp_ctrl_command(struct wapp_ctrl *ctrl,const char *cmd,char *rsp,size_t *rsp_len) {
    (void)ctrl;
    if(transport_error) return transport_error;
    const char *ack=ack_override;
    if(!ack) {
        char request[256];
        strcpy(request,cmd);
        size_t reply_len=2047;
        int ret=wapp_ctrl_iface_cmd_process(&global_app,request,rsp,&reply_len);
        assert(reply_len==0);
        ack=ret==0 ? "OK\n" : "FAIL\n";
    }
    assert(strlen(ack)<=*rsp_len);
    memcpy(rsp,ack,strlen(ack));*rsp_len=strlen(ack);return 0;
}
/* CLIENT */
static void reset(void) {
    memset(&global_app,0,sizeof(global_app));memset(&global_map,0,sizeof(global_map));
    global_map.TurnKeyEnable=1;global_map.bh_type=99;global_app.map=&global_map;
    dl_list_init(&global_app.conf_list);dl_list_init(&global_app.dev_list);
    hw_error=send_error=ready_error=mac_queries=sends=readies=transport_error=0;
    memset(hw_mac,0,6);hw_mac[0]=2;hw_mac[5]=9;ack_override=NULL;
}
static int command(char *name) {
    char *args[]={"ra0","map","set_bh_type","eth",name};
    return wapp_cli_cmd_ext(NULL,5,args);
}
int main(void) {
    reset();assert(command("wan")==0);
    assert(mac_queries==1 && sends==1 && readies==1 && global_map.bh_type==MAP_BH_ETH);
    assert(!strcmp(ready_iface,"wan") && !memcmp(ready_mac,hw_mac,6));
    const char *bad_names[]={"","bad/name","abcdefghijklmnop","wan;true"};
    for(size_t i=0;i<sizeof(bad_names)/sizeof(bad_names[0]);i++) {
        reset();assert(command((char *)bad_names[i])!=0);
        assert(mac_queries==0 && sends==0 && readies==0 && global_map.bh_type==99);
    }
    reset();hw_error=1;assert(command("wan")!=0);assert(sends==0 && readies==0 && global_map.bh_type==99);
    reset();memset(hw_mac,0,6);assert(command("wan")!=0);assert(sends==0 && readies==0);
    reset();hw_mac[0]=1;assert(command("wan")!=0);assert(sends==0 && readies==0);
    reset();global_map.TurnKeyEnable=0;assert(command("wan")!=0);assert(mac_queries==0 && sends==0 && readies==0);
    reset();send_error=-1;assert(command("wan")!=0);assert(sends==1 && readies==0 && global_map.bh_type==99);
    reset();ready_error=2;assert(command("wan")!=0);assert(sends==1 && readies==1);
    const char *bad_acks[]={"FAIL\n","OK","OK\nextra",""};
    for(size_t i=0;i<sizeof(bad_acks)/sizeof(bad_acks[0]);i++) {
        reset();ack_override=bad_acks[i];assert(command("wan")!=0);
    }
    reset();transport_error=-2;assert(command("wan")!=0);
    reset();ack_override="OK\n";assert(command("wan")==0);
    /* Legacy forms keep their existing ACK semantics. */
    char *legacy[]={"ra0","map","set_bh_type","eth"};
    reset();ack_override="FAIL\n";assert(wapp_cli_cmd_ext(NULL,4,legacy)==0);
    return 0;
}
'''


class ExplicitWappEthernet(unittest.TestCase):
    def test_real_interface_validation_and_daemon_ack_reach_cli(self):
        archive = os.environ.get('WAPP_SOURCE_ARCHIVE')
        if not archive:
            self.skipTest('set WAPP_SOURCE_ARCHIVE for pinned-source behavior checks')
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('host C compiler required')
        self.assertEqual(hashlib.sha256(Path(archive).read_bytes()).hexdigest(), SOURCE_HASH)
        with tempfile.TemporaryDirectory(prefix='wapp-ethernet-test-') as scratch:
            with tarfile.open(archive) as vendor:
                vendor.extractall(scratch, filter='data')
            source = Path(scratch) / 'wappd'
            for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
                result = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            mapping = (source / 'map/map.c').read_text()
            server = (source / 'common/ctrl_iface_unix.c').read_text()
            client = (source / 'wapp_ctrl/wapp_cli.c').read_text()
            harness = HARNESS.replace('/* HANDLER */', function(mapping, 'static int map_set_eth_bh_explicit(') + '\n' + function(mapping, 'int map_cmd_set_bh_type( struct wifi_app *wapp, const char *iface, u8 argc, char **argv)\n{'))
            harness = harness.replace('/* ROUTER */', function(mapping, 'int map_ctrl_interface_cmd_handle('))
            harness = harness.replace('/* SERVER */', function(server, 'static int wapp_ctrl_iface_cmd_map('))
            process = function(server, 'static int wapp_ctrl_iface_cmd_process(')
            # Other commands are unreachable here; keep the real outer router
            # and ACK decision, stubbing only unrelated command handlers.
            unrelated = sorted(set(re.findall(r'\b(wapp_ctrl_iface_cmd_\w+)\(', process)) - {'wapp_ctrl_iface_cmd_process', 'wapp_ctrl_iface_cmd_map'})
            stubs = '\n'.join('#define ' + name + '(...) 0' for name in unrelated)
            # Keep the vendor's pointer comparison in its legacy tail; the
            # explicit command must return before it to produce a real ACK.
            process = '#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored "-Wextra"\n' + process + '\n#pragma GCC diagnostic pop\n'
            harness = harness.replace('/* PROCESS */', stubs + '\n' + process)
            harness = harness.replace('/* CLIENT */', function(client, 'static int wapp_cli_cmd_ext('))
            test = source / 'ethernet-test.c'
            test.write_text(harness)
            binary = source / 'ethernet-test'
            build = subprocess.run([compiler, '-std=c99', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-sign-compare', '-I', str(source), str(test), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
