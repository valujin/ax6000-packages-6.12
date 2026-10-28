"""Execute WAPP's pinned event dispatcher with both daemon attachment orders.

Set WAPP_SOURCE_ARCHIVE to wappd-80ca5724.tar.bz2. The dispatcher, registration
helpers, event enum, and vendor linked lists are real. Minimal client/message
structures and a counting socket stub isolate routing. Opaque payload bytes must
arrive unchanged while the caller still owns the event.
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
PACKAGE = ROOT / 'files/mediatek-mesh/packages/wapp'
SOURCE_HASH = '73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462'


HARNESS = r'''
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "include/list.h"
/* REAL_EVENT_ENUM */
#define os_memcmp memcmp
#define os_strlen strlen
#define os_free free
#define DBGPRINT(...) ((void)0)
struct msg { unsigned short type; };
struct client_cmd { struct dl_list list; struct msg *cmd_buf; };
struct wapp_usr_intf_cli {
    struct dl_list list, cmd_list;
    char daemon_name[32];
    unsigned char registerd_event_bitmap[32];
    int sends;
};
struct wifi_app { struct { struct dl_list daemon_cli_list; } infcli_ctrl; };
struct _map_cmd_event { int (*match_func)(struct msg *,struct msg *); };
static struct _map_cmd_event *lookup_mapping_entry(int event,int command) { (void)event;(void)command;return NULL; }
static unsigned char expected[1024];
static const void *event_pointer;
static size_t event_length;
static void wapp_socket_send(struct wifi_app *w,char *data,size_t length,struct wapp_usr_intf_cli *dst) {
    (void)w;
    assert(data==event_pointer && length==event_length);
    assert(memcmp(data,expected,length)==0);
    dst->sends++;
}
/* REAL_FUNCTIONS */
static void init_client(struct wapp_usr_intf_cli *client,const char *name) {
    memset(client,0,sizeof(*client));
    dl_list_init(&client->list);dl_list_init(&client->cmd_list);
    strcpy(client->daemon_name,name);
}
int main(void) {
    for (int target_first=0;target_first<2;target_first++) {
        const unsigned short types[]={WAPP_MAP_BH_READY,WAPP_MAP_BH_CONFIG,WAPP_WPS_CONFIG_STATUS};
        for (size_t event_index=0;event_index<sizeof(types)/sizeof(types[0]);event_index++) {
            const unsigned short type=types[event_index];
            for (size_t payload_len=0;payload_len<=513;payload_len+=171) {
                for (int target_registered=0;target_registered<2;target_registered++) {
                    struct wifi_app wapp;
                    struct wapp_usr_intf_cli target,subscriber,unregistered;
                    struct { struct msg header; unsigned char payload[513]; } event;
                    memset(&event,0,sizeof(event));
                    event.header.type=type;
                    for(size_t byte=0;byte<payload_len;byte++) event.payload[byte]=(byte*17+3)&255;
                    event_pointer=&event;
                    event_length=sizeof(event.header)+payload_len;
                    memcpy(expected,&event,event_length);
                    dl_list_init(&wapp.infcli_ctrl.daemon_cli_list);
                    init_client(&target,"mapDemo_wapp_App");
                    init_client(&subscriber,"mapd");
                    init_client(&unregistered,"unregistered");
                    assert(register_event(&subscriber,type)==0);
                    if(target_registered) assert(register_event(&target,type)==0);
                    /* Match wapp_iface_attach(): each attachment inserts at head. */
                    if(target_first) {
                        dl_list_add(&wapp.infcli_ctrl.daemon_cli_list,&subscriber.list);
                        dl_list_add(&wapp.infcli_ctrl.daemon_cli_list,&target.list);
                    } else {
                        dl_list_add(&wapp.infcli_ctrl.daemon_cli_list,&target.list);
                        dl_list_add(&wapp.infcli_ctrl.daemon_cli_list,&subscriber.list);
                    }
                    dl_list_add_tail(&wapp.infcli_ctrl.daemon_cli_list,&unregistered.list);
                    send_event_dispatch(&wapp,&event.header,event_length,"mapDemo_wapp_App");
                    assert(target.sends==1); /* Even if target also registered. */
                    assert(unregistered.sends==0);
                    /* Separate assertion demonstrates CONFIG's r3 regression. */
                    assert(type!=WAPP_MAP_BH_CONFIG || subscriber.sends==1);
                    if(type==WAPP_MAP_BH_READY || type==WAPP_MAP_BH_CONFIG)
                        assert(subscriber.sends==1);
                    else
                        assert(subscriber.sends==!target_first); /* Existing routing. */
                    target.sends=subscriber.sends=unregistered.sends=0;
                    send_event_dispatch(&wapp,&event.header,event_length,NULL);
                    assert(subscriber.sends==1 && unregistered.sends==0);
                    assert(target.sends==target_registered);
                    target.sends=subscriber.sends=unregistered.sends=0;
                    send_event_dispatch(&wapp,&event.header,event_length,"absent-target");
                    assert(subscriber.sends==1 && unregistered.sends==0);
                    assert(target.sends==target_registered);
                    assert(memcmp(&event,expected,event_length)==0);
                }
            }
        }
    }
    return 0;
}
'''


def function(text, name):
    start = text.index(name)
    start = text.rfind('\n', 0, start) + 1
    opening = text.index('{', start)
    end, depth = opening + 1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


class WappBackhaulDispatch(unittest.TestCase):
    def source(self):
        archive = os.environ.get('WAPP_SOURCE_ARCHIVE')
        if not archive:
            self.skipTest('set WAPP_SOURCE_ARCHIVE for pinned-source behavior checks')
        self.assertEqual(hashlib.sha256(Path(archive).read_bytes()).hexdigest(), SOURCE_HASH)
        scratch = tempfile.TemporaryDirectory(prefix='wapp-dispatch-test-')
        self.addCleanup(scratch.cleanup)
        with tarfile.open(archive) as vendor:
            vendor.extractall(scratch.name, filter='data')
        return Path(scratch.name) / 'wappd'

    def execute(self, source):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('host C compiler required')
        implementation = (source / 'wapp_usr_intf/wapp_usr_intf.c').read_text()
        functions = '\n'.join(function(implementation, name) for name in (
            'int is_client_event_registered(', 'int register_event(', 'void send_event_dispatch('))
        harness = source / 'dispatch-test.c'
        interface = (source / 'include/interface.h').read_text()
        enum_start = interface.rfind('enum {', 0, interface.index('WAPP_MAP_MIN_CMD'))
        event_enum = interface[enum_start:interface.index('};', enum_start) + 2]
        harness.write_text(HARNESS.replace('/* REAL_FUNCTIONS */', functions)
                           .replace('/* REAL_EVENT_ENUM */', event_enum))
        binary = source / 'dispatch-test'
        # The unchanged vendor registration helper compares int with sizeof.
        build = subprocess.run([compiler, '-std=c99', '-Wall', '-Wextra', '-Werror', '-Wno-sign-compare', '-I', str(source), str(harness), '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(build.returncode, 0, build.stderr)
        return subprocess.run([str(binary)], capture_output=True, text=True)

    def test_pinned_dispatch_reproduces_attachment_order_failure(self):
        result = self.execute(self.source())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('subscriber.sends==1', result.stderr)

    def apply_patches(self, source, before=None):
        for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
            if before and patch.name >= before:
                continue
            apply = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, capture_output=True, text=True)
            self.assertEqual(apply.returncode, 0, apply.stdout + apply.stderr)

    def test_r3_dispatch_reproduces_config_attachment_order_failure(self):
        source = self.source()
        self.apply_patches(source, before='130-')
        result = self.execute(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('type!=WAPP_MAP_BH_CONFIG || subscriber.sends==1', result.stderr)

    def test_patch_delivers_readiness_and_config_once_without_changing_other_routing(self):
        source = self.source()
        self.apply_patches(source)
        result = self.execute(source)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
