"""Run the read-only negotiated-security query with a bounded driver transport fake."""
import hashlib
import os
import re
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKAGE=ROOT/'files/mediatek-mesh/packages/mapd'
HARNESS=r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/wireless.h>
#define WAPP_APCLI_ASSOCIATED 1
struct bh_link_entry { unsigned char ifname[16],bssid[6]; unsigned int bh_assoc_state; struct bh_link_entry *next; };
struct mapd_global { struct { struct { struct bh_link_entry *first; } bh_link_head; } dev; };
#define SLIST_FOREACH_SAFE(e,h,f,t) for((e)=(h)->first; (e) && ((t)=(e)->next,1); (e)=(t))
static int mock_socket(int domain,int type,int protocol);
static int mock_ioctl(int fd,unsigned long request,...);
static int mock_close(int fd);
#define socket mock_socket
#define ioctl mock_ioctl
#define close mock_close
#include "mapd_interface/mesh_bh_security.inc"
static int failure,wrong_bssid,wrong_length;
static unsigned long peers=1;
static unsigned int auth=1U<<13,cipher=1U<<5;
static int mock_socket(int domain,int type,int protocol) {
    assert(domain==AF_INET && type==SOCK_DGRAM && protocol==0); return failure==1 ? -1: 42;
}
static int mock_close(int fd) { assert(fd==42); return 0; }
static int mock_ioctl(int fd,unsigned long request,...) {
    assert(fd==42 && request==SIOCIWFIRSTPRIV+0x1f);
    va_list ap;va_start(ap,request);struct iwreq *wrq=va_arg(ap,struct iwreq*);va_end(ap);
    assert(!strcmp(wrq->ifr_name,"apcli0") || !strcmp(wrq->ifr_name,"apclix0"));
    if (failure==2) return -1;
    struct mesh_bh_mac_table *table=wrq->u.data.pointer;
    assert(wrq->u.data.length==sizeof(*table));
    table->count=peers; table->entries[0].auth=auth;table->entries[0].cipher=cipher;
    memcpy(table->entries[0].mac,"\x02\x00\x00\x00\x00\x01",6);
    if(wrong_bssid) table->entries[0].mac[5]=2;
    if(wrong_length) wrq->u.data.length--;
    return 0;
}
static void check(struct mapd_global *g,int expected) {
    char reply[32]={0}; int len=mesh_bh_security(g,reply,sizeof(reply));
    assert(len==6);assert(!strcmp(reply,expected ? "sae=1\n":"sae=0\n"));
}
int main(void) {
    struct bh_link_entry first={.ifname="apcli0",.bssid={2,0,0,0,0,1},.bh_assoc_state=1};
    struct bh_link_entry second={.ifname="apclix0",.bssid={2,0,0,0,0,1},.bh_assoc_state=1};
    struct mapd_global g={.dev.bh_link_head.first=&first};
    check(&g,1);
    first.next=&second;check(&g,1);first.next=NULL;
    auth=1U<<7;check(&g,0); auth=(1U<<7)|(1U<<13);check(&g,0);auth=1U<<13;
    cipher=1U<<4;check(&g,0);cipher=(1U<<4)|(1U<<5);check(&g,0);cipher=1U<<5;
    peers=0;check(&g,0);peers=2;check(&g,0);peers=545;check(&g,0);peers=1;
    wrong_bssid=1;check(&g,0);wrong_bssid=0;
    wrong_length=1;check(&g,0);wrong_length=0;
    failure=1;check(&g,0);failure=2;check(&g,0);failure=0;
    strcpy((char*)first.ifname,"ra0");check(&g,0);strcpy((char*)first.ifname,"apcli0");
    first.bh_assoc_state=0;check(&g,0);first.bh_assoc_state=1;
    g.dev.bh_link_head.first=NULL;check(&g,0);
    assert(mesh_bh_security(&g,(char[1]){0},1)==-1);
    return 0;
}
'''

class LiveSaeQuery(unittest.TestCase):
    def execute(self, driver_definitions=""):
        archive=os.environ.get('MAPD_SOURCE_ARCHIVE')
        if not archive:self.skipTest('set MAPD_SOURCE_ARCHIVE for native C behavior checks')
        self.assertEqual(hashlib.sha256(Path(archive).read_bytes()).hexdigest(),'39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18')
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(archive) as vendor:vendor.extractall(tmp,filter='data')
            source=Path(tmp)/'mapd'
            for patch in sorted((PACKAGE/'patches').glob('*.patch')):
                if patch.name>'150-strict-sae-backhaul.patch':continue
                result=subprocess.run(['patch','-p1','--fuzz=0','-i',str(patch)],cwd=source,capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertTrue((source/'mapd_interface/mesh_bh_security.inc').is_file())
            harness=source/'query-test.c';harness.write_text(HARNESS.replace('#include "mapd_interface/mesh_bh_security.inc"', driver_definitions+'\n#include "mapd_interface/mesh_bh_security.inc"'))
            result=subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(harness),'-o',str(source/'query-test')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(source/'query-test')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_native_query_rejects_missing_stale_mixed_and_wrong_peer_evidence(self):
        self.execute()

    def test_query_layout_matches_authenticated_driver_types_and_constants(self):
        directory=os.environ.get('MTWIFI_DRIVER_SOURCE_DIR')
        if not directory:self.skipTest('set MTWIFI_DRIVER_SOURCE_DIR for actual driver ABI comparison')
        root=Path(directory)
        hashes={
            'embedded/common/cmm_info.c':'02768ebf04caafa7eb238f33e9251266dff7ffd80bb9452484626b9509283f42',
            'embedded/include/mgmt/mgmt_entrytb.h':'fd8a1bea114bf68fbe73fad8c8b857b05c40e4f119f13b9d933451cfd7e779d8',
            'embedded/include/security/sec_cmm.h':'05cd327953efd1928c47157488f67aa0ff986992a330c82dcf45c949fb5a1e85',
        }
        for path,expected in hashes.items():self.assertEqual(hashlib.sha256((root/path).read_bytes()).hexdigest(),expected)
        source=(root/'embedded/common/cmm_info.c').read_text()
        start=source.index('typedef union _HTTRANSMIT_SETTING_FIX {')
        end=source.index('UINT32 RTMPGetLastTxRate_fix(',start)
        definitions=source[start:end]
        header=(root/'embedded/include/mgmt/mgmt_entrytb.h').read_text()
        start=header.index('/* static size about MacTab in compiler time */')
        end=header.index('#endif /* ! defined(MT7986)',start)
        end=header.index('\n',end)
        definitions=header[start:end]+'\n'+definitions
        security=(root/'embedded/include/security/sec_cmm.h').read_text()
        for kind in ('AKM','CIPHER'):
            match=re.search(r'typedef enum _SEC_'+kind+r'_MODE \{.*?\}[^;]+;',security,re.S)
            self.assertIsNotNone(match)
            definitions+=match[0]+'\n'
        definitions='''#define MT7986 1
#define MAC_ADDR_LEN 6
#define UCHAR unsigned char
#define CHAR signed char
#define USHORT unsigned short
#define SHORT short
#define UINT16 unsigned short
#define UINT32 unsigned int
#define ULONG unsigned long
'''+definitions+'''
_Static_assert(sizeof(RT_802_11_MAC_ENTRY_FIX)==48,"native entry layout");
_Static_assert(sizeof(RT_802_11_MAC_TABLE_FIX)==26120,"native table layout");
_Static_assert(__builtin_offsetof(RT_802_11_MAC_ENTRY_FIX,AuthMode)==44,"native AKM offset");
_Static_assert(__builtin_offsetof(RT_802_11_MAC_ENTRY_FIX,EncryMode)==40,"native cipher offset");
_Static_assert(SEC_AKM_SAE_SHA256==13,"native SAE bit");
_Static_assert(SEC_CIPHER_CCMP128==5,"native CCMP bit");
'''
        self.execute(definitions)
