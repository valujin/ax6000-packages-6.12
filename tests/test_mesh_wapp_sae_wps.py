"""Execute pinned WAPP's real driver-profile request with and without the fix."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT / 'files/mediatek-mesh/packages/wapp/patches'
DEFAULT = ROOT.parent / 'local-native-mesh-20261027/work/build/source/dl/wappd-80ca5724.tar.bz2'
SHA256 = '73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462'


def function(text, signature):
    start = text.index(signature); p = text.index('{', start); depth = 1; end = p + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}'); end += 1
    return text[start:end]


class WappPureSaeProfile(unittest.TestCase):
    def test_real_driver_payload_preserves_pure_sae(self):
        archive = Path(os.environ.get('WAPP_SOURCE_ARCHIVE', str(DEFAULT)))
        if not archive.exists(): self.skipTest('pinned vendor archive unavailable')
        compiler = shutil.which('cc')
        if not compiler: self.skipTest('host C compiler unavailable')
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), SHA256)
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(archive) as tar: tar.extractall(tmp, filter='data')
            source = Path(tmp) / 'wappd'
            patches = sorted(PATCHES.glob('*.patch'))
            for patch in patches:
                if patch.name.startswith('160-'): continue
                r = subprocess.run(['patch','-p1','--fuzz=0','-i',str(patch)],cwd=source,capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            old = function((source/'common/wapp_cmm.c').read_text(),'int wapp_set_bh_wsc_profile(')
            patch = PATCHES/'160-preserve-pure-sae-wps-backhaul.patch'
            r = subprocess.run(['patch','-p1','--fuzz=0','-i',str(patch)],cwd=source,capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            new = function((source/'common/wapp_cmm.c').read_text(),'int wapp_set_bh_wsc_profile(')
            harness = r'''
#include <assert.h>
#include <string.h>
#include <stddef.h>
#define MAP_SUPPORT 1
#define MAP_R3 1
#define WSC_AUTHTYPE_SAE 0x40
#define WSC_AUTHTYPE_WPA2PSK 0x20
#define AUTH_DPP_ONLY 0x80
#define BIT_BH_BSS 0x40
#define WAPP_WSC_SET_BH_PROFILE 7
#define WAPP_INVALID_ARG -1
#define TRUE 1
#define FALSE 0
#define BOOLEAN int
#define os_memset memset
#define os_memcpy memcpy
#define os_strlen strlen
#define COPY_MAC_ADDR(dst,src) memcpy(dst,src,6)
struct wifi_app { int unused; };
struct wapp_dev { int ifindex; char ifname[16]; };
struct wireless_setting { unsigned char Ssid[33], mac_addr[6], WPAKey[65]; unsigned short AuthMode, EncrypType; unsigned char map_vendor_extension; };
struct wapp_req { int req_id; struct { int ifindex; struct { struct { unsigned char Ssid[33]; size_t SsidLength; } SSID; unsigned char MacAddr[6], Key[65]; unsigned short AuthType, EncrType; unsigned char bss_role; size_t KeyLength; } bh_wsc_profile; } data; };
static struct wapp_req captured;
static int wapp_req_send(struct wifi_app *a,const char *n,struct wapp_req *r) {(void)a;(void)n;captured=*r;return 0;}
/* FUNCTION */
static void check(unsigned short auth,unsigned short expected) {
 struct wifi_app app={0};struct wapp_dev dev={.ifindex=4};struct wireless_setting p={0};
 strcpy((char*)p.Ssid,"fixture-bh");strcpy((char*)p.WPAKey,"fixture-key");p.mac_addr[0]=2;p.AuthMode=auth;p.EncrypType=8;p.map_vendor_extension=BIT_BH_BSS;
 assert(wapp_set_bh_wsc_profile(&app,&dev,&p)==0);
 assert(captured.req_id==WAPP_WSC_SET_BH_PROFILE && captured.data.ifindex==4);
 assert(captured.data.bh_wsc_profile.AuthType==expected && p.AuthMode==auth);
 assert(captured.data.bh_wsc_profile.EncrType==8 && captured.data.bh_wsc_profile.bss_role==BIT_BH_BSS);
 assert(!strcmp((char*)captured.data.bh_wsc_profile.SSID.Ssid,"fixture-bh"));
 assert(!strcmp((char*)captured.data.bh_wsc_profile.Key,"fixture-key"));
}
int main(void) {check(0x40,EXPECT_SAE);check(0x60,0x20);check(0x20,0x20);check(0xc0,0x20);return 0;}
'''
            for label, implementation, expected in [('before',old,'0x20'),('after',new,'0x40')]:
                c=Path(tmp)/(label+'.c');c.write_text(harness.replace('/* FUNCTION */',implementation).replace('EXPECT_SAE',expected))
                binary=Path(tmp)/label
                r=subprocess.run([compiler,'-std=gnu11','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stderr)
                r=subprocess.run([str(binary)],capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stderr)
