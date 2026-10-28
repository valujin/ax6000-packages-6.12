"""Execute the real WAPP argument parser with native-runtime configuration paths."""
import hashlib
import os
from pathlib import Path
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
#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MAP_SUPPORT 1
#define IFNAMSIZ 16
#define IAPP_ENCRYPT_KEY_MAX_SIZE 32
#define FT_KDP_DEFAULT_IF_ETH "br-lan"
#define FT_KDP_DEFAULT_IF_WLAN "br-lan"
#define FT_KDP_DEFAULT_IF_WLAN_IOCTL "ra0"
#define FT_KDP_DEFAULT_PTK "fixture"
#define DEFAULT_IFNAME "ra0"
#define OPMODE_STA 0
#define OPMODE_AP 1
#define RA_WEXT 0
#define RA_NETLINK 1
#define RT_DEBUG_OFF 0
#define RT_DEBUG_ERROR 1
#define RT_DEBUG_WARN 2
#define RT_DEBUG_TRACE 3
#define RT_DEBUG_INFO 4
#define DBGPRINT(...) ((void)0)
#define os_strcmp strcmp
#define os_strncpy strncpy
#define os_memcpy memcpy
typedef struct {
    char IfNameEth[16],IfNameWlan[16],IfNameWlanIoctl[8][16],CommonKey[64];
    int IfNameWlanCount;
} RTMP_IAPP;
static void hs_usage(void) {}
static void IAPP_Usage(void) {}
static int foreground;
/* PARSER */
static int parse(char *config,size_t config_size,char *user,size_t user_size,char *path,char *user_path) {
    (void)config_size;(void)user_size;
    int mode=0,driver=0,debug=0,version=0;
    char filename[256]={0},iface[16]={0};RTMP_IAPP iapp={0};
    char *args[]={"wapp","-n","-d1","-v2","-cra0","-crax0","-F",path,"-u",user_path,NULL};
    optind=0;foreground=0;
    int result=process_options(10,args,filename,&mode,&driver,&debug,&version,iface,
                              config,/* CONFIG_SIZE */user,/* USER_SIZE */&iapp);
    if(result==0) {
        assert(foreground==1 && debug==RT_DEBUG_ERROR && version==2);
        assert(iapp.IfNameWlanCount==2 && !strcmp(iapp.IfNameWlanIoctl[0],"ra0") && !strcmp(iapp.IfNameWlanIoctl[1],"rax0"));
    }
    return result;
}
int main(void) {
    struct { char path[128]; unsigned char guard[8]; } cfg,user;
    memset(&cfg,0,sizeof(cfg));memset(&user,0,sizeof(user));
    memset(cfg.guard,0x5a,sizeof(cfg.guard));memset(user.guard,0xa5,sizeof(user.guard));
    assert(parse(cfg.path,sizeof(cfg.path),user.path,sizeof(user.path),"/etc/map/mapd_cfg","/etc/map/mapd_user.cfg")==0);
    assert(!strcmp(cfg.path,"/etc/map/mapd_cfg"));
    assert(!strcmp(user.path,"/etc/map/mapd_user.cfg"));
    for(size_t i=0;i<8;i++) assert(cfg.guard[i]==0x5a && user.guard[i]==0xa5);
    memset(cfg.path,0,sizeof(cfg.path));memset(user.path,0,sizeof(user.path));
    assert(parse(cfg.path,sizeof(cfg.path),user.path,sizeof(user.path),"","")==0);
    assert(!cfg.path[0] && !user.path[0]); /* Main retains its default-path branch. */
    char longest[128];memset(longest,'x',127);longest[127]=0;
    assert(parse(cfg.path,sizeof(cfg.path),user.path,sizeof(user.path),longest,longest)==0);
    assert(strlen(cfg.path)==127 && strlen(user.path)==127);
    char excessive[129];memset(excessive,'x',128);excessive[128]=0;
    assert(parse(cfg.path,sizeof(cfg.path),user.path,sizeof(user.path),excessive,longest)!=0);
    assert(parse(cfg.path,sizeof(cfg.path),user.path,sizeof(user.path),longest,excessive)!=0);
    char small[8]={0};
    assert(parse(small,sizeof(small),user.path,sizeof(user.path),"/etc/map/mapd_cfg",longest)!=0);
    assert(parse(cfg.path,sizeof(cfg.path),small,sizeof(small),longest,"/etc/map/mapd_user.cfg")!=0);
    for(size_t i=0;i<8;i++) assert(cfg.guard[i]==0x5a && user.guard[i]==0xa5);
    return 0;
}
'''


class WappConfigurationPaths(unittest.TestCase):
    def source(self):
        archive = os.environ.get('WAPP_SOURCE_ARCHIVE')
        if not archive:
            self.skipTest('set WAPP_SOURCE_ARCHIVE for pinned-source behavior checks')
        self.assertEqual(hashlib.sha256(Path(archive).read_bytes()).hexdigest(), SOURCE_HASH)
        scratch = tempfile.TemporaryDirectory(prefix='wapp-path-test-')
        self.addCleanup(scratch.cleanup)
        with tarfile.open(archive) as vendor:
            vendor.extractall(scratch.name, filter='data')
        return Path(scratch.name) / 'wappd'

    def execute(self, source):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('host C compiler required')
        main = (source / 'common/main.c').read_text()
        # The vendor's #ifdef/#else selects two signatures for the same body.
        parser = '#ifdef MAP_SUPPORT\n' + function(main, 'int process_options(')
        harness = HARNESS.replace('/* PARSER */', parser)
        explicit_sizes = 'map_cfg_len' in parser
        harness = harness.replace('/* CONFIG_SIZE */', 'config_size,' if explicit_sizes else '')
        harness = harness.replace('/* USER_SIZE */', 'user_size,' if explicit_sizes else '')
        if 'static int foreground;' not in main:
            # The pristine archive predates our foreground option.
            harness = harness.replace('assert(foreground==1 && debug==RT_DEBUG_ERROR && version==2);', '')
            harness = harness.replace('"wapp","-n",', '"wapp",')
            harness = harness.replace('process_options(10,', 'process_options(9,')
        cfile = source / 'path-test.c'
        cfile.write_text(harness)
        binary = source / 'path-test'
        build = subprocess.run([compiler, '-std=c99', '-Wall', '-Wextra', '-Wno-sizeof-pointer-memaccess',
                                '-Wno-sequence-point', str(cfile), '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(build.returncode, 0, build.stderr)
        return subprocess.run([str(binary)], capture_output=True, text=True)

    def test_pristine_parser_truncates_explicit_configuration_paths(self):
        result = self.execute(self.source())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('!strcmp(cfg.path,"/etc/map/mapd_cfg")', result.stderr)

    def test_r4_parser_still_truncates_explicit_configuration_paths(self):
        source = self.source()
        for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
            if patch.name >= '150-':
                continue
            result = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.execute(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('!strcmp(cfg.path,"/etc/map/mapd_cfg")', result.stderr)

    def test_patched_parser_preserves_paths_and_rejects_overlong_arguments(self):
        source = self.source()
        for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
            result = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.execute(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        main = (source / 'common/main.c').read_text()
        self.assertIn('map_cfg, sizeof(map_cfg), map_user_cfg, sizeof(map_user_cfg), &IAPP_Ctrl_Block', main)


if __name__ == '__main__':
    unittest.main()
