"""Strict SAE backhaul, using real pinned mapd selection functions and shell helpers."""
import hashlib
import os
import re
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from test_mesh_wapp_dispatch import function
import test_mesh_vendor as vendor_tests
import test_mesh_saved_profile as profile_tests

LIBRARY = vendor_tests.LIBRARY

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'files/mediatek-mesh/packages/mapd/patches/150-strict-sae-backhaul.patch'
SOURCE_HASH = '39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18'

HARNESS = r'''
#include <assert.h>
#include <string.h>
static const char *strict_env;
#define getenv(name) strict_env
#define TRUE 1
#define FALSE 0
/* AUTH DEFINITIONS */
#define SSID_EQUAL(a,al,b,bl) ((al)==(bl) && !memcmp((a),(b),(al)))
#define err(...) ((void)0)
#define info(...) ((void)0)
struct profile { char ssid[33]; unsigned int SsidLen,EncrType,AuthType; };
struct own_1905_device { int bh_config_count; struct profile bh_configs[2]; };
struct bss_info { char Ssid[33]; unsigned int SsidLen,EncrypType,AuthMode; };
/* FUNCTIONS */
static void check(unsigned int saved,unsigned int advertised,int matches,unsigned int after) {
    for (int which=0;which<3;which++) {
        struct own_1905_device ctx={.bh_config_count=1,.bh_configs={{"mesh",4,8,saved}}};
        struct bss_info bss={"mesh",4,8,advertised};
        int result=which==1 ? bss_profile_matches(&ctx,&bss) : which==2 ? get_matching_bss_profile_6g(&ctx,bss.Ssid,bss.SsidLen,bss.EncrypType,bss.AuthMode)>=0 : get_matching_bss_profile(&ctx,&bss)>=0;
        assert(result==matches);
        /* bss_profile_matches prefers SAE for mixed peers, getter keeps compatible AKMs. */
        unsigned int expected=(which==1 && matches && (advertised&0x40)) ? 0x40 : after;
        assert(ctx.bh_configs[0].AuthType==expected);
    }
}
int main(void) {
    const unsigned int rejected[]={0,1,2,4,8,0x10,0x20,0x22,0x80,0x100};
    for (unsigned int i=0;i<sizeof(rejected)/sizeof(rejected[0]);i++) check(0x40,rejected[i],0,0x40);
    check(0x40,0x40,1,0x40); check(0x40,0x60,1,0x40);
    check(0x20,0x20,1,0x20); check(0x60,0x20,1,0x60);
    check(0x60,0x40,1,0x60); check(0x60,0x60,1,0x60);
    check(0x20,0x40,1,0x40); /* Preserve vendor upgrade behavior. */
    check(0x20,1,0,0x20);
    for (int which=0;which<2;which++) {
        struct own_1905_device ctx={.bh_config_count=2,.bh_configs={{"mesh",4,8,0x40},{"mesh",4,8,0x20}}};
        struct bss_info bss={"mesh",4,8,0x20};
        assert(which ? bss_profile_matches(&ctx,&bss)==TRUE : get_matching_bss_profile(&ctx,&bss)==1);
        assert(ctx.bh_configs[0].AuthType==0x40 && ctx.bh_configs[1].AuthType==0x20);
        bss.SsidLen=3;
        assert(which ? !bss_profile_matches(&ctx,&bss) : get_matching_bss_profile(&ctx,&bss)==-1);
        bss.SsidLen=4; bss.EncrypType=4;
        assert(which ? !bss_profile_matches(&ctx,&bss) : get_matching_bss_profile(&ctx,&bss)==-1);
    }
    strict_env="sae";
    check(0x20,0x20,0,0x20); check(0x20,0x60,0,0x20);
    check(0x60,0x60,0,0x60); check(0x40,0x20,0,0x40);
    check(0x40,0x40,1,0x40); check(0x40,0x60,1,0x40);
    strict_env="invalid"; check(0x40,0x40,0,0x40);
    strict_env="psk2"; check(0x20,0x20,1,0x20); check(0x40,0x40,1,0x40);
    return 0;
}
'''

class MapdSae(unittest.TestCase):
    def test_real_selection_never_downgrades_pure_sae(self):
        archive = os.environ.get('MAPD_SOURCE_ARCHIVE')
        if not archive: self.skipTest('set MAPD_SOURCE_ARCHIVE for pinned-source behavior checks')
        compiler = shutil.which('cc')
        if not compiler: self.skipTest('host C compiler required')
        self.assertEqual(hashlib.sha256(Path(archive).read_bytes()).hexdigest(), SOURCE_HASH)
        with tempfile.TemporaryDirectory(prefix='mapd-sae-') as tmp:
            with tarfile.open(archive) as vendor: vendor.extractall(tmp, filter='data')
            source = Path(tmp) / 'mapd'
            if PATCH.exists():
                for patch in sorted(PATCH.parent.glob('*.patch')):
                    if patch.name > PATCH.name: continue
                    result = subprocess.run(['patch','-p1','--fuzz=0','-i',str(patch)],cwd=source,capture_output=True,text=True)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            code = (source / 'src/apSelection/apSelection.c').read_text()
            policy = function(code,'static int mesh_bh_profile_allowed(') if 'static int mesh_bh_profile_allowed(' in code else ''
            funcs = policy + '\n' + function(code,'signed int get_matching_bss_profile(') + '\n' + function(code,'unsigned char bss_profile_matches(') + '\n' + function(code,'signed int get_matching_bss_profile_6g(')
            header = (source / 'src/apSelection/apSelection.h').read_text()
            definitions = '\n'.join(re.findall(r'^#define WSC_AUTHTYPE_(?:SAE|DPP)\s+[^\n]+',header,re.M))
            harness = source / 'sae-test.c'; harness.write_text(HARNESS.replace('/* AUTH DEFINITIONS */',definitions).replace('/* FUNCTIONS */',funcs))
            for defines in ([],['-DMAP_R3']):
                with self.subTest(defines=defines):
                    binary = source / 'sae-test'
                    result = subprocess.run([compiler,'-std=c99','-Wall','-Wextra','-Werror',*defines,str(harness),'-o',str(binary)],capture_output=True,text=True)
                    self.assertEqual(result.returncode,0,result.stderr)
                    result = subprocess.run([str(binary)],capture_output=True,text=True)
                    self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(PATCH.is_file())

class SaePersistence(unittest.TestCase):
    setUp = vendor_tests.VendorPersistence.setUp
    tearDown = vendor_tests.VendorPersistence.tearDown
    save = vendor_tests.VendorPersistence.save
    def test_sae_backhaul_requires_pmf_and_preserves_fronthaul(self):
        self.save('ra0','AuthMode','WPA2PSKWPA3PSK')
        data = self.save('ra1','AuthMode','WPA3PSK')
        self.assertEqual(data['AuthMode'],'WPA2PSKWPA3PSK;WPA3PSK')
        self.assertEqual(data['PMFMFPC'],'1;1')
        self.assertEqual(data['PMFMFPR'],'0;1')
        self.assertEqual(data['PMFSHA256'],'0;0')
        data = self.save('ra1','AuthMode','WPA2PSK')
        self.assertEqual(data['PMFMFPC'],'1;0')
        self.assertEqual(data['PMFMFPR'],'0;0')

class SaeSavedProfile(unittest.TestCase):
    setUp = profile_tests.SavedBackhaulProfile.setUp
    tearDown = profile_tests.SavedBackhaulProfile.tearDown
    write_profile = profile_tests.SavedBackhaulProfile.write_profile
    check = profile_tests.SavedBackhaulProfile.check
    def test_pure_sae_profile_is_valid_and_private(self):
        self.values['BhProfile0AuthMode']='WPA3PSK'; self.write_profile()
        result=self.check()
        self.assertEqual(result.returncode,0)
        self.assertEqual(result.stdout+result.stderr,'')

class SaeRendering(unittest.TestCase):
    def test_sae_backhaul_is_independent_and_invalid_modes_do_not_truncate(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'wts'
            args=['sh','-c','. "$1"; shift; mesh_write_bss "$@"','sh',str(LIBRARY),str(output),'Home24','clientpass24','sae-mixed','Home5','clientpass5','psk2','PrivateBH','backhaulpass']
            result=subprocess.run(args+['sae'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            expected=output.read_text()
            rows=expected.splitlines()
            for index in (2,4,6): self.assertIn('PrivateBH 0x0040 0x0008 backhaulpass 1 0 hidden-Y',rows[index])
            self.assertIn('Home24 0x0060',rows[1]); self.assertIn('Home5 0x0020',rows[3])
            for invalid in ('sae-mixed','open','', 'SAE'):
                result=subprocess.run(args+[invalid],capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(output.read_text(),expected)
            # FH remains limited to the supported visible pairing modes.
            args[8]='sae'
            self.assertNotEqual(subprocess.run(args+['sae'],capture_output=True).returncode,0)

class SaeControl(unittest.TestCase):
    """Execute real preflight/apply through preparation, without device actions."""
    def invoke(self, role, security, action, *, selected_band=None, backhaul="wireless", committed=False, cli=None):
        import json
        with tempfile.TemporaryDirectory(prefix='mesh-sae-control-') as tmp:
            root=Path(tmp)
            for name in ('tmp/sysinfo','sys/class/net/br-lan/bridge','sys/class/net/ra0',
                         'sys/class/net/rax0','sys/class/net/br-lan/brif','sys/module/mapfilter',
                         'etc/ax6000-mesh','etc/map','var/lock','usr/share/ax6000-mesh/vendor','bin'):
                (root/name).mkdir(parents=True,exist_ok=True)
            (root/'tmp/sysinfo/board_name').write_text('xiaomi,redmi-router-ax6000-stock\n')
            (root/'sys/class/net/br-lan/bridge/vlan_filtering').write_text('0\n')
            for port in ('lan2','lan3','lan4'): (root/'sys/class/net/br-lan/brif'/port).touch()
            (root/'sys/class/net/br-lan/address').write_text('02:00:00:00:00:01\n')
            for name in ('mapd_default.cfg','mapd_user.cfg','1905d.cfg','ethernet_cfg.txt','wapp_ap_ra0.conf','wapp_ap_rax0.conf'):
                (root/'usr/share/ax6000-mesh/vendor'/name).write_text('')
            (root/'etc/ax6000-mesh/backhaul-ssid').write_text('FixtureBH\n')
            (root/'etc/ax6000-mesh/backhaul-key').write_text('fixture-bh-password\n')
            (root/'usr/share/ax6000-mesh/vendor/mapd_default.cfg').write_text('KeepDefault=yes\nBhPriority2G=3\nBhPriority5GL=1\nBhPriority5GH=1\n')
            (root/'etc/map/mapd_user.cfg').write_text('BhProfile0Valid=1\nBhProfile0AuthMode=WPA3PSK\n')
            if committed:
                (root/'etc/ax6000-mesh/phase').write_text('committed\n')
                (root/'etc/map/1905d.cfg').write_text('map_controller_alid=02:00:00:00:00:02\nmap_agent_alid=02:00:00:00:00:02\n')
                (root/'etc/map/wts_bss_info_config').write_text('retained-fronthaul-and-backhaul\n')
            values={'ax6000_mesh.main.role':role,'ax6000_mesh.main.backhaul':backhaul,
                    'ax6000_mesh.main.enabled':'0'}
            if security is not None: values['ax6000_mesh.main.backhaul_security']=security
            if selected_band is not None: values['ax6000_mesh.main.backhaul_band']=selected_band
            for index,band in ((0,'2g'),(1,'5g')):
                ap='wireless.client'+str(index); dev='radio'+str(index)
                values.update({ap+'.mode':'ap',ap+'.network':'lan',ap+'.device':dev,
                               ap+'.ssid':'Home'+str(index),ap+'.key':'fixture-password',ap+'.encryption':'sae-mixed',
                               'wireless.'+dev+'.type':'mtwifi','wireless.'+dev+'.band':band})
            config=root/'uci.json'; config.write_text(json.dumps(values))
            uci=root/'bin/uci'; uci.write_text('''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
p=Path(os.environ['TEST_UCI']); d=json.loads(p.read_text()); args=[a for a in sys.argv[1:] if a not in ('-q','-X')]
if args[0]=='get':
 if args[1] not in d: sys.exit(1)
 print(d[args[1]])
elif args[0]=='show': print('wireless.client0=wifi-iface\\nwireless.client1=wifi-iface')
elif args[0]=='set':
 key,value=args[1].split('=',1);d[key]=value;p.write_text(json.dumps(d))
''');uci.chmod(0o755)
            script=ROOT/'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-control'
            pieces=script.read_text().split('\ncase "${1:-}" in',1)
            source=pieces[0]
            dispatch='\ncase "${1:-}" in'+pieces[1] if cli is not None else ''
            source+= '\n# TEST_DISPATCH\n'+dispatch
            band_helper=root/'band-helper'
            band_helper.write_text((script.parent/'ax6000-mesh-band').read_text().replace('/etc/map/mapd_cfg',str(root/'etc/map/mapd_cfg')))
            band_helper.chmod(0o755)
            source=re.sub(r'/(?:etc|sys|tmp|var)/',lambda match: str(root)+match[0],source)
            source=source.replace('/usr/libexec/ax6000-mesh-band',str(band_helper))
            source=source.replace('/usr/share/ax6000-mesh/vendor.sh',str(LIBRARY))
            source=source.replace('template=/usr/share/ax6000-mesh/vendor','template='+str(root/'usr/share/ax6000-mesh/vendor'))
            source=source.replace('/usr/libexec/ax6000-mesh-transaction','transaction')
            source=source.replace('/usr/libexec/ax6000-mesh-profile','profile')
            datconf=root/'bin/datconf'
            datconf.write_text('''#!/usr/bin/python3
import sys
from pathlib import Path
a=sys.argv[1:]; p=Path(a[1]); op=a[2]; key=a[3]; lines=p.read_text().splitlines()
if op=='get':
 for line in lines:
  if line.startswith(key+'='): print(line.split('=',1)[1]); break
 else: sys.exit(1)
elif op=='set':
 lines=[line for line in lines if not line.startswith(key+'=')]; lines.append(key+'='+a[4]); p.write_text('\\n'.join(lines)+'\\n')
else: sys.exit(1)
''');datconf.chmod(0o755)
            stubs='''
abi_ok() { return 0; }
phase() { :; }
wapp() { :; }; wappctrl() { :; }; mapd() { :; }; p1905_managerd() { :; }; mapd_cli() { :; }
pidof() { return 1; }; modprobe() { :; }; profile() { :; }; iwpriv() { :; }
restore() { return 1; }
transaction() {
  if [ "$1" = seal ]; then success=1; exit 0; fi
}
wifi_config_save() { printf '%s %s %s\\n' "$1" "$2" "$3" >> "$TEST_SEED"; }
'''
            source=source.replace('# TEST_DISPATCH',stubs)
            if cli is None: source+=action+'\n'
            target=root/'control';target.write_text(source)
            seed=root/'seed'
            result=subprocess.run(['sh',str(target),*(cli or [])],env={**os.environ,'PATH':str(root/'bin')+':'+os.environ['PATH'],
                                  'TEST_UCI':str(config),'TEST_SEED':str(seed),'TEST_WTS':str(root/'etc/map/wts_bss_info_config'),'TEST_MAP':str(root/'etc/map/mapd_cfg')},capture_output=True,text=True,timeout=10)
            return result,json.loads(config.read_text()),seed.read_text() if seed.exists() else ''

    def test_missing_legacy_and_explicit_security_apply_to_both_backhaul_radios(self):
        for role in ('controller','agent'):
            for security in (None,'psk2','sae'):
                with self.subTest(role=role,security=security):
                    result,config,seed=self.invoke(role,security,'apply_mesh')
                    self.assertEqual(result.returncode,0,result.stderr)
                    expected=security or 'psk2'
                    for index in (1,2):
                        prefix='wireless.ax6000_mesh_ap'+str(index)
                        self.assertEqual(config[prefix+'.encryption'],expected)
                        self.assertEqual(config[prefix+'.ieee80211w'],'2' if expected=='sae' else '0')
                        self.assertEqual(config[prefix+'.map_bss_type'],'64')
                    if role=='agent':
                        for interface in ('ra1','rax1'):
                            self.assertIn(interface+' AuthMode '+('WPA3PSK' if expected=='sae' else 'WPA2PSK')+'\n',seed)
                        for interface in ('ra0','rax0'): self.assertIn(interface+' AuthMode WPA2PSKWPA3PSK\n',seed)
                    else: self.assertEqual(seed,'')

    def test_unknown_security_fails_before_preparing_any_wireless_section(self):
        for security in ('sae-mixed','open','SAE'):
            result,config,seed=self.invoke('controller',security,'apply_mesh')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Invalid backhaul security.',result.stderr)
            self.assertNotIn('wireless.ax6000_mesh_ap1',config)
            self.assertEqual(seed,'')

    def test_control_preparation_passes_sae_policy_into_wts(self):
        for security in (None,'psk2','sae'):
            result,_,_=self.invoke('controller',security,'preflight; prepare; cat "$TEST_WTS"')
            self.assertEqual(result.returncode,0,result.stderr)
            auth='0x0040' if security=='sae' else '0x0020'
            rows=result.stdout.splitlines()
            for index in (2,4,6): self.assertIn('FixtureBH '+auth+' 0x0008 fixture-bh-password 1 0 hidden-Y',rows[index])
