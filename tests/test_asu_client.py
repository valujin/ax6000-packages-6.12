"""Execute the actual patched LuCI view and client policy with mock device RPC.

Never execute ARM code or send a real router upgrade request.
"""
import importlib.util
import gzip
import hashlib
import os
import re
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('asu_client', ROOT / 'scripts/asu_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class AsuClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def profile(self, cohort='66'):
        return {'package_manager': 'opkg' if cohort == '66' else 'apk', 'asu': {'enabled': True, 'cohort': cohort, 'server_url': client.URLS[cohort], 'seed': '1'*64}}

    def source(self, series):
        values = client._originals(series)
        files = {client.APP / client.JS: values['overview.js'],
                 client.APP / client.STATUS: values['status.js'],
                 client.APP / 'Makefile': values['Makefile'],
                 client.APP / client.ACL: values['acl.json'],
                 client.COMMON / 'Makefile': values['common.Makefile'],
                 client.COMMON / client.DEFAULTS: values['common.defaults']}
        for relative, data in files.items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)

    def node(self, code, view=None):
        if not shutil.which('node'):
            self.fail('node required to execute actual LuCI behavior tests')
        context = {'module': (ROOT / 'files/asu-client/ax6000_asu.js').read_text(), 'view': view,
                   'luci': gzip.decompress((ROOT / 'tests/fixtures/asu-client/612/luci.js.gz').read_bytes()).decode()}
        program = "const input = JSON.parse(require('fs').readFileSync(0,'utf8'));\n" + r"""
String.prototype.format=function(...args){let i=0;return this.replace(/%[sd]/g,()=>args[i++]);};
// Execute the pinned Class implementation and complete LuCI require() method.
// Only module transport and device dependencies are supplied by this harness.
const classStart=input.luci.indexOf('\tconst toCamelCase =');
const classEnd=input.luci.indexOf('\n\n\t/**\n\t * @class headers');
const requireStart=input.luci.indexOf('\t\trequire(name, from = []) {');
const requireEnd=input.luci.indexOf('\n\t\t/* DOM setup */',requireStart);
if(classStart<0 || classEnd<0 || requireStart<0 || requireEnd<0)throw Error('Pinned LuCI anchors differ');
const classSource=input.luci.slice(classStart,classEnd);
const requireSource=input.luci.slice(requireStart,requireEnd).trim().replace(/,$/,'');
const loaderFactory=new Function('source','dependencies',classSource+`
 const window={},document={},env={base_url:'/luci-static/resources'};
 const classes=Object.assign({baseclass:Class,view:Class.extend({})},dependencies);
 const Request={get:url=>Promise.resolve({ok:true,text:()=>source,url})};
 const LuCI=Class.extend({${requireSource},
   error(type,message,...args){throw new globalThis[type](message.format(...args));},
   raise(type,message,...args){throw new globalThis[type](message.format(...args));}
 });
 const instance=new LuCI();
 instance.resolveDefault=(p,d)=>Promise.resolve(p).catch(()=>d);
 instance.bind=(fn,obj,...args)=>fn.bind(obj,...args);
 instance.env={cgi_base:'/cgi-bin'};
 return {Class,instance};
`);
async function loadLuCI(source,name,dependencies={}) {
 const loader=loaderFactory(source,dependencies);
 const instance=await loader.instance.require(name);
 if(!(instance instanceof loader.Class))throw Error('LuCI did not instantiate a class');
 return instance;
}
(async()=>{
""" + code + "\n})().catch(e=>{console.error(e);process.exitCode=1;});\n"
        process = subprocess.run(['node', '-e', program], input=json.dumps(context), text=True,
                                 capture_output=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)

    def test_actual_pinned_loader_rejects_object_and_instantiates_policy(self):
        source = ROOT / 'tests/fixtures/asu-client/612/luci.js.gz'
        # Actual AE LuCI feed d6167ea0645cbd1327708d85f94824f42d0eb872.
        self.assertEqual(hashlib.sha256(gzip.decompress(source.read_bytes())).hexdigest(),
                         'a8fd2e9100249f54e64def80bf96d43a03b5af6a3f86a9f151d898994a1e1966')
        self.node(r"""
const assert=require('assert/strict');
await assert.rejects(loadLuCI("'use strict'; return {};",'invalid'), /factory yields invalid constructor/);
const a=await loadLuCI(input.module,'ax6000_asu');
assert.equal(typeof a.constructor,'function');
const Constructor=a.constructor;
assert.throws(()=>Constructor(), /Constructor must not be called without/);
assert.equal(Object.hasOwn(a,'runtime'),false); // method inherited from real Class prototype
assert.equal(a.runtime({schema_version:1,cohort:'612-recommended',package_manager:'apk',seed:'1'.repeat(64)},true,false),'apk');
""")

    def test_only_app_revisions_increase_and_common_revisions_stay_unchanged(self):
        self.assertEqual(client.release(self.profile('612-recommended')), '3')
        self.assertEqual(client.release(self.profile('66')), '2.ax6000asu3')
        original=client._originals('612')
        self.assertIn(b'PKG_RELEASE:=3\n',client._app_makefile(original['Makefile'],'apk'))
        self.assertIn(b'PKG_RELEASE:=2\n',client._common_makefile(original['common.Makefile'],'apk'))
        original=client._originals('66')
        self.assertIn(b'PKG_RELEASE:=2.ax6000asu3\n',client._app_makefile(original['Makefile'],'opkg'))
        self.assertIn(b'PKG_RELEASE:=2.ax6000asu2\n',client._common_makefile(original['common.Makefile'],'opkg'))

    def test_pinned_patches_all_cohorts_idempotent_and_sdk(self):
        for cohort in client.URLS:
            with self.subTest(cohort=cohort):
                shutil.rmtree(self.root)
                self.root.mkdir()
                self.source('66' if cohort == '66' else '612')
                first = client.apply(self.profile(cohort), self.root)
                self.assertTrue(first['changed'])
                self.assertFalse(client.apply(self.profile(cohort), self.root, check_only=True)['changed'])
                client.configure(self.profile(cohort), self.root)
                client.configure(self.profile(cohort), self.root, check_only=True)
                local = json.loads((self.root / 'files/etc/asu-cohort.json').read_text())
                self.assertEqual(local, {'schema_version': 1, 'cohort': cohort, 'seed': '1'*64, 'package_manager': 'opkg' if cohort == '66' else 'apk'})
                acl = json.loads((self.root / client.APP / client.ACL).read_text())['luci-app-attendedsysupgrade']
                self.assertEqual(acl['read']['file']['/etc/asu-cohort.json'], ['read'])
                self.assertEqual(acl['write']['file'], {'/sbin/sysupgrade --test /tmp/firmware.bin': ['exec']})
                self.assertIn('exec', acl['write']['ubus']['file'])
                self.assertNotIn('--force', json.dumps(acl))
                self.assertEqual(first['required_packages'], list(client.REQUIRED_PACKAGES))
                self.assertIn(client.URLS[cohort], (self.root / client.COMMON / client.DEFAULTS).read_text())
                self.assertEqual('etc/opkg/keys' in (self.root / client.COMMON / 'Makefile').read_text(), cohort == '66')
                self.assertIn('PKG_VERSION:=9' if cohort == '66' else 'PKG_VERSION:=10',
                              (self.root / client.COMMON / 'Makefile').read_text())

    def test_actual_pinned_luci_version_expression_honors_explicit_client_version(self):
        hashes = {'66': 'bc1a97fb6c3b4fef065227c6d1530ee580f0af3966d36a967fbca2da1c7000ac',
                  '612': '9716c9a7a1c276b867df5887558e2b63b78f7d3695915adb7fcd0a7f0182ed0d'}
        for series, manager in [('66', 'opkg'), ('612', 'apk')]:
            original = client._originals(series)['Makefile']
            source = (ROOT / 'tests/fixtures/asu-client' / series / 'luci.mk').read_bytes()
            self.assertEqual(hashlib.sha256(source).hexdigest(), hashes[series])
            expression, = re.findall(r'^  VERSION:=.+$', source.decode(), re.M)
            def evaluate(recipe):
                assignments = '\n'.join(re.findall(r'^PKG_(?:VERSION|RELEASE):=.+$', recipe.decode(), re.M))
                make = self.root / 'version.mk'
                make.write_text(assignments + '\nPKG_SRC_VERSION:=26.123.12345~legacy\n' + expression +
                                "\nall:\n\t@printf '%s\\n' '$(VERSION)'\n")
                return subprocess.check_output(['make', '-s', '-f', str(make)], text=True, timeout=10).strip()
            self.assertEqual(evaluate(client._release(original)), '26.123.12345~legacy')
            value = evaluate(client._app_makefile(original, manager))
            expected = client.APP_VERSION + '-r' + (client.APP_APK_RELEASE if manager == 'apk' else client.APP_OPKG_RELEASE)
            self.assertEqual(value, expected)
            self.assertGreater(int(client.APP_VERSION.split('.')[0]), 26)
            if manager == 'apk':
                apk = os.environ.get('AX6000_HOST_APK') or os.environ.get('AX6000_APK')
                if apk:
                    checked = subprocess.run([apk, 'version', '--check', value], capture_output=True, timeout=10)
                    self.assertEqual(checked.returncode, 0)
                    self.assertEqual(checked.stdout, b'')  # Invalid versions still exit zero.
                    self.assertEqual(checked.stderr, b'')
                    payload = self.root / 'apk-version-payload'; payload.mkdir(exist_ok=True)
                    (payload / 'fixture').write_bytes(b'never executed')
                    output = self.root / 'luci-app-attendedsysupgrade.apk'
                    subprocess.run([apk, '--no-network', 'mkpkg', '--info', 'name:luci-app-attendedsysupgrade',
                        '--info', 'version:' + value, '--info', 'arch:noarch', '--files', str(payload),
                        '--output', str(output)], check=True, capture_output=True, timeout=10)
                    self.assertTrue(output.is_file())

    def test_unknown_partial_and_wrong_cohort_sources_rejected(self):
        self.source('66')
        with self.assertRaisesRegex(ValueError, 'preimage/postimage'):
            client.apply(self.profile('612-latest'), self.root)
        js = self.root / client.APP / client.JS
        js.write_bytes(js.read_bytes() + b'\n// unknown source\n')
        with self.assertRaisesRegex(ValueError, 'preimage/postimage'):
            client.apply(self.profile(), self.root)

    def test_policy_url_identity_overlay_and_symlink_guard(self):
        for suffix in ['/', '//api/v1', '?other=true', '#cohort']:
            value = self.profile()
            value['asu']['server_url'] += suffix
            with self.assertRaises(ValueError):
                client.configure(value, self.root)
        for enabled in [False, None, 1]:
            value = self.profile()
            value['asu']['enabled'] = enabled
            with self.assertRaises(ValueError):
                client.policy(value)
        value = self.profile()
        value['asu']['seed'] = "foo'\ncommand"
        with self.assertRaises(ValueError):
            client.configure(value, self.root)
        (self.root / 'files').symlink_to('/tmp', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'escapes'):
            client.configure(self.profile(), self.root)
        self.assertIsNone(client.apply({}, self.root))

    def test_manager_profile_contract_new_apk_and_legacy_66_only(self):
        legacy66 = self.profile('66')
        del legacy66['package_manager']
        self.assertEqual(client.package_manager(legacy66), 'opkg')
        for cohort in ['612-recommended', '612-latest']:
            value = self.profile(cohort)
            self.assertEqual(client.package_manager(value), 'apk')
            del value['package_manager']
            with self.assertRaisesRegex(ValueError, 'explicit APK'):
                client.package_manager(value)
        value = self.profile('66')
        value['package_manager'] = 'apk'
        with self.assertRaisesRegex(ValueError, 'requires OPKG'):
            client.package_manager(value)

    def test_actual_policy_generation_snapshot_tail_and_layout(self):
        self.node(r"""
const assert = require('assert/strict');
const a = await loadLuCI(input.module,'ax6000_asu');
const local = {schema_version:1,cohort:'612-recommended',package_manager:'apk',seed:'1'.repeat(64)};
const remote = {...local,build_id:'build-one',catalog_sha256:'a'.repeat(64),snapshot_sha256:'b'.repeat(64),kernel_version:'6.12.108~'+'a'.repeat(32)+'-r1'};
assert(a.hasUpgrade(local,remote));
assert(!a.hasUpgrade({...remote},remote));
assert(a.hasUpgrade({...remote,snapshot_sha256:'c'.repeat(64)},remote));
assert(a.hasUpgrade({...remote,seed:'2'.repeat(64)},remote));
assert(a.same(remote,JSON.parse(JSON.stringify(remote,Object.keys(remote).reverse()))));
assert.throws(()=>a.hasUpgrade(local,{...remote,cohort:'612-latest'}), /cohort/);
assert.throws(()=>a.hasUpgrade(local,{...remote,kernel_version:'6.6.133'}), /foreign/);
assert.throws(()=>a.hasUpgrade(local,{...remote,snapshot_sha256:undefined}), /Incomplete/);
assert.throws(()=>a.identity({},false), /identity/);
assert.throws(()=>a.identity({...local,snapshot_sha256:'not-a-hash'},false), /Incomplete/);
assert.equal(a.runtime(local,{type:'file'},null),'apk');
assert.throws(()=>a.runtime(local,null,{type:'file'}), /differs/);
assert.throws(()=>a.runtime(local,null,null), /determine/);
assert.throws(()=>a.runtime(local,{type:'file'},{type:'file'}), /determine/);
assert.throws(()=>a.hasUpgrade({...local,package_manager:'opkg'},remote), /explicit firmware migration/);
const old612={schema_version:1,cohort:'612-recommended',seed:'1'.repeat(64)};
assert.equal(a.runtime(old612,null,{type:'file'}),'opkg');
assert.throws(()=>a.hasUpgrade(old612,remote), /explicit firmware migration/);
const old66={...old612,cohort:'66'};
assert.equal(a.runtime(old66,null,{type:'file'}),'opkg');
const remote66={...remote,cohort:'66',package_manager:'opkg',kernel_version:'6.6.133~'+'a'.repeat(32)+'-r1'};
assert(a.hasUpgrade(old66,remote66));
assert.throws(()=>a.identity({...old66,package_manager:'apk'},false), /requires OPKG/);
assert.throws(()=>a.target(local,{...remote,package_manager:undefined}), /package manager identity/);
assert.equal(a.server('https://asu.ezon.by/612/recommended///',local),'https://asu.ezon.by/612/recommended');
assert.throws(()=>a.server('https://asu.ezon.by/612/latest',local), /server/);
assert.throws(()=>a.server('https://asu.ezon.by/612/recommended?url=x',local), /server/);
for(const layout of ['stock','mtkuboot','ubootmod']) {
 const board='xiaomi,redmi-router-ax6000-'+layout, profile=board.replace(',','_');
 assert.equal(a.profile(board,local),profile);
 const installed={busybox:'1',pbr:'1.2.4-r2',tailscale:'1.104.2-r2'};
 const r=a.request(local,remote,board,profile,installed,['pbr']);
 assert(r.packages.includes('tailscale'));
 assert(r.packages.includes('busybox'));
 assert.deepEqual(r.installed_packages,['busybox','pbr','tailscale']);
 assert.equal(r.diff_packages,false);assert.equal(r.installed_package_manager,'apk');
 assert.deepEqual(r.ax6000,remote);
 assert.throws(()=>a.request(local,remote,board,'other',installed,[]),/layout/);
 const clean=a.request(local,remote,board,profile,{busybox:'1'},[]);
 assert(!clean.packages.includes('tailscale'));
 assert.throws(()=>a.request(local,remote,board,profile,{busybox:'1'},['tailscale']),/already installed/);
}
assert.throws(()=>a.profile('xiaomi,redmi-router-ax6000-mtkuboot',{...local,cohort:'66',package_manager:'opkg'}),/layout/);
""")

    def test_actual_status_check_uses_cohort_generation_and_own_origin(self):
        for series in ['66', '612']:
            status = client.patch_status(client._originals(series)['status.js']).decode()
            self.node(r"""
const assert=require('assert/strict');
const a=await loadLuCI(input.module,'ax6000_asu');
const local={schema_version:1,cohort:'612-recommended',package_manager:'apk',seed:'1'.repeat(64)};
const remote={...local,build_id:'build-one',catalog_sha256:'a'.repeat(64),snapshot_sha256:'b'.repeat(64),kernel_version:'6.12.108~'+'a'.repeat(32)+'-r1'};
let enabled=true,notifications=0,urls=[];
const board={board_name:'xiaomi,redmi-router-ax6000-stock',release:{version:'25.12-SNAPSHOT',target:'mediatek/filogic'}};
const rpc={declare:()=>()=>Promise.resolve(board)};
const fs={read:()=>Promise.resolve(JSON.stringify(local)),stat:path=>Promise.resolve(path==='/lib/apk/db/installed'?{type:'file'}:null)};
const uci={load:()=>Promise.resolve(),get_bool:()=>enabled,get_first:()=> 'https://asu.ezon.by/612/recommended'};
const fetch=async url=>{urls.push(url);return {ok:true,json:async()=>({ax6000:remote})};};
const ui={addTimeLimitedNotification:()=>{notifications++;}};
const E=()=>({});
const source=input.view+"\n";
globalThis.E=E;globalThis._=x=>x;globalThis.fetch=fetch;
const v=await loadLuCI(source,'status',{fs,rpc,uci,ui,ax6000_asu:a});
(async()=>{
 const data=await v.load();await v.oneshot(data);
 assert.equal(notifications,1);
 assert.deepEqual(urls,['https://asu.ezon.by/612/recommended/api/v1/revision/25.12-SNAPSHOT/mediatek/filogic']);
 data[3]={...remote};await v.oneshot(data);assert.equal(notifications,1);
 enabled=false;await v.oneshot(data);assert.equal(urls.length,2);
})().catch(e=>{console.error(e);process.exitCode=1;});
""", status)

    def test_actual_patched_view_full_request_and_verification_behavior(self):
        for series in ['66', '612']:
            view = client.patch_overview(client._originals(series)['overview.js']).decode()
            with self.subTest(series=series):
                self.node(r"""
const assert=require('assert/strict');
String.prototype.format=function(...args){let i=0;return this.replace(/%[sd]/g,()=>args[i++]);};
const policy=await loadLuCI(input.module,'ax6000_asu');
const local={schema_version:1,cohort:'612-recommended',package_manager:'apk',seed:'1'.repeat(64)};
const remote={...local,build_id:'build-one',catalog_sha256:'a'.repeat(64),snapshot_sha256:'b'.repeat(64),kernel_version:'6.12.108~'+'a'.repeat(32)+'-r1'};
let uploaded=false, validated=false, tested=false, upgrades=0, valid=true, testCode=0;
let captured, menu, callback, requestBody, notification;
const rpc={getSessionID:()=> 'session',declare: d=>(...args)=>{
 if(d.method==='packagelist'){assert.equal(args[0],true);return Promise.resolve({packages:{busybox:'1',tailscale:'1.104.2-r2','luci-app-attendedsysupgrade':'1'}});}
 if(d.method==='board') return Promise.resolve({board_name:'xiaomi,redmi-router-ax6000-stock',release:{version:'25.12-SNAPSHOT',revision:'r0+38427-ae65e1d',target:'mediatek/filogic'},rootfs_type:'squashfs'});
 if(d.method==='validate_firmware_image'){assert(uploaded); validated=true; return Promise.resolve({valid});}
 if(d.method==='upgrade_start'){assert(validated && tested); upgrades++; return Promise.resolve({});}
}};
const ui={showModal:(title,body)=>{menu=title;},hideModal:()=>{},createHandlerFn:(obj,fn,...args)=>()=>fn.apply(obj,args),awaitReconnect:()=>{},addNotification:(title,body)=>{notification=body;}};
const fs={read:()=>Promise.resolve(JSON.stringify(local)),stat:path=>Promise.resolve(path==='/lib/apk/db/installed'?{type:'file'}:null),exec:(path,args)=>{assert.equal(path,'/sbin/sysupgrade');assert.deepEqual(args,['--test','/tmp/firmware.bin']);tested=true;return Promise.resolve({code:testCode});}};
const uci={load:()=>Promise.resolve(),get_first:(c,s,o)=>o==='url'?'https://asu.ezon.by/612/recommended':0};
const form={JSONMap:class {constructor(data){this.data=data;} section(){return {option:()=>({value:()=>{}})};}render(){return Promise.resolve('form');}save(){return Promise.resolve();}},NamedSection:0,ListValue:0,Value:0,DynamicList:0};
const poll={add:fn=>{callback=fn;},start:()=>{},remove:()=>{}};
const E=(tag,attrs,children)=>{if(tag==='button' && attrs && attrs.click)captured=attrs.click;return {appendChild:()=>{},text:attrs};};
const request={get:(url,opts)=>{
 if(url.includes('cgi-upload')){uploaded=true;return Promise.resolve({json:()=>({sha256sum:'checksum'})});}
 if(opts && opts.responseType==='blob')return Promise.resolve({blob:()=>({})});
 return Promise.resolve({ok:true,json:()=>({revision:'r0+38427-ae65e1d',ax6000:remote})});
},request:(url,opts)=>{requestBody=opts.content;return Promise.resolve({status:202,json:()=>({request_hash:'hash',imagebuilder_status:'init'})});}};
globalThis.fixtureFormData=class{append(){}};
const source=input.view;
globalThis.E=E;globalThis._=x=>x;globalThis.FormData=globalThis.fixtureFormData;globalThis.setTimeout=()=>{};
const actual=await loadLuCI(source,'attendedsysupgrade',{form,uci,rpc,ui,poll,request,dom:{},fs,ax6000_asu:policy});
const flush=()=>new Promise(r=>setImmediate(r));
(async()=>{
 const [data,firmware]=await actual.load();
 assert.equal(firmware.profile,'xiaomi_redmi-router-ax6000-stock');
 assert.equal(firmware.rootfs_size_mb,null);
 actual.handleCheck(data,firmware);await flush();await flush();
 assert.equal(menu,'New firmware upgrade available'); // r0+ number unchanged, full generation differs
 await captured();await flush();await flush();callback();await flush();
 assert(requestBody.packages.includes('tailscale'));assert.equal(requestBody.diff_packages,false);
 assert.deepEqual(requestBody.ax6000,remote);
 assert.equal(requestBody.installed_package_manager,'apk');
 assert.equal(requestBody.profile,firmware.profile);
 await actual.handleInstall('/image',true,'checksum');await flush();
 assert.equal(upgrades,1);
 // No upgrade_start on rejected standard image validation.
 valid=false;await actual.handleInstall('/image',true,'checksum');
 assert.equal(upgrades,1);assert.match(notification.text,/verification/);
 valid=true;testCode=1;await actual.handleInstall('/image',true,'checksum');
 assert.equal(upgrades,1);assert.match(notification.text,/verification/);
 assert(!input.view.includes('--force'));
})().catch(e=>{console.error(e);process.exitCode=1;});
""", view)


if __name__ == '__main__':
    unittest.main()
