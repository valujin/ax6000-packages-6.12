"""Pinned full-feature multicall build contracts; no downloads or Go compilation."""
import copy
import importlib.util
import json
import gzip
import hashlib
import shutil
import subprocess
import struct
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CompactTailscale(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('tailscale_source_fixture', ROOT/'scripts/tailscale_source.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.lock = json.loads((ROOT/'tests/fixtures/tailscale-source-1.104.2.json').read_text())

    def test_locked_sources_and_host_tools_have_exact_immutable_urls(self):
        self.module.validate(self.lock)
        self.assertEqual(self.lock['version'], '1.104.2')
        for field in ('commit', 'sha256', 'url'):
            wrong = copy.deepcopy(self.lock); wrong[field] = 'moving'
            with self.subTest(field=field), self.assertRaises(ValueError): self.module.validate(wrong)
        for section in ('go', 'upx'):
            wrong = copy.deepcopy(self.lock); wrong[section]['url'] += '?mutable'
            with self.subTest(section=section), self.assertRaises(ValueError): self.module.validate(wrong)

    def test_exact_upstream_go_build_prerelease_is_accepted_and_wrong_revision_asset_is_rejected(self):
        lock=self.lock;sha=lock['commit'];go=lock['go'];tag='c3430f0d2b8a1d646ad3ae867e3470bac07f1fe0'
        responses={
            'https://api.github.com/repos/tailscale/tailscale/git/ref/tags/v1.104.2':json.dumps({'object':{'type':'tag','sha':tag}}).encode(),
            'https://api.github.com/repos/tailscale/tailscale/git/tags/'+tag:json.dumps({'object':{'type':'commit','sha':sha}}).encode(),
            'https://raw.githubusercontent.com/tailscale/tailscale/'+sha+'/go.toolchain.rev':(go['commit']+'\n').encode(),
            'https://raw.githubusercontent.com/tailscale/tailscale/'+sha+'/go.mod':b'module tailscale.com\ngo 1.27.3\n',
            'https://raw.githubusercontent.com/tailscale/go/'+go['commit']+'/VERSION':b'go1.27.3\ntime fixture\n',
            'https://api.github.com/repos/tailscale/go/releases/tags/build-'+go['commit']:json.dumps({'tag_name':'build-'+go['commit'],'draft':False,'prerelease':True,'assets':[{'name':'linux-amd64.tar.gz','browser_download_url':go['url'],'digest':'sha256:'+go['sha256'],'size':go['size']}]}).encode(),
            lock['url']:b'synthetic source bytes; source hash is tested against these exact bytes',
        }
        resolved=self.module.resolve('1.104.2',lambda url,*_:responses[url])
        self.assertEqual(resolved['commit'],sha);self.assertEqual(resolved['go'],go)
        release='https://api.github.com/repos/tailscale/go/releases/tags/build-'+go['commit']
        value=json.loads(responses[release]);value['assets'][0]['browser_download_url']=go['url'].replace(go['commit'],'a'*40)
        responses[release]=json.dumps(value).encode()
        with self.assertRaises(ValueError):self.module.resolve('1.104.2',lambda url,*_:responses[url])

    def test_inherited_go_and_upx_options_cannot_change_the_reviewed_build(self):
        with patch.dict(os.environ,{'UPX':'--force-pie --lzma','GOFLAGS':'-tags=ts_omit_netstack','TS_PERMIT_TOOLCHAIN_MISMATCH':'1'}):
            env,commands=self.module.build_commands(self.lock,Path('/source'),Path('/go'),Path('/upx'),Path('/work'),Path('/out'),4)
        self.assertNotIn('UPX',env);self.assertNotIn('GOFLAGS',env);self.assertNotIn('TS_PERMIT_TOOLCHAIN_MISMATCH',env)
        env,_=self.module.build_commands(self.lock,Path('/source'),Path('/go'),Path('/upx'),Path('/work'),Path('/out'),4,Path('/dl/tailscale-specific-cache'),True)
        self.assertEqual(env['GOPROXY'],'off');self.assertEqual(env['GOMODCACHE'],'/dl/tailscale-specific-cache')
        compile_block=self.module.recipe(self.lock).split('define Build/Compile',1)[1].split('endef',1)[0]
        self.assertIn('--module-cache $(DL_DIR)/tailscale-go-mod-cache-$(PKG_SOURCE_VERSION)',compile_block)
        self.assertIn('--offline',compile_block)
        self.assertIn('--prefetch-only',self.module.recipe(self.lock))
        self.assertIn('tailscale-go-mod-cache-$(PKG_SOURCE_VERSION)',self.module.recipe(self.lock))

    def test_existing_token_is_used_only_for_exact_api_metadata_and_never_redirected(self):
        with patch.dict(os.environ,{'GH_TOKEN':'fixture-token'}):
            self.assertEqual(self.module.request_headers('https://api.github.com/repos/tailscale/go')['Authorization'],'Bearer fixture-token')
            for url in ('https://raw.githubusercontent.com/tailscale/go/rev/VERSION', 'https://codeload.github.com/tailscale/tailscale/tar.gz/rev',
                        'https://github.com/tailscale/go/releases/download/build-rev/linux-amd64.tar.gz', 'https://api.github.com.evil.invalid/x', 'http://api.github.com/x'):
                self.assertNotIn('Authorization',self.module.request_headers(url))
        self.assertIsNone(self.module.MetadataNoRedirect().redirect_request(None,None,302,'redirect',{},'https://raw.githubusercontent.com/x'))
        with patch.dict(os.environ,{},clear=True):self.assertNotIn('Authorization',self.module.request_headers('https://api.github.com/repos/tailscale/go'))

    def test_build_keeps_every_feature_and_does_not_use_global_go_or_unsafe_upx_flags(self):
        env, commands = self.module.build_commands(self.lock, Path('/source'), Path('/isolated/go'), Path('/isolated/upx'), Path('/work'), Path('/out/tailscale.multicall'), 4)
        go = commands['compile']
        self.assertEqual(go[0], '/isolated/go/bin/go')
        self.assertEqual(go[go.index('-tags')+1], 'ts_include_cli')
        self.assertEqual(go[-1], './cmd/tailscaled')
        self.assertIn('-trimpath', go)
        self.assertIn('-s -w', go[go.index('-ldflags')+1])
        self.assertIn('gitCommitStamp='+self.lock['commit'], go[go.index('-ldflags')+1])
        self.assertEqual(env['GOTOOLCHAIN'], 'local'); self.assertEqual(env['CGO_ENABLED'], '0')
        self.assertEqual(env['GOARCH'], 'arm64'); self.assertEqual(env['GOMAXPROCS'], '4')
        self.assertEqual(env['GOSUMDB'], 'sum.golang.org'); self.assertEqual(env['GOPROXY'], 'https://proxy.golang.org')
        self.assertTrue(env['GOMODCACHE'].startswith('/work/'))
        self.assertNotIn('ts_omit', ' '.join(go))
        self.assertNotIn('--force', ' '.join(commands['compress']))
        self.assertIn('--no-lzma', commands['compress'])
        self.assertIn('-t', commands['test'])

    def test_recipe_is_package_format_neutral_with_one_regular_binary_and_relative_links(self):
        recipe = self.module.recipe(self.lock)
        self.assertIn('PKG_RELEASE:=3', recipe)
        self.assertIn('RSTRIP:=:', recipe)
        self.assertEqual(recipe.count('$(INSTALL_BIN) $(PKG_BUILD_DIR)/tailscale.multicall'), 1)
        self.assertIn('$(LN) tailscale.multicall $(1)/usr/sbin/tailscale', recipe)
        self.assertIn('$(LN) tailscale.multicall $(1)/usr/sbin/tailscaled', recipe)
        self.assertIn('files/tailscale.init', recipe); self.assertIn('files/tailscale.conf', recipe)
        for forbidden in ('golang-package.mk', 'opkg', 'apk add', '/usr/bin/tailscale', 'ts_omit'):
            self.assertNotIn(forbidden, recipe)

    @unittest.skipUnless(shutil.which('make') and shutil.which('file'), 'Native Make/install tools required')
    def test_native_make_install_keeps_one_binary_relative_aliases_wrappers_and_strip_protection(self):
        from test_tailscale_static_strip import NATIVE_FILES
        from test_verify_firmware import elf_fixture
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);include=root/'include';include.mkdir();files=root/'files';files.mkdir()
            for name in ('tailscale.init','tailscale.conf'):(files/name).write_text('unchanged '+name+'\n')
            native={}
            for name,sha in NATIVE_FILES.items():
                data=gzip.decompress((ROOT/'tests/fixtures'/('ax6000-612-'+name+'.gz')).read_bytes())
                self.assertEqual(hashlib.sha256(data).hexdigest(),sha);native[name]=data.decode()
            rules=native['rules.mk'].split('# strip an entire directory\n',1)[1].split('\nNINJA =',1)[0]
            (root/'rules.mk').write_text(rules)
            strip_line=next(line for line in native['include-package-pack.mk'].splitlines() if line.strip()=='$(RSTRIP) $$(IDIR_$(1))')
            (include/'package.mk').write_text('define BuildPackage\nall:\n\t$(call Package/$(1)/install,$(IDIR_$(1)))\n'+strip_line+'\nendef\n')
            scripts=root/'scripts';scripts.mkdir();(scripts/'rstrip.sh').write_text(native['scripts-rstrip.sh']);(scripts/'rstrip.sh').chmod(0o755)
            host=root/'host/bin';host.mkdir(parents=True);marker=root/'strip-called'
            (host/'sstrip').write_text('#!/bin/sh\necho strip > '+str(marker)+'\n');(host/'sstrip').chmod(0o755)
            build=root/'build'/('tailscale-'+self.lock['commit']);build.mkdir(parents=True)
            payload=bytearray(elf_fixture());struct.pack_into('<H',payload,16,2);(build/'tailscale.multicall').write_bytes(payload)
            output=root/'package'
            common='TOPDIR:='+str(root)+'\nINCLUDE_DIR:='+str(include)+'\nBUILD_DIR:='+str(root/'build')+'\nSCRIPT_DIR:='+str(scripts)+'\nSTAGING_DIR_HOST:='+str(root/'host')+'\nCONFIG_USE_SSTRIP:=y\nCONFIG_SSTRIP_DISCARD_TRAILING_ZEROES:=y\nINSTALL_DIR:=install -d -m0755\nINSTALL_BIN:=install -m0755\nINSTALL_DATA:=install -m0644\nLN:=ln -sf\nIDIR_tailscale:='+str(output)+'\n'
            subprocess.run(['make','--no-print-directory','-f','-','all'],input=common+self.module.recipe(self.lock),cwd=root,text=True,check=True,capture_output=True,timeout=5)
            self.assertEqual((output/'usr/sbin/tailscale.multicall').read_bytes(),payload)
            for name in ('tailscale','tailscaled'):
                self.assertTrue((output/'usr/sbin'/name).is_symlink());self.assertEqual(os.readlink(output/'usr/sbin'/name),'tailscale.multicall')
            self.assertFalse(marker.exists());self.assertEqual((output/'etc/init.d/tailscale').read_text(),'unchanged tailscale.init\n')
            self.assertEqual((output/'etc/config/tailscale').read_text(),'unchanged tailscale.conf\n')

    def test_prepare_override_copies_exact_helper_lock_and_preserves_upstream_for_both_managers(self):
        from test_prepare import prepare
        for manager in ('opkg','apk'):
            with self.subTest(manager=manager),tempfile.TemporaryDirectory() as directory:
                sdk=Path(directory);original=sdk/'feeds/packages/net/tailscale';(original/'files').mkdir(parents=True)
                for name in ('tailscale.init','tailscale.conf'):(original/'files'/name).write_text('preserved '+name)
                (original/'Makefile').write_text('original pinned feed recipe')
                prepare.apply_overrides({'tailscale':self.lock},sdk,{'firmware':{'architecture':'aarch64_cortex-a53'},'package_manager':manager})
                target=sdk/'package/ax6000-overrides/tailscale'
                self.assertEqual((target/'files/tailscale_source.py').read_bytes(),(ROOT/'scripts/tailscale_source.py').read_bytes())
                self.assertEqual(json.loads((target/'files/source-lock.json').read_text()),self.lock)
                self.assertEqual((target/'files/tailscale.init').read_bytes(),(original/'files/tailscale.init').read_bytes())
                self.assertEqual((original/'Makefile').read_text(),'original pinned feed recipe')

    def test_manual_workflow_is_unsigned_bounded_and_uses_same_shared_helper(self):
        from test_apk_workflows import shell_blocks
        text=(ROOT/'.github/workflows/tailscale-compact.yml').read_text()
        for term in ('verify-build','--cpu-quota 400000','--memory 10g --memory-swap 10g','--cap-drop ALL','--network none','scripts/tailscale_probe.py'):
            self.assertIn(term,text)
        for term in ('SIGNING_KEY','deploy-pages','--privileged','binfmt'):
            self.assertNotIn(term,text)
        for name,block in shell_blocks('tailscale-compact.yml').items():
            result=subprocess.run(['bash','-n'],input=block,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,name+result.stderr)

    def test_no_normal_image_includes_tailscale_and_asu_policy_remains_installed_only(self):
        for channel in ('recommended', 'latest'):
            profile = json.loads((ROOT/f'profiles/redmi-ax6000-612-{channel}-new.json').read_text())
            self.assertNotIn('tailscale', profile['image_packages'])
            self.assertIn('tailscale', profile['package_only'])
        self.assertIn('installed_packages', (ROOT/'files/asu-client/ax6000_asu.js').read_text())


if __name__ == '__main__': unittest.main()
