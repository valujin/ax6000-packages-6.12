"""Real SDK augmentation/export round trip, without a compiler or network."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from test_integration import control_ipk
from test_firmware_layouts import fixture, ABI
from test_source_layouts_612 import profile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('export_612',ROOT/'scripts/prepare-firmware.py')
firmware=importlib.util.module_from_spec(spec);spec.loader.exec_module(firmware)
import prepare


@unittest.skipUnless(shutil.which('zstd'),'zstd is needed for actual compressed SDK fixture')
class Export612Tests(unittest.TestCase):
    def fixture(self,root):
        source=root/'source'; generated_native,_,_=fixture(source)
        target=source/'bin/targets/mediatek/filogic'
        (target/'immortalwrt-sdk-mediatek-filogic.tar.zst').unlink()
        p=profile();p['packages']=['kmod-wireguard','kmod-amneziawg'];p['image_packages']=[]
        packages=source/'bin/packages/base';packages.mkdir(parents=True)
        for name,deps in [('kernel',''),('kmod-wireguard','kernel (= '+ABI+')'),('kmod-amneziawg','kernel (= '+ABI+')'),
                          ('vendor-ui','libvendor'),('libvendor','')]:
            control_ipk(packages/(name+'.ipk'),name,ABI if name=='kernel' else '1-r1',depends=deps)
        relative=Path('build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/linux-6.12.108')
        kernel={'Makefile':b'all:', '.config':b'CONFIG_WIREGUARD=m\n','Module.symvers':b'0x123\tfixture\tvmlinux\tEXPORT_SYMBOL\n',
                '.vermagic':('a'*32+'\n').encode(),'.config.set':b'CONFIG_WIREGUARD=m\n',
                'modules.builtin.modinfo':b'fixture.license=GPL\x00',
                'include/generated/autoconf.h':b'#define CONFIG_WIREGUARD_MODULE 1\n',
                'include/config/kernel.release':b'6.12.108\n'}
        for name,data in kernel.items():
            path=source/relative/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as tar:
            for name,payload in {'Makefile':b'all:',**{str(relative/name):body for name,body in kernel.items()
                         if name not in ('.config.set','.vermagic','modules.builtin.modinfo')}}.items():
                member=tarfile.TarInfo('sdk/'+name);member.size=len(payload);tar.addfile(member,io.BytesIO(payload))
        sdk=target/'immortalwrt-sdk-mediatek-filogic.tar.zst'
        sdk.write_bytes(subprocess.check_output(['zstd','-q','-T1','-c'],input=data.getvalue()))
        (source/'tmp').mkdir()
        (source/'tmp/.packageinfo').write_text('Source-Makefile: package/kernel/linux/Makefile\nPackage: kmod-wireguard\n'
                'Source-Makefile: package/feeds/amneziawg/kmod-amneziawg/Makefile\nPackage: kmod-amneziawg\n')
        (source/'.config').write_text('CONFIG_TARGET_mediatek=y\n# CONFIG_USE_APK is not set\n')
        (source/'build-selection.json').write_text(json.dumps({'selected_kmods':p['packages'],'devices':p['firmware']['devices'],
                'channel':p['channel'],'candidate_kmods':p['packages'],'requested':p['packages']}))
        signer=source/'staging_dir/host/bin/usign';signer.parent.mkdir(parents=True)
        signer.write_bytes(b'#!/bin/sh\nexit 1\n');signer.chmod(0o755)
        return p,source,sdk,kernel,relative

    def test_final_sdk_hash_release_url_three_layouts_and_daily_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);p,source,sdk,kernel,relative=self.fixture(root)
            raw=root/'raw';firmware.export(p,{},source,raw)
            generated=json.loads((raw/'profile.json').read_text());lock=json.loads((raw/'lock.json').read_text())
            manifest=json.loads((raw/'firmware-manifest.json').read_text());catalog=json.loads((raw/'downloads.json').read_text())
            prepare.validate(generated,lock)
            sdk_sha=hashlib.sha256(sdk.read_bytes()).hexdigest()
            self.assertEqual(generated['build_id'],p['id']+'-'+p['firmware']['commit'][:12]+'-'+sdk_sha[:12])
            self.assertEqual(generated['sdk']['url'],'https://github.com/valujin/ax6000-packages-6.12/releases/download/firmware-'+generated['build_id']+'/'+sdk.name)
            self.assertEqual(generated['feeds'][0]['root'],'package')
            self.assertEqual(manifest['channel'],'recommended');self.assertEqual(manifest['devices'],p['firmware']['devices'])
            self.assertEqual(lock['profile_sha256'],hashlib.sha256((raw/'profile.json').read_bytes()).hexdigest())
            self.assertEqual({x['layout'] for x in catalog['assets'] if x['kind']=='sysupgrade'},{'stock','mtkuboot','ubootmod'})
            unpacked=root/'sdk.tar'
            unpacked.write_bytes(subprocess.check_output(['zstd','-q','-d','-c',str(sdk)]))
            daily_sdk=prepare.extract_sdk(unpacked,root/'extracted')
            for name,payload in kernel.items(): self.assertEqual((daily_sdk/relative/name).read_bytes(),payload)
            baseline=json.loads((daily_sdk/'ax6000-baseline/manifest.json').read_text())
            self.assertEqual(baseline['frozen_kmods'],['kmod-wireguard'])
            self.assertTrue({'kernel','vendor-ui','libvendor','kmod-wireguard'} <= set(baseline['frozen_packages']))
            self.assertNotIn('kmod-amneziawg',baseline['frozen_packages'])
            bins=daily_sdk/'bin/packages';bins.mkdir(parents=True)
            control_ipk(bins/'fresh-awg.ipk','kmod-amneziawg','2-r1',depends='kernel (= '+ABI+')')
            signer=daily_sdk/'staging_dir/host/bin/usign';signer.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source/'staging_dir/host/bin/usign',signer)
            shutil.copy2(source/'build-selection.json',daily_sdk/'build-selection.json')
            daily=root/'daily';prepare.export_packages(generated,lock,daily_sdk,daily,sdk)
            for initial in (raw/'bin/targets/mediatek/filogic').iterdir():
                if initial.is_file() and ('redmi-router-ax6000-' in initial.name or initial.name==sdk.name):
                    self.assertEqual(initial.read_bytes(),(daily/'bin/targets/mediatek/filogic'/initial.name).read_bytes())
            self.assertEqual((daily/'bin/packages/kmod-wireguard.ipk').read_bytes(),(source/'bin/packages/base/kmod-wireguard.ipk').read_bytes())
            self.assertTrue((daily/'bin/packages/vendor-ui.ipk').is_file())
            self.assertTrue((daily/'bin/packages/fresh-awg.ipk').is_file())

    def test_missing_layout_fails_before_output_or_sdk_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);p,source,sdk,_,_=self.fixture(root)
            next((source/'bin/targets/mediatek/filogic').glob('*mtkuboot-squashfs-sysupgrade.bin')).unlink()
            before=sdk.read_bytes()
            with self.assertRaisesRegex(ValueError,'mtkuboot'):
                firmware.export(p,{},source,root/'raw')
            self.assertFalse((root/'raw').exists());self.assertEqual(sdk.read_bytes(),before)


if __name__=='__main__': unittest.main()
