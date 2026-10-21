"""Real APKv3 packages, EC signatures and usign snapshot round trips."""
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_channel_snapshot as fixtures

ROOT = Path(__file__).resolve().parents[1]
APK = os.environ.get('APK')
USIGN = os.environ.get('USIGN')
spec = importlib.util.spec_from_file_location('publish_apk_test', ROOT/'scripts/publish.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
snapshot = fixtures.snapshot


@unittest.skipUnless(APK and USIGN, 'Set APK and USIGN to trusted host tools')
class APKPublication(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ChannelSnapshots()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.private, self.public = self.root/'apk-private.pem', self.root/'repository-apk.pem'
        subprocess.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:prime256v1',
                        '-out',str(self.private)],check=True,capture_output=True)
        subprocess.run(['openssl','pkey','-in',str(self.private),'-pubout','-out',str(self.public)],
                       check=True,capture_output=True)
        self.tree, self.profile = self.fixture.channel('recommended')
        self.profile.update(package_manager='apk',apk_key_sha256=publisher.sha256_file(self.public))
        self.raw = self.root/'raw';self.raw.mkdir()
        self.rewrite_profile()

    def rewrite_profile(self):
        (self.tree/'profile.json').write_text(json.dumps(self.profile))
        lock=json.loads((self.tree/'state/lock.json').read_text())
        lock.update(profile_sha256=publisher.sha256_file(self.tree/'profile.json'),package_manager='apk',
                    apk_key_sha256=self.profile['apk_key_sha256'])
        (self.tree/'state/lock.json').write_text(json.dumps(lock))
        catalog=json.loads((self.tree/'downloads.json').read_text())
        catalog.update(package_manager='apk',apk_key_sha256=self.profile['apk_key_sha256'])
        (self.tree/'downloads.json').write_text(json.dumps(catalog))
        self.fixture.sign(self.tree/'downloads.json',self.tree/'downloads.sig')
        shutil.copyfile(self.public,self.tree/'repository-apk.pem')
        self.fixture.sign(self.tree/'profile.json',self.tree/'profile.sig')

    def package(self,name='kmod-wireguard',version='1-r1',depends=None,tags=None,payload=b'fixture',provides=None):
        files=self.root/('files-'+str(len(list(self.root.glob('files-*')))))
        (files/'usr/share/test').mkdir(parents=True)
        (files/'usr/share/test'/name).write_bytes(payload)
        target=self.raw/(name+'-'+version+'.apk')
        command=[APK,'--no-network','mkpkg','--files',str(files),'--output',str(target),
                 '--info','name:'+name,'--info','version:'+version,
                 '--info','arch:'+self.profile['firmware']['architecture']]
        if depends is None and name.startswith('kmod-'):
            depends='kernel='+self.profile['firmware']['kernel_version']+' libc'
        for key,value in [('depends',depends),('tags',tags),('provides',provides)]:
            if value:command+=['--info',key+':'+value]
        subprocess.run(command,check=True,capture_output=True)
        return target

    def stage(self):
        return publisher.stage_feed(self.raw,self.root/'staged',self.profile,apk=APK,
                                    apk_key=self.private,apk_public_key=self.public)

    def channel(self):
        self.package()
        self.package('libfixture20261021',tags='openwrt:abiversion=20261021')
        staged=self.stage()
        shutil.rmtree(self.tree/'feeds')
        target=self.tree/'feeds'/self.profile['id']/self.profile['firmware']['kernel_version']
        shutil.copytree(staged,target)
        shutil.copyfile(staged.parents[2]/'native-providers.json',self.tree/'native-providers.json')
        self.fixture.sign(target/'Packages',target/'Packages.sig')
        return target

    def test_native_signed_index_and_abi_names_are_exact(self):
        feed=self.channel()
        controls=publisher.package_format().index_info(feed/'packages.adb',APK)
        library=next(x for x in controls if x['Package']=='libfixture20261021')
        self.assertEqual(library['Base-Package'],'libfixture')
        self.assertEqual(library['ABIVersion'],'20261021')
        self.assertNotIn('APK-Raw:',(feed/'Packages').read_text())
        self.assertEqual(gzip.decompress((feed/'Packages.gz').read_bytes()),(feed/'Packages').read_bytes())
        snapshot.validate_channel(self.tree,'recommended',self.fixture.repository,self.fixture.public,USIGN,apk=APK)

    def test_signed_snapshot_round_trip_preserves_apk_and_key_bytes(self):
        self.channel()
        plan=snapshot.pack_snapshot(self.tree,'recommended',self.fixture.repository,self.fixture.recipe,
                                   self.fixture.key,self.fixture.public,USIGN,self.root/'packed',apk=APK)
        archive=self.root/'packed/channel.tar.zst'
        pointer=dict(channel='recommended',profile_id=self.profile['id'],build_id=self.profile['build_id'],
                     kernel_version=self.profile['firmware']['kernel_version'],release_id=20,asset_id=21,
                     tag=plan['tag'],manifest_sha256=plan['manifest_sha256'],
                     archive_size=archive.stat().st_size,archive_sha256=publisher.sha256_file(archive))
        metadata=dict(id=20,tag_name=plan['tag'],draft=False,immutable=True,assets=[
            dict(id=21+i,name=name,size=(archive.parent/name).stat().st_size,state='uploaded',updated_at='now',
                 digest='sha256:'+publisher.sha256_file(archive.parent/name))
            for i,name in enumerate(('channel.tar.zst','channel.tar.zst.sha256'))])
        restored=self.root/'restored'
        snapshot.restore_snapshot(archive,pointer,metadata,metadata,self.profile,self.fixture.public,USIGN,restored,apk=APK)
        self.assertEqual({p.relative_to(self.tree).as_posix():p.read_bytes() for p in self.tree.rglob('*') if p.is_file()},
                         {p.relative_to(restored/'channel').as_posix():p.read_bytes() for p in (restored/'channel').rglob('*') if p.is_file()})

    def test_signed_but_wrong_native_index_inventory_is_rejected(self):
        feed=self.channel()
        other=self.package('unindexed')
        subprocess.run([APK,'--no-network','mkndx','--allow-untrusted','--sign',str(self.private),
                        '--output',str(feed/'packages.adb'),str(other)],check=True,capture_output=True)
        with self.assertRaisesRegex(ValueError,'index inventory'):
            snapshot.validate_feed(self.tree,self.profile,self.fixture.public,USIGN,apk=APK)

    def test_missing_or_wrong_trust_and_tampered_index_fail(self):
        feed=self.channel()
        for kind in ('missing tool','wrong PEM','signature'):
            with self.subTest(kind=kind):
                if kind=='missing tool':
                    with self.assertRaisesRegex(ValueError,'trusted host apk'):
                        snapshot.validate_feed(self.tree,self.profile,self.fixture.public,USIGN)
                elif kind=='wrong PEM':
                    with self.assertRaisesRegex(ValueError,'public key'):
                        publisher.verify_apk_index(feed,self.profile,APK,self.fixture.public)
                else:
                    subprocess.run([APK,'--no-network','mkndx','--allow-untrusted','--output',
                                    str(feed/'packages.adb'),*[str(p) for p in sorted(feed.glob('*.apk'))]],
                                   check=True,capture_output=True)
                    with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                        snapshot.validate_feed(self.tree,self.profile,self.fixture.public,USIGN,apk=APK)

    def test_profile_signature_is_required_and_opkg_allowlist_stays_strict(self):
        self.channel()
        (self.tree/'profile.sig').unlink()
        with self.assertRaises(subprocess.CalledProcessError):
            snapshot.validate_channel(self.tree,'recommended',self.fixture.repository,self.fixture.public,USIGN,apk=APK)
        legacy=copy.deepcopy(self.profile);legacy.pop('package_manager');legacy.pop('apk_key_sha256')
        with self.assertRaisesRegex(ValueError,'Unexpected (snapshot|feed) file'):
            snapshot.channel_files(self.tree,legacy)

    def test_foreign_ipk_and_wrong_kernel_rejected_before_output(self):
        (self.raw/'foreign.ipk').write_bytes(b'no conversion')
        with self.assertRaisesRegex(ValueError,'foreign IPK'):self.stage()
        (self.raw/'foreign.ipk').unlink()
        self.package(depends='kernel=6.12.1~'+'b'*32+'-r1 libc')
        with self.assertRaisesRegex(ValueError,'ABI mismatch'):self.stage()
        self.assertFalse((self.root/'staged').exists())

    def test_essential_packages_and_provider_aliases_are_excluded(self):
        self.package()
        self.package('libc')
        self.package('apk-openssl')
        self.package('foreign-manager',provides='apk=3.0.5')
        feed=self.stage()
        self.assertEqual({p.name for p in feed.glob('*.apk')},{'kmod-wireguard-1-r1.apk'})

    def test_native_essential_actual_abi_aliases_satisfy_dependencies(self):
        self.package('libgcc1',tags='openwrt:abiversion=1',provides='libgcc libgcc-any')
        self.package('libstdcpp6',tags='openwrt:abiversion=6',provides='libstdcpp libstdcpp-any')
        self.package('consumer',depends='libgcc1 libstdcpp6')
        feed=self.channel()
        self.assertNotIn('libgcc1-1-r1.apk',{p.name for p in feed.glob('*.apk')})
        providers=snapshot.native_provider_identity(self.tree,self.profile)
        self.assertTrue({'libgcc1','libgcc','libstdcpp6','libstdcpp'}<=providers)
        snapshot.validate_feed(self.tree,self.profile,self.fixture.public,USIGN,apk=APK)
        metadata=json.loads((self.tree/'native-providers.json').read_text())
        metadata['packages'][0]['Provides']='unrelated-package'
        (self.tree/'native-providers.json').write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError,'unrelated name'):
            snapshot.native_provider_identity(self.tree,self.profile)

    def test_native_keyring_compatibility_alias_satisfies_dependencies_without_public_replacement(self):
        version='2025.12.11~14e1f88b-r1'
        self.package('openwrt-keyring',version=version,
                     provides='lede-keyring='+version+' openwrt-keyring-any')
        self.package('consumer',depends='lede-keyring='+version)
        feed=self.channel()
        self.assertNotIn('openwrt-keyring-'+version+'.apk',{path.name for path in feed.glob('*.apk')})
        providers=snapshot.native_provider_identity(self.tree,self.profile)
        self.assertTrue({'openwrt-keyring','lede-keyring','openwrt-keyring-any'}<=providers)
        snapshot.validate_feed(self.tree,self.profile,self.fixture.public,USIGN,apk=APK)

    def test_new_publisher_cli_signs_profile_and_copies_pinned_pem(self):
        self.package()
        (self.raw/'profile.json').write_bytes((self.tree/'profile.json').read_bytes())
        (self.raw/'lock.json').write_bytes((self.tree/'state/lock.json').read_bytes())
        catalog=json.loads((self.tree/'downloads.json').read_text())
        metadata=dict(id=catalog['release']['id'],tag_name=catalog['release']['tag'],draft=False,immutable=True,
                      assets=[dict(id=asset['asset_id'],name=asset['filename'],state='uploaded',size=asset['size'],
                                   digest='sha256:'+asset['sha256'],updated_at=asset['updated_at']) for asset in catalog['assets']])
        (self.root/'release.json').write_text(json.dumps(metadata))
        output=self.root/'cli-output'
        subprocess.run(['python3',str(ROOT/'scripts/publish.py'),'--profile',str(self.raw/'profile.json'),
                        '--lock',str(self.raw/'lock.json'),'--input',str(self.raw),'--output',str(output),
                        '--key',str(self.fixture.key),'--public-key',str(self.fixture.public),'--usign',USIGN,
                        '--apk',APK,'--apk-key',str(self.private),'--apk-public-key',str(self.public),
                        '--external-assets',str(self.tree/'downloads.json'),
                        '--external-assets-signature',str(self.tree/'downloads.sig'),
                        '--generation-release-metadata',str(self.root/'release.json')],check=True,capture_output=True)
        snapshot.verify(output/'profile.json',output/'profile.sig',self.fixture.public,USIGN)
        self.assertEqual((output/'repository-apk.pem').read_bytes(),self.public.read_bytes())
        snapshot.validate_channel(output,'recommended',self.fixture.repository,self.fixture.public,USIGN,apk=APK)

    def test_imported_raw_apk_executable_cannot_be_used_as_trusted_decoder(self):
        executable=self.raw/'apk';executable.write_text('#!/bin/sh\nexit 99\n');executable.chmod(0o755)
        self.package()
        with self.assertRaisesRegex(ValueError,'RAW executable'):
            publisher.stage_feed(self.raw,self.root/'staged',self.profile,apk=executable,
                                 apk_key=self.private,apk_public_key=self.public)
        self.assertFalse((self.root/'staged').exists())

    def test_disabled_or_unchanged_apk_refresh_needs_no_private_apk_signer(self):
        self.channel()
        restored=self.root/'retained';shutil.copytree(self.tree,restored/'channel')
        profiles=self.root/'profiles';profiles.mkdir()
        profile_path=profiles/(self.profile['id']+'.json')
        original_run=subprocess.run
        for state in ('disabled','unchanged'):
            with self.subTest(state=state):
                profile=copy.deepcopy(self.profile)
                if state=='disabled':profile['enabled']=False
                profile_path.write_text(json.dumps(profile))
                def monitor(command,**kwargs):
                    if command[0]=='python3' and command[1].endswith('/scripts/monitor.py'):
                        output=Path(command[command.index('--output')+1])
                        output.write_bytes((self.tree/'state/lock.json').read_bytes())
                        return subprocess.CompletedProcess(command,0)
                    return original_run(command,**kwargs)
                with patch.object(snapshot,'fetch_live',return_value={'channels':{}}), \
                     patch.object(snapshot,'restore_live_channels',return_value={'recommended':(restored,{})}), \
                     patch.object(snapshot.subprocess,'run',side_effect=monitor), \
                     patch.object(snapshot,'apk_publication_args',side_effect=AssertionError('private signer must not be needed')):
                    result=snapshot.refresh('https://fixture.invalid',self.fixture.repository,profiles,
                        self.root/('refresh-'+state),self.fixture.key,self.fixture.public,USIGN,
                        self.root/('site-'+state),apk=APK)
                    self.assertIsNone(result)


if __name__=='__main__':unittest.main()
