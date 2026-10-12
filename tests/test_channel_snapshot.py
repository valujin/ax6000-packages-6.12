import base64
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch
import tempfile
import io
import tarfile
import unittest

from test_publish import ipk

ROOT = Path(__file__).resolve().parents[1]
USIGN = os.environ.get('USIGN')
SCRIPT = ROOT / 'scripts/channel-snapshot.py'
if SCRIPT.exists():
    spec = importlib.util.spec_from_file_location('snapshot_under_test', SCRIPT)
    snapshot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(snapshot)
else:
    snapshot = None


@unittest.skipUnless(USIGN, 'Set USIGN to the official host tool')
class ChannelSnapshots(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(snapshot, 'signed snapshot implementation is missing')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key, self.public = self.root/'secret', self.root/'public'
        subprocess.run([USIGN, '-G', '-s', str(self.key), '-p', str(self.public)], check=True, capture_output=True)
        self.repository = 'valujin/ax6000-packages-6.12'
        self.recipe = 'f'*40

    def channel(self, name):
        tree = self.root/name
        tree.mkdir()
        profile_id = 'redmi-ax6000-612-'+name
        sdk_sha = 'c'*64
        commit = 'ae65e1de69971b5a2e3cf7e39390ee93f274d488' if name == 'recommended' else 'a99b0888b88f134f56bcb2a7d93027b5d20638a9'
        build_id = profile_id+'-'+commit[:12]+'-'+sdk_sha[:12]
        profile = {'schema_version':1, 'id':profile_id,'channel':name,'enabled':True,
                   'build_id':build_id,'all_kmods':False,
                   'publication':{'repository':self.repository,'site_url':'https://fixture.github.io/ax6000-packages-6.12','firmware_assets':'github-release'},
                   'firmware':{'repository':'https://github.com/fixture/source.git','commit':commit,
                               'device':'xiaomi_redmi-router-ax6000-stock',
                               'devices':[{'device':'xiaomi_redmi-router-ax6000-'+layout,'layout':layout} for layout in ('stock','mtkuboot','ubootmod')],
                               'target':'mediatek','subtarget':'filogic','architecture':'aarch64_cortex-a53',
                               'kernel_version':('6.12.108' if name=='recommended' else '6.12.112')+'~'+('a'*32)+'-r1'},
                   'sdk':{'url':f'https://github.com/{self.repository}/releases/download/firmware-{build_id}/sdk.tar.zst','sha256':sdk_sha},
                   'feeds':[], 'packages':['kmod-wireguard']}
        (tree/'profile.json').write_text(json.dumps(profile))
        lock = {'schema_version':1,'profile_id':profile_id,'profile_sha256':hashlib.sha256((tree/'profile.json').read_bytes()).hexdigest(),
                'firmware':profile['firmware'],'sdk':profile['sdk'],'feeds':{'base':commit},'recipe_sha256':'d'*64}
        (tree/'state').mkdir();(tree/'state/lock.json').write_text(json.dumps(lock))
        (tree/'repository.pub').write_bytes(self.public.read_bytes())
        catalog={'schema_version':1,'channel':name,'profile_id':profile_id,'build_id':build_id,
                 'firmware':profile['firmware'],'sdk':profile['sdk'],
                 'release':{'repository':self.repository,'id':12,'tag':'firmware-'+build_id,'recipe_commit':self.recipe},
                 'assets':[{'filename':'sdk.tar.zst','kind':'sdk','device':None,'layout':None,'supported_devices':[],
                            'size':123,'sha256':sdk_sha,'asset_id':100,'updated_at':'2026-10-12T00:00:00Z','url':profile['sdk']['url']}]}
        for i, layout in enumerate(('stock','mtkuboot','ubootmod')):
            device='xiaomi_redmi-router-ax6000-'+layout
            filename='immortalwrt-mediatek-filogic-'+device+'-squashfs-sysupgrade.'+('itb' if layout=='ubootmod' else 'bin')
            catalog['assets'].append({'filename':filename,'device':device,'layout':layout,'kind':'sysupgrade','supported_devices':['xiaomi,redmi-router-ax6000-'+layout],
                                     'size':456,'sha256':'e'*64,'asset_id':101+i,'updated_at':'2026-10-12T00:00:00Z',
                                     'url':f'https://github.com/{self.repository}/releases/download/firmware-{build_id}/{filename}'})
        (tree/'downloads.json').write_text(json.dumps(catalog))
        self.sign(tree/'downloads.json',tree/'downloads.sig')
        feed=tree/'feeds'/profile_id/profile['firmware']['kernel_version'];feed.mkdir(parents=True)
        package=feed/'wireguard.ipk';ipk(package,kernel=profile['firmware']['kernel_version'])
        spec=importlib.util.spec_from_file_location('fixture_publish',ROOT/'scripts/publish.py');publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)
        control=publisher.read_control(package)
        control.update(Filename=package.name,Size=str(package.stat().st_size),SHA256sum=hashlib.sha256(package.read_bytes()).hexdigest())
        index=('\n'.join(f'{k}: {v}' for k,v in control.items())+'\n\n').encode()
        (feed/'Packages').write_bytes(index);(feed/'Packages.gz').write_bytes(gzip.compress(index,mtime=0));self.sign(feed/'Packages',feed/'Packages.sig')
        return tree,profile

    def sign(self,path,signature):
        subprocess.run([USIGN,'-S','-m',str(path),'-s',str(self.key),'-x',str(signature)],check=True,capture_output=True)

    def pack_restore(self,name):
        tree,profile=self.channel(name)
        packed=self.root/('packed-'+name)
        plan=snapshot.pack_snapshot(tree,name,self.repository,self.recipe,self.key,self.public,USIGN,packed)
        archive=packed/'channel.tar.zst'
        pointer={'channel':name,'profile_id':profile['id'],'build_id':profile['build_id'],'kernel_version':profile['firmware']['kernel_version'],
                 'release_id':20,'tag':plan['tag'],'asset_id':21,'archive_sha256':snapshot.sha256_file(archive),'archive_size':archive.stat().st_size,'manifest_sha256':plan['manifest_sha256']}
        metadata={'id':20,'tag_name':plan['tag'],'draft':False,'immutable':True,'assets':[{'id':21,'name':'channel.tar.zst','size':archive.stat().st_size,'state':'uploaded','updated_at':'now','digest':'sha256:'+pointer['archive_sha256']},
                        {'id':22,'name':'channel.tar.zst.sha256','size':(packed/'channel.tar.zst.sha256').stat().st_size,'state':'uploaded','updated_at':'now','digest':'sha256:'+snapshot.sha256_file(packed/'channel.tar.zst.sha256')}]}
        restored=self.root/('restored-'+name)
        snapshot.restore_snapshot(archive,pointer,metadata,metadata,profile,self.public,USIGN,restored)
        return tree,profile,packed,pointer,metadata,restored

    def test_real_signed_snapshot_restores_exact_channel_bytes(self):
        tree,_,_,_,_,restored=self.pack_restore('recommended')
        self.assertEqual({p.relative_to(tree).as_posix():p.read_bytes() for p in tree.rglob('*') if p.is_file()},
                         {p.relative_to(restored/'channel').as_posix():p.read_bytes() for p in (restored/'channel').rglob('*') if p.is_file()})

    def test_foreign_key_refuses_before_snapshot_output(self):
        tree,_=self.channel('recommended');other=self.root/'other.pub'
        subprocess.run([USIGN,'-G','-s',str(self.root/'other.key'),'-p',str(other)],check=True,capture_output=True)
        output=self.root/'bad-pack'
        with self.assertRaises(ValueError):snapshot.pack_snapshot(tree,'recommended',self.repository,self.recipe,self.key,other,USIGN,output)
        self.assertFalse(output.exists())

    def test_tampered_index_refuses_before_snapshot_output(self):
        tree,_=self.channel('recommended')
        next(tree.rglob('Packages')).write_text('tampered')
        with self.assertRaises((ValueError,subprocess.CalledProcessError)):
            snapshot.pack_snapshot(tree,'recommended',self.repository,self.recipe,self.key,self.public,USIGN,self.root/'bad-pack')
        self.assertFalse((self.root/'bad-pack').exists())

    def test_wrong_pointer_hash_and_mutable_release_refuse_before_restore(self):
        _,profile,packed,pointer,metadata,_=self.pack_restore('recommended')
        for alteration in ('hash','mutable','asset'):
            p,m=copy.deepcopy(pointer),copy.deepcopy(metadata)
            if alteration=='hash':p['archive_sha256']='0'*64
            elif alteration=='mutable':m['immutable']=False
            else:m['assets'][0]['id']=999
            target=self.root/('bad-'+alteration)
            with self.assertRaises(ValueError):snapshot.restore_snapshot(packed/'channel.tar.zst',p,m,m,profile,self.public,USIGN,target)
            self.assertFalse(target.exists())

    def test_symlink_and_unexpected_tool_rejected(self):
        tree,_=self.channel('recommended')
        (tree/'usign').symlink_to(USIGN)
        with self.assertRaises(ValueError):snapshot.pack_snapshot(tree,'recommended',self.repository,self.recipe,self.key,self.public,USIGN,self.root/'bad-pack')
        (tree/'usign').unlink();(tree/'usign').write_bytes(b'not executable')
        with self.assertRaises(ValueError):snapshot.pack_snapshot(tree,'recommended',self.repository,self.recipe,self.key,self.public,USIGN,self.root/'bad-pack')

    def test_compose_two_channels_preserves_other_channel_and_signed_state(self):
        a=self.pack_restore('recommended');b=self.pack_restore('latest')
        public=self.root/'site'
        state=snapshot.compose_site(None,None,{'recommended':(a[-1],a[3]),'latest':(b[-1],b[3])},self.repository,self.key,self.public,USIGN,public,bootstrap=True)
        subprocess.run([USIGN,'-V','-m',str(public/'site-state.json'),'-p',str(self.public),'-x',str(public/'site-state.sig')],check=True,capture_output=True)
        self.assertEqual(state['channels']['latest'],b[3])
        before={p.relative_to(public/'channels/latest').as_posix():p.read_bytes() for p in (public/'channels/latest').rglob('*') if p.is_file()}
        (a[0]/'index.html').write_text('<h1>Refreshed recommended feed</h1>')
        newpack=self.root/'refreshed-pack'
        newplan=snapshot.pack_snapshot(a[0],'recommended',self.repository,self.recipe,self.key,self.public,USIGN,newpack)
        newpointer=dict(a[3],tag=newplan['tag'],manifest_sha256=newplan['manifest_sha256'],archive_sha256=snapshot.sha256_file(newpack/'channel.tar.zst'),archive_size=(newpack/'channel.tar.zst').stat().st_size)
        metadata=copy.deepcopy(a[4]);metadata['tag_name']=newpointer['tag']
        for asset in metadata['assets']:
            asset['size']=(newpack/asset['name']).stat().st_size;asset['digest']='sha256:'+snapshot.sha256_file(newpack/asset['name'])
        newrestored=self.root/'refreshed-restored'
        snapshot.restore_snapshot(newpack/'channel.tar.zst',newpointer,metadata,metadata,a[1],self.public,USIGN,newrestored)
        public2=self.root/'site2'
        snapshot.compose_site(public/'site-state.json',public/'site-state.sig',{'recommended':(newrestored,newpointer),'latest':(b[-1],b[3])},self.repository,self.key,self.public,USIGN,public2)
        self.assertEqual(before,{p.relative_to(public2/'channels/latest').as_posix():p.read_bytes() for p in (public2/'channels/latest').rglob('*') if p.is_file()})

    def test_snapshot_recipe_plan_mismatch_refuses_remote_mutation(self):
        _,_,packed,_,_,_=self.pack_restore('recommended')
        plan=snapshot.read_json(packed/'snapshot-plan.json')
        plan['recipe_commit']='0'*40
        (packed/'snapshot-plan.json').write_bytes(snapshot.canonical_json(plan))
        real_loader=snapshot.module
        api_module=real_loader('publication_api')
        with patch.object(snapshot,'module',wraps=real_loader) as loader:
            with patch.object(api_module.ReleaseAPI,'publish_release') as publish:
                loader.side_effect=lambda name: api_module if name=='publication_api' else real_loader(name)
                with self.assertRaises(ValueError):
                    snapshot.publish_snapshot(packed/'snapshot-plan.json',self.repository,self.public,USIGN,self.root/'bad-publish')
                publish.assert_not_called()
        self.assertFalse((self.root/'bad-publish').exists())

    def test_packing_same_signed_inputs_is_deterministic(self):
        tree,_=self.channel('recommended')
        first=snapshot.pack_snapshot(tree,'recommended',self.repository,self.recipe,self.key,self.public,USIGN,self.root/'pack1')
        for path in tree.rglob('*'):
            if path.is_file():os.utime(path,(1234,5678))
        second=snapshot.pack_snapshot(tree,'recommended',self.repository,self.recipe,self.key,self.public,USIGN,self.root/'pack2')
        self.assertEqual(first['manifest_sha256'],second['manifest_sha256'])
        self.assertEqual(first['assets'][0]['sha256'],second['assets'][0]['sha256'])

    def test_unsigned_live_state_and_generation_change_refused(self):
        a=self.pack_restore('recommended');public=self.root/'site'
        snapshot.compose_site(None,None,{'recommended':(a[-1],a[3])},self.repository,self.key,self.public,USIGN,public,bootstrap=True)
        (public/'site-state.json').write_text('{}')
        with self.assertRaises(subprocess.CalledProcessError):
            snapshot.compose_site(public/'site-state.json',public/'site-state.sig',{'recommended':(a[-1],a[3])},self.repository,self.key,self.public,USIGN,self.root/'bad-site')
        self.assertFalse((self.root/'bad-site').exists())
        state={'schema_version':1,'repository':self.repository,'channels':{'recommended':dict(a[3],build_id='old-generation'),'latest':None}}
        (public/'site-state.json').write_bytes(snapshot.canonical_json(state));self.sign(public/'site-state.json',public/'site-state.sig')
        with self.assertRaisesRegex(ValueError,'switch firmware generation'):
            snapshot.compose_site(public/'site-state.json',public/'site-state.sig',{'recommended':(a[-1],a[3])},self.repository,self.key,self.public,USIGN,self.root/'bad-site')

    def test_generation_download_counts_do_not_change_immutable_identity(self):
        tree,_=self.channel('recommended');catalog=snapshot.read_json(tree/'downloads.json')
        payloads={'raw.tar.zst':b'raw fixture','raw.tar.zst.sha256':b'checksum fixture',
                  'downloads.json':(tree/'downloads.json').read_bytes(),'downloads.sig':(tree/'downloads.sig').read_bytes()}
        release={'id':12,'tag_name':catalog['release']['tag'],'draft':False,'immutable':True,'assets':[
            {'id':100+i,'name':name,'size':len(body),'state':'uploaded','digest':'sha256:'+hashlib.sha256(body).hexdigest(),'updated_at':'now','download_count':0}
            for i,(name,body) in enumerate(payloads.items())]}
        after=copy.deepcopy(release)
        for asset in after['assets']:asset['download_count']=1
        api_module=snapshot.module('publication_api');real_loader=snapshot.module
        def download(_client,_release,asset,destination,_digest,_size):Path(destination).write_bytes(payloads[asset['name']])
        with patch.object(snapshot,'module',side_effect=lambda name:api_module if name=='publication_api' else real_loader(name)), \
             patch.object(api_module.ReleaseAPI,'get_release',side_effect=[release,after]), \
             patch.object(api_module.ReleaseAPI,'resolve_tag_commit',return_value=self.recipe), \
             patch.object(api_module.ReleaseAPI,'download_asset',new=download):
            snapshot.fetch_generation(release['tag_name'],self.repository,self.public,USIGN,self.root/'fetched')
        self.assertEqual((self.root/'fetched/downloads.json').read_bytes(),payloads['downloads.json'])

    def test_archive_extra_traversal_and_symlink_refuse_without_output(self):
        _,profile,packed,pointer,metadata,_=self.pack_restore('recommended')
        original=subprocess.check_output(['zstd','-q','-d','-c',str(packed/'channel.tar.zst')])
        for kind in ('extra','traversal','symlink'):
            data=io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(original)) as source,tarfile.open(fileobj=data,mode='w') as target:
                for item in source:target.addfile(item,source.extractfile(item))
                item=tarfile.TarInfo('channel/unexpected' if kind=='extra' else '../outside')
                if kind=='symlink':item.name='channel/repository-link';item.type=tarfile.SYMTYPE;item.linkname='/etc/passwd';target.addfile(item)
                else:item.size=1;target.addfile(item,io.BytesIO(b'x'))
            archive=self.root/(kind+'.tar.zst')
            result=subprocess.run(['zstd','-q','-T1','-3','-c'],input=data.getvalue(),stdout=subprocess.PIPE,check=True)
            archive.write_bytes(result.stdout)
            p=dict(pointer,archive_size=archive.stat().st_size,archive_sha256=snapshot.sha256_file(archive))
            meta=copy.deepcopy(metadata);meta['assets'][0].update(size=p['archive_size'],digest='sha256:'+p['archive_sha256'])
            output=self.root/('bad-'+kind)
            with self.assertRaises(ValueError):snapshot.restore_snapshot(archive,p,meta,meta,profile,self.public,USIGN,output)
            self.assertFalse(output.exists());self.assertFalse((self.root/'outside').exists())

    def test_broken_sdk_signer_fails_before_generation_remote_writes(self):
        wrapper=self.root/'sdk-usign'
        wrapper.write_text('#!/bin/sh\nexec /nonexistent-sdk-lib/ld-linux-x86-64.so.2 "$@"\n');wrapper.chmod(0o755)
        real_loader=snapshot.module;api_module=real_loader('publication_api')
        with patch.object(snapshot,'module',side_effect=lambda name:api_module if name=='publication_api' else real_loader(name)), \
             patch.object(api_module.ReleaseAPI,'publish_release') as remote:
            with self.assertRaises(subprocess.CalledProcessError):
                snapshot.publish_generation(self.root/'absent-raw',self.root/'absent-profile',self.root/'absent-archive',self.root/'absent-checksum',
                    self.repository,self.key,self.public,wrapper,self.root/'generation')
            remote.assert_not_called()
        self.assertFalse((self.root/'generation').exists())

    def test_no_silent_channel_disappearance(self):
        a=self.pack_restore('recommended');b=self.pack_restore('latest');public=self.root/'site'
        snapshot.compose_site(None,None,{'recommended':(a[-1],a[3]),'latest':(b[-1],b[3])},self.repository,self.key,self.public,USIGN,public,bootstrap=True)
        with self.assertRaises(ValueError):snapshot.compose_site(public/'site-state.json',public/'site-state.sig',{'recommended':(a[-1],a[3])},self.repository,self.key,self.public,USIGN,self.root/'bad-site')
        self.assertFalse((self.root/'bad-site').exists())


if __name__=='__main__':unittest.main()
