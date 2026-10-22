"""Activation orchestration; immutable transport/crypto stay in channel-snapshot APIs."""
import base64
import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('activate_snapshot',ROOT/'scripts/activate-snapshot.py')
activation=importlib.util.module_from_spec(spec);spec.loader.exec_module(activation)
snapshot=activation.snapshot_module()


def encode(value):return base64.b64encode(json.dumps(value).encode()).decode()


class SnapshotActivation(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.profiles=self.root/'profiles';self.profiles.mkdir()
        self.profile=(ROOT/'tests/fixtures/rec-r5-apk-profile.json').read_bytes()
        self.assertEqual(__import__('hashlib').sha256(self.profile).hexdigest(),activation.PROFILE_SHA256)
        active=json.loads(self.profile)
        (self.profiles/'redmi-ax6000-612-recommended.json').write_bytes(self.profile)
        (self.profiles/'redmi-ax6000-612-latest.json').write_text(json.dumps({'channel':'latest'}))
        self.old={'channel':'recommended','profile_id':active['id'],'build_id':active['build_id'],
                  'kernel_version':active['firmware']['kernel_version'],'manifest_sha256':'a'*64,'tag':'packages-recommended-'+'a'*64,
                  'archive_sha256':'b'*64,'archive_size':1234,'release_id':123,'asset_id':456}
        self.incoming=dict(self.old,manifest_sha256='c'*64,tag='packages-recommended-'+'c'*64,release_id=789,asset_id=987)
        self.latest=dict(self.old,channel='latest',profile_id='redmi-ax6000-612-latest',build_id='old-latest',manifest_sha256='d'*64,tag='packages-latest-'+'d'*64)
        self.previous={'schema_version':1,'repository':activation.REPOSITORY,'channels':{'recommended':self.old,'latest':self.latest}}
        self.restores=[];self.identities=[];self.compositions=[];self.fetches=0
        self.changed_profile=False;self.missing_proof=False;self.changed_live=False
        def fetch(site,repo,key,usign,out):
            self.fetches+=1;out.mkdir();state=copy.deepcopy(self.previous)
            if self.changed_live and self.fetches==2:state['channels']['latest']['asset_id']+=1
            (out/'site-state.json').write_bytes(snapshot.canonical_json(state));(out/'site-state.sig').write_text('authenticated boundary')
            return state
        def restore(pointer,expected,repo,key,usign,out,**kwargs):
            self.restores.append(copy.deepcopy(pointer));(out/'channel').mkdir(parents=True)
            data=self.profile if pointer['channel']=='recommended' else b'{}'
            if self.changed_profile and pointer['manifest_sha256']==self.incoming['manifest_sha256']:data+=b' '
            (out/'channel/profile.json').write_bytes(data)
            if not(self.missing_proof and pointer['manifest_sha256']==self.incoming['manifest_sha256']):
                (out/'snapshot-manifest.sig').write_text('transport proof fixture')
        def identity(tree,*args,**kwargs):
            self.identities.append(tree)
            if not (tree/'snapshot-manifest.sig').is_file():raise ValueError('Missing signed snapshot proof')
        def compose(live,sig,channels,repo,key,pub,usign,out,**kwargs):
            self.assertEqual(key,self.root/'private','Activation changed the original signing-key argument')
            self.compositions.append(channels);self.assertEqual(set(kwargs),{'apk'})
            state=copy.deepcopy(self.previous);state['channels']={name:pointer for name,(_,pointer) in channels.items()}
            out.mkdir();(out/'site-state.json').write_bytes(snapshot.canonical_json(state));(out/'site-state.sig').write_text('new signed state')
            return state
        self.backend=types.SimpleNamespace(sha256_file=snapshot.sha256_file,read_json=snapshot.read_json,fresh=snapshot.fresh,
            fetch_live=fetch,restore_online=restore,restored_identity=identity,compose_site=compose,deployment_record=snapshot.deployment_record)

    def run_activation(self,pointer=None,predecessor=None,channel='recommended'):
        with patch.object(activation,'snapshot_module',return_value=self.backend):
            return activation.activate(encode(pointer or self.incoming),channel,predecessor or 'a'*64,'https://fixture.invalid',activation.REPOSITORY,
                self.profiles,self.root/'work',self.root/'private',self.root/'public-key',self.root/'usign',self.root/'apk',self.root/'public')

    def test_preserves_other_pointer_and_emits_normal_deployment_record(self):
        state=self.run_activation();self.assertEqual(state['channels']['latest'],self.latest)
        self.assertEqual(state['channels']['recommended'],self.incoming)
        self.assertEqual(len(self.restores),3);self.assertEqual(len(self.identities),3)
        check=snapshot.read_json(self.root/'work/deployment-check.json')
        self.assertEqual(set(check),{'schema_version','site_url','before','after'})
        self.assertEqual(check['before']['site-state.json'],snapshot.sha256_file(self.root/'work/live/site-state.json'))
        self.assertEqual(check['after']['site-state.json'],snapshot.sha256_file(self.root/'public/site-state.json'))

    @unittest.skipUnless(os.environ.get('USIGN'), 'Set USIGN to the official host tool')
    def test_original_signer_reaches_normal_compose_and_real_usign(self):
        tool=os.environ['USIGN'];key=self.root/'private';public=self.root/'public-key'
        subprocess.run([tool,'-G','-s',str(key),'-p',str(public)],check=True,capture_output=True)
        def compose(live,sig,channels,repo,signer,pub,usign,out,**kwargs):
            self.assertEqual(signer,key,'Original signing-key path must cross the composition boundary unchanged')
            def identity(tree,*args,**kw):
                return snapshot.read_json(tree/'channel/profile.json'),[{'path':'profile.json','size':(tree/'channel/profile.json').stat().st_size}]
            with patch.object(snapshot,'read_state',return_value=copy.deepcopy(self.previous)),patch.object(snapshot,'restored_identity',side_effect=identity):
                return snapshot.compose_site(live,sig,channels,repo,signer,pub,tool,out,**kwargs)
        self.backend.compose_site=compose
        state=self.run_activation()
        self.assertEqual(state['channels']['latest'],self.latest)
        snapshot.verify(self.root/'public/site-state.json',self.root/'public/site-state.sig',public,tool)
        self.assertEqual(snapshot.read_json(self.root/'public/site-state.json'),state)

    def test_wrong_predecessor_fails_before_restore_or_compose(self):
        with self.assertRaisesRegex(ValueError,'predecessor'):self.run_activation(predecessor='0'*64)
        self.assertEqual(self.restores,[]);self.assertEqual(self.compositions,[])

    def test_wrong_channel_or_generation_refused(self):
        for key,value in [('channel','latest'),('build_id','different'),('kernel_version','different')]:
            bad=dict(self.incoming);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.run_activation(pointer=bad)
        with self.assertRaises(ValueError):self.run_activation(channel='latest')
        self.assertEqual(self.restores,[])

    def test_missing_signed_proof_aborts_before_composition(self):
        self.missing_proof=True
        with self.assertRaisesRegex(ValueError,'signed snapshot proof'):self.run_activation()
        self.assertEqual(self.compositions,[])

    def test_changed_incoming_profile_bytes_refused(self):
        self.changed_profile=True
        with self.assertRaisesRegex(ValueError,'profile bytes'):self.run_activation()
        self.assertEqual(self.compositions,[])

    def test_changed_active_profile_refused_before_network(self):
        (self.profiles/'redmi-ax6000-612-recommended.json').write_bytes(self.profile+b' ')
        with self.assertRaisesRegex(ValueError,'active recommended profile|Active recommended profile'):self.run_activation()
        self.assertEqual(self.fetches,0)

    def test_changed_live_state_aborts_without_deployment_record(self):
        self.changed_live=True
        with self.assertRaisesRegex(ValueError,'live state changed'):self.run_activation()
        self.assertFalse((self.root/'work/deployment-check.json').exists())

    def test_strict_bounded_pointer_parser(self):
        text=json.dumps(self.incoming)
        cases=['',encode({}),encode([]),'!bad',base64.b64encode((text[:-1]+',"channel":"recommended"}').encode()).decode(),
               base64.b64encode(b'{"x":NaN}').decode(),base64.b64encode(b'x'*4097).decode(),encode(dict(self.incoming,release_id=True)),
               encode(dict(self.incoming,archive_size=2*1024**3)),encode(dict(self.incoming,extra='unknown')),
               encode(dict(self.incoming,tag='wrong')),encode(dict(self.incoming,archive_sha256='bad'))]
        for value in cases:
            with self.subTest(value=value[:30]),self.assertRaises(ValueError):activation.decode_pointer(value,'recommended')
        self.assertEqual(activation.decode_pointer(encode(self.incoming),'recommended'),self.incoming)

    def test_retired_snapshot_ASU_workflow_is_absent(self):
        self.assertFalse((ROOT/'.github/workflows/activate-snapshot.yml').exists())

    def test_normal_recommended_publisher_keeps_shared_lock_and_deploy_checks(self):
        text=(ROOT/'.github/workflows/publish-existing.yml').read_text()
        self.assertIn('group: package-publication\n  cancel-in-progress: false',text)
        for term in ('verify-deployment --check deployment-check/deployment-check.json --phase before',
                     'verify-deployment --check deployment-check/deployment-check.json --phase after','actions/deploy-pages@v4'):
            self.assertIn(term,text)
        for term in ('activate-snapshot.py','--allow-asu-apk-migration'):
            self.assertNotIn(term,text)

if __name__=='__main__':unittest.main()
