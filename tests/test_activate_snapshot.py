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

    def test_public_pointer_survives_actual_workflow_argv_and_scoped_env_scrubbing(self):
        from test_apk_workflows import shell_blocks
        scope_spec=importlib.util.spec_from_file_location('activation_scope',ROOT/'scripts/hosted-publication.py')
        scope=importlib.util.module_from_spec(scope_spec);scope_spec.loader.exec_module(scope)
        self.assertNotIn('SNAPSHOT_POINTER_BASE64',scope.PRESERVE)
        commands=self.root/'commands';commands.mkdir();record=self.root/'argv.json'
        stub=commands/'python3'
        stub.write_text('#!'+sys.executable+'\nimport json,sys\nfrom pathlib import Path\nPath('+repr(str(record))+').write_text(json.dumps(sys.argv[1:]))\n')
        stub.chmod(0o755)
        encoded=encode(self.incoming)
        environment=dict(os.environ,PATH=str(commands)+':'+os.environ['PATH'],RUNNER_TEMP=str(self.root),
            OPKG_SIGNING_KEY='fixture-only',SNAPSHOT_POINTER_BASE64=encoded,CHANNEL='recommended',
            EXPECTED_PREDECESSOR='a'*64,GITHUB_REPOSITORY=activation.REPOSITORY,GITHUB_REPOSITORY_OWNER='valujin')
        block=shell_blocks('activate-snapshot.yml')['Authenticate the published snapshot and compose both channels']
        result=subprocess.run(['bash','-eu','-c',block],env=environment,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        outer=json.loads(record.read_text());payload=outer[outer.index('--')+1:]
        self.assertEqual(payload[:2],['python3','scripts/activate-snapshot.py'])
        bounded=scope.scope_command(2*1024**3,1,1000,payload)
        self.assertEqual(bounded[-len(payload):],payload)
        sanitized={key:value for key,value in environment.items() if key in scope.PRESERVE}
        self.assertNotIn('SNAPSHOT_POINTER_BASE64',sanitized)
        with patch.dict(os.environ,sanitized,clear=True),patch.object(sys,'argv',payload[1:]),patch.object(activation,'activate') as called:
            activation.main()
        self.assertEqual(called.call_args.args[0],encoded)
        self.assertEqual(activation.decode_pointer(called.call_args.args[0],'recommended'),self.incoming)
        self.assertFalse((self.root/'opkg-signing.key').exists())

    def test_workflow_uses_shared_publication_lock_and_existing_deploy_gates(self):
        text=(ROOT/'.github/workflows/activate-snapshot.yml').read_text()
        self.assertIn('group: package-publication\n  cancel-in-progress: false',text)
        for term in ('scripts/hosted-publication.py','scripts/build-apk-host.sh','OPKG_SIGNING_KEY','SNAPSHOT_POINTER_BASE64',
                     'verify-deployment --check deployment-check/deployment-check.json --phase before',
                     'verify-deployment --check deployment-check/deployment-check.json --phase after','actions/deploy-pages@v4'):
            self.assertIn(term,text)
        for term in ('APK_SIGNING_KEY','publish-channel','import-release','build-sdk','--bootstrap','--allow-asu-apk-migration'):
            self.assertNotIn(term,text)
        original=(ROOT/'.github/workflows/publish-existing.yml').read_text()
        self.assertEqual(text[text.index('  deploy:\n'):],original[original.index('  deploy:\n'):])

if __name__=='__main__':unittest.main()
