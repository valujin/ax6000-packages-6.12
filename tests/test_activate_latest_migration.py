"""Finite LATEST authorization and unchanged real normal guards; no actual activation."""
import base64,copy,hashlib,importlib.util,io,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_latest_same_image_migration as migration_fixtures
ROOT=Path(__file__).resolve().parents[1]
def encode(value):return base64.b64encode(json.dumps(value).encode()).decode()
class LatestActivation(unittest.TestCase):
 def setUp(self):
  path=ROOT/'scripts/activate-latest-migration.py';self.assertTrue(path.is_file(),'Finite separate LATEST entry point missing')
  s=importlib.util.spec_from_file_location('finite_latest_activation_test',path);self.a=importlib.util.module_from_spec(s);s.loader.exec_module(self.a)
 def pointer(self):
  return {'channel':'latest','profile_id':'redmi-ax6000-612-latest','build_id':self.a.BUILD,'kernel_version':self.a.ABI,'manifest_sha256':'1'*64,'tag':'packages-latest-'+'1'*64,'release_id':11,'asset_id':12,'archive_sha256':'2'*64,'archive_size':123}
 def ticket(self):
  return {'schema_version':1,'kind':'latest-31599-publication-activation-authorization','eligible_for_normal_activation':True,**self.a.PINS,'snapshot_sha256':'1'*64,'client_evidence_sha256':'3'*64,'smoke_evidence_sha256':'4'*64,'predecessor_pointer':copy.deepcopy(self.a.PREDECESSOR),'recommended_pointer':copy.deepcopy(self.a.RECOMMENDED),'pointer':self.pointer()}
 def check(self,t):self.a.validate_ticket(t,self.pointer(),self.a.PREDECESSOR['manifest_sha256'],self.a.PINS['migration_proof_sha256'])
 def test_default_is_inert_before_any_source_or_network_import(self):
  with patch('sys.argv',['activate-latest-migration']),patch('sys.stdout',new_callable=io.StringIO) as out:self.a.main()
  self.assertEqual(json.loads(out.getvalue()),{'execute':False,'pages_deployed':False})
 def test_ticket_requires_exact_actual_context_and_fresh_nonnull_acceptance(self):
  self.check(self.ticket())
  for name in self.a.PINS:
   with self.subTest(name=name),self.assertRaises(ValueError):self.check(self.ticket()|{name:'0'*64})
  for name,value in [('schema_version',True),('eligible_for_normal_activation',False),('client_evidence_sha256',None),('smoke_evidence_sha256',None),('client_evidence_sha256','pending'),('snapshot_sha256','0'*64)]:
   with self.subTest(name=name),self.assertRaises(ValueError):self.check(self.ticket()|{name:value})
  with self.assertRaises(ValueError):self.check(self.ticket()|{'unreviewed_url':'https://example.invalid'})
 def test_retained_REC_or_old_LATEST_pointer_change_refused(self):
  for name in ('predecessor_pointer','recommended_pointer'):
   bad=self.ticket();bad[name]['asset_id']+=1
   with self.subTest(name=name),self.assertRaises(ValueError):self.check(bad)
 def test_latest_pointer_is_bounded_canonical_and_exact_finite_generation(self):
  self.assertEqual(self.a.decode_pointer(encode(self.pointer())),self.pointer())
  for key,value in [('channel','recommended'),('build_id','foreign'),('archive_size',True),('release_id',0),('tag','arbitrary'),('archive_sha256','bad')]:
   with self.subTest(key=key),self.assertRaises(ValueError):self.a.decode_pointer(encode(self.pointer()|{key:value}))
  for raw in ('','!',encode(self.pointer())+'\n',base64.b64encode(b'{"x":1,"x":2}').decode(),base64.b64encode(b'{"x":NaN}').decode()):
   with self.assertRaises(ValueError):self.a.decode_pointer(raw)
 def fixture(self):
  f=migration_fixtures.LatestSameImage();f.setUp();self.addCleanup(f.doCleanups);return f
 def test_real_normal_transition_rejects_wrong_authenticated_old_pointer(self):
  f=self.fixture();trees=f.trees()
  with self.assertRaisesRegex(ValueError,'authenticated predecessor'):
   self.a.authorize_transition(f.snapshot,f.old,f.new,trees['before'],trees['after'],dict(f.data['predecessor_pointer'],asset_id=1),f.proof())
 def test_real_normal_transition_refuses_modified_native_manifest(self):
  f=self.fixture();trees=f.trees();p=trees['after']/'firmware-manifest.json';p.write_bytes(p.read_bytes()+b' ')
  with self.assertRaises((ValueError,FileNotFoundError)):
   self.a.authorize_transition(f.snapshot,f.old,f.new,trees['before'],trees['after'],f.data['predecessor_pointer'],f.proof())
 def test_real_normal_transition_reaches_actual_full_payload_guard(self):
  f=self.fixture();trees=f.trees()
  with self.assertRaises((ValueError,FileNotFoundError)):
   self.a.authorize_transition(f.snapshot,f.old,f.new,trees['before'],trees['after'],f.data['predecessor_pointer'],f.proof())
 def test_live_race_retained_REC_and_latest_are_rechecked(self):
  t=self.ticket();state={'channels':{'recommended':t['recommended_pointer'],'latest':t['predecessor_pointer']}}
  self.a.require_live_predecessor(state,t,self.a.PREDECESSOR['manifest_sha256'])
  for channel in ('recommended','latest'):
   changed=copy.deepcopy(state);changed['channels'][channel]['manifest_sha256']='0'*64
   with self.assertRaises(ValueError):self.a.require_live_predecessor(changed,t,self.a.PREDECESSOR['manifest_sha256'])
 def test_transport_caps_and_schema3_reject_unreviewed_forms(self):
  proof=self.fixture().proof();self.a.validate_proof_transport(proof)
  for change in ({'schema_version':True},{'schema_version':2},{'cohort':'612-recommended'},{'extra':1}):
   with self.subTest(change=change),self.assertRaises(ValueError):self.a.validate_proof_transport(proof|change)
  with self.assertRaises(ValueError):self.a.decode_json(encode({'data':'x'*4096}),4096)
 def test_real_six_image_replay_accepts_identical_payloads_and_rejects_corruption(self):
  f=self.fixture();trees,proof,identity=f.tiny_pair()
  context=copy.deepcopy(f.data['context']);context['retained/Image']=identity
  original=f.snapshot.module
  def module(name):return f.helper if name=='latest_kernel_migration' else original(name)
  with patch.object(f.snapshot,'module',side_effect=module),patch.object(f.helper,'MANIFESTS',proof['firmware_manifest_sha256']),patch.object(f.helper,'IMAGE',identity),patch.object(f.helper,'CONTEXT',context):
   self.a.authorize_transition(f.snapshot,f.old,f.new,trees['before'],trees['after'],f.data['predecessor_pointer'],proof)
   payload=next((trees['after']/'bin/targets/mediatek/filogic').iterdir());payload.write_bytes(payload.read_bytes()[:-1]+b'!')
   with self.assertRaisesRegex(ValueError,'checksum'):
    self.a.authorize_transition(f.snapshot,f.old,f.new,trees['before'],trees['after'],f.data['predecessor_pointer'],proof)
 def test_authenticated_live_recheck_detects_changes(self):
  import types,tempfile
  state={'channels':{'recommended':self.a.RECOMMENDED,'latest':self.a.PREDECESSOR}}
  with tempfile.TemporaryDirectory() as temp:
   snapshot=types.SimpleNamespace(fetch_live=lambda *a:copy.deepcopy(state))
   self.a.require_live_unchanged(snapshot,state,self.a.SITE,None,None,Path(temp))
   snapshot.fetch_live=lambda *a:state|{'changed':True}
   with self.assertRaises(ValueError):self.a.require_live_unchanged(snapshot,state,self.a.SITE,None,None,Path(temp))
 def test_retired_latest_ASU_workflow_is_absent(self):
  self.assertFalse((ROOT/'.github/workflows/activate-latest-migration.yml').exists())
 def historical_root(self):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name)
  # The archived command authorizes this exact retained REC, not the mutable active cohort.
  for destination,source in {
   'scripts/activate-latest-migration.py':'scripts/activate-latest-migration.py',
   self.a.PROFILE:self.a.PROFILE,
   'profiles/redmi-ax6000-612-latest.json':'profiles/redmi-ax6000-612-latest.json',
   'profiles/redmi-ax6000-612-recommended.json':'profiles/redmi-ax6000-612-recommended-b122.json',
   'keys/repository.pub':'keys/repository.pub',
  }.items():
   target=root/destination;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/source).read_bytes())
  return root
 def check_args(self,root,smoke):
  raw=(json.dumps(self.fixture().proof(),sort_keys=True,indent=2)+'\n').encode()
  self.assertEqual(hashlib.sha256(raw).hexdigest(),self.a.PINS['migration_proof_sha256'])
  ticket=self.ticket()|{'smoke_evidence_sha256':smoke};auth=json.dumps(ticket).encode()
  return [sys.executable,'-I',str(root/'scripts/activate-latest-migration.py'),'--check-inputs','--pointer-base64',encode(self.pointer()),'--expected-predecessor',self.a.PREDECESSOR['manifest_sha256'],'--migration-proof-base64',base64.b64encode(raw).decode(),'--migration-proof-sha256',self.a.PINS['migration_proof_sha256'],'--authorization-base64',base64.b64encode(auth).decode(),'--authorization-sha256',hashlib.sha256(auth).hexdigest(),'--site-url',self.a.SITE,'--profiles',str(root/'profiles'),'--public-key',str(root/'keys/repository.pub')]
 def test_clean_cli_checks_exact_real_proof_bytes_and_refuses_pending_smokes_without_secrets(self):
  root=self.historical_root()
  for smoke,success in [('4'*64,True),(None,False)]:
   result=subprocess.run(self.check_args(root,smoke),env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,timeout=15)
   self.assertEqual(result.returncode==0,success,result.stderr)
   if success:self.assertEqual(json.loads(result.stdout),{'eligible_for_normal_activation':True,'check_inputs_only':True,'pages_deployed':False})
   else:self.assertIn('Missing actual local acceptance digest',result.stderr)
 def test_fixed_generated_profile_and_historical_retained_profiles_are_genuine(self):
  root=self.historical_root()
  spec=importlib.util.spec_from_file_location('historical_latest_activation',root/'scripts/activate-latest-migration.py')
  archived=importlib.util.module_from_spec(spec);spec.loader.exec_module(archived)
  self.assertEqual(archived.validate_fixed_profiles(root/'profiles',root/'keys/repository.pub')['build_id'],self.a.BUILD)
  with self.assertRaisesRegex(ValueError,'Only fixed checkout profiles/key'):
   archived.validate_fixed_profiles(ROOT/'profiles',ROOT/'keys/repository.pub')
 def test_archived_cli_refuses_current_recommended_mesh_cohort_without_secrets(self):
  current=json.loads((ROOT/'profiles/redmi-ax6000-612-recommended.json').read_bytes())
  self.assertIs(current.get('mediatek_mesh'),True)
  self.assertNotEqual(current['build_id'],self.a.RECOMMENDED['build_id'])
  result=subprocess.run(self.check_args(ROOT,'4'*64),env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,timeout=15)
  self.assertNotEqual(result.returncode,0)
  self.assertIn('Fixed accepted source profile/key differs',result.stderr)
  self.assertEqual(result.stdout,'')
if __name__=='__main__':unittest.main()
