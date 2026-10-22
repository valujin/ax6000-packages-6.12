"""Root-reviewed retained metadata vectors; no native APK/tool execution."""
import copy,gzip,json,unittest
from pathlib import Path
from unittest.mock import patch
import test_native_generation as legacy
ROOT=Path(__file__).resolve().parents[1]

class NativeAppMetadata(unittest.TestCase):
 def setUp(self):
  self.n=legacy.NativeProfiles.helper(self);self.fixture=json.loads(gzip.decompress((ROOT/'tests/fixtures/rec_native_app_metadata.json.gz').read_bytes()))
 def test_actual_eight_timestamp_vectors_pass_only_exact_new_relation(self):
  self.assertTrue(hasattr(self.n,'reviewed_app_paths'),'Finite APP timestamp relation is missing')
  paths={p:self.fixture[p]['paths'] for p in ('before','after')}
  self.n.reviewed_app_paths(paths)
  for phase in ('before','after'):
   bad=copy.deepcopy(paths);bad[phase][2]['files'][0]['mtime']+=1
   with self.subTest(phase=phase),self.assertRaises(ValueError):self.n.reviewed_app_paths(bad)
 def test_modes_owners_hooks_extra_paths_and_unrelated_hashes_refused(self):
  paths={p:self.fixture[p]['paths'] for p in ('before','after')}
  for mutate in (lambda x:x[2]['files'][0]['acl'].update(mode=420),lambda x:x[2]['files'][0]['acl'].update(user='nobody'),lambda x:x[2]['files'][0].update(hash='0'*64),lambda x:x[2]['files'].append(copy.deepcopy(x[2]['files'][0])),lambda x:x[2]['files'][0].update(target='outside'),lambda x:x[0].update(acl={'mode':511,'user':'root','group':'root'})):
   bad=copy.deepcopy(paths);mutate(bad['after'])
   with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.n.reviewed_app_paths(bad)

 def test_new_helper_real_shaped_decoded_IO_preserves_payload_and_control_guards(self):
  from types import SimpleNamespace
  controls={p:copy.deepcopy(self.fixture[p]['control']) for p in ('before','after')}
  paths={p:copy.deepcopy(self.fixture[p]['paths']) for p in ('before','after')}
  module=(ROOT/'files/asu-client/ax6000_asu.js').read_bytes()
  payload={p:{name:b'unchanged hook/view fixture' for name in self.n.APP_METADATA_RELATION['exact_regular_paths']} for p in ('before','after')}
  payload['before'][self.n.MODULE]=b'old module';payload['after'][self.n.MODULE]=module
  def phase(path):return 'after' if str(path).endswith('r3.apk') else 'before'
  fmt=SimpleNamespace(read_control=lambda path,**kw:controls[phase(path)],apk_json=lambda path,apk:{'paths':paths[phase(path)]},payload_files=lambda path,**kw:payload[phase(path)])
  before={'producer_commit':self.n.OLD_PRODUCER,'raw':'/fixture/before','source':'/fixture/before-source'}
  after={'producer_commit':self.n.NEW_PRODUCER,'raw':'/fixture/after','source':'/fixture/after-source'}
  apk={'path':'/tools/apk','sha256':'ec6f3df6b3e295ad4395649bfd5bc5ca8f2afe52c8fe7bff04df3617f78952f8','size':1}
  with patch.object(self.n,'checked_ref',return_value=Path('/tools/apk')),patch.object(self.n,'regular',side_effect=lambda path,*args:Path(path)),patch.object(self.n,'identity',side_effect=lambda path:self.n.APP_METADATA_RELATION['archives'][phase(path)]),patch.object(self.n,'module',return_value=fmt):
   self.n.app_payload_new_context(before,after,apk)
   original=payload['after'].copy();hook='etc/uci-defaults/95-luci-app-attendedsysupgrade-housekeeping'
   payload['after'][hook]=b'changed hook'
   with self.assertRaisesRegex(ValueError,'unrelated'):self.n.app_payload_new_context(before,after,apk)
   payload['after']=original.copy();payload['after'][self.n.MODULE]=b'wrong module'
   with self.assertRaisesRegex(ValueError,'constructor'):self.n.app_payload_new_context(before,after,apk)
   payload['after']=original.copy();controls['after']['APK-Raw']['depends'].append('arbitrary-hook-provider')
   with self.assertRaisesRegex(ValueError,'controls'):self.n.app_payload_new_context(before,after,apk)
   controls['after']=copy.deepcopy(self.fixture['after']['control'])
   with patch.object(self.n,'identity',return_value={'sha256':'0'*64,'size':12186}):
    with self.assertRaisesRegex(ValueError,'archive'):self.n.app_payload_new_context(before,after,apk)
   with self.assertRaisesRegex(ValueError,'producers'):self.n.app_payload_new_context(before,{**after,'producer_commit':'0'*40},apk)
 def test_portable_new_context_rejects_changed_app_metadata_authority(self):
  import test_native_context as context
  case=context.NewContext();case.setUp();self.addCleanup(case.doCleanups);fixture=case.typed_fixture();case.check(fixture)
  for mutate in (lambda x:x.update(root_decision_sha256='0'*64),lambda x:x['mtime'].update(after=1),lambda x:x['exact_regular_paths'].pop(),lambda x:x['archives']['after'].update(sha256='0'*64)):
   bad=copy.deepcopy(fixture);mutate(bad[2]['summary']['context_transition']['app_metadata_relation'])
   with self.subTest(mutate=mutate),self.assertRaises(ValueError):case.check(bad)

if __name__=='__main__':unittest.main()
