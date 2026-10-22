"""Tiny owned SDK directory fixtures; no SDK, signing or publication execution."""
import importlib.util,json,os,shutil,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,Mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('refresh_cleanup',ROOT/'scripts/channel-snapshot.py')
snapshot=importlib.util.module_from_spec(spec);spec.loader.exec_module(snapshot)

class RefreshCleanup(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def owned(self):
  work=self.root/'work';work.mkdir();owned=work/'build-recommended';certs=owned/'sdk'/'certs';certs.mkdir(parents=True)
  (certs/'localhost-crt.pem').write_text('public test fixture');certs.chmod(0o555)
  self.addCleanup(lambda:certs.chmod(0o755) if certs.exists() else None)
  return work,owned
 def test_readonly_sdk_directory_can_be_removed_without_changing_outside_symlinks(self):
  work,owned=self.owned();outside=self.root/'outside';outside.mkdir();outside.chmod(0o555)
  self.addCleanup(lambda:outside.chmod(0o755))
  (owned/'outside-link').symlink_to(outside,target_is_directory=True)
  snapshot.cleanup_owned_workspace(work,owned)
  self.assertFalse(owned.exists());self.assertEqual(outside.stat().st_mode&0o777,0o555)
 def test_linked_root_and_nonowned_workspace_are_refused(self):
  work=self.root/'work';work.mkdir();outside=self.root/'outside';outside.mkdir()
  linked=work/'build-recommended';linked.symlink_to(outside,target_is_directory=True)
  for owned in (linked,outside,work/'arbitrary'):
   with self.subTest(owned=owned),self.assertRaises((ValueError,OSError)):snapshot.cleanup_owned_workspace(work,owned)
  self.assertTrue(outside.exists())
 def test_linked_workspace_ancestor_is_refused_before_chmod(self):
  outside=self.root/'outside';work=outside/'work';owned=work/'build-recommended';owned.mkdir(parents=True);owned.chmod(0o555)
  self.addCleanup(lambda:owned.chmod(0o755))
  alias=self.root/'alias';alias.symlink_to(outside,target_is_directory=True)
  with self.assertRaises(ValueError):snapshot.cleanup_owned_workspace(alias/'work',alias/'work'/'build-recommended')
  self.assertEqual(owned.stat().st_mode&0o777,0o555)
 def test_refresh_reaches_composition_after_successful_publish_with_readonly_sdk_fixture(self):
  profiles=self.root/'profiles';profiles.mkdir();profile={'channel':'recommended','enabled':True,'exclude_asu':True}
  (profiles/'redmi-ax6000-612-recommended.json').write_text(json.dumps(profile))
  old=self.root/'old';channel=old/'channel';(channel/'state').mkdir(parents=True)
  for name,value in (('profile.json',profile),('state/lock.json',{'old':True}),('downloads.json',{'release':{'id':1}})):(channel/name).write_text(json.dumps(value))
  work=self.root/'work';output=self.root/'public';previous={'signed':'previous'};api=Mock();api.get_release.return_value={'id':1}
  def run(args,**kwargs):
   if 'scripts/monitor.py' in str(args):Path(args[args.index('--output')+1]).write_text(json.dumps({'new':True}))
   if 'scripts/build.sh' in str(args):
    certs=Path(args[args.index('--work-dir')+1])/'certs';certs.mkdir(parents=True);(certs/'localhost-crt.pem').write_text('public fixture');certs.chmod(0o555)
    self.addCleanup(lambda:certs.chmod(0o755) if certs.exists() else None)
  with patch.object(snapshot,'signing_key'),patch.object(snapshot,'fetch_live',return_value=previous),patch.object(snapshot,'restore_live_channels',return_value={'recommended':(old,{'old':'pointer'})}),patch.object(snapshot,'cohort',return_value='same'),patch.object(snapshot,'apk_publication_args',return_value=[]),patch.object(snapshot.subprocess,'run',side_effect=run),patch.object(snapshot,'module',return_value=Mock(ReleaseAPI=Mock(return_value=api))),patch.object(snapshot,'pack_snapshot'),patch.object(snapshot,'publish_snapshot',return_value={'new':'pointer'}),patch.object(snapshot,'restore_online') as restore,patch.object(snapshot,'compose_site') as compose,patch.object(snapshot,'deployment_record'),patch.object(snapshot.subprocess,'check_output',return_value='a'*40):
   result=snapshot.refresh('https://fixture.invalid','own/repo',profiles,work,'unused-key','public','usign',output)
  self.assertEqual(result,output);restore.assert_called_once();compose.assert_called_once();self.assertFalse((work/'build-recommended').exists())

if __name__=='__main__':unittest.main()
