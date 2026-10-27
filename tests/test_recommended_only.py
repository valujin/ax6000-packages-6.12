import copy, importlib.util, json, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
try:import no_asu
except ImportError:no_asu=None
spec=importlib.util.spec_from_file_location('no_asu_firmware',ROOT/'scripts/prepare-firmware.py');firmware=importlib.util.module_from_spec(spec);spec.loader.exec_module(firmware)
class RecommendedOnlyTests(unittest.TestCase):
 def test_future_profile_has_no_asu_and_preserves_router_features(self):
  p=json.loads((ROOT/'profiles/redmi-ax6000-612-recommended-new.json').read_text())
  self.assertTrue(p.get('exclude_asu'));self.assertNotIn('asu',p)
  self.assertFalse(any('attendedsysupgrade' in n or n=='auc' for n in p['packages']+p['image_packages']))
  self.assertEqual(p['package_only'],['tailscale']);self.assertNotIn('tailscale',p['image_packages'])
  self.assertEqual([x['layout'] for x in p['firmware']['devices']],['stock','mtkuboot','ubootmod'])
  self.assertEqual(p['pbr_source'],'mossdef-stable');self.assertTrue(p['vendor_country_db']);self.assertEqual(p['package_manager'],'apk')
 def test_concrete_no_asu_guard(self):self.assertIsNotNone(no_asu)
 def test_warm_overlay_and_selected_asu_are_removed_without_touching_kernel(self):
  if no_asu is None:self.skipTest('RED guard absent')
  p={'exclude_asu':True,'channel':'recommended','package_manager':'apk','packages':['pbr'],'image_packages':['pbr']}
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);stale=root/'files/etc/asu-cohort.json';stale.parent.mkdir(parents=True);stale.write_text('{}')
   js=root/'files/www/luci-static/resources/ax6000_asu.js';js.parent.mkdir(parents=True);js.write_text('old')
   keep=root/'files/etc/keep';keep.write_text('keep')
   no_asu.configure(p,root);self.assertFalse(stale.exists());self.assertFalse(js.exists());self.assertEqual(keep.read_text(),'keep')
   cfg='CONFIG_KERNEL_FIXED=y\nCONFIG_PACKAGE_luci-app-attendedsysupgrade=y\nCONFIG_IB=y\n'
   result=firmware.set_symbols(cfg,no_asu.symbols(cfg,{'luci-i18n-attendedsysupgrade-zh-cn'}))
   self.assertIn('CONFIG_KERNEL_FIXED=y\n',result);self.assertNotIn('CONFIG_IB=y',result);self.assertNotIn('CONFIG_PACKAGE_luci-app-attendedsysupgrade=y',result)
   no_asu.verify_config(result)
   with self.assertRaises(ValueError):no_asu.verify_config(result+'CONFIG_PACKAGE_auc=m\n')
 def test_actual_root_status_payload_and_symlink_absence(self):
  if no_asu is None:self.skipTest('RED guard absent')
  no_asu.assert_absent({'libc':{}},{'etc/config/network'})
  for packages,files,links in [({'luci-app-attendedsysupgrade':{}},set(),{}),({}, {'etc/asu-cohort.json'},{}),({}, {'www/luci-static/resources/ax6000_asu.js'},{}),({},set(),{'usr/bin/link':b'auc'})]:
   with self.assertRaises(ValueError):no_asu.assert_absent(packages,files,links)
 def test_no_asu_policy_refuses_client_reintroduction_and_wrong_channel(self):
  if no_asu is None:self.skipTest('RED guard absent')
  p={'exclude_asu':True,'channel':'recommended','package_manager':'apk','packages':[],'image_packages':[]}
  no_asu.validate(p)
  for change in [{'asu':{'enabled':True}},{'packages':['auc']},{'channel':'latest'}]:
   with self.assertRaises(ValueError):no_asu.validate({**p,**change})
 def test_warm_overlay_refuses_links_and_removes_client_acl_and_defaults(self):
  p={'exclude_asu':True,'channel':'recommended','package_manager':'apk','packages':[],'image_packages':[]}
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp)
   for name in ['usr/share/rpcd/acl.d/luci-app-attendedsysupgrade.json','etc/config/attendedsysupgrade','etc/uci-defaults/99-ax6000-asu','usr/bin/owut']:
    file=root/'files'/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_text('stale')
   with self.assertRaises(ValueError):no_asu.configure(p,root,check_only=True)
   no_asu.configure(p,root);no_asu.configure(p,root,check_only=True)
   target=root/'outside';target.write_text('preserve');link=root/'files/etc/asu-cohort.json';link.symlink_to(target)
   with self.assertRaisesRegex(ValueError,'Linked'):no_asu.configure(p,root)
   self.assertEqual(target.read_text(),'preserve')
 def test_manual_no_asu_generation_only_removes_client_and_preserves_exact_abi(self):
  spec=importlib.util.spec_from_file_location('no_asu_snapshot',ROOT/'scripts/channel-snapshot.py');snap=importlib.util.module_from_spec(spec);spec.loader.exec_module(snap)
  old=json.loads((ROOT/'tests/fixtures/rec-r5-apk-profile.json').read_text());new=copy.deepcopy(old)
  new.pop('asu');new.pop('imagebuilder');new['exclude_asu']=True
  for field in ['packages','image_packages']:new[field]=[n for n in old[field] if not no_asu.package(n)]
  new['sdk']={'url':'https://example.org/new-sdk','sha256':'9'*64};new['build_id']='new-no-asu-native'
  snap.validate_generation_replacement(old,new,old['build_id'])
  for field,value in [('firmware',{**new['firmware'],'kernel_version':'6.12.108~'+'f'*32+'-r1'}),('firmware',{**new['firmware'],'commit':'f'*40}),('apk_key_sha256','f'*64),('image_packages',new['image_packages']+['unreviewed'])]:
   with self.subTest(field=field,value=value),self.assertRaises(ValueError):snap.validate_generation_replacement(old,{**new,field:value},old['build_id'])
  with self.assertRaises(ValueError):snap.validate_generation_replacement(old,new,None)
  with self.assertRaises(ValueError):snap.validate_generation_replacement(old,{**new,'asu':old['asu']},old['build_id'])
