"""Exercise actual workflow input gates with no signing, builds or network."""
import contextlib,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from test_apk_workflows import ROOT,shell_blocks


def embedded(filename,step,marker='PY'):
    text=shell_blocks(filename)[step]
    return text.split("<<'"+marker+"'\n",1)[1].split('\n'+marker,1)[0]


class RecommendedWorkflows(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        (self.root/'profiles').mkdir();(self.root/'raw').mkdir();self.calls=[]
        self.profile={'id':'redmi-ax6000-612-recommended','channel':'recommended','enabled':True,
                      'exclude_asu':True,'package_manager':'apk','sdk':{'sha256':'1'*64}}
    def write(self,path,value):
        path=self.root/path;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value))
    def execute(self,code):
        env={'GITHUB_OUTPUT':str(self.root/'outputs'),'GITHUB_STEP_SUMMARY':str(self.root/'summary'),
             'GITHUB_ENV':str(self.root/'environment'),'PROFILE':'redmi-ax6000-612-recommended.json'}
        with contextlib.chdir(self.root),patch.dict(os.environ,env),patch('subprocess.run',side_effect=lambda args,**kw:self.calls.append(args)):
            exec(compile(code,'actual-workflow-input-gate','exec'),{})
    def monitor(self):
        self.execute(embedded('packages.yml','Monitor recommended inputs and check no-ASU activation'))
        return (self.root/'outputs').read_text()
    def test_old_ASU_generated_profile_monitors_new_source_without_enabling_publication(self):
        old=dict(self.profile,asu={'enabled':True});old.pop('exclude_asu')
        self.write('profiles/redmi-ax6000-612-recommended.json',old)
        self.write('profiles/redmi-ax6000-612-recommended-new.json',self.profile)
        self.assertIn('enabled=false',self.monitor())
        self.assertIn('profiles/redmi-ax6000-612-recommended-new.json',self.calls[0])
    def test_fresh_activated_noASU_profile_enables_only_recommended_APK_daily(self):
        self.write('profiles/redmi-ax6000-612-recommended.json',self.profile)
        outputs=self.monitor();self.assertIn('enabled=true',outputs);self.assertIn('apk_signing=true',outputs)
        self.assertEqual(len(self.calls),1);self.assertIn('state/recommended-monitored.json',self.calls[0])
    def test_missing_generated_profile_is_monitor_only(self):
        self.write('profiles/redmi-ax6000-612-recommended-new.json',self.profile)
        self.assertIn('enabled=false',self.monitor())
    def test_wrong_active_channel_or_invalid_source_rejected_before_monitor(self):
        self.write('profiles/redmi-ax6000-612-recommended.json',dict(self.profile,channel='latest'))
        with self.assertRaises(SystemExit):self.monitor()
        self.assertEqual(self.calls,[])
    def test_manual_import_gate_refuses_old_ASU_OPKG_and_latest(self):
        code=embedded('publish-existing.yml','Detect imported and retained package managers','PYCODE')
        for change in ({'asu':{'enabled':True}},{'exclude_asu':False},{'channel':'latest'},{'package_manager':'opkg'}):
            self.write('raw/profile.json',self.profile|change)
            with self.subTest(change=change),self.assertRaises(SystemExit):self.execute(code)
        self.write('raw/profile.json',self.profile);self.execute(code)
        self.assertEqual((self.root/'outputs').read_text(),'incoming=apk\napk=true\n')
    def test_tail_SDK_gate_refuses_ASU_and_uses_exact_active_SDK_identity(self):
        code=embedded('tailscale-sdk.yml','Bind the published firmware profile and normal source lock')
        path='package-recipe/profiles/redmi-ax6000-612-recommended.json'
        self.write(path,self.profile|{'asu':{'enabled':True}})
        with self.assertRaises(SystemExit):self.execute(code)
        self.write(path,self.profile);self.execute(code)
        text=(self.root/'environment').read_text();self.assertIn('EXPECTED_SDK='+'1'*64,text)
        import hashlib
        self.assertIn('EXPECTED_PROFILE='+hashlib.sha256((self.root/path).read_bytes()).hexdigest(),text)
    def test_no_retired_workflow_or_channel_dispatch_survives(self):
        for filename in ('activate-native-generation.yml','activate-latest-migration.yml','activate-snapshot.yml'):
            self.assertFalse((ROOT/'.github/workflows'/filename).exists())
        for filename in ('firmware.yml','publish-existing.yml'):
            text=(ROOT/'.github/workflows'/filename).read_text()
            self.assertNotIn('          - latest',text);self.assertNotIn('66-opkg',text)
            self.assertNotIn('allow_asu_apk_migration:',text);self.assertNotIn('allow_native_apk_replacement:',text)
        text=(ROOT/'.github/workflows/tailscale-sdk.yml').read_text()
        for retired in ('opkg_ref','matrix.','66-opkg','valujin/ax6000-packages\n'):
            self.assertNotIn(retired,text)
        self.assertIn('PROFILE: profiles/redmi-ax6000-612-recommended-new.json',(ROOT/'.github/workflows/firmware.yml').read_text())

if __name__=='__main__':unittest.main()
