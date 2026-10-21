"""Exercise the APK router installer with isolated filesystem and tool stubs."""
import json
import os
import shutil
import shlex
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ABI = '6.12.108~0123456789abcdef0123456789abcdef-r1'
BASE = 'https://valujin.github.io/ax6000-packages-6.12/channels/recommended'
INDEX = f'{BASE}/feeds/redmi-ax6000-612-recommended/{ABI}/packages.adb'
PUBLIC = '@public https://downloads.immortalwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/packages/packages.adb\n'


class ApkInstallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.etc = self.root / 'etc'
        self.apk = self.etc / 'apk'
        (self.apk / 'keys').mkdir(parents=True)
        (self.apk / 'repositories.d').mkdir()
        (self.etc / 'ax6000').mkdir()
        (self.etc / 'ax6000/repository.pub').write_bytes((ROOT / 'keys/repository.pub').read_bytes())
        (self.root / 'lib/apk/repositories.d').mkdir(parents=True)
        self.mock = self.root / 'mock'
        self.mock.mkdir()
        self.key = ROOT / 'keys/repository-apk.pem'
        (self.apk / 'keys/repository-apk.pem').write_bytes(self.key.read_bytes())
        self.world = f'kernel={ABI}\nlibc=1.2.5-r1\nbase-files=1-r1\nbusybox=1-r1\napk-openssl=3.0.5-r3\n'
        (self.apk / 'world').write_text(self.world)
        (self.apk / 'arch').write_text('aarch64_cortex-a53\n')
        (self.apk / 'ax6000-protected.list').write_text(self.world)
        self.public = self.apk / 'repositories.d/public.list'
        self.public.write_text(PUBLIC)
        self.installer = self.root / 'installer.sh'
        source = ROOT / 'scripts/install-feed-apk.sh'
        self.assertTrue(source.exists(), 'APK installer must exist')
        self.installer.write_text(source.read_text().replace('/etc', str(self.etc)).replace('/lib/apk/repositories.d', str(self.root / 'lib/apk/repositories.d')))
        self.env = dict(os.environ, PATH=str(self.mock) + ':' + os.environ['PATH'], MOCK_KEY=str(self.key),
                        MOCK_LOG=str(self.root / 'log'), MOCK_QUERY_LOG=str(self.root / 'queries'), MOCK_ABI=ABI, MOCK_ARCH='aarch64',
                        MOCK_PROFILE_ARCH='aarch64_cortex-a53', MOCK_PROFILE_SIG='0', MOCK_INDEX_SIG='0', MOCK_UPDATE='0', MOCK_FORMAT='apk')
        self.tool('id', '#!/bin/sh\necho 0\n')
        self.tool('wget', '''#!/usr/bin/env python3
import json,os,pathlib,sys
p=pathlib.Path(sys.argv[sys.argv.index('-O')+1]);u=sys.argv[-1]
if u.endswith('/profile.json'):
 p.write_text(json.dumps({'id':'redmi-ax6000-612-recommended','channel':'recommended','package_manager':os.environ['MOCK_FORMAT'],'apk_key_sha256':'279ea19b627e16d0807e099de8bd6cf8b69830281defa9bdb9e4ae96f5beb751','firmware':{'architecture':os.environ['MOCK_PROFILE_ARCH'],'kernel_version':''' + repr(ABI) + '''}}))
elif u.endswith('/repository-apk.pem'): p.write_bytes(pathlib.Path(os.environ['MOCK_KEY']).read_bytes())
else: p.write_text('downloaded data')
''')
        self.tool('jsonfilter', '''#!/usr/bin/env python3
import json,sys
d=json.load(open(sys.argv[sys.argv.index('-i')+1]));a=sys.argv
for i,flag in enumerate(a):
 if flag not in ('-e','-t'):continue
 expr=a[i+1]
 if expr=='@': values=[d]
 elif expr=='@[*]':values=list(d.values()) if isinstance(d,dict) else list(d)
 elif expr.startswith('@[*].'):values=[row[expr[5:]] for row in d if isinstance(row,dict) and expr[5:] in row]
 else:
  value=d
  if expr.startswith('@[0]'):value=value[0];expr='@'+expr[4:]
  for k in expr[2:].split('.'):value=value[k]
  values=[value]
 if flag=='-t':
  def kind(v):return 'string' if isinstance(v,str) else 'object' if isinstance(v,dict) else 'array' if isinstance(v,list) else 'null' if v is None else 'int'
  if values:print('\\\\ '.join(kind(v) for v in values))
 else:
  for value in values:
   if value is not None:print(value if isinstance(value,str) else json.dumps(value))
''')
        self.tool('usign', '''#!/usr/bin/env python3
import os,sys
if '-F' in sys.argv: print('eaad5e29fcc9ed69')
else:
 with open(os.environ['MOCK_LOG'],'a') as f:f.write('profile-verify\\n')
 sys.exit(int(os.environ['MOCK_PROFILE_SIG']))
''')
        self.tool('apk', '''#!/usr/bin/env python3
import json,os,sys
a=sys.argv[1:]
if a==['--print-arch']: print(os.environ['MOCK_ARCH'])
elif 'query' in a:
 name=a[-1];versions={'kernel':os.environ['MOCK_ABI'],'libc':'1.2.5-r1','base-files':'1-r1','busybox':'1-r1','apk-openssl':'3.0.5-r3'}
 with open(os.environ['MOCK_QUERY_LOG'],'a') as f:f.write(json.dumps(a)+'\\n')
 rows=json.loads(os.environ['MOCK_INSTALLED']) if 'MOCK_INSTALLED' in os.environ else [{'name':n,'version':v} for n,v in versions.items()]
 print(json.dumps(rows if name=='*' else [row for row in rows if isinstance(row,dict) and row.get('name')==name]))
elif 'verify' in a:
 with open(os.environ['MOCK_LOG'],'a') as f:f.write('index-verify\\n')
 sys.exit(int(os.environ['MOCK_INDEX_SIG']))
elif a==['update']:
 with open(os.environ['MOCK_LOG'],'a') as f:f.write('update\\n')
 sys.exit(int(os.environ['MOCK_UPDATE']))
else: raise SystemExit('Unexpected APK mutation: '+repr(a))
''')

    def tool(self, name, data):
        p = self.mock / name
        p.write_text(data)
        p.chmod(0o755)

    def run_installer(self):
        return subprocess.run(['sh', str(self.installer)], env=self.env, text=True, capture_output=True)

    def own(self):
        return self.apk / 'repositories.d/ax6000.list'

    def test_installed_database_is_queried_once_including_kernel_and_reports_progress(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        queries = [json.loads(line) for line in (self.root / 'queries').read_text().splitlines()]
        self.assertEqual(len(queries), 1, 'APK must load the installed database only once')
        self.assertEqual(queries[0], ['--no-network', '--repositories-file', '/dev/null', 'query', '--installed', '--format', 'json', '--fields', 'name,version', '*'])
        self.assertIn('Reading installed APK package inventory', result.stdout)
        self.assertIn('Protected APK packages verified: 5/5', result.stdout)

    def test_real_jsonfilter_rejects_nul_terminated_installed_names_and_versions(self):
        binary = os.environ.get('AX6000_JSONFILTER') or shutil.which('jsonfilter')
        if not binary:
            self.skipTest('Real jsonfilter binary is required for NUL semantics')
        self.tool('jsonfilter', '#!/bin/sh\nexec ' + shlex.quote(binary) + ' "$@"\n')
        good = [{'name':name, 'version':version} for name, version in (line.split('=') for line in self.world.splitlines())]
        for field in ('name', 'version'):
            rows = [dict(row) for row in good]
            rows[0][field] += '\x00hidden'
            self.env['MOCK_INSTALLED'] = json.dumps(rows)
            result = self.run_installer()
            self.assertNotEqual(result.returncode, 0, 'jsonfilter must not silently truncate installed ' + field)
            self.assertFalse(self.own().exists())

    def test_malformed_or_duplicate_installed_inventory_fails_before_feed_changes(self):
        good = [{'name':name, 'version':version} for name, version in (line.split('=') for line in self.world.splitlines())]
        for rows in ([], {}, good + [good[0]], good + [{'name':'extra'}],
                     good + [{'version':'1-r1'}], good + [{'name':'extra','version':1}],
                     good + [{'name':'bad\nname','version':'1-r1'}],
                     good + [{'name':'extra','version':'bad\nversion'}], good + [None]):
            with self.subTest(rows=rows):
                self.env['MOCK_INSTALLED'] = json.dumps(rows)
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.own().exists())
                self.assertEqual(self.public.read_text(), PUBLIC)

    def test_verifies_before_install_and_preserves_public_feed(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.public.read_text(), PUBLIC)
        self.assertEqual(self.own().read_text(), INDEX + '\n')
        self.assertEqual((self.root / 'log').read_text(), 'profile-verify\nindex-verify\nupdate\n')
        self.assertEqual((self.apk / 'world').read_text(), self.world)

    def test_exact_firstboot_mirror_five_public_feeds_are_preserved(self):
        mirror = '# Public userspace packages; explicitly select with @public.\n# Core, kernel and vendor packages stay bound to this image.\n' + ''.join('@public https://mirrors.vsean.net/openwrt/releases/25.12.0/packages/aarch64_cortex-a53/' + feed + '/packages.adb\n' for feed in ('base','luci','packages','routing','telephony'))
        self.public.write_text(mirror)
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.public.read_text(), mirror)
        self.assertEqual(self.own().read_text(), INDEX + '\n')

    def test_mirror_allowance_rejects_foreign_roots_versions_architectures_and_untagged_urls(self):
        mirror = '@public https://mirrors.vsean.net/openwrt/releases/25.12.0/packages/aarch64_cortex-a53/base/packages.adb'
        for line in (mirror.replace('mirrors.vsean.net','evil.invalid'), mirror.replace('/openwrt/','/other/'),
                     mirror.replace('25.12.0','25.12-SNAPSHOT'), mirror.replace('25.12.0','25.12.1'),
                     mirror.replace('aarch64_cortex-a53','aarch64_generic'), mirror.replace('/base/','/video/'),
                     mirror.replace('@public ','@other '), mirror.replace('@public ',''),
                     mirror.replace('https://','http://'), mirror + '/extra'):
            with self.subTest(line=line):
                self.public.write_text(line + '\n')
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.own().exists())
                self.assertEqual(self.public.read_text(), line + '\n')

    def test_same_full_compiled_architecture_also_works(self):
        self.env['MOCK_ARCH']='aarch64_cortex-a53'
        result=self.run_installer()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.own().read_text(),INDEX+'\n')

    def test_foreign_malformed_multiple_missing_linked_or_oversized_arch_refused(self):
        path=self.apk/'arch'
        for data in (b'aarch64\n',b'x86_64\n',b'',b'aarch64_cortex-a53\naarch64\n',
                     b'aarch64_cortex-a53\n\n',b'aarch64_cortex-a53 \n',b'aarch64_cortex-a53\r\n',
                     b'aarch64_cortex-a53\0',b'x'*257):
            with self.subTest(data=data):
                path.write_bytes(data);result=self.run_installer()
                self.assertNotEqual(result.returncode,0)
                self.assertFalse(self.own().exists())
                self.assertEqual(self.public.read_text(),PUBLIC)
                self.assertNotIn('update', (self.root/'log').read_text())
        path.unlink()
        self.assertNotEqual(self.run_installer().returncode,0)
        outside=self.root/'outside-arch';outside.write_text('aarch64_cortex-a53\n');path.symlink_to(outside)
        self.assertNotEqual(self.run_installer().returncode,0)
        self.assertEqual(outside.read_text(),'aarch64_cortex-a53\n')
        self.assertFalse(self.own().exists())

    def test_busybox_awk_cannot_hide_nul_architecture_bytes(self):
        busybox=shutil.which('busybox')
        self.assertIsNotNone(busybox,'BusyBox required for actual router awk semantics')
        self.tool('awk','#!/bin/sh\nexec '+busybox+' awk "$@"\n')
        for data in (b'aarch64_cortex-a53\0',b'aarch64_cortex-a53\0\n'):
            (self.apk/'arch').write_bytes(data)
            result=self.run_installer()
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(self.own().exists())
        for data in (b'aarch64_cortex-a53',b'aarch64_cortex-a53\n'):
            (self.apk/'arch').write_bytes(data)
            result=self.run_installer()
            self.assertEqual(result.returncode,0,result.stderr)

    def test_profile_architecture_and_cpu_mismatch_report_actual_values(self):
        for name,value in [('MOCK_ARCH','x86_64'),('MOCK_PROFILE_ARCH','aarch64')]:
            old=self.env[name];self.env[name]=value
            result=self.run_installer()
            self.assertNotEqual(result.returncode,0)
            self.assertIn('compiled='+self.env['MOCK_ARCH'],result.stderr)
            self.assertIn('effective=aarch64_cortex-a53',result.stderr)
            self.assertIn('repository='+self.env['MOCK_PROFILE_ARCH'],result.stderr)
            self.assertFalse(self.own().exists());self.env[name]=old

    def test_repeated_install_is_idempotent(self):
        for _ in range(2):
            result = self.run_installer()
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.own().read_text(), INDEX + '\n')

    def test_identity_signature_and_format_fail_without_mutation(self):
        for name, value in [('MOCK_PROFILE_SIG','1'), ('MOCK_INDEX_SIG','1'), ('MOCK_ABI','6.12.1~bad-r1'),
                            ('MOCK_ARCH','wrong'), ('MOCK_FORMAT','ipk')]:
            with self.subTest(name=name):
                old = self.env[name]
                self.env[name] = value
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.own().exists())
                self.assertEqual(self.public.read_text(), PUBLIC)
                self.env[name] = old

    def test_refuses_untagged_foreign_target_or_userspace(self):
        for line in ['https://downloads.immortalwrt.org/releases/25.12.0/targets/mediatek/filogic/packages/packages.adb',
                     '@public https://downloads.immortalwrt.org/releases/25.12.0/targets/mediatek/filogic/kmods/bad/packages.adb',
                     PUBLIC.split(' ',1)[1].strip(), '@public https://evil.invalid/packages.adb',
                     'set public_mirror=https://evil.invalid']:
            with self.subTest(line=line):
                self.public.write_text(line+'\n')
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.public.read_text(), line+'\n')
                self.assertFalse(self.own().exists())

    def test_missing_or_inconsistent_core_pins_refused(self):
        (self.apk / 'world').write_text('kernel\n')
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.own().exists())

    def test_bad_bundled_key_and_symlink_config_refused(self):
        (self.apk / 'keys/repository-apk.pem').write_text('wrong key')
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.own().exists())
        (self.apk / 'keys/repository-apk.pem').write_bytes(self.key.read_bytes())
        outside = self.root / 'outside'
        outside.write_text(PUBLIC)
        self.public.unlink()
        self.public.symlink_to(outside)
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertEqual(outside.read_text(), PUBLIC)

    def test_update_failure_rolls_back_own_feed(self):
        self.env['MOCK_UPDATE'] = '4'
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.own().exists())
        self.assertEqual(self.public.read_text(), PUBLIC)
        self.assertNotIn('Verified matching APK feed enabled', result.stdout)

    def test_update_failure_restores_existing_own_file_and_mode(self):
        original = '# installed own feed\n' + INDEX + '\n'
        self.own().write_text(original)
        self.own().chmod(0o600)
        self.env['MOCK_UPDATE'] = '4'
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.own().read_text(), original)
        self.assertEqual(self.own().stat().st_mode & 0o777, 0o600)

    def test_overridden_channel_url_is_rejected_before_download(self):
        self.env['PACKAGE_REPOSITORY_URL'] = 'https://evil.invalid/channels/recommended'
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'log').exists())
        self.assertFalse(self.own().exists())

    def test_protected_version_drift_is_refused(self):
        wrong = self.world.replace('libc=1.2.5-r1', 'libc=1.2.6-r1')
        (self.apk / 'world').write_text(wrong)
        (self.apk / 'ax6000-protected.list').write_text(wrong)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Protected package version differs: libc', result.stderr)
        self.assertFalse(self.own().exists())


if __name__ == '__main__':
    unittest.main()
