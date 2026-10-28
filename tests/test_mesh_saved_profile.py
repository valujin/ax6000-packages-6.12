import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-profile'


class SavedBackhaulProfile(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'bin').mkdir()
        self.profile = self.root / 'mapd_user.cfg'
        self.values = {'BhProfile0Valid': '1', 'BhProfile0Ssid': 'AX6000-BH-example',
                       'BhProfile0WpaPsk': 'fixture-only-password', 'BhProfile0AuthMode': 'WPA2PSK',
                       'BhProfile0EncrypType': 'AES'}
        self.write_profile()
        datconf = self.root / 'bin/datconf'
        datconf.write_text('''#!/usr/bin/python3
import json,sys
try:
 d=json.load(open(sys.argv[2])); value=d[sys.argv[4]]
except (OSError,KeyError,ValueError): sys.exit(1)
print(value)
'''); datconf.chmod(0o755)
        source = SCRIPT.read_text().replace('/etc/map/mapd_user.cfg', str(self.profile))
        self.script = self.root / 'profile'; self.script.write_text(source); self.script.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.root / 'bin') + ':' + os.environ['PATH']}

    def tearDown(self): self.temp.cleanup()
    def write_profile(self): self.profile.write_text(json.dumps(self.values)); self.profile.chmod(0o600)
    def check(self): return subprocess.run(['sh', str(self.script)], env=self.env, capture_output=True, text=True, timeout=5)

    def test_valid_profile_succeeds_without_disclosing_credentials(self):
        result = self.check(); self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, ''); self.assertEqual(result.stderr, '')

    def test_missing_invalid_or_unsupported_data_fails(self):
        for field, value in [('BhProfile0Valid','0'), ('BhProfile0Ssid',''), ('BhProfile0Ssid','x'*33),
                             ('BhProfile0WpaPsk','short'), ('BhProfile0WpaPsk','x'*64),
                             ('BhProfile0AuthMode','OPEN'), ('BhProfile0EncrypType','TKIP')]:
            with self.subTest(field=field, value=value):
                old = self.values[field]; self.values[field] = value; self.write_profile()
                result = self.check(); self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, ''); self.assertEqual(result.stderr, '')
                self.values[field] = old
        self.profile.unlink(); self.assertNotEqual(self.check().returncode, 0)

    def test_readonly_and_symlink_profiles_fail(self):
        self.profile.chmod(0o400); self.assertNotEqual(self.check().returncode, 0)
        target = self.root / 'target'; self.profile.rename(target); self.profile.symlink_to(target)
        self.assertNotEqual(self.check().returncode, 0)

    def test_pending_enrollment_clears_old_profiles_but_preserves_other_settings(self):
        self.profile.write_text('Other=keep\nBhProfile0Valid=1\nBhProfile0Ssid=old\nBhProfile0WpaPsk=oldsecret\nBhProfile1Valid=1\n')
        result = subprocess.run(['sh', str(self.script), 'reset'], env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.profile.read_text(), 'Other=keep\n')
        self.assertEqual(self.profile.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result.stdout + result.stderr, '')
