"""Band policy is applied to an isolated copy of the actual vendor config."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-band'


class BandPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); (self.root / 'bin').mkdir()
        self.cfg = self.root / 'mapd_cfg'
        self.original = 'Other=preserve\nBhPriority2G=3\nBhPriority5GL=1\nBhPriority5GH=1\n'
        self.cfg.write_text(self.original); self.cfg.chmod(0o600)
        self.tool('uci', '''#!/bin/sh
[ "$*" = '-q get ax6000_mesh.main.backhaul_band' ] || exit 2
[ "${BAND_MISSING:-0}" != 1 ] || exit 1
printf '%s\\n' "${BAND_VALUE-auto}"
''')
        self.tool('datconf', '''#!/usr/bin/python3
import os,sys
from pathlib import Path
a=sys.argv[1:]; assert a[0]=='-f'; path=Path(a[1]); op=a[2]; key=a[3]
lines=path.read_text().splitlines()
if op=='set':
 if os.environ.get('FAIL_KEY')==key: sys.exit(1)
 lines=[line for line in lines if not line.startswith(key+'=')]; lines.append(key+'='+a[4]); path.write_text('\\n'.join(lines)+'\\n')
elif op=='get':
 for line in lines:
  if line.startswith(key+'='): print(line.split('=',1)[1]); break
 else: sys.exit(1)
else: sys.exit(2)
''')
        self.env={**os.environ, 'PATH': str(self.root/'bin')+':'+os.environ['PATH']}
        if HELPER.exists():
            source=HELPER.read_text().replace('/etc/map/mapd_cfg',str(self.cfg))
            self.script=self.root/'helper'; self.script.write_text(source)

    def tool(self,name,text):
        p=self.root/'bin'/name; p.write_text(text); p.chmod(0o755)

    def call(self, action, **env):
        self.assertTrue(HELPER.exists(), 'band helper is missing')
        return subprocess.run(['sh',str(self.script),action],env={**self.env,**env},capture_output=True,text=True,timeout=5)

    def test_band_modes_apply_exact_priorities_and_preserve_private_file(self):
        for mode, expected in [('auto',('3','1','1')),('5g',('0','1','1')),('2g',('1','0','0'))]:
            with self.subTest(mode=mode):
                result=self.call('apply',BAND_VALUE=mode); self.assertEqual(result.returncode,0,result.stderr)
                data=dict(line.split('=',1) for line in self.cfg.read_text().splitlines())
                self.assertEqual(tuple(data[k] for k in ('BhPriority2G','BhPriority5GL','BhPriority5GH')),expected)
                self.assertEqual(data['Other'],'preserve'); self.assertEqual(self.cfg.stat().st_mode & 0o777,0o600)

    def test_missing_uci_defaults_to_auto(self):
        self.assertEqual(self.call('apply',BAND_VALUE='5g').returncode,0)
        self.assertEqual(self.call('apply',BAND_MISSING='1').returncode,0)
        self.assertIn('BhPriority2G=3\n',self.cfg.read_text())

    def test_matching_auto_keeps_original_bytes_and_mtime(self):
        os.utime(self.cfg, ns=(946684800123456789,946684800123456789))
        before=self.cfg.stat()
        self.assertEqual(self.call('apply', BAND_VALUE='auto').returncode,0)
        after=self.cfg.stat()
        self.assertEqual(self.cfg.read_text(),self.original)
        self.assertEqual(after.st_mtime_ns,before.st_mtime_ns)
        self.assertEqual(after.st_ino,before.st_ino)

    def test_vendor_default_auto_keeps_actual_bytes(self):
        vendor=os.environ.get('AX6000_VENDOR_MAPD_DEFAULT')
        if not vendor: self.skipTest('Set AX6000_VENDOR_MAPD_DEFAULT to the pinned vendor template')
        self.cfg.write_bytes(Path(vendor).read_bytes())
        before=self.cfg.stat(); old=self.cfg.read_bytes()
        self.assertEqual(self.call('apply',BAND_MISSING='1').returncode,0)
        self.assertEqual(self.cfg.read_bytes(),old)
        self.assertEqual(self.cfg.stat().st_ino,before.st_ino)

    def test_invalid_policy_is_rejected_without_touching_vendor_config(self):
        for mode in ('bad', '', '5g;touch /tmp/unsafe', 'AUTO'):
            for action in ('validate','apply'):
                result=self.call(action,BAND_VALUE=mode); self.assertNotEqual(result.returncode,0)
                self.assertEqual(self.cfg.read_text(),self.original)
        self.assertFalse(list(self.root.glob('mapd_cfg.*')))

    def test_mid_write_failure_leaves_original_config_unchanged(self):
        result=self.call('apply',BAND_VALUE='5g',FAIL_KEY='BhPriority5GL')
        self.assertNotEqual(result.returncode,0); self.assertEqual(self.cfg.read_text(),self.original)
        self.assertFalse(list(self.root.glob('mapd_cfg.*')))

    def test_symlink_destination_is_rejected(self):
        target=self.root/'target'; self.cfg.rename(target); self.cfg.symlink_to(target)
        self.assertNotEqual(self.call('apply',BAND_VALUE='5g').returncode,0)
        self.assertEqual(target.read_text(),self.original)

    def test_success_preserves_owner_and_group(self):
        before=self.cfg.stat()
        self.assertEqual(self.call('apply',BAND_VALUE='5g').returncode,0)
        after=self.cfg.stat(); self.assertEqual((after.st_uid,after.st_gid),(before.st_uid,before.st_gid))

    def test_readback_failure_leaves_original_config_unchanged(self):
        datconf=self.root/'bin/datconf'
        datconf.write_text(datconf.read_text().replace("if op=='set':", "if op=='set' and key=='BhPriority5GL': sys.exit(0)\nif op=='set':"))
        result=self.call('apply',BAND_VALUE='2g')
        self.assertNotEqual(result.returncode,0); self.assertEqual(self.cfg.read_text(),self.original)
        self.assertFalse(list(self.root.glob('mapd_cfg.*')))
