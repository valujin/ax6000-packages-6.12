"""Exercise the pinned vendor UI country option with real source and mocked LuCI."""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/vendor-country'
SPEC = importlib.util.spec_from_file_location('vendor_country', ROOT / 'scripts/vendor_country.py')
MODULE = None
if SPEC.origin and Path(SPEC.origin).exists():
    MODULE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(MODULE)


class VendorCountryTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(MODULE, 'vendor country helper is required')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.provenance = json.loads((FIXTURES / 'provenance.json').read_text())

    def fixture(self, series, prefix=''):
        for name, data in self.provenance[series]['files'].items():
            raw = gzip.decompress((FIXTURES / f'{series}-{name}.gz').read_bytes())
            self.assertEqual(hashlib.sha256(raw).hexdigest(), data['sha256'])
            path = self.root / prefix / data['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        return self.root / prefix / self.provenance[series]['files']['wireless-mtk.js']['path']

    def test_both_native_preimages_and_repeat_are_exact(self):
        for series in ('66', '612'):
            with self.subTest(series=series):
                source = self.root / series
                source.mkdir()
                previous = self.root
                self.root = source
                js = self.fixture(series)
                report = MODULE.apply_vendor_country_patch(source)
                first = js.read_bytes()
                makefile = js.parents[4] / 'Makefile'
                self.assertEqual(report['series'], series)
                self.assertTrue(report['changed'])
                expected_release = '2.ax6000db1' if series == '66' else '2'
                self.assertEqual(report['release'], expected_release)
                self.assertIn(f'PKG_RELEASE:={expected_release}\n'.encode(), makefile.read_bytes())
                again = MODULE.apply_vendor_country_patch(source)
                self.assertFalse(again['changed'])
                self.assertEqual(first, js.read_bytes())
                self.root = previous

    def test_sdk_path_and_alias_are_supported(self):
        js = self.fixture('612', 'feeds/base_root')
        alias = self.root / 'feeds/base'
        alias.symlink_to(self.root / 'feeds/base_root/package', target_is_directory=True)
        report = MODULE.apply_vendor_country_patch(self.root)
        self.assertTrue(report['changed'])
        self.assertIn('MediaTek debug domain', js.read_text())

    def test_ambiguous_recipes_and_changed_preimage_fail_without_writes(self):
        js = self.fixture('66')
        original = js.read_bytes()
        self.fixture('612', 'feeds/base_root')
        with self.assertRaisesRegex(ValueError, 'one|ambiguous'):
            MODULE.apply_vendor_country_patch(self.root)
        self.assertEqual(js.read_bytes(), original)
        shutil.rmtree(self.root / 'feeds')
        makefile = js.parents[4] / 'Makefile'
        before = makefile.read_bytes()
        js.write_bytes(original + b'\n// unreviewed edit\n')
        with self.assertRaisesRegex(ValueError, 'preimage|reviewed'):
            MODULE.apply_vendor_country_patch(self.root)
        self.assertEqual(makefile.read_bytes(), before)
        js.write_bytes(original)
        makefile.write_bytes(before + b'\n# unreviewed edit\n')
        with self.assertRaisesRegex(ValueError, 'preimage|reviewed'):
            MODULE.apply_vendor_country_patch(self.root)
        self.assertEqual(js.read_bytes(), original)

    def test_escape_and_partial_patch_fail_closed(self):
        outside = self.root / 'outside'
        outside.mkdir()
        previous = self.root
        self.root = outside
        js = self.fixture('66')
        self.root = previous / 'source'
        self.root.mkdir()
        alias = self.root / 'package/mtk/applications/luci-app-mtwifi-cfg'
        alias.parent.mkdir(parents=True)
        alias.symlink_to(js.parents[4], target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'escape|outside'):
            MODULE.apply_vendor_country_patch(self.root)
        self.root = outside
        original = js.read_bytes()
        MODULE.apply_vendor_country_patch(self.root)
        js.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'partial|mixed|preimage|reviewed'):
            MODULE.apply_vendor_country_patch(self.root)

    @unittest.skipUnless(os.environ.get('AX6000_APK') or os.environ.get('AX6000_HOST_APK'),
                         'Explicit independently trusted host APK required')
    def test_612_release_is_accepted_by_actual_apk_and_upgrades_old_package(self):
        tool = os.environ.get('AX6000_APK') or os.environ['AX6000_HOST_APK']
        js = self.fixture('612')
        report = MODULE.apply_vendor_country_patch(self.root)
        version = '1-r' + report['release']
        accepted = subprocess.run([tool, 'version', '--check', version], text=True, capture_output=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        comparison = subprocess.check_output([tool, 'version', '-t', '1-r1', version], text=True).strip()
        self.assertEqual(comparison, '<')
        self.assertIn(b'PKG_RELEASE:=2\n', (js.parents[4] / 'Makefile').read_bytes())

    def test_actual_javascript_country_behavior_for_both_sources(self):
        self.assertIsNotNone(shutil.which('node'), 'Node is required for meaningful UI behavior tests')
        for series in ('66', '612'):
            with self.subTest(series=series):
                source = self.root / series
                source.mkdir()
                previous = self.root
                self.root = source
                js = self.fixture(series)
                MODULE.apply_vendor_country_patch(source)
                result = subprocess.run(['node', str(ROOT / 'tests/vendor-country-behavior.cjs'), str(js)],
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('country behavior passed', result.stdout)
                self.root = previous


if __name__ == '__main__':
    unittest.main()
