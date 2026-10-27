"""Exercise the SDK's actual source-backed frozen-module inventory gate."""
import ast
from pathlib import Path
import tempfile
import unittest

from test_verify_firmware import ROOT, verify


def check_inventory(source, requested, frozen, native):
    tree = ast.parse((ROOT / 'scripts/verify-firmware.py').read_text())
    sdk = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'inspect_sdk')
    guards = [node for node in ast.walk(sdk) if isinstance(node, ast.If)
              and any(isinstance(child, ast.Constant) and isinstance(child.value, str)
                      and 'APK SDK omits a native frozen kernel module' in child.value
                      for child in ast.walk(node))]
    guard = min(guards, key=lambda node: len(list(ast.walk(node))))
    scope = dict(vars(verify), source=source, profile={'packages': requested},
                 baseline={'frozen_kmods': frozen}, native_controls={name: {} for name in native})
    exec(compile(ast.fix_missing_locations(ast.Module(body=[guard], type_ignores=[])),
                 'actual-sdk-frozen-kmod-gate', 'exec'), scope)


class SdkFrozenModules(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name)
        (self.source / 'tmp').mkdir()
        (self.source / 'tmp/.packageinfo').write_text(
            'Source-Makefile: package/mtk/drivers/mt_wifi/Makefile\nPackage: kmod-mt_wifi\n'
            'Source-Makefile: package/ax6000-overrides/mapfilter/Makefile\nPackage: kmod-mapfilter\n'
            'Source-Makefile: package/feeds/amneziawg/amneziawg/Makefile\nPackage: kmod-amneziawg\n')
        self.native = ['kmod-mt_wifi', 'kmod-mapfilter', 'kmod-amneziawg']

    def test_native_local_override_is_frozen_and_requested_feed_module_is_refreshed(self):
        check_inventory(self.source, ['kmod-mapfilter', 'kmod-amneziawg'],
                        ['kmod-mt_wifi', 'kmod-mapfilter'], self.native)

    def test_missing_native_override_cannot_pass_as_a_refreshed_module(self):
        with self.assertRaisesRegex(ValueError, r"missing=\['kmod-mapfilter'\], extra=\[\]"):
            check_inventory(self.source, ['kmod-mapfilter', 'kmod-amneziawg'], ['kmod-mt_wifi'], self.native)

    def test_feed_module_cannot_be_frozen_when_requested_for_refresh(self):
        with self.assertRaisesRegex(ValueError, 'native frozen kernel module'):
            check_inventory(self.source, ['kmod-amneziawg'], self.native, self.native)

    def test_unrequested_feed_module_is_retained_and_foreign_module_is_rejected(self):
        check_inventory(self.source, [], self.native, self.native)
        with self.assertRaisesRegex(ValueError, r"missing=\[\], extra=\['kmod-foreign'\]"):
            check_inventory(self.source, [], self.native + ['kmod-foreign'], self.native)


if __name__ == '__main__':
    unittest.main()
