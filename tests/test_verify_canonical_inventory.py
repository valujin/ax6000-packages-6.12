"""Exercise the actual selection and SDK baseline blocks without native builds."""
import ast
import copy
from pathlib import Path
import tempfile
import unittest

from test_verify_firmware import ROOT, verify


def verifier_tree():
    return ast.parse((ROOT / 'scripts/verify-firmware.py').read_text())


def selection_views(controls, paths, names, manager='apk', firmware=None):
    main = next(node for node in verifier_tree().body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    index = next(i for i, node in enumerate(main.body) if isinstance(node, ast.Expr)
                 and isinstance(node.value, ast.Call) and any(isinstance(arg, ast.Constant)
                 and arg.value == 'Exported selection firmware/built package inventory differs' for arg in node.value.args))
    start = index
    if index >= 2 and isinstance(main.body[index - 2], ast.Assign):
        target = main.body[index - 2].targets[0]
        if isinstance(target, ast.Tuple) and any(isinstance(item, ast.Name) and item.id == 'canonical_controls' for item in target.elts):
            start = index - 2
    actual_firmware = {'kernel_version': 'fixture-ABI'}
    scope = {'controls': controls, 'ipks': paths, 'manager': manager, 'firmware': actual_firmware,
             'selection': {'firmware': actual_firmware if firmware is None else firmware, 'built_packages': names},
             'require': verify.require}
    exec(compile(ast.fix_missing_locations(ast.Module(body=main.body[start:index + 1], type_ignores=[])),
                 'actual-selection-inventory', 'exec'), scope)
    return scope.get('canonical_controls', controls), scope.get('canonical_ipks', paths)


def baseline_guard(controls, paths, record, baseline_packages):
    sdk = next(node for node in verifier_tree().body if isinstance(node, ast.FunctionDef) and node.name == 'inspect_sdk')
    nodes = [node for node in ast.walk(sdk) if isinstance(node, ast.If)
             and any(isinstance(child, ast.Constant) and child.value == 'APK SDK/native baseline package identity differs'
                     for child in ast.walk(node))]
    # The innermost actual native_controls guard checks Version and whole archive bytes.
    guard = min(nodes, key=lambda node: len(list(ast.walk(node))))
    scope = {'native_controls': controls, 'native_packages': paths, 'name': record['package'],
             'record': record, 'path': record['path'], 'baseline_packages': baseline_packages,
             'require': verify.require, 'sha256': verify.sha256}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[guard], type_ignores=[])),
                 'actual-sdk-baseline-guard', 'exec'), scope)


class CanonicalNativeInventory(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def bank(self, *specs):
        controls, paths = {}, {}
        for name, suffix in specs:
            info = {'name': name, 'version': '1-r0', 'arch': 'aarch64_cortex-a53'}
            if suffix:
                info['tags'] = ['openwrt:abiversion=' + suffix]
            controls[name] = verify.package_format.normalize_apk_info(info)
            paths[name] = self.root / (name + '.apk')
            paths[name].write_bytes(('actual archive fixture ' + name).encode())
        return controls, paths

    def test_tagged_abi_and_untagged_numeric_names_map_without_mutating_actual_controls(self):
        controls, paths = self.bank(('libexample2026', '2026'), ('libgcc1', None), ('libstdcpp6', None))
        original = copy.deepcopy(controls)
        canonical, archives = selection_views(controls, paths, ['libexample', 'libgcc1', 'libstdcpp6'])
        self.assertEqual(set(canonical), {'libexample', 'libgcc1', 'libstdcpp6'})
        self.assertIs(canonical['libexample'], controls['libexample2026'])
        self.assertEqual(archives['libexample'], paths['libexample2026'])
        self.assertEqual(canonical['libexample']['Package'], 'libexample2026')
        self.assertEqual(controls, original)

    def test_colliding_or_missing_canonical_identity_is_rejected(self):
        controls, paths = self.bank(('libexample2026', '2026'), ('libexample', None))
        with self.assertRaises(ValueError):
            selection_views(controls, paths, ['libexample', 'libexample'])
        controls, paths = self.bank(('libexample2026', '2026'))
        controls['libexample2026'].pop('Base-Package')
        with self.assertRaises(ValueError):
            selection_views(controls, paths, ['libexample'])

    def test_missing_extra_duplicate_or_foreign_firmware_selection_is_rejected(self):
        controls, paths = self.bank(('libexample2026', '2026'), ('libgcc1', None))
        for names in (['libexample'], ['libexample', 'libgcc1', 'extra'],
                      ['libexample', 'libexample'], ['libexample', 'extra']):
            with self.subTest(names=names):
                with self.assertRaises(ValueError):
                    selection_views(controls, paths, names)
        with self.assertRaises(ValueError):
            selection_views(controls, paths, ['libexample', 'libgcc1'], firmware={'kernel_version': 'foreign'})

    def test_opkg_views_and_legacy_set_comparison_semantics_are_unchanged(self):
        controls = {'libgcc1': {'Package': 'libgcc1', 'Version': '1-r0'}}
        paths = {'libgcc1': self.root / 'libgcc1.ipk'}
        canonical, archives = selection_views(controls, paths, ['libgcc1', 'libgcc1'], 'opkg')
        self.assertIs(canonical, controls)
        self.assertIs(archives, paths)

    def test_canonical_sdk_baseline_view_preserves_exact_version_archive_sha_and_size(self):
        controls, paths = self.bank(('libexample2026', '2026'))
        canonical, archives = selection_views(controls, paths, ['libexample'])
        path = paths['libexample2026']
        record = {'package': 'libexample', 'version': '1-r0', 'path': 'apks/libexample.apk', 'sha256': verify.sha256(path)}
        packages = {record['path']: {'sha256': record['sha256'], 'size': path.stat().st_size}}
        baseline_guard(canonical, archives, record, packages)
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            baseline_guard(controls, paths, record, packages)
        for changed_record, changed_packages in (
                ({**record, 'version': 'foreign'}, packages),
                ({**record, 'sha256': 'f' * 64}, packages),
                (record, {record['path']: {'sha256': record['sha256'], 'size': 1}})):
            with self.assertRaises(ValueError):
                baseline_guard(canonical, archives, changed_record, changed_packages)
        main = next(node for node in verifier_tree().body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        call = next(node for node in ast.walk(main) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == 'inspect_sdk')
        arguments = {item.arg: item.value.id for item in call.keywords if isinstance(item.value, ast.Name)}
        self.assertEqual(arguments['native_controls'], 'canonical_controls')
        self.assertEqual(arguments['native_packages'], 'canonical_ipks')


if __name__ == '__main__':
    unittest.main()
