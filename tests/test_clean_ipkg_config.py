"""Run the real verifier block against canonical and adversarial Kconfig states."""
import ast
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def check(config, manager):
    # Execute the exact production assignment/loop, not a mirrored predicate.
    tree = ast.parse((ROOT / 'scripts/verify-firmware.py').read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    index = next(i for i, node in enumerate(main.body) if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == 'disabled' for target in node.targets))
    block = ast.Module(body=main.body[index:index + 2], type_ignores=[])
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    exec(compile(ast.fix_missing_locations(block), 'actual-native-disabled-config', 'exec'),
         {'config': config, 'manager': manager, 'require': require, 're': re})


class CleanIpkgConfigTests(unittest.TestCase):
    apk = b'# CONFIG_PACKAGE_opkg is not set\n# CONFIG_PACKAGE_apk-mbedtls is not set\n'

    def test_apk_accepts_canonical_absence_or_one_exact_disabled_comment(self):
        check(self.apk, 'apk')
        check(self.apk + b'# CONFIG_CLEAN_IPKG is not set\n', 'apk')
        check(self.apk + b'CONFIG_CLEAN_IPKG_EXTRA=y\n', 'apk')

    def test_apk_rejects_every_assignment_conflict_malformed_or_duplicate_declaration(self):
        for line in (b'CONFIG_CLEAN_IPKG=y', b'CONFIG_CLEAN_IPKG=m', b'CONFIG_CLEAN_IPKG=n',
                     b' CONFIG_CLEAN_IPKG = n', b'\tCONFIG_CLEAN_IPKG=""',
                     b'#CONFIG_CLEAN_IPKG is not set', b'# CONFIG_CLEAN_IPKG=no',
                     b'# CONFIG_CLEAN_IPKG is not set\n# CONFIG_CLEAN_IPKG is not set'):
            for prefix in (b'', b'# CONFIG_CLEAN_IPKG is not set\n'):
                with self.subTest(line=line, prefix=prefix):
                    with self.assertRaisesRegex(ValueError, 'CLEAN_IPKG'):
                        check(self.apk + prefix + line + b'\n', 'apk')

    def test_other_apk_disabled_symbols_and_original_opkg_requirement_remain_strict(self):
        for symbol in ('PACKAGE_opkg', 'PACKAGE_apk-mbedtls'):
            with self.subTest(symbol=symbol):
                with self.assertRaisesRegex(ValueError, symbol):
                    check(self.apk.replace(('# CONFIG_' + symbol + ' is not set\n').encode(), b''), 'apk')
        opkg = b'# CONFIG_USE_APK is not set\n# CONFIG_CLEAN_IPKG is not set\n'
        check(opkg, 'opkg')
        for symbol in ('USE_APK', 'CLEAN_IPKG'):
            with self.subTest(symbol=symbol):
                with self.assertRaisesRegex(ValueError, symbol):
                    check(opkg.replace(('# CONFIG_' + symbol + ' is not set\n').encode(), b''), 'opkg')

    @unittest.skipUnless(shutil.which('cc'), 'native C compiler required')
    def test_actual_pinned_kconfig_omits_invisible_clean_ipkg_for_apk(self):
        native = gzip.decompress((ROOT / 'tests/fixtures/ax6000-612-config-build.gz').read_bytes())
        self.assertEqual(hashlib.sha256(native).hexdigest(), '416b1d08b4df87cfffa284b77e38091ace388432bba7616d815a524a0451e505')
        start = native.index(b'\tconfig CLEAN_IPKG\n')
        end = native.index(b'\tconfig IPK_FILES_CHECKSUMS\n', start)
        block = native[start:end]
        self.assertIn(b'depends on !USE_APK', block)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            with tarfile.open(ROOT / 'tests/fixtures/openwrt-kconfig-tools-ae65e1d.tar.gz') as archive:
                manifest = json.load(archive.extractfile('fixture-manifest.json'))
                self.assertEqual(manifest['source_commit'], 'ae65e1de69971b5a2e3cf7e39390ee93f274d488')
                for name, sha in manifest['files'].items():
                    data = archive.extractfile(name).read()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), sha)
                    path = work / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
            tools = work / 'scripts/config'
            conf = work / 'conf'
            subprocess.run(['cc', '-O0', '-I', str(tools), '-o', str(conf)] + [str(tools / name) for name in
                ('conf.c', 'confdata.c', 'expr.c', 'lexer.lex.c', 'menu.c', 'parser.tab.c', 'preprocess.c', 'symbol.c', 'util.c')],
                check=True, capture_output=True, timeout=30)
            (work / 'Kconfig').write_bytes(b'mainmenu "Native CLEAN_IPKG visibility"\nconfig USE_APK\n\tbool "APK"\n' + block)
            path = work / '.config'
            for apk in (True, False):
                path.write_bytes(b'CONFIG_USE_APK=y\n# CONFIG_CLEAN_IPKG is not set\n' if apk else
                                 b'# CONFIG_USE_APK is not set\n# CONFIG_CLEAN_IPKG is not set\n')
                subprocess.run([str(conf), '--olddefconfig', 'Kconfig'], cwd=work,
                    env={**os.environ, 'KCONFIG_CONFIG': str(path)}, check=True, capture_output=True, timeout=5)
                canonical = path.read_bytes()
                if apk:
                    self.assertNotIn(b'CONFIG_CLEAN_IPKG', canonical)
                    check(self.apk + canonical, 'apk')
                else:
                    self.assertIn(b'# CONFIG_CLEAN_IPKG is not set\n', canonical)
                    check(canonical, 'opkg')


if __name__ == '__main__':
    unittest.main()
