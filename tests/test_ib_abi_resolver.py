"""Mixed native/public ABIs resolve only from explicit reviewed actual names."""
import importlib.util
import gzip
import re
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from test_package_format import make_apk
import imagebuilder

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/ax6000-ib-abi.py'
SPEC = importlib.util.spec_from_file_location('ib_abi_resolver', SCRIPT)
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)


class ActualResolverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.apk = os.environ.get('APK')
        if not cls.apk:
            raise unittest.SkipTest('Set APK to trusted host apk-tools 3.0.5')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        keys = self.root / 'keys'
        keys.mkdir()
        secret = self.root / 'private.pem'
        subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(secret)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(secret), '-pubout', '-out', str(keys / 'public.pem')], check=True, capture_output=True)
        indexes = []
        for cohort, abi in [('native', '2025'), ('public', '2026')]:
            directory = self.root / cohort
            directory.mkdir()
            package = make_apk(self.apk, directory, 'libfixture' + abi, provides=['libfixture'], tags=['openwrt:abiversion=' + abi])
            index = directory / 'packages.adb'
            subprocess.run([self.apk, '--no-network', 'mkndx', '--allow-untrusted', '--sign', str(secret), '--output', str(index), str(package)], check=True, capture_output=True)
            indexes.append(index)
        repositories = self.root / 'repositories'
        repositories.write_text(str(indexes[0]) + '\n@public ' + str(indexes[1]) + '\n')
        installed = self.root / 'installed'
        installed.mkdir()
        self.command = [self.apk, '--no-network', '--root', str(installed), '--repositories-file', str(repositories),
            '--keys-dir', str(keys), '--arch', 'aarch64_cortex-a53']
        subprocess.run(self.command + ['--usermode', '--no-scripts', '--no-commit-hooks', 'add', '--initdb'], check=True, capture_output=True)
        subprocess.run(self.command + ['update'], check=True, capture_output=True)

    def test_actual_catalog_spec_selects_public_abi_and_unqualified_base_fails(self):
        self.assertEqual(resolver.resolve(self.command, 'libfixture2026', 'public', '1-r1'), '2026')
        self.assertEqual(resolver.resolve(self.command, 'libfixture2025', '', '1-r1'), '2025')
        for tag in ['', 'public']:
            with self.assertRaisesRegex(ValueError, 'ambiguous ABI'):
                resolver.resolve(self.command, 'libfixture', tag, '1-r1')
        with self.assertRaises(ValueError):
            resolver.resolve(self.command, 'libfixture2026', 'public', '9-r9')

    def test_actual_gnu_make_uses_trusted_resolver_without_double_abi(self):
        fixture = self.root / 'format.mk'
        native = gzip.decompress((Path(__file__).parent / 'fixtures/imagebuilder-apk-ae65e1de-Makefile.gz').read_bytes()).decode()
        transformed = imagebuilder.freeze_makefile(native, 'apk')
        query = re.search(r'define GetABISuffix\n.*?\nendef', transformed, re.S).group(0) + '\n'
        query = ('TOPDIR := ' + str(SCRIPT.parents[1]) + '\nSTAGING_DIR_HOST := /usr\nAPK := ' + shlex.join(self.command) + '\n') + query
        fixture.write_text(query + imagebuilder.APK_FORMAT_PACKAGES + '\nall:\n\t@echo $(call FormatPackages,libfixture2026@public=1-r1 libfixture2025=1-r1)\n')
        actual = subprocess.check_output(['make', '--no-print-directory', '-f', str(fixture)], text=True).strip()
        self.assertEqual(actual, 'libfixture2026@public=1-r1 libfixture2025=1-r1')
        fixture.write_text(query + imagebuilder.APK_FORMAT_PACKAGES + '\nall:\n\t@echo $(call FormatPackages,libfixture@public=1-r1)\n')
        failed = subprocess.run(['make', '--no-print-directory', '-f', str(fixture)], capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('APK ABI resolution failed', failed.stderr)


if __name__ == '__main__':
    unittest.main()
