"""Exercise the actual patched Makefile targets, without a firmware rebuild."""
import gzip
from pathlib import Path
import re
import shutil
import subprocess
import unittest
import test_imagebuilder as fixtures

ib = fixtures.ib


class FrozenKeyLifecycleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.usign = fixtures.MatchingBuilderTest.usign if hasattr(fixtures.MatchingBuilderTest, 'usign') else None
        if cls.usign is None:
            import os
            cls.usign = os.environ.get('USIGN') or shutil.which('usign')
        if not cls.usign:
            raise unittest.SkipTest('Real USIGN required for immutable IB key lifecycle')

    def setUp(self):
        base = fixtures.MatchingBuilderTest()
        base.usign = self.usign
        base.setUp()
        self.addCleanup(base.doCleanups)
        base.export()
        self.tree = base.extract()
        self.source = base.source
        self.base = base
        host = self.tree / 'staging_dir/host/bin'
        host.mkdir(parents=True, exist_ok=True)
        (host / 'usign').symlink_to(self.usign)
        self.target = self.tree / 'target'
        keys = self.target / 'etc/opkg/keys'
        keys.mkdir(parents=True)
        for key in (self.tree / 'keys').iterdir():
            shutil.copy2(key, keys / key.name)
        self.before_keys = {p.name: p.read_bytes() for p in keys.iterdir()}

    def makefile(self, frozen):
        check = re.search(r'\n_check_keys: FORCE\n.*?(?=\nimage:\n)', frozen, re.S).group(0)
        rootfs = re.search(r'\nprepare_rootfs: FORCE\n.*?(?=\nbuild_image: FORCE\n)', frozen, re.S).group(0)
        output = self.tree / 'lifecycle.mk'
        output.write_text(ib.FROZEN_KEY_POLICY + '\n' + '\n'.join([
            'TOPDIR := ' + str(self.tree), 'STAGING_DIR_HOST := $(TOPDIR)/staging_dir/host',
            'PACKAGE_DIR := $(TOPDIR)/packages', 'OPKG_KEYS := $(TOPDIR)/keys', 'APK_KEYS := $(TOPDIR)/keys',
            'BUILD_KEY := $(TOPDIR)/key-build', 'BUILD_KEY_APK_SEC := $(TOPDIR)/keys/local-private-key.pem',
            'TARGET_DIR := $(TOPDIR)/target', 'TARGET_DIR_ORIG := $(TOPDIR)/target.orig',
            'CP := cp -a', 'prepare_rootfs = true', 'FORCE:', check, rootfs]))
        return output

    def run_make(self, makefile, *targets):
        return subprocess.run(['make', '--no-print-directory', '-f', str(makefile), *targets], capture_output=True, text=True)

    def test_actual_source_key_and_rootfs_targets_validate_without_generating_or_injecting(self):
        source_fixtures = sorted((Path(__file__).parent / 'fixtures').glob('imagebuilder-*-Makefile.gz'))
        self.assertTrue(source_fixtures)
        for fixture in source_fixtures:
            with self.subTest(fixture=fixture.name):
                frozen = ib.freeze_makefile(gzip.decompress(fixture.read_bytes()).decode())
                self.assertNotIn('Generate local signing keys', frozen)
                self.assertNotIn('$(SCRIPT_DIR)/opkg-key add', frozen)
                self.assertNotIn('cp $(BUILD_KEY_APK_PUB)', frozen)
                for generated in ('key-build', 'key-build.pub', 'key-build.ucert', 'private-key.pem'):
                    self.assertFalse((self.tree / generated).exists())
                makefile = self.makefile(frozen)
                result = self.run_make(makefile, '_check_keys', 'prepare_rootfs')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual({p.name: p.read_bytes() for p in (self.target / 'etc/opkg/keys').iterdir()}, self.before_keys)
                self.assertEqual({p.name: p.read_bytes() for p in (self.tree / 'target.orig/etc/opkg/keys').iterdir()}, self.before_keys)
                shutil.rmtree(self.tree / 'target.orig')
                for generated in ('key-build', 'key-build.pub', 'key-build.ucert', 'private-key.pem'):
                    self.assertFalse((self.tree / generated).exists())
                for value in ('1', '0'):
                    result = self.run_make(makefile, '_check_keys', 'ADD_LOCAL_KEY=' + value)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('ADD_LOCAL_KEY is forbidden', result.stderr)

    def test_verifier_rejects_restoring_native_ephemeral_key_generation(self):
        path = self.tree / 'Makefile'
        original = gzip.decompress((Path(__file__).parent / 'fixtures/imagebuilder-opkg-ec9ef10-Makefile.gz').read_bytes()).decode()
        unsafe = re.search(r'\n_check_keys: FORCE\n.*?\nimage:\n', original, re.S).group(0)
        path.write_text(path.read_text().replace(ib.FROZEN_KEY_TARGET, unsafe))
        with self.assertRaisesRegex(ValueError, 'ephemeral signing keys'):
            ib.verify_tree(self.tree, self.base.profile, self.base.public, self.usign)

    def test_missing_index_signature_and_introduced_private_keys_are_rejected(self):
        makefile = self.makefile((self.tree / 'Makefile').read_text())
        signature = self.tree / 'packages/Packages.sig'
        before = signature.read_bytes()
        signature.unlink()
        self.assertNotEqual(self.run_make(makefile, '_check_keys').returncode, 0)
        signature.write_bytes(before)
        for forbidden in ('key-build', 'key-build.ucert', 'private-key.pem', 'keys/local-private-key.pem'):
            path = self.tree / forbidden
            path.write_bytes(b'forbidden private key or certificate fixture')
            result = self.run_make(makefile, '_check_keys')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Private signing keys or local certificates are forbidden', result.stderr)
            path.unlink()


if __name__ == '__main__':
    unittest.main()
