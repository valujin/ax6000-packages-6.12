"""Real APKv3 host tools validate frozen native bank and tagged selection."""
import gzip
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import unittest
import test_imagebuilder as original_tests
ib = original_tests.ib
from test_package_format import make_apk

FIXTURES = Path(__file__).resolve().parent / 'fixtures'


class ApkImageBuilderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.apk, cls.usign = os.environ.get('APK'), os.environ.get('USIGN')
        if not cls.apk or not cls.usign:
            raise unittest.SkipTest('Real pinned APK and USIGN host tools required')

    def setUp(self):
        base = original_tests.MatchingBuilderTest()
        base.usign = self.usign
        base.setUp()
        self.addCleanup(base.doCleanups)
        for key in ('root', 'source', 'profile', 'tree', 'archive', 'public'):
            setattr(self, key, getattr(base, key))
        self.profile.update(id='redmi-ax6000-612-recommended', channel='recommended', package_manager='apk')
        self.profile['firmware']['kernel_version'] = '6.12.108~' + 'b' * 32 + '-r1'
        old = next((self.source / 'build_dir').glob('target-*/linux-*/linux-*'))
        kernel = old.with_name('linux-6.12.108')
        old.rename(kernel)
        (kernel / 'include/config/kernel.release').write_text('6.12.108\n')
        shutil.rmtree(self.tree / 'build_dir')
        shutil.rmtree(self.source / 'bin/packages')
        shutil.rmtree(self.tree / 'packages')
        native_packages = self.source / 'bin/packages'
        native_packages.mkdir()
        for name in ('kernel', 'libc', 'base-files', 'busybox', 'apk-openssl', 'kmod-test'):
            work = self.root / ('mk-' + name)
            work.mkdir()
            version = self.profile['firmware']['kernel_version'] if name == 'kernel' else '1-r1'
            depends = ['kernel=' + self.profile['firmware']['kernel_version']] if name == 'kmod-test' else []
            package = make_apk(self.apk, work, name, version=version, depends=depends)
            shutil.copy2(package, native_packages / package.name)
        shutil.copytree(native_packages, self.tree / 'packages')
        self.native = self.source / 'private-key.pem'
        self.native_public = self.source / 'public-key.pem'
        self.public_apk = self.root / 'production-apk.pem'
        for secret, public in ((self.native, self.native_public), (self.root / 'production-apk-private.pem', self.public_apk)):
            subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(secret)], check=True, capture_output=True)
            subprocess.run(['openssl', 'pkey', '-in', str(secret), '-pubout', '-out', str(public)], check=True, capture_output=True)
        host = self.tree / 'staging_dir/host/bin'
        host.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.apk, host / 'apk')
        native_host = self.source / 'staging_dir/host/bin'
        native_host.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.apk, native_host / 'apk')
        (self.source / 'scripts').mkdir(exist_ok=True)
        (self.source / 'scripts/bundle-libraries.sh').write_bytes(gzip.decompress((FIXTURES / 'host-bundler-ae65e1de.sh.gz').read_bytes()))
        self.profile['apk_key_sha256'] = ib.sha256(self.public_apk)
        makefile = gzip.decompress((FIXTURES / 'imagebuilder-apk-ae65e1de-Makefile.gz').read_bytes())
        (self.tree / 'Makefile').write_bytes(makefile)
        (self.source / 'target/imagebuilder/files/Makefile').write_bytes(makefile)
        (self.tree / '.config').write_text((self.tree / '.config').read_text() + 'CONFIG_USE_APK=y\nCONFIG_SIGNATURE_CHECK=y\n')
        (self.tree / 'repositories.conf').unlink()
        (self.source / 'ax6000-apk-world-policy.json').write_text('{"fixture":true}\n')
        for path, content in [(self.source / 'scripts/ax6000-apk-world.py', b'fixture policy script'),
                              (self.source / 'include/rootfs.mk', b'fixture patched rootfs')]:
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)
        for entry in ib.native_context(self.source, self.profile['firmware']['kernel_version']):
            if entry['path'].startswith('tmp/'):
                continue
            target = self.tree / entry['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.source / entry['path'], target)
        self.repack()

    def repack(self):
        import tarfile
        with tarfile.open(self.archive, 'w:gz') as tar:
            tar.add(self.tree, arcname=self.tree.name)

    def export(self):
        return ib.export_archive(self.profile, self.source, self.archive, self.public, self.native, self.usign,
            native_public_key=self.native_public, apk=self.apk, public_apk_key=self.public_apk)

    def test_actual_signed_adb_export_and_native_context(self):
        result = self.export()
        self.assertEqual(result['packages'], 6)
        self.assertEqual(result['identity']['package_manager'], 'apk')
        tree = ib.safe_extract(self.archive, self.root / 'exported')
        self.assertEqual((tree / 'repositories').read_text(), ib.APK_REPOSITORIES)
        self.assertFalse((tree / 'repositories.conf').exists())
        self.assertFalse((tree / 'keys/local-private-key.pem').exists())
        ib.verify_tree(tree, self.profile, self.public, self.usign, self.source,
            list((self.source / 'bin').rglob('*.apk')), apk=self.apk, public_apk_key=self.public_apk)

    def test_actual_portable_sstrip_bundle_and_library_tampering(self):
        portable = os.environ.get('IB_APK_BUNDLE')
        stripper = os.environ.get('SSTRIP')
        if not portable or not stripper:
            self.skipTest('Set IB_APK_BUNDLE and SSTRIP to retained real native bundle evidence')
        shutil.rmtree(self.tree / 'staging_dir/host')
        shutil.copytree(Path(portable) / 'staging_dir/host', self.tree / 'staging_dir/host', symlinks=True)
        shutil.copy2(stripper, self.source / 'staging_dir/host/bin/sstrip')
        self.repack()
        self.export()
        tree = ib.safe_extract(self.archive, self.root / 'exported')
        metadata = json.loads((tree / 'ax6000-imagebuilder.json').read_text())
        self.assertEqual(metadata['host_apk']['kind'], 'openwrt-bundle-v1')
        self.assertEqual(metadata['host_apk']['source_transform']['name'], 'sstrip')
        self.assertNotEqual(metadata['host_apk']['sha256'], metadata['native_host_apk_sha256'])
        portable_apk = ib.host_apk_bundle.verify(tree, metadata['host_apk'])
        self.assertIn('apk-tools 3.0.5', subprocess.check_output([str(portable_apk), '--version'], text=True))
        library = tree / metadata['host_apk']['loader']
        library.write_bytes(library.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'member hash, size, mode or link differs'):
            ib.verify_tree(tree, self.profile, self.public, self.usign, apk=self.apk, public_apk_key=self.public_apk)

    def test_actual_apk_key_target_only_verifies_existing_native_bank(self):
        self.export()
        tree = ib.safe_extract(self.archive, self.root / 'key-target')
        frozen = (tree / 'Makefile').read_text()
        check = re.search(r'\n_check_keys: FORCE\n.*?(?=\nimage:\n)', frozen, re.S).group(0)
        makefile = tree / 'keys-test.mk'
        makefile.write_text(ib.FROZEN_KEY_POLICY + '\n' + '\n'.join([
            'TOPDIR := ' + str(tree), 'STAGING_DIR_HOST := $(TOPDIR)/staging_dir/host',
            'PACKAGE_DIR := $(TOPDIR)/packages', 'APK_KEYS := $(TOPDIR)/keys', 'CONFIG_USE_APK := y',
            'BUILD_KEY := $(TOPDIR)/key-build', 'BUILD_KEY_APK_SEC := $(TOPDIR)/keys/local-private-key.pem',
            'FORCE:', check]))
        command = ['make', '--no-print-directory', '-f', str(makefile), '_check_keys']
        before = {x.name: x.read_bytes() for x in (tree / 'keys').iterdir()}
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual({x.name: x.read_bytes() for x in (tree / 'keys').iterdir()}, before)
        for name in ('private-key.pem', 'key-build', 'key-build.pub', 'key-build.ucert', 'keys/local-private-key.pem', 'keys/local-public-key.pem'):
            self.assertFalse((tree / name).exists())
        result = subprocess.run(command + ['ADD_LOCAL_KEY=1'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ADD_LOCAL_KEY is forbidden', result.stderr)
        native_key = tree / 'keys/ax6000-native.pem'
        native_key.unlink()
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_apk_optin_requires_explicit_tool_key_and_native_fullbank(self):
        with self.assertRaisesRegex(ValueError, 'host apk'):
            ib.export_archive(self.profile, self.source, self.archive, self.public, self.native, self.usign)
        next((self.tree / 'packages').glob('apk-openssl-*.apk')).unlink()
        self.repack()
        with self.assertRaisesRegex(ValueError, 'APK manager bank invalid'):
            self.export()

    def test_wrong_public_key_modified_index_and_moving_repo_rejected(self):
        self.export()
        tree = ib.safe_extract(self.archive, self.root / 'exported')
        wrong = self.native_public
        with self.assertRaisesRegex(ValueError, 'APK key differs from profile'):
            ib.verify_tree(tree, self.profile, self.public, self.usign, apk=self.apk, public_apk_key=wrong)
        index = tree / 'packages/packages.adb'
        before = index.read_bytes()
        index.write_bytes(before + b'tampering')
        with self.assertRaisesRegex(ValueError, 'index hash'):
            ib.verify_tree(tree, self.profile, self.public, self.usign, apk=self.apk, public_apk_key=self.public_apk)
        index.write_bytes(before)
        (tree / 'repositories').write_text('https://example.org/moving/packages.adb\n')
        with self.assertRaisesRegex(ValueError, 'moving, foreign'):
            ib.verify_tree(tree, self.profile, self.public, self.usign, apk=self.apk, public_apk_key=self.public_apk)

    def test_make_expansion_resets_pin_and_queries_abi_by_untagged_base(self):
        makefile = self.root / 'format.mk'
        makefile.write_text('GetABISuffix = $(if $(filter libfixture,$(1)),2026,)\n' + ib.APK_FORMAT_PACKAGES
            + '\nall:\n\t@echo $(call FormatPackages,libfixture@public=1-r1 busybox libc=2-r1 libfixture2026@public)\n')
        actual = subprocess.check_output(['make', '--no-print-directory', '-f', str(makefile)], text=True).strip()
        self.assertEqual(actual, 'libfixture2026@public=1-r1 busybox libc=2-r1 libfixture2026@public')


if __name__ == '__main__':
    unittest.main()
