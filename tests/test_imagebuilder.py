"""ImageBuilder boundaries: real host signatures where USIGN is available."""
import copy
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import imagebuilder as ib


def ipk(path, name, version='1-r1', arch='aarch64_cortex-a53', depends=''):
    control = f'Package: {name}\nVersion: {version}\nArchitecture: {arch}\n'
    if depends:
        control += 'Depends: ' + depends + '\n'
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode='w:gz') as tar:
        member = tarfile.TarInfo('./control')
        member.size = len(control.encode())
        tar.addfile(member, io.BytesIO(control.encode()))
    with tarfile.open(path, 'w:gz') as tar:
        member = tarfile.TarInfo('./control.tar.gz')
        member.size = len(inner.getvalue())
        tar.addfile(member, io.BytesIO(inner.getvalue()))


class ArchiveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def archive(self, entries):
        path = self.root / 'ib.tar'
        with tarfile.open(path, 'w') as tar:
            for name, kind, value in [('ib/Makefile', 'file', b'all:')] + entries:
                member = tarfile.TarInfo(name)
                if kind == 'file':
                    member.size = len(value)
                    tar.addfile(member, io.BytesIO(value))
                else:
                    member.type = tarfile.SYMTYPE if kind == 'sym' else tarfile.LNKTYPE
                    member.linkname = value
                    tar.addfile(member)
        return path

    def test_standard_relative_links_and_hardlinks_are_safe(self):
        archive = self.archive([('ib/relative', 'sym', 'Makefile'), ('ib/hard', 'hard', 'ib/Makefile')])
        tree = ib.safe_extract(archive, self.root / 'out')
        self.assertTrue((tree / 'relative').is_symlink())
        self.assertEqual((tree / 'hard').read_bytes(), b'all:')

    def test_escapes_duplicate_paths_and_symlink_parents_fail_before_extract(self):
        cases = [[('ib/out', 'sym', '/etc/passwd')], [('ib/out', 'sym', '../../outside')],
                 [('ib/../outside', 'file', b'bad')], [('ib/Makefile', 'file', b'bad')],
                 [('ib/a', 'sym', 'elsewhere'), ('ib/a/child', 'file', b'bad')],
                 [('ib/hard', 'hard', 'ib/missing')]]
        for entries in cases:
            with self.subTest(entries=entries):
                with self.assertRaises(ValueError):
                    ib.safe_extract(self.archive(entries), self.root / 'out')
                self.assertFalse((self.root / 'out').exists())

    def test_unrecognized_makefile_cannot_silently_leave_mutable_bank(self):
        with self.assertRaisesRegex(ValueError, 'unrecognized'):
            ib.freeze_makefile('all:\n\ttrue\n')

    def test_asu_opt_in_is_explicit(self):
        self.assertFalse(ib.enabled({}))
        self.assertFalse(ib.enabled({'asu': {'enabled': 'true'}}))
        self.assertTrue(ib.enabled({'asu': {'enabled': True}}))


class MatchingBuilderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.usign = os.environ.get('USIGN') or shutil.which('usign')
        if not cls.usign:
            raise unittest.SkipTest('real host USIGN required for ImageBuilder signing fixtures')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.profile = {'id': 'redmi-ax6000', 'build_id': 'fixture-build', 'asu': {'enabled': True}, 'packages': ['kmod-test'],
                        'firmware': {'commit': 'a' * 40, 'kernel_version': '6.6.133~' + 'b' * 32 + '-r1',
                                     'architecture': 'aarch64_cortex-a53', 'target': 'mediatek', 'subtarget': 'filogic'}}
        self.public = self.root / 'production.pub'
        self.native = self.source / 'key-build'
        for private, public in [(self.root / 'production.key', self.public), (self.native, self.source / 'key-build.pub')]:
            subprocess.run([self.usign, '-G', '-s', str(private), '-p', str(public)], check=True, capture_output=True)
        self.packages = self.source / 'bin/packages'
        self.packages.mkdir(parents=True)
        for name in ['kernel', 'libc', 'base-files', 'busybox', 'opkg', 'kmod-test']:
            version = self.profile['firmware']['kernel_version'] if name == 'kernel' else '1-r1'
            depends = 'kernel (= ' + self.profile['firmware']['kernel_version'] + ')' if name == 'kmod-test' else ''
            ipk(self.packages / (name + '.ipk'), name, version, depends=depends)
        kernel = self.source / 'build_dir/target-test/linux-mediatek_filogic/linux-6.6.133'
        files = {kernel / 'include/config/kernel.release': b'6.6.133\n', kernel / '.config': b'CONFIG_TEST=y\n',
                 kernel.parent / 'Image': b'native kernel bytes', kernel.parent / 'mt7986a-ax6000.dtb': b'native dtb bytes',
                 self.source / 'tmp/.targetinfo': b'native target metadata', self.source / 'tmp/.packageinfo': b'native package metadata',
                 self.source / 'staging_dir/target-test/image/vendor.bin': b'vendor input'}
        for path, value in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        self.tree = self.root / 'immortalwrt-imagebuilder-mediatek-filogic.Linux-x86_64'
        self.tree.mkdir()
        (self.tree / 'Makefile').write_bytes(gzip.decompress((Path(__file__).parent / 'fixtures/imagebuilder-opkg-ec9ef10-Makefile.gz').read_bytes()))
        native_makefile = self.source / 'target/imagebuilder/files/Makefile'
        native_makefile.parent.mkdir(parents=True)
        shutil.copy2(self.tree / 'Makefile', native_makefile)
        (self.tree / '.config').write_text('CONFIG_IB_STANDALONE=y\nCONFIG_TARGET_BOARD="mediatek"\nCONFIG_TARGET_SUBTARGET="filogic"\nCONFIG_TARGET_ARCH_PACKAGES="aarch64_cortex-a53"\n')
        (self.tree / 'include').mkdir()
        (self.tree / 'include/version.mk').write_text('REVISION:=r123-aaaaaaaaaaaa\n')
        (self.tree / 'repositories.conf').write_text('src/gz moving https://example.org/SNAPSHOT\n')
        shutil.copytree(self.packages, self.tree / 'packages')
        for item in ib.native_context(self.source, self.profile['firmware']['kernel_version']):
            target = self.tree / (Path(item['path']).name if item['path'].startswith('tmp/') else item['path'])
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.source / item['path'], target)
        self.archive = self.root / (self.tree.name + '.tar.gz')
        self.repack()

    def repack(self):
        with tarfile.open(self.archive, 'w:gz') as tar:
            tar.add(self.tree, arcname=self.tree.name)

    def export(self):
        return ib.export_archive(self.profile, self.source, self.archive, self.public, self.native, self.usign)

    def extract(self):
        return ib.safe_extract(self.archive, self.root / 'verified')

    def test_export_preserves_native_context_and_complete_core_signed_bank(self):
        native_hash = ib.sha256(self.archive)
        result = self.export()
        self.assertEqual(result['native_archive_sha256'], native_hash)
        self.assertEqual(result['packages'], 6)
        self.assertFalse(result['native_make_executed'])
        tree = self.extract()
        self.assertEqual((tree / 'repositories.conf').read_text(), ib.REPOSITORIES)
        self.assertEqual(len(list((tree / 'keys').iterdir())), 2)
        self.assertNotIn(self.native.read_bytes(), self.archive.read_bytes())
        ib.verify_tree(tree, self.profile, self.public, self.usign, self.source, list(self.packages.glob('*.ipk')))

    def test_verify_archive_rejects_other_argument_beside_the_legitimate_pinned_archive(self):
        result = self.export()
        self.profile['imagebuilder'] = {'url': 'https://github.com/valujin/ax6000-packages/releases/download/firmware-'
            + self.profile['build_id'] + '/' + self.archive.name, 'sha256': result['sha256'], 'size': result['size']}
        tree = self.extract()
        (tree / '.config').write_text((tree / '.config').read_text() + 'CONFIG_FOREIGN_EXTRA=y\n')
        other = self.root / 'other.tar.gz'
        with tarfile.open(other, 'w:gz') as tar:
            tar.add(tree, arcname=tree.name)
        with self.assertRaisesRegex(ValueError, 'archive argument differs'):
            ib.verify_archive(other, self.profile, self.public, self.usign, self.root / 'wrong-verified')
        self.assertFalse((self.root / 'wrong-verified').exists())
        self.assertEqual(ib.sha256(self.archive), result['sha256'])

    def test_native_feed_directories_do_not_change_canonical_bank_identity(self):
        for name, directory in [('base-files.ipk', 'zz-feed'), ('kernel.ipk', 'aa-feed')]:
            target = self.source / 'bin' / directory / name
            target.parent.mkdir()
            (self.packages / name).rename(target)
        native = ib.package_bank((self.source / 'bin').rglob('*.ipk'), self.profile)
        flattened = ib.package_bank((self.tree / 'packages').glob('*.ipk'), self.profile)
        self.assertEqual(native, flattened)
        self.assertEqual([x['filename'] for x in native], sorted(x['filename'] for x in native))
        self.export()
        duplicate = self.source / 'bin/third-feed/base-files.ipk'
        duplicate.parent.mkdir()
        shutil.copy2(self.source / 'bin/zz-feed/base-files.ipk', duplicate)
        with self.assertRaisesRegex(ValueError, 'duplicate native package identity'):
            ib.package_bank((self.source / 'bin').rglob('*.ipk'), self.profile)

    def test_missing_imagebuilder_and_incomplete_standalone_bank_fail(self):
        with self.assertRaisesRegex(ValueError, 'missing'):
            ib.export_archive(self.profile, self.source, self.root / 'missing.tar', self.public, self.native, self.usign)
        (self.tree / 'packages/opkg.ipk').unlink()
        self.repack()
        before = self.archive.read_bytes()
        with self.assertRaisesRegex(ValueError, 'core package bank incomplete'):
            self.export()
        self.assertEqual(self.archive.read_bytes(), before)

    def test_foreign_kernel_or_module_abi_is_rejected(self):
        for name in ['kernel', 'kmod-test']:
            with self.subTest(name=name):
                package = self.tree / 'packages' / (name + '.ipk')
                ipk(package, name, '6.6.1~' + 'c' * 32 + '-r1', depends='kernel (= 6.6.1~' + 'c' * 32 + '-r1)')
                self.repack()
                with self.assertRaisesRegex(ValueError, 'foreign ImageBuilder'):
                    self.export()
                shutil.copy2(self.packages / package.name, package)

    def test_moving_repositories_key_changes_and_foreign_context_rejected(self):
        self.export()
        tree = self.extract()
        repositories = tree / 'repositories.conf'
        repositories.write_text(ib.REPOSITORIES + 'src/gz remote https://downloads.openwrt.org/snapshots/\n')
        with self.assertRaisesRegex(ValueError, 'moving or foreign'):
            ib.verify_tree(tree, self.profile, self.public, self.usign)
        repositories.write_text(ib.REPOSITORIES)
        image = next(tree.glob('build_dir/*/linux-*/Image'))
        image.write_bytes(b'foreign kernel')
        with self.assertRaisesRegex(ValueError, 'context bytes differ'):
            ib.verify_tree(tree, self.profile, self.public, self.usign)

    def test_actual_native_package_index_and_source_provenance_checked(self):
        self.export()
        tree = self.extract()
        (tree / 'packages/Packages').write_text('Package: malicious\n')
        with self.assertRaisesRegex(ValueError, 'index metadata differs'):
            ib.verify_tree(tree, self.profile, self.public, self.usign)

    def test_private_key_in_native_archive_rejected_without_export(self):
        (self.tree / 'unexpected-key').write_bytes(self.native.read_bytes())
        self.repack()
        with self.assertRaisesRegex(ValueError, 'private key leaked'):
            self.export()


if __name__ == '__main__':
    unittest.main()
