"""Reproduce mapfilter's kernel compatibility proof from its pinned vendor tar.

MAPFILTER_SOURCE_ARCHIVE enables real patch/application tests without network.
MAPFILTER_KERNEL_DIR and CROSS_COMPILE additionally enable the real module build;
the prepared kernel tree must be an isolated writable copy, never the active
firmware tree. Build is serial and limited to 2 GiB address space per process.
"""
import hashlib
import os
from pathlib import Path
import resource
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'files/mediatek-mesh/packages/mapfilter'
SOURCE_HASH = '3928c6614b84e74f1f1762cee61de8e422299e792f5f363dc369dfc0ed0f1714'


class MeshMapfilterTests(unittest.TestCase):
    def test_kernel_package_is_pinned_and_built_as_module(self):
        self.assertTrue((PACKAGE / 'Makefile').is_file(), 'required kmod-mapfilter recipe missing')
        recipe = (PACKAGE / 'Makefile').read_text()
        self.assertIn('PKG_HASH:=' + SOURCE_HASH, recipe)
        self.assertIn('CONFIG_MAP_FILTER_SUPPORT=m', recipe)
        self.assertIn('$(eval $(call KernelPackage,mapfilter))', recipe)

    def patched_source(self):
        archive = os.environ.get('MAPFILTER_SOURCE_ARCHIVE')
        if not archive:
            self.skipTest('set MAPFILTER_SOURCE_ARCHIVE for pinned-source checks')
        self.assertEqual(hashlib.sha256(Path(archive).read_bytes()).hexdigest(), SOURCE_HASH)
        scratch = tempfile.TemporaryDirectory(prefix='mapfilter-test-')
        self.addCleanup(scratch.cleanup)
        with tarfile.open(archive, 'r:bz2') as src:
            src.extractall(scratch.name, filter='data')
        source = Path(scratch.name) / 'mapfilter'
        for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
            subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, check=True,
                           capture_output=True, text=True)
        return source

    def test_patch_applies_and_module_load_starts_with_passive_ip_filter(self):
        source = self.patched_source()
        implementation = (source / 'mtkmapfilter.c').read_text()
        init = implementation.split('static int __init map_init(void)', 1)[1]
        init = init.split('static void __exit map_exit(void)', 1)[0]
        self.assertIn('drop_ip_status.drop_flag = 0;', init)
        self.assertNotIn('drop_ip_status.drop_flag = 1;', init)

    def test_module_compiles_and_links_against_prepared_kernel(self):
        kernel = os.environ.get('MAPFILTER_KERNEL_DIR')
        cross = os.environ.get('CROSS_COMPILE')
        if not kernel or not cross:
            self.skipTest('set MAPFILTER_KERNEL_DIR and CROSS_COMPILE for real cross-build')
        source = self.patched_source()
        def build_limits():
            os.nice(19)
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        build = subprocess.run(['make', '-C', kernel, 'M=' + str(source), 'ARCH=arm64',
                                'CROSS_COMPILE=' + cross, 'CONFIG_SUPPORT_OPENWRT=y',
                                'CONFIG_MAP_FILTER_SUPPORT=m', '-j1', 'modules'],
                               text=True, capture_output=True, preexec_fn=build_limits)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        module = source / 'mapfilter.ko'
        self.assertTrue(module.is_file())
        modinfo = shutil.which('modinfo')
        if modinfo:
            info = subprocess.check_output([modinfo, str(module)], text=True)
            self.assertIn('Dual BSD/GPL', info)
            self.assertRegex(info, r'vermagic:\s+6\.12\.')
            self.assertRegex(info, r'vermagic:[^\n]+aarch64')
            self.assertRegex(info, r'depends:\s*\n')


if __name__ == '__main__':
    unittest.main()
