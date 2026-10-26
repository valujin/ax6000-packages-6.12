"""Exercise OpenWrt package discovery and, when supplied, the pinned metadata toolchain."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'files/mediatek-mesh/packages/luci-app-ax6000-mesh'
SOURCE = os.environ.get('AX6000_METADATA_SOURCE')


class MeshMetadata(unittest.TestCase):
    def test_openwrt_scanner_discovers_local_luci_recipe(self):
        # This is include/scan.mk's actual recipe discovery command. LuCI's
        # included helper expands BuildPackage later, after this filtering step.
        found = subprocess.run(['find', '-L', str(PACKAGE), '-mindepth', '1', '-name', 'Makefile'],
                               check=True, capture_output=True, text=True).stdout.splitlines()
        result = subprocess.run(['grep', '-aHE', r'call (Build/DefaultTargets|BuildPackage|KernelPackage)', *found],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, 'OpenWrt scan.mk skips the LuCI recipe before metadata evaluation')
        self.assertIn(str(PACKAGE / 'Makefile') + ':', result.stdout)

    @unittest.skipUnless(SOURCE, 'Set AX6000_METADATA_SOURCE to the pinned prepared source for real package metadata')
    def test_real_pinned_openwrt_metadata_declares_app_and_russian_translation(self):
        source = Path(SOURCE)
        luci = source / 'feeds/luci/luci.mk'
        self.assertEqual(hashlib.sha256(luci.read_bytes()).hexdigest(),
                         '9716c9a7a1c276b867df5887558e2b63b78f7d3695915adb7fcd0a7f0182ed0d')
        with tempfile.TemporaryDirectory(prefix='mesh-metadata-') as directory:
            scratch = Path(directory)
            for name in ('include', 'scripts', 'config'):
                shutil.copytree(source / name, scratch / name, symlinks=True)
            for name in ('rules.mk', '.config'):
                shutil.copyfile(source / name, scratch / name)
            (scratch / 'tmp/info').mkdir(parents=True)
            (scratch / 'feeds/luci').mkdir(parents=True)
            shutil.copyfile(luci, scratch / 'feeds/luci/luci.mk')
            hostbin = scratch / 'staging_dir/host/bin'
            hostbin.mkdir(parents=True)
            (hostbin / 'mkhash').symlink_to(source / 'staging_dir/host/bin/mkhash')
            (hostbin / 'awk').symlink_to(shutil.which('gawk'))
            shutil.copytree(PACKAGE, scratch / 'package/ax6000-overrides/luci-app-ax6000-mesh')
            env = {**os.environ, 'TOPDIR': str(scratch), 'PATH': str(hostbin) + ':' + os.environ['PATH']}
            result = subprocess.run(['make', '--no-print-directory', '-r', '-f', 'include/scan.mk',
                                     'SCAN_DIR=package', 'SCAN_TARGET=packageinfo'],
                                    cwd=scratch, env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            symbols = subprocess.run(['perl', 'scripts/package-metadata.pl', 'config', 'tmp/.packageinfo'],
                                     cwd=scratch, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(symbols.returncode, 0, symbols.stderr)
            (scratch / 'tmp/.config-package.in').write_text(symbols.stdout)
            metadata = (scratch / 'tmp/.packageinfo').read_text()
            proof = os.environ.get('AX6000_METADATA_PROOF_DIR')
            if proof:
                (Path(proof) / 'packageinfo-after').write_text(metadata)
                (Path(proof) / 'config-package-after.in').write_text(symbols.stdout)
            entries = {}
            for chunk in metadata.split('\nPackage: ')[1:]:
                name, body = chunk.split('\n', 1)
                entries[name] = body
            self.assertIn('luci-app-ax6000-mesh', entries, result.stdout + result.stderr)
            self.assertIn('luci-i18n-ax6000-mesh-ru', entries)
            self.assertIn('Depends: +libc +luci-base +ax6000-mesh\n', entries['luci-app-ax6000-mesh'])
            self.assertIn('Depends: +libc luci-app-ax6000-mesh\n', entries['luci-i18n-ax6000-mesh-ru'])
            sys.path.insert(0, str(ROOT / 'scripts'))
            import prepare
            self.assertLessEqual({'luci-app-ax6000-mesh', 'luci-i18n-ax6000-mesh-ru'}, prepare.available_packages(scratch))


if __name__ == '__main__':
    unittest.main()
