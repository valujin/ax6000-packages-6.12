"""Recipe modes must agree with INSTALL_BIN and SquashFS verification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MeshInstallModes(unittest.TestCase):
    def test_runtime_executables_match_image_verifier_inputs(self):
        files = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files'
        paths = [*files.glob('etc/init.d/*'), *files.glob('usr/bin/*'),
                 *files.glob('usr/libexec/ax6000-mesh-*'),
                 files / 'usr/libexec/rpcd/ax6000.mesh']
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=str(path.relative_to(files))):
                self.assertTrue(path.is_file() and not path.is_symlink())
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)
