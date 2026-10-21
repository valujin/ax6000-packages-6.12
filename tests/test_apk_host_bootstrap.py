"""Pinned bootstrap inputs and archive boundaries for the independent host APK."""
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/build-apk-host.sh'
SOURCE = SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0]
BOOTSTRAP = {'__name__': 'apk_host_bootstrap_test'}
exec(compile(SOURCE, str(SCRIPT), 'exec'), BOOTSTRAP)


class APKHostBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def archive(self, extra=()):
        path = self.root / 'source.tar.gz'
        with tarfile.open(path, 'w:gz') as output:
            for name in ('meson.build', 'src/apk.c'):
                info = tarfile.TarInfo(BOOTSTRAP['APK_TOP'] + '/' + name)
                info.size = 1
                output.addfile(info, io.BytesIO(b'x'))
            for info, data in extra:
                output.addfile(info, io.BytesIO(data) if data is not None else None)
        return path

    def test_release_commit_urls_and_complete_download_pins(self):
        reviewed = json.loads((ROOT / 'tests/fixtures/apk-host-pins.json').read_text())
        self.assertEqual(BOOTSTRAP['APK_COMMIT'], reviewed['source_commit'])
        self.assertEqual(BOOTSTRAP['INPUTS'], reviewed['source'])
        self.assertIn('-Dcrypto_backend=openssl', BOOTSTRAP['OPTIONS'])
        self.assertIn('-Durl_backend=wget', BOOTSTRAP['OPTIONS'])
        self.assertIn('-Ddefault_library=static', BOOTSTRAP['OPTIONS'])

    def test_source_extraction_accepts_only_known_local_symlink(self):
        info = tarfile.TarInfo(BOOTSTRAP['APK_TOP'] + '/src/apk-static.c')
        info.type = tarfile.SYMTYPE
        info.linkname = 'apk.c'
        path = self.archive([(info, None)])
        output = self.root / 'extract'
        output.mkdir()
        BOOTSTRAP['extract_source'](path, output)
        link = output / BOOTSTRAP['APK_TOP'] / 'src/apk-static.c'
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.read_bytes(), b'x')

    def test_source_rejects_escape_foreign_topdir_hardlink_and_unknown_symlink_before_writes(self):
        for problem in ('escape', 'topdir', 'hardlink', 'symlink'):
            with self.subTest(problem=problem):
                name = BOOTSTRAP['APK_TOP'] + '/extra'
                if problem == 'escape':
                    name = BOOTSTRAP['APK_TOP'] + '/../escape'
                if problem == 'topdir':
                    name = 'unreviewed-topdir/file'
                info = tarfile.TarInfo(name)
                data = b'bad'
                info.size = len(data)
                if problem in ('hardlink', 'symlink'):
                    info.type = tarfile.LNKTYPE if problem == 'hardlink' else tarfile.SYMTYPE
                    info.linkname = '../../outside'
                    data = None
                path = self.archive([(info, data)])
                output = self.root / problem
                output.mkdir()
                with self.assertRaises(ValueError):
                    BOOTSTRAP['extract_source'](path, output)
                self.assertEqual(list(output.iterdir()), [])

    def test_meson_wheel_rejects_traversal_without_extracting(self):
        path = self.root / 'meson.whl'
        with zipfile.ZipFile(path, 'w') as output:
            output.writestr('mesonbuild/mesonmain.py', 'pass')
            output.writestr('../outside.py', 'bad')
        with self.assertRaisesRegex(ValueError, 'unsafe archive path'):
            BOOTSTRAP['verify_wheel'](path)
        self.assertFalse((self.root / 'outside.py').exists())

    def test_cache_mismatch_is_rejected_without_compiling(self):
        cache = self.root / 'cache'
        cache.mkdir()
        downloads = self.root / 'downloads'
        downloads.mkdir()
        (cache / BOOTSTRAP['INPUTS']['apk']['filename']).write_bytes(b'foreign source')
        with self.assertRaisesRegex(ValueError, 'SHA256/size mismatch'):
            BOOTSTRAP['obtain'](BOOTSTRAP['INPUTS']['apk'], downloads, cache)
        self.assertEqual(list(downloads.iterdir()), [])

    def test_cli_requires_fresh_explicit_work_directory(self):
        missing = subprocess.run(['bash', str(SCRIPT)], capture_output=True, text=True)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn('--work-dir', missing.stderr)
        marker = self.root / 'marker'
        marker.write_text('preserve')
        existing = subprocess.run(['bash', str(SCRIPT), '--work-dir', str(self.root)], capture_output=True, text=True)
        self.assertNotEqual(existing.returncode, 0)
        self.assertIn('must be fresh', existing.stderr)
        self.assertEqual(marker.read_text(), 'preserve')
        self.assertEqual(list(self.root.iterdir()), [marker])


if __name__ == '__main__':
    unittest.main()
