"""Only explicitly ASU-enabled immutable generations publish matching IBs."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from test_firmware_layouts import fixture, layouts


class BuilderCatalogTests(unittest.TestCase):
    def fixture(self, root):
        profile, native, manifest = fixture(root)
        profile['asu'] = {'enabled': True}
        path = root / 'bin/targets/mediatek/filogic/immortalwrt-imagebuilder-mediatek-filogic.Linux-x86_64.tar.zst'
        payload = b'matching native imagebuilder fixture'
        path.write_bytes(payload)
        profile['imagebuilder'] = {'url': layouts.firmware_release_url(profile, path.name),
            'sha256': hashlib.sha256(payload).hexdigest(), 'size': len(payload)}
        manifest['files'].append({'path': path.relative_to(root).as_posix(), **{k: v for k, v in profile['imagebuilder'].items() if k != 'url'}})
        return profile, manifest, path

    def test_asu_catalog_binds_one_exact_imagebuilder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile, manifest, path = self.fixture(root)
            assets = layouts.collect_firmware_assets(root, profile, manifest)
            self.assertEqual([x['filename'] for x in assets if x['kind'] == 'imagebuilder'], [path.name])
            catalog = {'schema_version': 1, 'channel': profile['channel'], 'profile_id': profile['id'],
                'build_id': profile['build_id'], 'firmware': profile['firmware'], 'sdk': profile['sdk'],
                'imagebuilder': profile['imagebuilder'], 'assets': [{**{k: v for k, v in x.items() if k != 'path'},
                'url': layouts.firmware_release_url(profile, x['filename'])} for x in assets]}
            self.assertEqual(layouts.validate_download_catalog(catalog, profile), catalog)
            broken = copy.deepcopy(catalog)
            del broken['imagebuilder']
            with self.assertRaisesRegex(ValueError, 'ImageBuilder identity'):
                layouts.validate_download_catalog(broken, profile)
            broken = copy.deepcopy(catalog)
            next(x for x in broken['assets'] if x['kind'] == 'imagebuilder')['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'ImageBuilder identity'):
                layouts.validate_download_catalog(broken, profile)

    def test_missing_changed_moving_or_nonoptin_imagebuilder_rejected(self):
        for problem in ['missing', 'bytes', 'moving', 'legacy', 'identity']:
            with tempfile.TemporaryDirectory() as tmp, self.subTest(problem=problem):
                profile, manifest, path = self.fixture(Path(tmp))
                if problem == 'missing':
                    path.unlink()
                elif problem == 'bytes':
                    path.write_bytes(b'foreign')
                elif problem == 'moving':
                    profile['imagebuilder']['url'] = 'https://downloads.openwrt.org/snapshots/' + path.name
                elif problem == 'legacy':
                    del profile['asu']
                else:
                    del profile['imagebuilder']
                with self.assertRaises(ValueError):
                    layouts.collect_firmware_assets(Path(tmp), profile, manifest)


if __name__ == '__main__':
    unittest.main()
