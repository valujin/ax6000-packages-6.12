"""Cohort import checks using independently assembled raw metadata."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from test_prepare_612 import channel_profile
SPEC = importlib.util.spec_from_file_location('import_612', ROOT / 'scripts/import-release.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class CohortImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.raw = self.root / 'raw'
        self.target = self.raw / 'bin/targets/mediatek/filogic'
        self.target.mkdir(parents=True)
        self.profile = channel_profile()
        sdk = self.target / 'immortalwrt-sdk-filogic.tar.zst'
        sdk.write_bytes(b'independent SDK bytes')
        digest = hashlib.sha256(sdk.read_bytes()).hexdigest()
        self.profile['build_id'] = self.profile['id'] + '-' + self.profile['firmware']['commit'][:12] + '-' + digest[:12]
        self.profile['sdk'] = {'sha256': digest, 'url': 'https://github.com/valujin/ax6000-packages-6.12/releases/download/firmware-' + self.profile['build_id'] + '/' + sdk.name}
        self.expected = self.root / 'expected.json'
        expected = copy.deepcopy(self.profile)
        expected['firmware']['kernel_version'] = None
        expected['sdk'] = None
        self.expected.write_text(json.dumps(expected))
        native = {'target': 'mediatek/filogic', 'arch_packages': 'aarch64_cortex-a53',
                  'linux_kernel': {'version': '6.12.108', 'vermagic': 'a' * 32, 'release': '1'}, 'profiles': {}}
        for item in self.profile['firmware']['devices']:
            suffix = 'squashfs-sysupgrade.itb' if item['layout'] == 'ubootmod' else 'squashfs-sysupgrade.bin'
            name = 'immortalwrt-mediatek-filogic-' + item['device'] + '-' + suffix
            payload = ('independent ' + item['layout']).encode()
            (self.target / name).write_bytes(payload)
            native['profiles'][item['device']] = {'supported_devices': [item['device'].replace('xiaomi_', 'xiaomi,')],
                'images': [{'name': name, 'sha256': hashlib.sha256(payload).hexdigest()}]}
        (self.target / 'profiles.json').write_text(json.dumps(native))
        self.manifest = {'channel': self.profile['channel'], 'devices': self.profile['firmware']['devices'],
                         'build_id': self.profile['build_id'], 'source_commit': self.profile['firmware']['commit'],
                         'kernel_version': self.profile['firmware']['kernel_version']}
        self.write_metadata()

    def write_metadata(self):
        profile = self.raw / 'profile.json'
        profile.write_text(json.dumps(self.profile))
        lock = {'schema_version': 1, 'profile_id': self.profile['id'],
                'profile_sha256': hashlib.sha256(profile.read_bytes()).hexdigest(),
                'firmware': self.profile['firmware'], 'sdk': self.profile['sdk'],
                'feeds': {feed['name']: feed['commit'] for feed in self.profile['feeds']}}
        (self.raw / 'lock.json').write_text(json.dumps(lock))
        self.manifest['files'] = [{'path': path.relative_to(self.raw).as_posix(),
                                  'size': path.stat().st_size,
                                  'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                                 for path in sorted(self.target.iterdir()) if path.is_file()]
        (self.raw / 'firmware-manifest.json').write_text(json.dumps(self.manifest))

    def test_valid_metadata_returns_validated_records(self):
        result = release.validate_metadata(self.raw, self.expected)
        self.assertEqual(set(result), {'profile', 'lock', 'manifest'})
        self.assertEqual(result['profile'], self.profile)

    def test_manifest_cannot_mix_generations_or_layouts(self):
        for key, value in [('channel', 'latest'), ('devices', self.manifest['devices'][:2]),
                           ('build_id', 'foreign-generation')]:
            with self.subTest(key=key):
                original = self.manifest[key]
                self.manifest[key] = value
                self.write_metadata()
                with self.assertRaisesRegex(ValueError, 'manifest'):
                    release.validate_metadata(self.raw, self.expected)
                self.manifest[key] = original

    def test_missing_layout_is_rejected_even_with_self_consistent_inventory(self):
        next(self.target.glob('*mtkuboot*sysupgrade.bin')).unlink()
        self.write_metadata()
        with self.assertRaises(ValueError):
            release.validate_metadata(self.raw, self.expected)

    def test_cross_channel_source_profile_is_rejected(self):
        expected = json.loads(self.expected.read_text())
        expected['channel'] = 'latest'
        self.expected.write_text(json.dumps(expected))
        with self.assertRaisesRegex(ValueError, 'channel'):
            release.validate_metadata(self.raw, self.expected)


class SelectedAssetsTests(unittest.TestCase):
    def test_snapshot_pair_can_be_selected_without_raw(self):
        names = ('channel.tar.zst', 'channel.tar.zst.sha256')
        metadata = {'id': 1, 'tag_name': 'packages-recommended-fixture', 'draft': False, 'immutable': True,
                    'assets': [{'id': i + 1, 'name': name, 'state': 'uploaded', 'size': 123,
                                'updated_at': '2026-10-12T00:00:00Z'} for i, name in enumerate(names)]}
        self.assertEqual(len(release.release_identity(metadata, names)[-1]), 2)
        for invalid in ([], ('../channel.tar.zst',), (names[0], names[0])):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                release.release_identity(metadata, invalid)


if __name__ == '__main__':
    unittest.main()
