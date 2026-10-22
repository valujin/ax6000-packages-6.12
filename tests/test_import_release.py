import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('import_release', ROOT / 'scripts/import-release.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseMetadataTests(unittest.TestCase):
    def setUp(self):
        self.metadata = {
            'id': 42, 'tag_name': 'firmware-fixture', 'immutable': True, 'draft': False,
            'assets': [{'id': number, 'name': name, 'size': 123,
                        'updated_at': '2026-10-11T00:00:00Z', 'state': 'uploaded'}
                       for number, name in enumerate(('raw.tar.zst', 'raw.tar.zst.sha256'), 1)]}

    def test_immutable_release_identity_is_stable(self):
        self.assertEqual(release.release_identity(self.metadata),
                         release.release_identity(json.loads(json.dumps(self.metadata))))

    def test_mutable_release_is_rejected(self):
        self.metadata['immutable'] = False
        with self.assertRaisesRegex(ValueError, 'immutable'):
            release.release_identity(self.metadata)

    def test_draft_release_is_rejected(self):
        self.metadata['draft'] = True
        with self.assertRaisesRegex(ValueError, 'draft'):
            release.release_identity(self.metadata)

    def test_missing_or_duplicate_assets_are_rejected(self):
        for assets in ([], self.metadata['assets'] + [self.metadata['assets'][0]]):
            with self.subTest(assets=assets), self.assertRaisesRegex(ValueError, 'exactly one'):
                release.release_identity(dict(self.metadata, assets=assets))

    def test_asset_replacement_changes_identity(self):
        original = release.release_identity(self.metadata)
        self.metadata['assets'][0]['id'] += 100
        self.assertNotEqual(original, release.release_identity(self.metadata))


@unittest.skipUnless(shutil.which('zstd'), 'zstd is required for release transport tests')
class ReleaseImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profile = json.loads((ROOT / 'profiles/redmi-ax6000-new.json').read_text())
        self.profile['enabled'] = True  # Historical importer fixture, not an enabled source build.
        self.expected = self.root / 'expected.json'
        self.expected.write_text(json.dumps(self.profile))
        self.profile['firmware']['kernel_version'] = '6.6.133~' + 'a' * 32 + '-r1'
        self.target = 'bin/targets/mediatek/filogic/'
        self.sdk_path = self.target + 'immortalwrt-sdk-mediatek-filogic.tar.zst'
        self.image_path = self.target + 'immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-stock-squashfs-sysupgrade.bin'
        self.assets = {
            'bin/packages/aarch64_cortex-a53/base/fixture.ipk': b'package',
            self.sdk_path: b'fixture matching SDK archive',
            self.image_path: b'fixture complete stock sysupgrade image',
        }
        self.profile['sdk'] = {'url': 'https://example.com/' + Path(self.sdk_path).name,
                               'sha256': hashlib.sha256(self.assets[self.sdk_path]).hexdigest()}
        self.profile['feeds'].insert(0, {'name': 'base', 'url': self.profile['firmware']['repository'],
                                        'commit': self.profile['firmware']['commit']})
        self.profile_bytes = json.dumps(self.profile).encode()
        self.lock = {'schema_version': 1, 'profile_id': self.profile['id'],
                     'profile_sha256': hashlib.sha256(self.profile_bytes).hexdigest(),
                     'firmware': self.profile['firmware'], 'sdk': self.profile['sdk'],
                     'feeds': {f['name']: f['commit'] for f in self.profile['feeds']}}
        self.manifest = {
            'source_commit': self.profile['firmware']['commit'],
            'kernel_version': self.profile['firmware']['kernel_version'],
            'files': [{'path': path, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
                      for path, data in sorted(self.assets.items())],
        }

    def bundle(self, extra=(), overrides=None):
        files = {'profile.json': self.profile_bytes,
                 'lock.json': json.dumps(self.lock).encode(),
                 'firmware-manifest.json': json.dumps(self.manifest).encode(),
                 'usign': b'#!/bin/sh\nexit 99\n'}
        files.update(self.assets)
        for path, data in (overrides or {}).items():
            if data is None:
                files.pop(path, None)
            else:
                files[path] = data
        plain = self.root / 'bundle.tar'
        with tarfile.open(plain, 'w') as archive:
            directory = tarfile.TarInfo('./')
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            for name, data in files.items():
                member = tarfile.TarInfo('./' + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            for member in extra:
                archive.addfile(member, io.BytesIO(b'x') if member.isfile() else None)
        packed = self.root / 'raw.tar.zst'
        subprocess.run(['zstd', '-q', '-f', str(plain), '-o', str(packed)], check=True)
        checksum = self.root / 'raw.tar.zst.sha256'
        checksum.write_text(hashlib.sha256(packed.read_bytes()).hexdigest() + '  raw.tar.zst\n')
        return packed, checksum

    def run_import(self, packed, checksum):
        return release.import_bundle(packed, checksum, self.root / 'raw', self.expected)

    def test_valid_bundle_extracts_files_and_never_runs_bundled_signer(self):
        packed, checksum = self.bundle()
        self.run_import(packed, checksum)
        self.assertEqual((self.root / 'raw/bin/packages/aarch64_cortex-a53/base/fixture.ipk').read_bytes(), b'package')
        self.assertEqual((self.root / 'raw/usign').stat().st_mode & 0o111, 0)

    def test_checksum_mismatch_prevents_extraction(self):
        packed, checksum = self.bundle()
        checksum.write_text('0' * 64 + '  raw.tar.zst\n')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.run_import(packed, checksum)
        self.assertFalse((self.root / 'raw').exists())

    def test_traversal_and_absolute_paths_are_rejected(self):
        for name in ('../escaped', '/escaped', './a/../../escaped', 'a\\escaped'):
            with self.subTest(name=name):
                member = tarfile.TarInfo(name)
                member.size = 1
                packed, checksum = self.bundle([member])
                with self.assertRaises(ValueError):
                    self.run_import(packed, checksum)
                self.assertFalse((self.root / 'raw').exists())
                self.assertFalse((self.root / 'escaped').exists())

    def test_links_and_devices_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                member = tarfile.TarInfo('unexpected')
                member.type = kind
                member.linkname = 'profile.json'
                packed, checksum = self.bundle([member])
                with self.assertRaises(ValueError):
                    self.run_import(packed, checksum)
                self.assertFalse((self.root / 'raw').exists())

    def test_duplicate_file_is_rejected(self):
        member = tarfile.TarInfo('./profile.json')
        member.size = 1
        packed, checksum = self.bundle([member])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.run_import(packed, checksum)

    def test_unpacked_size_limit(self):
        packed, checksum = self.bundle()
        with self.assertRaisesRegex(ValueError, 'size limit'):
            release.import_bundle(packed, checksum, self.root / 'raw', self.expected, max_bytes=16)

    def test_wrong_firmware_source_is_rejected(self):
        self.profile['firmware']['commit'] = 'c' * 40
        packed, checksum = self.bundle(overrides={'profile.json': json.dumps(self.profile).encode()})
        with self.assertRaises(ValueError):
            self.run_import(packed, checksum)

    def test_lock_firmware_disagreement_is_rejected(self):
        self.lock['firmware'] = dict(self.lock['firmware'], kernel_version='6.6.133~' + 'd' * 32 + '-r1')
        packed, checksum = self.bundle()
        with self.assertRaisesRegex(ValueError, 'lock firmware'):
            self.run_import(packed, checksum)

    def test_manifest_abi_disagreement_is_rejected(self):
        packed, checksum = self.bundle(overrides={'firmware-manifest.json': json.dumps({
            'source_commit': self.profile['firmware']['commit'], 'kernel_version': 'incorrect'}).encode()})
        with self.assertRaisesRegex(ValueError, 'manifest'):
            self.run_import(packed, checksum)

    def test_manifest_missing_extra_and_duplicate_assets_are_rejected(self):
        for changes in ('missing', 'extra', 'duplicate'):
            with self.subTest(changes=changes):
                manifest = json.loads(json.dumps(self.manifest))
                overrides = {}
                if changes == 'missing':
                    overrides[self.image_path] = None
                elif changes == 'extra':
                    overrides[self.target + 'unexpected.bin'] = b'unlisted image'
                else:
                    manifest['files'].append(manifest['files'][0])
                overrides['firmware-manifest.json'] = json.dumps(manifest).encode()
                packed, checksum = self.bundle(overrides=overrides)
                with self.assertRaisesRegex(ValueError, 'inventory|duplicate'):
                    self.run_import(packed, checksum)
                self.assertFalse((self.root / 'raw').exists())

    def test_manifest_hash_size_and_invalid_fields_are_rejected(self):
        for field, value in (('sha256', '0' * 64), ('sha256', 'invalid'),
                             ('size', 1), ('size', -1), ('size', True), ('size', '123')):
            with self.subTest(field=field, value=value):
                manifest = json.loads(json.dumps(self.manifest))
                manifest['files'][0][field] = value
                packed, checksum = self.bundle(overrides={'firmware-manifest.json': json.dumps(manifest).encode()})
                with self.assertRaisesRegex(ValueError, 'manifest|inventory'):
                    self.run_import(packed, checksum)
                self.assertFalse((self.root / 'raw').exists())

    def test_manifest_paths_must_be_canonical_safe_bin_files(self):
        for path in ('../escaped', '/bin/file', 'bin/../profile.json', 'profile.json',
                     'bin\\file', 'bin//file', 'bin/./file', 'bin', 'bin/targets/'):
            with self.subTest(path=path):
                manifest = json.loads(json.dumps(self.manifest))
                manifest['files'][0]['path'] = path
                packed, checksum = self.bundle(overrides={'firmware-manifest.json': json.dumps(manifest).encode()})
                with self.assertRaisesRegex(ValueError, 'manifest|inventory'):
                    self.run_import(packed, checksum)
                self.assertFalse((self.root / 'raw').exists())

    def test_absent_inventory_is_rejected(self):
        for entries in (None, [], {}, [None]):
            with self.subTest(entries=entries):
                manifest = dict(self.manifest, files=entries)
                packed, checksum = self.bundle(overrides={'firmware-manifest.json': json.dumps(manifest).encode()})
                with self.assertRaisesRegex(ValueError, 'inventory|manifest'):
                    self.run_import(packed, checksum)
                self.assertFalse((self.root / 'raw').exists())

    def test_sdk_and_stock_image_are_required_even_with_self_consistent_inventory(self):
        for asset in (self.sdk_path, self.image_path):
            with self.subTest(asset=asset):
                manifest = dict(self.manifest, files=[entry for entry in self.manifest['files'] if entry['path'] != asset])
                packed, checksum = self.bundle(overrides={asset: None,
                    'firmware-manifest.json': json.dumps(manifest).encode()})
                with self.assertRaisesRegex(ValueError, 'SDK|stock sysupgrade'):
                    self.run_import(packed, checksum)
                self.assertFalse((self.root / 'raw').exists())

    def test_sdk_profile_hash_must_match_even_when_inventory_hash_matches(self):
        profile = json.loads(self.profile_bytes)
        profile['sdk']['sha256'] = '0' * 64
        data = json.dumps(profile).encode()
        lock = dict(self.lock, sdk=profile['sdk'], profile_sha256=hashlib.sha256(data).hexdigest())
        packed, checksum = self.bundle(overrides={'profile.json': data, 'lock.json': json.dumps(lock).encode()})
        with self.assertRaisesRegex(ValueError, 'SDK.*checksum'):
            self.run_import(packed, checksum)
        self.assertFalse((self.root / 'raw').exists())

    def test_duplicate_sdk_archive_is_rejected_even_when_both_are_in_inventory(self):
        duplicate = self.target + 'second-sdk.tar.zst'
        data = b'other SDK archive'
        manifest = dict(self.manifest, files=self.manifest['files'] + [
            {'path': duplicate, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}])
        packed, checksum = self.bundle(overrides={duplicate: data,
            'firmware-manifest.json': json.dumps(manifest).encode()})
        with self.assertRaisesRegex(ValueError, 'exactly one.*SDK'):
            self.run_import(packed, checksum)
        self.assertFalse((self.root / 'raw').exists())

    def test_duplicate_stock_image_is_rejected_even_when_both_are_in_inventory(self):
        duplicate = self.target + 'other-xiaomi_redmi-router-ax6000-stock-squashfs-sysupgrade.bin'
        data = b'other stock image'
        manifest = dict(self.manifest, files=self.manifest['files'] + [
            {'path': duplicate, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}])
        packed, checksum = self.bundle(overrides={duplicate: data,
            'firmware-manifest.json': json.dumps(manifest).encode()})
        with self.assertRaisesRegex(ValueError, 'exactly one.*stock sysupgrade'):
            self.run_import(packed, checksum)
        self.assertFalse((self.root / 'raw').exists())


if __name__ == '__main__':
    unittest.main()
