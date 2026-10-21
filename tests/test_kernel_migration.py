"""Independent TAR/FIT fixtures; none authorize a production migration."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest

from test_fit_payload import fit_fixture

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import kernel_migration as migration


def sha(data):
    return hashlib.sha256(data).hexdigest()


def image(marker):
    data = bytearray(128)
    data[56:60] = b'ARM\x64'
    data[64:64 + len(marker)] = marker
    return bytes(data)


def sysupgrade(layout, data, *, bad_hash=False):
    fit = fit_fixture(external=layout == 'ubootmod', kernel_data=data, bad_hash=bad_hash)
    if layout == 'ubootmod':
        return fit
    prefix = 'sysupgrade-xiaomi_redmi-router-ax6000-' + layout
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo(prefix)
        member.type = tarfile.DIRTYPE
        archive.addfile(member)
        for name, value in {'CONTROL': ('BOARD=xiaomi_redmi-router-ax6000-' + layout + '\n').encode(),
                            'kernel': fit, 'root': b'hsqs' + bytes(4092)}.items():
            member = tarfile.TarInfo(prefix + '/' + name)
            member.size = len(value)
            archive.addfile(member, io.BytesIO(value))
    return stream.getvalue() + b'outer-metadata-is-bound-by-the-full-asset-SHA'


class NativeMigrationPayloads(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def phase(self, phase):
        root = self.root / phase
        target = root / 'bin/targets/mediatek/filogic'
        target.mkdir(parents=True)
        data = image(phase.encode())
        assets = []
        for layout in migration.LAYOUTS:
            name = ('immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-' + layout
                    + '-squashfs-sysupgrade' + ('.itb' if layout == 'ubootmod' else '.bin'))
            payload = sysupgrade(layout, data)
            (target / name).write_bytes(payload)
            assets.append({'path': 'bin/targets/mediatek/filogic/' + name,
                           'sha256': sha(payload), 'size': len(payload)})
        manifest = root / 'firmware-manifest.json'
        manifest.write_text(json.dumps({'files': assets}))
        return root, {'size': len(data), 'sha256': sha(data)}, sha(manifest.read_bytes())

    def setup_pair(self):
        before, old, old_manifest = self.phase('before')
        after, new, new_manifest = self.phase('after')
        proof = {'predecessor_build_id': 'fixture-before', 'successor_build_id': 'fixture-after',
                 'functional_image': {'before': old, 'after': new},
                 'firmware_manifest_sha256': {'before': old_manifest, 'after': new_manifest}}
        return [('before', before), ('after', after)], proof

    @staticmethod
    def read(path):
        return json.loads(Path(path).read_text())

    def validate(self, pair, proof, *, cache=None, transport=None, budget=None):
        migration.validate_payloads(pair, proof, self.read, transport,
                                    {} if cache is None else cache, {'used': 0} if budget is None else budget)

    def test_actual_tar_inline_and_external_fit_full_images_match_all_six_payloads(self):
        pair, proof = self.setup_pair()
        cache = {}
        self.validate(pair, proof, cache=cache)
        self.assertEqual(len(cache), 6)
        self.validate(pair, proof, cache=cache)

    def test_changed_local_asset_rejected_even_after_successful_memoization(self):
        pair, proof = self.setup_pair()
        cache = {}
        self.validate(pair, proof, cache=cache)
        path = next((pair[0][1] / 'bin/targets/mediatek/filogic').iterdir())
        path.write_bytes(path.read_bytes()[:-1] + b'X')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.validate(pair, proof, cache=cache)

    def test_whole_image_mismatch_and_fit_payload_corruption_rejected(self):
        pair, proof = self.setup_pair()
        proof['functional_image']['after']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'full functional Image'):
            self.validate(pair, proof)
        path = self.root / 'bad.itb'
        path.write_bytes(sysupgrade('ubootmod', image(b'bad'), bad_hash=True))
        with self.assertRaisesRegex(ValueError, 'FIT payload hash'):
            migration.functional_image(path, 'ubootmod', self.root / 'bad-fit-work')

    def test_foreign_tar_board_symlink_and_missing_layout_rejected(self):
        path = self.root / 'wrong.bin'
        data = sysupgrade('stock', image(b'board'))
        path.write_bytes(data.replace(b'BOARD=xiaomi_redmi-router-ax6000-stock', b'BOARD=xiaomi_redmi-router-ax6000-wrong'))
        with self.assertRaisesRegex(ValueError, 'board'):
            migration.functional_image(path, 'stock', self.root / 'wrong-work')
        link = self.root / 'link.bin'
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, 'regular'):
            migration.functional_image(link, 'stock', self.root / 'link-work')
        with self.assertRaisesRegex(ValueError, 'all three'):
            migration.manifest_assets({'files': []})

    def remote_transport(self, pair):
        releases = {}
        payloads = {}
        counter = {'downloads': 0}
        for number, (phase, root) in enumerate(pair, 1):
            catalog = {'release': {'id': number, 'tag': 'firmware-fixture-' + phase, 'recipe_commit': 'a' * 40}, 'assets': []}
            remote = []
            for index, record in enumerate(self.read(root / 'firmware-manifest.json')['files'], 1):
                name = Path(record['path']).name
                layout = next(x for x in migration.LAYOUTS if '-' + x + '-squashfs-' in name)
                catalog['assets'].append({'filename': name, 'kind': 'sysupgrade', 'layout': layout,
                                          'sha256': record['sha256'], 'size': record['size'],
                                          'asset_id': index, 'updated_at': 'unchanged'})
                remote.append({'name': name, 'id': index, 'updated_at': 'unchanged', 'state': 'uploaded',
                               'size': record['size'], 'digest': 'sha256:' + record['sha256']})
                path = root / record['path']
                payloads[number, name] = path.read_bytes()
                path.unlink()
            (root / 'downloads.json').write_text(json.dumps(catalog))
            releases[number] = {'id': number, 'tag_name': catalog['release']['tag'], 'draft': False,
                                'immutable': True, 'assets': remote}
        class API:
            def __init__(self, repository):
                assert repository == 'valujin/ax6000-packages-6.12'
            def get_release(self, identity):
                return copy.deepcopy(releases[identity])
            def resolve_tag_commit(self, tag):
                return 'a' * 40
            def download_asset(self, release, asset, destination, digest, size):
                counter['downloads'] += 1
                Path(destination).write_bytes(payloads[release['id'], asset['name']])
        return types.SimpleNamespace(ReleaseAPI=API, release_identity=lambda r: json.dumps(r, sort_keys=True)), counter, releases

    def test_signed_remote_identity_cache_avoids_duplicate_downloads_but_rechecks_metadata(self):
        pair, proof = self.setup_pair()
        transport, counts, releases = self.remote_transport(pair)
        cache = {}
        budget = {'used': 0}
        self.validate(pair, proof, cache=cache, transport=transport, budget=budget)
        self.assertEqual(counts['downloads'], 6)
        self.validate(pair, proof, cache=cache, transport=transport, budget=budget)
        self.assertEqual(counts['downloads'], 6)
        releases[1]['assets'][0]['digest'] = 'sha256:' + 'f' * 64
        with self.assertRaisesRegex(ValueError, 'metadata differs'):
            self.validate(pair, proof, cache=cache, transport=transport, budget=budget)

    def test_manifest_and_aggregate_download_caps_fail_before_any_transport(self):
        pair, proof = self.setup_pair()
        proof['firmware_manifest_sha256']['after'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'manifest checksum'):
            self.validate(pair, proof)
        for phase, tree in pair:
            manifest = self.read(tree / 'firmware-manifest.json')
            for item in manifest['files']:
                item['size'] = 100 * migration.MIB
            (tree / 'firmware-manifest.json').write_text(json.dumps(manifest))
            proof['firmware_manifest_sha256'][phase] = sha((tree / 'firmware-manifest.json').read_bytes())
        with self.assertRaisesRegex(ValueError, 'Aggregate'):
            self.validate(pair, proof)


if __name__ == '__main__':
    unittest.main()
