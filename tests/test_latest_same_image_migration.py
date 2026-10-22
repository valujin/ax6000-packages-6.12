"""Finite policy metadata and tiny real TAR/FIT tests; never native acceptance."""
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from test_kernel_migration import image, sysupgrade

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT/'tests/fixtures/latest-same-image'
sha = lambda data: hashlib.sha256(data).hexdigest()


class LatestSameImage(unittest.TestCase):
    def setUp(self):
        path = ROOT/'scripts/latest_kernel_migration.py'
        self.assertTrue(path.is_file(), 'Finite LATEST same-Image helper missing')
        spec = importlib.util.spec_from_file_location('latest_policy_test', path)
        self.helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.helper)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = json.loads((FIXTURE/'metadata.json').read_text())
        spec = importlib.util.spec_from_file_location('latest_snapshot_test', ROOT/'scripts/channel-snapshot.py')
        self.snapshot = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.snapshot)
        self.old, self.new = (copy.deepcopy(self.data['profiles'][p]) for p in ('before', 'after'))

    def proof(self):
        return {'schema_version': 3, 'kind': 'asu-apk-native-migration', 'cohort': '612-latest',
                'predecessor_build_id': 'redmi-ax6000-612-latest-a99b0888b88f-0b1249707848',
                'successor_build_id': 'redmi-ax6000-612-latest-a99b0888b88f-31599e148e45',
                'source_commit': 'a99b0888b88f134f56bcb2a7d93027b5d20638a9',
                'kernel_version': '6.12.112~d405163bfdb42254c245797a894994c0-r1',
                'kernel_context': {name: {'before': copy.deepcopy(row), 'after': copy.deepcopy(row)}
                                   for name, row in self.data['context'].items()},
                'functional_image': {p: {'sha256': 'a1db81320a822eab661310185948456cef216faa7fac0a11d689ce61233a8681', 'size': 14661640}
                                     for p in ('before', 'after')},
                'reviewed_context': {'kind': 'latest-accepted-existing-context-v1',
                                     'native_acceptance_sha256': 'ef3920c9c2ac506d9a230c9eeda9d2b557d430c1673326a4f2fd0103cadf44f8',
                                     'root_decision_sha256': '4ba65dc1f31383a40f538ddc5c1c6ad29dc5ba12c7885771b04d9d5ac303a1e9',
                                     'hosted_context_sha256': '428ef4d3df486f2e9ad85876915c04e5749aad4d1662f1d4e43908ebae96930f'},
                'source_patches': {p: copy.deepcopy(self.data['source_patches']) for p in ('before', 'after')},
                'firmware_manifest_sha256': {'before': '459a7e06661b22e3b21a66ecb2e67d4416c3e0b1aef8c279305c97e0a1f49567',
                                             'after': '0f8095952e7e4444dc464865d4b9608f507b56035f67e8df01e90fc6bd7a3ff2'},
                'predecessor_pointer': copy.deepcopy(self.data['predecessor_pointer'])}

    def test_exact_existing_context_all_ten_roles_and_manifest_pair_are_accepted(self):
        self.helper.validate_receipt(self.old, self.new, self.proof())
        self.snapshot.validate_migration_proof(self.old, self.new, self.proof())
        self.snapshot.validate_asu_apk_migration(self.old, self.new)

    def test_each_missing_or_changed_context_role_or_full_image_is_refused(self):
        for role in self.data['context']:
            bad = self.proof(); bad['kernel_context'].pop(role)
            with self.subTest(role=role, change='missing'), self.assertRaises(ValueError):
                self.helper.validate_receipt(self.old, self.new, bad)
            for field, value in [('sha256', '0'*64), ('size', True)]:
                bad = self.proof(); bad['kernel_context'][role]['after'][field] = value
                with self.subTest(role=role, field=field), self.assertRaises(ValueError):
                    self.helper.validate_receipt(self.old, self.new, bad)
        bad = self.proof(); bad['functional_image']['after']['sha256'] = '0'*64
        with self.assertRaises(ValueError): self.helper.validate_receipt(self.old, self.new, bad)

    def test_other_channel_schema_source_authority_patch_or_manifest_is_refused(self):
        mutations = [lambda x: x.update(schema_version=True), lambda x: x.update(schema_version=2),
                     lambda x: x.update(cohort='612-recommended'), lambda x: x.update(source_commit='0'*40),
                     lambda x: x['reviewed_context'].update(root_decision_sha256='0'*64),
                     lambda x: x['source_patches']['after'].pop(),
                     lambda x: x['firmware_manifest_sha256'].update(before='0'*64),
                     lambda x: x['predecessor_pointer'].update(manifest_sha256='0'*64)]
        for mutation in mutations:
            bad = self.proof(); mutation(bad)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.helper.validate_receipt(self.old, self.new, bad)
        bad = copy.deepcopy(self.new); bad['firmware']['kernel_version'] = 'foreign'
        with self.assertRaises(ValueError): self.helper.validate_receipt(self.old, bad, self.proof())

    def trees(self):
        trees = {}
        for phase, profile in [('before', self.old), ('after', self.new)]:
            root = self.root/phase; root.mkdir(); trees[phase] = root
            (root/'profile.json').write_text(json.dumps(profile))
            (root/'firmware-manifest.json').write_bytes(gzip.decompress((FIXTURE/(phase+'-manifest.json.gz')).read_bytes()))
        return trees

    def test_wrong_live_pointer_refused_before_missing_manifest_fallback(self):
        trees = self.trees(); (trees['before']/'firmware-manifest.json').unlink()
        with self.assertRaisesRegex(ValueError, 'authenticated predecessor'):
            self.snapshot.validate_migration_manifests(trees['before'], trees['after'], self.proof(),
                predecessor_pointer=dict(self.data['predecessor_pointer'], asset_id=1))
        self.assertFalse((trees['before']/'firmware-manifest.json').exists())

    def test_actual_present_metadata_reaches_real_payload_guard_without_optional_sdk_compile(self):
        trees = self.trees()
        # These genuine manifests name firmware that this unit fixture does not
        # contain. The real decoder must refuse absent catalog/payload material.
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.snapshot.validate_migration_manifests(trees['before'], trees['after'], self.proof(),
                predecessor_pointer=self.data['predecessor_pointer'])
        self.assertEqual(sha((trees['before']/'firmware-manifest.json').read_bytes()),
                         '459a7e06661b22e3b21a66ecb2e67d4416c3e0b1aef8c279305c97e0a1f49567')

    def test_legacy_manifest_resolves_via_real_normal_guard_without_mutating_signed_tree(self):
        trees = self.trees(); original_manifest = (trees['before']/'firmware-manifest.json').read_bytes()
        (trees['before']/'firmware-manifest.json').unlink()
        (trees['before']/'downloads.json').write_bytes(gzip.decompress((FIXTURE/'catalog.json.gz').read_bytes()))
        (trees['before']/'downloads.sig').write_bytes((FIXTURE/'catalog.sig').read_bytes())
        original = {p.name: p.read_bytes() for p in trees['before'].iterdir()}
        release = self.data['release']; requests = []; outer = self
        class API:
            def __init__(self, repository): outer.assertEqual(repository, 'valujin/ax6000-packages-6.12')
            def get_release(self, identity):
                outer.assertEqual(identity, 419152056); return copy.deepcopy(release)
            def resolve_tag_commit(self, tag): return '6359d43b321f6049824a880a82081f93add13b98'
            def download_asset(self, remote, asset, path, expected_sha, expected_size):
                outer.assertEqual((asset['name'], expected_sha, expected_size),
                                 ('firmware-manifest.json', '459a7e06661b22e3b21a66ecb2e67d4416c3e0b1aef8c279305c97e0a1f49567', 327805))
                requests.append(asset['id']); Path(path).write_bytes(original_manifest)
        real_module = self.snapshot.module
        transport = types.SimpleNamespace(ReleaseAPI=API, release_identity=real_module('publication_api').release_identity)
        def module(name): return transport if name=='publication_api' else real_module(name)
        # Real full-payload validation follows the successful bounded metadata
        # fallback and refuses the deliberately absent actual firmware assets.
        with patch.object(self.snapshot, 'module', side_effect=module), self.assertRaisesRegex(ValueError, 'Missing/ambiguous catalog migration asset'):
            self.snapshot.validate_migration_manifests(trees['before'], trees['after'], self.proof(),
                predecessor_pointer=self.data['predecessor_pointer'])
        self.assertEqual(requests, [661318733])
        self.assertEqual({p.name: p.read_bytes() for p in trees['before'].iterdir()}, original)

    def tiny_pair(self):
        trees = {}; data = image(b'identical-kernel'); manifest_hashes = {}
        for phase, profile in [('before', self.old), ('after', self.new)]:
            root = self.root/phase; target = root/'bin/targets/mediatek/filogic'; target.mkdir(parents=True); trees[phase] = root
            (root/'profile.json').write_text(json.dumps(profile)); files = []
            for layout in ('stock', 'mtkuboot', 'ubootmod'):
                name = 'immortalwrt-xiaomi_redmi-router-ax6000-'+layout+'-squashfs-sysupgrade'+('.itb' if layout=='ubootmod' else '.bin')
                payload = sysupgrade(layout, data); (target/name).write_bytes(payload)
                files.append({'path': 'bin/targets/mediatek/filogic/'+name, 'sha256': sha(payload), 'size': len(payload)})
            manifest = {'build_id': profile['build_id'], 'source_commit': profile['firmware']['commit'],
                        'kernel_version': profile['firmware']['kernel_version'], 'source_patches': self.data['source_patches'], 'files': files}
            raw = json.dumps(manifest).encode(); (root/'firmware-manifest.json').write_bytes(raw); manifest_hashes[phase] = sha(raw)
        proof = self.proof(); identity = {'sha256': sha(data), 'size': len(data)}
        proof['functional_image'] = {p: copy.deepcopy(identity) for p in ('before', 'after')}
        proof['kernel_context']['retained/Image'] = copy.deepcopy(proof['functional_image'])
        proof['firmware_manifest_sha256'] = manifest_hashes
        return trees, proof, identity

    def test_tiny_real_six_tar_fit_payloads_and_cached_after_asset_corruption(self):
        trees, proof, identity = self.tiny_pair()
        # Only policy data is scoped to tiny synthetic identities. Guard and
        # TAR/FIT implementations execute unchanged; no acceptance is issued.
        context = copy.deepcopy(self.data['context']); context['retained/Image'] = identity
        with patch.object(self.helper, 'MANIFESTS', proof['firmware_manifest_sha256']), patch.object(self.helper, 'IMAGE', identity), patch.object(self.helper, 'CONTEXT', context):
            self.helper.validate_manifests(self.snapshot, trees['before'], trees['after'], proof,
                                           self.data['predecessor_pointer'])
            path = next((trees['after']/'bin/targets/mediatek/filogic').iterdir())
            path.write_bytes(path.read_bytes()[:-1]+b'!')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                self.helper.validate_manifests(self.snapshot, trees['before'], trees['after'], proof,
                                               self.data['predecessor_pointer'])

    def test_corrupt_or_linked_present_manifest_never_uses_legacy_fallback(self):
        trees = self.trees(); path = trees['before']/'firmware-manifest.json'
        original = path.read_bytes()
        for mode in ('corrupt', 'linked'):
            if path.exists() or path.is_symlink(): path.unlink()
            if mode == 'corrupt': path.write_bytes(original+b' ')
            else:
                outside = self.root/'elsewhere'; outside.write_bytes(original); path.symlink_to(outside)
            with self.subTest(mode=mode), patch.object(self.snapshot, 'legacy_migration_metadata') as fallback:
                with self.assertRaises(ValueError):
                    self.snapshot.validate_migration_manifests(trees['before'], trees['after'], self.proof(),
                        predecessor_pointer=self.data['predecessor_pointer'])
                fallback.assert_not_called()

    def test_new_valid_archive_and_manifest_cannot_hide_changed_complete_image(self):
        trees, proof, identity = self.tiny_pair()
        path = next((trees['after']/'bin/targets/mediatek/filogic').iterdir())
        replacement = sysupgrade('stock', image(b'changed-kernel'))
        path.write_bytes(replacement)
        manifest_path = trees['after']/'firmware-manifest.json'
        manifest = json.loads(manifest_path.read_bytes())
        manifest['files'][0].update(sha256=sha(replacement), size=len(replacement))
        raw = json.dumps(manifest).encode(); manifest_path.write_bytes(raw)
        proof['firmware_manifest_sha256']['after'] = sha(raw)
        context = copy.deepcopy(self.data['context']); context['retained/Image'] = identity
        with patch.object(self.helper, 'MANIFESTS', proof['firmware_manifest_sha256']), patch.object(self.helper, 'IMAGE', identity), patch.object(self.helper, 'CONTEXT', context):
            with self.assertRaisesRegex(ValueError, 'full functional Image differs'):
                self.helper.validate_manifests(self.snapshot, trees['before'], trees['after'], proof,
                                               self.data['predecessor_pointer'])

    def test_projection_rejects_wrong_actual_metadata_and_does_not_emit_proof(self):
        accepted = self.root/'accepted.json'; accepted.write_text('{}')
        # A present but wrongly authenticated first input must fail before any
        # later file can be consumed; this is not an acceptance fixture.
        with self.assertRaisesRegex(ValueError, 'metadata checksum differs'):
            self.helper.from_accepted_metadata({'accepted_status': accepted})
        output = self.root/'result.json'
        args = ['latest-kernel-migration', '--execute', '--output', str(output)]
        for name in ('accepted-status', 'root-decision', 'hosted-context', 'old-profile',
                     'new-profile', 'old-manifest', 'new-manifest', 'old-snapshot'):
            args += ['--'+name, str(accepted)]
        with patch('sys.argv', args), self.assertRaisesRegex(ValueError, 'overlaps'):
            self.helper.main()
        self.assertFalse(output.exists())

    def test_default_generator_is_inert(self):
        import contextlib, io
        stream = io.StringIO()
        with patch('sys.argv', ['latest-kernel-migration']), contextlib.redirect_stdout(stream): self.helper.main()
        self.assertEqual(json.loads(stream.getvalue()), {'execute': False, 'publication_performed': False})

if __name__ == '__main__': unittest.main()
