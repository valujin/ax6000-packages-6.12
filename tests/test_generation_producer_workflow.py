"""Tiny Git/signed transport fixtures; no network or native artifact access."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_apk_workflows import shell_blocks
from test_channel_snapshot import snapshot
import test_import_release as import_fixtures
import test_channel_snapshot as signed_fixtures
release = import_fixtures.release

ROOT = Path(__file__).resolve().parents[1]


class ProducerProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'git'; self.repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        self.name = 'profiles/redmi-ax6000-612-recommended-new.json'
        self.profile = {'id': 'redmi-ax6000-612-recommended', 'channel': 'recommended',
                        'asu': {'enabled': True, 'seed': '0' * 64}}
        self.write('scripts/example.py', b'original producer code')
        self.write(self.name, json.dumps(self.profile).encode())
        first = self.commit()
        native = snapshot.module('native_generation')
        self.profile['asu']['seed'] = native.producer_seed(self.repo, first, self.profile)
        self.write(self.name, json.dumps(self.profile).encode()); self.producer = self.commit()
        self.expected = (self.repo / self.name).read_bytes()
        self.catalog = {'channel': 'recommended', 'profile_id': self.profile['id'], 'build_id': 'native-build',
                        'release': {'repository': 'valujin/ax6000-packages-6.12', 'recipe_commit': self.producer,
                                    'tag': 'firmware-native-build'}}
        self.write('scripts/example.py', b'later publisher code')
        later = self.commit(); self.profile['asu']['seed'] = native.producer_seed(self.repo, later, self.profile)
        self.write(self.name, json.dumps(self.profile).encode()); self.commit()

    def write(self, name, data):
        path = self.repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)

    def commit(self):
        subprocess.run(['git', '-C', str(self.repo), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', 'fixture'], check=True)
        return subprocess.check_output(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'], text=True).strip()

    def select(self, catalog=None, channel='recommended'):
        if not hasattr(snapshot, 'select_generation_profile'):
            self.fail('Authenticated producer profile selector is missing')
        return snapshot.select_generation_profile(catalog or self.catalog, 'valujin/ax6000-packages-6.12', channel,
                                                    self.root / 'selected', recipe=self.repo)

    def test_exact_git_producer_profile_ignores_changed_publisher_seed_and_never_executes_blob(self):
        self.select()
        self.assertEqual((self.root / 'selected/producer-profile.json').read_bytes(), self.expected)
        self.assertNotEqual(json.loads(self.expected)['asu']['seed'], self.profile['asu']['seed'])
        receipt = json.loads((self.root / 'selected/producer-profile-proof.json').read_text())
        self.assertEqual(receipt['producer_commit'], self.producer)
        self.assertEqual(receipt['source_profile_sha256'], hashlib.sha256(self.expected).hexdigest())

    def test_foreign_repository_channel_or_noncommit_producer_fields_fail_before_fetch(self):
        for mutate in (lambda x: x['release'].update(repository='foreign/repo'),
                       lambda x: x['release'].update(recipe_commit='main'),
                       lambda x: x.update(channel='latest'),
                       lambda x: x.update(profile_id='foreign')):
            bad = copy.deepcopy(self.catalog); mutate(bad)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.select(bad)
            self.assertFalse((self.root / 'selected').exists())

    def test_missing_native_seed_or_source_profile_drift_refuses(self):
        # A valid Git commit does not excuse a seed computed from different code.
        self.catalog['release']['recipe_commit'] = self.commit_if_changed_bad_seed()
        with self.assertRaisesRegex(ValueError, 'seed'): self.select()
        self.assertFalse((self.root / 'selected').exists())

    def test_cache_miss_fetches_only_the_authenticated_commit_from_fixed_repository(self):
        calls = []; real_run = snapshot.subprocess.run
        def controlled(command, **options):
            if command[3:5] == ['cat-file', '-e']:
                return subprocess.CompletedProcess(command, 1)
            if command[3:4] == ['fetch']:
                calls.append(command)
                return subprocess.CompletedProcess(command, 0)
            return real_run(command, **options)
        with patch.object(snapshot.subprocess, 'run', side_effect=controlled): self.select()
        self.assertEqual(calls, [['/usr/bin/git', '-C', str(self.repo), 'fetch', '--no-tags', '--depth=1',
                                  'https://github.com/valujin/ax6000-packages-6.12.git', self.producer]])
        self.assertEqual((self.root / 'selected/producer-profile.json').read_bytes(), self.expected)

    def commit_if_changed_bad_seed(self):
        self.profile['asu']['seed'] = 'f' * 64
        self.write(self.name, json.dumps(self.profile).encode())
        return self.commit()


class ImportedProducerTests(unittest.TestCase):
    def test_known_b122_seed_is_checked_against_declared_profile_not_publisher_profile(self):
        fixture = import_fixtures.ReleaseImportTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        profile = copy.deepcopy(fixture.profile)
        profile['asu'] = {'enabled': True, 'cohort': '66', 'server_url': 'https://asu.ezon.by/66',
                          'seed': '3254dd70ea96217f41221b29998780639bbf2e7f33deb735c8bd7b380274c4e3'}
        fixture.profile = profile; fixture.profile_bytes = json.dumps(profile).encode()
        fixture.lock['profile_sha256'] = hashlib.sha256(fixture.profile_bytes).hexdigest()
        fixture.expected.write_text(json.dumps(profile))
        producer = 'b122c35046ab1c3cd03828aabd168bb35466e2c8'
        fixture.manifest['recipe_commit'] = producer
        packed, checksum = fixture.bundle()
        try:
            release.import_bundle(packed, checksum, fixture.root / 'raw', fixture.expected, expected_producer_commit=producer)
        except TypeError:
            self.fail('RAW import cannot bind its authenticated producer commit/profile')
        for change in ('producer', 'seed'):
            profile2 = copy.deepcopy(profile); manifest = copy.deepcopy(fixture.manifest)
            if change == 'producer': manifest['recipe_commit'] = '0' * 40
            else: profile2['asu']['seed'] = 'e' * 64
            fixture.profile_bytes = json.dumps(profile2).encode(); fixture.lock['profile_sha256'] = hashlib.sha256(fixture.profile_bytes).hexdigest()
            fixture.manifest = manifest; packed, checksum = fixture.bundle()
            with self.subTest(change=change), self.assertRaises(ValueError):
                release.import_bundle(packed, checksum, fixture.root / ('bad-' + change), fixture.expected, expected_producer_commit=producer)
            self.assertFalse((fixture.root / ('bad-' + change)).exists())


class NativeProofTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_block(self, **changes):
        blocks = shell_blocks('publish-existing.yml')
        name = 'Prepare the operator-reviewed native APK replacement receipt'
        self.assertIn(name, blocks, 'Separate native proof transport is missing')
        code = blocks[name].split("<<'PYCODE'\n", 1)[1].rsplit('\nPYCODE', 1)[0]
        raw = b'{"schema_version":1,"kind":"rec-native-apk-generation-transition-v1","summary":{"actual":"operator reviewed"}}'
        env = dict(os.environ, RUNNER_TEMP=str(self.root), GITHUB_OUTPUT=str(self.root / 'outputs'),
                   ALLOW_NATIVE_APK_REPLACEMENT='true', ALLOW_ASU_APK_MIGRATION='false', CHANNEL='recommended',
                   BOOTSTRAP='false', REPLACE_BUILD_ID='actual-live-build',
                   NATIVE_REPLACEMENT_PROOF_BASE64=base64.b64encode(raw).decode(),
                   NATIVE_REPLACEMENT_PROOF_SHA256=hashlib.sha256(raw).hexdigest())
        env.update(changes)
        return subprocess.run([sys.executable, '-'], input=code, env=env, cwd=self.root, capture_output=True, text=True), raw

    def test_actual_bytes_sha_and_private_file_transport_are_preserved(self):
        result, raw = self.run_block(); self.assertEqual(result.returncode, 0, result.stderr)
        path = self.root / 'native-replacement-proof.json'
        self.assertEqual(path.read_bytes(), raw); self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn('sha256=' + hashlib.sha256(raw).hexdigest(), (self.root / 'outputs').read_text())

    def test_exact_v2_pair_preserves_full_bytes_and_all_authorization_guards(self):
        raw = b'{"schema_version":2,"kind":"rec-native-apk-generation-transition-v2","summary":{"actual":"operator reviewed new context"}}'
        values = {'NATIVE_REPLACEMENT_PROOF_BASE64': base64.b64encode(raw).decode(),
                  'NATIVE_REPLACEMENT_PROOF_SHA256': hashlib.sha256(raw).hexdigest()}
        result, _ = self.run_block(**values)
        self.assertEqual(result.returncode, 0, result.stderr)
        path = self.root / 'native-replacement-proof.json'
        self.assertEqual(path.read_bytes(), raw); self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.unlink(); (self.root / 'outputs').unlink()
        for changes in ({'ALLOW_NATIVE_APK_REPLACEMENT': 'false'}, {'REPLACE_BUILD_ID': ''}, {'CHANNEL': 'latest'},
                        {'ALLOW_ASU_APK_MIGRATION': 'true'}, {'BOOTSTRAP': 'true'},
                        {'NATIVE_REPLACEMENT_PROOF_SHA256': '0' * 64}):
            with self.subTest(changes=changes):
                result, _ = self.run_block(**{**values, **changes}); self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists()); self.assertFalse((self.root / 'outputs').exists())

    def test_crossed_unknown_and_noninteger_native_transport_pairs_are_rejected(self):
        for schema, kind in ((1, 'rec-native-apk-generation-transition-v2'),
                             (2, 'rec-native-apk-generation-transition-v1'),
                             (3, 'rec-native-apk-generation-transition-v2'),
                             (2, 'unknown'), ('2', 'rec-native-apk-generation-transition-v2'),
                             (True, 'rec-native-apk-generation-transition-v1')):
            raw = json.dumps({'schema_version': schema, 'kind': kind, 'summary': {}}).encode()
            with self.subTest(schema=schema, kind=kind):
                result, _ = self.run_block(NATIVE_REPLACEMENT_PROOF_BASE64=base64.b64encode(raw).decode(),
                                           NATIVE_REPLACEMENT_PROOF_SHA256=hashlib.sha256(raw).hexdigest())
                self.assertNotEqual(result.returncode, 0); self.assertFalse((self.root / 'native-replacement-proof.json').exists())
                self.assertFalse((self.root / 'outputs').exists())

    def test_absent_flag_sha_predecessor_wrong_channel_conflict_bootstrap_or_invalid_json_refuse(self):
        for changes in ({'ALLOW_NATIVE_APK_REPLACEMENT': 'false'}, {'REPLACE_BUILD_ID': ''}, {'CHANNEL': 'latest'},
                        {'ALLOW_ASU_APK_MIGRATION': 'true'}, {'BOOTSTRAP': 'true'}, {'NATIVE_REPLACEMENT_PROOF_SHA256': ''},
                        {'NATIVE_REPLACEMENT_PROOF_SHA256': '0' * 64}, {'NATIVE_REPLACEMENT_PROOF_BASE64': '!bad'},
                        {'NATIVE_REPLACEMENT_PROOF_BASE64': base64.b64encode(b'{"a":1,"a":2}').decode()},
                        {'NATIVE_REPLACEMENT_PROOF_BASE64': base64.b64encode(b'[]').decode()},
                        {'NATIVE_REPLACEMENT_PROOF_BASE64': base64.b64encode(b'x' * 65537).decode()}):
            with self.subTest(changes=changes):
                result, _ = self.run_block(**changes); self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'native-replacement-proof.json').exists())
                self.assertFalse((self.root / 'outputs').exists())

    def test_default_does_not_require_proof_and_strict_json_failures_are_checked_after_matching_sha(self):
        result, _ = self.run_block(ALLOW_NATIVE_APK_REPLACEMENT='false', NATIVE_REPLACEMENT_PROOF_BASE64='',
                                   NATIVE_REPLACEMENT_PROOF_SHA256='')
        self.assertEqual(result.returncode, 0, result.stderr)
        for raw in (b'{"a":1,"a":2}', b'{"x":{"a":1,"a":2}}', b'{"x":NaN}', b'[]',
                    b'{"schema_version":true,"kind":"rec-native-apk-generation-transition-v1","summary":{}}',
                    b'{"schema_version":1,"kind":"wrong","summary":{}}'):
            with self.subTest(raw=raw):
                result, _ = self.run_block(NATIVE_REPLACEMENT_PROOF_BASE64=base64.b64encode(raw).decode(),
                                           NATIVE_REPLACEMENT_PROOF_SHA256=hashlib.sha256(raw).hexdigest())
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'native-replacement-proof.json').exists())


@unittest.skipUnless(os.environ.get('USIGN'), 'Set USIGN to the trusted official host tool')
class AuthenticatedProducerTests(unittest.TestCase):
    def test_forged_signed_catalog_producer_is_rejected_by_actual_tag_before_git_selection(self):
        fixture = signed_fixtures.ChannelSnapshots(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        tree, _ = fixture.channel('recommended')
        original = snapshot.read_json(tree / 'downloads.json')
        api_module = snapshot.module('publication_api'); real_loader = snapshot.module
        for forged in (False, True):
            catalog = copy.deepcopy(original)
            if forged: catalog['release']['recipe_commit'] = 'b' * 40
            (tree / 'downloads.json').write_text(json.dumps(catalog)); fixture.sign(tree / 'downloads.json', tree / 'downloads.sig')
            payloads = {'raw.tar.zst': b'never imported fixture', 'raw.tar.zst.sha256': b'fixture checksum',
                        'downloads.json': (tree / 'downloads.json').read_bytes(), 'downloads.sig': (tree / 'downloads.sig').read_bytes()}
            release_meta = {'id': catalog['release']['id'], 'tag_name': catalog['release']['tag'], 'draft': False, 'immutable': True,
                            'assets': [{'id': 100 + i, 'name': name, 'size': len(data), 'state': 'uploaded',
                                        'digest': 'sha256:' + hashlib.sha256(data).hexdigest(), 'updated_at': 'now'}
                                       for i, (name, data) in enumerate(payloads.items())]}
            def download(_client, _release, asset, destination, _digest, _size):
                Path(destination).write_bytes(payloads[asset['name']])
            with patch.object(snapshot, 'module', side_effect=lambda name: api_module if name == 'publication_api' else real_loader(name)), \
                 patch.object(api_module.ReleaseAPI, 'get_release', side_effect=[release_meta, copy.deepcopy(release_meta)]), \
                 patch.object(api_module.ReleaseAPI, 'resolve_tag_commit', return_value=fixture.recipe), \
                 patch.object(api_module.ReleaseAPI, 'download_asset', new=download), \
                 patch.object(snapshot, 'select_generation_profile') as selected:
                output = fixture.root / ('forged' if forged else 'valid')
                if forged:
                    with self.assertRaisesRegex(ValueError, 'tag target'):
                        snapshot.fetch_generation(catalog['release']['tag'], fixture.repository, fixture.public, os.environ['USIGN'], output, channel='recommended')
                    selected.assert_not_called(); self.assertFalse(output.exists())
                else:
                    snapshot.fetch_generation(catalog['release']['tag'], fixture.repository, fixture.public, os.environ['USIGN'], output, channel='recommended')
                    self.assertEqual(selected.call_args.args[0]['release']['recipe_commit'], fixture.recipe)
