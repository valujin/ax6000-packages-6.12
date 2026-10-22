"""Offline finite activation guards. No production native acceptance is issued.

The normal-delegation cases use existing synthetic portable metadata, execute
real normal guards, and deliberately stop before absent sysupgrade payloads.
Only the fresh live HTTP boundary is substituted; no crypto/build is simulated.
"""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_native_generation as native_fixtures

ROOT = Path(__file__).resolve().parents[1]


def encode(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


class NativeActivation(unittest.TestCase):
    helper = native_fixtures.NativeProfiles.helper
    file = native_fixtures.ActualFiles.file
    portable_fixture = native_fixtures.ActualFiles.portable_fixture

    def setUp(self):
        path = ROOT / 'scripts/activate-native-generation.py'
        self.assertTrue(path.is_file(), 'Finite native activation entry point is missing')
        spec = importlib.util.spec_from_file_location('finite_native_activation_test', path)
        self.activation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.activation)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.n = self.helper()
        self.snapshot = self.n.module('channel-snapshot')

    def ticket(self):
        return {'schema_version': 1, 'kind': 'rec-b122-publication-activation-authorization',
                'eligible_for_normal_activation': True, 'snapshot_sha256': '1' * 64,
                'profile_sha256': 'a3575ff580b2495e5fde0b9d2164e8a84b27e65e0a0bf95d973954603818adb9',
                'native_status_sha256': 'e7bfbf6ad2698eb05718b0c379c81468b681a5f84b07161d9da252dcc979dbf6',
                'native_evidence_sha256': 'c71d134343482bd84c8cb9d465aeebdec38a203d4d53b20730186a3f68da46e0',
                'sdk_sha256': '50a1bd72eee117acf22d353e11b93930820f3a5c72fbf1cead663043320b163d',
                'imagebuilder_sha256': '952871ae7a71285445fd68c01df13ee68b9be51da1d51ef0e2b9fe549adcb5e2',
                'tail_sha256': '4600a0a499dd8484247c8217adf5f6a43cb86b44528c1afeec954ae188287a00',
                'client_evidence_sha256': '2' * 64, 'smoke_evidence_sha256': '3' * 64,
                'portable_proof_sha256': '4' * 64,
                'predecessor_pointer': {'manifest_sha256': '5' * 64},
                'latest_pointer': {'manifest_sha256': '6' * 64},
                'pointer': {'manifest_sha256': '1' * 64,
                            'build_id': 'redmi-ax6000-612-recommended-ae65e1de6997-50a1bd72eee1'}}

    def check_ticket(self, ticket):
        self.activation.validate_ticket(ticket, ticket['pointer'], '5' * 64, '4' * 64)

    def test_ticket_binds_native_generation_signed_snapshot_and_actual_acceptance_digests(self):
        self.check_ticket(self.ticket())
        for key in ('profile_sha256', 'native_status_sha256', 'native_evidence_sha256',
                    'sdk_sha256', 'imagebuilder_sha256', 'tail_sha256'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check_ticket(dict(self.ticket(), **{key: '0' * 64}))
        for key, value in (('schema_version', True), ('eligible_for_normal_activation', False),
                           ('client_evidence_sha256', None), ('smoke_evidence_sha256', 'pending'),
                           ('portable_proof_sha256', '0' * 64), ('snapshot_sha256', '0' * 64)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check_ticket(dict(self.ticket(), **{key: value}))
        extra = self.ticket(); extra['unreviewed'] = True
        with self.assertRaises(ValueError): self.check_ticket(extra)

    def test_proof_transport_rejects_wrong_kind_schema_duplicate_and_nonfinite_json(self):
        good = {'schema_version': 2, 'kind': 'rec-native-apk-generation-transition-v2', 'summary': {}}
        self.activation.validate_proof_transport(self.activation.decode_json(encode(good), 65536))
        for proof in (dict(good, schema_version=1), dict(good, schema_version=True),
                      dict(good, kind='rec-native-apk-generation-transition-v1'), dict(good, summary=[])):
            with self.subTest(proof=proof), self.assertRaises(ValueError):
                self.activation.validate_proof_transport(proof)
        for raw in (b'{"ok":true,"ok":false}', b'{"v":NaN}', b'{"v":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.activation.decode_json(base64.b64encode(raw).decode(), 65536)

    def test_decoded_and_encoded_caps_reject_before_any_external_file_access(self):
        exact = b'"' + b'a' * 65534 + b'"'
        self.assertEqual(len(self.activation.decode_json(base64.b64encode(exact).decode(), 65536)), 65534)
        for encoded in (base64.b64encode(exact + b' ').decode(), '!' * 100000,
                        base64.b64encode(b'{}').decode() + '\n', ''):
            with self.subTest(size=len(encoded)), self.assertRaises(ValueError):
                self.activation.decode_json(encoded, 65536)

    def test_stale_predecessor_or_unrelated_latest_is_refused(self):
        ticket = self.ticket()
        previous = {'channels': {'recommended': ticket['predecessor_pointer'], 'latest': ticket['latest_pointer']}}
        self.activation.require_live_predecessor(previous, ticket, '5' * 64)
        for channel in ('recommended', 'latest'):
            changed = copy.deepcopy(previous); changed['channels'][channel]['manifest_sha256'] = '0' * 64
            with self.subTest(channel=channel), self.assertRaises(ValueError):
                self.activation.require_live_predecessor(changed, ticket, '5' * 64)
        with self.assertRaises(ValueError): self.activation.require_live_predecessor(None, ticket, '5' * 64)

    def test_fresh_http_state_boundary_detects_post_composition_race(self):
        previous = {'channels': {'recommended': {'manifest_sha256': '5' * 64}, 'latest': {'manifest_sha256': '6' * 64}}}
        with patch.object(self.snapshot, 'fetch_live', return_value=copy.deepcopy(previous)):
            self.activation.require_live_unchanged(self.snapshot, previous, 'https://fixture.invalid',
                                                   self.root/'public', self.root/'usign', self.root)
        changed = copy.deepcopy(previous); changed['channels']['latest']['manifest_sha256'] = '0' * 64
        with patch.object(self.snapshot, 'fetch_live', return_value=changed), self.assertRaises(ValueError):
            self.activation.require_live_unchanged(self.snapshot, previous, 'https://fixture.invalid',
                                                   self.root/'public', self.root/'usign', self.root)

    def fixture_proof(self):
        old, new, proof, pointer, trees = self.portable_fixture()
        row = self.file('portable.json', json.dumps(proof).encode())
        return old, new, pointer, trees, Path(row['path']), row['sha256']

    def test_real_normal_native_guard_rejects_wrong_authenticated_predecessor(self):
        old, new, pointer, trees, path, pin = self.fixture_proof()
        with self.assertRaisesRegex(ValueError, 'predecessor differs from authenticated live pointer'):
            self.activation.authorize_transition(self.snapshot, old, new, trees['before'], trees['after'],
                                                  dict(pointer, manifest_sha256='0'*64), path, pin)

    def test_real_normal_metadata_guard_refuses_mutated_native_manifest(self):
        old, new, pointer, trees, path, pin = self.fixture_proof()
        manifest = trees['after']/'firmware-manifest.json'; manifest.write_bytes(manifest.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError, 'Publication tree differs from reviewed native proof'):
            self.activation.authorize_transition(self.snapshot, old, new, trees['before'], trees['after'], pointer, path, pin)

    def test_real_whole_image_guard_requires_all_actual_sysupgrade_payloads(self):
        old, new, pointer, trees, path, pin = self.fixture_proof()
        with self.assertRaisesRegex(ValueError, 'requires all three actual sysupgrades'):
            self.activation.authorize_transition(self.snapshot, old, new, trees['before'], trees['after'], pointer, path, pin)

    def test_explicit_scripts_import_context_loads_real_prepare_dependencies_offline(self):
        code = ("import importlib.util,json; from pathlib import Path; "
                "spec=importlib.util.spec_from_file_location('context_prepare'," + repr(str(ROOT/'scripts/prepare.py')) + "); "
                "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); "
                "profile=json.loads(Path(" + repr(str(ROOT/'profiles/redmi-ax6000-612-recommended-b122.json')) + ").read_text()); "
                "module.validate_channel_inputs(profile,{x['name']:x['commit'] for x in profile['feeds']}); "
                "import firmware_layouts; print(json.dumps([module.__file__,firmware_layouts.__file__]))")
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        env.pop('PYTHONPATH', None)
        absent = subprocess.run([sys.executable, '-c', code], cwd=self.root, env=env, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(absent.returncode, 0)
        self.assertIn("No module named 'firmware_layouts'", absent.stderr)
        env['PYTHONPATH'] = str(ROOT/'scripts')
        present = subprocess.run([sys.executable, '-c', code], cwd=self.root, env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(present.returncode, 0, present.stderr)
        self.assertEqual(json.loads(present.stdout), [str(ROOT/'scripts/prepare.py'), str(ROOT/'scripts/firmware_layouts.py')])

    def test_default_cli_is_inert_before_importing_external_sources(self):
        output = io.StringIO()
        with patch('sys.argv', ['activate-native-generation']), contextlib.redirect_stdout(output):
            self.activation.main()
        self.assertEqual(json.loads(output.getvalue()), {'execute': False, 'pages_deployed': False})


if __name__ == '__main__':
    unittest.main()
