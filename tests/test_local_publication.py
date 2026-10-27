"""Local execution receipts bind genuine verification to exact publication bytes."""
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


def sha(data):
    return hashlib.sha256(data).hexdigest()


class LocalPublicationTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'scripts/local_publication.py'
        self.assertTrue(path.is_file(), 'Local publication verifier is missing')
        spec = importlib.util.spec_from_file_location('local_publication_test', path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.profile = {'channel': 'recommended', 'package_manager': 'apk', 'exclude_asu': True,
                        'mediatek_mesh': True, 'build_id': 'fixture-build', 'sdk': {'sha256': 'a' * 64},
                        'firmware': {'commit': 'b' * 40, 'kernel_version': 'fixture-abi'}}
        self.manifest = {'recipe_commit': 'c' * 40, 'source_commit': 'b' * 40,
                         'files': [{'path': 'bin/' + name + '.bin', 'sha256': sha(name.encode()), 'size': len(name)}
                                   for name in ('stock', 'mtkuboot', 'ubootmod')]}
        self.native = {'schema_version': 1, 'ok': True, 'channel': 'recommended', 'package_manager': 'apk',
                       'build_id': 'fixture-build', 'source_commit': 'b' * 40, 'kernel_abi': 'fixture-abi',
                       'sdk_context': {'sdk_sha256': 'a' * 64, 'apk_baseline': {'manifest_sha256': 'f' * 64}, 'kernel_relative_path': 'build_dir/linux/linux',
                                       'matching_contexts': {name: {'sha256': sha(name.encode()), 'size': len(name)}
                                                            for name in self.module.CONTEXTS}},
                       'stock_factory': {'ok': True},
                       'layouts': {name: {'image': name + '.bin', 'image_sha256': sha(name.encode()), 'image_size': len(name)}
                                   for name in ('stock', 'mtkuboot', 'ubootmod')}}

    def test_native_identity_accepts_real_report_shape_and_refuses_false_or_foreign_result(self):
        self.module.validate_native(self.profile, self.manifest, self.native)
        for field, bad in [('ok', False), ('ok', 1), ('build_id', 'foreign'), ('kernel_abi', 'foreign'),
                           ('source_commit', 'd' * 40), ('stock_factory', None)]:
            with self.subTest(field=field):
                proof = copy.deepcopy(self.native)
                proof[field] = bad
                with self.assertRaises(ValueError):
                    self.module.validate_native(self.profile, self.manifest, proof)
        proof = copy.deepcopy(self.native)
        proof['layouts']['stock']['image_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'image'):
            self.module.validate_native(self.profile, self.manifest, proof)
        proof = copy.deepcopy(self.native)
        del proof['sdk_context']['matching_contexts']['Module.symvers']
        with self.assertRaisesRegex(ValueError, 'context'):
            self.module.validate_native(self.profile, self.manifest, proof)

    def test_local_handoff_hashes_every_input_and_rejects_tamper(self):
        inputs = {}
        for name in self.module.INPUTS:
            path = self.directory / name
            path.write_bytes((name + '\n').encode())
            inputs[name] = path
        handoff = self.module.handoff(self.profile, self.manifest, inputs)
        self.assertEqual(handoff['execution'], 'local-server')
        self.assertEqual(handoff['producer_commit'], 'c' * 40)
        self.assertNotIn('firmware_run_id', handoff)
        self.module.validate_files(self.directory, handoff)
        for name in self.module.INPUTS:
            original = inputs[name].read_bytes()
            inputs[name].write_bytes(original + b'tampered')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'checksum|size'):
                self.module.validate_files(self.directory, handoff)
            inputs[name].write_bytes(original)

    def test_candidate_input_does_not_accept_links_extra_assets_or_unknown_execution(self):
        for name in self.module.INPUTS:
            (self.directory / name).write_bytes(name.encode())
        handoff = self.module.handoff(self.profile, self.manifest,
                                     {name: self.directory / name for name in self.module.INPUTS})
        handoff['execution'] = 'github-actions'
        with self.assertRaisesRegex(ValueError, 'local'):
            self.module.validate_files(self.directory, handoff)
        handoff['execution'] = 'local-server'
        handoff['files']['foreign'] = {'sha256': '0' * 64, 'size': 1}
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.module.validate_files(self.directory, handoff)
        del handoff['files']['foreign']
        path = self.directory / 'sdk-acceptance.json'
        path.unlink()
        path.symlink_to(self.directory / 'native-verification.json')
        with self.assertRaisesRegex(ValueError, 'regular'):
            self.module.validate_files(self.directory, handoff)

    def test_local_sdk_receipt_is_bound_to_all_native_inputs_and_package_evidence(self):
        self.assertTrue(callable(getattr(self.module, 'validate_sdk', None)), 'Local SDK receipt validator missing')
        raw = self.directory / 'raw'
        raw.mkdir()
        for name in ('profile.json', 'lock.json', 'firmware-manifest.json'):
            (raw / name).write_text(name)
        native_path = self.directory / 'native-verification.json'
        native_path.write_text(json.dumps(self.native))
        packages = set(self.module.REQUIRED) | {'kmod-amneziawg'}
        self.profile['packages'] = sorted(self.module.REQUIRED)
        proof = {'schema_version': 1, 'execution': 'local-server', 'ok': True, 'producer_commit': 'c' * 40,
                 'build_id': self.profile['build_id'], 'sdk_sha256': 'a' * 64,
                 'compiled_amneziawg': True, 'native_verification_sha256': self.module.sha(native_path),
                 'kernel_context': self.native['sdk_context']['matching_contexts'],
                 'baseline_manifest_sha256': 'f' * 64,
                 'compiled_requested_packages': sorted(self.module.REQUIRED),
                 'compiled_packages': {name: {'version': '1-r1', 'size': 1, 'sha256': 'e' * 64} for name in packages},
                 **self.module.identity(raw)}
        self.module.validate_sdk(self.profile, self.native, proof, raw, native_path, 'c' * 40)
        for field, bad in [('execution', 'github-actions'), ('producer_commit', 'd' * 40),
                           ('manifest_sha256', '0' * 64), ('native_verification_sha256', '0' * 64),
                           ('compiled_amneziawg', False), ('compiled_amneziawg', 1), ('ok', 1), ('kernel_context', {}), ('baseline_manifest_sha256', '0' * 64)]:
            altered = copy.deepcopy(proof)
            altered[field] = bad
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'SDK'):
                self.module.validate_sdk(self.profile, self.native, altered, raw, native_path, 'c' * 40)
        altered = copy.deepcopy(proof)
        altered['compiled_packages']['wapp']['sha256'] = 'invalid'
        with self.assertRaisesRegex(ValueError, 'package'):
            self.module.validate_sdk(self.profile, self.native, altered, raw, native_path, 'c' * 40)

    def test_signer_workflow_contains_no_firmware_or_sdk_compilation(self):
        path = ROOT / '.github/workflows/publish-local-generation.yml'
        self.assertTrue(path.is_file(), 'Signing-only local publication workflow is missing')
        text = path.read_text()
        self.assertIn('LOCAL_MANIFEST_SHA256', text)
        self.assertIn('PRODUCER_COMMIT', text)
        self.assertIn('local_publication.py verify', text)
        self.assertIn('channel-snapshot.py publish-generation', text)
        for forbidden in ('build-firmware.sh', 'scripts/build.sh', 'FIRMWARE_RUN_ID', 'firmware_run_id'):
            self.assertNotIn(forbidden, text)


if __name__ == '__main__':
    unittest.main()
