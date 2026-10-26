"""Exercise the actual manual publisher gates without network or signing."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from test_apk_workflows import ROOT


WORKFLOW = 'publish-firmware-generation.yml'


def shell_blocks(filename):
    text = (ROOT / '.github/workflows' / filename).read_text()
    text = re.sub(r'^(\s*)- &\w+\n\1  name:', r'\1- name:', text, flags=re.M)
    blocks, step = {}, ''
    lines = text.splitlines()
    for index, line in enumerate(lines):
        name = re.match(r'\s*- name: (.*)', line)
        if name: step = name[1]
        if re.match(r'\s*run: \|\s*$', line):
            indent = len(line) - len(line.lstrip())
            body = []
            for candidate in lines[index + 1:]:
                if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indent: break
                body.append(candidate[indent + 2:])
            blocks[step] = '\n'.join(body) + '\n'
    return blocks


def embedded(step):
    return shell_blocks(WORKFLOW)[step].split("<<'PY'\n", 1)[1].split('\nPY', 1)[0]


class FirmwareGenerationPublisher(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = 'valujin/ax6000-packages-6.12'
        self.sha = 'a' * 40
        self.run = {'id': 123, 'status': 'completed', 'conclusion': 'success',
                    'event': 'workflow_dispatch', 'head_branch': 'main', 'head_sha': self.sha,
                    'path': '.github/workflows/firmware.yml',
                    'repository': {'full_name': self.repository},
                    'head_repository': {'full_name': self.repository}}
        self.artifacts = {'artifacts': [
            {'id': index, 'name': name + '-123', 'expired': False, 'size_in_bytes': 200,
             'digest': 'sha256:' + '1' * 64,
             'workflow_run': {'id': 123, 'head_sha': self.sha}}
            for index, name in enumerate(('ax6000-firmware-sdk-packages', 'ax6000-build-diagnostics'), 1)]}
        self.env = {'FIRMWARE_RUN_ID': '123', 'GITHUB_REPOSITORY': self.repository,
                    'DEFAULT_BRANCH': 'main', 'GITHUB_OUTPUT': str(self.root / 'outputs')}

    def execute_gate(self, run=None, artifacts=None):
        (self.root / 'run.json').write_text(json.dumps(run or self.run))
        (self.root / 'artifacts.json').write_text(json.dumps(artifacts or self.artifacts))
        with contextlib.chdir(self.root), patch.dict(os.environ, self.env):
            exec(compile(embedded('Bind the exact successful firmware run and artifacts'), WORKFLOW, 'exec'), {})

    def test_success_binds_artifact_ids_digests_and_head(self):
        self.execute_gate()
        result = (self.root / 'outputs').read_text()
        self.assertIn('producer=' + self.sha, result)
        self.assertIn('raw_id=1\n', result)
        self.assertIn('diagnostics_id=2\n', result)
        self.assertIn('raw_digest=' + '1' * 64, result)

    def test_failed_foreign_or_wrong_workflow_runs_fail_before_output(self):
        for changes in ({'conclusion': 'failure'}, {'status': 'in_progress'}, {'id': 124},
                        {'event': 'pull_request'}, {'head_branch': 'feature'},
                        {'head_repository': {'full_name': 'other/repo'}},
                        {'path': '.github/workflows/test.yml'}, {'head_sha': 'main'}):
            with self.subTest(changes=changes), self.assertRaises(SystemExit):
                self.execute_gate(self.run | changes)
            self.assertFalse((self.root / 'outputs').exists())

    def test_missing_expired_duplicate_or_foreign_artifact_fails(self):
        for kind in ('missing', 'expired', 'duplicate', 'head', 'digest', 'size'):
            artifacts = copy.deepcopy(self.artifacts)
            if kind == 'missing': artifacts['artifacts'].pop()
            elif kind == 'duplicate': artifacts['artifacts'].append(artifacts['artifacts'][0])
            elif kind == 'expired': artifacts['artifacts'][0]['expired'] = True
            elif kind == 'head': artifacts['artifacts'][0]['workflow_run']['head_sha'] = 'b' * 40
            elif kind == 'digest': artifacts['artifacts'][0]['digest'] = None
            else: artifacts['artifacts'][0]['size_in_bytes'] = 0
            with self.subTest(kind=kind), self.assertRaises(SystemExit): self.execute_gate(artifacts=artifacts)
            self.assertFalse((self.root / 'outputs').exists())

    def test_native_report_is_genuine_producer_data_bound_to_images_and_sdk(self):
        (self.root / 'diagnostics/_temp').mkdir(parents=True)
        profile = {'channel': 'recommended', 'package_manager': 'apk', 'exclude_asu': True,
                   'mediatek_mesh': True, 'build_id': 'mesh-build', 'firmware': {'kernel_version': 'native-abi'},
                   'sdk': {'sha256': '2' * 64}}
        layouts = {name: {'image': name + '.bin', 'image_sha256': '3' * 64, 'image_size': 20}
                   for name in ('stock', 'mtkuboot', 'ubootmod')}
        manifest = {'source_commit': '4' * 40, 'files': [
            {'path': 'bin/' + record['image'], 'sha256': record['image_sha256'], 'size': record['image_size']}
            for record in layouts.values()]}
        proof = {'ok': True, 'channel': 'recommended', 'build_id': 'mesh-build', 'source_commit': '4' * 40,
                 'kernel_abi': 'native-abi', 'package_manager': 'apk', 'stock_factory': {'verified': True},
                 'sdk_context': {'sdk_sha256': '2' * 64}, 'layouts': layouts}
        importer = SimpleNamespace(validate_metadata=lambda *a, **k: {'profile': profile, 'manifest': manifest})
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda m: None))
        env = self.env | {'PRODUCER_COMMIT': self.sha}
        code = embedded('Require producer native verification for these exact images and SDK')
        def execute(value):
            (self.root / 'diagnostics/_temp/firmware-verification.json').write_text(json.dumps(value))
            with contextlib.chdir(self.root), patch.dict(os.environ, env), \
                    patch('importlib.util.spec_from_file_location', return_value=spec), \
                    patch('importlib.util.module_from_spec', return_value=importer):
                exec(compile(code, WORKFLOW, 'exec'), {})
        execute(proof)
        self.assertEqual(json.loads((self.root / 'native-verification.json').read_text()), proof)
        for field, value in (('ok', False), ('build_id', 'different'), ('stock_factory', None),
                             ('sdk_context', {'sdk_sha256': '5' * 64}), ('layouts', {})):
            with self.subTest(field=field), self.assertRaises(SystemExit): execute(proof | {field: value})
        bad = copy.deepcopy(proof); bad['layouts']['stock']['image_sha256'] = '6' * 64
        with self.assertRaises(SystemExit): execute(bad)

    def test_signer_handoff_rejects_different_artifacts_even_with_recomputed_proof_hash(self):
        (self.root / 'acceptance-proof').mkdir()
        (self.root / 'raw').mkdir()
        profile = {'build_id': 'mesh-build', 'sdk': {'sha256': '2' * 64}}
        for name, data in (('profile.json', profile), ('lock.json', {}), ('firmware-manifest.json', {})):
            (self.root / 'raw' / name).write_text(json.dumps(data))
        (self.root / 'native-verification.json').write_text(json.dumps({'sdk_context': {'matching_contexts': {}}}))
        proof = {'schema_version': 1, 'ok': True, 'build_id': 'mesh-build', 'sdk_sha256': '2' * 64,
                 'compiled_amneziawg': True, 'firmware_run_id': 123, 'producer_commit': self.sha,
                 'raw_artifact_sha256': '1' * 64, 'diagnostics_artifact_sha256': '3' * 64,
                 'kernel_context': {}, 'compiled_requested_packages': [
                     'wapp', 'mapd', '1905daemon', 'libmapd', 'ax6000-mesh', 'luci-app-ax6000-mesh', 'tailscale']}
        for field, filename in (('profile_sha256', 'raw/profile.json'), ('lock_sha256', 'raw/lock.json'),
                                ('manifest_sha256', 'raw/firmware-manifest.json'),
                                ('native_verification_sha256', 'native-verification.json')):
            proof[field] = hashlib.sha256((self.root / filename).read_bytes()).hexdigest()
        def execute(value, wrong_digest=False):
            path = self.root / 'acceptance-proof/sdk-acceptance.json'
            path.write_text(json.dumps(value))
            digest = '0' * 64 if wrong_digest else hashlib.sha256(path.read_bytes()).hexdigest()
            env = self.env | {'ACCEPTANCE_SHA256': digest, 'PRODUCER_COMMIT': self.sha,
                              'RAW_DIGEST': '1' * 64, 'DIAGNOSTICS_DIGEST': '3' * 64}
            with contextlib.chdir(self.root), patch.dict(os.environ, env):
                exec(compile(embedded('Verify the hash-bound SDK acceptance handoff'), WORKFLOW, 'exec'), {})
        execute(proof)
        with self.assertRaises(SystemExit): execute(proof, wrong_digest=True)
        for field, value in (('producer_commit', 'b' * 40), ('firmware_run_id', 124),
                             ('raw_artifact_sha256', '5' * 64), ('profile_sha256', '6' * 64),
                             ('kernel_context', {'changed': True}), ('compiled_requested_packages', [])):
            with self.subTest(field=field), self.assertRaises(SystemExit): execute(proof | {field: value})

    def test_workflow_orders_real_sdk_build_before_signing_and_never_deploys(self):
        text = (ROOT / '.github/workflows' / WORKFLOW).read_text()
        self.assertLess(text.index('Compile the exact exported SDK'), text.index('OPKG_SIGNING_KEY:'))
        self.assertIn('scripts/build.sh --profile raw/profile.json --lock raw/lock.json', text)
        self.assertIn("shutil.copyfile(sdk, work / 'sdk.archive')", text)
        self.assertIn('scripts/channel-snapshot.py publish-generation', text)
        self.assertNotIn('APK_SIGNING_KEY', text)
        self.assertNotIn('deploy-pages', text)
        self.assertNotIn('pages: write', text)
        self.assertIn('group: package-publication', text)
        acceptance, signer = text.split('\n  generation:\n', 1)
        self.assertNotIn('contents: write', acceptance)
        self.assertNotIn('secrets.', acceptance)
        self.assertNotIn('scripts/build.sh', signer)
        self.assertIn('needs: acceptance', signer)
        self.assertIn('- *bind_producer', signer)
        self.assertIn('- *download_producer', signer)
        self.assertIn('- *verify_native', signer)
        self.assertIn('ACCEPTANCE_SHA256', signer)
        for step, code in shell_blocks(WORKFLOW).items():
            result = subprocess.run(['bash', '-n'], input=code, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, (step, result.stderr))


if __name__ == '__main__':
    unittest.main()
