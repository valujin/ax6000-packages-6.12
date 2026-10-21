"""Run actual publication shell blocks against a recording CLI, without secrets/network."""
import json
import base64
import runpy
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


def shell_blocks(filename):
    text = (ROOT / '.github/workflows' / filename).read_text()
    blocks = {}
    step = ''
    lines = text.splitlines()
    for index, line in enumerate(lines):
        name = re.match(r'\s*- name: (.*)', line)
        if name:
            step = name[1]
        if re.match(r'\s*run: \|\s*$', line):
            indentation = len(line) - len(line.lstrip())
            body = []
            for candidate in lines[index + 1:]:
                if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indentation:
                    break
                body.append(candidate[indentation + 2:])
            blocks[step] = '\n'.join(body) + '\n'
    return blocks


class APKWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'keys').mkdir()
        (self.root / 'keys/repository-apk.pem').write_text('fixture public PEM')
        commands = self.root / 'commands'
        commands.mkdir()
        # The launcher records CLI arguments and fixture key contents only.
        stub = commands / 'python3'
        stub.write_text('#!' + sys.executable + '\n' + textwrap.dedent('''
            import json, os, sys
            from pathlib import Path
            args = sys.argv[1:]
            keys = {}
            for flag in ('--key', '--apk-key'):
                if flag in args:
                    keys[flag] = Path(args[args.index(flag)+1]).read_text()
            Path(os.environ['RECORD']).write_text(json.dumps({
                'args': args, 'keys': keys,
                'secrets_present': [key for key in ('OPKG_SIGNING_KEY', 'APK_SIGNING_KEY') if key in os.environ]}))
        '''))
        stub.chmod(0o755)
        self.tool = self.root / 'trusted-apk'
        self.tool.write_text('#!/bin/sh\nexit 0\n')
        self.tool.chmod(0o755)
        self.environment = dict(os.environ, PATH=str(commands) + ':' + os.environ['PATH'],
            RECORD=str(self.root / 'record.json'), RUNNER_TEMP=str(self.root),
            GITHUB_REPOSITORY='valujin/ax6000-packages-6.12', GITHUB_REPOSITORY_OWNER='valujin',
            OPKG_SIGNING_KEY='fixture signing key', APK_SIGNING_KEY='',
            PACKAGE_REPOSITORY_URL='', NEEDS_APK_SIGNING='false', FORCE='false', BOOTSTRAP='false', REPLACE_BUILD_ID='',
            ALLOW_ASU_APK_MIGRATION='false', MIGRATION_PROOF='', AX6000_APK=str(self.tool))

    def run_step(self, workflow, name, **environment):
        result = subprocess.run(['bash', '-euo', 'pipefail', '-c', shell_blocks(workflow)[name]],
            cwd=self.root, env=dict(self.environment, **environment), text=True, capture_output=True)
        self.assertFalse((self.root / 'opkg-signing.key').exists())
        self.assertFalse((self.root / 'apk-signing.pem').exists())
        return result

    def record(self):
        record = json.loads((self.root / 'record.json').read_text())
        self.assertEqual(record['secrets_present'], [], 'secret values must be removed before launching publication')
        return record

    def test_hosted_scope_preserves_only_trusted_apk_path_without_signing_secrets(self):
        scope = runpy.run_path(str(ROOT / 'scripts/hosted-publication.py'))
        preserved = scope['PRESERVE']
        self.assertIn('AX6000_APK', preserved)
        self.assertNotIn('APK_SIGNING_KEY', preserved)
        self.assertNotIn('OPKG_SIGNING_KEY', preserved)
        self.assertNotIn('AX6000_APK_PRIVATE_KEY', preserved)

    def test_all_changed_workflow_shell_blocks_parse(self):
        for filename in ('firmware.yml', 'packages.yml', 'publish-existing.yml'):
            for name, block in shell_blocks(filename).items():
                with self.subTest(workflow=filename, step=name):
                    result = subprocess.run(['bash', '-n'], input=block, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_daily_publication_does_not_require_apk_secret_or_options(self):
        result = self.run_step('packages.yml', 'Refresh serial channel snapshots and compose the complete site', NEEDS_APK='false')
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record()
        self.assertNotIn('--apk', record['args'])
        self.assertEqual(list(record['keys']), ['--key'])

    def test_apk_daily_publication_passes_separate_signing_key_and_independent_tool(self):
        result = self.run_step('packages.yml', 'Refresh serial channel snapshots and compose the complete site',
                               NEEDS_APK='true', NEEDS_APK_SIGNING='true', APK_SIGNING_KEY='fixture APK PEM')
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record()
        self.assertEqual(record['args'][record['args'].index('--apk') + 1], str(self.tool))
        self.assertEqual(record['args'][record['args'].index('--apk-public-key') + 1], 'keys/repository-apk.pem')
        self.assertEqual(record['keys']['--apk-key'], 'fixture APK PEM\n')
        self.assertNotEqual(record['keys']['--key'], record['keys']['--apk-key'])

    def test_daily_opkg_publication_restores_disabled_apk_channel_without_apk_signing_key(self):
        result = self.run_step('packages.yml', 'Refresh serial channel snapshots and compose the complete site',
                               NEEDS_APK='true', NEEDS_APK_SIGNING='false')
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record()
        self.assertIn('--apk', record['args'])
        self.assertNotIn('--apk-key', record['args'])

    def test_manual_legacy_opkg_publication_has_no_apk_requirement(self):
        result = self.run_step('publish-existing.yml', 'Publish a signed durable snapshot and compose both channels',
                               NEEDS_APK='false', INCOMING_MANAGER='opkg')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('--apk', self.record()['args'])

    def test_manual_opkg_publication_retains_apk_channel_without_requiring_apk_private_key(self):
        result = self.run_step('publish-existing.yml', 'Publish a signed durable snapshot and compose both channels',
                               NEEDS_APK='true', INCOMING_MANAGER='opkg')
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record()
        self.assertIn('--apk', record['args'])
        self.assertNotIn('--apk-key', record['args'])
        self.assertNotIn('--apk-public-key', record['args'])

    def test_manual_apk_migration_passes_explicit_authorization_and_own_key(self):
        proof = self.root / 'reviewed.json'
        proof.write_text('{"schema_version": 1}')
        result = self.run_step('publish-existing.yml', 'Publish a signed durable snapshot and compose both channels',
                               NEEDS_APK='true', INCOMING_MANAGER='apk', APK_SIGNING_KEY='fixture APK PEM',
                               ALLOW_ASU_APK_MIGRATION='true', REPLACE_BUILD_ID='exact-authenticated-old-build', MIGRATION_PROOF=str(proof))
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record()
        self.assertIn('--allow-asu-apk-migration', record['args'])
        self.assertIn('--replace-build-id', record['args'])
        self.assertEqual(record['args'][record['args'].index('--migration-proof') + 1], str(proof))
        self.assertEqual(record['keys']['--apk-key'], 'fixture APK PEM\n')

    def migration_receipt_step(self, *, allowed='true', predecessor='old-build', encoded=''):
        block = shell_blocks('publish-existing.yml')['Prepare the operator-reviewed native migration receipt']
        code = block.split("<<'PYCODE'\n", 1)[1].rsplit('\nPYCODE', 1)[0]
        return subprocess.run([sys.executable, '-'], input=code, cwd=self.root,
            env=dict(os.environ, RUNNER_TEMP=str(self.root), GITHUB_OUTPUT=str(self.root / 'outputs'),
                     ALLOW_ASU_APK_MIGRATION=allowed, REPLACE_BUILD_ID=predecessor, MIGRATION_PROOF_BASE64=encoded),
            text=True, capture_output=True)

    def test_legacy_publication_does_not_require_a_migration_receipt(self):
        result = self.migration_receipt_step(allowed='false')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'migration-proof.json').exists())

    def test_operator_receipt_is_strictly_decoded_to_private_file(self):
        raw = b'{"schema_version":1,"nested":{"field":"value"}}'
        result = self.migration_receipt_step(encoded=base64.b64encode(raw).decode())
        self.assertEqual(result.returncode, 0, result.stderr)
        proof = self.root / 'migration-proof.json'
        self.assertEqual(proof.read_bytes(), raw)
        self.assertEqual(proof.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / 'outputs').read_text(), 'path=' + str(proof) + '\n')

    def test_operator_receipt_missing_flag_predecessor_duplicate_json_and_bad_base64_fail(self):
        valid = base64.b64encode(b'{"schema_version":1}').decode()
        for args in ({'allowed': 'false', 'encoded': valid}, {'encoded': ''},
                     {'predecessor': '', 'encoded': valid}, {'encoded': '!not-base64'},
                     {'encoded': base64.b64encode(b'{"a":1,"a":2}').decode()},
                     {'encoded': base64.b64encode(b'{"nested":{"a":1,"a":2}}').decode()},
                     {'encoded': base64.b64encode(b'[]').decode()},
                     {'encoded': base64.b64encode(b'{"a":NaN}').decode()},
                     {'encoded': base64.b64encode(b'x' * 65537).decode()}):
            with self.subTest(args=list(args)):
                result = self.migration_receipt_step(**args)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'migration-proof.json').exists())
                self.assertFalse((self.root / 'outputs').exists())

    def test_missing_apk_key_fails_only_for_actual_apk_publication(self):
        for workflow, name, environment in (
            ('packages.yml', 'Refresh serial channel snapshots and compose the complete site', {'NEEDS_APK': 'true', 'NEEDS_APK_SIGNING': 'true'}),
            ('publish-existing.yml', 'Publish a signed durable snapshot and compose both channels',
             {'NEEDS_APK': 'true', 'INCOMING_MANAGER': 'apk'})):
            with self.subTest(workflow=workflow):
                result = self.run_step(workflow, name, **environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('APK_SIGNING_KEY', result.stderr)
                self.assertFalse((self.root / 'record.json').exists())


if __name__ == '__main__':
    unittest.main()
