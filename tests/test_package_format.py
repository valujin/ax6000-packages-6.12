"""APKv3 metadata is decoded by the real pinned host tool, never target code."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import package_format as packages


def make_apk(apk, root, name, version='1-r1', arch='aarch64_cortex-a53', depends=None, provides=None, tags=None, payload=None, script=None):
    files = root / ('files-' + name)
    files.mkdir()
    if payload:
        for filename, content in payload.items():
            target = files / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    output = root / (name + '-' + version + '.apk')
    command = [str(apk), '--no-network', 'mkpkg', '--info', 'name:' + name, '--info', 'version:' + version,
               '--info', 'arch:' + arch, '--files', str(files), '--output', str(output)]
    for field, value in [('depends', depends), ('provides', provides), ('tags', tags)]:
        if value:
            command += ['--info', field + ':' + ' '.join(value)]
    if script:
        command += ['--script', 'post-install:' + str(script)]
    subprocess.run(command, check=True, capture_output=True)
    return output


class FormatPolicyTest(unittest.TestCase):
    def test_manager_optin_is_only_for612_cohorts(self):
        self.assertEqual(packages.manager({}), 'opkg')
        self.assertEqual(packages.manager({'package_manager': 'opkg'}), 'opkg')
        for channel in ['recommended', 'latest']:
            self.assertEqual(packages.manager({'id': 'redmi-ax6000-612-' + channel, 'channel': channel, 'package_manager': 'apk'}), 'apk')
        for profile in [{'package_manager': 'apk'}, {'package_manager': 'yes'}, {'package_manager': False},
                        {'id': 'redmi-ax6000', 'channel': 'recommended', 'package_manager': 'apk'}]:
            with self.assertRaises(ValueError):
                packages.manager(profile)

    def test_stdout_cap_is_enforced_while_child_runs(self):
        with self.assertRaisesRegex(ValueError, 'exceeds limit'):
            packages.bounded_output([sys.executable, '-c', 'import sys;sys.stdout.write("x"*1000000)'], limit=128)

    def test_actual_abi_names_remain_authority_and_exact_kernel_version_is_unchanged(self):
        fields = packages.normalize_apk_info({'name': 'libtest2026', 'version': '1.2.3-r4', 'arch': 'aarch64_cortex-a53',
            'tags': ['openwrt:abiversion=2026'], 'depends': ['kernel=6.12.108~' + 'a' * 32 + '-r1', '!opkg'],
            'provides': ['libtest=1.2.3-r4']})
        self.assertEqual((fields['Package'], fields['Base-Package'], fields['ABIVersion']), ('libtest2026', 'libtest', '2026'))
        self.assertIn('kernel (= 6.12.108~' + 'a' * 32 + '-r1)', fields['Depends'])
        self.assertEqual(fields['Provides'], 'libtest (= 1.2.3-r4)')
        self.assertEqual(packages.normalized_dependencies(['wget-any', '!other-any', 'lib-any=1-r1']),
            'wget-any, !other-any, lib-any (= 1-r1)')
        with self.assertRaisesRegex(ValueError, 'unsupported APK dependency'):
            packages.normalized_dependencies(['@source-annotation-any'])
        for tags in [['openwrt:abiversion=wrong'], ['openwrt:abiversion='], ['openwrt:abiversion=2026'] * 2]:
            broken = copy.deepcopy(fields['APK-Raw'])
            broken['tags'] = tags
            with self.assertRaises(ValueError):
                packages.normalize_apk_info(broken)


class RealApkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.apk = os.environ.get('APK')
        if not cls.apk:
            raise unittest.SkipTest('Set APK to trusted host apk-tools 3.0.5')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_real_v3_control_payload_and_installed_db_without_scripts(self):
        marker = self.root / 'SCRIPT-MUST-NOT-RUN'
        script = self.root / 'post-install'
        script.write_text('#!/bin/sh\ntouch ' + str(marker) + '\n')
        path = make_apk(self.apk, self.root, 'libfixture2026', tags=['openwrt:abiversion=2026'],
                        payload={'usr/share/value': b'real APKv3 payload'}, script=script)
        control = packages.read_control(path, apk=self.apk)
        self.assertEqual((control['Package'], control['Base-Package']), ('libfixture2026', 'libfixture'))
        self.assertEqual(packages.payload_files(path, apk=self.apk), {'usr/share/value': b'real APKv3 payload'})
        self.assertFalse(marker.exists())
        installed = self.root / 'installed'
        installed.mkdir()
        subprocess.run([self.apk, '--no-network', '--root', str(installed), '--repositories-file', '/dev/null',
            '--arch', 'aarch64_cortex-a53', '--usermode', '--allow-untrusted', '--no-scripts', '--no-commit-hooks',
            'add', '--initdb', str(path)], check=True, capture_output=True)
        controls = packages.installed_controls(installed, self.apk)
        self.assertEqual([x['Package'] for x in controls], ['libfixture2026'])
        self.assertEqual(controls[0]['Base-Package'], 'libfixture')
        self.assertFalse(marker.exists())

    def test_payload_symlinks_are_not_read_and_unsafe_metadata_rejected_before_extract(self):
        path = make_apk(self.apk, self.root, 'links', payload={'usr/share/value': b'payload'})
        files = self.root / 'files-links'
        (files / 'usr/absolute-link').symlink_to('/tmp/AX6000-MUST-NOT-READ')
        subprocess.run([self.apk, '--no-network', 'mkpkg', '--info', 'name:links', '--info', 'version:1-r1',
            '--info', 'arch:noarch', '--files', str(files), '--output', str(path)], check=True, capture_output=True)
        self.assertEqual(packages.payload_files(path, apk=self.apk), {'usr/share/value': b'payload'})
        for metadata in [{'paths': [{'name': '../escape'}]}, {'paths': [{'name': '', 'files': [{'name': '../escape'}]}]},
            {'paths': [{'name': '', 'files': [{'name': 'link', 'target': '00a02f746d70'}]},
                       {'name': 'link', 'files': [{'name': 'write', 'size': 1}]}]}]:
            with mock.patch.object(packages, 'apk_json', return_value=metadata), mock.patch.object(packages.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    packages.payload_files(path, apk=self.apk)
                run.assert_not_called()

    def test_canonical_tagged_exact_version_with_actual_host_solver(self):
        keys = self.root / 'keys'
        keys.mkdir()
        secret = self.root / 'private.pem'
        subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(secret)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(secret), '-pubout', '-out', str(keys / 'public.pem')], check=True, capture_output=True)
        library = make_apk(self.apk, self.root, 'libfixture2026', provides=['libfixture=1-r1', 'fixture-any'], tags=['openwrt:abiversion=2026'])
        busybox = make_apk(self.apk, self.root, 'busybox', version='2-r1')
        index = self.root / 'packages.adb'
        subprocess.run([self.apk, '--no-network', 'mkndx', '--allow-untrusted', '--sign', str(secret), '--output', str(index),
            str(library), str(busybox)], check=True, capture_output=True)
        repositories = self.root / 'repositories'
        repositories.write_text('@public ' + str(index) + '\n')
        installed = self.root / 'installed'
        installed.mkdir()
        prefix = [self.apk, '--no-network', '--root', str(installed), '--repositories-file', str(repositories),
            '--keys-dir', str(keys), '--arch', 'aarch64_cortex-a53', '--usermode', '--no-scripts', '--no-commit-hooks']
        subprocess.run(prefix + ['add', '--initdb', 'libfixture2026@public=1-r1', 'busybox@public'], check=True, capture_output=True)
        self.assertEqual({x['Package']: x['Version'] for x in packages.installed_controls(installed, self.apk)},
            {'libfixture2026': '1-r1', 'busybox': '2-r1'})
        wrong = subprocess.run(prefix + ['add', 'libfixture2026@public=9-r9'], capture_output=True)
        self.assertNotEqual(wrong.returncode, 0)

    def test_missing_host_tool_wrong_suffix_and_nonpackage_adb_rejected(self):
        path = make_apk(self.apk, self.root, 'fixture')
        with self.assertRaisesRegex(ValueError, 'host apk'):
            packages.read_control(path)
        with self.assertRaisesRegex(ValueError, 'suffix'):
            packages.read_package(path, format='opkg', apk=self.apk)
        index = self.root / 'packages.adb'
        subprocess.run([self.apk, '--no-network', 'mkndx', '--allow-untrusted', '--output', str(index), str(path)], check=True, capture_output=True)
        self.assertEqual([x['Package'] for x in packages.index_info(index, self.apk)], ['fixture'])
        fake = self.root / 'not-package.apk'
        fake.write_bytes(index.read_bytes())
        with self.assertRaisesRegex(ValueError, 'not an APKv3 package'):
            packages.read_control(fake, apk=self.apk)


if __name__ == '__main__':
    unittest.main()
