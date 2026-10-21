"""Protect installed native ABI/core/vendor closure without pinning user apps."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
APK = os.environ.get('AX6000_HOST_APK') or os.environ.get('AX6000_APK') or os.environ.get('APK') or shutil.which('apk')


def guard():
    path = ROOT / 'scripts/apk_world.py'
    if not path.is_file():
        raise AssertionError('native APK world guard is missing')
    spec = importlib.util.spec_from_file_location('apk_world_fixture', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class GuardPolicyTests(unittest.TestCase):
    def test_reviewed_source_hook_rejects_foreign_bytes_and_is_idempotent(self):
        module = guard()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory); (source / 'include').mkdir()
            original = (ROOT / 'tests/fixtures/apk-rootfs.mk').read_bytes()
            (source / 'include/rootfs.mk').write_bytes(original)
            profile = {'package_manager': 'apk', 'channel': 'recommended'}
            module.configure_source(profile, source)
            postimage = (source / 'include/rootfs.mk').read_bytes()
            self.assertNotEqual(postimage, original)
            module.configure_source(profile, source)
            module.configure_source(profile, source, check_only=True)
            self.assertEqual((source / 'include/rootfs.mk').read_bytes(), postimage)
            self.assertEqual((source / 'scripts/ax6000-apk-world.py').read_bytes(), (ROOT / 'scripts/apk_world.py').read_bytes())
            (source / 'include/rootfs.mk').write_bytes(postimage + b'# foreign\n')
            with self.assertRaisesRegex(ValueError, 'reviewed'):
                module.configure_source(profile, source)

    def test_only_core_source_recipe_roots_and_required_vendor_are_selected(self):
        module = guard()
        metadata = ('Source-Makefile: package/libs/libc/Makefile\nPackage: libc\n'
                    'Source-Makefile: package/mtk/vendor/Makefile\nPackage: vendor-tool\n'
                    'Source-Makefile: package/feeds/packages/pbr/Makefile\nPackage: pbr\n'
                    'Source-Makefile: package/ax6000-overrides/tailscale/Makefile\nPackage: tailscale\n')
        roots = module.core_recipe_roots(metadata)
        self.assertEqual(roots, ['libc', 'vendor-tool'])


@unittest.skipUnless(APK, 'set AX6000_APK to the trusted host apk-tools 3 binary')
class RealApkGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name); self.root = self.directory / 'root'
        self.bank = self.directory / 'packages'; self.bank.mkdir()
        self.payload = self.directory / 'payload'; self.payload.mkdir()
        self.abi = '6.12.108~' + 'a' * 32 + '-r1'
        self.policy = {'schema_version': 1, 'package_manager': 'apk', 'cohort': '612-recommended',
                       'protected_roots': ['apk-openssl', 'base-files', 'busybox', 'kernel', 'libc', 'vendor-tool']}
        definitions = [('kernel', self.abi, '', '', ''), ('libc', '1-r0', '', '', ''),
                       ('base-files', '1-r0', 'libc', '', ''), ('busybox', '1-r0', 'libc', '', ''),
                       ('apk-openssl', '1-r0', 'libc', '', ''),
                       ('kmod-vendor', '1-r0', 'kernel=' + self.abi + ' libc', '', ''),
                       ('libfixture2026', '1-r0', 'libc', 'vlib=1-r0', 'openwrt:abiversion=2026'),
                       ('vendor-tool', '1-r0', 'vlib>=1-r0', '', ''),
                       ('pbr', '1.2.4-r2', 'libc', '', ''), ('public-tool', '1-r0', 'libc', '', '')]
        postinst = self.directory / 'post-install'; postinst.write_text('#!/bin/sh\nexit 0\n')
        for name, version, depends, provides, tags in definitions:
            args = [APK, 'mkpkg', '--info', 'name:' + name, '--info', 'version:' + version,
                    '--info', 'arch:aarch64_cortex-a53', '--files', str(self.payload),
                    '--output', str(self.bank / (name + '-' + version + '.apk'))]
            for field, value in [('depends', depends), ('provides', provides), ('tags', tags)]:
                if value: args.extend(['--info', field + ':' + value])
            if name == 'base-files': args.extend(['--script', 'post-install:' + str(postinst)])
            subprocess.run(args, check=True, capture_output=True)
        subprocess.run([APK, 'mkndx', '--allow-untrusted', '--output', str(self.bank / 'packages.adb'),
                        *map(str, sorted(self.bank.glob('*.apk')))], check=True, capture_output=True)
        subprocess.run([APK, '--root', str(self.root), '--arch', 'aarch64_cortex-a53', '--no-network',
                        '--repositories-file', '/dev/null', '--repository', 'file://' + str(self.bank / 'packages.adb'),
                        '--initdb', '--allow-untrusted', '--no-scripts', '--no-cache', '--usermode', 'add',
                        *[row[0] for row in definitions]], check=True, capture_output=True)

    def test_installed_metadata_pins_actual_abi_and_closure_but_preserves_user_apps(self):
        module = guard()
        report = module.pin_root(self.root, Path(APK), self.policy)
        protected = (self.root / 'etc/apk/ax6000-protected.list').read_text().splitlines()
        self.assertIn('kernel=' + self.abi, protected)
        self.assertIn('kmod-vendor=1-r0', protected)
        self.assertIn('libfixture2026=1-r0', protected)
        self.assertNotIn('pbr=1.2.4-r2', protected)
        self.assertNotIn('public-tool=1-r0', protected)
        world = (self.root / 'etc/apk/world').read_text()
        self.assertIn('pbr\n', world); self.assertIn('public-tool\n', world)
        self.assertTrue(all(pin + '\n' in world for pin in protected))
        self.assertEqual(report['protected_packages'], len(protected))
        before = world
        module.pin_root(self.root, Path(APK), self.policy)
        self.assertEqual((self.root / 'etc/apk/world').read_text(), before)

    def test_malformed_world_and_alias_parent_fail_before_either_output_changes(self):
        module = guard(); world = self.root / 'etc/apk/world'
        world.write_text('pbr;bad\n')
        with self.assertRaisesRegex(ValueError, 'world'):
            module.pin_root(self.root, Path(APK), self.policy)
        self.assertEqual(world.read_text(), 'pbr;bad\n')
        self.assertFalse((world.parent / 'ax6000-protected.list').exists())
        world.write_text('pbr\n')
        outside = self.directory / 'outside'; shutil.copytree(world.parent, outside)
        shutil.rmtree(world.parent); world.parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink|outside'):
            module.pin_root(self.root, Path(APK), self.policy)
        self.assertFalse((outside / 'ax6000-protected.list').exists())

    def test_world_alias_cannot_select_a_public_replacement_for_native_abi(self):
        module = guard(); world = self.root / 'etc/apk/world'
        original = world.read_bytes()
        for alias in ('libfixture@public', 'vlib@public'):
            world.write_bytes(original + alias.encode() + b'\n')
            with self.assertRaisesRegex(ValueError, 'alias'):
                module.pin_root(self.root, Path(APK), self.policy)
            self.assertFalse((world.parent / 'ax6000-protected.list').exists())

    def test_signed_tagged_public_dependency_cannot_upgrade_pinned_native_libc(self):
        module = guard(); module.pin_root(self.root, Path(APK), self.policy)
        public = self.directory / 'public'; public.mkdir()
        for name, depends in [('libc', ''), ('need-new-libc', 'libc>=2-r0')]:
            version = '2-r0' if name == 'libc' else '1-r0'
            args = [APK, 'mkpkg', '--info', 'name:' + name, '--info', 'version:' + version,
                    '--info', 'arch:aarch64_cortex-a53', '--files', str(self.payload),
                    '--output', str(public / (name + '-' + version + '.apk'))]
            if depends: args.extend(['--info', 'depends:' + depends])
            subprocess.run(args, check=True, capture_output=True)
        secret = public / 'private-key.pem'; keys = public / 'keys'; keys.mkdir()
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-out', str(secret)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(secret), '-pubout', '-out', str(keys / 'public.pem')],
                       check=True, capture_output=True)
        subprocess.run([APK, 'mkndx', '--allow-untrusted', '--sign', str(secret), '--output', str(public / 'packages.adb'),
                        *map(str, public.glob('*.apk'))], check=True, capture_output=True)
        repositories = public / 'repositories'; repositories.write_text('@public ' + str(public / 'packages.adb') + '\n')
        command = [APK, '--root', str(self.root), '--arch', 'aarch64_cortex-a53', '--no-network',
                   '--repositories-file', str(repositories), '--keys-dir', str(keys), '--no-cache',
                   '--no-scripts', '--no-commit-hooks', '--usermode', 'add', 'need-new-libc@public']
        world = self.root / 'etc/apk/world'; before = world.read_bytes()
        denied = subprocess.run(command, capture_output=True)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn(b'world[libc=1-r0]', denied.stderr)
        self.assertEqual(world.read_bytes(), before)
        world.write_bytes(before.replace(b'libc=1-r0\n', b'libc\n'))
        subprocess.run(command, check=True, capture_output=True)
        installed = {row['name']: row['version'] for row in module.installed_packages(self.root, Path(APK))}
        self.assertEqual(installed['libc'], '2-r0')
        self.assertEqual(installed['need-new-libc'], '1-r0')

    def test_native_prepare_rootfs_executes_guard_before_timestamps(self):
        module = guard()
        source = self.directory / 'source'; (source / 'include').mkdir(parents=True)
        (source / 'include/rootfs.mk').write_bytes((ROOT / 'tests/fixtures/apk-rootfs.mk').read_bytes())
        module.configure_source({'package_manager': 'apk', 'channel': 'recommended'}, source)
        (source / 'ax6000-apk-world-policy.json').write_text(json.dumps(self.policy))
        host = source / 'host'; (host / 'bin').mkdir(parents=True)
        shutil.copy2(APK, host / 'bin/apk')
        for tool in ('python3', 'gzip', 'tar'):
            (host / 'bin' / tool).symlink_to(shutil.which(tool))
        makefile = source / 'Makefile'
        makefile.write_text('CONFIG_USE_APK:=y\nSTAGING_DIR_HOST:=' + str(host) + '\nTOPDIR:=' + str(source)
                            + '\nSOURCE_DATE_EPOCH:=1\nXARGS:=xargs\ninclude include/rootfs.mk\nall:\n'
                            + '\t$(call prepare_rootfs,' + str(self.root) + ')\n')
        subprocess.run(['make', '-f', str(makefile), 'all'], cwd=source, check=True, capture_output=True)
        protected = self.root / 'etc/apk/ax6000-protected.list'
        self.assertIn('kmod-vendor=1-r0\n', protected.read_text())
        self.assertEqual(protected.stat().st_mtime, 1)
        self.assertEqual((self.root / 'etc/apk/world').stat().st_mtime, 1)

    def test_ambiguous_installed_virtual_provider_refuses_pins(self):
        module = guard()
        installed = module.installed_packages(self.root, Path(APK))
        installed.append({'name': 'second-provider', 'version': '1-r0', 'provides': ['vlib=1-r0']})
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            module.protected_packages(installed, self.policy, Path(APK))


if __name__ == '__main__':
    unittest.main()
