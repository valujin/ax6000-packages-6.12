"""SDK APK boundaries. Fixture package bytes are never executed or called builds."""
import copy
import hashlib
import gzip
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_prepare_612 import channel_profile, prepare
from test_package_format import make_apk


def bundle_proof(sdk, native_source):
    module = prepare.optional_package_module('host_apk_bundle')
    bundler = sdk.parent / 'bundle-libraries.sh'
    fixture = Path(__file__).with_name('fixtures') / 'sdk-bundle-libraries.sh.gz'
    bundler.write_bytes(gzip.decompress(fixture.read_bytes()))
    return module.describe(sdk, native_source, bundler)


class FreshNativeApkSelectionTests(unittest.TestCase):
    def test_actual_source_profiles_verify_before_sdk_baseline_exists(self):
        repository = Path(__file__).resolve().parents[1]
        for channel in ('recommended', 'latest'):
            with self.subTest(channel=channel), tempfile.TemporaryDirectory() as directory:
                source = Path(directory)
                profile = json.loads((repository / 'profiles' /
                    f'redmi-ax6000-612-{channel}-new.json').read_text())
                # Isolate fresh APK selection from the independently tested mesh source installer.
                profile.pop('mediatek_mesh', None)
                self.assertEqual(profile['package_manager'], 'apk')
                self.assertIsNone(profile['sdk']['url'])
                self.assertIsNone(profile['firmware']['kernel_version'])
                config = 'CONFIG_USE_APK=y\n' + ''.join(
                    f'CONFIG_PACKAGE_{name}=y\n' for name in profile['packages'])
                languages = {language: 'y' for language in profile.get('luci_languages', [])}
                config += ''.join(f'CONFIG_LUCI_LANG_{language}=y\n' for language in languages)
                (source / '.config').write_text(config)
                (source / 'build-selection.json').write_text(json.dumps(
                    {'candidate_kmods': [], 'luci_languages': languages}))
                self.assertFalse((source / 'ax6000-baseline').exists())
                report = prepare.verify_selection(profile, source)
                self.assertEqual(report['required_native_kmods'], [])
                self.assertTrue(set(profile['packages']) <= set(report['selected_packages']))
                (source / '.config').write_text(config.replace('CONFIG_PACKAGE_pbr=y\n', ''))
                with self.assertRaisesRegex(ValueError, 'requested packages unresolved.*pbr'):
                    prepare.verify_selection(profile, source)

    def test_sdk_decoder_still_requires_native_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = channel_profile(); profile['package_manager'] = 'apk'
            with self.assertRaisesRegex(ValueError, 'APK SDK requires its native baseline manifest'):
                prepare.sdk_apk(profile, Path(directory))


class ApkSdkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.sdk = self.root / 'sdk'; self.sdk.mkdir()
        self.profile = channel_profile(); self.profile['package_manager'] = 'apk'
        self.abi = self.profile['firmware']['kernel_version']
        self.controls = {}
        self.baseline = self.sdk / 'ax6000-baseline'; self.baseline.mkdir()
        self.tool = self.sdk / 'staging_dir/host/bin/apk'; self.tool.parent.mkdir(parents=True)
        binary = os.environ.get('APK')
        if not binary: self.skipTest('Set APK to the independently trusted native apk-tools executable')
        shutil.copy2(binary, self.tool)
        self.manifest = {'schema_version': 1, 'package_manager': 'apk',
            'source_commit': self.profile['firmware']['commit'], 'kernel_version': self.abi,
            'architecture': self.profile['firmware']['architecture'], 'frozen_kmods': [], 'frozen_packages': [],
            'files': [], 'protected_packages': ['kernel'], 'host_apk': bundle_proof(self.sdk, Path(binary))}
        self.save_manifest()

    def save_manifest(self):
        (self.baseline / 'manifest.json').write_text(json.dumps(self.manifest))

    def add(self, name, *, baseline=False, depends='', provides='', marker='native', version=None):
        directory = self.baseline / 'apks' if baseline else self.sdk / 'bin/packages'
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f'{name}-{marker}.apk'; path.write_text(marker)
        control = {'Package': name, 'Version': version or (self.abi if name == 'kernel' else '1-r1'),
                   'Architecture': 'aarch64_cortex-a53', 'Depends': depends, 'Provides': provides}
        self.controls[path] = control
        if baseline:
            self.manifest['frozen_packages'].append(name)
            if name.startswith('kmod-'): self.manifest['frozen_kmods'].append(name)
            self.manifest['files'].append({'package': name, 'version': control['Version'],
                'path': 'apks/' + path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
            self.save_manifest()
        return path

    def metadata(self):
        (self.sdk / 'tmp').mkdir()
        (self.sdk / 'tmp/.packageinfo').write_text('Package: pbr\n')
        (self.sdk / 'tmp/.config-package.in').write_text('config PACKAGE_pbr\n')
        (self.sdk / '.config').write_text('CONFIG_USE_APK=y\nCONFIG_TARGET_BOARD="mediatek"\n')

    def test_apk_requires_explicit_valid_cohort_and_invalid_manager_refuses(self):
        prepare.validate(self.profile, {})
        for manager in ('APK', True, None, 'unknown'):
            bad = copy.deepcopy(self.profile); bad['package_manager'] = manager
            with self.subTest(manager=manager), self.assertRaises(ValueError): prepare.validate(bad, {})
        bad = copy.deepcopy(self.profile); bad.pop('channel')
        with self.assertRaises(ValueError): prepare.package_manager(bad)
        with self.assertRaisesRegex(ValueError, 'lock package manager'):
            prepare.validate(self.profile, {'package_manager': 'opkg'})

    def test_host_apk_is_bound_by_baseline_hash_size_and_host_elf(self):
        self.assertEqual(prepare.sdk_apk(self.profile, self.sdk), self.tool)
        self.tool.write_bytes(b'not trusted host tool')
        with self.assertRaisesRegex(ValueError, 'host APK'): prepare.sdk_apk(self.profile, self.sdk)

    def test_selection_preserves_apk_and_verify_rejects_format_flip(self):
        self.add('kernel', baseline=True)
        self.metadata()
        with patch.object(prepare, 'read_package_control', side_effect=lambda path, apk=None: self.controls[path]):
            prepare.select_packages(self.profile, self.sdk)
            text = (self.sdk / '.config').read_text()
            self.assertIn('CONFIG_USE_APK=y\n', text)
            self.assertNotIn('# CONFIG_USE_APK is not set', text)
            prepare.verify_selection(self.profile, self.sdk)
            (self.sdk / '.config').write_text(text.replace('CONFIG_USE_APK=y', '# CONFIG_USE_APK is not set'))
            with self.assertRaisesRegex(ValueError, 'APK'): prepare.verify_selection(self.profile, self.sdk)

    def test_apk_controls_keep_actual_abi_name_as_provider_after_normalizing(self):
        actual = {'Package': 'libfixture1', 'Base-Package': 'libfixture', 'Version': '1-r1',
                  'Architecture': 'aarch64_cortex-a53', 'APK-Name': 'libfixture1',
                  'Provides': 'so:libfixture.so.1'}
        module = prepare.optional_package_module('package_format')
        with patch.object(module, 'read_control', return_value=actual):
            normalized = prepare.read_package_control(self.root / 'fixture.apk', apk=self.tool)
        self.assertEqual(normalized['Package'], 'libfixture')
        self.assertIn('libfixture1 (= 1-r1)', normalized['Provides'])
        self.assertEqual(actual['Package'], 'libfixture1')

    def test_apk_native_closure_follows_colon_providers_and_preserves_frozen_bytes(self):
        core = self.add('kmod-core', baseline=True, depends=f'kernel (= {self.abi}), so:libfixture.so.1')
        library = self.add('libfixture', baseline=True, provides='so:libfixture.so.1')
        self.add('kernel', baseline=True)
        with patch.object(prepare, 'read_package_control', side_effect=lambda path, apk=None: self.controls[path]):
            baseline = prepare.baseline_packages(self.profile, self.sdk)
            self.assertEqual(prepare.required_native_kmods(baseline, 'CONFIG_PACKAGE_kmod-core=y\n', apk=self.tool), {'kmod-core'})
        self.assertEqual(core.read_bytes(), b'native'); self.assertEqual(library.read_bytes(), b'native')
        self.manifest['package_manager'] = 'opkg'; self.save_manifest()
        with self.assertRaisesRegex(ValueError, 'package manager'): prepare.baseline_packages(self.profile, self.sdk)

    def test_apk_export_retains_native_modules_fresh_userland_and_host_tool_proof(self):
        self.profile['packages'] = ['pbr', 'kmod-core']
        original = self.add('kmod-core', baseline=True, depends=f'kernel (= {self.abi})')
        self.add('kernel', baseline=True)
        provider = self.add('apk-openssl', baseline=True, marker='native-provider', version='3.0.5-r1')
        self.manifest['protected_packages'].append('apk-openssl'); self.save_manifest()
        self.add('apk-openssl', marker='refreshed-provider', version='3.0.6-r1')
        self.add('kmod-core', depends=f'kernel (= {self.abi})', marker='repacked')
        fresh = self.add('pbr', marker='fresh', version='1.2.4-r2')
        (self.sdk / 'build-selection.json').write_text('{}')
        signer = self.tool.with_name('usign'); signer.write_text('host signer fixture'); signer.chmod(0o755)
        with patch.object(prepare, 'read_package_control', side_effect=lambda path, apk=None: self.controls[path]):
            output = self.root / 'output'; prepare.export_packages(self.profile, {}, self.sdk, output)
        self.assertEqual((output / 'bin/packages' / original.name).read_bytes(), original.read_bytes())
        self.assertFalse((output / 'bin/packages/kmod-core-repacked.apk').exists())
        self.assertEqual((output / 'bin/packages' / fresh.name).read_bytes(), fresh.read_bytes())
        self.assertEqual((output / 'bin/packages' / provider.name).read_bytes(), provider.read_bytes())
        self.assertFalse((output / 'bin/packages/apk-openssl-refreshed-provider.apk').exists())
        proof = json.loads((output / 'host-apk-proof.json').read_text())
        self.assertEqual(proof['sha256'], hashlib.sha256((output / 'apk').read_bytes()).hexdigest())
        self.assertEqual(proof['sdk_sha256'], self.profile['sdk']['sha256'])
        self.assertEqual(proof['exported_entrypoint_data_path'], 'apk')
        self.assertEqual(proof['executable_entrypoint_path'], 'apk')
        self.assertEqual(json.loads((output / 'lock.json').read_text())['package_manager'], 'apk')

    def test_apk_kernel_context_rejects_config_or_symbol_drift_without_rewriting(self):
        self.profile['all_kmods'] = True
        tree = self.sdk / 'build_dir/target-aarch64/linux-mediatek_filogic/linux-6.12.108'
        (tree / 'include/generated').mkdir(parents=True); (tree / 'include/config').mkdir()
        inputs = {'.config': b'CONFIG_NET=y\n', 'Module.symvers': b'native symbol table\n',
                  'include/generated/autoconf.h': b'#define CONFIG_NET 1\n',
                  'include/config/kernel.release': b'6.12.108\n'}
        for relative, data in inputs.items(): (tree / relative).write_bytes(data)
        (tree / 'Makefile').write_text('native kernel'); (tree / '.vermagic').write_text('a' * 32)
        self.manifest['kernel_context'] = {'path': tree.relative_to(self.sdk).as_posix(),
            'files': {relative: {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                      for relative, data in inputs.items()}}
        self.save_manifest(); prepare.check_kernel(self.profile, self.sdk)
        for relative in ('.config', 'Module.symvers'):
            with self.subTest(relative=relative):
                changed = inputs[relative] + b'changed\n'; (tree / relative).write_bytes(changed)
                with self.assertRaisesRegex(ValueError, 'kernel context'): prepare.check_kernel(self.profile, self.sdk)
                self.assertEqual((tree / relative).read_bytes(), changed)
                (tree / relative).write_bytes(inputs[relative])

    def test_apk_runtime_dependencies_exclude_only_valid_conflicts(self):
        self.assertEqual(prepare.native_dependency_groups('!foreign, so:libc.so, provider (~ 1.2)', 'Depends', apk=True),
                         [{'so:libc.so'}, {'provider'}])
        for value, label in [('!bad name', 'Depends'), ('!foreign | available', 'Depends'), ('!foreign', 'Provides')]:
            with self.subTest(value=value, label=label), self.assertRaises(ValueError):
                prepare.native_dependency_groups(value, label, apk=True)


class RealApkSdkClosureTests(unittest.TestCase):
    def test_real_apkv3_metadata_closure_and_exact_native_export(self):
        binary = os.environ.get('APK')
        if not binary:
            self.skipTest('Set APK to the independently trusted host decoder')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); sdk = root / 'sdk'; sdk.mkdir()
            profile = channel_profile(); profile.update(package_manager='apk', packages=['pbr', 'kmod-amneziawg'])
            abi = profile['firmware']['kernel_version']
            host = sdk / 'staging_dir/host/bin/apk'; host.parent.mkdir(parents=True); shutil.copy2(binary, host)
            signer = host.with_name('usign'); signer.write_text('unexecuted signer fixture'); signer.chmod(0o755)
            bank = sdk / 'ax6000-baseline/apks'; bank.mkdir(parents=True)
            native = []
            for name, version, depends, provides, tags in [
                ('kernel', abi, [], [], []),
                ('libfixture2026', '1-r1', [], ['so:libfixture.so.1'], ['openwrt:abiversion=2026']),
                ('kmod-core', '1-r1', ['kernel=' + abi, 'libfixture2026'], [], [])]:
                package = make_apk(binary, root, name, version=version, depends=depends, provides=provides,
                                   tags=tags, payload={'usr/share/' + name: name.encode()})
                target = bank / package.name; shutil.move(package, target)
                native.append({'package': 'libfixture' if name == 'libfixture2026' else name,
                               'version': version, 'path': 'apks/' + target.name,
                               'sha256': hashlib.sha256(target.read_bytes()).hexdigest()})
            bundler = root / 'bundle-libraries.sh'
            bundler.write_bytes(gzip.decompress((Path(__file__).with_name('fixtures') / 'sdk-bundle-libraries.sh.gz').read_bytes()))
            subprocess.run(['bash', str(bundler), str(sdk / 'staging_dir/host'), str(host)],
                           check=True, capture_output=True)
            strip_targets = [host.with_name('.apk.bin')] + [
                path for path in (sdk / 'staging_dir/host/lib').rglob('*')
                if path.is_file() and not path.is_symlink() and (path.name.endswith('.so') or '.so.' in path.name)]
            subprocess.run(['strip', *map(str, strip_targets)], check=True, capture_output=True)
            manifest = {'schema_version': 1, 'package_manager': 'apk', 'source_commit': profile['firmware']['commit'],
                'kernel_version': abi, 'architecture': profile['firmware']['architecture'],
                'frozen_kmods': ['kmod-core'], 'frozen_packages': ['kernel', 'libfixture', 'kmod-core'],
                'protected_packages': ['kernel', 'libfixture', 'kmod-core'], 'files': native,
                'host_apk': bundle_proof(sdk, Path(binary))}
            (bank.parent / 'manifest.json').write_text(json.dumps(manifest))
            baseline = prepare.baseline_packages(profile, sdk)
            self.assertEqual(set(baseline), {'kernel', 'libfixture', 'kmod-core'})
            self.assertEqual(prepare.required_native_kmods(baseline, 'CONFIG_PACKAGE_kmod-core=y\n', apk=host), {'kmod-core'})
            output_packages = sdk / 'bin/packages'; output_packages.mkdir(parents=True)
            for name, version, deps in [('pbr', '1.2.4-r2', []), ('kmod-amneziawg', '1-r1', ['kernel=' + abi, 'kmod-core'])]:
                path = make_apk(binary, root, name, version=version, depends=deps,
                                payload={'usr/share/' + name: name.encode()})
                shutil.move(path, output_packages / path.name)
            (sdk / 'build-selection.json').write_text('{}')
            output = root / 'export'; prepare.export_packages(profile, {}, sdk, output)
            for entry in native:
                original = bank.parent / entry['path']
                self.assertEqual((output / 'bin/packages' / original.name).read_bytes(), original.read_bytes())
            self.assertEqual(len(list((output / 'bin/packages').glob('*.apk'))), 5)
            self.assertFalse(list((output / 'bin/packages').glob('*.ipk')))
            exported = json.loads((output / 'host-apk-proof.json').read_text())
            self.assertEqual(exported['kind'], 'openwrt-bundle-v1')
            portable = prepare.optional_package_module('host_apk_bundle').verify(output / exported['bundle_path'], exported)
            self.assertEqual(portable, output / exported['executable_entrypoint_path'])
            self.assertEqual(exported['exported_entrypoint_data_path'], 'apk')
            self.assertEqual(hashlib.sha256(portable.read_bytes()).hexdigest(), exported['sha256'])
            # This is our freshly generated trusted host-only fixture, after
            # source/bundle verification; publication never executes imported RAW tools.
            version = subprocess.run([str(output / exported['executable_entrypoint_path']), '--version'],
                                     text=True, capture_output=True, timeout=15)
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertIn('3.0.5', version.stdout)


if __name__ == '__main__': unittest.main()
