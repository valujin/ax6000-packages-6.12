"""Real package metadata/payload boundaries; no SDK downloads or Go compilation."""
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('tailscale_sdk', ROOT / 'scripts/tailscale_sdk.py')
sdk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sdk)


class PackageAcceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lock = json.loads((ROOT / 'tests/fixtures/tailscale-source-1.104.2.json').read_text())
        self.files = {'usr/sbin/tailscale.multicall': b'packed ELF fixture',
                      'etc/init.d/tailscale': b'unchanged init', 'etc/config/tailscale': b'unchanged config',
                      'lib/upgrade/keep.d/tailscale': b'/etc/tailscale/\n'}
        self.keep = {'content': b'/etc/tailscale/\n', 'mode': 0o644}
        self.links = {name: 'tailscale.multicall' for name in ('usr/sbin/tailscale', 'usr/sbin/tailscaled')}
        self.control = {'Package': 'tailscale', 'Version': '1.104.2-r3', 'Architecture': 'aarch64_cortex-a53',
                        'Depends': 'libc, ca-bundle, kmod-tun', 'Provides': 'tailscaled (= 1.104.2-r3)'}
        self.baseline = dict(self.control, Version='1.104.2-r2', Provides='tailscaled (= 1.104.2-r2)')

    def ipk(self, links=None):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w:gz') as tar:
            for name, content in self.files.items():
                item = tarfile.TarInfo('./' + name); item.size = len(content)
                item.mode = 0o755 if name in ('usr/sbin/tailscale.multicall', 'etc/init.d/tailscale') else 0o644
                tar.addfile(item, io.BytesIO(content))
            for name, target in (self.links if links is None else links).items():
                item = tarfile.TarInfo('./' + name); item.type = tarfile.SYMTYPE; item.linkname = target
                item.mode = 0o777; tar.addfile(item)
        control = io.BytesIO()
        with tarfile.open(fileobj=control, mode='w:gz') as tar:
            item = tarfile.TarInfo('conffiles'); data = b'/etc/config/tailscale\n'
            item.size = len(data); tar.addfile(item, io.BytesIO(data))
        path = self.root / 'tailscale.ipk'
        with tarfile.open(path, mode='w:gz') as tar:
            for name, data in [('data.tar.gz', payload.getvalue()), ('control.tar.gz', control.getvalue())]:
                item = tarfile.TarInfo(name); item.size = len(data); tar.addfile(item, io.BytesIO(data))
        return path

    def test_real_ipk_tar_contains_one_binary_two_exact_relative_links_and_conffiles(self):
        files, inventory, conffiles = sdk.package_payload(self.ipk(), None)
        self.assertEqual(files, self.files)
        self.assertEqual({k: v['target'] for k, v in inventory.items() if v['type'] == 'symlink'}, self.links)
        self.assertEqual(conffiles, ['/etc/config/tailscale'])

    def test_absolute_alias_and_extra_binary_are_rejected(self):
        links = dict(self.links); links['usr/sbin/tailscale'] = '/usr/sbin/tailscale.multicall'
        files, inventory, conffiles = sdk.package_payload(self.ipk(links), None)
        with self.assertRaisesRegex(ValueError, 'aliases'):
            sdk.validate_payload(files, inventory, conffiles, self.files, 'opkg', self.keep)
        files, inventory, conffiles = sdk.package_payload(self.ipk(), None)
        files['usr/bin/tailscale'] = b'extra'; inventory['usr/bin/tailscale'] = {'type': 'file', 'mode': 0o755}
        with self.assertRaisesRegex(ValueError, 'inventory'):
            sdk.validate_payload(files, inventory, conffiles, self.files, 'opkg', self.keep)

    def test_service_bytes_and_modes_cannot_drift(self):
        files, inventory, conffiles = sdk.package_payload(self.ipk(), None)
        sdk.validate_payload(files, inventory, conffiles, self.files, 'opkg', self.keep)
        for mutation in ('bytes', 'mode', 'conffiles'):
            f, i, c = copy.deepcopy((files, inventory, conffiles))
            if mutation == 'bytes': f['etc/init.d/tailscale'] = b'changed'
            elif mutation == 'mode': i['usr/sbin/tailscale.multicall']['mode'] = 0o644
            else: c.append('/etc/foreign')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                sdk.validate_payload(f, i, c, self.files, 'opkg', self.keep)

    def test_controls_preserve_dependencies_and_all_native_providers(self):
        sdk.validate_control(self.control, self.baseline, self.lock, 'aarch64_cortex-a53')
        for field, value in [('Provides', ''), ('Depends', 'libc'), ('Version', '1.104.2-r2')]:
            wrong = dict(self.control); wrong[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                sdk.validate_control(wrong, self.baseline, self.lock, 'aarch64_cortex-a53')
        baseline = dict(self.baseline, Provides='tailscale-any, tailscaled (= 1.104.2-r2)')
        with self.assertRaises(ValueError): sdk.validate_control(self.control, baseline, self.lock, 'aarch64_cortex-a53')

    def test_new_overlay_and_package_agreement_cannot_hide_native_service_drift(self):
        wrappers = {name: self.files[name] for name in sdk.WRAPPERS}
        inventory = {sdk.KEEPFILE: {'type': 'file', 'mode': 0o644}}
        sdk.validate_native_wrappers(wrappers, self.files, sdk.CONFFILES['opkg'], 'opkg', inventory)
        changed = dict(self.files); changed['etc/init.d/tailscale'] += b'old native difference'
        with self.assertRaises(ValueError): sdk.validate_native_wrappers(wrappers, changed, sdk.CONFFILES['opkg'], 'opkg', inventory)
        with self.assertRaises(ValueError): sdk.validate_native_wrappers(wrappers, self.files, [], 'opkg', inventory)

    def test_exact_native_keep_fragment_generates_state_policy_and_guard_preserves_it(self):
        text = gzip.decompress((ROOT / 'tests/fixtures/ax6000-612-include-package-pack.mk.gz').read_bytes()).decode()
        begin = text.index('    ifneq ($$(KEEP_$(1)),)')
        fragment = text[begin:text.index('    endif', begin) + len('    endif')]
        for has_directory in (False, True):
            root = self.root / str(has_directory); (root / 'etc/config').mkdir(parents=True)
            (root / 'etc/config/tailscale').write_text('native config')
            if has_directory: (root / 'etc/tailscale').mkdir()
            makefile = 'KEEP_tailscale:=/etc/config/tailscale /etc/tailscale/\nIDIR_tailscale:=' + str(root) + '\ndefine NativeKeep\nall:\n' + fragment + '\nendef\n$(eval $(call NativeKeep,tailscale))\n'
            subprocess.run(['make', '--no-print-directory', '-f', '-'], input=makefile, text=True,
                           check=True, capture_output=True, preexec_fn=lambda: os.umask(0o022))
            self.assertEqual((root / sdk.KEEPFILE).read_bytes(), self.keep['content'])
            self.assertEqual((root / sdk.KEEPFILE).stat().st_mode & 0o777, 0o644)
        files, inventory, conffiles = sdk.package_payload(self.ipk(), None)
        sdk.validate_payload(files, inventory, conffiles, self.files, 'opkg', self.keep)
        for mutation in ('bytes', 'mode', 'missing'):
            f, i = copy.deepcopy((files, inventory))
            if mutation == 'bytes': f[sdk.KEEPFILE] = b'/etc/foreign/\n'
            elif mutation == 'mode': i[sdk.KEEPFILE]['mode'] = 0o755
            else: del f[sdk.KEEPFILE]; del i[sdk.KEEPFILE]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                sdk.validate_payload(f, i, conffiles, self.files, 'opkg', self.keep)

    def test_probe_subset_changes_no_native_identity_and_mutates_no_original_input(self):
        profile = {'id': 'redmi-ax6000-612-recommended', 'firmware': {'kernel_version': 'actual ABI'},
                   'sdk': {'sha256': 'native SHA'}, 'feeds': [{'commit': 'native feed'}], 'channel': 'recommended',
                   'packages': ['tailscale', 'pbr'], 'package_only': ['tailscale'], 'all_kmods': True,
                   'luci_languages': ['ru'], 'asu': {'seed': 'native seed'}, 'pbr_source': 'mossdef-stable',
                   'vendor_country_db': True, 'image_packages': ['pbr']}
        lock = {'tailscale': self.lock, 'pbr': {'version': '1.2.4'}, 'feeds': {'base': 'same pin'}}
        saved = copy.deepcopy((profile, lock))
        probe, narrowed = sdk.probe_inputs(profile, lock)
        self.assertEqual((profile, lock), saved)
        for key in ('id', 'firmware', 'sdk', 'feeds', 'channel', 'image_packages'): self.assertEqual(probe[key], profile[key])
        self.assertEqual(probe['packages'], ['tailscale']); self.assertFalse(probe['all_kmods'])
        for key in ('pbr_source', 'asu', 'vendor_country_db'): self.assertNotIn(key, probe)
        self.assertNotIn('pbr', narrowed); self.assertEqual(narrowed['tailscale'], self.lock)
        self.assertIn('prepare.check_kernel(original, sdk)', (ROOT / 'scripts/tailscale_sdk.py').read_text())

    def test_pinned_comparison_archives_are_actual_authenticated_payloads_not_sdk_members(self):
        self.assertEqual(sdk.REFERENCES['apk']['sha256'], '021bfd0cc9e453004d7d359c1690d01d871c1fa5047f1fe14a229923c61e3898')
        self.assertEqual(sdk.REFERENCES['opkg']['sha256'], '66fec5f0e2cf4eab5d45bb73f94b1f067ec555ea8ab1aece9bb14c984b80c224')
        for row in sdk.REFERENCES.values():
            self.assertTrue(row['url'].startswith('https://')); self.assertIn('snapshot_manifest_sha256', row['provenance'])

    def test_native_config_set_and_builtin_modinfo_are_bound_and_vermagic_absence_is_honest(self):
        tree = self.root / 'sdk'; kernel = tree / 'build_dir/target-aarch64/linux-mediatek/linux-6.12.108'
        kernel.mkdir(parents=True); (kernel / 'Makefile').write_text('kernel')
        (tree / 'include').mkdir(); (tree / 'include/kernel.mk').write_text('baked vermagic')
        (tree / 'ax6000-baseline').mkdir()
        manifest = tree / 'ax6000-baseline/manifest.json'
        manifest.write_text(json.dumps({'package_manager': 'opkg', 'files': []}))
        for name in ('.config', 'Module.symvers', 'include/config/kernel.release', 'include/generated/autoconf.h',
                     '.config.set', 'modules.builtin.modinfo'):
            path = kernel / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(name)
        before = sdk.kernel_and_bank(tree)
        self.assertIsNone(before[(kernel / '.vermagic').relative_to(tree).as_posix()])
        for name in ('.config.set', 'modules.builtin.modinfo'):
            path = kernel / name; content = path.read_bytes(); path.write_bytes(content + b'changed')
            self.assertNotEqual(before, sdk.kernel_and_bank(tree)); path.write_bytes(content)
        manifest.write_text(json.dumps({'package_manager': 'apk', 'files': []}))
        (kernel / '.config.set').unlink()
        with self.assertRaisesRegex(ValueError, 'native kernel role'): sdk.kernel_and_bank(tree)

    def test_normal_build_plan_never_builds_world_or_injects_a_binary(self):
        commands = sdk.compile_plan(4)
        self.assertEqual(commands, [['make', '-j4', 'package/ax6000-overrides/tailscale/compile', 'CONFIG_AUTOREMOVE=', 'V=s']])
        source = (ROOT / 'scripts/tailscale_sdk.py').read_text()
        self.assertIn('prepare.export_packages(', source)
        self.assertIn('prepare.close_native(', source)
        self.assertIn('prepare.check_kernel(', source)
        self.assertNotIn('skip_compile', source)

    def test_packed_payload_must_equal_normal_make_helper_proof(self):
        import hashlib
        binary = self.files['usr/sbin/tailscale.multicall']
        proof = {'lock': self.lock, 'packed_sha256': hashlib.sha256(binary).hexdigest(),
                 'packed_size': len(binary), 'upx_test_and_exact_roundtrip': True,
                 'offline_compile': True, 'feature_reducing_tags': []}
        sdk.validate_build_proof(proof, self.lock, binary)
        with self.assertRaises(ValueError): sdk.validate_build_proof(proof, self.lock, binary + b'stripped/corrupted')
        for field, value in [('upx_test_and_exact_roundtrip', False), ('offline_compile', False), ('feature_reducing_tags', ['ts_omit_netstack'])]:
            wrong = copy.deepcopy(proof); wrong[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): sdk.validate_build_proof(wrong, self.lock, binary)

    def test_hosted_workflow_uses_current_runner_uid_and_no_secrets_or_publication(self):
        workflow = (ROOT / '.github/workflows/tailscale-sdk.yml').read_text()
        self.assertIn('workflow_dispatch:', workflow); self.assertIn('max-parallel: 1', workflow)
        self.assertIn('--user "$(id -u):$(id -g)"', workflow)
        self.assertIn('--network none', workflow); self.assertIn('--memory 10g --memory-swap 10g', workflow)
        for forbidden in ('secrets.', 'gh release', 'contents: write', 'chmod -R 777'):
            self.assertNotIn(forbidden, workflow)

    @unittest.skipUnless(os.environ.get('APK'), 'optional trusted host APK')
    def test_actual_apk_decoder_preserves_relative_links_and_conffiles(self):
        apk = Path(os.environ['APK']); payload = self.root / 'files'
        data = dict(self.files, **{'lib/apk/packages/tailscale.conffiles': b'/etc/config/tailscale\n/etc/tailscale/\n',
                                 'lib/apk/packages/tailscale.conffiles_static': b'generated checksum\n',
                                 'lib/apk/packages/tailscale.list': b'generated inventory\n'})
        for name, content in data.items():
            path = payload / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
            path.chmod(0o755 if name in ('usr/sbin/tailscale.multicall', 'etc/init.d/tailscale') else 0o644)
        for name, target in self.links.items(): (payload / name).symlink_to(target)
        path = self.root / 'tailscale.apk'
        subprocess.run([str(apk), 'mkpkg', '--info', 'name:tailscale', '--info', 'version:1.104.2-r3',
                        '--info', 'arch:aarch64_cortex-a53', '--files', str(payload), '--output', str(path)],
                       check=True, capture_output=True)
        files, inventory, conffiles = sdk.package_payload(path, apk)
        sdk.validate_payload(files, inventory, conffiles, self.files, 'apk', self.keep)


if __name__ == '__main__': unittest.main()
