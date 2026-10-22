"""Real signing integration; set USIGN to an OpenWrt host usign executable."""
import gzip
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from urllib.parse import urlsplit

from test_publish import ipk
from test_firmware_patches import vendor_source_fixture

ROOT = Path(__file__).resolve().parents[1]
USIGN = os.environ.get('USIGN') or shutil.which('usign')


def control_ipk(path, name, version='1-r1', depends='', provides=''):
    data = io.BytesIO()
    control = (f'Package: {name}\nVersion: {version}\n'
               'Architecture: aarch64_cortex-a53\nDescription: fixture\n'
               f'Depends: {depends}\nProvides: {provides}\n').encode()
    with tarfile.open(fileobj=data, mode='w:gz') as archive:
        member = tarfile.TarInfo('./control')
        member.size = len(control)
        archive.addfile(member, io.BytesIO(control))
    with tarfile.open(path, mode='w:gz') as archive:
        member = tarfile.TarInfo('./control.tar.gz')
        member.size = len(data.getvalue())
        archive.addfile(member, io.BytesIO(data.getvalue()))


def kernel_ipk(path, version):
    control_ipk(path, 'kernel', version)


class DependencyClosureTest(unittest.TestCase):
    def test_missing_runtime_provider_refuses_incomplete_snapshot(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        try:
            closure = runpy.run_path(str(ROOT / 'scripts/prepare-firmware.py'))['runtime_dependency_closure']
        finally:
            sys.path.pop(0)
        controls = [(Path('module.ipk'), {'Package': 'kmod-fixture',
                                        'Depends': 'unbuilt-provider (>= 2) | missing-alternative'})]
        with self.assertRaisesRegex(ValueError, 'kmod-fixture -> missing-alternative.*unbuilt-provider'):
            closure(controls, {'kmod-fixture'})


class FirmwareExportIntegration(unittest.TestCase):
    def test_exported_profile_lock_and_sdk_url_describe_actual_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = json.loads((ROOT / 'profiles/redmi-ax6000-new.json').read_text())
            profile['enabled'] = True  # Historical export fixture only.
            profile['packages'] = ['kmod-wireguard', 'kmod-amneziawg', 'fw-helper-live']
            profile['image_packages'] = []
            profile['build_source']['publication_url'] = 'https://example.com/packages'
            profile_path = root / 'profile.json'
            profile_path.write_text(json.dumps(profile))
            lock = {'schema_version': 1, 'profile_id': profile['id'],
                    'profile_sha256': hashlib.sha256(profile_path.read_bytes()).hexdigest(),
                    'firmware': profile['firmware'], 'sdk': profile['sdk'],
                    'feeds': {feed['name']: feed['commit'] for feed in profile['feeds']}}
            lock_path = root / 'lock.json'
            lock_path.write_text(json.dumps(lock))
            source = root / 'source'
            target = source / 'bin/targets/mediatek/filogic'
            target.mkdir(parents=True)
            packages = source / 'bin/packages/aarch64_cortex-a53/base'
            packages.mkdir(parents=True)
            abi = '6.6.133~' + 'a' * 32 + '-r1'
            kernel_ipk(packages / 'kernel.ipk', abi)
            ipk(packages / 'kmod-wireguard.ipk', kernel=abi)
            control_ipk(packages / 'kmod-ipt-geoip.ipk', 'kmod-ipt-geoip',
                        depends=f'kernel (= {abi}), firmware-fixture, batctl (>= 1), fw-helper-live')
            ipk(packages / 'kmod-amneziawg.ipk', name='kmod-amneziawg', kernel=abi)
            control_ipk(packages / 'firmware-fixture.ipk', 'firmware-fixture',
                        depends='libfirmware-fixture (>= 1) | alternative-library')
            control_ipk(packages / 'libfirmware-fixture.ipk', 'libfirmware-fixture', depends='libc')
            control_ipk(packages / 'batctl-default.ipk', 'batctl-default', provides='batctl (= 1-r1)')
            control_ipk(packages / 'libc.ipk', 'libc')
            control_ipk(packages / 'fw-helper-live.ipk', 'fw-helper-live', depends='libfirmware-fixture')
            control_ipk(packages / 'vendor-luci-fixture.ipk', 'vendor-luci-fixture', depends='libvendor-gui')
            control_ipk(packages / 'libvendor-gui.ipk', 'libvendor-gui')
            control_ipk(packages / 'base-files.ipk', 'base-files')
            (target / 'immortalwrt-xiaomi_redmi-router-ax6000-stock-squashfs-sysupgrade.bin').write_bytes(b'image')
            sdk = target / 'immortalwrt-sdk-mediatek-filogic.tar.xz'
            kernel_relative = Path('build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/linux-6.6.133')
            kernel_tree = source / kernel_relative
            kernel_files = {'Makefile': b'all:', '.config': b'CONFIG_WIREGUARD=m\n',
                            'Module.symvers': b'0x12345678\tfixture\tvmlinux\tEXPORT_SYMBOL\n',
                            '.vermagic': ('a' * 32 + '\n').encode(),
                            '.config.set': b'CONFIG_WIREGUARD=m\n',
                            'modules.builtin.modinfo': b'kernel/fixture.ko:license=GPL\x00',
                            'include/generated/autoconf.h': b'#define CONFIG_WIREGUARD_MODULE 1\n',
                            'include/config/kernel.release': b'6.6.133\n'}
            for name, data in kernel_files.items():
                path = kernel_tree / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            (source / 'tmp').mkdir()
            (source / 'tmp/.packageinfo').write_text(
                'Source-Makefile: package/kernel/linux/Makefile\nPackage: kmod-wireguard\n'
                'Source-Makefile: package/feeds/packages/xtables-addons/Makefile\nPackage: kmod-ipt-geoip\n'
                'Source-Makefile: package/feeds/amneziawg/kmod-amneziawg/Makefile\nPackage: kmod-amneziawg\n')
            with tarfile.open(sdk, 'w:xz') as archive:
                sdk_files = {'Makefile': b'all:'}
                sdk_files.update({str(kernel_relative / name): data for name, data in kernel_files.items()
                                  if name not in ('.vermagic', '.config.set', 'modules.builtin.modinfo')})
                for name, data in sdk_files.items():
                    member = tarfile.TarInfo('sdk/' + name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
                which = tarfile.TarInfo('sdk/staging_dir/host/bin/which')
                which.type, which.linkname = tarfile.SYMTYPE, '/usr/bin/which'
                archive.addfile(which)
            signer = source / 'staging_dir/host/bin/usign'
            signer.parent.mkdir(parents=True)
            signer.write_text('#!/bin/sh\nexit 0\n')
            signer.chmod(0o755)
            (source / '.config').write_text('CONFIG_TARGET_mediatek=y\n')
            (source / 'build-selection.json').write_text(json.dumps(
                {'selected_kmods': ['kmod-wireguard', 'kmod-ipt-geoip', 'kmod-amneziawg']}))
            source_patches = vendor_source_fixture(source)['patches']
            fixes = subprocess.run(['python3', str(ROOT / 'scripts/prepare-firmware.py'),
                                    '--profile', str(profile_path), '--lock', str(lock_path),
                                    '--source-dir', str(source), '--phase', 'vendor-fixes'],
                                   text=True, capture_output=True)
            self.assertEqual(fixes.returncode, 0, fixes.stderr)
            defaults = subprocess.run(['python3', str(ROOT / 'scripts/prepare-firmware.py'),
                                       '--profile', str(profile_path), '--lock', str(lock_path),
                                       '--source-dir', str(source), '--phase', 'repository-files'],
                                      text=True, capture_output=True)
            self.assertEqual(defaults.returncode, 0, defaults.stderr)
            output = root / 'raw'
            result = subprocess.run(['python3', str(ROOT / 'scripts/prepare-firmware.py'),
                                     '--profile', str(profile_path), '--lock', str(lock_path),
                                     '--source-dir', str(source), '--phase', 'export',
                                     '--output-dir', str(output)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            generated = json.loads((output / 'profile.json').read_text())
            generated_lock = json.loads((output / 'lock.json').read_text())
            manifest = json.loads((output / 'firmware-manifest.json').read_text())
            self.assertEqual(generated['firmware']['kernel_version'], abi)
            self.assertEqual(generated_lock['firmware'], generated['firmware'])
            self.assertEqual(generated_lock['sdk'], generated['sdk'])
            self.assertEqual(generated_lock['profile_sha256'],
                             hashlib.sha256((output / 'profile.json').read_bytes()).hexdigest())
            self.assertEqual(generated['sdk']['sha256'], hashlib.sha256(sdk.read_bytes()).hexdigest())
            self.assertEqual(generated['build_id'],
                             profile['id'] + '-' + profile['firmware']['commit'][:12] + '-'
                             + generated['sdk']['sha256'][:12])
            self.assertEqual(manifest['build_id'], generated['build_id'])
            self.assertEqual(manifest['source_patches'], source_patches)
            self.assertEqual(urlsplit(generated['sdk']['url']).path,
                             '/packages/firmware/' + manifest['build_id'] + '/' + sdk.name)
            self.assertFalse(generated['all_kmods'])
            self.assertEqual(generated_lock['feeds']['base'], profile['firmware']['commit'])
            with tarfile.open(output / 'bin/targets/mediatek/filogic' / sdk.name) as archive:
                baseline = json.load(archive.extractfile('sdk/ax6000-baseline/manifest.json'))
                which = archive.getmember('sdk/staging_dir/host/bin/which')
                self.assertTrue(which.isfile())
                self.assertEqual(which.mode, 0o755)
                self.assertEqual(archive.extractfile(which).read(), b'#!/bin/sh\nexec /usr/bin/which "$@"\n')
                self.assertEqual(baseline['source_patches'], source_patches)
                self.assertEqual(baseline['kernel_version'], abi)
                self.assertEqual(baseline['frozen_kmods'], ['kmod-ipt-geoip', 'kmod-wireguard'])
                self.assertEqual(baseline['refreshed_kmods'], ['kmod-amneziawg'])
                self.assertEqual(baseline['frozen_packages'],
                                 ['batctl-default', 'firmware-fixture', 'kernel', 'kmod-ipt-geoip',
                                  'kmod-wireguard', 'libc', 'libfirmware-fixture', 'libvendor-gui',
                                  'vendor-luci-fixture'])
                self.assertNotIn('base-files', baseline['frozen_packages'])
                self.assertNotIn('sdk/ax6000-baseline/ipks/kmod-amneziawg.ipk', archive.getnames())
                self.assertNotIn('sdk/ax6000-baseline/ipks/fw-helper-live.ipk', archive.getnames())
                self.assertEqual(archive.extractfile('sdk/ax6000-baseline/ipks/kmod-wireguard.ipk').read(),
                                 (packages / 'kmod-wireguard.ipk').read_bytes())
                for name, data in kernel_files.items():
                    self.assertEqual(archive.extractfile('sdk/' + str(kernel_relative / name)).read(), data)
            extracted = root / 'extracted'
            result = subprocess.run(['python3', str(ROOT / 'scripts/prepare.py'), '--extract', str(sdk),
                                     '--extract-dir', str(extracted)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            daily_sdk = extracted / 'sdk'
            daily_packages = daily_sdk / 'bin/packages'
            daily_packages.mkdir(parents=True)
            ipk(daily_packages / 'amneziawg-refreshed.ipk', name='kmod-amneziawg', kernel=abi)
            control_ipk(daily_packages / 'fw-helper-live-new.ipk', 'fw-helper-live', '2-r1',
                        depends='libfirmware-fixture')
            control_ipk(daily_packages / 'libfirmware-fixture-new.ipk', 'libfirmware-fixture', '2-r1')
            daily_signer = daily_sdk / 'staging_dir/host/bin/usign'
            daily_signer.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(signer, daily_signer)
            shutil.copy2(source / 'build-selection.json', daily_sdk / 'build-selection.json')
            daily_output = root / 'daily-raw'
            result = subprocess.run(['python3', str(ROOT / 'scripts/prepare.py'),
                                     '--profile', str(output / 'profile.json'), '--lock', str(output / 'lock.json'),
                                     '--sdk-dir', str(daily_sdk), '--phase', 'export',
                                     '--sdk-archive', str(sdk), '--output-dir', str(daily_output)],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((daily_output / 'bin/packages/kmod-ipt-geoip.ipk').read_bytes(),
                             (packages / 'kmod-ipt-geoip.ipk').read_bytes())
            self.assertEqual((daily_output / 'bin/packages/amneziawg-refreshed.ipk').read_bytes(),
                             (daily_packages / 'amneziawg-refreshed.ipk').read_bytes())
            self.assertFalse((daily_output / 'bin/packages/kmod-amneziawg.ipk').exists())
            for name in ('firmware-fixture', 'batctl-default', 'libc'):
                self.assertEqual((daily_output / f'bin/packages/{name}.ipk').read_bytes(),
                                 (packages / f'{name}.ipk').read_bytes())
            self.assertTrue((daily_output / 'bin/packages/libfirmware-fixture-new.ipk').is_file())
            self.assertFalse((daily_output / 'bin/packages/libfirmware-fixture.ipk').exists())
            self.assertTrue((daily_output / 'bin/packages/fw-helper-live-new.ipk').is_file())
            read_control = runpy.run_path(str(ROOT / 'scripts/publish.py'))['read_control']
            protected = {'kernel', 'libc', 'base-files', 'busybox', 'opkg'}
            original_names = {read_control(path)['Package'] for path in output.rglob('*.ipk')} - protected
            daily_names = {read_control(path)['Package'] for path in daily_output.rglob('*.ipk')} - protected
            self.assertEqual(original_names, daily_names)
            for name in ('vendor-luci-fixture', 'libvendor-gui'):
                self.assertEqual((daily_output / f'bin/packages/{name}.ipk').read_bytes(),
                                 (packages / f'{name}.ipk').read_bytes())


@unittest.skipUnless(USIGN, 'real OpenWrt host usign unavailable; set USIGN to run signing integration')
class RealSigningIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = self.root / 'raw'
        self.raw.mkdir()
        self.key = self.root / 'private.key'
        self.original_public = self.root / 'public.key'
        subprocess.run([USIGN, '-G', '-s', str(self.key), '-p', str(self.original_public)],
                       check=True, capture_output=True)
        self.profile = {'schema_version': 1, 'id': 'router', 'enabled': True,
                        'firmware': {'kernel_version': '6.6.95~abcdef-r1',
                                     'architecture': 'aarch64_cortex-a53'}}
        self.profile_file = self.root / 'profile.json'
        self.profile_file.write_text(json.dumps(self.profile))
        self.lock = {'schema_version': 1,
                     'profile_sha256': hashlib.sha256(self.profile_file.read_bytes()).hexdigest(),
                     'feeds': {}, 'tailscale': {'version': '1.96.5'}}
        self.lock_file = self.root / 'lock.json'
        self.lock_file.write_text(json.dumps(self.lock))
        self.output = self.root / 'public'

    def publish(self, *extra):
        return subprocess.run(['python3', str(ROOT / 'scripts/publish.py'),
                               '--profile', str(self.profile_file), '--input', str(self.raw),
                               '--output', str(self.output), '--key', str(self.key),
                               '--usign', USIGN, '--lock', str(self.lock_file), *extra],
                              text=True, capture_output=True)

    def test_matching_pinned_key_publishes_signature_verifiable_by_firmware_key(self):
        ipk(self.raw / 'wireguard.ipk', kernel=self.profile['firmware']['kernel_version'])
        result = self.publish('--public-key', str(self.original_public))
        self.assertEqual(result.returncode, 0, result.stderr)
        feed = self.output / 'feeds/router' / self.profile['firmware']['kernel_version']
        verified = subprocess.run([USIGN, '-V', '-m', str(feed / 'Packages'),
                                   '-p', str(self.original_public), '-x', str(feed / 'Packages.sig')],
                                  capture_output=True)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())

    def test_different_signing_key_refuses_before_creating_publication_output(self):
        ipk(self.raw / 'wireguard.ipk', kernel=self.profile['firmware']['kernel_version'])
        foreign_public = self.root / 'foreign.pub'
        subprocess.run([USIGN, '-G', '-s', str(self.root / 'foreign.key'), '-p', str(foreign_public)],
                       check=True, capture_output=True)
        result = self.publish('--public-key', str(foreign_public))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Signing key differs from pinned public key', result.stderr)
        self.assertFalse(self.output.exists())

    def test_malformed_pinned_key_refuses_before_creating_publication_output(self):
        ipk(self.raw / 'wireguard.ipk', kernel=self.profile['firmware']['kernel_version'])
        malformed = self.root / 'malformed.pub'
        for payload in ['not-base64', base64.b64encode(b'wrong-format').decode(),
                        base64.b64encode(b'XX' + bytes(40)).decode()]:
            with self.subTest(payload=payload):
                malformed.write_text('untrusted comment: fixture\n' + payload + '\n')
                result = self.publish('--public-key', str(malformed))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Invalid pinned public key', result.stderr)
                self.assertFalse(self.output.exists())

    def test_real_signed_publication_verifies_decompressed_opkg_index(self):
        package = self.raw / 'kmod-wireguard_1_aarch64_cortex-a53.ipk'
        ipk(package, kernel=self.profile['firmware']['kernel_version'])
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        feed = self.output / 'feeds/router' / self.profile['firmware']['kernel_version']
        decompressed = self.root / 'decompressed-Packages'
        decompressed.write_bytes(gzip.decompress((feed / 'Packages.gz').read_bytes()))
        self.assertEqual(decompressed.read_bytes(), (feed / 'Packages').read_bytes())
        public = self.output / 'repository.pub'
        # usign comments may differ, but the encoded key must match the generated pair.
        self.assertEqual(public.read_text().splitlines()[-1],
                         self.original_public.read_text().splitlines()[-1])
        verify = subprocess.run([USIGN, '-V', '-m', str(decompressed), '-p', str(public),
                                 '-x', str(feed / 'Packages.sig')], capture_output=True)
        self.assertEqual(verify.returncode, 0, verify.stderr.decode())
        decompressed.write_bytes(decompressed.read_bytes() + b'\ncorrupted')
        tampered = subprocess.run([USIGN, '-V', '-m', str(decompressed), '-p', str(public),
                                   '-x', str(feed / 'Packages.sig')], capture_output=True)
        self.assertNotEqual(tampered.returncode, 0)
        self.assertEqual((self.output / 'state/lock.json').read_bytes(), self.lock_file.read_bytes())
        self.assertFalse(any(path.read_bytes() == self.key.read_bytes()
                             for path in self.output.rglob('*') if path.is_file()))

    def test_mismatched_kernel_never_creates_publication_output(self):
        ipk(self.raw / 'wrong.ipk', kernel='6.6.95~wrong-r1')
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('kernel ABI mismatch', result.stderr)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
