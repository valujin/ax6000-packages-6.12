"""The mesh SDK carries its native WAPP ABI without rebuilding the vendor driver."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import mediatek_mesh as mesh
from test_mesh_integration import profile

FIXTURES = ROOT / 'tests/fixtures/mesh-uapi'
HEADERS = {'wapp_cmm_type.h': '821fa92e0b2f044928af64e420a4f1735635e7567f312add971c9d715da13898',
           'mt_wlan_cmm_oid.h': 'a11e84592439326bb7d6cc6cc8e4dd1eec4f570b6c31e0bce041039c5ddae5b9'}


def headers():
    result = {name: gzip.decompress((FIXTURES / (name + '.gz')).read_bytes()) for name in HEADERS}
    for name, data in result.items():
        if hashlib.sha256(data).hexdigest() != HEADERS[name]:
            raise AssertionError('Pinned WAPP header fixture differs: ' + name)
    return result


def seed_sdk_headers(sdk):
    directory = sdk / 'ax6000-baseline/mesh-uapi'
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in headers().items():
        (directory / name).write_bytes(data)


class MeshSdkUapi(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('AX6000_METADATA_SOURCE'), 'Set AX6000_METADATA_SOURCE for the real SDK dependency graph')
    def test_mesh_consumers_retain_frozen_mapfilter_without_sdk_compile_edges(self):
        source = Path(os.environ['AX6000_METADATA_SOURCE'])
        with tempfile.TemporaryDirectory(prefix='mesh-mapfilter-graph-') as temporary:
            sdk = Path(temporary)
            for name in ('include', 'scripts', 'config'):
                shutil.copytree(source / name, sdk / name, symlinks=True)
            for name in ('rules.mk', '.config'):
                shutil.copyfile(source / name, sdk / name)
            for name in ('1905daemon', 'ax6000-mesh', 'mapfilter', 'wapp', 'mapd', 'libmapd'):
                shutil.copytree(ROOT / 'files/mediatek-mesh/packages' / name, sdk / 'package/ax6000-overrides' / name)
            hostbin = sdk / 'staging_dir/host/bin'; hostbin.mkdir(parents=True)
            (hostbin / 'mkhash').symlink_to(source / 'staging_dir/host/bin/mkhash')
            (hostbin / 'awk').symlink_to(shutil.which('gawk'))
            env = {**os.environ, 'TOPDIR': str(sdk), 'PATH': str(hostbin) + ':' + os.environ['PATH']}
            baseline = sdk / 'ax6000-baseline/manifest.json'
            baseline.parent.mkdir(); baseline.write_text('{}')
            for native in (False, True):
                if native:
                    baseline.unlink()
                shutil.rmtree(sdk / 'tmp', ignore_errors=True)
                (sdk / 'tmp/info').mkdir(parents=True)
                scan = subprocess.run(['make', '--no-print-directory', '-r', '-f', 'include/scan.mk',
                                       'SCAN_DIR=package', 'SCAN_TARGET=packageinfo'], cwd=sdk, env=env,
                                      capture_output=True, text=True, timeout=60)
                self.assertEqual(scan.returncode, 0, scan.stdout + scan.stderr)
                metadata = (sdk / 'tmp/.packageinfo').read_text()
                self.assertIn('Package: kmod-mapfilter\n', metadata)
                graph = subprocess.run(['perl', 'scripts/package-metadata.pl', 'mk', 'tmp/.packageinfo'],
                                       cwd=sdk, env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(graph.returncode, 0, graph.stderr)
                config = subprocess.run(['perl', 'scripts/package-metadata.pl', 'config', 'tmp/.packageinfo'],
                                        cwd=sdk, env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(config.returncode, 0, config.stderr)
                for name in ('1905daemon', 'ax6000-mesh'):
                    edges = [line for line in graph.stdout.splitlines() if f'/{name}/compile' in line]
                    self.assertEqual(any('/mapfilter/compile' in line for line in edges), native, edges)
                    package = sdk / 'package/ax6000-overrides' / name
                    (package / 'runtime.mk').write_text('include Makefile\n$(eval $(call Package/' + name + '))\n'
                        'runtime-dependency:\n\t@printf "EXTRA=%s\\nDEPENDS=%s\\nPACKED=%s\\n" "$(EXTRA_DEPENDS)" "$(DEPENDS)" "$(call FormatDepends,,$(EXTRA_DEPENDS))"\n')
                    runtime = subprocess.run(['make', '--no-print-directory', '-r', '-f', 'runtime.mk',
                                              'DUMP=1', 'TOPDIR=' + str(sdk), 'runtime-dependency'], cwd=package,
                                             capture_output=True, text=True, timeout=60)
                    self.assertEqual(runtime.returncode, 0, runtime.stdout + runtime.stderr)
                    if native:
                        self.assertIn('+kmod-mapfilter', runtime.stdout)
                    else:
                        self.assertIn('kmod-mapfilter (=6.12.108.3.0.1.2-r1)', runtime.stdout)
                        packed = next(line for line in runtime.stdout.splitlines() if line.startswith('PACKED='))
                        self.assertIn('kmod-mapfilter (=6.12.108.3.0.1.2-r1)', packed)
                        if name == 'ax6000-mesh':
                            self.assertIn('wapp (>=3.0.2.0-r3)', packed)
                        self.assertNotIn('+kmod-mapfilter', runtime.stdout)
                self.assertEqual('select PACKAGE_kmod-mapfilter' in config.stdout, native)
                proof = os.environ.get('AX6000_METADATA_PROOF_DIR')
                if proof:
                    (Path(proof) / ('mesh-mapfilter-native' if native else 'mesh-mapfilter-sdk')).write_text(graph.stdout)

    def test_native_sdk_export_carries_exact_headers_and_detects_tamper(self):
        self.assertTrue(hasattr(mesh, 'export_sdk_uapi'), 'Native mesh SDK header export is required')
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'native'
            kernel = source / 'build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/linux-6.12.108'
            native = {'wapp_cmm_type.h': kernel.parent / 'mt_wifi/mt_wifi/embedded/include/wapp/wapp_cmm_type.h',
                      'mt_wlan_cmm_oid.h': kernel / 'include/uapi/linux/wapp/mt_wlan_cmm_oid.h'}
            for name, data in headers().items():
                native[name].parent.mkdir(parents=True, exist_ok=True)
                native[name].write_bytes(data)
            sdk = Path(temporary) / 'sdk'
            sdk.mkdir()
            mesh.export_sdk_uapi(profile(), source, kernel, sdk)
            self.assertEqual(mesh.verify_sdk_uapi(sdk), HEADERS)
            self.assertFalse((sdk / 'build_dir').exists(), 'SDK needs no external vendor driver source/build')
            copied = sdk / 'ax6000-baseline/mesh-uapi/wapp_cmm_type.h'
            copied.write_bytes(copied.read_bytes() + b'\n/* changed */\n')
            with self.assertRaisesRegex(ValueError, 'WAPP.*header|UAPI'):
                mesh.verify_sdk_uapi(sdk)

    def test_declared_mesh_sdk_without_header_fails_before_source_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            sdk = Path(temporary)
            baseline = sdk / 'ax6000-baseline/manifest.json'
            baseline.parent.mkdir()
            baseline.write_text(json.dumps({'source_commit': mesh.SOURCE_COMMIT, 'mediatek_mesh': mesh.provenance(profile())}))
            with self.assertRaisesRegex(ValueError, 'WAPP.*header|UAPI'):
                mesh.configure(profile(), sdk)
            self.assertFalse((sdk / 'package').exists())

    @unittest.skipUnless(os.environ.get('AX6000_METADATA_SOURCE'), 'Set AX6000_METADATA_SOURCE for the real OpenWrt package prepare path')
    def test_real_wapp_prepare_uses_exported_headers_without_driver_build_dependency(self):
        source = Path(os.environ['AX6000_METADATA_SOURCE'])
        with tempfile.TemporaryDirectory(prefix='mesh-sdk-prepare-') as temporary:
            sdk = Path(temporary)
            for name in ('include', 'scripts', 'config'):
                shutil.copytree(source / name, sdk / name, symlinks=True)
            for name in ('rules.mk', '.config'):
                shutil.copyfile(source / name, sdk / name)
            seed_sdk_headers(sdk)
            (sdk / 'ax6000-baseline/manifest.json').write_text('{}')
            package = sdk / 'package/ax6000-overrides/wapp'
            shutil.copytree(ROOT / 'files/mediatek-mesh/packages/wapp', package)
            (package / 'smoke.mk').write_text('''include Makefile
# Header staging exercises the real recipe; archive extraction is irrelevant here.
define Build/Prepare/Default
endef
.PHONY: sdk-uapi-stage
sdk-uapi-stage:
\t$(call Build/Prepare)
\t@printf 'SDK-BUILD-DEPENDS=%s\\nSDK-BUILD-DIR=%s\\n' '$(PKG_BUILD_DEPENDS)' '$(PKG_BUILD_DIR)'
''')
            result = subprocess.run(['make', '--no-print-directory', '-r', '-f', 'smoke.mk', 'DUMP=1',
                                     'TOPDIR=' + str(sdk), 'sdk-uapi-stage'],
                                    cwd=package, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('SDK-BUILD-DEPENDS=datconf\n', result.stdout)
            build = next(line.split('=', 1)[1] for line in result.stdout.splitlines() if line.startswith('SDK-BUILD-DIR='))
            for name, data in headers().items():
                self.assertEqual((Path(build) / 'driver-uapi' / name).read_bytes(), data)
            self.assertFalse((sdk / 'build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/mt_wifi').exists())

            # Exercise the actual metadata scanner and dependency graph with the
            # real vendor recipe present: runtime DEPENDS also creates edges.
            driver = sdk / 'package/mtk/drivers/mt_wifi'
            driver.mkdir(parents=True)
            shutil.copyfile(source / 'package/mtk/drivers/mt_wifi/Makefile', driver / 'Makefile')
            (sdk / 'tmp/info').mkdir(parents=True, exist_ok=True)
            hostbin = sdk / 'staging_dir/host/bin'
            hostbin.mkdir(parents=True, exist_ok=True)
            (hostbin / 'mkhash').symlink_to(source / 'staging_dir/host/bin/mkhash')
            (hostbin / 'awk').symlink_to(shutil.which('gawk'))
            env = {**os.environ, 'TOPDIR': str(sdk), 'PATH': str(hostbin) + ':' + os.environ['PATH']}
            scan = subprocess.run(['make', '--no-print-directory', '-r', '-f', 'include/scan.mk',
                                   'SCAN_DIR=package', 'SCAN_TARGET=packageinfo'], cwd=sdk, env=env,
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(scan.returncode, 0, scan.stdout + scan.stderr)
            metadata = (sdk / 'tmp/.packageinfo').read_text()
            self.assertIn('Package: kmod-mt_wifi\n', metadata)
            graph = subprocess.run(['perl', 'scripts/package-metadata.pl', 'mk', 'tmp/.packageinfo'],
                                   cwd=sdk, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(graph.returncode, 0, graph.stderr)
            wapp_edges = [line for line in graph.stdout.splitlines()
                          if 'ax6000-overrides/wapp/compile' in line]
            self.assertIn('package-$(CONFIG_PACKAGE_wapp) += ax6000-overrides/wapp', graph.stdout)
            self.assertFalse(any('/mt_wifi/compile' in line for line in wapp_edges), wapp_edges)
            # Positive control: the former runtime dependency really causes
            # the vendor compile edge in this same real metadata graph.
            wapp_start = metadata.index('Package: wapp\n')
            dep_start = metadata.index('Depends: ', wapp_start) + len('Depends: ')
            old_metadata = metadata[:dep_start] + '+kmod-mt_wifi ' + metadata[dep_start:]
            (sdk / 'tmp/.packageinfo-old-dependency').write_text(old_metadata)
            previous = subprocess.run(['perl', 'scripts/package-metadata.pl', 'mk', 'tmp/.packageinfo-old-dependency'],
                                      cwd=sdk, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(previous.returncode, 0, previous.stderr)
            self.assertTrue(any('ax6000-overrides/wapp/compile' in line and '/mt_wifi/compile' in line
                                for line in previous.stdout.splitlines()), previous.stdout)
            # DUMP skips package packing. Evaluate its actual package definition
            # to confirm EXTRA_DEPENDS retains the precise frozen APK version.
            with (package / 'smoke.mk').open('a') as smoke:
                smoke.write("\n$(eval $(call Package/wapp))\nsdk-runtime-dep:\n\t@printf '%s\\nPACKED=%s\\n' '$(EXTRA_DEPENDS)' '$(call FormatDepends,,$(EXTRA_DEPENDS))'\n")
            runtime = subprocess.run(['make', '--no-print-directory', '-r', '-f', 'smoke.mk', 'DUMP=1',
                                      'TOPDIR=' + str(sdk), 'sdk-runtime-dep'], cwd=package,
                                     capture_output=True, text=True, timeout=60)
            self.assertEqual(runtime.returncode, 0, runtime.stdout + runtime.stderr)
            self.assertIn('kmod-mt_wifi (=6.12.108.7.6.7.3-r2)', runtime.stdout)
            self.assertIn('PACKED=kmod-mt_wifi (=6.12.108.7.6.7.3-r2)\n', runtime.stdout)
            proof = os.environ.get('AX6000_METADATA_PROOF_DIR')
            if proof:
                (Path(proof) / 'sdk-packageinfo').write_text(metadata)
                (Path(proof) / 'sdk-packagedeps').write_text(graph.stdout)

            # Native kernel paths are established after package variables. A
            # real Build/Prepare invocation must resolve those paths lazily.
            (sdk / 'ax6000-baseline/manifest.json').unlink()
            kernel_build = sdk / 'native-kernel'
            linux = kernel_build / 'linux-6.12.108'
            paths = {'wapp_cmm_type.h': kernel_build / 'mt_wifi/mt_wifi/embedded/include/wapp/wapp_cmm_type.h',
                     'mt_wlan_cmm_oid.h': linux / 'include/uapi/linux/wapp/mt_wlan_cmm_oid.h'}
            for name, data in headers().items():
                paths[name].parent.mkdir(parents=True, exist_ok=True)
                paths[name].write_bytes(data)
            with (package / 'smoke.mk').open('a') as smoke:
                smoke.write('\nKERNEL_BUILD_DIR:=' + str(kernel_build) + '\nLINUX_DIR:=' + str(linux) + '\n')
            native = subprocess.run(['make', '--no-print-directory', '-r', '-f', 'smoke.mk', 'DUMP=1',
                                     'TOPDIR=' + str(sdk), 'sdk-uapi-stage'], cwd=package,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
            self.assertIn('SDK-BUILD-DEPENDS=mt_wifi datconf\n', native.stdout)
            self.assertIn(str(paths['wapp_cmm_type.h']) + ': OK', native.stdout)


if __name__ == '__main__':
    unittest.main()
