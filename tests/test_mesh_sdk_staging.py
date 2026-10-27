"""Exercise real development staging after dependency build directories vanish."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ROOT / 'files/mediatek-mesh/packages'


@unittest.skipUnless(os.environ.get('AX6000_METADATA_SOURCE') and os.environ.get('AX6000_MESH_SOURCE_ARCHIVES'),
                     'Set AX6000_METADATA_SOURCE and AX6000_MESH_SOURCE_ARCHIVES for real source/staging checks')
class MeshDevelopmentStaging(unittest.TestCase):
    def test_mapd_uses_exact_staged_dependencies_after_sdk_autoremove(self):
        source = Path(os.environ['AX6000_METADATA_SOURCE'])
        archives = Path(os.environ['AX6000_MESH_SOURCE_ARCHIVES'])
        with tempfile.TemporaryDirectory(prefix='mesh-sdk-staging-') as temporary:
            sdk = Path(temporary)
            for name in ('include', 'scripts', 'config'):
                shutil.copytree(source / name, sdk / name, symlinks=True)
            for name in ('rules.mk', '.config'):
                shutil.copyfile(source / name, sdk / name)
            build, staging = sdk / 'build', sdk / 'staging'
            build.mkdir()
            roots = {'wapp': 'wappd', '1905daemon': '1905daemon', 'libmapd': 'libmapd', 'mapd': 'mapd'}
            for name, dirname in roots.items():
                recipe = (PACKAGES / name / 'Makefile').read_text()
                filename = re.search(r'^PKG_SOURCE:=(.+)$', recipe, re.M)[1]
                expected = re.search(r'^PKG_HASH:=(.+)$', recipe, re.M)[1]
                archive = archives / filename
                self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), expected)
                subprocess.run(['tar', '-xjf', str(archive), '-C', str(build)], check=True, timeout=60)
                for patch in sorted((PACKAGES / name / 'patches').glob('*.patch')):
                    applied = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                                             cwd=build / dirname, capture_output=True, text=True, timeout=30)
                    self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
            # Sentinel libraries test the real InstallDev file-copy contract;
            # target compilation/linking is covered by the actual SDK proof.
            libraries = {'wapp': 'libwapp_usr_intf_client.a',
                         '1905daemon': 'lib_export/lib1905_interface.a',
                         'libmapd': 'libmapd_interface_client.so'}
            for name, relative in libraries.items():
                (build / roots[name] / relative).write_bytes(('staging fixture ' + name).encode())
                package = sdk / 'package/ax6000-overrides' / name
                shutil.copytree(PACKAGES / name, package)
                (package / 'stage.mk').write_text('include Makefile\n'
                    'PKG_BUILD_DIR:=' + str(build / roots[name]) + '\n'
                    'stage-development:\n\t$(call Build/InstallDev,$(STAGING_DIR))\n')
                result = subprocess.run(['make', '--no-print-directory', '-r', '-f', 'stage.mk', 'DUMP=1',
                                         'TOPDIR=' + str(sdk), 'STAGING_DIR=' + str(staging), 'stage-development'],
                                        cwd=package, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            expected = {'usr/include/mediatek/1905/' + name: build / '1905daemon/lib_export' / name
                        for name in ('data_def.h', 'interface.h', '_1905_interface_ctrl.h')}
            expected['usr/include/mediatek/wapp/wapp_usr_intf/wapp_usr_intf_ctrl.h'] = build / 'wappd/wapp_usr_intf/wapp_usr_intf_ctrl.h'
            for name, relative in libraries.items():
                expected['usr/lib/' + Path(relative).name] = build / roots[name] / relative
            for relative, original in expected.items():
                self.assertEqual((staging / relative).read_bytes(), original.read_bytes(), relative)
            self.assertFalse((staging / 'usr/include/mediatek/1905/os.h').exists())
            # Simulate CONFIG_AUTOREMOVE=y after successful dependency staging.
            for dirname in ('wappd', '1905daemon', 'libmapd'):
                shutil.rmtree(build / dirname)
            mapd = build / 'mapd'
            (mapd / 'inspect.mk').write_text('include Makefile\n'
                'staged-inputs:\n\t@printf "%s\\n" "$(CFLAGS) $(FLAGS_1905) $(LIBS) $(LIBS_c) $(LIBS_bs)"\n')
            result = subprocess.run(['make', '--no-print-directory', '-r', '-f', 'inspect.mk',
                                     'TOPDIR=' + str(sdk), 'STAGING_DIR=' + str(staging),
                                     'CONFIG_SUPPORT_OPENWRT=y', 'staged-inputs'], cwd=mapd,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for dirname in ('wappd', '1905daemon', 'libmapd'):
                self.assertNotIn(str(build / dirname), result.stdout)
                self.assertNotIn('../' + dirname, result.stdout)
            self.assertIn(str(staging / 'usr/include/mediatek/1905'), result.stdout)
            self.assertIn(str(staging / 'usr/lib/lib1905_interface.a'), result.stdout)
            # Preserve mapd's patched interface.h/os.h include precedence.
            self.assertLess(result.stdout.index(str(mapd / 'src/utils')),
                            result.stdout.index(str(staging / 'usr/include/mediatek/1905')))


if __name__ == '__main__':
    unittest.main()
