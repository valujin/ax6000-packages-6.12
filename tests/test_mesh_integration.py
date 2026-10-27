"""Feature opt-in, pinned source installation and actual-image contracts."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('mediatek_mesh', ROOT / 'scripts/mediatek_mesh.py')
MESH = None
if Path(SPEC.origin).is_file():
    MESH = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(MESH)


def profile():
    value = json.loads((ROOT / 'profiles/redmi-ax6000-612-recommended-new.json').read_text())
    value['mediatek_mesh'] = True
    for name in ('mapd', 'wapp', '1905daemon', 'libmapd', 'ax6000-mesh', 'luci-app-ax6000-mesh', 'luci-i18n-ax6000-mesh-ru', 'datconf', 'libkvcutil', 'kmod-mapfilter'):
        for key in ('packages', 'image_packages'):
            if name not in value[key]:
                value[key].append(name)
    return value


class MeshIntegration(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(MESH, 'MediaTek mesh integration helper is required')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)

    def test_historical_profiles_have_no_mesh_side_effects(self):
        old = profile()
        del old['mediatek_mesh']
        self.assertFalse(MESH.validate(old))
        self.assertEqual(MESH.symbols(old), {})
        self.assertIsNone(MESH.configure(old, self.source, native=True))
        self.assertEqual(list(self.source.iterdir()), [])

    def test_opt_in_rejects_other_kernels_channels_architectures_and_asu(self):
        for path, value in ((('mediatek_mesh',), 'yes'), (('channel',), 'latest'),
                            (('firmware', 'commit'), 'a' * 40), (('firmware', 'architecture'), 'mipsel_24kc'),
                            (('package_manager',), 'opkg'), (('exclude_asu',), False),
                            (('package_only',), []), (('firmware', 'devices'), [])):
            candidate = profile()
            target = candidate
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                MESH.validate(candidate)
        candidate = profile()
        candidate['asu'] = {'enabled': True}
        with self.assertRaises(ValueError):
            MESH.validate(candidate)

    def test_feature_packages_must_be_requested_and_installed_in_all_layouts(self):
        self.assertTrue(MESH.validate(profile()))
        for field in ('packages', 'image_packages'):
            candidate = profile()
            candidate[field].remove('mapd')
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'packages'):
                MESH.validate(candidate)

    def test_source_installer_checks_all_preimages_before_writing_packages(self):
        from test_mesh_mtwifi import MeshMtwifiTests
        MeshMtwifiTests.setUpClass()
        self.addCleanup(MeshMtwifiTests.doClassCleanups)
        shutil.copytree(MeshMtwifiTests.source / 'package', self.source / 'package')
        subprocess.run(['git', 'apply', '-R', str(ROOT / 'files/mediatek-mesh/patches/mtwifi-mesh.patch')], cwd=self.source, check=True)
        damaged = self.source / 'package/mtk/applications/mtwifi-cfg-ucode/Makefile'
        damaged.write_bytes(damaged.read_bytes() + b'\n# foreign modification\n')
        before = damaged.read_bytes()
        with self.assertRaisesRegex(ValueError, 'preimage|hash|patch'):
            MESH.configure(profile(), self.source, native=True)
        self.assertFalse((self.source / 'package/ax6000-overrides').exists())
        self.assertEqual(damaged.read_bytes(), before)

    def test_sdk_cannot_add_mesh_to_an_older_vendor_generation(self):
        baseline = self.source / 'ax6000-baseline/manifest.json'
        baseline.parent.mkdir()
        baseline.write_text(json.dumps({'source_commit': profile()['firmware']['commit']}))
        with self.assertRaisesRegex(ValueError, 'SDK|native'):
            MESH.configure(profile(), self.source)
        self.assertFalse((self.source / 'package').exists())

    def test_checked_in_profile_only_enables_new_recommended_generation(self):
        source = json.loads((ROOT / 'profiles/redmi-ax6000-612-recommended-new.json').read_text())
        self.assertTrue(source.get('mediatek_mesh'))
        self.assertEqual(source['package_only'], ['tailscale'])
        for filename in ('redmi-ax6000-612-recommended.json', 'redmi-ax6000-612-latest-new.json', 'redmi-ax6000-new.json'):
            self.assertNotIn('mediatek_mesh', json.loads((ROOT / 'profiles' / filename).read_text()))

    def vendor_source(self):
        from test_mesh_mtwifi import MeshMtwifiTests
        MeshMtwifiTests.setUpClass()
        self.addCleanup(MeshMtwifiTests.doClassCleanups)
        shutil.copytree(MeshMtwifiTests.source / 'package', self.source / 'package')
        subprocess.run(['git', 'apply', '-R', str(ROOT / 'files/mediatek-mesh/patches/mtwifi-mesh.patch')], cwd=self.source, check=True)
        return self.source

    def test_complete_native_install_is_idempotent_and_detects_package_tamper(self):
        self.vendor_source()
        selected = profile()
        proof = MESH.configure(selected, self.source, native=True)
        config = ''.join('CONFIG_' + key + '=' + value + '\n' for key, value in MESH.symbols(selected).items())
        (self.source / '.config').write_text(config)
        self.assertEqual(MESH.verify(selected, self.source, native=True), proof)
        self.assertEqual(MESH.configure(selected, self.source, native=True), proof)
        self.assertEqual(proof['vendor_driver']['release'], 2)
        self.assertEqual(proof['vendor_driver']['flags']['MTK_MAP_R3_6E_SUPPORT'], 'y')
        changed = self.source / 'package/ax6000-overrides/mapd/Makefile'
        changed.write_bytes(changed.read_bytes() + b'\n# unreviewed change\n')
        with self.assertRaisesRegex(ValueError, 'copied package differs'):
            MESH.verify(selected, self.source, native=True)

    def test_matching_sdk_uses_native_receipt_and_rejects_abi_flag_drift(self):
        self.vendor_source()
        selected = profile()
        proof = MESH.configure(selected, self.source, native=True)
        baseline = self.source / 'ax6000-baseline/manifest.json'
        baseline.parent.mkdir()
        baseline.write_text(json.dumps({'source_commit': MESH.SOURCE_COMMIT, 'mediatek_mesh': proof}))
        from test_mesh_sdk import seed_sdk_headers
        seed_sdk_headers(self.source)
        (self.source / '.config').write_text(''.join('CONFIG_' + name + '=y\n' for name in MESH.FLAGS))
        self.assertEqual(MESH.configure(selected, self.source), proof)
        self.assertEqual(MESH.verify(selected, self.source), proof)
        (self.source / '.config').write_text('CONFIG_MTK_MAP_SUPPORT=y\n')
        with self.assertRaisesRegex(ValueError, 'build flag differs'):
            MESH.verify(selected, self.source)
        baseline.write_text(json.dumps({'source_commit': MESH.SOURCE_COMMIT, 'mediatek_mesh': {**proof, 'vendor_driver': {}}}))
        with self.assertRaisesRegex(ValueError, 'provenance differs'):
            MESH.configure(selected, self.source)

    def test_actual_image_contract_detects_missing_package_and_changed_runtime(self):
        import image_features
        self.vendor_source()
        selected = profile()
        selected.pop('pbr_source', None)
        selected.pop('vendor_country_db', None)
        MESH.configure(selected, self.source, native=True)
        policy = image_features.expected(selected, {})
        files = {name: data for name, (data, mode) in policy['files'].items()}
        from test_image_features import argon_payload
        files.update(argon_payload())
        for relative in json.loads((ROOT / 'files/mediatek-mesh/patches/mtwifi-manifest.json').read_text())['files']:
            if '/files/' in relative:
                files[relative.split('/files/', 1)[1]] = (self.source / relative).read_bytes()
        translation = 'usr/lib/lua/luci/i18n/ax6000-mesh.ru.lmo'
        files[translation] = b'compiled translation fixture' * 2
        installed = {name: {'Version': value} for name, value in policy['versions'].items()}
        installed['luci-i18n-ax6000-mesh-ru'] = {'Version': '20261027-r1'}
        verify = lambda: image_features.verify(selected, {}, installed, lambda name, cap: files[name], lambda name, mode: None,
                                               native_translations={translation: files[translation]})
        checked = verify()
        self.assertIn('mapd', checked['packages'])
        self.assertIn('lib/netifd/wireless/mtwifi.sh', checked['files'])
        original = installed.pop('mapd')
        with self.assertRaisesRegex(ValueError, 'package version'):
            verify()
        installed['mapd'] = original
        files['usr/libexec/ax6000-mesh-control'] += b'\nchanged\n'
        with self.assertRaisesRegex(ValueError, 'feature bytes'):
            verify()

    def test_native_daemon_payload_mismatch_is_rejected(self):
        selected = profile()
        names = ('wapp', 'wappctrl', 'mapd', 'mapd_cli', 'p1905_managerd', '1905ctrl')
        payload = {'usr/bin/' + name: ('native package fixture ' + name).encode() for name in names}
        payload['usr/lib/libmapd_interface_client.so'] = b'native libmapd fixture'
        payload['usr/lib/libeth_1905ops.so'] = b'native ethernet fixture'
        for name, data in payload.items():
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o755 if name.startswith('usr/bin/') else 0o644)
        read_file = lambda name, cap: (self.source / name).read_bytes()
        def check_mode(name, mode):
            if (self.source / name).stat().st_mode & 0o777 != mode:
                raise ValueError('native daemon mode differs')
        verified = MESH.verify_payloads(selected, {'mapd': payload}, read_file, check_mode)
        self.assertEqual(verified['usr/bin/mapd']['mode'], '0755')
        daemon = self.source / 'usr/bin/mapd'
        daemon.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'mode differs'):
            MESH.verify_payloads(selected, {'mapd': payload}, read_file, check_mode)
        daemon.chmod(0o755)
        daemon.write_bytes(b'foreign binary fixture')
        with self.assertRaisesRegex(ValueError, 'native bytes differ'):
            MESH.verify_payloads(selected, {'mapd': payload}, read_file, check_mode)

    def test_recipe_digest_tracks_nested_mesh_asset_changes(self):
        import monitor
        asset = self.source / 'files/mediatek-mesh/packages/runtime/files/etc/config/mesh'
        asset.parent.mkdir(parents=True)
        asset.write_bytes(b'approved')
        with patch.object(monitor, 'ROOT', self.source):
            first = monitor.recipe_digest()
            asset.write_bytes(b'changed')
            self.assertNotEqual(monitor.recipe_digest(), first)

    def test_native_abi_marker_is_immutable_and_not_shipped_by_runtime_apk(self):
        self.vendor_source()
        selected = profile()
        MESH.configure(selected, self.source, native=True)
        marker = self.source / 'files' / MESH.ABI_PATH
        self.assertEqual(marker.read_bytes(), MESH.abi_bytes())
        self.assertEqual(marker.stat().st_mode & 0o777, 0o644)
        for package in MESH.LOCAL_PACKAGES:
            self.assertFalse((ROOT / 'files/mediatek-mesh/packages' / package / 'files' / MESH.ABI_PATH).exists())
            self.assertFalse((ROOT / 'files/mediatek-mesh/packages' / package / 'root' / MESH.ABI_PATH).exists())
        marker.write_bytes(b'{}\n')
        with self.assertRaisesRegex(ValueError, 'ABI marker differs'):
            MESH.configure(selected, self.source, native=True)


if __name__ == '__main__':
    unittest.main()
