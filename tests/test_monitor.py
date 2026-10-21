import importlib.util
import json
import json
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/monitor.py'


class MonitorTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), 'Release monitor must exist')
        spec = importlib.util.spec_from_file_location('monitor', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_stable_manifest_selects_official_arm64_release(self):
        value = self.module.tailscale_artifact({'TarballsVersion': '1.104.1',
            'Tarballs': {'arm64': 'tailscale_1.104.1_arm64.tgz'}},
            'a' * 64 + '\n')
        self.assertEqual(value, {'version':'1.104.1', 'artifact':'static',
            'url':'https://pkgs.tailscale.com/stable/tailscale_1.104.1_arm64.tgz', 'sha256':'a' * 64})

    def test_manifest_rejects_unexpected_archive(self):
        with self.assertRaises(ValueError):
            self.module.tailscale_artifact({'TarballsVersion':'1.104.1',
                'Tarballs':{'arm64':'https://other.example/unsafe.tgz'}}, 'a' * 64)

    def test_bad_checksum_rejected(self):
        with self.assertRaises(ValueError):
            self.module.tailscale_artifact({'TarballsVersion':'1.104.1',
                'Tarballs':{'arm64':'tailscale_1.104.1_arm64.tgz'}}, 'sha256: missing')

    def test_recipe_changes_require_rebuild_even_same_upstream(self):
        self.assertTrue(self.module.changed({'recipe_sha256':'old'}, {'recipe_sha256':'new'}))

    def test_identical_lock_skips_build_regardless_key_order(self):
        self.assertFalse(self.module.changed({'a':1, 'b':2}, {'b':2, 'a':1}))

    def test_apk_lock_binds_manager_and_pinned_public_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile.json'
            profile = {'schema_version': 1, 'id': 'redmi-ax6000-612-recommended',
                       'firmware': {}, 'sdk': {}, 'feeds': [],
                       'package_manager': 'apk', 'apk_key_sha256': 'b' * 64}
            path.write_text(json.dumps(profile))
            manifest = json.dumps({'TarballsVersion': '1.104.1',
                                  'Tarballs': {'arm64': 'tailscale_1.104.1_arm64.tgz'}}).encode()
            with patch.object(self.module, 'fetch', side_effect=[manifest, b'a' * 64]):
                lock = self.module.resolve(path)
            self.assertEqual(lock['package_manager'], 'apk')
            self.assertEqual(lock['apk_key_sha256'], 'b' * 64)
            profile['apk_key_sha256'] = 'not-a-key-hash'
            path.write_text(json.dumps(profile))
            with patch.object(self.module, 'fetch', side_effect=[manifest, b'a' * 64]):
                with self.assertRaisesRegex(ValueError, 'APK.*key'):
                    self.module.resolve(path)

    def test_asu_runtime_asset_and_contract_changes_require_rebuild(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / 'files/asu-client'; assets.mkdir(parents=True)
            module = assets / 'ax6000_asu.js'; module.write_text('first runtime')
            contract = assets / 'contract-fixture.json'; contract.write_text('{"cohort":"66"}')
            with patch.object(self.module, 'ROOT', root):
                first = self.module.recipe_digest()
                module.write_text('changed runtime')
                second = self.module.recipe_digest()
                contract.write_text('{"cohort":"612-latest"}')
                third = self.module.recipe_digest()
            self.assertNotEqual(first, second)
            self.assertNotEqual(second, third)

    def test_native_pinned_feeds_are_resolved_before_pbr_without_git_remote(self):
        profile = {'schema_version': 1, 'id': 'source', 'firmware': {}, 'sdk': {},
                   'pbr_source': 'mossdef-stable', 'feeds': [{'name': 'luci',
                       'url': 'https://github.com/immortalwrt/luci.git', 'commit': 'c' * 40,
                       'monitor_ref': 'refs/heads/openwrt-25.12'}]}
        def author(value, feeds):
            self.assertEqual(value, profile)
            self.assertEqual(feeds, {'luci': 'c' * 40})
            return {'translations': {'ru': {'commit': feeds['luci']}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile.json'; path.write_text(json.dumps(profile))
            responses = [json.dumps({'TarballsVersion': '1.104.2', 'Tarballs': {
                'arm64': 'tailscale_1.104.2_arm64.tgz'}}).encode(), ('a' * 64).encode()]
            with patch.object(self.module, 'fetch', side_effect=responses), patch.object(
                    self.module.subprocess, 'run', side_effect=AssertionError('native lock must not query moving refs')), patch.object(
                    self.module, 'resolve_author_pbr', side_effect=author) as resolve:
                lock = self.module.resolve(path, pinned_feeds=True)
            resolve.assert_called_once()
            self.assertEqual(lock['feeds'], {'luci': 'c' * 40})
            self.assertEqual(lock['pbr']['translations']['ru']['commit'], lock['feeds']['luci'])


if __name__ == '__main__':
    unittest.main()
