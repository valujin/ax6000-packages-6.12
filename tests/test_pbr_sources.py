"""Stable author PBR source selection and complete overlay boundaries."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import pbr_sources as pbr


def archive(name, commit, version='1.2.4', release=2, compat=38, extra=None):
    make = f'PKG_NAME:={name}\nPKG_VERSION:={version}\nPKG_RELEASE:={release}\n'
    if name == 'pbr':
        files = {'Makefile': make, 'files/etc/init.d/pbr': f"readonly initCompat='{compat}'\n",
                 'files/etc/config/pbr': "config pbr 'config'\n",
                 'files/lib/pbr/pkg.uc': f"const pkg = {{compat: '{compat}'}};\n",
                 'files/lib/pbr/pbr.uc': 'export default function() {};\n'}
    else:
        files = {'Makefile': make + 'include ../../luci.mk\n',
                 'root/usr/share/rpcd/ucode/luci.pbr': f'const rpcdCompat = {compat};\n',
                 'htdocs/luci-static/resources/pbr/status.js':
                     f'get LuciCompat() {{ return {compat}; }}\n',
                 'po/templates/pbr.pot': 'msgid "Policy Routing"\nmsgstr ""\n'}
    files.update(extra or {})
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as tar:
        for path, text in files.items():
            value = text.encode(); info = tarfile.TarInfo(f'{name}-{commit}/{path}')
            info.size = len(value); tar.addfile(info, io.BytesIO(value))
    return output.getvalue()


class PbrSourceTests(unittest.TestCase):
    def setUp(self):
        self.profile = {'pbr_source': 'mossdef-stable', 'packages': ['pbr', 'luci-app-pbr', 'luci-i18n-pbr-ru'],
                        'luci_languages': ['ru'], 'feeds': [{'name': 'luci',
                         'url': 'https://github.com/immortalwrt/luci.git', 'commit': 'c' * 40}]}
        self.pins = {'luci': 'd' * 40}
        self.archives = {}
        packages = {}
        for name, char in [('pbr', 'a'), ('luci-app-pbr', 'b')]:
            commit = char * 40; data = archive(name, commit)
            self.archives[pbr.archive_url(name, commit)] = data
            packages[name] = {'repository': 'https://github.com/mossdef-org/' + name + '.git',
                              'commit': commit, 'url': pbr.archive_url(name, commit),
                              'sha256': hashlib.sha256(data).hexdigest()}
        self.translation = b'msgid "Policy Routing"\nmsgstr "Russian"\n'
        self.value = {'version': '1.2.4', 'release': 2, 'packages': packages,
                      'translation_package_manager': 'opkg',
                      'translation_version': '20261018.160000+pbr1.2.4-r2',
                      'translation_commit_timestamp': '2026-10-18T16:00:00Z',
                      'translations': {'ru': {'feed': 'luci', 'commit': 'd' * 40,
                          'path': 'applications/luci-app-pbr/po/ru/pbr.po',
                          'sha256': hashlib.sha256(self.translation).hexdigest()}}}
        self.lock = {'feeds': self.pins, 'pbr': self.value}

    def test_old_profiles_and_locks_are_unchanged(self):
        self.assertIsNone(pbr.validate({}, {}))
        with self.assertRaisesRegex(ValueError, 'opt-in'):
            pbr.validate({}, self.lock)
        with self.assertRaisesRegex(ValueError, 'requires'):
            pbr.validate(self.profile, {})

    def test_stable_pair_uses_numeric_order_and_rejects_half_release(self):
        stable = [{'tag_name': x, 'draft': False, 'prerelease': False} for x in
                  ('v1.2.4-0', 'v1.2.4-2', 'v1.2.4-3', 'v1.2.3-101')]
        self.assertEqual(pbr.select_release(stable, stable), ('1.2.4', 2))
        with self.assertRaisesRegex(ValueError, 'matching'):
            pbr.select_release(stable, stable[:1])
        with self.assertRaisesRegex(ValueError, 'stable'):
            pbr.select_release(stable[2:], stable[2:])

    def test_pair_metadata_and_translation_pin_validation(self):
        self.assertEqual(pbr.validate(self.profile, self.lock), self.value)
        for mutate in (lambda v: v.update(release=3),
                       lambda v: v['packages']['pbr'].update(commit='main'),
                       lambda v: v['packages'].pop('luci-app-pbr'),
                       lambda v: v['translations']['ru'].update(commit='c' * 40),
                       lambda v: v['packages']['pbr'].update(url='https://evil.example/a.tar.gz')):
            bad = copy.deepcopy(self.lock); mutate(bad['pbr'])
            with self.assertRaises(ValueError): pbr.validate(self.profile, bad)

    def test_archive_rejects_hash_mismatch_readme_tag_and_traversal(self):
        meta = self.value['packages']['pbr']; data = self.archives[meta['url']]
        self.assertIn('Makefile', pbr.read_archive('pbr', meta, self.value, data))
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            pbr.read_archive('pbr', meta, self.value, data + b'corrupt')
        for files in ({'README.md': '# README-only main tag'}, {'../escape': 'bad'}):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w:gz') as tar:
                for path, text in files.items():
                    value = text.encode(); info = tarfile.TarInfo('pbr-' + 'a' * 40 + '/' + path)
                    info.size = len(value); tar.addfile(info, io.BytesIO(value))
            data = output.getvalue(); changed = dict(meta, sha256=hashlib.sha256(data).hexdigest())
            with self.assertRaises(ValueError): pbr.read_archive('pbr', changed, self.value, data)

    def test_complete_overlay_drops_old_rpc_keeps_only_pinned_translation(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory)
            for name in pbr.PACKAGES:
                recipe = sdk / 'feeds' / ('luci/applications' if name.startswith('luci') else 'packages/net') / name
                recipe.mkdir(parents=True); (recipe / 'Makefile').write_text('old recipe')
                link = sdk / 'package/feeds/old' / name; link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(recipe)
            old = sdk / 'feeds/luci/applications/luci-app-pbr'
            (old / 'root/usr/libexec/rpcd').mkdir(parents=True)
            (old / 'root/usr/libexec/rpcd/luci.pbr').write_text('old shell RPC')
            (old / 'po/ru').mkdir(parents=True); (old / 'po/ru/pbr.po').write_bytes(self.translation)
            (sdk / 'feeds/luci/luci.mk').write_text('# pinned LuCI build rules')
            with patch.object(pbr, 'local_feed_timestamp', return_value='2026-10-19T16:00:00Z'):
                with self.assertRaisesRegex(ValueError, 'timestamp differs'):
                    pbr.apply(self.profile, self.lock, sdk, fetch=self.archives.__getitem__)
            self.assertFalse((sdk / 'package/ax6000-overrides/pbr').exists())
            with patch.object(pbr, 'local_feed_timestamp', return_value='2026-10-18T16:00:00Z'):
                pbr.apply(self.profile, self.lock, sdk, fetch=self.archives.__getitem__)
            target = sdk / 'package/ax6000-overrides/luci-app-pbr'
            self.assertFalse((target / 'root/usr/libexec/rpcd/luci.pbr').exists())
            self.assertTrue((target / 'root/usr/share/rpcd/ucode/luci.pbr').exists())
            self.assertEqual((target / 'po/ru/pbr.po').read_bytes(), self.translation)
            self.assertIn('include $(TOPDIR)/feeds/luci/luci.mk', (target / 'Makefile').read_text())
            self.assertIn('PKG_PO_VERSION:=20261018.160000+pbr1.2.4-r2', (target / 'Makefile').read_text())
            self.assertFalse((sdk / 'package/feeds/old/pbr').exists())
            self.assertEqual((old / 'Makefile').read_text(), 'old recipe')

    def test_bad_pair_is_rejected_before_any_overlay_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory)
            bad = dict(self.archives)
            meta = self.value['packages']['luci-app-pbr']
            bad[meta['url']] = b'bad bytes'
            with self.assertRaises(ValueError): pbr.apply(self.profile, self.lock, sdk, fetch=bad.__getitem__)
            self.assertFalse((sdk / 'package/ax6000-overrides/pbr').exists())

    def test_monitor_uses_published_branch_recipe_commit_not_readme_release_tag(self):
        responses = {}
        for name, meta in self.value['packages'].items():
            api = 'https://api.github.com/repos/mossdef-org/' + name + '/'
            responses[api + 'releases?per_page=100'] = json.dumps([{
                'tag_name': 'v1.2.4-2', 'draft': False, 'prerelease': False,
                'published_at': '2026-10-18T16:20:00Z', 'target_commitish': 'main'}]).encode()
            responses[api + 'commits?sha=1.2.4&path=Makefile&per_page=100'] = json.dumps([
                {'sha': 'e' * 40, 'commit': {'committer': {'date': '2026-10-19T00:00:00Z'}}},
                {'sha': meta['commit'], 'commit': {'committer': {'date': '2026-10-18T16:05:00Z'}}}]).encode()
            responses[f'https://raw.githubusercontent.com/mossdef-org/{name}/{meta["commit"]}/Makefile'] = (
                f'PKG_NAME:={name}\nPKG_VERSION:=1.2.4\nPKG_RELEASE:=2\n').encode()
        responses.update(self.archives)
        responses['https://raw.githubusercontent.com/immortalwrt/luci/' + 'd' * 40 +
                  '/applications/luci-app-pbr/po/ru/pbr.po'] = self.translation
        responses['https://api.github.com/repos/immortalwrt/luci/commits/' + 'd' * 40] = json.dumps({
            'sha': 'd' * 40, 'commit': {'committer': {'date': '2026-10-18T16:00:00Z'}}}).encode()
        result = pbr.resolve(self.profile, self.pins, fetch=responses.__getitem__)
        self.assertEqual(result, self.value)
        responses['https://api.github.com/repos/mossdef-org/luci-app-pbr/releases?per_page=100'] = b'[]'
        with self.assertRaises(ValueError): pbr.resolve(self.profile, self.pins, fetch=responses.__getitem__)

    def test_compatibility_mismatch_is_rejected(self):
        sources = {name: pbr.read_archive(name, meta, self.value, self.archives[meta['url']])
                   for name, meta in self.value['packages'].items()}
        sources['luci-app-pbr']['root/usr/share/rpcd/ucode/luci.pbr'] = b'const rpcdCompat = 39;'
        with self.assertRaisesRegex(ValueError, 'stamps differ'): pbr.verify_compatibility(sources)

    def test_archive_correct_hash_still_requires_matching_recipe_and_no_links(self):
        meta = self.value['packages']['pbr']
        data = archive('pbr', meta['commit'], release=0)
        changed = dict(meta, sha256=hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(ValueError, 'recipe version'):
            pbr.read_archive('pbr', changed, self.value, data)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as tar:
            info = tarfile.TarInfo('pbr-' + 'a' * 40 + '/escape')
            info.type = tarfile.SYMTYPE; info.linkname = '/outside'; tar.addfile(info)
        data = output.getvalue(); changed = dict(meta, sha256=hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(ValueError, 'links'):
            pbr.read_archive('pbr', changed, self.value, data)

    def test_monitor_legacy_output_has_no_pbr_or_new_network_requests(self):
        import monitor
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile.json'
            profile = {'schema_version': 1, 'id': 'legacy', 'firmware': {}, 'sdk': {},
                       'feeds': [{'name': 'luci', 'url': 'https://github.com/immortalwrt/luci.git',
                                  'commit': 'd' * 40}]}
            path.write_text(json.dumps(profile))
            with patch.object(monitor, 'fetch', side_effect=[json.dumps({'TarballsVersion': '1.104.2',
                    'Tarballs': {'arm64': 'tailscale_1.104.2_arm64.tgz'}}).encode(), ('a' * 64).encode()]) as fetch:
                lock = monitor.resolve(path)
            self.assertNotIn('pbr', lock)
            self.assertEqual(fetch.call_count, 2)

    def test_prepare_integration_rejects_opt_in_without_complete_lock(self):
        import prepare
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'requires'):
                prepare.apply_overrides({}, Path(directory), self.profile)

    def test_translation_version_requires_pinned_timestamp_not_wallclock(self):
        self.assertEqual(pbr.translation_version('2026-10-18T16:00:00Z', '1.2.4', 2),
                         '20261018.160000+pbr1.2.4-r2')
        bad = copy.deepcopy(self.lock); bad['pbr']['translation_version'] = '0'
        with self.assertRaisesRegex(ValueError, 'translation version'): pbr.validate(self.profile, bad)
        with patch.object(pbr.subprocess, 'check_output', return_value='d' * 40 + '\n1792339200\n'):
            self.assertEqual(pbr.local_feed_timestamp(Path('/unused'), 'd' * 40), '2026-10-18T16:00:00Z')
        with patch.object(pbr.subprocess, 'check_output', return_value='e' * 40 + '\n1792339200\n'):
            with self.assertRaisesRegex(ValueError, 'checkout'): pbr.local_feed_timestamp(Path('/unused'), 'd' * 40)

    def test_prepare_loaded_by_filename_resolves_sibling_without_sys_path_changes(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/prepare.py'
        code = '''import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_prepare', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
helper = module.pbr_source_module()
assert helper.validate({}, {}) is None
try:
    helper.validate({'pbr_source': 'mossdef-stable', 'packages': ['pbr', 'luci-app-pbr']}, {})
except ValueError as error:
    assert 'requires' in str(error)
else:
    raise AssertionError('missing source lock accepted')
'''
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-B', '-c', code, str(script)], cwd=directory,
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_locked_source_archive_cache_is_readonly_and_hash_checked_on_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory); meta = self.value['packages']['pbr']
            data = self.archives[meta['url']]
            pbr.cache_archive(sdk, 'pbr', meta, data)
            path = pbr.cached_archive_path(sdk, 'pbr', meta)
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(path.stat().st_mode & 0o222, 0)
            with patch.object(pbr, 'fetch_bytes', side_effect=AssertionError('cache should avoid download')):
                self.assertEqual(pbr.source_archive(sdk, 'pbr', meta, pbr.fetch_bytes), data)
            path.chmod(0o644); path.write_bytes(data + b'corrupt')
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                pbr.source_archive(sdk, 'pbr', meta, self.archives.__getitem__)

    def test_apk_translation_version_is_numeric_and_format_bound(self):
        version = pbr.translation_version('2026-09-06T07:54:19Z', '1.2.4', 2, 'apk')
        self.assertEqual(version, '20260906.075419.1.2.4-r2')
        profile = copy.deepcopy(self.profile); profile['package_manager'] = 'apk'
        with self.assertRaisesRegex(ValueError, 'package manager'): pbr.validate(profile, self.lock)
        lock = copy.deepcopy(self.lock)
        lock['pbr']['translation_package_manager'] = 'apk'
        lock['pbr']['translation_version'] = pbr.translation_version('2026-10-18T16:00:00Z', '1.2.4', 2, 'apk')
        pbr.validate(profile, lock)
        with self.assertRaisesRegex(ValueError, 'package manager'): pbr.validate(self.profile, lock)

    def test_actual_apk_accepts_translation_version_and_orders_updates(self):
        apk = os.environ.get('APK')
        if not apk: self.skipTest('Set APK to independently trusted host apk-tools')
        timestamp = '2026-09-06T07:54:19Z'
        current = pbr.translation_version(timestamp, '1.2.4', 2, 'apk')
        next_release = pbr.translation_version(timestamp, '1.2.4', 4, 'apk')
        next_version = pbr.translation_version(timestamp, '1.2.6', 0, 'apk')
        for version in (current, next_release, next_version):
            checked = subprocess.run([apk, 'version', '--check', version], capture_output=True, text=True)
            self.assertEqual(checked.stdout, '', 'APK reports an invalid version on stdout')
            self.assertEqual(checked.stderr, '')
            self.assertEqual(checked.returncode, 0)
        for newer, older in ((current, '26.249.28459~d6167ea'), (next_release, current), (next_version, current)):
            compared = subprocess.run([apk, 'version', '--test', newer, older], capture_output=True, text=True)
            self.assertEqual(compared.returncode, 0, compared.stderr)
            self.assertEqual(compared.stdout.strip(), '>')


if __name__ == '__main__': unittest.main()
