"""Optional image checks use reviewed sources and reject actual payload drift."""
import copy
import gzip
from unittest.mock import patch
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import asu_client
import image_features as features
import pbr_sources
import vendor_country
from test_pbr_sources import archive


class ImageFeatureTests(unittest.TestCase):
    def test_native_asu_metadata_identity_runtime_and_no_auto_manager_migration(self):
        for cohort, manager in [('66', 'opkg'), ('612-recommended', 'apk'), ('612-latest', 'apk')]:
            profile = {'package_manager': manager, 'asu': {'enabled': True, 'cohort': cohort,
                       'seed': 'a' * 64, 'server_url': asu_client.URLS[cohort]}}
            expected = features.expected(profile, {})
            files = {path: value[0] for path, value in expected['files'].items()}
            files['usr/lib/lua/luci/i18n/attendedsysupgrade.ru.lmo'] = b'compiled LMO fixture' * 2
            installed = {name: {'Version': version} for name, version in expected['versions'].items()}
            installed['luci-app-attendedsysupgrade'] = {'Version': asu_client.APP_VERSION + '-r' + asu_client.release(profile)}
            installed['luci-i18n-attendedsysupgrade-ru'] = {'Version': '26.123'}
            def verify():
                return features.verify(profile, {}, installed, lambda path, cap: files[path], lambda path, mode: None)
            self.assertEqual(verify()['package_manager'], manager)
            local = json.loads(files['etc/asu-cohort.json'])
            self.assertEqual(local['package_manager'], manager)
            original = files['etc/asu-cohort.json']
            files['etc/asu-cohort.json'] = original.replace(b'"seed": "a', b'"seed": "b')
            with self.assertRaisesRegex(ValueError, 'feature bytes'):
                verify()
            files['etc/asu-cohort.json'] = original
            installed['attendedsysupgrade-common']['Version'] = 'old'
            with self.assertRaisesRegex(ValueError, 'package version'):
                verify()

    def test_app_hotfix_and_unchanged_common_versions_are_independent(self):
        for cohort, manager, common, app in [('66','opkg','9-r2.ax6000asu2','20261021.2-r2.ax6000asu3'),
                                             ('612-recommended','apk','10-r2','20261021.2-r3')]:
            with self.subTest(cohort=cohort):
                profile={'package_manager':manager,'asu':{'enabled':True,'cohort':cohort,
                         'seed':'a'*64,'server_url':asu_client.URLS[cohort]}}
                expected=features.expected(profile,{})
                self.assertEqual(expected['versions']['attendedsysupgrade-common'],common)
                self.assertEqual(expected['versions']['luci-app-attendedsysupgrade'],app)
                files={path:data for path,(data,_) in expected['files'].items()}
                files['usr/lib/lua/luci/i18n/attendedsysupgrade.ru.lmo']=b'compiled LMO fixture'*2
                installed={name:{'Version':version} for name,version in expected['versions'].items()}
                installed['luci-i18n-attendedsysupgrade-ru']={'Version':'26.123'}
                verify=lambda:features.verify(profile,{},installed,lambda path,cap:files[path],lambda path,mode:None)
                self.assertEqual(verify()['package_manager'],manager)
                installed['attendedsysupgrade-common']['Version']=common.rsplit('-r',1)[0]+'-r'+asu_client.release(profile)
                with self.assertRaisesRegex(ValueError,'package version'):verify()

    def test_actual_pinned_luci_install_paths_and_native_compiled_translation_payloads(self):
        import re
        import subprocess
        pins = {'66': 'bc1a97fb6c3b4fef065227c6d1530ee580f0af3966d36a967fbca2da1c7000ac',
                '612': '9716c9a7a1c276b867df5887558e2b63b78f7d3695915adb7fcd0a7f0182ed0d'}
        locations = set()
        for series, digest in pins.items():
            data = (ROOT / 'tests/fixtures/asu-client' / series / 'luci.mk').read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            text = data.decode()
            assignments = [next(line for line in text.splitlines() if line.startswith(name + ' ='))
                           for name in ('LUA_LIBRARYDIR', 'LUCI_LIBRARYDIR')]
            self.assertIn('$$(INSTALL_DIR) $$(1)$(LUCI_LIBRARYDIR)/i18n', text)
            makefile = '\n'.join(assignments) + "\nall:\n\t@printf '%s\\n' '$(LUCI_LIBRARYDIR)/i18n'\n"
            result = subprocess.run(['make', '--no-print-directory', '-f', '-'], input=makefile.encode(),
                                    capture_output=True, check=True)
            locations.add(result.stdout.decode().strip().lstrip('/'))
        self.assertEqual(locations, {'usr/lib/lua/luci/i18n'})
        fixture = ROOT / 'tests/fixtures/native66-lmo'
        digests = {'luci-i18n-attendedsysupgrade-ru': '75e8308bffa4224d327f48180d2ac44dd1a206fbcdebfeff01fb6190262399c5',
                   'luci-i18n-pbr-ru': '6d1a0334be889af27c3a1adcbaf86901e5e8aa552143d06e360620519a3e8726'}
        payload = {}
        for package, digest in digests.items():
            path = next(fixture.glob(package + '_*.ipk'))
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            with tarfile.open(path, 'r:*') as outer:
                data = outer.extractfile('./data.tar.gz').read() if './data.tar.gz' in outer.getnames() else outer.extractfile('data.tar.gz').read()
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                lmos = [entry for entry in archive if entry.isfile() and entry.name.endswith('.lmo')]
                self.assertEqual(len(lmos), 1)
                name = lmos[0].name.removeprefix('./')
                self.assertTrue(name.startswith(next(iter(locations)) + '/'))
                payload[name] = archive.extractfile(lmos[0]).read()
        profile = {'asu': {'enabled': True, 'cohort': '66', 'seed': 'a' * 64,
                          'server_url': asu_client.URLS['66']}}
        expected = features.expected(profile, {})
        files = {path: value[0] for path, value in expected['files'].items()}
        files.update(payload)
        installed = {name: {'Version': version} for name, version in expected['versions'].items()}
        installed['luci-i18n-attendedsysupgrade-ru'] = {'Version': '26.246.30525~80ed8a4'}
        verify = lambda: features.verify(profile, {}, installed, lambda path, cap: files[path],
                                         lambda path, mode: None, native_translations=payload)
        proof = verify()
        lmo = 'usr/lib/lua/luci/i18n/attendedsysupgrade.ru.lmo'
        self.assertEqual(proof['files'][lmo]['sha256'], hashlib.sha256(payload[lmo]).hexdigest())
        files[lmo] = files[lmo][:-1] + bytes([files[lmo][-1] ^ 1])
        with self.assertRaisesRegex(ValueError, 'translation differs'): verify()

    def test_locked_author_archive_drives_exact_pbr_runtime_and_version_substitution(self):
        selected = ['etc/init.d/pbr', 'etc/config/pbr', 'etc/uci-defaults/90-pbr',
                    'usr/share/pbr/.keep', 'usr/share/pbr/pbr.user.dnsprefetch',
                    'usr/share/pbr/pbr.user.aws.uc', 'usr/share/pbr/pbr.user.netflix.uc']
        selected += ['lib/pbr/' + name + '.uc' for name in
                     ('pbr', 'pkg', 'cli', 'sys', 'validators', 'output', 'config', 'platform', 'network', 'nft')]
        extra = {'files/' + path: 'runtime ' + path + '\n' for path in selected}
        extra['files/etc/init.d/pbr'] = "readonly initCompat='38'\n"
        extra['files/lib/pbr/pkg.uc'] = "const pkg = {compat: '38',\n\tversion: 'dev-test',\n};\n"
        sources = {'pbr': archive('pbr', 'a' * 40, extra=extra),
                   'luci-app-pbr': archive('luci-app-pbr', 'b' * 40)}
        pair = {'version': '1.2.4', 'release': 2, 'translations': {}, 'packages': {}}
        for name, char in [('pbr', 'a'), ('luci-app-pbr', 'b')]:
            pair['packages'][name] = {'repository': 'https://github.com/mossdef-org/' + name + '.git',
                'commit': char * 40, 'url': pbr_sources.archive_url(name, char * 40),
                'sha256': hashlib.sha256(sources[name]).hexdigest()}
        profile = {'pbr_source': 'mossdef-stable', 'packages': ['pbr', 'luci-app-pbr'],
                   'asu': {'enabled': True, 'cohort': '66', 'server_url': 'https://asu.ezon.by/66', 'seed': 'a' * 64},
                   'vendor_country_db': True, 'firmware': {'commit': 'ec9ef10efc65da1e6d1de4e2c043c0e13d08eed8'}}
        lock = {'pbr': pair}
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            for name, meta in pair['packages'].items():
                pbr_sources.cache_archive(source, name, meta, sources[name])
            with patch.object(features, 'minified_js', side_effect=lambda data, source: b'minified fixture:' + data) as minifier:
                expected = features.expected(profile, lock, source)
                self.assertIs(minifier.call_args[0][1], source)
            files = {path: data for path, (data, _) in expected['files'].items()}
            self.assertIn(b"version: '1.2.4-r2'", files['lib/pbr/pkg.uc'])
            files['usr/share/luci-app-mtwifi-cfg/wireless-mtk.js'] = vendor_country._patched_js(gzip.decompress(
                (ROOT / 'tests/fixtures/vendor-country/66-wireless-mtk.js.gz').read_bytes()))
            files['usr/lib/lua/luci/i18n/attendedsysupgrade.ru.lmo'] = b'compiled LMO fixture' * 2
            installed = {name: {'Version': version} for name, version in expected['versions'].items()}
            installed['luci-app-attendedsysupgrade'] = {'Version': asu_client.APP_VERSION + '-r' + asu_client.release(profile)}
            installed['luci-i18n-attendedsysupgrade-ru'] = {'Version': '26.123'}
            def verify():
                with patch.object(features, 'minified_js', side_effect=lambda data, source: b'minified fixture:' + data):
                    return features.verify(profile, lock, installed, lambda path, cap: files[path], lambda path, mode: None, source)
            self.assertGreaterEqual(len(verify()['files']), 18)
            files['lib/pbr/pkg.uc'] += b'corrupted runtime'
            with self.assertRaisesRegex(ValueError, 'feature bytes'):
                verify()
            cached = pbr_sources.cached_archive_path(source, 'pbr', pair['packages']['pbr'])
            cached.chmod(0o644); cached.write_bytes(cached.read_bytes() + b'bad archive')
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                features.expected(profile, lock, source)


if __name__ == '__main__':
    unittest.main()
