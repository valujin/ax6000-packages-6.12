"""Optional image checks use reviewed sources and reject actual payload drift."""
import copy
import gzip
from unittest.mock import patch
import hashlib
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
import asu_client
import image_features as features
import pbr_sources
import vendor_country
from test_pbr_sources import archive


def argon_payload():
    fixture = ROOT / 'tests/fixtures/argon-native612/installed-assets.tar.gz'
    data = fixture.read_bytes()
    if hashlib.sha256(data).hexdigest() != '5d4edb90d3f4f9e9513bafedf4885b9efde17b6364ab52e655e74e2a2e10d987':
        raise AssertionError('Genuine installed Argon fixture checksum differs')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as payload:
        return {entry.name: payload.extractfile(entry).read() for entry in payload if entry.isfile()}


def mtwifi_timeout_sources():
    data = (ROOT / 'tests/fixtures/native612-mtwifi-timeout/source.tar.gz').read_bytes()
    if hashlib.sha256(data).hexdigest() != 'af1552dca943a160d374252ff08fade5bb008c043ede1ebdaf3838fb3c133301':
        raise AssertionError('Pinned wifi-scripts source fixture checksum differs')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as payload:
        return {entry.name: payload.extractfile(entry).read() for entry in payload if entry.isfile()}


class ImageFeatureTests(unittest.TestCase):
    def test_timeout_image_fixture_is_exact_pinned_source_plus_reviewed_patch(self):
        directory = ROOT / 'patches/firmware-6.12/recommended'
        manifest = json.loads((directory / 'manifest.json').read_bytes())
        spec = next(p for p in manifest['patches'] if p['patch'] == '170-mtwifi-setup-timeout.patch')
        files = mtwifi_timeout_sources()
        self.assertEqual(hashlib.sha256(files['before.uc']).hexdigest(), spec['before_sha256'])
        self.assertEqual(hashlib.sha256(files['after.uc']).hexdigest(), spec['after_sha256'])
        patch = directory / spec['patch']
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), spec['sha256'])
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / spec['path']
            target.parent.mkdir(parents=True)
            target.write_bytes(files['before.uc'])
            subprocess.run(['git', 'apply', '--check', str(patch)], cwd=temporary, check=True)
            subprocess.run(['git', 'apply', str(patch)], cwd=temporary, check=True)
            self.assertEqual(target.read_bytes(), files['after.uc'])

    def test_argon_requested_in_native_seed_cannot_be_missing_from_image(self):
        seed = json.loads((ROOT / 'profiles/redmi-ax6000-612-recommended-new.json').read_text())
        self.assertIn('luci-theme-argon', seed['packages'])
        self.assertIn('luci-theme-argon', seed['image_packages'])
        profile = {'package_manager': 'apk', 'packages': ['luci-theme-argon'],
                   'image_packages': ['luci-theme-argon']}
        with self.assertRaisesRegex(ValueError, 'package version differs: luci-theme-argon'):
            features.verify(profile, {}, {}, lambda path, cap: b'', lambda path, mode: None)

    def test_argon_image_selection_requires_requested_package(self):
        with self.assertRaisesRegex(ValueError, 'Argon image package must also be requested'):
            features.expected({'packages': [], 'image_packages': ['luci-theme-argon']}, {})

    def test_argon_genuine_modern_templates_and_css_reject_missing_or_modified_payload(self):
        profile = {'package_manager': 'apk', 'packages': ['luci-theme-argon'],
                   'image_packages': ['luci-theme-argon']}
        policy = features.expected(profile, {})
        self.assertEqual(policy['versions'], {'luci-theme-argon': '2.4.7-r20260824'})
        files = argon_payload()
        self.assertEqual(set(files), set(policy['hashes']))
        installed = {'luci-theme-argon': {'Version': '2.4.7-r20260824'}}
        modes = {}
        def verify():
            return features.verify(profile, {}, installed, lambda path, cap: files.get(path, b''),
                                   lambda path, mode: modes.update({path: mode}))
        checked = verify()
        self.assertIn('usr/share/ucode/luci/template/themes/argon/header.ut', checked['files'])
        self.assertTrue(all(mode == 0o644 for mode in modes.values()))
        for path in files:
            original = files[path]
            for bad in (b'', original + b'changed'):
                files[path] = bad
                with self.subTest(path=path, missing=not bad):
                    with self.assertRaisesRegex(ValueError, 'feature hash differs'):
                        verify()
            files[path] = original
        installed['luci-theme-argon']['Version'] = 'old'
        with self.assertRaisesRegex(ValueError, 'package version differs: luci-theme-argon'):
            verify()

    @unittest.skipUnless(os.environ.get('AX6000_METADATA_SOURCE'),
                         'Set AX6000_METADATA_SOURCE for exact pinned Argon source install rules')
    def test_argon_genuine_fixture_matches_pinned_feed_install_rules(self):
        theme = Path(os.environ['AX6000_METADATA_SOURCE']) / 'feeds/luci/themes/luci-theme-argon'
        for path, installed in argon_payload().items():
            if path.startswith('usr/share/ucode/luci/'):
                data = (theme / 'ucode' / path.removeprefix('usr/share/ucode/luci/')).read_bytes()
                # Execute the pinned luci.mk SubstituteVersion sed expressions.
                data = subprocess.run(['sed', '-e', r's/{# *\([^ ]*\)PKG_VERSION *#}/\12.4.7/g',
                    '-e', r's/"\({{ *\(media\|resource\) *}}[^"]*\.\(js\|css\)\)"/"\1?v=2.4.7"/g'],
                    input=data, capture_output=True, check=True).stdout
            else:
                relative = 'htdocs/' + path[4:] if path.startswith('www/') else 'root/' + path
                data = (theme / relative).read_bytes()
            self.assertEqual(installed, data, path)

    def test_vendor_hash_checks_preserve_exact_pinned_file_modes(self):
        from test_verify_firmware import verify as native_verify

        # mtwifi-cfg-ucode installs files with CP, preserving pinned git modes.
        modes = {
            'usr/share/ucode/mtwifi/config.uc': '-rwxr-xr-x',
            'usr/share/ucode/mtwifi/converter.uc': '-rw-r--r--',
            'usr/share/ucode/mtwifi/driver.uc': '-rw-r--r--',
            'usr/share/schema/mtwifi/wireless.device.json': '-rw-r--r--',
            'usr/share/luci-app-mtwifi-cfg/wireless-mtk.js': '-rw-r--r--',
            'lib/netifd/wireless/mtwifi.sh': '-rwxr-xr-x',
        }
        files = {path: ('pinned payload ' + path).encode() for path in modes}
        policy = {'files': {}, 'hashes': {path: hashlib.sha256(data).hexdigest()
                                        for path, data in files.items()},
                  'versions': {}, 'version_suffixes': {}}

        def inspect():
            listing = ''.join(f'{mode} 0/0 1 2026-10-27 00:00 squashfs-root/{path}\n'
                              for path, mode in modes.items()).encode()
            return features.verify({}, {}, {}, lambda path, cap: files[path],
                                   lambda path, mode: native_verify.require_mode(listing, path, mode))

        with patch.object(features, 'expected', return_value=policy):
            checked = inspect()
            self.assertEqual(checked['files']['usr/share/ucode/mtwifi/config.uc']['mode'], '0755')
            self.assertEqual(checked['files']['usr/share/ucode/mtwifi/converter.uc']['mode'], '0644')
            for path in modes:
                original = modes[path]
                for wrong in ('-rw-r--r--' if original == '-rwxr-xr-x' else '-rwxr-xr-x',
                              '-rwxrwxrwx', 'lrwxrwxrwx'):
                    with self.subTest(path=path, mode=wrong):
                        modes[path] = wrong
                        with self.assertRaisesRegex(ValueError, 'must be regular with mode'):
                            inspect()
                modes[path] = original
            files['usr/share/ucode/mtwifi/config.uc'] += b'changed'
            with self.assertRaisesRegex(ValueError, 'feature hash differs'):
                inspect()

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
