"""Apply the pinned LuCI feed patch, then execute the complete Wireless view."""
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'files/mediatek-mesh/patches'


def wireless_preimages(manifest_name="luci-wireless-manifest.json"):
    manifest = json.loads((ASSETS / manifest_name).read_text())
    patch = (ASSETS / manifest['patch']).read_bytes()
    if hashlib.sha256(patch).hexdigest() != manifest['sha256']:
        raise AssertionError('LuCI patch checksum differs')
    files, current = {}, None
    for line in patch.decode().splitlines(keepends=True):
        if line.startswith('diff --git '):
            current = line.split(' b/', 1)[1].strip(); files[current] = []
        elif line.startswith('--- a/'):
            current = line[6:].strip(); files[current] = []
        elif line.startswith(('+++ ', '@@', '--- /dev/null')):
            continue
        elif current and line[0] in ' -':
            files[current].append(line[1:])
    result = {name: ''.join(lines).encode() for name, lines in files.items()}
    for name, data in result.items():
        if manifest['files'][name]['before_sha256'] is None and data == b'': continue
        if hashlib.sha256(data).hexdigest() != manifest['files'][name]['before_sha256']:
            raise AssertionError('Pinned LuCI preimage differs: ' + name)
    return manifest, result


def seed_wireless_source(source):
    manifest, files = wireless_preimages()
    for name, data in files.items():
        if manifest['files'][name]['before_sha256'] is None: continue
        path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
    vendor, files = wireless_preimages('mtwifi-wireless-manifest.json')
    for name, data in files.items():
        path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
    return manifest


class MeshWirelessPage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mesh-wireless-page-')
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.assertTrue((ASSETS / 'luci-wireless-manifest.json').exists(), 'Wireless feed patch is absent')
        self.manifest = seed_wireless_source(self.source)
        self.vendor = wireless_preimages("mtwifi-wireless-manifest.json")[0]

    def apply(self):
        subprocess.run(['git', 'apply', str(ASSETS / self.vendor['patch'])], cwd=self.source, check=True)
        result = subprocess.run(['git', 'apply', '--check', str(ASSETS / self.manifest['patch'])],
                                cwd=self.source, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        subprocess.run(['git', 'apply', str(ASSETS / self.manifest['patch'])], cwd=self.source, check=True)
        for name, hashes in self.manifest['files'].items():
            self.assertEqual(hashlib.sha256((self.source / name).read_bytes()).hexdigest(), hashes['after_sha256'])

    def test_pinned_patch_only_grants_read_client_access(self):
        self.apply()
        self.assertEqual(self.manifest['feed_commit'], 'd6167ea0645cbd1327708d85f94824f42d0eb872')
        for name in self.manifest['files']:
            self.assertTrue(name.startswith('feeds/luci/modules/luci-mod-network/'))
        acl_name = next(name for name in self.manifest['files'] if name.endswith('.json'))
        after = json.loads((self.source / acl_name).read_text())
        before = json.loads(wireless_preimages()[1][acl_name])
        self.assertEqual(after['luci-mod-network-config']['read']['ubus'].pop('ax6000.mesh'), ['clients'])
        self.assertIn('ax6000_mesh', after['luci-mod-network-config']['read']['uci'])
        after['luci-mod-network-config']['read']['uci'].remove('ax6000_mesh')
        self.assertEqual(after, before, 'Only read client telemetry and Mesh ownership access change')

    def test_managed_form_guard_is_called_after_modal_options_are_constructed(self):
        self.apply()
        name = next(name for name in self.vendor['files'] if name.endswith('wireless-mtk.js'))
        source = (self.source / name).read_text()
        modal = source[source.index('s.addModalOptions ='):source.index('s.handleRemove =')]
        self.assertEqual(modal.count('mesh_agent_protect_form(ss, radioNet);'), 1)
        self.assertGreater(modal.index('mesh_agent_protect_form(ss, radioNet);'), modal.index("'wps_pushbutton'"))
        self.assertIn("uci.load('ax6000_mesh').catch(() => null)", source)

    def test_core_package_revision_is_literal_and_newer_than_the_native_baseline(self):
        self.apply()
        version = '26.249.28459~d6167ea-r2'
        self.assertEqual(self.manifest.get('package_version'), version, 'Patched core APK must have a distinct version')
        name = 'feeds/luci/modules/luci-mod-network/Makefile'
        self.assertIn(name, self.manifest['files'])
        self.assertIsNone(self.manifest['files'][name]['image_path'], 'Recipe is source metadata, never an installed file')
        makefile = (self.source / name).read_text()
        self.assertEqual(re.findall(r'^PKG_VERSION:=(.+)$', makefile, re.M), ['26.249.28459~d6167ea'])
        self.assertEqual(re.findall(r'^PKG_RELEASE:=(.+)$', makefile, re.M), ['2'])
        apk = ROOT.parent / 'task-tools/apk-3.0.5/build/src/apk'
        if apk.is_file():
            for previous in ['26.249.28459~d6167ea', '26.249.28459~d6167ea-r1']:
                result = subprocess.run([str(apk), 'version', '-t', version, previous], capture_output=True, text=True, check=True)
                self.assertEqual(result.stdout.strip(), '>')

    def test_real_luci_metadata_keeps_revision_with_git_and_nongit_source_versions(self):
        self.apply()
        pinned = Path(os.environ.get('AX6000_METADATA_SOURCE', str(ROOT.parent / 'local-native-mesh-20261027/work/build/source')))
        luci = pinned / 'feeds/luci/luci.mk'
        if not luci.is_file(): self.skipTest('Pinned LuCI source required for real metadata evaluation')
        (self.source / 'feeds/luci/luci.mk').write_bytes(luci.read_bytes())
        (self.source / 'include').mkdir()
        (self.source / 'rules.mk').write_text('INCLUDE_DIR:=$(TOPDIR)/include\n')
        (self.source / 'include/package.mk').write_text('')
        module = self.source / 'feeds/luci/modules/luci-mod-network'
        with (module / 'Makefile').open('a') as f:
            f.write("\n$(eval $(call Package/luci-mod-network))\n.PHONY: metadata\nmetadata:\n\t@printf '%s\\n' '$(VERSION)'\n")
        for source_version in ['26.249.28459~d6167ea', '0.261029.00000']:
            result = subprocess.run(['make', '-s', '-C', str(module), 'TOPDIR=' + str(self.source),
                'PKG_SRC_VERSION=' + source_version, 'metadata'], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), '26.249.28459~d6167ea-r2')

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_actual_pinned_page_keeps_local_actions_and_safely_appends_remote_clients(self):
        self.apply()
        view = next(self.source / name for name in self.vendor['files'] if name.endswith('.js'))
        result = subprocess.run(['node', str(ROOT / 'tests/fixtures/mesh-wireless-page.js'), str(view)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_luci_pin_and_mixed_or_linked_source_are_rejected(self):
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        import mediatek_mesh
        from test_mesh_integration import profile
        selected = profile()
        for feed in selected['feeds']:
            if feed['name'] == 'luci': feed['commit'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'feed pin'):
            mediatek_mesh.wireless_manifest(selected)
        images = mediatek_mesh.wireless_images(self.manifest)
        name = next(iter(images))
        target = self.source / name
        target.write_bytes(images[name])
        with self.assertRaisesRegex(ValueError, 'mixed'):
            mediatek_mesh.wireless_targets(self.source, self.manifest)
        target.unlink(); target.symlink_to(ROOT / 'README.md')
        with self.assertRaisesRegex(ValueError, 'linked|root'):
            mediatek_mesh.wireless_targets(self.source, self.manifest)

    def test_source_hook_and_image_contract_include_the_owned_core_files(self):
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        import mediatek_mesh
        from test_mesh_integration import profile
        from test_mesh_mtwifi import MeshMtwifiTests
        MeshMtwifiTests.setUpClass(); self.addCleanup(MeshMtwifiTests.doClassCleanups)
        shutil.copytree(MeshMtwifiTests.source / 'package', self.source / 'package', dirs_exist_ok=True)
        subprocess.run(['git', 'apply', '-R', str(ASSETS / 'mtwifi-mesh.patch')], cwd=self.source, check=True, capture_output=True)
        before_vendor = (self.source / 'package/mtk/applications/mtwifi-cfg-ucode/Makefile').read_bytes()
        damaged = self.source / next(name for name in self.manifest['files'] if name.endswith('.json'))
        original = damaged.read_bytes(); damaged.write_bytes(original + b'\nforeign modification\n')
        with self.assertRaisesRegex(ValueError, 'LuCI.*hash|LuCI.*preimage'):
            mediatek_mesh.configure(profile(), self.source, native=True)
        self.assertFalse((self.source / 'package/ax6000-overrides').exists())
        self.assertEqual((self.source / 'package/mtk/applications/mtwifi-cfg-ucode/Makefile').read_bytes(), before_vendor)
        damaged.write_bytes(original)
        proof = mediatek_mesh.configure(profile(), self.source, native=True)
        self.assertEqual(proof['luci_wireless']['patch_sha256'], self.manifest['sha256'])
        self.assertEqual(proof['vendor_wireless']['sha256'], self.vendor['sha256'])
        self.assertEqual(expected_version := mediatek_mesh.expected(profile())['versions']['luci-app-mtwifi-cfg'], '1-r3')
        self.assertEqual(mediatek_mesh.configure(profile(), self.source, native=True), proof)
        expected = mediatek_mesh.expected(profile())
        self.assertEqual(expected['versions']['luci-mod-network'], '26.249.28459~d6167ea-r2')
        for name, value in self.manifest['files'].items():
            if value['image_path'] is None:
                self.assertNotIn(None, expected['files'])
                continue
            data, mode = expected['files'][value['image_path']]
            self.assertEqual(mode, 0o644)
            self.assertEqual(hashlib.sha256(data).hexdigest(), value['after_sha256'])
            self.assertEqual((self.source / name).read_bytes(), data)

    def test_vendor_page_keeps_all_original_logic_outside_reviewed_additions(self):
        self.apply()
        _, before = wireless_preimages('mtwifi-wireless-manifest.json')
        name = next(name for name in before if name.endswith('.js'))
        old = before[name].decode(); new = (self.source / name).read_text()
        # Full vendor country/channel/power widgets and AP removal remain exact.
        for start, end in [('var CBIWifiFrequencyValue', 'var CBIWifiTxPowerValue'),
                           ('var CBIWifiTxPowerValue', 'var CBIWifiCountryValue'),
                           ('var CBIWifiCountryValue', 'return view.extend'),
                           ('s.handleRemove =', 's.handleScan =')]:
            self.assertEqual(old[old.index(start):old.index(end)], new[new.index(start):new.index(end)])
        self.assertNotIn('htdocs/luci-static/resources/view/network/wireless.js', '\n'.join(self.manifest['files']))

    def test_country_replay_accepts_only_complete_mesh_vendor_layer(self):
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        import vendor_country
        self.apply()
        result = vendor_country.apply_vendor_country_patch(self.source)
        self.assertEqual(result['release'], '3'); self.assertFalse(result['changed'])
        default = next(self.source / name for name in self.vendor['files'] if name.endswith('.default'))
        default.write_bytes(default.read_bytes() + b'# foreign\n')
        with self.assertRaisesRegex(ValueError, 'hash|preimage'):
            vendor_country.apply_vendor_country_patch(self.source)

    def test_core_and_vendor_install_orders_replay_copy_and_reject_symlinks(self):
        self.apply()
        vendor_default = next(self.source / n for n in self.vendor['files'] if n.endswith('.default'))
        core_default = next(self.source / n for n in self.manifest['files'] if '95-ax6000' in n)
        canonical = self.source / 'runtime/usr/share/luci-app-mtwifi-cfg/wireless-mtk.js'
        active = self.source / 'runtime/www/luci-static/resources/view/network/wireless.js'
        canonical.parent.mkdir(parents=True); active.parent.mkdir(parents=True)
        root = self.source / 'runtime'
        def invoke(path):
            script = path.read_text()
            for directory in ['usr', 'www']:
                script = script.replace('/' + directory + '/', str(root / directory) + '/')
            # Test host is unprivileged: model uid0 only; mode and all copy,
            # rename, symlink, path-resolution checks use the real filesystem.
            prefix = '''stat() {
              case "$2" in
                %u:%g:%a) printf '0:0:%s\\n' "$(command stat -c %a "$3")" ;;
                %u) printf '0\\n' ;;
                *) command stat "$@" ;;
              esac
            }
            '''
            return subprocess.run(['busybox', 'ash', '-c', prefix + script], capture_output=True, text=True)
        payload = next((self.source / n).read_bytes() for n in self.vendor['files'] if n.endswith('.js'))
        # Core first, no vendor installed: keep generic; vendor install copies.
        active.write_bytes(b'generic-core')
        self.assertEqual(invoke(core_default).returncode, 0); self.assertEqual(active.read_bytes(), b'generic-core')
        canonical.write_bytes(payload); canonical.chmod(0o644)
        self.assertEqual(invoke(vendor_default).returncode, 0); self.assertEqual(active.read_bytes(), payload)
        self.assertEqual(canonical.read_bytes(), payload, 'canonical payload survives vendor defaults')
        # Core installed/reinstalled after vendor: its own hook restores vendor.
        active.write_bytes(b'generic-upgrade')
        self.assertEqual(invoke(core_default).returncode, 0); self.assertEqual(active.read_bytes(), payload)
        self.assertEqual(invoke(vendor_default).returncode, 0, 'vendor defaults are replayable')
        canonical.chmod(0o666); active.write_bytes(b'keep')
        self.assertNotEqual(invoke(core_default).returncode, 0); self.assertEqual(active.read_bytes(), b'keep')
        self.assertNotEqual(invoke(vendor_default).returncode, 0, 'vendor copy uses the same protections')
        canonical.chmod(0o644); active.unlink(); active.symlink_to(root / 'victim')
        self.assertNotEqual(invoke(core_default).returncode, 0); self.assertFalse((root / 'victim').exists())
        active.unlink(); active.write_bytes(b'keep'); canonical.unlink(); canonical.symlink_to(active)
        self.assertNotEqual(invoke(core_default).returncode, 0); self.assertEqual(active.read_bytes(), b'keep')

    def test_pinned_default_postinst_deletes_and_replays_core_owned_hook(self):
        self.apply()
        pinned = ROOT.parent / 'local-native-mesh-20261027/work/build/source/package/base-files/files/lib/functions.sh'
        if not pinned.is_file(): self.skipTest('Pinned default_postinst source absent')
        functions = pinned.read_text()
        dispatcher = functions[functions.index('default_postinst() {'):functions.index('\ninclude() {')]
        root = self.source / 'postinst-root'
        canonical = root / 'usr/share/luci-app-mtwifi-cfg/wireless-mtk.js'
        active = root / 'www/luci-static/resources/view/network/wireless.js'
        installed = root / 'etc/uci-defaults/95-ax6000-mesh-wireless-vendor'
        listing = root / 'lib/apk/packages/luci-mod-network.list'
        for path in [canonical, active, installed, listing]: path.parent.mkdir(parents=True, exist_ok=True)
        canonical.write_bytes(b'installed vendor'); canonical.chmod(0o644)
        hook = next((self.source / n).read_text() for n in self.manifest['files'] if '95-ax6000' in n)
        def rooted(text):
            return re.sub(r'/(?:usr|etc|lib|tmp|www)/', lambda match: str(root) + match[0], text)
        listing.write_text(str(installed) + '\n')
        script = '''stat() { case "$2" in
          %u:%g:%a) printf '0:0:%s\\n' "$(command stat -c %a "$3")" ;;
          %u) printf '0\\n' ;; *) command stat "$@" ;; esac; }
        uci() { :; }
        ''' + rooted(dispatcher) + '\npkgname=luci-mod-network\nIPKG_INSTROOT=\ndefault_postinst ignored\n'
        for iteration in range(2):
            # Actual package postinst enumerates only its own installed list,
            # sources defaults, deletes successes, then a reinstall restores it.
            active.write_bytes(b'generic core payload'); installed.write_text(rooted(hook))
            result = subprocess.run(['busybox', 'ash', '-c', script], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(active.read_bytes(), b'installed vendor')
            self.assertFalse(installed.exists(), 'successful core defaults are deleted by real dispatcher')
            self.assertTrue(canonical.exists())

    def test_mesh_image_policy_preserves_verbatim_vendor_payload_and_separate_runtime_copy(self):
        import sys
        from unittest.mock import patch
        sys.path.insert(0, str(ROOT / 'scripts'))
        import image_features, mediatek_mesh
        from test_mesh_integration import profile
        selected = profile(); selected.pop('pbr_source', None)
        with patch.object(image_features.pbr_sources, 'validate', return_value=None), \
             patch.object(image_features, 'minified_js', side_effect=lambda data, source: b'minified:' + data):
            policy = image_features.expected(selected, {}, source=self.source)
        path = 'usr/share/luci-app-mtwifi-cfg/wireless-mtk.js'
        self.assertNotIn(path, policy['hashes'], 'country-only hash must not conflict with composed vendor file')
        self.assertEqual(policy['versions']['luci-app-mtwifi-cfg'], '1-r3')
        vendor = mediatek_mesh.vendor_wireless_manifest()
        name = next(n for n in vendor['files'] if n.endswith('.js'))
        self.assertEqual(hashlib.sha256(policy['files'][path][0]).hexdigest(), vendor['files'][name]['after_sha256'])
        self.assertNotIn('www/luci-static/resources/view/network/wireless.js', policy['files'],
                         'preboot core page is replaced by defaults, never asserted as vendor payload before boot')
        self.assertEqual(mediatek_mesh.expected(selected)['runtime_copies'][path],
                         'www/luci-static/resources/view/network/wireless.js')
