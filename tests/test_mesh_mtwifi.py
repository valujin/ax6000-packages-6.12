"""Apply reviewed vendor patch and exercise its converter with real host ucode.

Set UCODE to a host ucode binary for the behavioral cases.  The only adapter is
for datconf's native indexed-string helper; the complete vendor converter and
its actual DAT defaults execute unchanged.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT / 'files/mediatek-mesh/patches'


class MeshNativeDriverPatch(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('AX6000_METADATA_SOURCE') and os.environ.get('AX6000_DRIVER_ARCHIVE'),
                         'Set AX6000_METADATA_SOURCE and AX6000_DRIVER_ARCHIVE for the complete vendor patch sequence')
    def test_mesh_patch_after_complete_vendor_patch_sequence(self):
        source = Path(os.environ['AX6000_METADATA_SOURCE'])
        archive = Path(os.environ['AX6000_DRIVER_ARCHIVE'])
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),
                         'b029d7b43c498193092dc6a3c857361c8835ce34bb306561c550ac0539784a78')
        with tempfile.TemporaryDirectory(prefix='mesh-driver-patches-') as temporary:
            target = Path(temporary)
            subprocess.run(['tar', '-xJf', str(archive), '-C', str(target)], check=True, timeout=60)
            standard = source / 'package/mtk/drivers/mt_wifi/patches-7673'
            patches = sorted(standard.glob('*.patch'))
            self.assertTrue(patches)
            for patch in patches:
                result = subprocess.run(['patch', '--batch', '-p1', '-i', str(patch)], cwd=target,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, str(patch) + '\n' + result.stdout + result.stderr)
            # Recover the installed nested patch from the authenticated outer
            # patch, then require every hunk to match without offset or fuzz.
            outer = (PATCHES / 'mtwifi-mesh.patch').read_text()
            marker = '+++ b/package/mtk/drivers/mt_wifi/patches-7673/050-ax6000-mesh-native-abi.patch\n'
            nested = outer.split(marker, 1)[1].splitlines()[1:]
            mesh_patch = target / 'mesh.patch'
            mesh_patch.write_text('\n'.join(line[1:] for line in nested if line.startswith('+')) + '\n')
            before_make = (target / 'mt_wifi_ap/Makefile').read_text()
            before_bcn = (target / 'mt_wifi/embedded/common/bcn.c').read_text()
            result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(mesh_patch)],
                                    cwd=target, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('offset', result.stdout)
            self.assertNotIn('fuzz', result.stdout)
            self.assertEqual((target / 'mt_wifi_ap/Makefile').read_text(), before_make.replace(
                'ifeq ($(CONFIG_MAP_SUPPORT),y)\n',
                'ifeq ($(CONFIG_MAP_SUPPORT),y)\n    EXTRA_CFLAGS += -DMAP_MLO_UPLINK\n'))
            self.assertEqual((target / 'mt_wifi/embedded/common/bcn.c').read_text(), before_bcn.replace(
                '"[DFS-SLAVE] %s(): beaconing off Update reason: %d\\n", __func__, reason);\n\t\treturn NDIS_STATUS_SUCCESS;',
                '"[DFS-SLAVE] %s(): beaconing off Update reason: %d\\n", __func__, reason);\n\t\treturn;'))


class MeshMtwifiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.source = Path(cls.temp.name)
        cls.contract = json.loads((PATCHES / 'mtwifi-manifest.json').read_text())
        patch = PATCHES / 'mtwifi-mesh.patch'
        if hashlib.sha256(patch.read_bytes()).hexdigest() != cls.contract['sha256']:
            raise AssertionError('mtwifi patch checksum differs')
        # Full-context diff carries its exact upstream preimages, so tests need
        # neither network access nor a separately maintained copy of vendor code.
        current, content, previous_prefix = None, [], None
        def save():
            if current:
                target = cls.source / current
                target.parent.mkdir(parents=True, exist_ok=True)
                raw = ''.join(content).encode()
                if hashlib.sha256(raw).hexdigest() != cls.contract['files'][current]['before_sha256']:
                    raise AssertionError('mtwifi preimage checksum differs: ' + current)
                target.write_bytes(raw)
        for line in patch.read_text().splitlines(keepends=True):
            if line.startswith('--- /dev/null'):
                save()
                current, content = None, []
            elif line.startswith('--- a/'):
                save()
                current, content = line[6:].strip(), []
            elif line.startswith('\\ No newline'):
                if previous_prefix in (' ', '-'):
                    content[-1] = content[-1].removesuffix('\n')
            elif current and line[:1] in (' ', '-') and not line.startswith('--- '):
                content.append(line[1:])
            if not line.startswith('\\ No newline'):
                previous_prefix = line[:1]
        save()
        subprocess.run(['git', 'apply', '--check', str(patch)], cwd=cls.source, check=True)
        subprocess.run(['git', 'apply', str(patch)], cwd=cls.source, check=True)
        cls.base = cls.source / 'package/mtk/applications/mtwifi-cfg-ucode'
        cls.ucode = os.environ.get('UCODE') or shutil.which('ucode')

    def run_converter(self, config, interfaces, valid=True):
        if not self.ucode:
            self.skipTest('host ucode unavailable; set UCODE to execute converter')
        defs = json.loads((self.base / 'files/usr/share/schema/mtwifi/dat-defs.json').read_text())
        source = (self.base / 'files/usr/share/ucode/mtwifi/converter.uc').read_text()
        adapter = '''export function set_indexed_value(value, idx, val) {
            let items = split(value || '', ';');
            while (length(items) <= idx) push(items, '');
            items[idx] = val;
            return join(';', items);
        };\n'''
        # netifd imports this module before it can register any radio. Keep the
        # real import/export syntax: stripping exports concealed a missing
        # exported-function terminator that prevented Wi-Fi from starting.
        with tempfile.TemporaryDirectory(prefix='mesh-converter-module-') as temporary:
            modules = Path(temporary)
            (modules / 'mtwifi').mkdir()
            (modules / 'mtwifi/converter.uc').write_text(source)
            (modules / 'mtwifi/defaults.uc').write_text('export const defs = ' + json.dumps(defs) + ';\n')
            (modules / 'datconf.uc').write_text(adapter)
            script = "import * as converter from 'mtwifi.converter';\n"
            script += 'printf("%J", converter.convert(' + json.dumps({'config': config, 'interfaces': interfaces}) + '));'
            result = subprocess.run([self.ucode, '-L', str(modules), '-e', script],
                                    text=True, capture_output=True)
        if not valid:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('mtwifi:', result.stderr)
            return None
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def run_hooks(self, config):
        if not self.ucode:
            self.skipTest('host ucode unavailable; set UCODE to execute hooks')
        defs = json.loads((self.base / 'files/usr/share/schema/mtwifi/dat-defs.json').read_text())
        source = (self.base / 'files/usr/share/ucode/mtwifi/driver.uc').read_text()
        source = '\n'.join(line for line in source.splitlines() if not line.startswith('import '))
        source = source.replace('export function ', 'function ')
        script = 'let defs = ' + json.dumps(defs) + ';\n'
        script += 'let log = {debug: function(s) {}}; let calls = []; global.system = function(s) { push(calls, s); return 0; };\n'
        script += source + '\napply_runtime_hooks(' + json.dumps(config) + ', "rax0"); printf("%J", calls);'
        result = subprocess.run([self.ucode, '-e', script], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def radio(**options):
        return dict(band='5g', htmode='HE80', channel='36', country='DB', **options)

    @staticmethod
    def ap(**options):
        return {'mtwifi_ifname': 'rax0', 'config': dict(mode='ap', ssid='Local AP', key='local-secret', encryption='psk2', **options)}

    def test_patch_applies_to_exact_vendor_files(self):
        for relative, hashes in self.contract['files'].items():
            self.assertEqual(hashlib.sha256((self.source / relative).read_bytes()).hexdigest(), hashes['after_sha256'])

    def test_disabled_mesh_uses_ordinary_uci_credentials(self):
        dat = self.run_converter(self.radio(map_mode=0, map_agent=True), {'01': self.ap()})
        self.assertEqual(dat['MapMode'], '0')
        self.assertEqual(dat['SSID1'], 'Local AP')
        self.assertEqual(dat['WPAPSK1'], 'local-secret')
        self.assertEqual(dat['ApCliEnable'], '0')

    def test_agent_keeps_saved_ap_and_backhaul_configuration(self):
        dat = self.run_converter(self.radio(map_mode=1, map_agent=True), {'01': self.ap(), '02': {'mtwifi_ifname': 'apclix0', 'config': {'mode': 'sta', 'ssid': 'stale', 'key': 'stale', 'encryption': 'none'}}})
        saved = {'SSID1': 'Provisioned AP', 'WPAPSK1': 'provisioned-secret', 'AuthMode': 'WPA2PSK', 'EncrypType': 'AES', 'HideSSID': '1', 'ApCliSsid': 'Provisioned BH', 'ApCliEnable': '1', 'Channel': '149'}
        saved.update(dat)  # datconf.merge() contract
        self.assertEqual(saved['SSID1'], 'Provisioned AP')
        self.assertEqual(saved['WPAPSK1'], 'provisioned-secret')
        self.assertEqual(saved['ApCliSsid'], 'Provisioned BH')
        self.assertEqual(saved['ApCliEnable'], '1')
        self.assertEqual(saved['Channel'], '149')
        self.assertEqual(saved['MapMode'], '1')

    def test_controller_keeps_uci_authoritative(self):
        dat = self.run_converter(self.radio(map_mode=1), {'01': self.ap(map_bss_type=96)})
        self.assertEqual(dat['SSID1'], 'Local AP')
        self.assertEqual(dat['AuthMode'], 'WPA2PSK')
        self.assertEqual(dat['ApCliEnable'], '0')

    def test_explicit_disable_overwrites_previous_turnkey_mode(self):
        self.assertEqual(self.run_converter(self.radio(map_mode=0), {'01': self.ap()})['MapMode'], '0')

    def test_unconfigured_radio_does_not_enable_mesh(self):
        self.assertNotIn('MapMode', self.run_converter(self.radio(), {'01': self.ap()}))

    def test_invalid_mode_and_role_are_rejected_before_conversion(self):
        for mode in (-1, 2, 3, 4, '1; reboot'):
            with self.subTest(mode=mode):
                self.run_converter(self.radio(map_mode=mode), {'01': self.ap()}, valid=False)
        for role in (-1, 1, 128, '32; reboot'):
            with self.subTest(role=role):
                self.run_converter(self.radio(map_mode=1), {'01': self.ap(map_bss_type=role)}, valid=False)

    def test_controller_role_masks_set_both_driver_bits_explicitly(self):
        for role, fh, bh in ((0, '0', '0'), (32, '1', '0'), (64, '0', '1'), (96, '1', '1')):
            with self.subTest(role=role):
                calls = self.run_hooks({'mode': 'ap', 'map_mode': 1, 'map_bss_type': role})
                self.assertEqual(calls[:2], ['iwpriv rax0 set fhbss=' + fh, 'iwpriv rax0 set bhbss=' + bh])

    def test_agent_does_not_overwrite_dynamic_roles_or_reconnect_backhaul(self):
        ap = self.run_hooks({'mode': 'ap', 'map_mode': 1, 'map_agent': True, 'map_bss_type': 32})
        self.assertEqual(ap, ['iwpriv rax0 set KickStaRssiLow=0', 'iwpriv rax0 set AssocReqRssiThres=0'])
        self.assertEqual(self.run_hooks({'mode': 'sta', 'map_mode': 1, 'map_agent': True}), [])
        self.assertEqual(self.run_hooks({'mode': 'sta'}), ['iwpriv rax0 set ApCliEnable=1', 'iwpriv rax0 set ApCliAutoConnect=3'])

    def test_role_option_does_not_enable_mesh_on_an_ordinary_radio(self):
        calls = self.run_hooks({'mode': 'ap', 'map_mode': 0, 'map_bss_type': 96})
        self.assertEqual(calls, ['iwpriv rax0 set KickStaRssiLow=0', 'iwpriv rax0 set AssocReqRssiThres=0'])

    def test_setup_propagates_agent_ownership_to_runtime_hooks(self):
        if not self.ucode:
            self.skipTest('host ucode unavailable; set UCODE to execute setup')
        defs = json.loads((self.base / 'files/usr/share/schema/mtwifi/dat-defs.json').read_text())
        converter = (self.base / 'files/usr/share/ucode/mtwifi/converter.uc').read_text()
        config = (self.base / 'files/usr/share/ucode/mtwifi/config.uc').read_text()
        def script(source):
            return '\n'.join(line for line in source.splitlines() if not line.startswith('import ')).replace('export function ', 'function ')
        prefix = r'''let state = {MapMode: "0", SSID1: "Enrolled", WPAPSK1: "enrolled-secret"};
            let hooks = [], reloads = 0;
            let log = {debug: function(s) {}, error: function(s) {}, info: function(s) {}, notice: function(s) {}};
            global.system = function(s) { return 0; };
            function set_indexed_value(value, idx, val) {
                let a = split(value || '', ';');
                while (length(a) <= idx) push(a, '');
                a[idx] = val; return join(';', a);
            }
            let datconf = {open: function(path) { return {
                getall: function() { return state; },
                merge: function(dat) { for (let k,v in dat) state[k] = v; },
                commit: function() {}, close: function() {}
            }; }};
            let driver = {is_kmod: function() { return true; },
                scan_related_vifs: function(dev) { return []; },
                reload: function() { reloads++; },
                is_vif_inited: function(name) { return true; },
                ifup: function(name) {},
                apply_runtime_hooks: function(cfg, name) { push(hooks, cfg); }
            };
        '''
        cfg = {'config': self.radio(map_mode=1, map_agent=True), 'device': 'MT7986_1_2', 'interfaces': {'01': self.ap()}}
        program = 'let defs = ' + json.dumps(defs) + ';\n' + prefix + script(converter)
        program += '\nlet converter = {convert: convert, is_map_agent: is_map_agent};\n' + script(config)
        program += '\nsetup(' + json.dumps(cfg) + ', {MT7986_1_2: {profile_path: "/test/radio.dat", main_ifname: "rax0"}});'
        program += 'printf("%J", {state: state, hooks: hooks, reloads: reloads});'
        result = subprocess.run([self.ucode, '-e', program], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = json.loads(result.stdout)
        self.assertEqual(result['state']['SSID1'], 'Enrolled')
        self.assertEqual(result['hooks'][0]['map_mode'], 1)
        self.assertIs(result['hooks'][0]['map_agent'], True)
        self.assertEqual(result['reloads'], 1)


if __name__ == '__main__':
    unittest.main()
