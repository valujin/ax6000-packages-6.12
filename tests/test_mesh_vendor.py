import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SAVE = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/bin/wifi_config_save'
VENDOR = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-vendor'
LIBRARY = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/share/ax6000-mesh/vendor.sh'


class VendorPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name in ('etc/wireless/mediatek', 'var/lock', 'bin'):
            (self.root / name).mkdir(parents=True)
        self.profile = self.root / 'etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat'
        self.profile.write_text(json.dumps({
            'AuthMode': 'WPA2PSK;WPA2PSK', 'EncrypType': 'AES;AES',
            'PMFMFPC': '0;0', 'PMFMFPR': '0;0', 'PMFSHA256': '0;0',
            'HideSSID': '0;0', 'SSID1': 'Clients', 'SSID2': 'Mesh',
        }))
        (self.profile.parent / 'mt7986-ax6000.dbdc.b1.dat').write_text(self.profile.read_text())
        self.script = self.root / 'save'
        self.script.write_text(SAVE.read_text().replace('/etc/wireless/', str(self.root / 'etc/wireless') + '/').replace('/var/lock/', str(self.root / 'var/lock') + '/'))
        uci = self.root / 'bin/uci'
        uci.write_text('#!/bin/sh\necho 1\n')
        uci.chmod(0o755)
        datconf = self.root / 'bin/datconf'
        datconf.write_text('''#!/usr/bin/python3
import json, sys
from pathlib import Path
p = Path(sys.argv[2]); d = json.loads(p.read_text()); a = sys.argv[3:]
if a[0] == 'get':
    if a[1] not in d: sys.exit(1)
    print(d[a[1]])
else:
    d[a[1]] = a[2]; p.write_text(json.dumps(d))
''')
        datconf.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.root / 'bin') + ':' + os.environ['PATH']}

    def tearDown(self):
        self.tmp.cleanup()

    def save(self, interface, field, value):
        result = subprocess.run(['sh', str(self.script), interface, field, value], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(self.profile.read_text())

    def test_mixed_fronthaul_preserves_backhaul_and_sets_optional_pmf(self):
        data = self.save('ra0', 'AuthMode', 'WPA2PSKWPA3PSK')
        self.assertEqual(data['AuthMode'], 'WPA2PSKWPA3PSK;WPA2PSK')
        self.assertEqual(data['PMFMFPC'], '1;0')
        self.assertEqual(data['PMFMFPR'], '0;0')
        self.assertEqual(data['PMFSHA256'], '0;0')

    def test_backhaul_slot_writes_leave_client_credentials_intact(self):
        self.save('ra0', 'AuthMode', 'WPA2PSKWPA3PSK')
        self.save('ra1', 'SSID', 'Private Mesh')
        self.save('ra1', 'WPAPSK', 'separate-backhaul-secret')
        self.save('ra1', 'HideSSID', '1')
        data = self.save('ra1', 'AuthMode', 'WPA2PSK')
        self.assertEqual(data['SSID1'], 'Clients')
        self.assertEqual(data['SSID2'], 'Private Mesh')
        self.assertEqual(data['WPAPSK2'], 'separate-backhaul-secret')
        self.assertEqual(data['HideSSID'], '0;1')
        self.assertEqual(data['AuthMode'], 'WPA2PSKWPA3PSK;WPA2PSK')
        self.assertEqual(data['PMFMFPC'], '1;0')

    def test_second_slot_preserves_extra_tokens(self):
        data = json.loads(self.profile.read_text())
        data['HideSSID'] = '0;0;1;0'
        self.profile.write_text(json.dumps(data))
        self.assertEqual(self.save('ra1', 'HideSSID', '1')['HideSSID'], '0;1;1;0')

    def test_5ghz_slot_uses_other_radio_profile(self):
        self.save('rax1', 'SSID', 'Mesh5')
        other = json.loads((self.profile.parent / 'mt7986-ax6000.dbdc.b1.dat').read_text())
        self.assertEqual(other['SSID2'], 'Mesh5')
        self.assertEqual(json.loads(self.profile.read_text())['SSID2'], 'Mesh')

    def test_out_of_range_and_ambiguous_interfaces_are_rejected(self):
        for interface in ('ra16', 'rax16', 'ra02', 'ra-1', 'ra2;reboot', 'wlan2'):
            result = subprocess.run(['busybox', 'ash', str(self.script), interface, 'SSID', 'No'], env=self.env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, interface)

    def test_later_slot_preserves_bh_and_other_slots(self):
        data = json.loads(self.profile.read_text())
        data.update({'AuthMode':'WPA2PSK;WPA3PSK;WPA2PSK;WPA2PSK',
                     'PMFMFPC':'0;1;0;0', 'PMFMFPR':'0;1;0;0', 'PMFSHA256':'0;0;0;0'})
        self.profile.write_text(json.dumps(data))
        self.save('ra2', 'SSID', 'Guest')
        result = subprocess.run(['busybox', 'ash', str(self.script), 'ra2', 'AuthMode', 'WPA2PSKWPA3PSK'], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(self.profile.read_text())
        self.assertEqual(data['SSID3'], 'Guest')
        self.assertEqual(data['AuthMode'], 'WPA2PSK;WPA3PSK;WPA2PSKWPA3PSK;WPA2PSK')
        self.assertEqual(data['PMFMFPC'], '0;1;1;0')
        self.assertEqual(data['PMFMFPR'], '0;1;0;0')

    def test_slot_cannot_create_a_gap_in_token_list(self):
        before = self.profile.read_bytes()
        result = subprocess.run(['busybox', 'ash', str(self.script), 'ra4', 'HideSSID', '1'], env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.profile.read_bytes(), before)


class VendorRendering(unittest.TestCase):
    def test_distinct_band_ssids_and_mixed_fronthaul_separate_backhaul(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'wts'
            result = subprocess.run(['sh', '-c', '. "$1"; shift; mesh_write_bss "$@"', 'sh', str(LIBRARY), str(output), 'Home 24', 'clientpass24', 'sae-mixed', 'Home5', 'clientpass5', 'psk2', 'PrivateBH', 'backhaulpass'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = output.read_text().splitlines()
            self.assertEqual(len(rows), 7)
            self.assertIn(r'8x Home\ 24 0x0060 0x0008 clientpass24 0 1 hidden-N', rows[1])
            self.assertIn('8x PrivateBH 0x0020 0x0008 backhaulpass 1 0 hidden-Y', rows[2])
            self.assertIn('11x Home5 0x0020', rows[3])
            self.assertIn('12x Home5 0x0020', rows[5])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)


class VendorStatus(unittest.TestCase):
    def setUp(self):
        # Exercise the actual OpenWrt JSON shell implementation where available.
        native = ROOT.parent / 'local-native-mesh-20261027/work/build/source/staging_dir/host'
        self.jshn = native / 'share/libubox/jshn.sh'
        if not self.jshn.exists():
            self.jshn = Path('/usr/share/libubox/jshn.sh')
        if not self.jshn.exists():
            self.skipTest('OpenWrt jshn host tools are unavailable')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name in ('bin', 'var/lock', 'var/run', 'sys/class/net/br-lan', 'proc'):
            (self.root / name).mkdir(parents=True)
        (self.root / 'sys/class/net/br-lan/address').write_text('02:00:00:00:00:01\n')
        (self.root / 'proc/uptime').write_text('1000.50 500.00\n')
        self.fixture = self.root / 'topology.json'
        self.fixture.write_text('{}')
        script = VENDOR.read_text().replace('/usr/share/libubox/jshn.sh', str(self.jshn))
        for prefix in ('/var/lock/', '/var/run/', '/sys/', '/proc/'):
            script = script.replace(prefix, str(self.root) + prefix)
        self.script = self.root / 'vendor'
        self.script.write_text(script)
        for name, content in {
            'uci': '#!/bin/sh\ncase "$*" in *enabled) echo "$TEST_ENABLED";; *role) echo "$TEST_ROLE";; *backhaul) echo "$TEST_BACKHAUL";; esac\n',
            'pidof': '#!/bin/sh\nexit 0\n',
            'wappctrl': '#!/bin/sh\nprintf "%s\\n" "$*" > "$TEST_PAIR"\nexit "$TEST_PAIR_RC"\n',
            'mapd_cli': '''#!/bin/sh
case "$2" in
dump_topology_v1) [ "$TEST_BAD" != 1 ] && cp "$TEST_TOPOLOGY" "$3" ;;
bh_conn_status) echo "backhaul connection status $TEST_BH" ;;
conn_status) echo "conn_status fhbss: $TEST_FH, bhsta: 2" ;;
esac
''',
        }.items():
            target = self.root / 'bin' / name
            target.write_text(content)
            target.chmod(0o755)
        self.env = {**os.environ, 'PATH': f'{self.root}/bin:{native}/bin:' + os.environ['PATH'], 'LD_LIBRARY_PATH': str(native / 'lib'), 'TEST_TOPOLOGY': str(self.fixture), 'TEST_ROLE': 'agent', 'TEST_BH': '1', 'TEST_FH': '2', 'TEST_BAD': '0', 'TEST_PAIR': str(self.root / 'pair'), 'TEST_ENABLED': '1', 'TEST_BACKHAUL': 'wireless', 'TEST_PAIR_RC': '0'}

    def tearDown(self):
        if hasattr(self, 'tmp'):
            self.tmp.cleanup()

    def topology(self, local_role='02', peer_role='01'):
        self.fixture.write_text(json.dumps({'topology information': [
            {'AL MAC': '02:00:00:00:00:01', 'Device role': local_role, 'Upstream 1905 device': '02:00:00:00:00:02', 'BH Info': [{'Backhaul Medium Type': '5G'}]},
            {'AL MAC': '02:00:00:00:00:02', 'Device role': peer_role},
        ]}))

    def run_vendor(self, action='status'):
        # jshn uses export -n (supported by target BusyBox ash and host bash).
        result = subprocess.run(['bash', str(self.script), action], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_agent_requires_controller_backhaul_and_fronthaul(self):
        self.topology()
        data = self.run_vendor()
        self.assertTrue(data['connected'])
        self.assertEqual(data['controller_alid'], '02:00:00:00:00:02')
        self.assertEqual(data['peer_count'], 1)
        self.env['TEST_BH'] = '0'
        self.assertFalse(self.run_vendor()['connected'])
        self.env['TEST_BH'] = '1'
        self.env['TEST_FH'] = '0'
        self.assertFalse(self.run_vendor()['connected'])

    def test_controller_running_alone_is_not_paired(self):
        self.env['TEST_ROLE'] = 'controller'
        self.fixture.write_text(json.dumps({'topology information': [{'AL MAC': '02:00:00:00:00:01', 'Device role': '01'}]}))
        data = self.run_vendor()
        self.assertTrue(data['topology_valid'])
        self.assertFalse(data['connected'])
        self.topology(local_role='01', peer_role='02')
        data = self.run_vendor()
        self.assertTrue(data['connected'])
        self.assertTrue(data['peers'][0]['connected'])
        self.assertNotIn('address', data['peers'][0])

    def test_local_alid_comes_from_native_own_record_for_both_roles(self):
        # SDK topologySrv.c keeps own device first, irrespective of role or
        # controller distance. A bridge address is not the daemon's ALID.
        for role, local_role, peer_role in (('controller', '01', '02'), ('agent', '02', '01')):
            for bridge in ('02:00:00:00:00:03', '02:00:00:00:00:02'):
                with self.subTest(role=role, bridge=bridge):
                    self.env['TEST_ROLE'] = role
                    (self.root / 'sys/class/net/br-lan/address').write_text(bridge + '\n')
                    self.topology(local_role, peer_role)
                    data = self.run_vendor()
                    self.assertTrue(data['topology_valid'])
                    self.assertEqual(data['local_alid'], '02:00:00:00:00:01')
                    self.assertEqual(data['peers'][0]['alid'], '02:00:00:00:00:02')
                    self.assertTrue(data['connected'])

    def test_invalid_topology_clears_own_identity_and_duplicate_alids_fail(self):
        self.topology()
        data = json.loads(self.fixture.read_text())
        data['topology information'][1]['AL MAC'] = data['topology information'][0]['AL MAC']
        for value in (json.dumps(data), '{}', '{bad json'):
            with self.subTest(value=value):
                self.fixture.write_text(value)
                status = self.run_vendor()
                self.assertFalse(status['topology_valid'])
                self.assertFalse(status['connected'])
                self.assertEqual(status['local_alid'], '')
                self.assertEqual(status['peers'], [])

    def test_bad_or_failed_topology_never_reuses_connected_state(self):
        self.topology()
        self.assertTrue(self.run_vendor()['connected'])
        for value in ('{}', '{bad json', '{"topology information": []}'):
            self.fixture.write_text(value)
            data = self.run_vendor()
            self.assertFalse(data['connected'])
            self.assertFalse(data['topology_valid'])
        self.topology()
        self.env['TEST_BAD'] = '1'
        self.assertFalse(self.run_vendor()['connected'])

    def test_pairing_uses_role_aware_vendor_pbc_and_monotonic_timeout(self):
        data = self.run_vendor('pair')
        self.assertEqual(data['timeout_seconds'], 150)
        self.assertEqual((self.root / 'pair').read_text().strip(), 'ra0 wps_pbc')
        self.assertEqual(self.run_vendor()['pairing_remaining'], 150)
        (self.root / 'proc/uptime').write_text('1151.0 500.0\n')
        self.assertEqual(self.run_vendor()['pairing_remaining'], 0)

    def test_vendor_children_do_not_inherit_transaction_lock(self):
        self.topology()
        for name in ('wappctrl', 'mapd_cli'):
            target = self.root / 'bin' / name
            target.write_text(target.read_text().replace('#!/bin/sh\n', '#!/bin/sh\n[ ! -e /proc/self/fd/9 ] || exit 99\n', 1))
        for action in ('pair', 'status'):
            with self.subTest(action=action):
                result = subprocess.run(['bash', '-c', 'exec 9>"$1"; exec bash "$2" "$3"',
                                         'test', str(self.root / 'transaction.lock'), str(self.script), action],
                                        env=self.env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads(result.stdout)
                self.assertTrue(data['ok'])
                if action == 'status':
                    self.assertTrue(data['connected'])

    def test_controller_can_pair_with_saved_wired_backhaul(self):
        self.env.update(TEST_ROLE='controller', TEST_BACKHAUL='wired')
        self.assertTrue(self.run_vendor('pair')['ok'])

    def test_pairing_failures_return_json_and_nonzero_exit(self):
        for changes in ({'TEST_BACKHAUL': 'wired'}, {'TEST_ENABLED': '0'}, {'TEST_PAIR_RC': '1'}):
            with self.subTest(changes=changes):
                env = {**self.env, **changes}
                result = subprocess.run(['bash', str(self.script), 'pair'], env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(json.loads(result.stdout)['ok'])

    def test_pinned_native_topology_shape_and_backhaul_medium(self):
        # Source-derived structure, not a claimed two-router hardware capture.
        source = ROOT / 'tests/fixtures/mesh-runtime/mapd-topology-sdk20250408.json'
        data = json.loads(source.read_text())
        self.env['TEST_ROLE'] = 'controller'
        for medium, expected in (('Ethernet', 'wired'), ('2.4G', 'wireless'), ('5G', 'wireless'), ('5GL', 'wireless'), ('5GH', 'wireless')):
            with self.subTest(medium=medium):
                data['topology information'][1]['BH Info'][0]['Backhaul Medium Type'] = medium
                self.fixture.write_text(json.dumps(data))
                status = self.run_vendor()
                self.assertTrue(status['connected'])
                self.assertEqual(status['controller_alid'], '02:00:00:00:00:01')
                self.assertEqual(status['peers'][0]['backhaul'], expected)
                self.assertEqual(status['peers'][0]['upstream_alid'], '02:00:00:00:00:01')


if __name__ == '__main__':
    unittest.main()
