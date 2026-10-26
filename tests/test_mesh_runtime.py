import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-control'


class RuntimeValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.control = Path(self.tmp.name) / 'control'
        self.control.write_text(CONTROL.read_text().replace('/var/lock/ax6000-mesh.lock', str(Path(self.tmp.name) / 'mesh.lock')))

    def tearDown(self):
        self.tmp.cleanup()

    def test_invalid_role_is_rejected_before_changes(self):
        result = subprocess.run(['sh', str(self.control), 'configure', 'invalid', 'wired'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('role', result.stderr.lower())

    def test_invalid_backhaul_is_rejected_before_changes(self):
        result = subprocess.run(['sh', str(self.control), 'configure', 'agent', 'invalid'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('backhaul', result.stderr.lower())

    def test_configure_saves_only_allowlisted_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'uci'
            fake.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$MESH_TEST_LOG"\n')
            fake.chmod(0o755)
            log = Path(tmp) / 'log'
            env = {**os.environ, 'PATH': tmp + ':' + os.environ['PATH'], 'MESH_TEST_LOG': str(log)}
            result = subprocess.run(['sh', str(self.control), 'configure', 'agent', 'wireless'], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(log.read_text().splitlines(), ['-q get ax6000_mesh.main.enabled', '-q set ax6000_mesh.main=mesh', '-q set ax6000_mesh.main.role=agent', '-q set ax6000_mesh.main.backhaul=wireless', '-q commit ax6000_mesh'])

    def test_invalid_backhaul_never_invokes_uci(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'uci'
            fake.write_text('#!/bin/sh\ntouch "$MESH_TEST_LOG"\n')
            fake.chmod(0o755)
            log = Path(tmp) / 'log'
            env = {**os.environ, 'PATH': tmp + ':' + os.environ['PATH'], 'MESH_TEST_LOG': str(log)}
            result = subprocess.run(['sh', str(self.control), 'configure', 'agent', 'wireless; reboot'], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(log.exists())


class RuntimeLifecycle(unittest.TestCase):
    def setUp(self):
        import json
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name in ('tmp/sysinfo', 'sys/class/net/br-lan/bridge', 'sys/class/net/br-lan/brif/lan2', 'sys/class/net/br-lan/brif/lan3', 'sys/class/net/br-lan/brif/lan4', 'sys/class/net/ra0', 'sys/class/net/rax0', 'sys/module', 'etc/config', 'etc/wireless/mediatek', 'etc/init.d', 'usr/libexec', 'var/lock', 'bin'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / 'sys/class/net/br-lan/bridge/vlan_filtering').write_text('0\n')
        for radio in ('ra0', 'rax0'):
            (self.root / f'sys/class/net/{radio}/flags').write_text('0x1003\n')
        (self.root / 'tmp/sysinfo/board_name').write_text('xiaomi,redmi-router-ax6000-stock\n')
        (self.root / 'etc/config/wireless').write_text('original wireless\n')
        for band in ('b0', 'b1'):
            (self.root / f'etc/wireless/mediatek/mt7986-ax6000.dbdc.{band}.dat').write_text('original DAT\n')
        marker = {'schema_version': 1, 'abi': 'mtk-20250408-map6e', 'source_commit': 'ae65e1de69971b5a2e3cf7e39390ee93f274d488', 'driver': '7.6.7.3', 'release': 2, 'flags': dict.fromkeys(['MTK_MAP_SUPPORT', 'MTK_MAP_R2_VER_SUPPORT', 'MTK_MAP_R3_VER_SUPPORT', 'MTK_MAP_R2_6E_SUPPORT', 'MTK_MAP_R3_6E_SUPPORT', 'MTK_DFS_SLAVE_SUPPORT'], 'y')}
        (self.root / 'etc/ax6000-mesh-abi.json').write_text(json.dumps(marker, sort_keys=True, separators=(',', ':')) + '\n')
        self.db = self.root / 'uci.json'
        self.db.write_text(json.dumps({'wireless.a': 'wifi-iface', 'wireless.b': 'wifi-iface', 'wireless.a.mode': 'ap', 'wireless.b.mode': 'ap', 'wireless.a.device': 'd1', 'wireless.b.device': 'd2', 'wireless.d1.type': 'mtwifi', 'wireless.d2.type': 'mtwifi', 'wireless.a.network': 'lan', 'wireless.b.network': 'lan', 'wireless.a.encryption': 'psk2', 'wireless.b.encryption': 'psk2', 'wireless.a.ssid': 'Example', 'wireless.b.ssid': 'Example', 'wireless.a.key': 'password123', 'wireless.b.key': 'password123', 'ax6000_mesh.main.role': 'controller', 'ax6000_mesh.main.backhaul': 'wired', 'ax6000_mesh.main.enabled': '0'}))
        uci = self.root / 'bin/uci'
        uci.write_text('''#!/usr/bin/python3
import json, os, sys
p = os.environ['TEST_UCI_DB']
d = json.load(open(p)); a = sys.argv[1:]
plain_ids = '-X' in a
while a and a[0] in ('-q', '-X'): a = a[1:]
if a[0] == 'get':
    if a[1] not in d: sys.exit(1)
    print(d[a[1]])
elif a[0] == 'show':
    for k,v in d.items():
        if k.startswith(a[1]+'.'):
            if not plain_ids and k == 'wireless.cfg01abcd': k = 'wireless.@wifi-iface[2]'
            print(k+'='+v)
elif a[0] == 'set':
    k,v = a[1].split('=',1); d[k]=v; json.dump(d,open(p,'w'))
elif a[0] in ('commit', 'changes', 'revert'): pass
else: sys.exit(2)
''')
        uci.chmod(0o755)
        for cmd in ('wapp', 'wappctrl', 'mapd', 'p1905_managerd', 'mapd_cli'):
            f = self.root / 'bin' / cmd
            f.write_text('#!/bin/sh\nexit 0\n'); f.chmod(0o755)
        for name, body in {
            'pidof': '[ -f "$TEST_STARTED" ]',
            'wifi': '[ ! -f "$TEST_FAIL_WIFI" ] || { rm "$TEST_FAIL_WIFI"; exit 1; }',
            'sleep': ':',
            'modprobe': 'mkdir -p "$TEST_MODULE"',
            'iwpriv': ':',
            'rmmod': 'rmdir "$TEST_MODULE"',
        }.items():
            f = self.root / 'bin' / name
            f.write_text('#!/bin/sh\n' + body + '\n'); f.chmod(0o755)
        init = self.root / 'etc/init.d/ax6000-mesh'
        init.write_text('#!/bin/sh\ncase "$1" in start) touch "$TEST_STARTED";; stop) rm -f "$TEST_STARTED";; esac\n'); init.chmod(0o755)
        source = CONTROL.read_text()
        for prefix in ('/etc', '/sys', '/tmp/sysinfo', '/usr/libexec', '/usr/share/ax6000-mesh', '/var/lock'):
            source = source.replace(prefix + '/', str(self.root / prefix.lstrip('/')) + '/')
        health = self.root / 'usr/libexec/ax6000-mesh-health'
        health.write_text('#!/bin/sh\n[ -f "$TEST_STARTED" ]\n'); health.chmod(0o755)
        self.control = self.root / 'control'
        self.control.write_text(source)
        self.env = {**os.environ, 'PATH': str(self.root / 'bin') + ':' + os.environ['PATH'], 'TEST_UCI_DB': str(self.db), 'TEST_STARTED': str(self.root / 'started'), 'TEST_FAIL_WIFI': str(self.root / 'wifi-fail'), 'TEST_MODULE': str(self.root / 'sys/module/mapfilter')}

    def tearDown(self):
        self.tmp.cleanup()

    def run_control(self, *args):
        return subprocess.run(['sh', str(self.control), *args], env=self.env, text=True, capture_output=True)

    def test_apply_and_disable_restores_saved_wireless(self):
        import json
        applied = self.run_control('apply')
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(json.loads(self.db.read_text())['ax6000_mesh.main.enabled'], '1')
        self.assertTrue((self.root / 'etc/ax6000-mesh/original-wireless').exists())
        disabled = self.run_control('disable')
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        self.assertEqual((self.root / 'etc/config/wireless').read_text(), 'original wireless\n')
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_failed_wireless_reload_restores_snapshot_and_disables_mesh(self):
        import json
        (self.root / 'wifi-fail').touch()
        applied = self.run_control('apply')
        self.assertNotEqual(applied.returncode, 0)
        self.assertEqual(json.loads(self.db.read_text())['ax6000_mesh.main.enabled'], '0')
        self.assertEqual((self.root / 'etc/config/wireless').read_text(), 'original wireless\n')
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_agent_requires_dhcp_disabled_before_any_snapshot(self):
        import json
        db = json.loads(self.db.read_text()); db['ax6000_mesh.main.role'] = 'agent'; self.db.write_text(json.dumps(db))
        applied = self.run_control('apply')
        self.assertNotEqual(applied.returncode, 0)
        self.assertIn('DHCP', applied.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_refuses_to_overwrite_wireless_changes_on_disable(self):
        self.assertEqual(self.run_control('apply').returncode, 0)
        config = self.root / 'etc/config/wireless'
        config.write_text('new user settings\n')
        result = self.run_control('disable')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('changed', result.stderr)
        self.assertEqual(config.read_text(), 'new user settings\n')
        self.assertTrue((self.root / 'etc/ax6000-mesh/original-wireless').exists())

    def test_agent_rejects_enabled_ipv6_router_advertisements(self):
        import json
        db = json.loads(self.db.read_text())
        db.update({'ax6000_mesh.main.role': 'agent', 'dhcp.lan.ignore': '1', 'dhcp.lan.ra': 'server'})
        self.db.write_text(json.dumps(db))
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('IPv6', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_rejects_hidden_mesh_ap(self):
        import json
        db = json.loads(self.db.read_text()); db['wireless.a.hidden'] = '1'; self.db.write_text(json.dumps(db))
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SSID', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_anonymous_guest_ap_is_counted(self):
        import json
        db = json.loads(self.db.read_text())
        db.update({'wireless.cfg01abcd': 'wifi-iface', 'wireless.cfg01abcd.mode': 'ap', 'wireless.cfg01abcd.network': 'guest'})
        self.db.write_text(json.dumps(db))
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('LAN', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_printable_ssid_and_key_are_accepted(self):
        import json
        db = json.loads(self.db.read_text())
        db.update({'wireless.a.ssid': 'Home WiFi', 'wireless.b.ssid': 'Home WiFi', 'wireless.a.key': 'secret pass!', 'wireless.b.key': 'secret pass!'})
        self.db.write_text(json.dumps(db))
        result = self.run_control('preflight')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_agent_rejects_second_dhcp_section_for_lan(self):
        import json
        db = json.loads(self.db.read_text())
        db.update({'ax6000_mesh.main.role': 'agent', 'dhcp.lan.ignore': '1', 'dhcp.extra': 'dhcp', 'dhcp.extra.interface': 'lan', 'dhcp.extra.ignore': '0'})
        self.db.write_text(json.dumps(db))
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DHCP', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())
    def test_unloads_only_a_module_loaded_by_mesh(self):
        self.assertEqual(self.run_control('apply').returncode, 0)
        self.assertTrue((self.root / 'sys/module/mapfilter').is_dir())
        self.assertEqual(self.run_control('disable').returncode, 0)
        self.assertFalse((self.root / 'sys/module/mapfilter').exists())

    def test_preserves_preexisting_mapfilter_module(self):
        module = self.root / 'sys/module/mapfilter'
        module.mkdir()
        self.assertEqual(self.run_control('apply').returncode, 0)
        self.assertEqual(self.run_control('disable').returncode, 0)
        self.assertTrue(module.is_dir())

    def test_rejects_absent_or_mismatched_firmware_abi(self):
        marker = self.root / 'etc/ax6000-mesh-abi.json'
        marker.write_text('{}\n')
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ABI', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())
        marker.unlink()
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ABI', result.stderr)

    def test_rejects_vlan_filtered_lan_bridge(self):
        (self.root / 'sys/class/net/br-lan/bridge/vlan_filtering').write_text('1\n')
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('VLAN', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_agent_rejects_ndp_relay(self):
        import json
        db = json.loads(self.db.read_text())
        db.update({'ax6000_mesh.main.role': 'agent', 'dhcp.lan.ignore': '1', 'dhcp.lan.ndp': 'relay'})
        self.db.write_text(json.dumps(db))
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('NDP', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())


class ConfigSave(unittest.TestCase):
    def test_rejects_unsupported_interface_before_writing(self):
        target = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/bin/wifi_config_save'
        result = subprocess.run(['sh', str(target), 'eth0', 'SSID', 'Test'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('interface', result.stderr.lower())

    def test_psk_is_passed_as_one_argument_without_shell_execution(self):
        import json
        target = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/bin/wifi_config_save'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'etc/wireless/mediatek').mkdir(parents=True)
            (root / 'var/lock').mkdir(parents=True)
            (root / 'bin').mkdir()
            profile = root / 'etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat'
            profile.write_text('Default\n')
            script = root / 'save'
            script.write_text(target.read_text().replace('/etc/wireless/', str(root / 'etc/wireless') + '/').replace('/var/lock/', str(root / 'var/lock') + '/'))
            fake_uci = root / 'bin/uci'
            fake_uci.write_text('#!/bin/sh\necho 1\n'); fake_uci.chmod(0o755)
            fake_datconf = root / 'bin/datconf'
            fake_datconf.write_text('#!/usr/bin/python3\nimport json, os, sys\njson.dump(sys.argv[1:],open(os.environ["TEST_LOG"],"w"))\n'); fake_datconf.chmod(0o755)
            log = root / 'args.json'
            env = {**os.environ, 'PATH': str(root / 'bin') + ':' + os.environ['PATH'], 'TEST_LOG': str(log)}
            key = 'secret;touch ' + str(root / 'injected')
            result = subprocess.run(['sh', str(script), 'ra0', 'WPAPSK', key], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(log.read_text()), ['-f', str(profile), 'set', 'WPAPSK1', key])
            self.assertFalse((root / 'injected').exists())


class ConfigRendering(unittest.TestCase):
    setUp = RuntimeLifecycle.setUp
    tearDown = RuntimeLifecycle.tearDown
    run_control = RuntimeLifecycle.run_control

    def test_wts_escapes_spaces_and_backslashes(self):
        import json
        db = json.loads(self.db.read_text())
        db.update({'wireless.a.ssid': r'Home \ Mesh', 'wireless.b.ssid': r'Home \ Mesh', 'wireless.a.key': 'secret pass!', 'wireless.b.key': 'secret pass!'})
        self.db.write_text(json.dumps(db))
        template = self.root / 'usr/share/ax6000-mesh/vendor'
        template.mkdir(parents=True)
        for name in ('mapd_default.cfg', '1905d.cfg', 'mapd_user.cfg', 'ethernet_cfg.txt', 'wapp_ap_ra0.conf', 'wapp_ap_rax0.conf'):
            (template / name).write_text('Default\n')
        (self.root / 'etc/ax6000-mesh').mkdir()
        (self.root / 'sys/class/net/br-lan/address').write_text('02:00:00:00:00:01\n')
        fake = self.root / 'bin/datconf'
        fake.write_text('#!/bin/sh\nexit 0\n'); fake.chmod(0o755)
        result = self.run_control('prepare')
        self.assertEqual(result.returncode, 0, result.stderr)
        wts = (self.root / 'etc/map/wts_bss_info_config').read_text()
        self.assertIn(r'Home\ \\\ Mesh', wts)
        self.assertIn(r'secret\ pass!', wts)
        self.assertIn(' 8x ', wts)
        self.assertIn(' 11x ', wts)
        self.assertIn(' 12x ', wts)
        self.assertEqual((self.root / 'etc/map/wts_bss_info_config').stat().st_mode & 0o777, 0o600)

class BridgeFlush(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.log = root / 'args'
        fake = root / 'ip-full'
        fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_IP_LOG"\n')
        fake.chmod(0o755)
        source = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/bin/brsw-del.sh'
        self.script = root / 'brsw-del.sh'
        self.script.write_text(source.read_text().replace('/usr/libexec/ip-full', str(fake)))
        self.env = {**os.environ, 'TEST_IP_LOG': str(self.log)}

    def tearDown(self):
        self.tmp.cleanup()

    def invoke(self, *args):
        return subprocess.run(['sh', str(self.script), *args], env=self.env, capture_output=True, text=True)

    def test_any_flush_request_only_targets_lan_bridge(self):
        for args in [('1', '0'), ('0', '1'), ('1', '1')]:
            self.assertEqual(self.invoke(*args).returncode, 0)
        self.assertEqual(self.log.read_text().splitlines(), ['link set dev br-lan type bridge fdb_flush'] * 3)

    def test_no_flush_or_invalid_arguments_never_invoke_ip(self):
        self.assertEqual(self.invoke('0', '0').returncode, 0)
        for args in [('1',), ('1', '2'), ('1; reboot', '1'), ('1', '1', 'extra')]:
            self.assertNotEqual(self.invoke(*args).returncode, 0)
        self.assertFalse(self.log.exists())

if __name__ == '__main__':
    unittest.main()
