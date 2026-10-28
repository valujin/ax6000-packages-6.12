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
        import re
        from tests.test_mesh_transaction import MeshTransaction
        MeshTransaction.setUp(self)
        self.env = {**self.env, 'TEST_STARTED': str(self.root / 'started'),
                    'TEST_FAIL_WIFI': str(self.root / 'wifi-fail'),
                    'TEST_MODULE': str(self.root / 'sys/module/mapfilter')}
        for name in ('tmp/sysinfo', 'sys/class/net/br-lan/bridge', 'sys/class/net/br-lan/brif/lan2',
                     'sys/class/net/br-lan/brif/lan3', 'sys/class/net/br-lan/brif/lan4',
                     'sys/class/net/ra0', 'sys/class/net/rax0', 'sys/module', 'usr/share/ax6000-mesh'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / 'sys/class/net/br-lan/bridge/vlan_filtering').write_text('0\n')
        (self.root / 'sys/class/net/br-lan/address').write_text('02:00:00:00:00:01\n')
        for radio in ('ra0', 'rax0'):
            (self.root / f'sys/class/net/{radio}/flags').write_text('0x1003\n')
        (self.root / 'tmp/sysinfo/board_name').write_text('xiaomi,redmi-router-ax6000-stock\n')
        wireless = {'d1': 'wifi-device', 'd2': 'wifi-device', 'a': 'wifi-iface', 'b': 'wifi-iface', 'a.mode': 'ap', 'b.mode': 'ap',
                    'a.device': 'd1', 'b.device': 'd2', 'd1.type': 'mtwifi', 'd2.type': 'mtwifi',
                    'd1.band': '2g', 'd2.band': '5g', 'a.network': 'lan', 'b.network': 'lan',
                    'a.encryption': 'psk2', 'b.encryption': 'sae-mixed', 'a.ssid': 'Example 2G',
                    'b.ssid': 'Example 5G', 'a.key': 'password123', 'b.key': 'password456'}
        (self.root / 'etc/config/wireless').write_text(json.dumps(wireless, sort_keys=True))
        mesh = {'main': 'mesh', 'main.role': 'controller', 'main.backhaul': 'wired', 'main.enabled': '0'}
        (self.root / 'etc/config/ax6000_mesh').write_text(json.dumps(mesh, sort_keys=True))
        marker = {'schema_version': 1, 'abi': 'mtk-20250408-map6e', 'source_commit': 'ae65e1de69971b5a2e3cf7e39390ee93f274d488', 'driver': '7.6.7.3', 'release': 2, 'defines': {'MAP_MLO_UPLINK': 1}, 'flags': dict.fromkeys(['MTK_MAP_SUPPORT', 'MTK_MAP_R2_VER_SUPPORT', 'MTK_MAP_R3_VER_SUPPORT', 'MTK_MAP_R2_6E_SUPPORT', 'MTK_MAP_R3_6E_SUPPORT', 'MTK_DFS_SLAVE_SUPPORT'], 'y')}
        (self.root / 'etc/ax6000-mesh-abi.json').write_text(json.dumps(marker, sort_keys=True, separators=(',', ':')) + '\n')
        package = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files'
        (self.root / 'usr/share/ax6000-mesh/vendor.sh').write_text((package / 'usr/share/ax6000-mesh/vendor.sh').read_text())
        template = self.root / 'usr/share/ax6000-mesh/vendor'; template.mkdir()
        for name in ('mapd_default.cfg', '1905d.cfg', 'mapd_user.cfg', 'ethernet_cfg.txt', 'wapp_ap_ra0.conf', 'wapp_ap_rax0.conf'):
            (template / name).write_text('Default\n')
        for cmd in ('wapp', 'wappctrl', 'mapd', 'p1905_managerd', 'mapd_cli', 'datconf', 'wifi_config_save'):
            self.write_tool(cmd, '#!/bin/sh\nexit 0\n')
        self.write_tool('pidof', '#!/bin/sh\n[ -f "$TEST_ROOT/running-$1" ] && echo 123\n')
        self.write_tool('wifi', '''#!/usr/bin/python3
import fcntl,os,sys
from pathlib import Path
root=Path(os.environ['TEST_ROOT']); action=sys.argv[1]
with (root/'commands.log').open('a') as log: log.write('wifi '+action+'\\n')
fail=Path(os.environ['TEST_FAIL_WIFI'])
if action in ('reload','up') and fail.exists(): fail.unlink(); sys.exit(1)
if action=='down':
    (root/'radios-down').touch()
    for name in ('ra0','rax0'):
        flags=root/'sys/class/net'/name/'flags'
        if flags.exists(): flags.write_text('0x1002\\n')
elif action=='up':
    with (root/'var/lock/mtwifi.lock').open('w') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: sys.exit(2)
    if not all((root/'sys/module'/name).is_dir() for name in ('mt_wifi','mtk_warp','mtk_warp_proxy')): sys.exit(3)
    with (root/'commands.log').open('a') as log: log.write('network reload\\n')
    (root/'radios-down').unlink(missing_ok=True)
    for name in ('ra0','rax0'): (root/'sys/class/net'/name/'flags').write_text('0x1003\\n')
''')
        self.write_tool('sleep', '''#!/usr/bin/python3
import os
from pathlib import Path
p=Path(os.environ['TEST_ROOT'])/'proc/uptime'
now=float(p.read_text().split()[0]); p.write_text(str(now+1)+' 0.00\\n')
''')
        for module in ('mt_wifi', 'mtk_warp', 'mtk_warp_proxy'):
            (self.root / 'sys/module' / module).mkdir()
        self.write_tool('modprobe', '''#!/bin/sh
echo "modprobe $*" >> "$TEST_ROOT/commands.log"
if [ "$1" = mt_wifi ] && [ -f "$TEST_ROOT/etc/ax6000-mesh/radio-modules" ]; then cp "$TEST_ROOT/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat" "$TEST_ROOT/dat-at-load"; fi
mkdir -p "$TEST_ROOT/sys/module/$1"
if [ "$1" = mt_wifi ]; then
  for radio in ra0 rax0; do mkdir -p "$TEST_ROOT/sys/class/net/$radio"; echo 0x1002 > "$TEST_ROOT/sys/class/net/$radio/flags"; done
fi
''')
        self.write_tool('iwpriv', '#!/bin/sh\nexit 0\n')
        self.write_tool('rmmod', '''#!/bin/sh
echo "rmmod $*" >> "$TEST_ROOT/commands.log"
[ ! -f "$TEST_ROOT/fail-rmmod-$1" ] || exit 1
if [ "$1" = mt_wifi ]; then
  cp "$TEST_ROOT/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat" "$TEST_ROOT/dat-at-unload"
  for radio in ra0 rax0; do rm -rf "$TEST_ROOT/sys/class/net/$radio"; done
fi
rmdir "$TEST_ROOT/sys/module/$1"
''')
        self.write_tool('ubus', '''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
if sys.argv[2]=='network.wireless':
    down=(Path(os.environ['TEST_ROOT'])/'radios-down').exists()
    print(json.dumps({name:{'up':not down,'pending':(name=='d2' and (Path(os.environ['TEST_ROOT'])/'radio-pending').exists())} for name in ('d1','d2')}))
else: print(json.dumps({'up':True,'proto':'dhcp','ipv4-address':[{'address':'192.168.1.42'}]}))
''')
        self.write_tool('jsonfilter', '''#!/usr/bin/python3
import json,sys
args=sys.argv[1:]; value=json.loads(args[args.index('-s')+1]) if '-s' in args else json.load(sys.stdin); key=args[-1]
if key.startswith('@.d1.') or key.startswith('@.d2.'):
    value=value[key.split('.')[1]][key.split('.')[2]]; print(str(value).lower()); sys.exit(0)
for token in {'@.connected':['connected'], '@.ok':['ok'], '@.up':['up'], '@.proto':['proto'], '@["ipv4-address"][0].address':['ipv4-address',0,'address']}.get(key,[]): value=value[token]
print(str(value).lower() if isinstance(value,bool) else value)
''')
        init = self.root / 'etc/init.d/ax6000-mesh'
        init.write_text('#!/bin/sh\ncase "$1" in start) touch "$TEST_STARTED";; stop) rm -f "$TEST_STARTED";; esac\n'); init.chmod(0o755)
        health = self.root / 'usr/libexec/ax6000-mesh-health'
        health.write_text('#!/bin/sh\n[ -f "$TEST_STARTED" ]\n'); health.chmod(0o755)
        vendor = self.root / 'usr/libexec/ax6000-mesh-vendor'
        vendor.write_text('#!/bin/sh\ncase "$1" in status) echo \'{"connected":true}\';; pair) echo \'{"ok":true}\';; esac\n'); vendor.chmod(0o755)
        profile = self.root / 'usr/libexec/ax6000-mesh-profile'
        profile.write_text('#!/bin/sh\nexit 0\n'); profile.chmod(0o755)
        helper = self.root / 'usr/libexec/ax6000-mesh-transaction'
        helper.write_text(f'#!/bin/sh\nexec busybox ash "{self.helper}" "$@"\n'); helper.chmod(0o755)
        prefixes = ('/etc', '/sys', '/tmp/sysinfo', '/usr/libexec', '/usr/share/ax6000-mesh', '/var', '/proc/uptime')
        source = re.sub('|'.join(re.escape(p) for p in prefixes), lambda m: str(self.root) + m[0], CONTROL.read_text())
        self.control = self.root / 'usr/libexec/ax6000-mesh-control'
        self.control.write_text(source); self.control.chmod(0o755)
        self.original = {name: (self.root / 'etc/config' / name).read_bytes() for name in ('network', 'dhcp', 'wireless', 'ax6000_mesh')}

    write_tool = __import__('tests.test_mesh_transaction', fromlist=['MeshTransaction']).MeshTransaction.write_tool

    def set_config(self, package, **values):
        import json
        path = self.root / 'etc/config' / package
        config = json.loads(path.read_text()); config.update(values); path.write_text(json.dumps(config, sort_keys=True))

    def config(self, package):
        import json
        return json.loads((self.root / 'etc/config' / package).read_text())

    def run_control(self, *args):
        return subprocess.run(['sh', str(self.control), *args], env=self.env, text=True, capture_output=True, timeout=20)

    def test_controller_apply_and_disable_restore_saved_configuration(self):
        applied = self.run_control('apply')
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(self.config('ax6000_mesh')['main.enabled'], '1')
        wireless = self.config('wireless')
        for section in ('ax6000_mesh_ap1', 'ax6000_mesh_ap2'):
            self.assertEqual(wireless[section + '.multicast_to_unicast'], '0')
        for section in ('a', 'b'):
            self.assertNotIn(section + '.multicast_to_unicast', wireless)
        state = self.root / 'etc/ax6000-mesh'
        self.assertEqual((state / 'phase').read_text().strip(), 'committed')
        for name in ('network', 'dhcp', 'wireless', 'mesh'): self.assertTrue((state / ('original-' + name)).exists())
        disabled = self.run_control('disable')
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        for name, content in self.original.items(): self.assertEqual((self.root / 'etc/config' / name).read_bytes(), content)
        self.assertFalse(state.exists())

    def test_committed_vendor_wts_survives_service_prepare(self):
        self.set_config('ax6000_mesh', **{'main.role': 'agent'})
        self.assertEqual(self.run_control('apply').returncode, 0)
        wts = self.root / 'etc/map/wts_bss_info_config'
        wts.parent.mkdir(parents=True, exist_ok=True)
        wts.write_text('vendor-enrolled-config\n')
        result = self.run_control('prepare')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(wts.read_text(), 'vendor-enrolled-config\n')

    def test_r3_regenerated_agent_wts_does_not_block_recovery(self):
        self.set_config('ax6000_mesh', **{'main.role': 'agent'})
        vendor = self.root / 'usr/libexec/ax6000-mesh-vendor'
        vendor.write_text('''#!/bin/sh
case "$1" in
 status) mkdir -p "$TEST_ROOT/etc/map"; echo enrolled-vendor-profile > "$TEST_ROOT/etc/map/wts_bss_info_config"; chmod 600 "$TEST_ROOT/etc/map/wts_bss_info_config"; echo '{"connected":true}';;
 pair) echo '{"ok":true}';;
esac
'''); vendor.chmod(0o755)
        applied = self.run_control('apply'); self.assertEqual(applied.returncode, 0, applied.stderr)
        state = self.root / 'etc/ax6000-mesh'
        key = (state / 'backhaul-key').read_text().strip()
        ssid = (state / 'backhaul-ssid').read_text().strip()
        wts = self.root / 'etc/map/wts_bss_info_config'
        lib = self.root / 'usr/share/ax6000-mesh/vendor.sh'
        code = '. "$1"; mesh_write_bss "$2" AX6000-joining "$3" sae-mixed AX6000-joining "$3" sae-mixed "$4" "$3"'
        self.assertEqual(subprocess.run(['sh', '-c', code, 'test', str(lib), str(wts), key, ssid]).returncode, 0)
        result = subprocess.run(['busybox', 'ash', str(self.helper), 'check'], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        wts.write_text('unrelated manual edit\n')
        result = subprocess.run(['busybox', 'ash', str(self.helper), 'check'], env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)

    def test_signal_immediately_after_commit_does_not_roll_back(self):
        helper = self.root / 'usr/libexec/ax6000-mesh-transaction'
        helper.write_text(f'''#!/bin/sh
if [ "$1" = commit ]; then
  busybox ash "{self.helper}" "$@" || exit $?
  kill -TERM "$PPID"
  exit 0
fi
exec busybox ash "{self.helper}" "$@"
''')
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'etc/ax6000-mesh/phase').read_text().strip(), 'committed')
        self.assertEqual(self.config('ax6000_mesh')['main.enabled'], '1')
        self.assertTrue((self.root / 'etc/ax6000-mesh/original-wireless').exists())

    def test_restore_only_unloads_owned_mapfilter(self):
        result = self.run_control('apply'); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'sys/module/mapfilter').exists())
        result = self.run_control('disable'); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'sys/module/mapfilter').exists())
        (self.root / 'sys/module/mapfilter').mkdir()
        result = self.run_control('apply'); self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_control('disable'); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'sys/module/mapfilter').exists())

    def test_agent_automatically_configures_dhcp_and_disables_lan_servers(self):
        self.set_config('ax6000_mesh', **{'main.role': 'agent'})
        applied = self.run_control('apply')
        self.assertEqual(applied.returncode, 0, applied.stderr)
        network, dhcp = self.config('network'), self.config('dhcp')
        wireless = self.config('wireless')
        for section in ('ax6000_mesh_ap1', 'ax6000_mesh_ap2'):
            self.assertEqual(wireless[section + '.multicast_to_unicast'], '0')
        for section in ('a', 'b'):
            self.assertNotIn(section + '.multicast_to_unicast', wireless)
        self.assertEqual(network['lan.proto'], 'dhcp')
        self.assertIn('wan', network['brlan.ports'])
        for section in ('lan', 'extra'):
            self.assertEqual(dhcp[section + '.ignore'], '1')
            for key in ('ra', 'dhcpv6', 'ndp'): self.assertEqual(dhcp[section + '.' + key], 'disabled')
        self.assertEqual((self.root / 'etc/ax6000-mesh/phase').read_text().strip(), 'committed')
        result = self.run_control('disable')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'etc/config/network').read_bytes(), self.original['network'])
        self.assertEqual((self.root / 'etc/config/dhcp').read_bytes(), self.original['dhcp'])

    def test_wireless_agent_requires_durable_profile_before_commit(self):
        self.set_config('ax6000_mesh', **{'main.role': 'agent', 'main.backhaul': 'wireless'})
        helper = self.root / 'usr/libexec/ax6000-mesh-profile'
        real = self.root / 'profile-real'
        source = (ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-profile').read_text()
        real.write_text(source.replace('/etc/map/mapd_user.cfg', str(self.root / 'etc/map/mapd_user.cfg')))
        real.chmod(0o755)
        helper.write_text(f'#!/bin/sh\n[ "${{1:-}}" = reset ] && exec sh "{real}" reset\nexit "${{TEST_PROFILE_FAIL:-0}}"\n'); helper.chmod(0o755)
        profile = self.root / 'etc/map/mapd_user.cfg'
        profile.parent.mkdir(parents=True, exist_ok=True)
        old_profile = 'BhProfile0Valid=1\nBhProfile0Ssid=old-network\nBhProfile0WpaPsk=old-password\n'
        profile.write_text(old_profile); profile.chmod(0o600)
        vendor = self.root / 'usr/libexec/ax6000-mesh-vendor'
        vendor.write_text('''#!/usr/bin/python3
import os,sys
from pathlib import Path
r=Path(os.environ['TEST_ROOT']); p=r/'proc/uptime'
if sys.argv[1]=='status':
 if 'BhProfile0Valid=' in (r/'etc/map/mapd_user.cfg').read_text(): (r/'old-profile-present').touch()
 now=float(p.read_text().split()[0]); p.write_text(str(now+45)+' 0.00\\n'); print('{"connected":true}')
else: print('{"ok":true}')
'''); vendor.chmod(0o755)
        self.write_tool('sleep', '#!/bin/sh\nexit 0\n')
        self.env['TEST_PROFILE_FAIL'] = '1'
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())
        self.assertEqual(profile.read_text(), old_profile)
        self.assertFalse((self.root / 'old-profile-present').exists())
        for name in ('network', 'dhcp', 'wireless'):
            self.assertEqual((self.root / 'etc/config' / name).read_bytes(), self.original[name])
        self.env['TEST_PROFILE_FAIL'] = '0'
        applied = self.run_control('apply'); self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual((self.root / 'etc/ax6000-mesh/phase').read_text().strip(), 'committed')

    def test_slow_enrollment_status_respects_monotonic_deadline_and_rolls_back(self):
        self.set_config('ax6000_mesh', **{'main.role': 'agent'})
        original_mesh = (self.root / 'etc/config/ax6000_mesh').read_bytes()
        vendor = self.root / 'usr/libexec/ax6000-mesh-vendor'
        vendor.write_text('''#!/usr/bin/python3
import os,sys
from pathlib import Path
root=Path(os.environ['TEST_ROOT']); uptime=root/'proc/uptime'
if sys.argv[1]=='status':
    with (root/'status-calls').open('a') as calls: calls.write('status\\n')
    now=float(uptime.read_text().split()[0]); uptime.write_text(str(now+9)+' 0.00\\n')
    print('{"connected":false}')
else: print('{"ok":true}')
''')
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('did not join', result.stderr)
        self.assertEqual(len((self.root / 'status-calls').read_text().splitlines()), 18)
        self.assertEqual(float((self.root / 'proc/uptime').read_text().split()[0]), 280)
        for name in ('network', 'dhcp', 'wireless'):
            self.assertEqual((self.root / 'etc/config' / name).read_bytes(), self.original[name])
        self.assertEqual((self.root / 'etc/config/ax6000_mesh').read_bytes(), original_mesh)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_rpc_reports_only_valid_pending_snapshots_as_recovery_pending(self):
        import json
        import re
        native = ROOT.parent / 'local-native-mesh-20261027/work/build/source/staging_dir/host'
        jshn = native / 'share/libubox/jshn.sh'
        if not jshn.exists(): self.skipTest('OpenWrt jshn host tools are unavailable')
        rpc = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/rpcd/ax6000.mesh'
        source = rpc.read_text().replace('/usr/share/libubox/jshn.sh', str(jshn))
        prefixes = ('/etc', '/sys', '/tmp/sysinfo', '/usr/libexec', '/var')
        source = re.sub('|'.join(re.escape(p) for p in prefixes), lambda m: str(self.root) + m[0], source)
        script = self.root / 'rpc'; script.write_text(source)
        env = {**self.env, 'PATH': str(self.root / 'bin') + ':' + str(native / 'bin') + ':' + os.environ['PATH'], 'LD_LIBRARY_PATH': str(native / 'lib')}
        def status():
            result = subprocess.run(['bash', str(script), 'call', 'status'], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertFalse(status()['recovery_pending'])
        result = subprocess.run([str(self.root / 'usr/libexec/ax6000-mesh-transaction'), 'begin', 'controller', 'wired'], env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(status()['recovery_pending'])
        (self.root / 'etc/ax6000-mesh/original-wireless').write_text('corrupted')
        self.assertFalse(status()['recovery_pending'])

    def test_disconnect_clears_pairing_window(self):
        pairing = self.root / 'var/run/ax6000-mesh-pairing'; pairing.write_text('9999\n')
        result = self.run_control('disconnect-backhaul')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(pairing.exists())

    def test_disconnect_skips_inactive_backhaul_interfaces(self):
        for name in ('apcli0', 'apclix0'):
            directory = self.root / 'sys/class/net' / name; directory.mkdir()
            (directory / 'flags').write_text('0x1002\n')
        self.write_tool('iwpriv', '#!/bin/sh\necho invoked > "$TEST_ROOT/iwpriv-called"\nexit 1\n')
        result = self.run_control('disconnect-backhaul')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'iwpriv-called').exists())

    def configure_radio_delay(self, ready_at):
        self.write_tool('sleep', '''#!/bin/sh
read -r now rest < "$TEST_ROOT/proc/uptime"
now=${now%%.*}
printf '%s 0.00\\n' "$((now + 1))" > "$TEST_ROOT/proc/uptime"
''')
        wifi = self.root / 'bin/wifi'
        original = wifi.read_text()
        wifi.write_text(original.replace("fail=Path(os.environ['TEST_FAIL_WIFI'])", f'''if action=='isup':
    now=float((root/'proc/uptime').read_text().split()[0])
    sys.exit(0 if (root/'wifi-restored').exists() or now >= {ready_at} else 1)
if action=='up': (root/'wifi-restored').touch()
fail=Path(os.environ['TEST_FAIL_WIFI'])'''))

    def test_radios_ready_after_60_seconds_complete_setup(self):
        self.configure_radio_delay(170)
        result = self.run_control('apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(float((self.root / 'proc/uptime').read_text().split()[0]), 170)
        self.assertEqual((self.root / 'etc/ax6000-mesh/phase').read_text().strip(), 'committed')

    def test_radios_not_ready_at_deadline_roll_back(self):
        self.configure_radio_delay(260)
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('radios did not become ready', result.stderr)
        self.assertEqual(float((self.root / 'proc/uptime').read_text().split()[0]), 250)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())
        for name, content in self.original.items(): self.assertEqual((self.root / 'etc/config' / name).read_bytes(), content)

    def test_failure_reloads_restored_configuration(self):
        (self.root / 'wifi-fail').touch()
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Wireless reload failed', result.stderr)
        for name, content in self.original.items(): self.assertEqual((self.root / 'etc/config' / name).read_bytes(), content)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_restore_unloads_before_dat_and_reloads_modules_before_network(self):
        result = self.run_control('apply'); self.assertEqual(result.returncode, 0, result.stderr)
        dat = self.root / 'etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat'
        original = dat.read_text(); dat.write_text(original.replace('SSID1=original', 'SSID1=enrolled'))
        self.log.write_text('')
        result = self.run_control('disable'); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('SSID1=enrolled', (self.root / 'dat-at-unload').read_text())
        self.assertEqual((self.root / 'dat-at-load').read_text(), original)
        log = self.log.read_text()
        steps = ('wifi down', 'rmmod mtk_warp_proxy', 'rmmod mtk_warp', 'rmmod mt_wifi',
                 'modprobe mt_wifi', 'modprobe mtk_warp', 'modprobe mtk_warp_proxy', 'wifi up', 'network reload')
        offsets = [log.index(step) for step in steps]
        self.assertEqual(offsets, sorted(offsets), log)

    def test_pending_second_radio_blocks_unload_and_retains_snapshot(self):
        result = self.run_control('apply'); self.assertEqual(result.returncode, 0, result.stderr)
        dat = self.root / 'etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat'
        original = dat.read_text(); dat.write_text(original.replace('SSID1=original', 'SSID1=enrolled'))
        (self.root / 'radio-pending').touch(); self.log.write_text('')
        result = self.run_control('disable'); self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('rmmod mt_wifi', self.log.read_text())
        self.assertIn('SSID1=enrolled', dat.read_text())
        self.assertTrue((self.root / 'etc/ax6000-mesh/original-dat0').exists())
        (self.root / 'radio-pending').unlink()
        result = subprocess.run([str(self.root / 'usr/libexec/ax6000-mesh-transaction'), 'rollback', 'disable'],
                                env=self.env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(dat.read_text(), original)

    def test_partial_unload_preserves_current_dat_and_retry_restores(self):
        result = self.run_control('apply'); self.assertEqual(result.returncode, 0, result.stderr)
        dat = self.root / 'etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat'
        original = dat.read_text(); dat.write_text(original.replace('SSID1=original', 'SSID1=enrolled'))
        fail = self.root / 'fail-rmmod-mtk_warp'; fail.touch()
        result = self.run_control('disable'); self.assertNotEqual(result.returncode, 0)
        self.assertIn('SSID1=enrolled', dat.read_text())
        self.assertTrue((self.root / 'etc/ax6000-mesh/original-dat0').exists())
        self.assertFalse((self.root / 'sys/module/mtk_warp_proxy').exists())
        fail.unlink()
        result = subprocess.run([str(self.root / 'usr/libexec/ax6000-mesh-transaction'), 'rollback', 'disable'],
                                env=self.env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(dat.read_text(), original)
        for module in ('mt_wifi', 'mtk_warp', 'mtk_warp_proxy'): self.assertTrue((self.root / 'sys/module' / module).exists())
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_failed_radio_restore_retains_snapshot_for_transaction_retry(self):
        result = self.run_control('apply'); self.assertEqual(result.returncode, 0, result.stderr)
        (self.root / 'wifi-fail').touch()
        result = self.run_control('disable')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('snapshot retained', result.stderr.lower())
        self.assertTrue((self.root / 'etc/ax6000-mesh/original-wireless').exists())
        result = self.run_control('disable')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())
        for name, content in self.original.items(): self.assertEqual((self.root / 'etc/config' / name).read_bytes(), content)

    def test_disable_refuses_to_overwrite_user_edit(self):
        result = self.run_control('apply'); self.assertEqual(result.returncode, 0, result.stderr)
        path = self.root / 'etc/config/wireless'; path.write_text('user edit\n')
        result = self.run_control('disable')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('changed', result.stderr)
        self.assertEqual(path.read_text(), 'user edit\n')
        self.assertTrue((self.root / 'etc/ax6000-mesh/original-wireless').exists())

    def test_preflight_accepts_distinct_mixed_and_wpa2_credentials(self):
        result = self.run_control('preflight')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_preflight_agent_does_not_require_matching_client_credentials(self):
        self.set_config('ax6000_mesh', **{'main.role': 'agent'})
        self.set_config('wireless', **{'a.ssid': '', 'a.key': '', 'a.encryption': 'none'})
        result = self.run_control('preflight')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_hidden_client_ap(self):
        self.set_config('wireless', **{'a.hidden': '1'})
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0); self.assertIn('visible', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_disabled_extra_ap_is_rejected_before_snapshot(self):
        self.set_config('wireless', **{'extra': 'wifi-iface', 'extra.mode': 'ap', 'extra.disabled': '1',
                                       'extra.device': 'd1', 'extra.network': 'lan'})
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('disabled', result.stderr.lower())
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_disabled_primary_ap_is_rejected_before_snapshot(self):
        self.set_config('wireless', **{'a.disabled': '1'})
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('disabled', result.stderr.lower())
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_anonymous_guest_ap_is_counted(self):
        self.set_config('wireless', **{'cfg01abcd': 'wifi-iface', 'cfg01abcd.mode': 'ap', 'cfg01abcd.network': 'guest'})
        result = self.run_control('apply')
        self.assertNotEqual(result.returncode, 0); self.assertIn('LAN', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_rejects_absent_or_mismatched_firmware_abi(self):
        marker = self.root / 'etc/ax6000-mesh-abi.json'; marker.write_text('{}\n')
        result = self.run_control('apply'); self.assertNotEqual(result.returncode, 0); self.assertIn('ABI', result.stderr)
        marker.unlink(); result = self.run_control('apply'); self.assertNotEqual(result.returncode, 0); self.assertIn('ABI', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_rejects_vlan_filtered_lan_bridge(self):
        (self.root / 'sys/class/net/br-lan/bridge/vlan_filtering').write_text('1\n')
        result = self.run_control('apply'); self.assertNotEqual(result.returncode, 0); self.assertIn('VLAN', result.stderr)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_prepare_preserves_pinned_1905_defaults_and_replaces_owned_fields_once(self):
        # Original 1905daemon/1905d.cfg from archive 35234223, SHA-256
        # 82f7cc4ad5731e750f87c9a4ad19a39d2456bb8fec0cf79bf4b3f3ccb4f14795.
        fixture = ROOT / 'tests/fixtures/mesh-runtime/1905d-sdk35234223.cfg'
        (self.root / 'usr/share/ax6000-mesh/vendor/1905d.cfg').write_bytes(fixture.read_bytes())
        state = self.root / 'etc/ax6000-mesh'; state.mkdir()
        (state / 'backhaul-ssid').write_text('private-bh\n'); (state / 'backhaul-key').write_text('privatepassword\n')
        for role, backhaul in (('controller', 'wired'), ('agent', 'wired'), ('agent', 'wireless')):
            with self.subTest(role=role, backhaul=backhaul):
                self.set_config('ax6000_mesh', **{'main.role': role, 'main.backhaul': backhaul})
                result = self.run_control('prepare'); self.assertEqual(result.returncode, 0, result.stderr)
                rows = [line for line in (self.root / 'etc/map/1905d.cfg').read_text().splitlines()
                        if line and not line.startswith('#') and '=' in line]
                values = {}
                for row in rows:
                    key, value = row.split('=', 1); values.setdefault(key, []).append(value)
                self.assertEqual(values['gtk_rekey_interval'], ['3600'])
                self.assertEqual(values['decrypt_fail_threshold'], ['10'])
                self.assertEqual(values['ob_wan_only'], ['0'])
                self.assertEqual(values['radio_band'], ['24G;5GL;5GH;'])
                self.assertEqual(values['map_controller_alid'], ['02:00:00:00:00:01'])
                self.assertEqual(values['map_agent_alid'], ['02:00:00:00:00:01'])
                self.assertEqual(values['map_agent'], ['1' if role == 'agent' else '0'])
                self.assertEqual(values['map_root'], ['0' if role == 'agent' else '1'])
                self.assertEqual(values['bh_type'], ['wifi' if backhaul == 'wireless' else 'eth'])
                self.assertEqual(values['br_inf'], ['br-lan'])
                self.assertEqual(values['map_ver'], ['R2'])
                self.assertEqual(values['bss_config_priority'], ['ra0;ra1;rax0;rax1;apcli0;apclix0'])
                self.assertEqual(values['lan'], ['lan2', 'lan3', 'lan4'] + (['wan'] if role == 'agent' and backhaul == 'wired' else []))
                self.assertTrue(all(len(v) == 1 for k, v in values.items() if k != 'lan'), values)

    def test_wts_escapes_and_separates_client_and_backhaul(self):
        self.set_config('wireless', **{'a.ssid': r'Home \ Mesh', 'a.key': 'secret pass!'})
        state = self.root / 'etc/ax6000-mesh'; state.mkdir()
        (state / 'backhaul-ssid').write_text('private-bh\n'); (state / 'backhaul-key').write_text('privatepassword\n')
        result = self.run_control('prepare'); self.assertEqual(result.returncode, 0, result.stderr)
        wts = (self.root / 'etc/map/wts_bss_info_config').read_text()
        self.assertIn(r'Home\ \\\ Mesh', wts); self.assertIn(r'secret\ pass!', wts)
        self.assertIn('Example\\ 5G 0x0060 0x0008 password456 0 1', wts)
        self.assertIn('private-bh 0x0020 0x0008 privatepassword 1 0', wts)
        self.assertEqual((self.root / 'etc/map/wts_bss_info_config').stat().st_mode & 0o777, 0o600)


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
