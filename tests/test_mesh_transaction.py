"""Exercise transaction safety with real ash and isolated UCI/network tools."""
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files'
HELPER = FILES / 'usr/libexec/ax6000-mesh-transaction'


@unittest.skipUnless(shutil.which('busybox'), 'BusyBox ash required')
class MeshTransaction(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.exists(), 'Durable Mesh transaction helper is missing')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('etc/config', 'etc/init.d', 'etc/wireless/mediatek', 'var/lock', 'var/run',
                     'sys/class/net/br-lan/brif', 'sys/class/net/wan', 'proc/sys/kernel/random', 'usr/libexec', 'bin'):
            (self.root / name).mkdir(parents=True)
        (self.root / 'proc/uptime').write_text('100.00 0.00\n')
        (self.root / 'proc/sys/kernel/random/boot_id').write_text('fixture-boot\n')
        self.configs = {
            'network': {'lan': 'interface', 'lan.proto': 'static', 'lan.device': 'br-lan',
                        'lan.ipaddr': '192.168.1.1', 'lan.netmask': '255.255.255.0',
                        'brlan': 'device', 'brlan.name': 'br-lan', 'brlan.type': 'bridge',
                        'brlan.ports': ['lan2', 'lan3', 'lan4'], 'wan': 'interface',
                        'wan.device': 'wan', 'wan.proto': 'dhcp', 'wan6': 'interface', 'wan6.device': '@wan'},
            'dhcp': {'lan': 'dhcp', 'lan.interface': 'lan', 'lan.ignore': '0', 'lan.ra': 'server',
                     'lan.dhcpv6': 'server', 'extra': 'dhcp', 'extra.interface': 'lan', 'extra.ndp': 'relay'},
            'wireless': {'radio0': 'wifi-device', 'radio0.type': 'mtwifi', 'ap.ssid': 'original'},
            'ax6000_mesh': {'main': 'mesh', 'main.enabled': '0', 'main.role': 'agent', 'main.backhaul': 'wired'},
        }
        for name, values in self.configs.items():
            (self.root / 'etc/config' / name).write_text(json.dumps(values, sort_keys=True))
        for band in ('b0', 'b1'):
            (self.root / f'etc/wireless/mediatek/mt7986-ax6000.dbdc.{band}.dat').write_text(
                'SSID1=original\nWPAPSK1=fixture-only\nCountryCode=GB\nChannel=0\n')
        self.original = {str(p.relative_to(self.root)): p.read_bytes()
                         for p in (self.root / 'etc').rglob('*') if p.is_file()}
        self.log = self.root / 'commands.log'
        callback = self.root / 'usr/libexec/ax6000-mesh-control'
        callback.write_text('''#!/bin/sh
echo "disconnect $*" >> "$TEST_ROOT/commands.log"
if [ "$1" = quiesce-radios ]; then
  [ ! -f "$TEST_ROOT/fail-quiesce-radios" ] || exit 1
  if [ -f "$TEST_ROOT/require-topology-transition" ]; then
    for dat in "$TEST_ROOT"/etc/wireless/mediatek/*.dat; do grep -qx BssidNum=4 "$dat" || exit 1; done
  fi
  : > "$TEST_ROOT/radios-quiesced"
fi
if [ "$1" = restore-radios ]; then
  [ ! -f "$TEST_ROOT/fail-restore-radios" ] || exit 1
  if [ -f "$TEST_ROOT/require-topology-transition" ]; then
    [ -f "$TEST_ROOT/radios-quiesced" ] || exit 1
    for dat in "$TEST_ROOT"/etc/wireless/mediatek/*.dat; do grep -qx BssidNum=2 "$dat" || exit 1; done
  fi
  echo 'network reload' >> "$TEST_ROOT/commands.log"
  echo 'wifi up' >> "$TEST_ROOT/commands.log"
fi
exit 0
'''); callback.chmod(0o755)
        self.write_tool('wifi', '#!/bin/sh\necho "wifi $*" >> "$TEST_ROOT/commands.log"\n')
        self.write_tool('rmmod', '#!/bin/sh\necho "rmmod $*" >> "$TEST_ROOT/commands.log"\nrmdir "$TEST_ROOT/sys/module/mapfilter"\n')
        self.write_tool('iwpriv', '#!/bin/sh\necho "iwpriv $*" >> "$TEST_ROOT/commands.log"\n')
        self.write_tool('uci', r'''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
r=Path(os.environ['TEST_ROOT']); a=[x for x in sys.argv[1:] if x not in ('-q','-X')]
op=a.pop(0); key=a.pop(0); package,_,field=key.partition('.')
p=r/'etc/config'/package; d=json.loads(p.read_text()) if p.exists() and p.stat().st_size else {}
if op=='changes':
 q=r/('pending-'+package)
 if q.exists(): print(q.read_text())
elif op=='get':
 if field not in d: sys.exit(1)
 v=d[field]; print(' '.join(v) if isinstance(v,list) else v)
elif op=='show':
 for k,v in d.items():
  if isinstance(v,list): v=' '.join("'"+i+"'" for i in v)
  print(package+'.'+k+'='+str(v))
elif op in ('set','add_list','delete'):
 if op!='delete': field,_,value=field.partition('=')
 if op=='set': d[field]=value
 elif op=='add_list': d.setdefault(field,[]).append(value)
 elif field in d: del d[field]
 else: sys.exit(1)
 p.write_text(json.dumps(d,sort_keys=True))
elif op=='export':
 for k,v in sorted(d.items()): print("option "+k+" '"+str(v)+"'")
elif op not in ('commit','revert'): sys.exit(2)
''')
        self.write_tool('pidof', '''#!/bin/sh
if [ -f "$TEST_ROOT/stop-pending-$1" ]; then
  polls=$(cat "$TEST_ROOT/stop-polls-$1" 2>/dev/null || echo 0)
  if [ "$polls" -ge 2 ]; then rm -f "$TEST_ROOT/running-$1"; exit 1; fi
  echo "$((polls + 1))" > "$TEST_ROOT/stop-polls-$1"
fi
[ -f "$TEST_ROOT/running-$1" ] && echo 123
''')
        self.write_tool('ifdown', '#!/bin/sh\necho "ifdown $*" >> "$TEST_ROOT/commands.log"\n')
        self.write_tool('ip', r'''#!/bin/sh
echo "ip $*" >> "$TEST_ROOT/commands.log"
case "$*" in
 *nomaster*) [ ! -f "$TEST_ROOT/fail-detach" ] || exit 1; rm -f "$TEST_ROOT/sys/class/net/wan/master" "$TEST_ROOT/sys/class/net/br-lan/brif/wan" ;;
esac
''')
        self.write_tool('cp', '#!/bin/sh\n[ ! -f "$TEST_ROOT/fail-copy" ] || exit 1\ncase "$*" in *original-dhcp*) [ ! -f "$TEST_ROOT/fail-copy-dhcp" ] || exit 1 ;; esac\ncase "$2" in */original-network) echo restore-network >> "$TEST_ROOT/commands.log" ;; esac\nexec /bin/cp "$@"\n')
        for name in ('dnsmasq', 'odhcpd', 'network', 'ax6000-mesh-watchdog', 'ax6000-mesh-operation'):
            p = self.root / 'etc/init.d' / name
            p.write_text('''#!/bin/sh
name=${0##*/}
echo "$name $*" >> "$TEST_ROOT/commands.log"
case "$1" in
 stop) [ ! -f "$TEST_ROOT/fail-stop-$name" ] || exit 1
       if [ -f "$TEST_ROOT/delay-stop-$name" ]; then : > "$TEST_ROOT/stop-pending-$name";
       else rm -f "$TEST_ROOT/running-$name"; fi ;;
 start) [ ! -f "$TEST_ROOT/fail-start-$name" ] || exit 1; : > "$TEST_ROOT/running-$name" ;;
 running) [ -f "$TEST_ROOT/running-$name" ] ;;
 reload) [ ! -f "$TEST_ROOT/fail-reload-$name" ] ;;
esac
''')
            p.chmod(0o755)
        for name in ('dnsmasq', 'odhcpd'):
            (self.root / ('running-' + name)).touch()
        self.helper = self.root / 'transaction'
        text = HELPER.read_text()
        prefixes = ('/etc', '/sys', '/var', '/usr/libexec', '/usr/share/ax6000-mesh', '/proc/uptime', '/proc/sys/kernel/random/boot_id')
        text = re.sub('|'.join(re.escape(p) for p in prefixes), lambda m: str(self.root) + m[0], text)
        # This host BusyBox enables standalone applets, which otherwise bypass PATH.
        for command in ('uci', 'pidof', 'ifdown', 'ip', 'cp', 'wifi', 'iwpriv', 'rmmod'):
            text = re.sub(r'(?<![A-Za-z0-9_./-])' + command + r'(?= )',
                          str(self.root / 'bin' / command), text)
        self.helper.write_text(text)
        self.helper.chmod(0o755)
        self.env = {**os.environ, 'TEST_ROOT': str(self.root), 'PATH': str(self.root / 'bin') + ':' + os.environ['PATH']}

    def write_tool(self, name, text):
        p = self.root / 'bin' / name
        p.write_text(text)
        p.chmod(0o755)

    def call(self, *args):
        return subprocess.run(['busybox', 'ash', str(self.helper), *args], env=self.env,
                              capture_output=True, text=True, timeout=10)

    def begin(self, role='agent', backhaul='wired'):
        result = self.call('begin', role, backhaul)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_snapshot_is_complete_private_and_preserves_absent_files_and_modes(self):
        network = self.root / 'etc/config/network'; network.chmod(0o640)
        self.begin()
        state = self.root / 'etc/ax6000-mesh'
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.call('present').returncode, 0)
        self.assertEqual(json.loads(self.call('status').stdout)['state'], 'pending')
        self.assertTrue((state / 'original-wireless').is_file())
        self.assertTrue((state / 'absent-map-user').is_file())
        self.assertEqual(self.call('rollback', 'boot').returncode, 0)
        self.assertEqual(network.stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.root / 'etc/map/mapd_user.cfg').exists())

    def test_pending_changes_and_failed_snapshot_never_change_configuration(self):
        (self.root / 'pending-dhcp').write_text('uncommitted')
        self.assertNotEqual(self.call('begin', 'agent', 'wired').returncode, 0)
        (self.root / 'pending-dhcp').unlink()
        (self.root / 'fail-copy').touch()
        self.assertNotEqual(self.call('begin', 'agent', 'wired').returncode, 0)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())
        for path, expected in self.original.items(): self.assertEqual((self.root / path).read_bytes(), expected)

    def test_watchdog_start_failure_unpublishes_untouched_snapshot(self):
        (self.root / 'fail-start-ax6000-mesh-watchdog').touch()
        self.assertNotEqual(self.call('begin', 'agent', 'wired').returncode, 0)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())
        for path, expected in self.original.items(): self.assertEqual((self.root / path).read_bytes(), expected)

    def test_generated_vendor_files_are_adopted_at_commit_but_uci_stays_strict(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        self.assertEqual(self.call('seal').returncode, 0)
        dat = self.root / 'etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat'
        dat.write_text(dat.read_text() + 'BssidNum=2\nMapMode=1\n')
        wapp = self.root / 'etc/wapp_ap_ra0.conf'; wapp.write_text('generated profile\n')
        wireless = self.root / 'etc/config/wireless'; before = wireless.read_bytes()
        wireless.write_text(wireless.read_text() + ' user-edit')
        self.assertNotEqual(self.call('commit').returncode, 0)
        self.assertEqual(json.loads(self.call('status').stdout)['state'], 'pending')
        wireless.write_bytes(before)
        self.assertEqual(self.call('commit').returncode, 0)
        self.assertEqual(self.call('check').returncode, 0)
        wapp.write_text('user-edit\n')
        self.assertNotEqual(self.call('check').returncode, 0)
        self.assertEqual(self.call('rollback').returncode, 0)
        self.assertFalse(wapp.exists())

    def test_agent_stops_servers_before_preparing_wan_bridge_and_dhcp_client(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        network = json.loads((self.root / 'etc/config/network').read_text())
        self.assertEqual(network['lan.proto'], 'dhcp')
        self.assertNotIn('lan.ipaddr', network)
        self.assertEqual(network['wan.auto'], '0')
        self.assertEqual(network['wan6.auto'], '0')
        self.assertEqual(network['brlan.ports'], ['lan2', 'lan3', 'lan4', 'wan'])
        dhcp = json.loads((self.root / 'etc/config/dhcp').read_text())
        for section in ('lan', 'extra'):
            self.assertEqual(dhcp[section + '.ignore'], '1')
            for option in ('ra', 'dhcpv6', 'ndp'): self.assertEqual(dhcp[section + '.' + option], 'disabled')
        self.assertNotIn('network reload', self.log.read_text())
        self.assertLess(self.log.read_text().index('odhcpd stop'), self.log.read_text().index('ifdown wan'))

    def test_server_stop_allows_two_poll_async_exit_before_network_change(self):
        self.begin()
        (self.root / 'delay-stop-dnsmasq').touch()
        result = self.call('prepare-agent')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'stop-polls-dnsmasq').read_text().strip(), '2')
        self.assertFalse((self.root / 'running-dnsmasq').exists())
        self.assertLess(self.log.read_text().index('dnsmasq stop'), self.log.read_text().index('ifdown wan'))

    def test_failed_server_stop_cannot_change_network_or_attach_uplink(self):
        self.begin(); (self.root / 'fail-stop-dnsmasq').touch()
        self.assertNotEqual(self.call('prepare-agent').returncode, 0)
        self.assertEqual((self.root / 'etc/config/network').read_bytes(), self.original['etc/config/network'])
        self.assertNotIn('ifdown wan', self.log.read_text())

    def test_rollback_disconnects_wan_before_restoring_original_address_and_services(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        (self.root / 'sys/class/net/wan/master').touch()
        (self.root / 'sys/class/net/br-lan/brif/wan').touch()
        self.assertEqual(self.call('rollback').returncode, 0)
        for path, expected in self.original.items(): self.assertEqual((self.root / path).read_bytes(), expected)
        log = self.log.read_text()
        self.assertLess(log.index('wan nomaster'), log.index('network reload'))
        self.assertLess(log.index('wan nomaster'), log.index('dnsmasq start'))
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_detach_or_restore_failure_retains_snapshot_and_allows_retry(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        (self.root / 'sys/class/net/wan/master').touch(); (self.root / 'fail-detach').touch()
        self.assertNotEqual(self.call('rollback').returncode, 0)
        self.assertEqual(json.loads((self.root / 'etc/config/network').read_text())['lan.proto'], 'dhcp')
        self.assertTrue((self.root / 'etc/ax6000-mesh/original-network').exists())
        (self.root / 'fail-detach').unlink(); (self.root / 'fail-copy').touch()
        self.assertNotEqual(self.call('rollback').returncode, 0)
        self.assertEqual(self.call('present').returncode, 0)
        (self.root / 'fail-copy').unlink()
        self.assertEqual(self.call('rollback').returncode, 0)

    def test_sealed_uci_edits_rejected_but_owned_vendor_credentials_are_allowed(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        self.assertEqual(self.call('seal').returncode, 0)
        dat = self.root / 'etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat'
        dat.write_text(dat.read_text().replace('SSID1=original', 'SSID1=enrolled'))
        self.assertEqual(self.call('commit').returncode, 0)
        self.assertEqual(self.call('check').returncode, 0)
        dat.write_text(dat.read_text().replace('CountryCode=GB', 'CountryCode=US'))
        self.assertNotEqual(self.call('check').returncode, 0)
        dat.write_text(dat.read_text().replace('CountryCode=US', 'CountryCode=GB'))
        wireless = self.root / 'etc/config/wireless'; wireless.write_text(wireless.read_text() + 'user edit')
        self.assertNotEqual(self.call('check').returncode, 0)

    def test_pending_boot_restores_before_network_without_starting_services(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        self.log.write_text('')
        self.assertEqual(self.call('recover-boot').returncode, 0)
        self.assertEqual((self.root / 'etc/config/network').read_bytes(), self.original['etc/config/network'])
        self.assertNotIn('network reload', self.log.read_text())
        self.assertNotIn('dnsmasq start', self.log.read_text())
        self.assertNotIn('odhcpd start', self.log.read_text())
        self.assertNotIn('quiesce-radios', self.log.read_text())

    def test_partial_boot_restore_replaces_network_before_original_dhcp(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        (self.root / 'fail-copy-dhcp').touch()
        self.assertNotEqual(self.call('recover-boot').returncode, 0)
        self.assertEqual((self.root / 'etc/config/network').read_bytes(), self.original['etc/config/network'])
        self.assertEqual(json.loads((self.root / 'etc/config/dhcp').read_text())['lan.ignore'], '1')
        self.assertEqual(self.call('present').returncode, 0)
        (self.root / 'fail-copy-dhcp').unlink()
        self.assertEqual(self.call('recover-boot').returncode, 0)

    def test_corrupted_snapshot_cannot_restore_or_claim_present(self):
        self.begin()
        (self.root / 'etc/ax6000-mesh/original-network').write_text('damaged')
        self.assertNotEqual(self.call('present').returncode, 0)
        self.assertNotEqual(self.call('rollback').returncode, 0)
        self.assertEqual(json.loads(self.call('status').stdout)['state'], 'invalid')
        self.assertEqual((self.root / 'etc/config/network').read_bytes(), self.original['etc/config/network'])

    def test_wireless_uplink_must_be_verified_down_before_dhcp_restore(self):
        self.begin(backhaul='wireless'); self.assertEqual(self.call('prepare-agent').returncode, 0)
        apcli = self.root / 'sys/class/net/apcli0'; apcli.mkdir(); (apcli / 'flags').write_text('0x1')
        self.assertNotEqual(self.call('rollback').returncode, 0)
        self.assertEqual(json.loads((self.root / 'etc/config/network').read_text())['lan.proto'], 'dhcp')
        (apcli / 'flags').write_text('0x0')
        self.assertEqual(self.call('rollback').returncode, 0)
        self.assertLess(self.log.read_text().rindex('disconnect disconnect-backhaul'), self.log.read_text().index('network reload'))

    def test_inherited_mesh_lock_is_reused_and_other_owner_is_rejected(self):
        lock = self.root / 'var/lock/ax6000-mesh.lock'
        wrapper = self.root / 'locked'
        wrapper.write_text(f'exec 9>"{lock}"\nflock -n 9 || exit 2\nbusybox ash "{self.helper}" begin agent wired\n')
        result = subprocess.run(['busybox', 'ash', str(wrapper)], env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreater(int((self.root / 'etc/ax6000-mesh/owner-pid').read_text()), 1)
        import fcntl
        with lock.open('w') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertNotEqual(self.call('seal').returncode, 0)

    def test_inherited_mesh_lock_reuses_real_symlinked_var_lock(self):
        # OpenWrt /var/lock resolves into /tmp; /proc/PID/fd exposes its target.
        (self.root / 'var/lock').rmdir()
        target = self.root / 'tmp/lock'; target.mkdir(parents=True)
        (self.root / 'var/lock').symlink_to(target, target_is_directory=True)
        self.test_inherited_mesh_lock_is_reused_and_other_owner_is_rejected()

    def test_killed_snapshot_writer_never_publishes_or_mutates_configuration(self):
        self.write_tool('cp', '#!/bin/sh\nkill -KILL "$PPID"\nexit 1\n')
        self.assertNotEqual(self.call('begin', 'agent', 'wired').returncode, 0)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())
        for path, expected in self.original.items(): self.assertEqual((self.root / path).read_bytes(), expected)

    def test_independent_watchdog_stops_dead_worker_and_restores_expired_pending(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        self.assertEqual((self.root / 'etc/ax6000-mesh/deadline').read_text().strip(), '460')
        (self.root / 'proc/uptime').write_text('461.00 0.00\n')
        (self.root / 'sys/module/mapfilter').mkdir(parents=True)
        (self.root / 'etc/ax6000-mesh/owns-mapfilter').touch()
        libexec = self.root / 'usr/libexec'; libexec.mkdir(parents=True, exist_ok=True)
        target = libexec / 'ax6000-mesh-transaction'
        target.write_text(f'#!/bin/sh\nexec busybox ash "{self.helper}" "$@"\n'); target.chmod(0o755)
        watchdog = self.root / 'watchdog'
        text = (FILES / 'usr/libexec/ax6000-mesh-watchdog').read_text()
        prefixes = ('/etc', '/var', '/usr/libexec', '/proc/uptime', '/proc/sys/kernel/random/boot_id')
        text = re.sub('|'.join(re.escape(p) for p in prefixes), lambda m: str(self.root) + m[0], text)
        watchdog.write_text(text)
        self.log.write_text('')
        result = subprocess.run(['busybox', 'ash', str(watchdog)], env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'etc/config/network').read_bytes(), self.original['etc/config/network'])
        self.assertLess(self.log.read_text().index('ax6000-mesh-operation stop'), self.log.read_text().index('wan nomaster'))
        self.assertNotIn('ax6000-mesh-watchdog stop', self.log.read_text())
        self.assertLess(self.log.read_text().index('wifi up'), self.log.read_text().index('rmmod mapfilter'))
        self.assertFalse((self.root / 'sys/module/mapfilter').exists())

    def test_rollback_cold_quiesces_current_topology_before_replacing_any_files(self):
        profiles = [self.root / f'etc/wireless/mediatek/mt7986-ax6000.dbdc.{band}.dat' for band in ('b0', 'b1')]
        for profile in profiles: profile.write_text(profile.read_text() + 'BssidNum=2\n')
        self.begin(role='controller')
        for profile in profiles: profile.write_text(profile.read_text().replace('BssidNum=2', 'BssidNum=4'))
        self.assertEqual(self.call('seal').returncode, 0)
        self.assertEqual(self.call('commit').returncode, 0)
        (self.root / 'require-topology-transition').touch()
        self.log.write_text('')
        result = self.call('rollback', 'disable')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(self.log.read_text().index('quiesce-radios'), self.log.read_text().index('restore-network'))
        self.assertLess(self.log.read_text().index('restore-network'), self.log.read_text().index('restore-radios'))
        self.assertLess(self.log.read_text().index('restore-radios'), self.log.read_text().index('dnsmasq start'))
        for profile in profiles: self.assertIn('BssidNum=2', profile.read_text())
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_quiesce_failure_preserves_current_dat_and_valid_snapshot_for_retry(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        dat = self.root / 'etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat'
        dat.write_text(dat.read_text() + 'BssidNum=4\n')
        network_before = (self.root / 'etc/config/network').read_bytes()
        dat_before = dat.read_bytes()
        (self.root / 'fail-quiesce-radios').touch()
        result = self.call('rollback', 'failure')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('snapshot retained', result.stderr)
        self.assertEqual(dat.read_bytes(), dat_before)
        self.assertEqual((self.root / 'etc/config/network').read_bytes(), network_before)
        self.assertEqual(self.call('present').returncode, 0)
        self.assertNotIn('restore-radios', self.log.read_text())
        self.assertNotIn('dnsmasq start', self.log.read_text())
        (self.root / 'fail-quiesce-radios').unlink()
        self.assertEqual(self.call('rollback', 'failure').returncode, 0)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_interrupted_committed_disable_is_recovered_on_next_boot(self):
        self.begin(role='controller')
        self.assertEqual(self.call('seal').returncode, 0)
        self.assertEqual(self.call('commit').returncode, 0)
        state = self.root / 'etc/ax6000-mesh'
        immutable_manifest = (state / 'snapshot.sha256').read_bytes()
        (self.root / 'fail-quiesce-radios').touch()
        self.assertNotEqual(self.call('rollback', 'disable').returncode, 0)
        self.assertEqual(json.loads(self.call('status').stdout)['state'], 'pending')
        self.assertEqual((state / 'snapshot.sha256').read_bytes(), immutable_manifest)
        self.assertEqual(self.call('present').returncode, 0)
        self.log.write_text('')
        (self.root / 'proc/sys/kernel/random/boot_id').write_text('reboot-after-interrupted-disable\n')
        self.assertEqual(self.call('recover-boot').returncode, 0)
        for path, data in self.original.items(): self.assertEqual((self.root / path).read_bytes(), data)
        self.assertFalse(state.exists())
        self.assertNotIn('quiesce-radios', self.log.read_text())
        self.assertNotIn('restore-radios', self.log.read_text())

    def test_normal_rollback_unloads_owned_module_after_radio_readiness(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        module = self.root / 'sys/module/mapfilter'; module.mkdir(parents=True)
        (self.root / 'etc/ax6000-mesh/owns-mapfilter').touch()
        self.assertEqual(self.call('rollback', 'disable').returncode, 0)
        self.assertFalse(module.exists())
        self.assertLess(self.log.read_text().index('wifi up'), self.log.read_text().index('rmmod mapfilter'))

    def test_normal_rollback_preserves_preexisting_unowned_module(self):
        module = self.root / 'sys/module/mapfilter'; module.mkdir(parents=True)
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        self.assertEqual(self.call('rollback', 'disable').returncode, 0)
        self.assertTrue(module.exists())
        self.assertNotIn('rmmod mapfilter', self.log.read_text())

    def test_normal_radio_restore_failure_retains_snapshot_for_retry(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        (self.root / 'fail-restore-radios').touch()
        result = self.call('rollback', 'failure')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('snapshot retained', result.stderr)
        self.assertEqual(self.call('present').returncode, 0)
        self.assertNotIn('dnsmasq start', self.log.read_text())
        (self.root / 'fail-restore-radios').unlink()
        self.assertEqual(self.call('rollback', 'failure').returncode, 0)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())
        self.assertLess(self.log.read_text().index('wifi up'), self.log.read_text().index('dnsmasq start'))

    def test_timeout_radio_restore_failure_retains_snapshot_for_retry(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        (self.root / 'fail-restore-radios').touch()
        result = self.call('expire')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('snapshot retained', result.stderr)
        self.assertEqual(self.call('present').returncode, 0)
        self.assertEqual(json.loads(self.call('status').stdout)['state'], 'pending')
        self.assertNotIn('dnsmasq start', self.log.read_text())
        (self.root / 'fail-restore-radios').unlink()
        self.assertEqual(self.call('expire').returncode, 0)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())

    def test_timeout_does_not_report_success_when_service_restore_fails(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        (self.root / 'fail-start-dnsmasq').touch()
        result = self.call('rollback', 'timeout')
        self.assertNotEqual(result.returncode, 0)
        error = self.root / 'var/run/ax6000-mesh-error'
        self.assertFalse(error.exists() and 'original settings restored' in error.read_text())
        self.assertTrue((self.root / 'etc/ax6000-mesh/original-network').exists())

    def test_committed_boot_recovery_never_rolls_back(self):
        self.begin(); self.assertEqual(self.call('prepare-agent').returncode, 0)
        self.assertEqual(self.call('seal').returncode, 0); self.assertEqual(self.call('commit').returncode, 0)
        self.assertEqual(self.call('recover-boot').returncode, 0)
        self.assertEqual(json.loads((self.root / 'etc/config/network').read_text())['lan.proto'], 'dhcp')
        self.assertEqual(json.loads(self.call('status').stdout)['state'], 'committed')


@unittest.skipUnless(shutil.which('busybox'), 'BusyBox ash required')
class MeshRecoveryInit(unittest.TestCase):
    def invoke(self, name, action, phase='pending'):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'lib/functions').mkdir(parents=True)
            (root / 'lib/functions.sh').write_text('list_contains() { case "$2" in start|boot) return 0 ;; *) return 1 ;; esac; }\n')
            (root / 'lib/functions/service.sh').write_text('')
            (root / 'lib/functions/procd.sh').write_text('''
procd_open_service() { :; }
procd_open_instance() { printf 'INSTANCE=%s\\n' "$1"; }
procd_set_param() { printf 'PARAM'; printf ' <%s>' "$@"; printf '\\n'; }
procd_close_instance() { :; }
procd_close_service() { printf 'DISPATCH=%s\\n' "$1"; }
''')
            status = root / 'phase'; status.write_text(phase + '\n')
            transaction = root / 'transaction'
            transaction.write_text('#!/bin/sh\ncase "$1" in present) exit 0 ;; *) echo "TRANSACTION=$1" ;; esac\n')
            transaction.chmod(0o755)
            original = FILES / 'etc/init.d' / name
            text = original.read_text().replace('/usr/libexec/ax6000-mesh-transaction', str(transaction))
            text = text.replace('/etc/ax6000-mesh/phase', str(status))
            script = root / name; script.write_text(text)
            rc = ROOT / 'tests/fixtures/mesh-runtime/rc.common'
            result = subprocess.run(['busybox', 'ash', str(rc), str(script), action],
                                    env={**os.environ, 'IPKG_INSTROOT': str(root)},
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.splitlines()

    def test_early_recovery_runs_before_network_without_procd_dispatch(self):
        text = (FILES / 'etc/init.d/ax6000-mesh-recovery').read_text()
        self.assertIn('START=18', text)
        self.assertEqual(self.invoke('ax6000-mesh-recovery', 'boot'), ['TRANSACTION=recover-boot'])

    def test_watchdog_keeps_real_rc_common_set_method(self):
        self.assertEqual(self.invoke('ax6000-mesh-watchdog', 'start'), [
            'INSTANCE=enrollment', 'PARAM <command> </usr/libexec/ax6000-mesh-watchdog>',
            'PARAM <term_timeout> <5>', 'PARAM <respawn> <3600> <5> <3>', 'DISPATCH=set'])

    def test_committed_watchdog_start_does_not_launch_process(self):
        self.assertEqual(self.invoke('ax6000-mesh-watchdog', 'start', 'committed'), ['DISPATCH=set'])

if __name__ == '__main__': unittest.main()
