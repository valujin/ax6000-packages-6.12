import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-hairpin'


class BackhaulHairpin(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name in ('sys/class/net/br-lan/brif/ra1', 'sys/class/net/br-lan/brif/rax1', 'bin'):
            (self.root / name).mkdir(parents=True)
        for name in ('ra1', 'rax1'):
            (self.root / f'sys/class/net/br-lan/brif/{name}/hairpin_mode').write_text('1\n')
        uci = self.root / 'bin/uci'
        uci.write_text('''#!/bin/sh
case "$*" in
 *ax6000_mesh_ap1.device) echo d1;; *ax6000_mesh_ap2.device) echo d2;;
 *d1.band) echo 2g;; *d2.band) echo 5g;;
 *ax6000_mesh_ap*.mode) echo ap;; *ax6000_mesh_ap*.network) echo lan;;
 *ax6000_mesh_ap*.map_bss_type) echo 64;;
esac
'''); uci.chmod(0o755)
        bridge = self.root / 'bin/bridge'
        bridge.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$TEST_LOG"
[ "${TEST_BRIDGE_FAIL:-0}" = 0 ] || exit 1
[ "$1 $2 $3" = 'link set dev' ] && [ "$5 $6" = 'hairpin off' ] || exit 1
printf '0\\n' > "$TEST_ROOT/sys/class/net/br-lan/brif/$4/hairpin_mode"
'''); bridge.chmod(0o755)
        source = SCRIPT.read_text().replace('/sys/class/net', str(self.root / 'sys/class/net'))
        self.script = self.root / 'hairpin'; self.script.write_text(source); self.script.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.root / 'bin') + ':' + os.environ['PATH'], 'TEST_ROOT': str(self.root), 'TEST_LOG': str(self.root / 'commands')}

    def tearDown(self): self.tmp.cleanup()

    def run_once(self, **env):
        return subprocess.run(['sh', str(self.script), 'apply'], env={**self.env, **env}, capture_output=True, text=True, timeout=10)

    def test_only_hidden_backhaul_interfaces_are_changed(self):
        result = self.run_once(); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'commands').read_text().splitlines(), ['link set dev ra1 hairpin off', 'link set dev rax1 hairpin off'])
        self.assertEqual(self.run_once().returncode, 0)
        self.assertEqual(len((self.root / 'commands').read_text().splitlines()), 2)

    def test_missing_bridge_interface_fails_before_any_change(self):
        (self.root / 'sys/class/net/br-lan/brif/rax1/hairpin_mode').unlink()
        result = self.run_once(); self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'commands').exists())

    def test_command_failure_is_reported(self):
        result = self.run_once(TEST_BRIDGE_FAIL='1'); self.assertNotEqual(result.returncode, 0)

    def test_wrong_wireless_role_rejected(self):
        uci = self.root / 'bin/uci'; uci.write_text(uci.read_text().replace('echo 64', 'echo 32'))
        self.assertNotEqual(self.run_once().returncode, 0)
        self.assertFalse((self.root / 'commands').exists())

    def test_monitor_reapplies_after_bridge_reattach(self):
        for name in ('ra1', 'rax1'):
            (self.root / f'sys/class/net/br-lan/brif/{name}/hairpin_mode').write_text('0\n')
        uci = self.root / 'bin/uci'
        uci.write_text(uci.read_text().replace('case "$*" in', 'case "$*" in\n *ax6000_mesh.main.enabled) [ ! -f "$TEST_STOP" ] && echo 1;;'))
        sleep = self.root / 'bin/sleep'
        sleep.write_text('''#!/bin/sh
n=0; [ ! -f "$TEST_COUNT" ] || n=$(cat "$TEST_COUNT")
n=$((n+1)); echo "$n" > "$TEST_COUNT"
case "$n" in 1) echo 1 > "$TEST_ROOT/sys/class/net/br-lan/brif/rax1/hairpin_mode";; 3) touch "$TEST_STOP";; esac
'''); sleep.chmod(0o755)
        env = {**self.env, 'TEST_STOP': str(self.root / 'stop'), 'TEST_COUNT': str(self.root / 'count')}
        result = subprocess.run(['sh', str(self.script), 'monitor'], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'commands').read_text().splitlines(), ['link set dev rax1 hairpin off'])

    def test_monitor_survives_one_port_temporarily_missing(self):
        other = self.root / 'sys/class/net/br-lan/brif/rax1'
        (other / 'hairpin_mode').unlink(); other.rmdir()
        uci = self.root / 'bin/uci'
        uci.write_text(uci.read_text().replace('case "$*" in', 'case "$*" in\n *ax6000_mesh.main.enabled) [ ! -f "$TEST_STOP" ] && echo 1;;'))
        sleep = self.root / 'bin/sleep'
        sleep.write_text('''#!/bin/sh
n=0; [ ! -f "$TEST_COUNT" ] || n=$(cat "$TEST_COUNT")
n=$((n+1)); echo "$n" > "$TEST_COUNT"
case "$n" in 1) mkdir -p "$TEST_ROOT/sys/class/net/br-lan/brif/rax1"; echo 1 > "$TEST_ROOT/sys/class/net/br-lan/brif/rax1/hairpin_mode";; 3) touch "$TEST_STOP";; esac
'''); sleep.chmod(0o755)
        env = {**self.env, 'TEST_STOP': str(self.root / 'stop'), 'TEST_COUNT': str(self.root / 'count')}
        result = subprocess.run(['sh', str(self.script), 'monitor'], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'commands').read_text().splitlines(), ['link set dev ra1 hairpin off', 'link set dev rax1 hairpin off'])
