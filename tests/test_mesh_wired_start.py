import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-wired'


class WiredOnboarding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for d in ('sys/class/net/wan', 'sys/class/net/br-lan/brif/wan', 'etc/ax6000-mesh', 'usr/libexec', 'bin'):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        (self.root / 'sys/class/net/wan/carrier').write_text('1\n')
        (self.root / 'sys/class/net/wan/address').write_text('02:11:22:33:44:55\n')
        (self.root / 'etc/ax6000-mesh/phase').write_text('pending\n')
        (self.root / 'etc/ax6000-mesh/role').write_text('agent\n')
        (self.root / 'etc/ax6000-mesh/backhaul').write_text('wired\n')
        self.tool('uci', '''#!/bin/sh
case "$*" in *main.enabled) echo 1;; *main.role) echo agent;; *main.backhaul) echo wired;; esac
''')
        self.tool('wappctrl', '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_LOG"\nexit "${TEST_WAPP_EXIT:-0}"\n')
        self.tool('jsonfilter', '#!/bin/sh\ncat >/dev/null\necho "${TEST_CONNECTED:-false}"\n')
        for name, code in {'ax6000-mesh-health': 'exit "${TEST_HEALTH_EXIT:-0}"',
                           'ax6000-mesh-vendor': 'echo "{\\"connected\\":false}"',
                           'ax6000-mesh-transaction': 'exit "${TEST_TX_EXIT:-0}"'}.items():
            p = self.root / 'usr/libexec' / name
            p.write_text('#!/bin/sh\n' + code + '\n'); p.chmod(0o755)
        source = SCRIPT.read_text().replace('/sys/class/net', str(self.root / 'sys/class/net')).replace('/etc/ax6000-mesh', str(self.root / 'etc/ax6000-mesh')).replace('/usr/libexec/ax6000-mesh-', str(self.root / 'usr/libexec/ax6000-mesh-'))
        self.script = self.root / 'wired'; self.script.write_text(source); self.script.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.root / 'bin') + ':' + os.environ['PATH'], 'TEST_LOG': str(self.root / 'commands')}

    def tearDown(self): self.tmp.cleanup()

    def tool(self, name, content):
        p = self.root / 'bin' / name; p.write_text(content); p.chmod(0o755)

    def run_trigger(self, **env):
        return subprocess.run(['sh', str(self.script), 'trigger'], env={**self.env, **env}, capture_output=True, text=True, timeout=10)

    def test_ready_agent_triggers_on_exact_wan_interface(self):
        r = self.run_trigger(); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.root / 'commands').read_text().splitlines(), ['ra0 map set_bh_type eth wan'])

    def test_no_trigger_without_carrier_bridge_or_valid_unicast_mac(self):
        for path, value in [('sys/class/net/wan/carrier', '0\n'), ('sys/class/net/wan/address', '00:00:00:00:00:00\n'), ('sys/class/net/wan/address', '01:00:00:00:00:01\n')]:
            p = self.root / path; old = p.read_text(); p.write_text(value)
            self.assertNotEqual(self.run_trigger().returncode, 0)
            self.assertFalse((self.root / 'commands').exists()); p.write_text(old)
        (self.root / 'sys/class/net/br-lan/brif/wan').rmdir()
        self.assertNotEqual(self.run_trigger().returncode, 0)
        self.assertFalse((self.root / 'commands').exists())

    def test_no_reset_when_already_joined(self):
        self.assertEqual(self.run_trigger(TEST_CONNECTED='true').returncode, 0)
        self.assertFalse((self.root / 'commands').exists())

    def test_health_transaction_role_and_failure_are_enforced(self):
        for env in ({'TEST_HEALTH_EXIT': '1'}, {'TEST_TX_EXIT': '1'}):
            self.assertNotEqual(self.run_trigger(**env).returncode, 0)
            self.assertFalse((self.root / 'commands').exists())
        (self.root / 'etc/ax6000-mesh/backhaul').write_text('wireless\n')
        self.assertNotEqual(self.run_trigger().returncode, 0)
        (self.root / 'etc/ax6000-mesh/backhaul').write_text('wired\n')
        self.assertNotEqual(self.run_trigger(TEST_WAPP_EXIT='1').returncode, 0)

    def test_monitor_sends_once_per_daemon_and_carrier_generation(self):
        proc = self.root / 'proc/42'; proc.mkdir(parents=True)
        (proc / 'stat').write_text('42 (daemon) ' + ' '.join(['1'] * 30) + '\n')
        self.script.write_text(self.script.read_text().replace('/proc/$pid/stat', str(self.root / 'proc/$pid/stat')))
        self.tool('pidof', '#!/bin/sh\necho 42\n')
        self.tool('uci', '''#!/bin/sh
case "$*" in *main.enabled) [ ! -f "$TEST_STOP" ] && echo 1;; *main.role) echo agent;; *main.backhaul) echo wired;; esac
''')
        self.tool('sleep', '''#!/bin/sh
n=0; [ ! -f "$TEST_COUNT" ] || n=$(cat "$TEST_COUNT")
n=$((n+1)); echo "$n" > "$TEST_COUNT"
[ "$n" -lt 4 ] || touch "$TEST_STOP"
''')
        env = {**self.env, 'TEST_STOP': str(self.root / 'stop'), 'TEST_COUNT': str(self.root / 'count')}
        r = subprocess.run(['sh', str(self.script), 'monitor'], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.root / 'commands').read_text().splitlines(), ['ra0 map set_bh_type eth wan'])

    def test_monitor_retries_once_after_real_link_reconnect(self):
        proc = self.root / 'proc/42'; proc.mkdir(parents=True)
        (proc / 'stat').write_text('42 (daemon) ' + ' '.join(['1'] * 30) + '\n')
        self.script.write_text(self.script.read_text().replace('/proc/$pid/stat', str(self.root / 'proc/$pid/stat')))
        self.tool('pidof', '#!/bin/sh\necho 42\n')
        self.tool('uci', '''#!/bin/sh
case "$*" in *main.enabled) [ ! -f "$TEST_STOP" ] && echo 1;; *main.role) echo agent;; *main.backhaul) echo wired;; esac
''')
        self.tool('sleep', '''#!/bin/sh
n=0; [ ! -f "$TEST_COUNT" ] || n=$(cat "$TEST_COUNT")
n=$((n+1)); echo "$n" > "$TEST_COUNT"
case "$n" in 1) echo 0 > "$TEST_CARRIER";; 2) echo 1 > "$TEST_CARRIER";; 4) touch "$TEST_STOP";; esac
''')
        env = {**self.env, 'TEST_STOP': str(self.root / 'stop'), 'TEST_COUNT': str(self.root / 'count'), 'TEST_CARRIER': str(self.root / 'sys/class/net/wan/carrier')}
        r = subprocess.run(['sh', str(self.script), 'monitor'], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.root / 'commands').read_text().splitlines(), ['ra0 map set_bh_type eth wan'] * 2)
