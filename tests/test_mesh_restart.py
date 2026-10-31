"""Restart preparation must preserve the sealed, daemon-selected 1905 identity."""
import subprocess
import unittest
import test_mesh_runtime as runtime


class CommittedPrepare(unittest.TestCase):
    set_config = runtime.RuntimeLifecycle.set_config
    config = runtime.RuntimeLifecycle.config
    run_control = runtime.RuntimeLifecycle.run_control
    write_tool = runtime.RuntimeLifecycle.write_tool

    def setUp(self):
        runtime.RuntimeLifecycle.setUp(self)
        fixture = runtime.ROOT / 'tests/fixtures/mesh-runtime/1905d-sdk35234223.cfg'
        (self.root / 'usr/share/ax6000-mesh/vendor/1905d.cfg').write_bytes(fixture.read_bytes())
        init = self.root / 'etc/init.d/ax6000-mesh'
        init.write_text('''#!/bin/sh
case "$1" in
 start)
  "$TEST_ROOT/usr/libexec/ax6000-mesh-control" prepare || exit 1
  sed -i -E 's/^(map_controller_alid|map_agent_alid)=.*/\\1=02:00:00:00:00:02/' "$TEST_ROOT/etc/map/1905d.cfg"
  touch "$TEST_STARTED" ;;
 stop) rm -f "$TEST_STARTED" ;;
esac
''')
        init.chmod(0o755)

    def apply(self, role, backhaul):
        self.set_config('ax6000_mesh', **{'main.role': role, 'main.backhaul': backhaul})
        result = self.run_control('apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.check_seal()

    def check_seal(self):
        result = subprocess.run(['busybox', 'ash', str(self.helper), 'check'], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def restart(self, role, backhaul):
        self.apply(role, backhaul)
        cfg = self.root / 'etc/map/1905d.cfg'
        enrolled = cfg.read_bytes()
        self.assertIn(b'map_controller_alid=02:00:00:00:00:02\n', enrolled)
        expected = (self.root / 'etc/ax6000-mesh/expected').read_bytes()
        result = self.run_control('prepare')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(cfg.read_bytes(), enrolled)
        self.assertEqual((self.root / 'etc/ax6000-mesh/expected').read_bytes(), expected)
        self.check_seal()
        result = self.run_control('disable')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_controller_identity_survives_committed_restart_and_disable(self):
        self.restart('controller', 'wired')

    def test_wired_agent_identity_survives_committed_restart_and_disable(self):
        self.restart('agent', 'wired')

    def test_wireless_agent_identity_survives_committed_restart_and_disable(self):
        self.restart('agent', 'wireless')

    def test_user_1905_edit_rejected_before_prepare_mutates_any_vendor_file(self):
        self.apply('controller', 'wired')
        cfg = self.root / 'etc/map/1905d.cfg'
        cfg.write_text(cfg.read_text() + 'unowned_setting=changed\n')
        before = {p: p.read_bytes() for p in (self.root / 'etc').rglob('*') if p.is_file()}
        commands = self.log.read_bytes()
        result = self.run_control('prepare')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log.read_bytes(), commands)
        self.assertEqual({p: p.read_bytes() for p in (self.root / 'etc').rglob('*') if p.is_file()}, before)

    def test_missing_committed_1905_file_is_not_silently_regenerated(self):
        self.apply('controller', 'wired')
        cfg = self.root / 'etc/map/1905d.cfg'
        cfg.unlink()
        result = self.run_control('prepare')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(cfg.exists())
