"""Exercise radio callback -> actual rc.common/init -> real committed ownership check."""
import os
from pathlib import Path
import re
import subprocess
import unittest
import test_mesh_restart as restart
import test_mesh_runtime as runtime


class RadioReadyLock(unittest.TestCase):
    set_config = runtime.RuntimeLifecycle.set_config
    config = runtime.RuntimeLifecycle.config
    run_control = runtime.RuntimeLifecycle.run_control
    write_tool = runtime.RuntimeLifecycle.write_tool
    apply = restart.CommittedPrepare.apply
    check_seal = restart.CommittedPrepare.check_seal

    def setUp(self):
        restart.CommittedPrepare.setUp(self)
        self.apply('controller', 'wired')
        files = runtime.ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files'
        library = self.root / 'lib/functions'
        library.mkdir(parents=True)
        (self.root / 'lib/functions.sh').write_text('list_contains() { [ "$2" = restart ]; }\n')
        (library / 'service.sh').write_text('')
        # procd transport only: actual init and rc.common keep all their control
        # flow. Record both FD inheritance and the parent's continued exclusion.
        (library / 'procd.sh').write_text('''procd_lock() { :; }
procd_open_service() { :; }
procd_close_service() { :; }
procd_kill() { echo STOP >> "$TEST_ROOT/service-events"; }
procd_open_instance() {
  if [ -e /proc/$$/fd/9 ]; then echo FD9_LEAK >> "$TEST_ROOT/service-events"; fi
  if flock -n "$TEST_ROOT/var/lock/ax6000-mesh.lock" -c true; then echo PARENT_LOCK_LOST >> "$TEST_ROOT/service-events"; fi
  echo "INSTANCE=$1" >> "$TEST_ROOT/service-events"
}
procd_set_param() { :; }
procd_close_instance() { :; }
procd_add_reload_trigger() { :; }
''')
        init_source = (files / 'etc/init.d/ax6000-mesh').read_text()
        init_source = re.sub(r'/(?:etc|usr/libexec)/', lambda m: str(self.root) + m[0], init_source)
        actual_init = self.root / 'actual-init'
        actual_init.write_text(init_source)
        wrapper = self.root / 'etc/init.d/ax6000-mesh'
        rc = runtime.ROOT / 'tests/fixtures/mesh-runtime/rc.common'
        wrapper.write_text('#!/bin/sh\nexec busybox ash "' + str(rc) + '" "' + str(actual_init) + '" "$@"\n')
        wrapper.chmod(0o755)
        hairpin = self.root / 'usr/libexec/ax6000-mesh-hairpin'
        hairpin.write_text('#!/bin/sh\nexit 0\n'); hairpin.chmod(0o755)
        source = (files / 'usr/libexec/ax6000-mesh-radio-ready').read_text()
        source = re.sub(r'/(?:etc|var|usr/libexec)/', lambda m: str(self.root) + m[0], source)
        self.callback = self.root / 'radio-ready'; self.callback.write_text(source)
        self.env['IPKG_INSTROOT'] = str(self.root)
        self.events = self.root / 'service-events'

    def invoke(self):
        return subprocess.run(['sh', str(self.callback)], env=self.env, capture_output=True, text=True, timeout=15)

    def test_committed_callback_restarts_without_reopening_parent_lock_or_leaking_it(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text()
        self.assertIn('STOP\n', events)
        self.assertIn('INSTANCE=wapp\n', events)
        self.assertIn('INSTANCE=p1905\n', events)
        self.assertIn('INSTANCE=mapd\n', events)
        self.assertNotIn('FD9_LEAK', events)
        self.assertNotIn('PARENT_LOCK_LOST', events)
        self.check_seal()
        result = subprocess.run(['flock', '-n', str(self.root / 'var/lock/ax6000-mesh.lock'), '-c', 'true'])
        self.assertEqual(result.returncode, 0)

    def test_competing_mesh_operation_leaves_service_untouched(self):
        import fcntl
        with (self.root / 'var/lock/ax6000-mesh.lock').open('w') as owner:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.events.exists())

    def test_unowned_1905_edit_still_prevents_any_daemon_start(self):
        path = self.root / 'etc/map/1905d.cfg'
        changed = path.read_text() + 'unowned=value\n'; path.write_text(changed)
        self.invoke()
        self.assertFalse(self.events.exists(), 'An invalid edit must not stop the running native service')
        self.assertEqual(path.read_text(), changed)
