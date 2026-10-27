"""Run the operation init script through pinned rc.common under BusyBox ash."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INIT = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/etc/init.d/ax6000-mesh-operation'
RC = ROOT / 'tests/fixtures/mesh-runtime/rc.common'


@unittest.skipUnless(shutil.which('busybox'), 'BusyBox ash is required for rc.common scope regression')
class MeshOperationInit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # package/base-files/files/etc/rc.common at native source ae65e1de6997.
        assert hashlib.sha256(RC.read_bytes()).hexdigest() == 'dd8ae95c78d10cccf78cb487874f163ace4c1ee14dace05fe28393b19ba639e4'

    def invoke(self, state):
        with tempfile.TemporaryDirectory(prefix='mesh-operation-init-') as temporary:
            root = Path(temporary)
            helpers = root / 'lib/functions'
            helpers.mkdir(parents=True)
            (root / 'lib/functions.sh').write_text('list_contains() { [ "$2" = start ]; }\n')
            (helpers / 'service.sh').write_text('')
            # Keep the actual rc.common dispatch/scoping; replace only the
            # device transport so no service or router programs can execute.
            (helpers / 'procd.sh').write_text('''
procd_open_service() { :; }
procd_open_instance() { printf 'INSTANCE=%s\\n' "$1"; }
procd_set_param() { printf 'PARAM'; printf ' <%s>' "$@"; printf '\\n'; }
procd_close_instance() { :; }
procd_close_service() { printf 'DISPATCH=%s\\n' "$1"; }
''')
            status = root / 'state'
            status.write_text(state + '\n')
            script = root / 'operation'
            script.write_text(INIT.read_text().replace('/var/run/ax6000-mesh-operation/state', str(status)))
            result = subprocess.run([shutil.which('busybox'), 'ash', str(RC), str(script), 'start'],
                                    env={**os.environ, 'IPKG_INSTROOT': str(root)},
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout.splitlines()

    def test_apply_preserves_rc_common_service_set_dispatch(self):
        self.assertEqual(self.invoke('applying'), ['INSTANCE=job',
                         'PARAM <command> </usr/libexec/ax6000-mesh-job> <apply>', 'DISPATCH=set'])

    def test_disable_preserves_rc_common_service_set_dispatch(self):
        self.assertEqual(self.invoke('disabling'), ['INSTANCE=job',
                         'PARAM <command> </usr/libexec/ax6000-mesh-job> <disable>', 'DISPATCH=set'])

    def test_malformed_state_never_launches_worker_or_becomes_service_method(self):
        self.assertEqual(self.invoke('unexpected'), ['DISPATCH=set'])


if __name__ == '__main__':
    unittest.main()
