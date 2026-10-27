"""Run the daemon wait wrapper against actual Linux UNIX sockets."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files'
WRAPPER = FILES / 'usr/libexec/ax6000-mesh-wait'


@unittest.skipUnless(Path('/proc/net/unix').exists(), 'Linux UNIX socket table required')
class MeshDaemonWait(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mesh-wait-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.name = 'ax6000-mesh-' + uuid.uuid4().hex
        # Keep absent-socket checks bounded without replacing socket detection.
        tools = self.root / 'bin'
        tools.mkdir()
        sleeper = tools / 'sleep'
        sleeper.write_text('#!/bin/sh\nexec /bin/sleep 0.01\n')
        sleeper.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(tools) + ':' + os.environ['PATH']}

    def bind(self, name):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(server.close)
        server.bind(name)
        return server

    def run_wait(self, name):
        marker = self.root / 'launched'
        result = subprocess.run(
            ['/bin/sh', str(WRAPPER), name, '/bin/sh', '-c',
             'printf "%s\\n" "$1" > "$2"', 'wait-target', 'argument with spaces', str(marker)],
            env=self.env, capture_output=True, text=True, timeout=5)
        return result, marker

    def test_abstract_datagram_socket_launches_target_with_arguments(self):
        self.bind('\0' + self.name)
        result, marker = self.run_wait('@' + self.name)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(marker.read_text(), 'argument with spaces\n')

    def test_abstract_prefix_collision_does_not_launch_target(self):
        self.bind('\0' + self.name + '-other')
        result, marker = self.run_wait('@' + self.name)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def test_missing_abstract_socket_does_not_launch_target(self):
        result, marker = self.run_wait('@' + self.name)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def test_connected_abstract_endpoint_does_not_satisfy_ready_state(self):
        endpoint = self.bind('\0' + self.name)
        self.bind('\0' + self.name + '-peer')
        endpoint.connect('\0' + self.name + '-peer')
        result, marker = self.run_wait('@' + self.name)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def test_filesystem_datagram_socket_launches_target(self):
        path = str(self.root / 'daemon.sock')
        self.bind(path)
        result, marker = self.run_wait(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(marker.exists())

    def test_regular_file_does_not_satisfy_filesystem_socket_wait(self):
        path = self.root / 'daemon.sock'
        path.touch()
        result, marker = self.run_wait(str(path))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def test_init_waits_for_mapd_abstract_daemon_endpoint(self):
        init = (FILES / 'etc/init.d/ax6000-mesh').read_text()
        self.assertIn('ax6000-mesh-wait @1905_daemon /usr/bin/mapd', init)


if __name__ == '__main__':
    unittest.main()
