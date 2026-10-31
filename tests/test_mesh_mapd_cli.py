"""Exercise complete pinned mapd_cli stdout over its real Unix datagram transport.

The opaque vendor library's unrelated command entrypoints abort if dispatched.
GET uses the unmodified open/request/close transport extracted from its supplied
source, not a replacement CLI script or a mocked request function.
"""
import hashlib
import os
from pathlib import Path
import re
import socket
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT / 'files/mediatek-mesh/packages/mapd/patches'


class MapdCliOutput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive = os.environ.get('MAPD_SOURCE_ARCHIVE')
        if not archive:
            raise unittest.SkipTest('set MAPD_SOURCE_ARCHIVE for actual native CLI tests')
        if hashlib.sha256(Path(archive).read_bytes()).hexdigest() != '39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18':
            raise AssertionError('unexpected pinned mapd archive')
        cls.temporary = tempfile.TemporaryDirectory(prefix='mesh-cli-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        with tarfile.open(archive) as vendor:
            vendor.extractall(cls.directory, filter='data')
        source = cls.directory / 'mapd'
        for patch in sorted(PATCHES.glob('*.patch')):
            result = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, capture_output=True, text=True)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
        cli = source / 'mapd_ctrl/mapd_cli.c'
        # The remainder implements unused vendor commands and is not the library
        # object shipped by this SDK. Keep the complete actual transport prefix.
        transport = (source / 'mapd_interface/mapd_interface_ctrl.c').read_text().split('int mapd_interface_ctrl_pending')[0]
        (source / 'transport-test.c').write_text(transport)
        references = set(re.findall(r'\b(mapd_interface_\w+)\s*\(', cli.read_text()))
        references -= {'mapd_interface_ctrl_open', 'mapd_interface_ctrl_close', 'mapd_interface_ctrl_request'}
        stubs = '#include <stdlib.h>\n' + '\n'.join('int %s(void) { abort(); }' % name for name in sorted(references))
        stubs += '\nvoid *os_zalloc(size_t size) { (void)size; abort(); }\n'
        (source / 'unused-vendor-test.c').write_text(stubs)
        includes = [source, source / 'src', source / 'mapd_interface', source / '1905_local_lib']
        includes.extend(path for path in (source / 'src').iterdir() if path.is_dir())
        cls.binary = cls.directory / 'mapd_cli'
        command = ['cc', '-O2', '-fcommon', '-D_GNU_SOURCE', '-DCONFIG_SUPPORT_OPENWRT', '-DSUPPORT_MULTI_AP', '-DMAP_MLO_UPLINK', '-DMAP_R2', '-DMAP_R3', '-DMAP_6E_SUPPORT',
                   '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections']
        command += ['-D' + flag for flag in ('DFS_CAC_R2 MAP_RADIO_TEARDOWN ACL_CTRL SINGLE_BAND_SUPPORT MAP_R3_RECONFIG MAP_R3_DPP_CONFIG MAP_R3_SP MAP_R3_WF6 MAP_R3_DE MAP_R4_SPT DFS_SLAVE_SUPPORT RELEASE_EXCLUDE CONFIG_CLIENT_DB CONFIG_CLIENT_DB_FILE CENT_STR CORE_DUMP_ENABLED CONFIG_DEBUG_SYSLOG').split()]
        command += ['-I' + str(path) for path in includes]
        command += [str(cli), str(source / 'transport-test.c'), str(source / 'unused-vendor-test.c'),
                    str(source / 'src/utils/common.c'), str(source / 'src/utils/os_unix.c'), '-o', str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def request(self, parameter, reply, event=None):
        path = str(self.directory / 'socket')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
            server.bind(path)
            server.settimeout(3)
            child = subprocess.Popen([str(self.binary), path, 'get', parameter], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                request, peer = server.recvfrom(65536)
                self.assertEqual(request, ('GET ' + parameter).encode())
                if event:
                    server.sendto(event, peer)
                server.sendto(reply, peer)
                stdout, stderr = child.communicate(timeout=3)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate()
                Path(path).unlink(missing_ok=True)
        self.assertEqual(child.returncode, 0, stderr)
        return stdout, stderr

    def test_security_reply_is_exact_without_startup_banners(self):
        for reply in (b'sae=1\n', b'sae=0\n'):
            with self.subTest(reply=reply):
                stdout, _ = self.request('bh_security', reply)
                self.assertEqual(stdout, reply)

    def test_clients_json_is_exact_and_not_truncated_at_old_cli_limit(self):
        reply = b'{"test":"' + b'x' * 10000 + b'"}\n'
        stdout, _ = self.request('mesh_clients', reply)
        self.assertEqual(stdout, reply)

    def test_unsolicited_event_does_not_contaminate_machine_reply(self):
        stdout, stderr = self.request('bh_security', b'sae=1\n', b'<3>test event')
        self.assertEqual(stdout, b'sae=1\n')
        self.assertIn(b'<3>test event', stderr)

    def test_connection_failure_has_nonzero_status_and_no_protocol_reply(self):
        result = subprocess.run([str(self.binary), str(self.directory / 'absent'), 'get', 'bh_security'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertTrue(result.stderr)
