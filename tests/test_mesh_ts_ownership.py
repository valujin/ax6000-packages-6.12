import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_mesh_slot_allocation import LIB, NATIVE


class Ownership(unittest.TestCase):
    def setUp(self):
        if not (NATIVE / 'share/libubox/jshn.sh').exists():
            self.skipTest('OpenWrt jshn unavailable')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.proc = self.base / 'proc'; self.net = self.base / 'net'
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        self.boot = '11111111-2222-3333-4444-555555555555'
        (self.proc / 'sys/kernel/random/boot_id').write_text(self.boot)
        for pid, name, start in ((105, 'mapd', 1000), (106, 'p1905_managerd', 2000)):
            d = self.proc / str(pid); d.mkdir(); (d / 'comm').write_text(name)
            (d / 'stat').write_text(f'{pid} ({name}) S ' + '0 ' * 18 + str(start))
        (self.net / 'br-lan/bridge').mkdir(parents=True)
        for name in ('lan2', 'ra0', 'rax0', 'ra1', 'rax1', 'ra2'):
            (self.net / name).mkdir()
            if name != 'ra2':
                (self.net / 'br-lan/brif' / name).mkdir(parents=True)
        (self.net / 'ra2/address').write_text('02:00:00:00:00:22')
        shim = self.base / 'pidof'; shim.write_text('#!/bin/sh\necho 106\n'); shim.chmod(0o700)
        source = (LIB / 'ax6000-mesh-ts-own').read_text()
        source = source.replace('/usr/share/libubox/jshn.sh', str(NATIVE / 'share/libubox/jshn.sh'))
        source = source.replace('pidof p1905_managerd', str(shim) + ' p1905_managerd')
        source = source.replace('/proc/', str(self.proc) + '/').replace('/sys/class/net/', str(self.net) + '/')
        source = source.replace('[ "$(id -u)" = 0 ]', f'[ "$(id -u)" = {os.getuid()} ]')
        source = source.replace('[ "$(stat -c %u "$1")" = 0 ]', f'[ "$(stat -c %u "$1")" = {os.getuid()} ]')
        self.script = self.base / 'own'; self.script.write_text(source)
        self.env = {**os.environ, 'PATH': str(self.base) + ':' + str(NATIVE / 'bin') + ':' + os.environ['PATH'], 'LD_LIBRARY_PATH': str(NATIVE / 'lib')}
        self.declaration = dict(schema=2, bridge='br-lan', management_vid=1, quarantine_vid=4090, controller_alid='02:00:00:00:00:01',
                                cpu_guest_links=[], management_ifnames=['lan2', 'ra0', 'rax0', 'ra1', 'rax1'], trunk_ifnames=['ra1', 'rax1'],
                                guest_ports=[dict(ifname='ra2', actual_bssid='02:00:00:00:00:22', vid=10, enabled=False)])
        self.observation = dict(schema=2, boot_id=self.boot, producer_pid=105, producer_start_ticks=1000,
                                connection_generation=3, sequence=4, primary_vid=1, controller_alid='02:00:00:00:00:01',
                                fh=[dict(bssid='02:00:00:00:00:22', vid=10)])

    def run_own(self, success=True):
        declaration = self.base / 'declaration'; observation = self.base / 'observation'; output = self.base / 'ownership'
        output.unlink(missing_ok=True)
        for path, data in ((declaration, self.declaration), (observation, self.observation)):
            path.write_text(json.dumps(data)); path.chmod(0o600)
        r = subprocess.run(['busybox', 'ash', str(self.script), str(declaration), str(observation), str(output)], env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(r.returncode == 0, success, r.stderr)
        self.assertEqual(r.stdout, '')
        if success:
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            return json.loads(output.read_text())
        self.assertFalse(output.exists())

    def test_binds_explicit_authority_lifecycle_and_nonce(self):
        result = self.run_own()
        self.assertEqual(result['daemons'], dict(mapd=dict(pid=105, starttime=1000), ieee1905=dict(pid=106, starttime=2000)))
        self.assertEqual(result['observation'], dict(connection_generation=3, sequence=4))
        self.assertEqual(result['boot_id'], self.boot)
        self.assertRegex(result['generation'], '^[0-9a-f]{32}$')
        self.assertFalse(result['guest_ports'][0]['enabled'])
        self.assertNotEqual(self.run_own()['generation'], result['generation'])

    def test_wrong_controller_process_or_boot_fails(self):
        for field, value in [('controller_alid', '02:00:00:00:00:ff'), ('producer_start_ticks', 999), ('boot_id', 'old')]:
            before = self.observation[field]; self.observation[field] = value
            self.run_own(False); self.observation[field] = before

    def test_bssid_vid_and_management_aliases_fail(self):
        guest = self.declaration['guest_ports'][0]
        for field, value in [('actual_bssid', '02:00:00:00:00:23'), ('vid', 1), ('vid', 11), ('ifname', 'ra0'), ('enabled', True)]:
            before = guest[field]; guest[field] = value
            self.run_own(False); guest[field] = before

    def test_access_lan_is_not_implicitly_a_trunk(self):
        self.declaration['trunk_ifnames'] = ['lan2']
        self.run_own(False)

    def test_duplicate_guest_and_observation_rejected(self):
        self.declaration['guest_ports'] *= 2
        self.run_own(False)
        self.declaration['guest_ports'] = self.declaration['guest_ports'][:1]
        self.observation['fh'] *= 2
        self.run_own(False)
