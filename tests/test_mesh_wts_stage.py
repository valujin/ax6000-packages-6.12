"""Dense WTS staging preserves holes without publishing or exposing credentials."""
import json
import os
from pathlib import Path
import subprocess
import unittest
import test_mesh_slot_allocation as slots
LIB = slots.LIB


class DenseWTS(unittest.TestCase):
    bss = slots.StableSlots.bss
    allocate = slots.StableSlots.allocate
    def setUp(self):
        slots.StableSlots.setUp(self)
        source = (LIB / 'ax6000-mesh-stage-wts').read_text()
        source = source.replace('/usr/share/libubox/jshn.sh', str(self.tmpdir / 'jshn.sh'))
        source = source.replace('/usr/share/ax6000-mesh/vendor.sh', str(self.tmpdir / 'vendor.sh'))
        source = source.replace('/usr/libexec/ax6000-mesh-allocate-slots', str(self.tmpdir / 'ax6000-mesh-allocate-slots'))
        from test_mesh_slot_allocation import NATIVE
        (self.tmpdir / 'jshn.sh').write_text((NATIVE / 'share/libubox/jshn.sh').read_text())
        (self.tmpdir / 'vendor.sh').write_text((LIB.parent / 'share/ax6000-mesh/vendor.sh').read_text())
        self.writer = self.tmpdir / 'writer'; self.writer.write_text(source)
        self.policy['bsses'].append(self.bss('main5', 'lan', '5g'))
        self.creds = dict(schema=1, backhaul_ssid='PrivateBH', backhaul_key='private-bh-secret',
                          backhaul_security='sae', quarantine_key='private-quarantine-secret',
                          keys=[dict(id=b['id'], key='private-user-secret') for b in self.policy['bsses']])

    def stage(self, state=None, qvid=4090, success=True, public=False):
        policy = self.tmpdir / 'input-policy'; policy.write_text(json.dumps(self.policy))
        ledger = self.tmpdir / 'input-ledger'; ledger.write_text(json.dumps(state or dict(schema=1, slots=[])))
        creds = self.tmpdir / 'input-credentials'; creds.write_text(json.dumps(self.creds)); creds.chmod(0o644 if public else 0o600)
        output = self.tmpdir / 'candidate'; output.unlink(missing_ok=True)
        result = subprocess.run(['busybox', 'ash', str(self.writer), str(policy), str(ledger), str(creds), str(qvid), str(output)],
                                capture_output=True, text=True, env=self.env, timeout=10)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('private-', result.stderr)
        if success:
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            return output.read_text().splitlines()[1:]
        self.assertFalse(output.exists())

    def test_dense_hole_before_retained_slot_three(self):
        first = self.allocate()
        self.policy['bsses'][1] = self.bss('new')
        self.creds['keys'][1]['id'] = 'new'
        rows = self.stage(first['state'])
        self.assertEqual(len(rows), 12)
        self.assertIn(' main ', rows[0]); self.assertIn('1 pvid 0', rows[0])
        self.assertIn(' PrivateBH 0x0040 ', rows[1])
        self.assertIn('AX6000-quarantine-2g-2', rows[2]); self.assertIn('4090 N/A N/A', rows[2])
        self.assertIn(' new ', rows[3])
        self.assertEqual([r.split(' ', 2)[2] for r in rows[4:8]], [r.split(' ', 2)[2] for r in rows[8:12]])

    def test_conflict_and_unisolated_guest_rejected(self):
        self.stage(qvid=1, success=False)
        self.stage(qvid=10, success=False)
        self.policy['bsses'][1]['isolate'] = False
        self.stage(success=False)

    def test_quarantine_namespace_cannot_alias_real_bss(self):
        self.creds['backhaul_ssid'] = 'AX6000-quarantine-2g-2'
        self.stage(success=False)
        self.creds['backhaul_ssid'] = 'PrivateBH'
        self.policy['bsses'][1]['ssid'] = 'AX6000-quarantine-2g-3'
        self.stage(success=False)

    def test_private_file_complete_credentials_and_capacity_required(self):
        self.stage(public=True, success=False)
        self.creds['keys'].pop()
        self.stage(success=False)
        self.creds['keys'].append(dict(id='main5', key='private-user-secret'))
        self.policy['capacity24'] = 3
        self.stage(success=False)

    def test_secret_json_is_read_by_filename_not_external_argv(self):
        trace = self.tmpdir / 'argv-trace'
        shim = self.tmpdir / 'jshn'
        shim.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$ARG_TRACE"\nexec "$REAL_JSHN" "$@"\n')
        shim.chmod(0o700)
        self.env.update(PATH=str(self.tmpdir) + ':' + self.env['PATH'],
                        ARG_TRACE=str(trace), REAL_JSHN=str(slots.NATIVE / 'bin/jshn'))
        self.stage()
        self.assertNotIn('private-', trace.read_text())
        self.assertIn('-R', trace.read_text())

    def test_shell_syntax_in_credentials_remains_data(self):
        self.policy['bsses'][1]['ssid'] = 'Guest $(touch /tmp/UNUSED)'
        self.creds['keys'][1]['key'] = 'secret;$(not-a-command)'
        rows = self.stage()
        self.assertIn('Guest\\ $(touch\\ /tmp/UNUSED)', rows[2])
        self.assertIn('secret;$(not-a-command)', rows[2])
