"""Stable slot allocation must not renumber or recycle unacknowledged BSS ports."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec'
NATIVE = Path(os.environ.get('MESH_TEST_NATIVE', ROOT.parent / 'local-native-mesh-20261027/work/build/source/staging_dir/host'))


class StableSlots(unittest.TestCase):
    def setUp(self):
        jshn = NATIVE / 'share/libubox/jshn.sh'
        if not jshn.exists():
            self.skipTest('OpenWrt host jshn unavailable')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmpdir = Path(self.tmp.name)
        for name in ('ax6000-mesh-plan-networks', 'ax6000-mesh-allocate-slots'):
            source = (LIB / name).read_text().replace('/usr/share/libubox/jshn.sh', str(jshn))
            source = source.replace('#!/bin/sh', '#!/usr/bin/busybox ash', 1)
            source = source.replace('/usr/libexec/ax6000-mesh-plan-networks', str(self.tmpdir / 'ax6000-mesh-plan-networks'))
            path = self.tmpdir / name
            path.write_text(source)
            path.chmod(0o700)
        self.env = {**os.environ, 'PATH': str(NATIVE / 'bin') + ':' + os.environ['PATH'], 'LD_LIBRARY_PATH': str(NATIVE / 'lib')}
        self.policy = dict(schema=1, primary_network='lan', primary_vid=1, primary_pcp=0,
                           capacity24=4, capacity5=4, bsses=[self.bss('main', 'lan'), self.bss('guest')])

    def bss(self, name, network='guest', band='2g'):
        return dict(id=name, ssid=name, network=network, vid=1 if network == 'lan' else 10,
                    band=band, security='psk2', isolate=network != 'lan', hidden=False)

    def allocate(self, state=None, success=True):
        policy = self.tmpdir / 'policy'
        previous = self.tmpdir / 'state'
        policy.write_text(json.dumps(self.policy))
        previous.write_text(json.dumps(state or dict(schema=1, slots=[])))
        before = (policy.read_bytes(), previous.read_bytes())
        result = subprocess.run(['busybox', 'ash', str(self.tmpdir / 'ax6000-mesh-allocate-slots'), str(policy), str(previous)],
                                text=True, capture_output=True, env=self.env, timeout=10)
        self.assertEqual(result.returncode == 0, success, result.stderr + result.stdout)
        self.assertEqual(before, (policy.read_bytes(), previous.read_bytes()))
        self.assertEqual(result.stderr, '')
        return json.loads(result.stdout)

    def test_reorder_keeps_primary_and_guest_slots(self):
        self.policy['bsses'].reverse()
        first = self.allocate()
        self.assertEqual({b['id']: b['slot'] for b in first['bsses']}, {'guest': 2, 'main': 0})
        self.policy['bsses'].reverse()
        second = self.allocate(first['state'])
        self.assertEqual({b['id']: b['slot'] for b in second['bsses']}, {'guest': 2, 'main': 0})

    def test_delete_tombstone_readd_and_exhaustion(self):
        first = self.allocate()
        self.policy['bsses'] = [self.bss('main', 'lan'), self.bss('new')]
        second = self.allocate(first['state'])
        self.assertEqual(second['bsses'][1]['slot'], 3)
        self.assertFalse(next(s for s in second['state']['slots'] if s['id'] == 'guest')['active'])
        self.policy['bsses'][1] = self.bss('another')
        self.allocate(second['state'], success=False)
        self.policy['bsses'][1] = self.bss('guest')
        readded = self.allocate(second['state'])
        self.assertEqual(readded['bsses'][1]['slot'], 2)

    def test_no_primary_or_replacing_primary_identity_rejected(self):
        first = self.allocate()
        self.policy['bsses'] = [self.bss('guest')]
        self.allocate(success=False)
        self.policy['bsses'].insert(0, self.bss('replacement', 'lan'))
        self.allocate(first['state'], success=False)

    def test_corrupt_reserved_and_duplicate_state_rejected(self):
        first = self.allocate()['state']
        cases = []
        for slot in (1, 4, -1, '2', True):
            state = copy.deepcopy(first); state['slots'][1]['slot'] = slot; cases.append(state)
        state = copy.deepcopy(first); state['slots'].append(copy.deepcopy(state['slots'][1])); cases.append(state)
        state = copy.deepcopy(first); state['slots'][1]['unexpected'] = 'secret'; cases.append(state)
        for state in cases:
            with self.subTest(state=state):
                self.allocate(state, success=False)

    def test_capacity_reduction_cannot_hide_tombstone(self):
        first = self.allocate()
        self.policy['capacity24'] = 2
        self.policy['bsses'] = [self.bss('main', 'lan')]
        self.allocate(first['state'], success=False)

    def test_capacity_above_verified_pool_rejected(self):
        self.policy['capacity24'] = 16
        self.allocate(success=False)

    def test_output_never_claims_activation(self):
        data = self.allocate()
        self.assertEqual(data['phase'], 'proposed')
        self.assertNotIn('applied', data)
        self.assertNotIn('ready', data)
