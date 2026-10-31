"""Exercise the isolated, side-effect-free network policy planner."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PLANNER = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-plan-networks'
NATIVE = ROOT.parent / 'local-native-mesh-20261027/work/build/source/staging_dir/host'


class NetworkPlanner(unittest.TestCase):
    def setUp(self):
        jshn = NATIVE / 'share/libubox/jshn.sh'
        if not jshn.exists():
            self.skipTest('OpenWrt jshn host tools are unavailable')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.planner = Path(self.tmp.name) / 'planner'
        self.assertTrue(PLANNER.exists(), 'network planner missing')
        self.planner.write_text(PLANNER.read_text().replace('/usr/share/libubox/jshn.sh', str(jshn)))
        self.env = {**os.environ, 'PATH': str(NATIVE / 'bin') + ':' + os.environ['PATH'], 'LD_LIBRARY_PATH': str(NATIVE / 'lib')}
        self.base = {'schema': 1, 'primary_network': 'lan', 'primary_vid': 1, 'primary_pcp': 0,
                     'capacity24': 4, 'capacity5': 4, 'bsses': [
                         {'id': 'main24', 'ssid': 'Home', 'network': 'lan', 'vid': 1, 'band': '2g', 'security': 'sae-mixed', 'isolate': False, 'hidden': False},
                         {'id': 'guest24', 'ssid': 'Guest', 'network': 'guest', 'vid': 10, 'band': '2g', 'security': 'psk2', 'isolate': True, 'hidden': False},
                         {'id': 'main5', 'ssid': 'Home', 'network': 'lan', 'vid': 1, 'band': '5g', 'security': 'sae-mixed', 'isolate': False, 'hidden': False},
                         {'id': 'guest5', 'ssid': 'Guest', 'network': 'guest', 'vid': 10, 'band': '5g', 'security': 'psk2', 'isolate': True, 'hidden': False}]}

    def run_plan(self, obj):
        result = subprocess.run(['busybox', 'ash', str(self.planner)], input=json.dumps(obj), text=True,
                                capture_output=True, env=self.env, cwd=self.tmp.name, timeout=5)
        return result, json.loads(result.stdout)

    def test_deterministic_slots_reserve_backhaul_and_keep_guest_vid(self):
        result, plan = self.run_plan(self.base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(plan['ok'])
        self.assertEqual([(b['id'], b['slot'], b['ifname'], b['vid']) for b in plan['bsses']],
                         [('main24', 0, 'ra0', 1), ('guest24', 2, 'ra2', 10),
                          ('main5', 0, 'rax0', 1), ('guest5', 2, 'rax2', 10)])
        self.assertEqual(self.run_plan(self.base)[1], plan)

    def test_same_network_can_have_several_ssids(self):
        self.base['bsses'].append({'id': 'family24', 'ssid': 'Family', 'network': 'lan', 'vid': 1, 'band': '2g', 'security': 'psk2', 'isolate': False, 'hidden': False})
        result, plan = self.run_plan(self.base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(plan['bsses'][-1]['slot'], 3)

    def test_rejects_ambiguous_or_unsafe_policy(self):
        cases = []
        def case(edit):
            d = json.loads(json.dumps(self.base)); edit(d); cases.append(d)
        case(lambda d: d['bsses'][1].update(vid=1))
        case(lambda d: d['bsses'][1].update(network='lan'))
        case(lambda d: d['bsses'][1].update(ssid='Home'))
        case(lambda d: d['bsses'][3].update(network='lan', vid=1))
        case(lambda d: d['bsses'][3].update(security='sae-mixed'))
        case(lambda d: d['bsses'][3].update(isolate=False))
        case(lambda d: d['bsses'][1].update(vid=4095))
        case(lambda d: d.update(primary_vid=0))
        case(lambda d: d.update(primary_pcp=8))
        case(lambda d: d.update(capacity24=2))
        case(lambda d: d['bsses'][1].update(id='main24'))
        case(lambda d: d['bsses'][1].update(ssid='bad\nssid'))
        case(lambda d: d['bsses'][1].update(security='enterprise'))
        case(lambda d: d['bsses'][1].update(key='secret'))
        for obj in cases:
            with self.subTest(obj=obj):
                result, plan = self.run_plan(obj)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(plan['ok'])
                self.assertNotIn('secret', result.stdout + result.stderr)

    def test_nul_is_rejected_before_jshn_truncation(self):
        for field in ('ssid', 'network'):
            policy = json.loads(json.dumps(self.base))
            policy['bsses'][1][field] += '\0untrusted'
            result, data = self.run_plan(policy)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(data['ok'])
        payload = json.dumps(self.base).replace('Guest', 'Guest\x00untrusted', 1)
        result = subprocess.run(['busybox', 'ash', str(self.planner)], input=payload, text=True,
                                capture_output=True, env=self.env, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)['ok'])

    def test_ssid_punctuation_is_data_not_shell_code(self):
        target = Path(self.tmp.name) / 'x'
        self.base['bsses'][1]['ssid'] = '$(touch x); \"!'
        result, data = self.run_plan(self.base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(data['bsses'][1]['ssid'], self.base['bsses'][1]['ssid'])
        self.assertFalse(target.exists())

    def test_malformed_json_and_empty_array_return_safe_errors(self):
        for payload in ('{bad', '[]'):
            with self.subTest(payload=payload):
                result = subprocess.run(['busybox', 'ash', str(self.planner)], input=payload, text=True,
                                        capture_output=True, env=self.env, cwd=self.tmp.name, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(json.loads(result.stdout)['ok'])
                self.assertEqual(result.stderr, '')

    def test_primary_network_mapping_is_required(self):
        self.base['bsses'][0]['vid'] = 12
        result, data = self.run_plan(self.base)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(data['ok'])
