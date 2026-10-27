"""Execute the pinned netifd handler scheduler's driver-specific timeout."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_firmware_patches import firmware

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'package/network/config/wifi-scripts/files/lib/netifd/wireless-device.uc'


class MtwifiSetupTimeout(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.directory = ROOT / 'patches/firmware-6.12/recommended'
        manifest = json.loads((self.directory / 'manifest.json').read_text())
        self.spec = next(p for p in manifest['patches'] if p['path'] == TARGET)
        self.target = self.source / TARGET
        self.target.parent.mkdir(parents=True)
        self.before = gzip.decompress((ROOT / 'tests/fixtures/mtwifi-wireless-device-ae65e1d.uc.gz').read_bytes())
        self.assertEqual(hashlib.sha256(self.before).hexdigest(), self.spec['before_sha256'])
        self.target.write_bytes(self.before)
        firmware.apply_source_patch(self.source, self.spec, self.directory / self.spec['patch'])

    def test_exact_patch_is_idempotent_and_rejects_drift(self):
        after = self.target.read_bytes()
        self.assertEqual(hashlib.sha256(after).hexdigest(), self.spec['after_sha256'])
        firmware.apply_source_patch(self.source, self.spec, self.directory / self.spec['patch'], check_only=True)
        firmware.apply_source_patch(self.source, self.spec, self.directory / self.spec['patch'])
        self.assertEqual(self.target.read_bytes(), after)
        self.target.write_bytes(after + b'// unexpected change\n')
        with self.assertRaises(ValueError):
            firmware.apply_source_patch(self.source, self.spec, self.directory / self.spec['patch'])

    def test_only_mtwifi_setup_receives_extended_timeout(self):
        ucode = os.environ.get('UCODE') or shutil.which('ucode')
        if not ucode:
            self.skipTest('Set UCODE to execute the actual scheduler function')
        source = self.target.read_text()
        scheduler = source.split('function __run_next_handler()\n', 1)[1].split('\nfunction run_next_handler()', 1)[0]
        scheduler = 'function __run_next_handler()\n' + scheduler
        for driver, operation, expected in [('mtwifi', 'setup', 120000), ('mtwifi', 'teardown', 30000),
                                             ('mac80211', 'setup', 30000), ('other', 'setup', 30000)]:
            with self.subTest(driver=driver, operation=operation):
                program = '''
const DEFAULT_SCRIPT_TIMEOUT = 30000;
let timer_ms, callback_ran = false, launched = false;
let wdev_cur, wdev_script_task, wdev_script_timeout;
let device = {data: {config: {type: DRIVER}}, name: 'radio0', script: 'driver',
              handler_config: {}, handler_data: {}, dbg: () => {}};
let wdev_handler = {radio0: {wdev: device, op: OPERATION, cb: () => {}}};
function __run_next_handler_name() { return 'radio0'; }
function run_handler_cb(wdev, cb) { die('unexpected process failure'); }
function run_handler_timeout(wdev, cb) { callback_ran = true; }
let netifd = {wireless: {path: '/lib/netifd/wireless'},
              process: opts => { launched = true; return {}; }};
let uloop = {timer: (ms, cb) => { timer_ms = ms; cb(); return {}; }};
'''.replace('DRIVER', json.dumps(driver)).replace('OPERATION', json.dumps(operation))
                program += scheduler + '\n__run_next_handler();\nprintf("%J", {timer_ms, callback_ran, launched});'
                result = subprocess.run([ucode, '-e', program], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {'timer_ms': expected, 'callback_ran': True, 'launched': True})


if __name__ == '__main__':
    unittest.main()
