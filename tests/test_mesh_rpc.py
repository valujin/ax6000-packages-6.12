"""Run the actual rpcd shell script with native jshn and isolated backend tools."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
RPC = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/rpcd/ax6000.mesh'
NATIVE = Path(os.environ.get('MESH_TEST_NATIVE', ROOT.parent / 'local-native-mesh-20261027/work/build/source/staging_dir/host'))


@unittest.skipUnless((NATIVE / 'bin/jshn').exists(), 'native jshn required')
class MeshRPC(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mesh-rpc-')
        self.root = Path(self.tmp.name)
        self.log = self.root / 'args.json'
        backend = self.root / 'control'
        backend.write_text('#!/usr/bin/python3\nimport json,os,sys\njson.dump(sys.argv[1:],open(os.environ["MESH_RPC_ARGS"],"w"))\n')
        backend.chmod(0o755)
        uci = self.root / 'uci'
        uci.write_text('#!/bin/sh\ncase "$3" in\n *linux_ts) echo "${MESH_LINUX_TS:-0}" ;;\n *backhaul_security) [ -z "$MESH_SECURITY" ] || echo "$MESH_SECURITY" ;;\n *backhaul_band) [ -z "$MESH_BAND" ] || echo "$MESH_BAND" ;;\n *role) echo "${MESH_ROLE:-controller}" ;;\n *backhaul) echo "${MESH_BACKHAUL:-wired}" ;;\n *enabled) echo "${MESH_ENABLED:-0}" ;;\n *) exit 1 ;;\nesac\n')
        uci.chmod(0o755)
        board = self.root / 'board'
        board.write_text('xiaomi,mi-router-ax3000t\n')
        profile = self.root / 'l1profile'
        profile.write_text('INDEX0=MT7981\nINDEX0_profile_path=/etc/wireless/mediatek/mt7981.dbdc.b0.dat;/etc/wireless/mediatek/mt7981.dbdc.b1.dat\n')
        hardware = self.root / 'hardware'
        hardware.write_text((RPC.parent.parent / 'ax6000-mesh-hardware').read_text().replace('/tmp/sysinfo/board_name', str(board)).replace('/etc/wireless/l1profile.dat', str(profile)))
        hardware.chmod(0o755)
        script = RPC.read_text().replace('/usr/share/libubox/jshn.sh', str(NATIVE / 'share/libubox/jshn.sh'))
        script = script.replace('/usr/libexec/ax6000-mesh-control', str(backend))
        script = script.replace('/usr/libexec/ax6000-mesh-hardware', str(hardware))
        script = script.replace('/var/run/ax6000-mesh-operation', str(self.root / 'operation'))
        health = self.root / 'health'; health.write_text('#!/bin/sh\n[ "$MESH_RUNNING" = 1 ]\n'); health.chmod(0o755)
        vendor = self.root / 'vendor'; vendor.write_text("#!/bin/sh\necho '{\"ok\":true,\"connected\":true,\"pairing_remaining\":0}'\n"); vendor.chmod(0o755)
        security = self.root / 'security'; security.write_text('#!/bin/sh\nprintf "%s" "$MESH_SAE_REPLY"\n'); security.chmod(0o755)
        script = script.replace('/usr/libexec/ax6000-mesh-health', str(health))
        script = script.replace('/usr/libexec/ax6000-mesh-vendor', str(vendor))
        script = script.replace('/usr/libexec/ax6000-mesh-security', str(security))
        script = script.replace('/tmp/sysinfo/board_name', str(self.root / 'no-board'))
        script = script.replace('/etc/ax6000-mesh/phase', str(self.root / 'phase'))
        script = script.replace('/var/run/ax6000-mesh-managed-status.json', str(self.root / 'managed-status.json'))
        script = script.replace('/var/run/ax6000-mesh-radio-error', str(self.root / 'radio-error'))
        script = script.replace('/var/run/ax6000-mesh-error', str(self.root / 'general-error'))
        script = script.replace('/etc/ax6000-mesh-last-error', str(self.root / 'last-error'))
        self.script = self.root / 'rpc'; self.script.write_text(script)
        self.env = {**os.environ, 'PATH': str(self.root) + ':' + str(NATIVE / 'bin') + ':' + os.environ['PATH'],
                    'LD_LIBRARY_PATH': str(NATIVE / 'lib'), 'MESH_RPC_ARGS': str(self.log)}

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, method, payload=None):
        result = subprocess.run(['bash', str(self.script), 'call', method], input=json.dumps(payload or {}),
                                env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_optional_fields_and_legacy_argv(self):
        for extra, expected in [({}, []), ({'backhaul_security': 'sae'}, ['sae']),
                                ({'backhaul_security': 'psk2', 'backhaul_band': '2g'}, ['psk2', '2g']),
                                ({'backhaul_band': '5g'}, ['psk2', '5g'])]:
            self.assertTrue(self.call('configure', {'role': 'agent', 'backhaul': 'wireless', **extra})['ok'])
            self.assertEqual(json.loads(self.log.read_text()), ['configure', 'agent', 'wireless', *expected])
        self.env['MESH_SECURITY'] = 'sae'
        self.assertTrue(self.call('configure', {'role': 'agent', 'backhaul': 'wireless', 'backhaul_band': 'auto'})['ok'])
        self.assertEqual(json.loads(self.log.read_text())[-2:], ['sae', 'auto'])

    def test_types_enums_and_unknown_fields_rejected_before_backend(self):
        for extra in [{'backhaul_security': 'sae;reboot'}, {'backhaul_security': None},
                      {'backhaul_security': ['sae']}, {'backhaul_security': 1},
                      {'backhaul_band': '6g'}, {'backhaul_band': ''}, {'backhaul_band': {}},
                      {'backhaul': 'wireless;reboot'}, {'role': 'other'}, {'arbitrary': 'argument'}]:
            payload = {'role': 'agent', 'backhaul': 'wireless', **extra}
            self.assertFalse(self.call('configure', payload)['ok'], extra)
            self.assertFalse(self.log.exists(), extra)

    def test_status_security_defaults_and_saved_policy(self):
        self.assertEqual(self.call('status')['backhaul_security'], 'sae')
        self.env['MESH_ENABLED'] = '1'
        self.assertEqual(self.call('status')['backhaul_security'], 'psk2')
        self.assertEqual(self.call('status')['backhaul_band'], 'auto')
        self.env.update(MESH_SECURITY='sae', MESH_BAND='2g')
        result = self.call('status')
        self.assertEqual((result['backhaul_security'], result['backhaul_band']), ('sae', '2g'))

    def test_wireless_sae_agent_requires_negotiated_security(self):
        self.env.update(MESH_ROLE='agent', MESH_BACKHAUL='wireless', MESH_SECURITY='sae', MESH_ENABLED='1', MESH_RUNNING='1')
        (self.root / 'operation').mkdir()
        (self.root / 'operation/phase').write_text('connected')
        result = self.call('status')
        self.assertFalse(result['backhaul_security_verified'])
        self.assertFalse(result['enrollment']['connected'])
        self.assertNotEqual(result['phase'], 'connected')
        self.env['MESH_SAE_REPLY'] = 'sae=1'
        result = self.call('status')
        self.assertTrue(result['backhaul_security_verified'])
        self.assertTrue(result['enrollment']['connected'])
        self.assertEqual(result['phase'], 'connected')
        self.env['MESH_SECURITY'] = 'psk2'; self.env['MESH_SAE_REPLY'] = ''
        self.assertTrue(self.call('status')['enrollment']['connected'], 'legacy policy unchanged')

    def test_managed_status_is_bounded_allowlisted_and_never_exposes_private_fields(self):
        self.env.update(MESH_ENABLED='1', MESH_RUNNING='1', MESH_LINUX_TS='1')
        (self.root/'phase').write_text('committed')
        path=self.root/'managed-status.json'
        self.assertEqual(self.call('status')['managed_sync_phase'],'unknown')
        for phase in ('unsupported','pending','error','managed'):
            path.write_text(json.dumps({'schema':1,'phase':phase,'reason':'PRIVATE_REASON','ssid':'PRIVATE_SSID','key':'PRIVATE_KEY'}))
            result=self.call('status')
            self.assertEqual(result['managed_sync_phase'],phase)
            self.assertNotIn('PRIVATE_',json.dumps(result))
        for data in ('broken',json.dumps({'schema':2,'phase':'managed'}),json.dumps({'schema':'1','phase':'managed'}),
                     json.dumps({'schema':1,'phase':['managed']}),json.dumps({'schema':1,'phase':'applied'}),
                     json.dumps({'schema':1,'phase':'managed','padding':'x'*2048})):
            path.write_text(data)
            self.assertEqual(self.call('status')['managed_sync_phase'],'unknown',data[:80])
        path.unlink(); private=self.root/'private.json';private.write_text('{"schema":1,"phase":"managed"}')
        path.symlink_to(private)
        self.assertEqual(self.call('status')['managed_sync_phase'],'unknown')

    def test_managed_status_cannot_reuse_inactive_or_pending_enrollment(self):
        path=self.root/'managed-status.json';path.write_text('{"schema":1,"phase":"managed"}')
        (self.root/'phase').write_text('committed')
        self.env.update(MESH_ENABLED='1',MESH_RUNNING='1',MESH_LINUX_TS='1')
        self.assertEqual(self.call('status')['managed_sync_phase'],'managed')
        for key in ('MESH_ENABLED','MESH_RUNNING','MESH_LINUX_TS'):
            self.env[key]='0'
            self.assertEqual(self.call('status')['managed_sync_phase'],'unknown')
            self.env[key]='1'
        (self.root/'phase').write_text('pending')
        self.assertEqual(self.call('status')['managed_sync_phase'],'unknown')

    def test_radio_error_is_fixed_enabled_only_and_never_exposes_marker_contents(self):
        path = self.root / 'radio-error'
        self.env['MESH_ENABLED'] = '1'
        self.assertNotIn('error', self.call('status'))
        for content in ('PRIVATE_SSID PRIVATE_KEY PRIVATE_DAEMON_ERROR', ''):
            path.write_text(content)
            result = self.call('status')
            self.assertEqual(result.get('error'),
                'Mesh could not validate the wireless change. Restore the previous wireless settings or check Mesh recovery before retrying.')
            self.assertNotIn('PRIVATE_', json.dumps(result))
        self.env['MESH_ENABLED'] = '0'
        self.assertNotIn('error', self.call('status'))
        self.env['MESH_ENABLED'] = '1'
        path.unlink(); path.mkdir()
        self.assertNotIn('error', self.call('status'), 'directory markers are not accepted')
        path.rmdir(); private = self.root / 'private'; private.write_text('PRIVATE_KEY')
        path.symlink_to(private)
        self.assertNotIn('error', self.call('status'), 'symlink markers are not accepted')
        path.unlink(); path.symlink_to(self.root / 'missing')
        self.assertNotIn('error', self.call('status'), 'dangling symlinks are not accepted')

    def test_general_errors_keep_precedence_over_radio_callback_marker(self):
        self.env['MESH_ENABLED'] = '1'
        (self.root / 'radio-error').write_text('PRIVATE_RADIO_DETAIL')
        (self.root / 'last-error').write_text('Existing recovery error.')
        self.assertEqual(self.call('status')['error'], 'Existing recovery error.')
        (self.root / 'general-error').write_text('Current operation error.')
        self.assertEqual(self.call('status')['error'], 'Current operation error.')

    def test_clients_rpc_has_outer_deadline(self):
        helper = self.root / 'slow-clients'
        helper.write_text('#!/bin/sh\nexec sleep 10\n')
        helper.chmod(0o755)
        self.script.write_text(self.script.read_text().replace('/usr/libexec/ax6000-mesh-clients', str(helper)))
        started = time.monotonic()
        result = self.call('clients')
        self.assertFalse(result['ok'])
        self.assertEqual(result['clients'], [])
        self.assertLess(time.monotonic() - started, 7, 'RPC must bound the whole helper, including ubus calls')
