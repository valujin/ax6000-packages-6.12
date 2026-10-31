"""Managed generation adoption and accepted user rollback overlays."""
import json
import os
import unittest
import test_mesh_transaction as fixture
from test_mesh_slot_allocation import NATIVE

class ManagedTransaction(unittest.TestCase):
    write_tool=fixture.MeshTransaction.write_tool
    call=fixture.MeshTransaction.call
    begin=fixture.MeshTransaction.begin
    def setUp(self):
        fixture.MeshTransaction.setUp(self)
        self.helper.write_text(self.helper.read_text().replace('[ "$(stat -c %u "$source")" = 0 ]','[ "$(stat -c %u "$source")" = '+str(os.getuid())+' ]'))
        self.state=self.root/'etc/ax6000-mesh'
        validate=self.root/'usr/libexec/ax6000-mesh-agent-sync'
        validate.write_text('#!/bin/sh\n[ "$1" = validate-current ] && [ ! -f "$TEST_ROOT/fail-generation" ]\n'); validate.chmod(0o700)
    def committed(self,role):
        self.begin(role=role)
        p=self.root/'etc/config/ax6000_mesh'; data=json.loads(p.read_text()); data.update({'main.role':role,'main.enabled':'1','main.linux_ts':'1'}); p.write_text(json.dumps(data))
        for op in ['seal','commit']:
            result=self.call(op); self.assertEqual(result.returncode,0,result.stderr)
    def overlay(self):
        source=self.state/'ts-generations'/'generation'/'materialized'/'user-wireless'
        source.parent.mkdir(parents=True); source.write_text(json.dumps({'ap.ssid':'accepted-user','ap.key':'private-accepted'})); source.chmod(0o600)
        return source
    def test_controller_accepted_overlay_restores_latest_users_and_keeps_original_snapshot(self):
        self.committed('controller'); source=self.overlay()
        for name in ['network','dhcp']:
            p=self.root/'etc/config'/name; data=json.loads(p.read_text()); data['accepted']='new'; p.write_text(json.dumps(data))
        result=self.call('adopt-controller-sync',str(source)); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.state/'original-wireless').read_bytes(),self.original['etc/config/wireless'])
        overlay=self.state/(self.state/'accepted-user-path').read_text().strip()
        expected={name:(overlay/name).read_bytes() for name in ['network','dhcp','wireless']}
        result=self.call('rollback'); self.assertEqual(result.returncode,0,result.stderr)
        for name,value in expected.items(): self.assertEqual((self.root/'etc/config'/name).read_bytes(),value)
    def test_damaged_user_overlay_retains_snapshot(self):
        self.committed('controller'); source=self.overlay()
        result=self.call('adopt-controller-sync',str(source)); self.assertEqual(result.returncode,0,result.stderr)
        overlay=self.state/(self.state/'accepted-user-path').read_text().strip(); (overlay/'wireless').write_text('tampered')
        self.assertNotEqual(self.call('rollback').returncode,0); self.assertTrue((self.state/'snapshot.sha256').exists())
    def test_controller_unrelated_vendor_change_is_not_adopted(self):
        self.committed('controller'); source=self.overlay(); before=(self.state/'expected').read_bytes()
        (self.root/'etc/wapp_ap_ra0.conf').write_text('unrelated change')
        self.assertNotEqual(self.call('adopt-controller-sync',str(source)).returncode,0)
        self.assertEqual((self.state/'expected').read_bytes(),before); self.assertFalse((self.state/'accepted-user-path').exists())
    def test_agent_generation_gate_and_network_exclusion(self):
        self.committed('agent'); before=(self.state/'expected').read_bytes()
        p=self.root/'etc/config/wireless'; data=json.loads(p.read_text()); data['slot.count']='4'; p.write_text(json.dumps(data))
        (self.root/'fail-generation').touch(); self.assertNotEqual(self.call('adopt-agent-slots').returncode,0); self.assertEqual((self.state/'expected').read_bytes(),before)
        (self.root/'fail-generation').unlink(); result=self.call('adopt-agent-slots'); self.assertEqual(result.returncode,0,result.stderr)
        accepted=(self.state/'expected').read_bytes(); self.assertNotEqual(accepted,before)
        p=self.root/'etc/config/network'; data=json.loads(p.read_text()); data['lan.proto']='static-edited'; p.write_text(json.dumps(data))
        self.assertNotEqual(self.call('adopt-agent-slots').returncode,0); self.assertEqual((self.state/'expected').read_bytes(),accepted)

    def dat_fixture(self,manifest=None,enabled=True):
        if manifest is not None and not (NATIVE/'bin/jshn').exists(): self.skipTest('native jshn required')
        self.helper.write_text(self.helper.read_text().replace('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh')).replace('[ "$(stat -c %u "$manifest")" = 0 ]','[ "$(stat -c %u "$manifest")" = '+str(os.getuid())+' ]'))
        self.env.update(PATH=str(NATIVE/'bin')+':'+self.env['PATH'], LD_LIBRARY_PATH=str(NATIVE/'lib'))
        self.begin(role='agent')
        p=self.root/'etc/config/ax6000_mesh'; values=json.loads(p.read_text()); values.update({'main.enabled':'1','main.linux_ts':'1' if enabled else '0','main.role':'agent'}); p.write_text(json.dumps(values))
        if manifest is not None:
            p=self.state/'ts-capabilities.json'; p.write_text(json.dumps(manifest)); p.chmod(0o600)
        dat=self.root/'etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat'
        dat.write_text(dat.read_text()+'SSID3=guest-before\nWPAPSK3=private-before3\nSSID4=guest2-before\nWPAPSK4=private-before4\nSSID5=sealed-five\nWPAPSK5=private-five\n')
        for op in ['seal','commit']:
            result=self.call(op); self.assertEqual(result.returncode,0,result.stderr)
        return dat
    def test_managed_four_slot_wsc_credentials_allowed_but_slot_five_sealed(self):
        dat=self.dat_fixture(dict(schema=1,confirmed=True,capacity24=4,capacity5=4))
        original=dat.read_text(); updated=original.replace('guest-before','wsc-guest').replace('private-before3','private-wsc3').replace('guest2-before','wsc-guest2').replace('private-before4','private-wsc4')
        dat.write_text(updated); result=self.call('check'); self.assertEqual(result.returncode,0,result.stderr)
        dat.write_text(updated.replace('sealed-five','changed-five')); self.assertNotEqual(self.call('check').returncode,0)
        dat.write_text(updated.replace('private-five','changed-key-five')); self.assertNotEqual(self.call('check').returncode,0)
        dat.write_text(updated.replace('CountryCode=GB','CountryCode=US')); self.assertNotEqual(self.call('check').returncode,0)
    def test_legacy_two_slot_mode_keeps_third_credentials_sealed(self):
        dat=self.dat_fixture(); dat.write_text(dat.read_text().replace('guest-before','changed')); self.assertNotEqual(self.call('check').returncode,0)
    def test_disabled_managed_mode_keeps_third_credentials_sealed(self):
        dat=self.dat_fixture(dict(schema=1,confirmed=True,capacity24=4,capacity5=4),False)
        dat.write_text(dat.read_text().replace('guest-before','changed')); self.assertNotEqual(self.call('check').returncode,0)
    def test_string_confirmation_does_not_expand_credential_exception(self):
        dat=self.dat_fixture(dict(schema=1,confirmed='true',capacity24=4,capacity5=4))
        dat.write_text(dat.read_text().replace('private-before4','changed')); self.assertNotEqual(self.call('check').returncode,0)
    def test_unconfirmed_capacity_does_not_expand_credential_exception(self):
        dat=self.dat_fixture(dict(schema=1,confirmed=False,capacity24=4,capacity5=4))
        dat.write_text(dat.read_text().replace('private-before4','changed')); self.assertNotEqual(self.call('check').returncode,0)
    def test_nonprivate_manifest_revokes_credential_exception(self):
        dat=self.dat_fixture(dict(schema=1,confirmed=True,capacity24=4,capacity5=4))
        (self.state/'ts-capabilities.json').chmod(0o644)
        dat.write_text(dat.read_text().replace('private-before4','changed')); self.assertNotEqual(self.call('check').returncode,0)

    def test_other_capacity_keeps_third_credentials_sealed(self):
        dat=self.dat_fixture(dict(schema=1,confirmed=True,capacity24=4,capacity5=3))
        dat.write_text(dat.read_text().replace('private-before3','changed')); self.assertNotEqual(self.call('check').returncode,0)

class BootstrapAdoption(ManagedTransaction):
    def setUp(self):
        super().setUp()
        self.helper.write_text(self.helper.read_text().replace('[ "$(stat -c %u "$journal")" = 0 ]','[ "$(stat -c %u "$journal")" = '+str(os.getuid())+' ]').replace('[ "$(stat -c %u "$item")" = 0 ]','[ "$(stat -c %u "$item")" = '+str(os.getuid())+' ]'))
        for name in ['ax6000-mesh-managed-bootstrap','ax6000-mesh-ts-capability']:
            p=self.root/'usr/libexec'/name;p.write_text('#!/bin/sh\n[ ! -f "$TEST_ROOT/fail-bootstrap" ]\n');p.chmod(0o700)
    def prepare_bootstrap(self):
        self.begin(role='controller')
        p=self.root/'etc/config/ax6000_mesh';d=json.loads(p.read_text());d.update({'main.enabled':'1','main.role':'controller','main.linux_ts':'0'});p.write_text(json.dumps(d))
        for op in ['seal','commit']:
            r=self.call(op);self.assertEqual(r.returncode,0,r.stderr)
        j=self.state/'ts-bootstrap';j.mkdir(mode=0o700)
        for source,before,out in [('network','before-network','network'),('ax6000_mesh','before-mesh','ax6000_mesh')]:
            p=self.root/'etc/config'/source;(j/before).write_bytes(p.read_bytes());(j/before).chmod(0o600)
            d=json.loads(p.read_text());d['main.linux_ts' if source=='ax6000_mesh' else 'bridge.vlan_filtering']='1'
            p.write_text(json.dumps(d));(j/out).write_bytes(p.read_bytes());(j/out).chmod(0o600)
        return j
    def test_bootstrap_exact_apply_and_rollback_preserve_originals(self):
        j=self.prepare_bootstrap();original=(self.state/'original-network').read_bytes()
        r=self.call('adopt-managed-bootstrap');self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.call('check').returncode,0)
        for name,source in [('network','before-network'),('ax6000_mesh','before-mesh')]:
            (self.root/'etc/config'/name).write_bytes((j/source).read_bytes())
        r=self.call('adopt-managed-bootstrap','rollback');self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.call('check').returncode,0);self.assertEqual((self.state/'original-network').read_bytes(),original)
    def test_bootstrap_normalizes_dat_using_prior_mode_before_reseal(self):
        if not (NATIVE/'bin/jshn').exists(): self.skipTest('native jshn required')
        self.helper.write_text(self.helper.read_text().replace('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh')).replace('[ "$(stat -c %u "$manifest")" = 0 ]','[ "$(stat -c %u "$manifest")" = '+str(os.getuid())+' ]'))
        self.env.update(PATH=str(NATIVE/'bin')+':'+self.env['PATH'],LD_LIBRARY_PATH=str(NATIVE/'lib'))
        j=self.prepare_bootstrap()
        manifest=self.state/'ts-capabilities.json';manifest.write_text(json.dumps(dict(schema=1,confirmed=True,capacity24=4,capacity5=4)));manifest.chmod(0o600)
        result=self.call('adopt-managed-bootstrap');self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.call('check').returncode,0)
        for name,source in [('network','before-network'),('ax6000_mesh','before-mesh')]:
            (self.root/'etc/config'/name).write_bytes((j/source).read_bytes())
        result=self.call('adopt-managed-bootstrap','rollback');self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.call('check').returncode,0)
    def test_bootstrap_cannot_adopt_wireless_change(self):
        self.prepare_bootstrap();before=(self.state/'expected').read_bytes()
        (self.root/'etc/config/wireless').write_text('unrelated')
        self.assertNotEqual(self.call('adopt-managed-bootstrap').returncode,0);self.assertEqual((self.state/'expected').read_bytes(),before)
    def test_bootstrap_requires_validator_and_exact_candidate(self):
        self.prepare_bootstrap();before=(self.state/'expected').read_bytes()
        (self.root/'fail-bootstrap').touch();self.assertNotEqual(self.call('adopt-managed-bootstrap').returncode,0)
        (self.root/'fail-bootstrap').unlink();(self.root/'etc/config/network').write_text('newer user edit')
        self.assertNotEqual(self.call('adopt-managed-bootstrap').returncode,0);self.assertEqual((self.state/'expected').read_bytes(),before)
