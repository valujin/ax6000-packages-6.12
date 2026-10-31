"""Read-only controller normalization rejects unsupported network topology."""
import json, os, shlex, subprocess, tempfile, unittest
from pathlib import Path
from test_mesh_slot_allocation import LIB, NATIVE

class Normalize(unittest.TestCase):
    def setUp(self):
        if not (NATIVE / 'bin/jshn').exists(): self.skipTest('native jshn unavailable')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = {
          'wireless': [('radio0','wifi-device',{'band':'2g'}),('radio1','wifi-device',{'band':'5g'}),
            ('main','wifi-iface',dict(device='radio0',mode='ap',network='lan',ssid='Main',key='private-main',encryption='psk2')),
            ('main5','wifi-iface',dict(device='radio1',mode='ap',network='lan',ssid='Main',key='private-main',encryption='psk2')),
            ('guest','wifi-iface',dict(device='radio0',mode='ap',network='guest',ssid='Guest',key='private-guest',encryption='psk2',isolate='1'))],
          'network':[('lan','interface',dict(device='br-lan',proto='static')),('guest','interface',dict(device='br-lan.10',proto='static',ipaddr='192.168.10.1',netmask='255.255.255.0'))],
          'firewall':[('guest','zone',dict(name='guest',network='guest',input='REJECT',forward='REJECT',output='ACCEPT'))],
          'dhcp':[('guest','dhcp',dict(interface='guest',start='100',limit='100'))]}
        self.cap = dict(schema=1,confirmed=True,capacity24=4,capacity5=4,enrolled_agents=['02:11:22:33:44:55'])
        self.seed = dict(schema=1,backhaul_ssid='PrivateBH',backhaul_key='private-backhaul',backhaul_security='sae',quarantine_key='private-quarantine',quarantine_vid=4090)
    def run_helper(self, ok=True):
        # Fixture adapter has the same read-only function interface as OpenWrt.
        variables=sorted({f'CONFIG_{name}_{key}' for sections in self.config.values() for name,typ,values in sections for key in [*values,'TYPE']})
        lines=['config_load() {', 'unset '+' '.join(variables), 'case "$1" in']
        for package, sections in self.config.items():
            lines.append(package + ') CONFIG_SECTIONS=' + shlex.quote(' '.join(s[0] for s in sections)))
            for name, typ, values in sections:
                for key,value in {**values,'TYPE':typ}.items(): lines.append('export CONFIG_'+name+'_'+key+'='+shlex.quote(value))
            lines.append(';;')
        lines.extend(['esac; }', 'config_get() { eval "value=\\${CONFIG_${2}_${3}-}"; [ -n "$value" ] || value=${4-}; export "$1=$value"; }',
                      'config_foreach() { local section typ; for section in $CONFIG_SECTIONS; do config_get typ "$section" TYPE; [ "$typ" != "$2" ] || "$1" "$section"; done; }'])
        functions=self.root/'functions'; functions.write_text('\n'.join(lines))
        helper=self.root/'helper'
        helper.write_text((LIB/'ax6000-mesh-normalize-networks').read_text().replace('[ "$(id -u)" = 0 ]', '[ "$(id -u)" = '+str(os.getuid())+' ]').replace('[ "$(stat -c %u "$1")" = 0 ]', '[ "$(stat -c %u "$1")" = '+str(os.getuid())+' ]').replace('/lib/functions.sh',str(functions)).replace('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh')).replace('/usr/share/ax6000-mesh/vendor.sh',str(LIB.parent/'share/ax6000-mesh/vendor.sh')).replace('/usr/libexec/ax6000-mesh-plan-networks',str(self.root/'planner')))
        planner=self.root/'planner'; planner.write_text((LIB/'ax6000-mesh-plan-networks').read_text().replace('#!/bin/sh','#!/usr/bin/busybox ash',1).replace('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh'))); planner.chmod(0o700)
        for name,data in [('capacity',self.cap),('seed',self.seed)]:
            p=self.root/name; p.write_text(json.dumps(data)); p.chmod(0o600)
        out=self.root/'out'
        result=subprocess.run(['busybox','ash',str(helper),str(self.root/'capacity'),str(self.root/'seed'),str(out)],capture_output=True,text=True,env={**os.environ,'PATH':str(NATIVE/'bin')+':'+os.environ['PATH'],'LD_LIBRARY_PATH':str(NATIVE/'lib')})
        self.assertEqual(result.returncode==0,ok,result.stderr); self.assertEqual(result.stdout,''); self.assertNotIn('private-',result.stderr)
        if ok:
            for p in out.iterdir(): self.assertEqual(p.stat().st_mode & 0o777,0o600)
            return json.loads((out/'policy.json').read_text()),json.loads((out/'credentials.json').read_text())
        self.assertFalse(out.exists())
    def test_normalizes_existing_guest(self):
        p,c=self.run_helper(); self.assertEqual(p['bsses'][2]['vid'],10); self.assertNotIn('private-',json.dumps(p)); self.assertEqual(c['keys'][2]['key'],'private-guest')
    def test_crossband_key_mismatch(self):
        self.config['wireless'][3][2]['key']='private-mismatch'; self.run_helper(False)
    def test_unowned_or_flat_guest(self):
        self.config['network'][1][2]['device']='br-guest'; self.run_helper(False)
    def test_missing_firewall(self):
        self.config['firewall']=[]; self.run_helper(False)
    def test_missing_dhcp(self):
        self.config['dhcp']=[]; self.run_helper(False)
    def test_unconfirmed_capacity(self):
        self.cap['confirmed']=False; self.run_helper(False)
    def test_quarantine_conflict_unrelated_interface(self):
        self.config['network'].append(('other','interface',dict(device='br-lan.4090',proto='none'))); self.run_helper(False)
    def test_quarantine_conflict_bridge_vlan(self):
        self.config['network'].append(('vlan','bridge-vlan',dict(device='br-lan',vlan='4090'))); self.run_helper(False)
    def test_multinetwork_rejected(self):
        self.config['wireless'][4][2]['network']='guest lan'; self.run_helper(False)
    def test_logical_network_fallback(self):
        self.config['wireless'][4][2].update(network='',mesh_network='guest',mesh_managed='1')
        p,c=self.run_helper(); self.assertEqual(p['bsses'][2]['network'],'guest')
    def test_explicit_network_wins_over_fallback(self):
        self.config['wireless'][4][2].update(mesh_network='unknown')
        self.run_helper()
    def test_owned_backhaul_and_placeholder_are_excluded(self):
        self.config['wireless'] += [('ax6000_mesh_ap1','wifi-iface',dict(mode='ap',map_bss_type='64')),('ax6000_mesh_slot24_3','wifi-iface',dict(mesh_placeholder='1'))]
        p,c=self.run_helper(); self.assertEqual(len(p['bsses']),3)
    def test_arbitrary_backhaul_flag_does_not_hide_client(self):
        self.config['wireless'].append(('invalid','wifi-iface',dict(mesh_backhaul='1',mode='sta')))
        self.run_helper(False)
    def test_crossband_flags_mismatch(self):
        self.config['wireless'][3][2]['hidden']='1'; self.run_helper(False)
    def test_unisolated_guest(self):
        self.config['wireless'][4][2]['isolate']='0'; self.run_helper(False)
    def test_bad_agent_address(self):
        self.cap['enrolled_agents']=['ff:ff:ff:ff:ff:ff']; self.run_helper(False)
    def test_capacity_string_is_not_evidence(self):
        self.cap['capacity24']='4'; self.run_helper(False)
    def test_secret_never_passed_to_external_json_command(self):
        # Production calls the filename-aware jshn parser for private seed data.
        source=(LIB/'ax6000-mesh-normalize-networks').read_text()
        self.assertIn('jshn -R "$work/input"',source)
        self.assertNotIn('json_load "',source)
    def test_quarantine_zero_padded_reference(self):
        self.config['network'].append(('other','interface',dict(device='br-lan.04090',proto='none'))); self.run_helper(False)
    def test_multiple_primary_ssids_on_one_band_rejected(self):
        self.config['wireless'].append(('main_extra','wifi-iface',dict(device='radio0',mode='ap',network='lan',ssid='Extra',key='private-main',encryption='psk2')))
        self.run_helper(False)
    def test_guest_to_lan_forwarding_rejected(self):
        self.config['firewall'].append(('guest_lan','forwarding',dict(src='guest',dest='lan'))); self.run_helper(False)
    def test_guest_zone_cannot_share_primary_network(self):
        self.config['firewall'][0][2]['network']='guest lan'; self.run_helper(False)
    def test_explicit_guest_to_lan_accept_rule_rejected(self):
        self.config['firewall'].append(('allow','rule',dict(src='guest',dest='lan',target='ACCEPT'))); self.run_helper(False)
    def test_renamed_guest_zone_rule_rejected(self):
        self.config['firewall'][0][2]['name']='visitors'
        self.config['firewall'].append(('allow','rule',dict(src='visitors',dest='lan',target='ACCEPT'))); self.run_helper(False)
    def test_wildcard_allow_rule_rejected(self):
        self.config['firewall'].append(('allow','rule',dict(src='*',dest='lan',target='ACCEPT'))); self.run_helper(False)
    def test_router_management_accept_rejected(self):
        self.config['firewall'].append(('allow','rule',dict(src='guest',dest_port='22',proto='tcp',target='ACCEPT'))); self.run_helper(False)
    def test_existing_dns_dhcp_rules_and_wan_forward_supported(self):
        self.config['firewall'] += [('wan','zone',dict(name='wan',network='wan wan6',input='REJECT',forward='REJECT',output='ACCEPT')),
            ('internet','forwarding',dict(src='guest',dest='wan')),
            ('dns','rule',dict(src='guest',dest_port='53',proto='tcp udp',target='ACCEPT')),
            ('dhcp_rule','rule',dict(src='guest',dest_port='67',src_port='68',proto='udp',target='ACCEPT'))]
        self.run_helper()
    def test_guest_zone_extra_device_membership_rejected(self):
        self.config['firewall'][0][2]['device']='br-lan'; self.run_helper(False)
    def test_guest_redirect_to_lan_rejected(self):
        self.config['firewall'].append(('redirect','redirect',dict(src='guest',dest='lan',target='DNAT'))); self.run_helper(False)
    def test_unknown_active_include_rejected(self):
        self.config['firewall'].append(('custom','include',dict(path='/etc/custom-fw.sh'))); self.run_helper(False)
    def test_unrelated_wan_lan_port_forward_preserved(self):
        self.config['firewall'].append(('wan_forward','redirect',dict(src='wan',dest='lan',target='DNAT'))); self.run_helper()
    def test_disabled_guest_allow_and_include_ignored(self):
        self.config['firewall'] += [('allow','rule',dict(src='guest',dest='lan',target='ACCEPT',enabled='0')),('custom','include',dict(path='/etc/custom-fw.sh',enabled='0'))]
        self.run_helper()
    def stock_wan_icmpv6(self, **changes):
        rule=dict(src='wan',dest='*',proto='icmp',family='ipv6',target='ACCEPT',limit='1000/sec',
            icmp_type='echo-request echo-reply destination-unreachable packet-too-big time-exceeded bad-header unknown-header-type')
        rule.update(changes)
        self.config['firewall'] += [('wan','zone',dict(name='wan',network='wan wan6',input='REJECT',forward='REJECT',output='ACCEPT')),
            ('icmp6_forward','rule',rule)]
    def test_stock_wan_icmpv6_forward_preserved(self):
        self.stock_wan_icmpv6(); self.run_helper()
    def test_stock_icmpv6_guest_or_wildcard_origin_rejected(self):
        for src in ['guest','*']:
            with self.subTest(src=src):
                self.stock_wan_icmpv6(src=src); self.run_helper(False); self.config['firewall']=self.config['firewall'][:-2]
    def test_stock_icmpv6_requires_ipv6_icmp_accept(self):
        for changes in [dict(family='ipv4'),dict(family=''),dict(proto='tcp'),dict(proto='all'),dict(target='NOTRACK')]:
            with self.subTest(changes=changes):
                self.stock_wan_icmpv6(**changes); self.run_helper(False); self.config['firewall']=self.config['firewall'][:-2]
    def test_stock_icmpv6_rejects_missing_negated_or_other_types(self):
        for types in ['', '   ', '*', '!echo-request', 'router-advertisement', 'echo-request redirect', '0:255']:
            with self.subTest(types=types):
                self.stock_wan_icmpv6(icmp_type=types); self.run_helper(False); self.config['firewall']=self.config['firewall'][:-2]
    def test_stock_icmpv6_rejects_rule_extensions(self):
        for option in ['extra','set_mark','set_xmark','set_helper','helper']:
            with self.subTest(option=option):
                self.stock_wan_icmpv6(**{option:'unsafe'}); self.run_helper(False); self.config['firewall']=self.config['firewall'][:-2]
    def test_stock_icmpv6_requires_exclusive_wan_zone(self):
        self.stock_wan_icmpv6(); self.config['firewall'][-2][2]['network']='wan lan'; self.run_helper(False)
    def test_stock_icmpv6_rejects_extra_wan_device(self):
        self.stock_wan_icmpv6(); self.config['firewall'][-2][2]['device']='br-lan'; self.run_helper(False)
