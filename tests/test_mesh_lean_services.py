"""Agent service ownership is exercised against isolated UCI and init stubs."""
import json
import unittest
from pathlib import Path
import test_mesh_transaction as fixture


class LeanServices(unittest.TestCase):
    def setUp(self):
        self.f = fixture.MeshTransaction('runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root
        config = self.root / 'etc/config/dhcp'
        data = json.loads(config.read_text())
        data.update({'dns': 'dnsmasq', 'odhcp': 'odhcpd'})
        config.write_text(json.dumps(data, sort_keys=True))
        self.f.original['etc/config/dhcp'] = config.read_bytes()
        for name in ('dnsmasq', 'odhcpd'):
            (self.root / ('enabled-' + name)).touch()
            script = self.root / 'etc/init.d' / name
            old = script.read_text()
            old = old.replace('case "$1" in\n', '''case "$1" in
 enabled) [ -f "$TEST_ROOT/enabled-$name" ]; exit $? ;;
 enable) : > "$TEST_ROOT/enabled-$name"; exit 0 ;;
 disable) rm -f "$TEST_ROOT/enabled-$name"; exit 0 ;;
''')
            script.write_text(old)

    def setup_agent(self):
        self.f.begin()
        result = self.f.call('prepare-agent'); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.f.call('seal').returncode, 0)
        result = self.f.call('commit'); self.assertEqual(result.returncode, 0, result.stderr)

    def native_defaults(self):
        p = self.root / 'etc/config/network'; data = json.loads(p.read_text())
        data.update({'tailscale':'interface','tailscale.proto':'none','tailscale.device':'tailscale0','tailscale.multipath':'off'})
        p.write_text(json.dumps(data,sort_keys=True))
        (self.root / 'etc/dnsmasq.conf').write_text('# Native default logging only\nlog-facility=/dev/null\n')

    def optional_services(self):
        for name in ('pbr','miniupnpd'):
            script=self.root/'etc/init.d'/name
            script.write_text('''#!/bin/sh
name=${0##*/}
active="$TEST_ROOT/running-$name"
[ "$name" != pbr ] || active="$TEST_ROOT/rules-pbr"
echo "$name $*" >> "$TEST_ROOT/commands.log"
case "$1" in
 enabled) [ -f "$TEST_ROOT/enabled-$name" ] ;;
 enable) : > "$TEST_ROOT/enabled-$name" ;;
 disable) [ ! -f "$TEST_ROOT/fail-disable-$name" ] || exit 1; rm -f "$TEST_ROOT/enabled-$name" ;;
 running) [ ! -f "$TEST_ROOT/unknown-running-$name" ] || exit 2; [ -f "$active" ] ;;
 stop) [ ! -f "$TEST_ROOT/fail-stop-$name" ] || exit 1; rm -f "$active"
       # PBR resolver cleanup may restart DNS: it must stop before DNS.
       [ "$name" != pbr ] || : > "$TEST_ROOT/running-dnsmasq" ;;
 start) : > "$active"
        if [ "$name" = pbr ] && [ -f "$TEST_ROOT/pbr-restarts-dns" ]; then : > "$TEST_ROOT/running-dnsmasq"; fi ;;
 *) exit 2 ;;
esac
''');script.chmod(0o755)
            (self.root/('enabled-'+name)).touch()
        (self.root/'rules-pbr').touch();(self.root/'running-miniupnpd').touch()

    def test_lean_optional_services_stop_before_dns_and_restore_exact_states(self):
        self.optional_services();(self.root/'enabled-miniupnpd').unlink()
        self.setup_agent()
        for name in ('pbr','miniupnpd'):self.assertFalse((self.root/('enabled-'+name)).exists())
        self.assertFalse((self.root/'rules-pbr').exists());self.assertFalse((self.root/'running-miniupnpd').exists())
        self.assertFalse((self.root/'running-dnsmasq').exists())
        self.assertLess(self.f.log.read_text().index('pbr stop'),self.f.log.read_text().index('dnsmasq stop'))
        self.assertEqual(self.f.call('rollback').returncode,0)
        self.assertTrue((self.root/'rules-pbr').exists());self.assertTrue((self.root/'running-miniupnpd').exists())
        self.assertTrue((self.root/'enabled-pbr').exists());self.assertFalse((self.root/'enabled-miniupnpd').exists())

    def test_optional_enabled_but_inactive_state_stays_inactive_on_restore(self):
        self.optional_services();(self.root/'rules-pbr').unlink();(self.root/'running-miniupnpd').unlink()
        self.setup_agent();self.assertEqual(self.f.call('rollback').returncode,0)
        self.assertIn('pbr stop',self.f.log.read_text(),'Inactive procd watchers must also be removed before AP handover')
        self.assertFalse((self.root/'rules-pbr').exists());self.assertFalse((self.root/'running-miniupnpd').exists())
        self.assertTrue((self.root/'enabled-pbr').exists());self.assertTrue((self.root/'enabled-miniupnpd').exists())

    def test_custom_network_keeps_optional_services_untouched(self):
        self.optional_services()
        p=self.root/'etc/config/network';data=json.loads(p.read_text());data.update({'guest':'interface','guest.proto':'static'})
        p.write_text(json.dumps(data,sort_keys=True));self.setup_agent()
        self.assertTrue((self.root/'rules-pbr').exists());self.assertTrue((self.root/'enabled-miniupnpd').exists())

    def test_explicitly_enabled_pbr_configuration_keeps_services(self):
        self.optional_services()
        (self.root/'etc/config/pbr').write_text(json.dumps({'config':'pbr','config.enabled':'1'}))
        self.setup_agent()
        self.assertTrue((self.root/'rules-pbr').exists());self.assertTrue((self.root/'running-dnsmasq').exists())
        self.assertTrue((self.root/'enabled-pbr').exists())

    def test_unknown_oneshot_running_status_refuses_snapshot_before_changes(self):
        self.optional_services();(self.root/'unknown-running-pbr').touch()
        result=self.f.call('begin','agent','wired')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/'etc/ax6000-mesh').exists())
        self.assertTrue((self.root/'rules-pbr').exists());self.assertTrue((self.root/'enabled-pbr').exists())

    def test_pbr_restore_cannot_leave_originally_stopped_dns_running(self):
        self.optional_services();(self.root/'pbr-restarts-dns').touch();(self.root/'running-dnsmasq').unlink()
        self.setup_agent();self.assertEqual(self.f.call('rollback').returncode,0)
        self.assertFalse((self.root/'running-dnsmasq').exists())
        self.assertTrue((self.root/'rules-pbr').exists())

    def test_optional_disable_failure_keeps_snapshot_and_restores_all_states(self):
        self.optional_services();self.f.begin();(self.root/'fail-disable-miniupnpd').touch()
        self.assertNotEqual(self.f.call('prepare-agent').returncode,0)
        self.assertTrue((self.root/'etc/ax6000-mesh/snapshot.sha256').exists())
        (self.root/'fail-disable-miniupnpd').unlink()
        self.assertEqual(self.f.call('rollback').returncode,0)
        self.assertTrue((self.root/'rules-pbr').exists());self.assertTrue((self.root/'enabled-pbr').exists())
        self.assertTrue((self.root/'running-miniupnpd').exists());self.assertTrue((self.root/'enabled-miniupnpd').exists())

    def test_legacy_lean_snapshot_without_optional_ownership_does_not_touch_pbr(self):
        self.optional_services();self.f.begin();state=self.root/'etc/ax6000-mesh'
        names=['lean-optional-services']+[f'was-{field}-{service}'for field in ('present','running','enabled')for service in ('pbr','miniupnpd')]
        for name in names:(state/name).unlink()
        manifest=state/'snapshot.sha256';manifest.write_text(''.join(line for line in manifest.read_text().splitlines(True)if not any('./'+name+'\n' in line for name in names)))
        self.assertEqual(self.f.call('prepare-agent').returncode,0)
        self.assertTrue((self.root/'rules-pbr').exists());self.assertTrue((self.root/'enabled-miniupnpd').exists())

    def test_lean_boot_stops_optional_rules_before_dns_and_disables_restored_links(self):
        self.optional_services();self.setup_agent()
        (self.root/'rules-pbr').touch();(self.root/'running-miniupnpd').touch()
        for service in ('pbr','miniupnpd'):(self.root/('enabled-'+service)).touch()
        self.assertEqual(self.f.call('recover-boot').returncode,0)
        self.assertFalse((self.root/'rules-pbr').exists());self.assertFalse((self.root/'running-miniupnpd').exists())
        self.assertFalse((self.root/'running-dnsmasq').exists())
        for service in ('pbr','miniupnpd'):self.assertFalse((self.root/('enabled-'+service)).exists())

    def test_native_default_logging_and_missing_tailscale_device_are_lean(self):
        self.native_defaults(); self.setup_agent()
        for name in ('dnsmasq','odhcpd'):
            self.assertFalse((self.root / ('running-'+name)).exists())
            self.assertFalse((self.root / ('enabled-'+name)).exists())

    def test_existing_tailscale_device_preserves_services(self):
        self.native_defaults()
        (self.root / 'sys/class/net/tailscale0').mkdir()
        (self.root / 'sys/class/net/tailscale0/flags').write_text('0x1')
        self.setup_agent()
        self.assertTrue((self.root / 'running-dnsmasq').exists())
        self.assertTrue((self.root / 'enabled-odhcpd').exists())

    def test_active_userspace_tailscale_without_device_preserves_services(self):
        self.native_defaults();(self.root/'running-tailscaled').touch()
        self.setup_agent();self.assertTrue((self.root/'running-dnsmasq').exists())

    def test_enabled_tailscale_keeps_services_even_before_its_device_exists(self):
        self.native_defaults()
        init=self.root/'etc/init.d/tailscale';init.write_text('#!/bin/sh\n[ "$1" = enabled ]\n');init.chmod(0o755)
        self.setup_agent();self.assertTrue((self.root/'running-dnsmasq').exists())

    def test_dormant_tailscale_with_custom_dhcp_preserves_services(self):
        self.native_defaults()
        p=self.root/'etc/config/dhcp';data=json.loads(p.read_text())
        data.update({'tail':'dhcp','tail.interface':'tailscale','tail.ignore':'0'})
        p.write_text(json.dumps(data,sort_keys=True));self.setup_agent()
        self.assertTrue((self.root/'running-dnsmasq').exists())

    def test_tailscale_declaration_with_extra_address_preserves_services(self):
        self.native_defaults()
        p=self.root/'etc/config/network';data=json.loads(p.read_text());data['tailscale.ipaddr']='192.0.2.1'
        p.write_text(json.dumps(data,sort_keys=True));self.setup_agent()
        self.assertTrue((self.root/'running-dnsmasq').exists())

    def test_logging_exception_is_not_applied_to_per_instance_configuration(self):
        (self.root/'etc/dnsmasq.dns.conf').write_text('log-facility=/dev/null\n')
        self.setup_agent();self.assertTrue((self.root/'running-dnsmasq').exists())

    def test_pure_lan_agent_keeps_servers_off_across_boot_and_restores_original_state(self):
        self.setup_agent()
        for name in ('dnsmasq', 'odhcpd'):
            self.assertFalse((self.root / ('running-' + name)).exists())
            self.assertFalse((self.root / ('enabled-' + name)).exists())
        self.assertEqual(self.f.call('recover-boot').returncode, 0)
        self.assertEqual(self.f.call('rollback').returncode, 0)
        for name in ('dnsmasq', 'odhcpd'):
            self.assertTrue((self.root / ('running-' + name)).exists())
            self.assertTrue((self.root / ('enabled-' + name)).exists())
        self.assertLess(self.f.log.read_text().index('wan nomaster'), self.f.log.read_text().rindex('dnsmasq start'))

    def test_other_interface_keeps_services_available(self):
        p = self.root / 'etc/config/network'; data = json.loads(p.read_text())
        data.update({'guest': 'interface', 'guest.proto': 'static'}); p.write_text(json.dumps(data, sort_keys=True))
        self.setup_agent()
        for name in ('dnsmasq', 'odhcpd'):
            self.assertTrue((self.root / ('running-' + name)).exists())
            self.assertTrue((self.root / ('enabled-' + name)).exists())

    def test_openwrt_default_ignored_wan_pool_and_no_odhcp_section_are_lean(self):
        p = self.root / 'etc/config/dhcp'; data = json.loads(p.read_text())
        del data['odhcp']; data.update({'wan': 'dhcp', 'wan.interface': 'wan', 'wan.ignore': '1'})
        p.write_text(json.dumps(data, sort_keys=True))
        self.setup_agent()
        self.assertFalse((self.root / 'running-dnsmasq').exists())
        self.assertFalse((self.root / 'enabled-odhcpd').exists())

    def test_previously_stopped_and_disabled_services_restore_exactly(self):
        (self.root / 'running-dnsmasq').unlink(); (self.root / 'enabled-odhcpd').unlink()
        self.setup_agent()
        self.assertEqual(self.f.call('rollback').returncode, 0)
        self.assertFalse((self.root / 'running-dnsmasq').exists())
        self.assertTrue((self.root / 'enabled-dnsmasq').exists())
        self.assertTrue((self.root / 'running-odhcpd').exists())
        self.assertFalse((self.root / 'enabled-odhcpd').exists())

    def test_custom_dns_configuration_keeps_services(self):
        p = self.root / 'etc/config/dhcp'; data = json.loads(p.read_text())
        data['dns.server'] = ['10.0.0.53']; p.write_text(json.dumps(data, sort_keys=True))
        self.setup_agent()
        for name in ('dnsmasq', 'odhcpd'):
            self.assertTrue((self.root / ('running-' + name)).exists())
            self.assertTrue((self.root / ('enabled-' + name)).exists())

    def test_custom_dns_address_or_dnsmasq_conf_keeps_services(self):
        p = self.root / 'etc/config/dhcp'; data = json.loads(p.read_text())
        data['dns.address'] = ['/service.lan/192.168.1.2']; p.write_text(json.dumps(data, sort_keys=True))
        self.setup_agent()
        self.assertTrue((self.root / 'running-dnsmasq').exists())

    def test_custom_dnsmasq_conf_keeps_services(self):
        (self.root / 'etc/dnsmasq.conf').write_text('address=/fixture/192.0.2.1\n')
        self.setup_agent()
        self.assertTrue((self.root / 'running-dnsmasq').exists())

    def test_custom_per_instance_dnsmasq_conf_keeps_services(self):
        (self.root / 'etc/dnsmasq.dns.conf').write_text('address=/custom/192.0.2.1\n')
        self.setup_agent()
        self.assertTrue((self.root / 'running-dnsmasq').exists())

    def test_upgrade_restored_boot_links_are_disabled_for_committed_lean_agent(self):
        self.setup_agent()
        for name in ('dnsmasq', 'odhcpd'): (self.root / ('enabled-' + name)).touch()
        self.assertEqual(self.f.call('recover-boot').returncode, 0)
        for name in ('dnsmasq', 'odhcpd'): self.assertFalse((self.root / ('enabled-' + name)).exists())

    def test_boot_restores_enabled_services_if_custom_dns_is_added(self):
        self.setup_agent()
        (self.root / 'etc/dnsmasq.conf').write_text('address=/custom/192.0.2.1\n')
        self.assertEqual(self.f.call('recover-boot').returncode, 0)
        for name in ('dnsmasq', 'odhcpd'): self.assertTrue((self.root / ('enabled-' + name)).exists())

    def test_failed_disable_rolls_back_service_states(self):
        script = self.root / 'etc/init.d/odhcpd'
        script.write_text(script.read_text().replace('disable) rm -f', 'disable) [ ! -f "$TEST_ROOT/fail-disable" ] || exit 1; rm -f'))
        self.f.begin(); (self.root / 'fail-disable').touch()
        self.assertNotEqual(self.f.call('prepare-agent').returncode, 0)
        (self.root / 'fail-disable').unlink()
        self.assertEqual(self.f.call('rollback').returncode, 0)
        for name in ('dnsmasq', 'odhcpd'):
            self.assertTrue((self.root / ('running-' + name)).exists())
            self.assertTrue((self.root / ('enabled-' + name)).exists())

    def test_old_snapshot_without_new_markers_keeps_existing_service_behavior(self):
        self.f.begin()
        state = self.root / 'etc/ax6000-mesh'
        for name in ('lean-services', 'was-enabled-dnsmasq', 'was-enabled-odhcpd'):
            (state / name).unlink()
        manifest = state / 'snapshot.sha256'
        manifest.write_text(''.join(line for line in manifest.read_text().splitlines(keepends=True)
                                    if not any(name in line for name in ('lean-services', 'was-enabled-dnsmasq', 'was-enabled-odhcpd'))))
        self.assertEqual(self.f.call('prepare-agent').returncode, 0)
        self.assertEqual(self.f.call('seal').returncode, 0)
        self.assertEqual(self.f.call('commit').returncode, 0)
        self.assertTrue((self.root / 'running-dnsmasq').exists())
        self.assertEqual(self.f.call('rollback').returncode, 0)
        self.assertTrue((self.root / 'enabled-dnsmasq').exists())
