'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
'require dom';

const callStatus = rpc.declare({ object: 'ax6000.mesh', method: 'status', expect: {} });
const callConfigure = rpc.declare({ object: 'ax6000.mesh', method: 'configure',
	params: ['role', 'backhaul'], expect: {} });
const callApply = rpc.declare({ object: 'ax6000.mesh', method: 'apply', expect: {} });
const callPair = rpc.declare({ object: 'ax6000.mesh', method: 'pair', expect: {} });
const callDisable = rpc.declare({ object: 'ax6000.mesh', method: 'disable', expect: {} });

function checked(result) {
	if (!result || result.ok !== true)
		throw new Error(result && result.error || _('The router did not complete the operation.'));
	return result;
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,
	load: function() { return callStatus(); },
	render: function(data) {
		let busy = false;
		const role = E('select', { 'class': 'cbi-input-select', id: 'mesh-role' }, [
			E('option', { value: 'controller' }, [_('Main router (controller)')]),
			E('option', { value: 'agent' }, [_('Additional node (agent)')])
		]);
		const backhaul = E('select', { 'class': 'cbi-input-select', id: 'mesh-backhaul' }, [
			E('option', { value: 'wired' }, [_('Ethernet cable')]),
			E('option', { value: 'wireless' }, [_('Wi-Fi')])
		]);
		role.value = data.role === 'agent' ? 'agent' : 'controller';
		backhaul.value = data.backhaul === 'wireless' ? 'wireless' : 'wired';
		const status = E('div', { 'class': 'cbi-section', 'aria-live': 'polite' });
		const buttons = [];
		let current = data;
		function display(value) {
			current = value || {};
			const pending = current.state === 'applying' || current.state === 'disabling';
			const label = pending ? _('Applying settings… Keep this page open.') : !current.enabled ? _('Mesh is disabled') :
				(current.running ? _('Mesh services are running') : _('Mesh services are not running'));
			dom.content(status, [E('h3', {}, [label]),
				E('p', {}, [current.error || current.detail || '']),
				E('p', { 'class': 'cbi-value-description' }, [
					_('Service status does not confirm that another node has joined. Check the additional node and its clients after pairing.')])]);
			role.disabled = backhaul.disabled = busy || pending || !!current.enabled;
			for (const button of buttons) {
				const id = button.getAttribute('data-action');
				button.disabled = busy || pending || id === 'apply' && !!current.enabled ||
					id === 'pair' && (!current.enabled || !current.running || current.backhaul !== 'wireless');
			}
		}
		async function action(operation) {
			if (busy) return;
			busy = true;
			display(current);
			try {
				checked(await operation());
				display(await callStatus());
			} catch (error) {
				ui.addNotification(null, E('p', {}, [error.message || String(error)]), 'error');
			} finally {
				busy = false;
				display(current);
			}
		}
		function button(id, label, operation, style) {
			const node = E('button', { 'class': 'cbi-button ' + (style || 'cbi-button-action'),
				'data-action': id, click: () => action(operation) }, [label]);
			buttons.push(node);
			return node;
		}
		const controls = E('div', { 'class': 'cbi-page-actions' }, [
			button('disable', _('Disable Mesh and restore Wi-Fi'), callDisable, 'cbi-button-reset'), ' ',
			button('pair', _('Pair a node'), callPair), ' ',
			button('apply', _('Enable Mesh'), async () => {
				checked(await callConfigure(role.value, backhaul.value));
				return callApply();
			}, 'cbi-button-positive')
		]);
		display(data);
		poll.add(async () => {
			if (busy) return;
			try { display(await callStatus()); }
			catch (error) {
				dom.content(status, E('p', {}, [_('Unable to read Mesh status: ') + (error.message || String(error))]));
			}
		}, 5);
		return E('div', {}, [
			E('h2', {}, [_('MediaTek Mesh')]),
			E('p', {}, [_('Connect Redmi AX6000 routers running this firmware into one network using MediaTek EasyMesh.')]),
			status,
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [_('Setup')]),
				E('p', {}, [_('Choose one main router. Set every other router to Additional node. Before enabling a node, disable its LAN DHCP server and assign it a unique management address in the main router’s network.')]),
				E('p', {}, [_('Use one visible WPA2-PSK access point per band in LAN, with matching names and passwords. Disable separate 802.11r settings. On additional nodes, also disable IPv6 router advertisements and DHCPv6 serving.')]),
				E('p', {}, [E('a', { href: L.url('admin', 'network', 'wireless') }, [_('Wi-Fi settings')]),
					' · ', E('a', { href: L.url('admin', 'network', 'network') }, [_('LAN and DHCP settings')])]),
				E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title', 'for': 'mesh-role' }, [_('Role')]),
					E('div', { 'class': 'cbi-value-field' }, [role])]),
				E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title', 'for': 'mesh-backhaul' }, [_('Connection between routers')]),
					E('div', { 'class': 'cbi-value-field' }, [backhaul])]),
				E('p', {}, [_('The main router uses its existing Wi-Fi names and passwords. Mesh controls radio settings while enabled. Enabling or disabling it briefly interrupts Wi-Fi; configure it over Ethernet.')]),
				E('p', {}, [_('For Ethernet, connect LAN to LAN. For Wi-Fi, enable Mesh on both routers, then press Pair a node on both within two minutes. Keep the routers near each other for initial pairing.')]),
				E('p', {}, [_('WAN, routing and firewall settings are preserved. Disable Mesh to restore the saved wireless configuration.')])
			]), controls
		]);
	}
});
