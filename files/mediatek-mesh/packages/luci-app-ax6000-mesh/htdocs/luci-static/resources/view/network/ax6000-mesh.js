'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
'require dom';

const callStatus = rpc.declare({ object: 'ax6000.mesh', method: 'status', expect: {} });
const callConfigure = rpc.declare({ object: 'ax6000.mesh', method: 'configure', params: ['role', 'backhaul'], expect: {} });
const callApply = rpc.declare({ object: 'ax6000.mesh', method: 'apply', expect: {} });
const callPair = rpc.declare({ object: 'ax6000.mesh', method: 'pair', expect: {} });
const callDisable = rpc.declare({ object: 'ax6000.mesh', method: 'disable', expect: {} });

function checked(result) {
	if (!result || result.ok !== true)
		throw new Error(result && result.error || _('The router did not complete the operation.'));
	return result;
}

return view.extend({
	handleSave: null, handleSaveApply: null, handleReset: null,
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
		const instructions = E('p');
		const backhaulRow = E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title', 'for': 'mesh-backhaul' }, [_('Connection between routers')]), E('div', { 'class': 'cbi-value-field' }, [backhaul])]);
		const buttons = [];
		let current = data;
		function display(value) {
			current = value || {};
			const phase = current.phase || current.state;
			const pending = ['applying', 'disabling'].includes(current.state) ||
				['applying', 'disabling', 'preparing', 'pairing', 'address', 'validating'].includes(phase);
			let label;
			switch (phase) {
			case 'preparing': case 'applying': label = _('Preparing Mesh…'); break;
			case 'pairing': label = _('Waiting for connection or pairing…'); break;
			case 'address': label = _('Obtaining the management address…'); break;
			case 'validating': label = _('Checking the connection…'); break;
			case 'connected': label = _('Mesh node connected'); break;
			case 'restored': label = _('Setup failed; previous settings restored'); break;
			case 'disabling': label = _('Restoring previous settings…'); break;
			default: label = !current.enabled ? _('Mesh is disabled') : current.running ? _('Mesh services are running') : _('Mesh services are not running');
			}
			const content = [E('h3', {}, [label]), E('p', {}, [current.error || current.detail || ''])];
			if (current.enabled && current.running && current.role === 'controller')
				content.push(E('p', {}, [_('A running service does not mean a node has joined.') ]));
			if (typeof current.pairing_remaining === 'number' && current.pairing_remaining > 0)
				content.push(E('p', {}, [_('Pairing time remaining (seconds): ') + Math.ceil(current.pairing_remaining)]));
			const enrollment = current.enrollment || {};
			if (enrollment.topology_valid && Array.isArray(enrollment.peers)) {
				content.push(E('h4', {}, [_('Mesh nodes')]));
				if (!enrollment.peers.length) content.push(E('p', {}, [_('No joined nodes reported.')]));
				for (const peer of enrollment.peers) {
					if (!peer || typeof peer !== 'object') continue;
					const identity = peer.alid || _('Unknown node');
					const address = peer.address || _('Address unknown');
					content.push(E('p', {}, [identity + ' · ' + address + (peer.backhaul ? ' · ' + peer.backhaul : '')]));
				}
			}
			dom.content(status, content);
			dom.content(instructions, role.value === 'controller' ?
				_('Enable Mesh on the main router. For a Wi-Fi node, select Add a node here, then start joining on the additional node while the pairing window is open.') :
				_('For Ethernet, connect the additional node WAN port to a LAN port on the main router. For Wi-Fi, keep the routers nearby and open pairing on the main router before joining.'));
			backhaulRow.style.display = role.value === 'agent' ? '' : 'none';
			role.disabled = backhaul.disabled = busy || pending || !!current.enabled || !!current.recovery_pending;
			for (const button of buttons) {
				const id = button.getAttribute('data-action');
				if (id === 'apply') dom.content(button, role.value === 'agent' ? _('Join Mesh') : _('Enable Mesh'));
				if (id === 'disable') dom.content(button, current.recovery_pending ? _('Restore previous settings') : _('Disable Mesh and restore settings'));
				button.disabled = busy || pending || id === 'apply' && (!!current.enabled || !!current.recovery_pending) ||
					id === 'pair' && (!current.enabled || !current.running || current.role !== 'controller' || !!current.recovery_pending) ||
					id === 'disable' && !current.enabled && !current.recovery_pending;
			}
		}
		async function action(operation) {
			if (busy) return;
			busy = true; display(current);
			try { checked(await operation()); display(await callStatus()); }
			catch (error) { ui.addNotification(null, E('p', {}, [error.message || String(error)]), 'error'); }
			finally { busy = false; display(current); }
		}
		function button(id, label, operation, style) {
			const node = E('button', { 'class': 'cbi-button ' + (style || 'cbi-button-action'),
				'data-action': id, style: 'white-space: normal; max-width: 100%; box-sizing: border-box;', click: () => action(operation) }, [label]);
			buttons.push(node); return node;
		}
		const controls = E('div', { 'class': 'cbi-page-actions', style: 'flex-wrap: wrap;' }, [
			button('apply', _('Enable Mesh'), async () => { checked(await callConfigure(role.value, backhaul.value)); return callApply(); }, 'cbi-button-positive'), ' ',
			button('pair', _('Add a node'), callPair), ' ',
			button('disable', _('Disable Mesh and restore settings'), callDisable, 'cbi-button-reset')
		]);
		role.addEventListener ? role.addEventListener('change', () => display(current)) : role.onchange = () => display(current);
		display(data);
		poll.add(async () => {
			if (busy) return;
			try { display(await callStatus()); }
			catch (error) {
				dom.content(status, [E('p', {}, [_('Unable to read Mesh status: ') + (error.message || String(error))]),
					E('p', {}, [_('The additional node may have a new address. Check the main router’s DHCP lease list. If setup fails, recovery is attempted; check the error and retry restoration if needed.')])]);
			}
		}, 5);
		return E('div', {}, [
			E('h2', {}, [_('MediaTek Mesh')]),
			E('p', {}, [_('Connect Redmi AX6000 routers running this firmware into one network using MediaTek EasyMesh.')]), status,
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [_('Setup')]),
				E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title', 'for': 'mesh-role' }, [_('Role')]), E('div', { 'class': 'cbi-value-field' }, [role])]),
				backhaulRow,
				instructions,
				E('p', {}, [_('The main router keeps its Wi-Fi names and passwords. The additional node receives its settings automatically. Wi-Fi may briefly disconnect during setup.')]),
				E('p', {}, [_('The additional node obtains its management address automatically, so this page may disconnect. Check the main router’s DHCP lease list for the address. If joining fails, recovery is attempted; check the error and retry restoration if needed.')])
			]), controls
		]);
	}
});
