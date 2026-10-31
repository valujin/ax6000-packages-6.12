'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
'require dom';

const callStatus = rpc.declare({ object: 'ax6000.mesh', method: 'status', expect: {} });
const callClients = rpc.declare({ object: 'ax6000.mesh', method: 'clients', expect: {} });
const callConfigure = rpc.declare({ object: 'ax6000.mesh', method: 'configure', params: ['role', 'backhaul', 'backhaul_security', 'backhaul_band'], expect: {} });
const callApply = rpc.declare({ object: 'ax6000.mesh', method: 'apply', expect: {} });
const callPair = rpc.declare({ object: 'ax6000.mesh', method: 'pair', expect: {} });
const callDisable = rpc.declare({ object: 'ax6000.mesh', method: 'disable', expect: {} });

function checked(result) {
	if (!result || result.ok !== true)
		throw new Error(result && result.error || _('The router did not complete the operation.'));
	return result;
}

function clientTables(snapshot) {
	const unknown = _('Unknown');
	if (!snapshot || snapshot.ok !== true || !Array.isArray(snapshot.nodes) ||
		!Array.isArray(snapshot.clients) || snapshot.nodes.length > 16 || snapshot.clients.length > 128)
		return E('p', {}, [_('Client information is unavailable. Existing connections are not affected.')]);
	const numeric = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
	const ipv4 = value => typeof value === 'string' && /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value) &&
		value.split('.').every(part => Number(part) <= 255) && Number(value.split('.')[0]) > 0 && Number(value.split('.')[0]) < 224;
	const address = value => ipv4(value) ? E('a', { href: 'http://' + value + '/cgi-bin/luci/',
		target: '_blank', rel: 'noopener noreferrer' }, [value]) : unknown;
	const nodes = Object.create(null);
	const nodeRows = [];
	for (const node of snapshot.nodes) {
		if (!node || typeof node.alid !== 'string') continue;
		nodes[node.alid] = node;
		nodeRows.push(E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, [node.local ? _('This router') : node.hostname || node.alid]),
			E('td', { 'class': 'td' }, [node.role === 1 ? _('Controller') : node.role === 2 ? _('Node') : unknown]),
			E('td', { 'class': 'td' }, [node.local ? _('This router') : address(node.address)])
		]));
	}
	function rate(row, direction) {
		const phy = row[direction + '_kbps'];
		if (row.local === true && numeric(phy)) return (phy / 1000).toFixed(1) + ' Mbit/s';
		const estimate = row[direction === 'tx' ? 'downlink_mbps' : 'uplink_mbps'];
		return numeric(estimate) ? estimate + ' Mbit/s ' + _('(estimated)') : unknown;
	}
	function spatial(row, direction) {
		const nss = row[direction + '_nss'], mcs = row[direction + '_mcs'];
		return row.local === true && numeric(nss) && numeric(mcs) ? nss + ' / ' + mcs : unknown;
	}
	function traffic(row, field) {
		return numeric(row[field]) ? (row[field] / 1048576).toFixed(2) + ' MiB' : unknown;
	}
	const rows = [];
	for (const row of snapshot.clients) {
		if (!row || typeof row.mac !== 'string') continue;
		const owner = nodes[row.node];
		rows.push(E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, [row.hostname || row.mac, E('br'), row.address || unknown]),
			E('td', { 'class': 'td' }, [row.mac]),
			E('td', { 'class': 'td' }, [row.ambiguous ? _('Association is updating') : owner?.local ? _('This router') :
				owner ? owner.hostname || owner.alid : unknown, E('br'), owner && !owner.local ? address(owner.address) : '']),
			E('td', { 'class': 'td' }, [row.band === '2g' ? '2.4 GHz' : row.band === '5g' ? '5 GHz' : row.band === '6g' ? '6 GHz' : unknown,
				E('br'), row.bssid || unknown]),
			E('td', { 'class': 'td' }, [typeof row.rssi_dbm === 'number' && Number.isFinite(row.rssi_dbm) && row.rssi_dbm >= -127 && row.rssi_dbm < 0 ? row.rssi_dbm + ' dBm' : unknown]),
			E('td', { 'class': 'td' }, [rate(row, 'tx'), E('br'), rate(row, 'rx')]),
			E('td', { 'class': 'td' }, [spatial(row, 'tx'), E('br'), spatial(row, 'rx')]),
			E('td', { 'class': 'td' }, [traffic(row, 'tx_bytes'), E('br'), traffic(row, 'rx_bytes')])
		]));
	}
	function table(headers, body) {
		return E('div', { style: 'overflow-x:auto;' }, [E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr table-titles' }, headers.map(label => E('th', { 'class': 'th' }, [label]))),
			...body
		])]);
	}
	return E('div', {}, [
		E('h3', {}, [_('Mesh nodes')]), table([_('Node'), _('Role'), _('Management address')], nodeRows),
		E('h3', {}, [_('Wireless clients across Mesh')]),
		E('p', {}, [_('TX is from the access point to the client; RX is from the client to the access point. Missing or older measurements are shown as unknown. Remote NSS/MCS is unavailable from the Mesh protocol.')]),
		rows.length ? table([_('Host / IPv4'), _('MAC address'), _('Access point'), _('Radio / BSSID'), _('Signal'),
			_('TX / RX link rate'), _('TX / RX NSS / MCS'), _('TX / RX traffic')], rows) : E('p', {}, [_('No wireless clients reported.')])
	]);
}

return view.extend({
	handleSave: null, handleSaveApply: null, handleReset: null,
	load: async function() {
		const status = await callStatus();
		status.clients_snapshot = status.running ? await callClients().catch(() => null) : { ok: true, nodes: [], clients: [] };
		return status;
	},
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
		const security = E('select', { 'class': 'cbi-input-select', id: 'mesh-security' }, [
			E('option', { value: 'sae' }, [_('WPA3-SAE (recommended)')]),
			E('option', { value: 'psk2' }, [_('WPA2-PSK (compatibility)')])
		]);
		const band = E('select', { 'class': 'cbi-input-select', id: 'mesh-band' }, [
			E('option', { value: 'auto' }, [_('Auto (prefer 5 GHz)')]),
			E('option', { value: '5g' }, [_('5 GHz only')]),
			E('option', { value: '2g' }, [_('2.4 GHz only')])
		]);
		security.value = data.backhaul_security === 'psk2' || (!data.backhaul_security && data.enabled) ? 'psk2' : 'sae';
		band.value = ['5g', '2g'].includes(data.backhaul_band) ? data.backhaul_band : 'auto';
		const securityRow = E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title', 'for': 'mesh-security' }, [_('Backhaul security')]), E('div', { 'class': 'cbi-value-field' }, [security])]);
		const bandRow = E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title', 'for': 'mesh-band' }, [_('Wireless backhaul band')]), E('div', { 'class': 'cbi-value-field' }, [band])]);
		role.value = data.role === 'agent' ? 'agent' : 'controller';
		backhaul.value = data.backhaul === 'wireless' ? 'wireless' : 'wired';
		const status = E('div', { 'class': 'cbi-section', 'aria-live': 'polite' });
		let clientSnapshot = data.clients_snapshot;
		const clients = E('div', { 'class': 'cbi-section', 'aria-live': 'polite' }, [clientTables(clientSnapshot)]);
		const instructions = E('p');
		const backhaulRow = E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title', 'for': 'mesh-backhaul' }, [_('Connection between routers')]), E('div', { 'class': 'cbi-value-field' }, [backhaul])]);
		const buttons = [];
		let current = data;
		function display(value) {
			current = value || {};
			const phase = current.phase || current.state;
			const enrollment = current.enrollment || {};
			const connectedNodes = enrollment.topology_valid === true && enrollment.connected === true && Array.isArray(enrollment.peers) ?
				enrollment.peers.filter(peer => peer && peer.role === 'agent' && peer.connected === true).length : 0;
			const pending = ['applying', 'disabling'].includes(current.state) ||
				['applying', 'disabling', 'preparing', 'pairing', 'address', 'validating'].includes(phase);
			let label;
			switch (phase) {
			case 'preparing': case 'applying': label = _('Preparing Mesh…'); break;
			case 'pairing': label = _('Waiting for connection or pairing…'); break;
			case 'address': label = _('Obtaining the management address…'); break;
			case 'validating': label = _('Checking the connection…'); break;
			case 'connected':
				label = current.role === 'controller' && !connectedNodes ? _('Mesh services are running') : _('Mesh node connected');
				break;
			case 'restored': label = _('Setup failed; previous settings restored'); break;
			case 'disabling': label = _('Restoring previous settings…'); break;
			default: label = !current.enabled ? _('Mesh is disabled') : current.running ? _('Mesh services are running') : _('Mesh services are not running');
			}
			const content = [E('h3', {}, [label]), E('p', {}, [current.error || current.detail || ''])];
			if (current.enabled && current.running && current.role === 'agent' && current.backhaul === 'wireless' && current.backhaul_security === 'sae')
				content.push(E('p', {}, [current.backhaul_security_verified === true ? _('Wireless backhaul verified: WPA3-SAE.') : _('Waiting for verified WPA3-SAE wireless backhaul.') ]));
			if (current.enabled && current.running && current.role === 'controller')
				content.push(E('p', {}, [connectedNodes ? _('Connected Mesh nodes: ') + connectedNodes : _('A running service does not mean a node has joined.') ]));
			if (current.enabled) {
				let syncHint;
				switch (current.managed_sync_phase) {
				case 'unsupported': syncHint = _('Guest network synchronization is unavailable for this configuration.'); break;
				case 'pending': syncHint = _('Guest network synchronization is pending.'); break;
				case 'error': syncHint = _('Guest network synchronization needs attention.'); break;
				case 'managed': syncHint = _('Local guest network management is ready. Synchronization on other Mesh nodes is not yet verified.'); break;
				default: syncHint = _('Guest network synchronization status is unknown.');
				}
				content.push(E('p', {}, [syncHint]));
			}
			if (typeof current.pairing_remaining === 'number' && current.pairing_remaining > 0)
				content.push(E('p', {}, [_('Pairing time remaining (seconds): ') + Math.ceil(current.pairing_remaining)]));
			if (enrollment.topology_valid && Array.isArray(enrollment.peers) &&
				!(clientSnapshot?.ok && Array.isArray(clientSnapshot.nodes) && clientSnapshot.nodes.length)) {
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
			securityRow.style.display = role.value === 'controller' || backhaul.value === 'wireless' ? '' : 'none';
			bandRow.style.display = role.value === 'agent' && backhaul.value === 'wireless' ? '' : 'none';
			role.disabled = backhaul.disabled = security.disabled = band.disabled = busy || pending || !!current.enabled || !!current.recovery_pending;
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
			button('apply', _('Enable Mesh'), async () => { checked(await callConfigure(role.value, backhaul.value, security.value, band.value)); return callApply(); }, 'cbi-button-positive'), ' ',
			button('pair', _('Add a node'), callPair), ' ',
			button('disable', _('Disable Mesh and restore settings'), callDisable, 'cbi-button-reset')
		]);
		role.addEventListener ? role.addEventListener('change', () => display(current)) : role.onchange = () => display(current);
		backhaul.addEventListener ? backhaul.addEventListener('change', () => display(current)) : backhaul.onchange = () => display(current);
		display(data);
		poll.add(async () => {
			if (busy) return;
			try {
				const next = await callStatus();
				clientSnapshot = next.running ? await callClients().catch(() => null) : { ok: true, nodes: [], clients: [] };
				display(next);
				dom.content(clients, [clientTables(clientSnapshot)]);
			}
			catch (error) {
				dom.content(status, [E('p', {}, [_('Unable to read Mesh status: ') + (error.message || String(error))]),
					E('p', {}, [_('The additional node may have a new address. Check the main router’s DHCP lease list. If setup fails, recovery is attempted; check the error and retry restoration if needed.')])]);
			}
		}, 5);
		return E('div', {}, [
			E('h2', {}, [_('MediaTek Mesh')]),
			E('p', {}, [_('Connect supported Redmi AX6000 and Xiaomi AX3000T routers running this firmware into one network using MediaTek EasyMesh.')]), status,
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [_('Setup')]),
				E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title', 'for': 'mesh-role' }, [_('Role')]), E('div', { 'class': 'cbi-value-field' }, [role])]),
				backhaulRow, securityRow, bandRow,
				E('p', {}, [_('Use the same backhaul security on the main router and wireless node. To change security or band after enabling Mesh, disable Mesh and enroll the node again; this interrupts its connection.')]),
				instructions,
				E('p', {}, [_('The main router keeps its Wi-Fi names and passwords. The additional node receives its settings automatically. Wi-Fi may briefly disconnect during setup.')]),
				E('p', {}, [_('The additional node obtains its management address automatically, so this page may disconnect. Check the main router’s DHCP lease list for the address. If joining fails, recovery is attempted; check the error and retry restoration if needed.')])
			]), controls, clients
		]);
	}
});
