// Pure validation and joining. Never pass the vendor topology dump to a browser.
const MAX_SAFE = 9007199254740991;

function array(value, cap) {
	if (type(value) != 'array' || length(value) > cap)
		die('Invalid or oversized Mesh client data.');
	return value;
}

function number(value, minimum, maximum) {
	if ((type(value) != 'int' && type(value) != 'double') ||
	    !(value >= minimum && value <= maximum) || value % 1 != 0)
		die('Invalid Mesh measurement.');
	return value;
}

function mac(value) {
	if (type(value) != 'string') die('Invalid Mesh address.');
	value = lc(value);
	if (!match(value, /^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$/) || value == '00:00:00:00:00:00')
		die('Invalid Mesh address.');
	return value;
}

function ipv4(value) {
	if (type(value) != 'string' || length(value) > 15) return null;
	let parts = split(value, '.');
	if (length(parts) != 4) return null;
	for (let part in parts)
		if (!match(part, /^(0|[1-9][0-9]{0,2})$/) || int(part) > 255) return null;
	if (int(parts[0]) == 0 || int(parts[0]) >= 224 || int(parts[0]) == 127) return null;
	return value;
}

function text(value) {
	return type(value) == 'string' && length(value) <= 253 && value != '*' ? value : null;
}

function metric(value, minimum, maximum) {
	return value == null ? null : number(value, minimum, maximum);
}

export function normalize(snapshot, leases, hints, local_stations) {
	if (type(snapshot) != 'object' || snapshot.schema != 1 || snapshot.truncated !== false ||
	    snapshot.fresh_ms != 30000)
		die('Mesh client snapshot is incomplete or unavailable.');
	let nodes = [], clients = [], by_node = {}, by_mac = {}, lease_by_mac = {};
	for (let lease in array(leases?.dhcp_leases ?? [], 4096)) {
		if (type(lease) != 'object' || type(lease.macaddr) != 'string') continue;
		let address = ipv4(lease.ipaddr), identity;
		try { identity = mac(lease.macaddr); } catch (e) { continue; }
		// rpcd represents both expired and infinite leases as zero. Without
		// an active expiry we cannot claim this is a current DHCP address.
		if (!address || !(metric(lease.expires, 0, MAX_SAFE) > 0)) continue;
		lease_by_mac[identity] ??= {};
		lease_by_mac[identity][address] = text(lease.hostname);
	}
	for (let item in array(snapshot.nodes, 16)) {
		if (type(item) != 'object' || type(item.local) != 'bool') die('Invalid Mesh node.');
		let identity = mac(item.alid);
		if (by_node[identity]) die('Duplicate Mesh node.');
		let node = { alid: identity, role: number(item.role, 1, 3), local: item.local,
			address: null, management_mac: null, hostname: null };
		let candidates = {}, seen = {};
		for (let raw in array(item.interfaces, 16)) {
			let iface = mac(raw);
			if (seen[iface]) continue;
			seen[iface] = true;
			for (let address, hostname in lease_by_mac[iface] ?? {})
				candidates[address] = { mac: iface, hostname: hostname };
		}
		let addresses = keys(candidates);
		if (length(addresses) == 1) {
			node.address = addresses[0];
			node.management_mac = candidates[node.address].mac;
			node.hostname = candidates[node.address].hostname;
		}
		push(nodes, node); by_node[identity] = node;
	}
	for (let item in array(snapshot.clients, 128)) {
		if (type(item) != 'object') die('Invalid Mesh client.');
		let identity = mac(item.mac), owner = mac(item.node), bssid = mac(item.bssid);
		if (!by_node[owner] || (item.band != null && item.band != '2g' && item.band != '5g' && item.band != '6g'))
			die('Invalid serving Mesh node or band.');
		let link_age = metric(item.link_age_ms, 0, MAX_SAFE), traffic_age = metric(item.traffic_age_ms, 0, MAX_SAFE);
		let row = { mac: identity, node: owner, bssid: bssid, band: item.band,
			local: by_node[owner].local, address: null, hostname: null,
			link_age_ms: link_age, traffic_age_ms: traffic_age, ambiguous: false };
		row.rssi_dbm = metric(item.rssi_dbm, -127, -1);
		for (let field in ['downlink_mbps', 'uplink_mbps', 'last_downlink_mbps', 'last_uplink_mbps'])
			row[field] = metric(item[field], 0, 1000000);
		for (let field in ['tx_bytes', 'rx_bytes']) row[field] = metric(item[field], 0, MAX_SAFE);
		for (let field in ['tx_packets', 'rx_packets', 'tx_errors', 'rx_errors', 'retries'])
			row[field] = metric(item[field], 0, 4294967295);
		if (link_age == null || link_age > 30000) {
			row.rssi_dbm = row.downlink_mbps = row.uplink_mbps = null;
			row.link_age_ms = null;
		}
		// Extended rates have independent observation timestamps at the producer.
		// They are omitted from this UI until that independent age is exported.
		delete row.last_downlink_mbps; delete row.last_uplink_mbps;
		if (traffic_age == null || traffic_age > 30000) {
			for (let field in ['tx_bytes', 'rx_bytes', 'tx_packets', 'rx_packets', 'tx_errors', 'rx_errors', 'retries']) row[field] = null;
			row.traffic_age_ms = null;
		}
		let addresses = keys(lease_by_mac[identity] ?? {});
		if (length(addresses) == 1) {
			row.address = addresses[0]; row.hostname = lease_by_mac[identity][row.address];
		}
		row.hostname ??= text(hints?.[uc(identity)]?.name ?? hints?.[identity]?.name);
		if (by_mac[identity]) {
			let previous = by_mac[identity];
			if (previous.node != row.node || previous.bssid != row.bssid) {
				previous.ambiguous = true;
				previous.node = previous.bssid = previous.band = null;
				previous.link_age_ms = previous.traffic_age_ms = null;
				for (let field in ['rssi_dbm', 'downlink_mbps', 'uplink_mbps', 'tx_bytes', 'rx_bytes', 'tx_packets', 'rx_packets', 'tx_errors', 'rx_errors', 'retries']) previous[field] = null;
			}
			continue;
		}
		push(clients, row); by_mac[identity] = row;
	}
	for (let sample in array(local_stations ?? [], 4096)) {
		if (type(sample) != 'object' || type(sample.mac) != 'string') continue;
		let identity;
		try { identity = mac(sample.mac); } catch (e) { continue; }
		let row = by_mac[identity];
		if (!row || !row.local || row.ambiguous) continue;
		// These are current PHY fields from the controller's local driver.
		// They cannot describe a remote node's PHY or its NSS/MCS.
		for (let direction in ['rx', 'tx']) {
			let rate = sample[direction];
			if (type(rate) != 'object') continue;
			try {
				row[direction + '_kbps'] = metric(rate.rate, 1, 100000000);
				row[direction + '_nss'] = metric(rate.nss, 1, 16);
				row[direction + '_mcs'] = metric(rate.mcs, 0, 31);
			} catch (e) {
				row[direction + '_kbps'] = row[direction + '_nss'] = row[direction + '_mcs'] = null;
			}
		}
	}
	return { ok: true, nodes: nodes, clients: clients, fresh_ms: 30000 };
};
