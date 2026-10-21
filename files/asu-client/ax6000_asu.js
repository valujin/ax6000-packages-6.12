'use strict';
'require baseclass';

/* AX6000 cohort identity is read from a root-owned image file, never UCI. */
const urls = {
	'66': 'https://asu.ezon.by/66',
	'612-recommended': 'https://asu.ezon.by/612/recommended',
	'612-latest': 'https://asu.ezon.by/612/latest'
};
const profiles = {
	'xiaomi,redmi-router-ax6000-stock': 'xiaomi_redmi-router-ax6000-stock',
	'xiaomi,redmi-router-ax6000-mtkuboot': 'xiaomi_redmi-router-ax6000-mtkuboot',
	'xiaomi,redmi-router-ax6000-ubootmod': 'xiaomi_redmi-router-ax6000-ubootmod'
};
function manager(value) {
	// Existing OPKG images predate this field. Missing never means APK.
	const result = value.package_manager == null ? 'opkg' : value.package_manager;
	if (result !== 'opkg' && result !== 'apk')
		throw Error('Invalid AX6000 package manager identity');
	if (value.cohort === '66' && result !== 'opkg')
		throw Error('AX6000 6.6 requires OPKG');
	return result;
}
function identity(value, full) {
	if (!value || value.schema_version !== 1 || !urls[value.cohort] ||
		typeof value.seed !== 'string' || !/^[0-9a-f]{64}$/.test(value.seed))
		throw Error('Missing or invalid AX6000 firmware cohort identity');
	manager(value);
	if (full && value.cohort !== '66' && value.package_manager == null)
		throw Error('Upgrade generation lacks package manager identity');
	full = full || ['build_id', 'catalog_sha256', 'snapshot_sha256', 'kernel_version']
		.some(key => value[key] !== undefined);
	if (full && (typeof value.build_id !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,191}$/.test(value.build_id) ||
		!/^([0-9a-f]{64})$/.test(value.catalog_sha256 || '') ||
		!/^([0-9a-f]{64})$/.test(value.snapshot_sha256 || '') ||
		typeof value.kernel_version !== 'string' ||
		!/^6\.(6|12)\.[0-9]+~[0-9a-f]{32}-r[0-9]+$/.test(value.kernel_version) ||
		!value.kernel_version.startsWith(value.cohort === '66' ? '6.6.' : '6.12.')))
		throw Error('Incomplete or foreign AX6000 upgrade generation');
	return value;
}
function target(local, remote) {
	identity(local, false); identity(remote, true);
	if (local.cohort !== remote.cohort)
		throw Error('Automatic upgrades cannot change AX6000 kernel cohort');
	if (manager(local) !== manager(remote))
		throw Error('Changing OPKG/APK requires an explicit firmware migration');
	return remote;
}
return baseclass.extend({
	identity: identity,
	manager: manager,
	runtime: function(local, apkDatabase, opkgDatabase) {
		identity(local, false);
		if (!!apkDatabase === !!opkgDatabase)
			throw Error('Cannot determine one installed package manager');
		const actual = apkDatabase ? 'apk' : 'opkg';
		if (manager(local) !== actual)
			throw Error('Firmware package manager differs from installed package database');
		return actual;
	},
	target: target,
	same: function(a, b) {
		identity(a, true); identity(b, true);
		return ['schema_version', 'cohort', 'seed', 'build_id', 'catalog_sha256',
			'snapshot_sha256', 'kernel_version'].every(key => a[key] === b[key]) && manager(a) === manager(b);
	},
	server: function(url, local) {
		identity(local, false);
		if (typeof url !== 'string' || url.replace(/\/+$/, '') !== urls[local.cohort])
			throw Error('Upgrade server does not match the AX6000 firmware cohort');
		return urls[local.cohort];
	},
	profile: function(board, local) {
		identity(local, false);
		if (!profiles[board] || (local.cohort === '66' && board !== 'xiaomi,redmi-router-ax6000-stock'))
			throw Error('Unsupported AX6000 flash layout');
		return profiles[board];
	},
	hasUpgrade: function(local, remote) {
		target(local, remote);
		/* Native images intentionally lack the later catalog/snapshot hash.
		 * They may request one personalized image; that image records all fields.
		 * This also detects changed package snapshots with unchanged r0+ revisions.
		 */
		return local.seed !== remote.seed || local.build_id !== remote.build_id ||
			local.catalog_sha256 !== remote.catalog_sha256 ||
			local.snapshot_sha256 !== remote.snapshot_sha256;
	},
	request: function(local, remote, board, selectedProfile, installed, selected) {
		target(local, remote);
		if (this.profile(board, local) !== selectedProfile)
			throw Error('Automatic upgrades cannot change AX6000 flash layout');
		const names = Object.keys(installed);
		/* Preserve all installed packages, including Tailscale when present.
		 * Adding Tailscale through the advanced editor is deliberately rejected.
		 */
		if (selected.indexOf('tailscale') >= 0 && names.indexOf('tailscale') < 0)
			throw Error('Tailscale may be included only when already installed');
		const packages = Array.from(new Set(names.concat(selected))).sort();
		return { ax6000: remote, packages: packages, profile: selectedProfile,
			installed_packages: names.sort(), installed_package_manager: manager(local), diff_packages: false };
	}
});
