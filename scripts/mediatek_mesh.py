"""Pinned MediaTek EasyMesh integration for the new recommended AX6000 image.

Old profiles are inert. SDK userspace builds require the matching native mesh
receipt; they cannot add this feature to a previously issued vendor generation.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'files/mediatek-mesh'
SOURCE_COMMIT = 'ae65e1de69971b5a2e3cf7e39390ee93f274d488'
LOCAL_PACKAGES = ('wapp', '1905daemon', 'libmapd', 'mapd', 'ax6000-mesh', 'luci-app-ax6000-mesh', 'mapfilter')
PACKAGES = frozenset((*(name for name in LOCAL_PACKAGES if name != 'mapfilter'), 'kmod-mapfilter', 'luci-i18n-ax6000-mesh-ru', 'datconf', 'libkvcutil'))
FLAGS = ('MTK_MAP_SUPPORT', 'MTK_MAP_R2_VER_SUPPORT', 'MTK_MAP_R3_VER_SUPPORT',
         'MTK_MAP_R2_6E_SUPPORT', 'MTK_MAP_R3_6E_SUPPORT', 'MTK_DFS_SLAVE_SUPPORT')
RECEIPT = 'ax6000-mesh-source.json'
ABI_PATH = 'etc/ax6000-mesh-abi.json'
ABI_MARKER = {'schema_version': 1, 'abi': 'mtk-20250408-map6e', 'source_commit': SOURCE_COMMIT,
              'driver': '7.6.7.3', 'release': 2, 'flags': {flag: 'y' for flag in FLAGS},
              'defines': {'MAP_MLO_UPLINK': 1}}


LUCI_WIRELESS_VERSION = '26.249.28459~d6167ea-r2'
VENDOR_WIRELESS_VERSION = '1-r3'
SDK_UAPI = 'ax6000-baseline/mesh-uapi'
UAPI_HEADERS = {
    'wapp_cmm_type.h': '821fa92e0b2f044928af64e420a4f1735635e7567f312add971c9d715da13898',
    'mt_wlan_cmm_oid.h': 'a11e84592439326bb7d6cc6cc8e4dd1eec4f570b6c31e0bce041039c5ddae5b9',
}


def abi_bytes():
    return (json.dumps(ABI_MARKER, sort_keys=True, separators=(',', ':')) + '\n').encode()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate(profile):
    if 'mediatek_mesh' in profile:
        need(type(profile['mediatek_mesh']) is bool, 'mediatek_mesh must be boolean')
    if profile.get('mediatek_mesh') is not True:
        return False
    import firmware_layouts
    firmware = profile.get('firmware', {})
    need(profile.get('channel') == 'recommended' and profile.get('id') == 'redmi-ax6000-612-recommended'
         and profile.get('package_manager') == 'apk' and profile.get('exclude_asu') is True
         and 'asu' not in profile, 'MediaTek mesh requires recommended APK without ASU')
    need(firmware.get('commit') == SOURCE_COMMIT
         and firmware.get('repository') == 'https://github.com/chasey-dev/immortalwrt-mt798x-rebase.git'
         and (firmware.get('target'), firmware.get('subtarget'), firmware.get('architecture')) ==
             ('mediatek', 'filogic', 'aarch64_cortex-a53'), 'MediaTek mesh requires the pinned AX6000 vendor source')
    firmware_layouts.validate_devices(profile)
    need('ru' in profile.get('luci_languages', []), 'MediaTek mesh requires the Russian LuCI package')
    need('tailscale' in profile.get('package_only', []) and 'tailscale' in profile.get('packages', [])
         and 'tailscale' not in profile.get('image_packages', []), 'MediaTek mesh must retain Tailscale package_only')
    for key in ('packages', 'image_packages'):
        need(PACKAGES <= set(profile.get(key, [])), 'MediaTek mesh packages missing from ' + key)
    need(not PACKAGES.intersection(profile.get('package_only', [])), 'MediaTek mesh packages cannot be package_only')
    return True


def symbols(profile):
    return {**{flag: 'y' for flag in FLAGS}, **{'PACKAGE_' + name: 'y' for name in PACKAGES}} if validate(profile) else {}


def regular(path, root):
    need(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve())
         and not any(parent.is_symlink() for parent in path.parents if parent != root and parent.is_relative_to(root)),
         'MediaTek mesh file is absent, linked or outside its root: ' + str(path))
    return path.read_bytes()


def tree(directory):
    need(directory.is_dir() and not directory.is_symlink(), 'MediaTek mesh package absent: ' + str(directory))
    result = {}
    for path in sorted(directory.rglob('*')):
        need(not path.is_symlink(), 'Linked MediaTek mesh asset refused: ' + str(path))
        if path.is_dir():
            continue
        data = regular(path, directory)
        result[path.relative_to(directory).as_posix()] = {'sha256': digest(data), 'mode': path.stat().st_mode & 0o777}
    need('Makefile' in result, 'MediaTek mesh package has no Makefile')
    return result


def wireless_manifest(profile):
    """Authenticate the source patch against the selected immutable LuCI feed."""
    manifest = json.loads(regular(ASSETS / 'patches/luci-wireless-manifest.json', ASSETS))
    pins = [feed.get('commit') for feed in profile.get('feeds', []) if feed.get('name') == 'luci']
    need(manifest.get('schema_version') == 1 and pins == [manifest.get('feed_commit')],
         'MediaTek LuCI wireless feed pin differs')
    need(manifest.get('patch') == 'luci-wireless-mesh.patch', 'Unexpected LuCI wireless patch')
    patch = regular(ASSETS / 'patches' / manifest['patch'], ASSETS)
    need(len(patch) <= 512 * 1024 and digest(patch) == manifest['sha256'], 'LuCI wireless patch hash differs')
    need(manifest.get('package_version') == LUCI_WIRELESS_VERSION, 'LuCI wireless package version differs')
    allowed = {
        'feeds/luci/modules/luci-mod-network/Makefile': None,
        'feeds/luci/modules/luci-mod-network/root/etc/uci-defaults/95-ax6000-mesh-wireless-vendor':
            'etc/uci-defaults/95-ax6000-mesh-wireless-vendor',
        'feeds/luci/modules/luci-mod-network/root/usr/share/rpcd/acl.d/luci-mod-network.json':
            'usr/share/rpcd/acl.d/luci-mod-network.json',
    }
    need(set(manifest['files']) == set(allowed) and
         all(item['image_path'] == allowed[name] for name, item in manifest['files'].items()),
         'Unexpected LuCI wireless patch target')
    recipe = wireless_images(manifest)['feeds/luci/modules/luci-mod-network/Makefile'].decode()
    need(re.findall(r'^PKG_VERSION:=(.+)$', recipe, re.M) == ['26.249.28459~d6167ea']
         and re.findall(r'^PKG_RELEASE:=(.+)$', recipe, re.M) == ['2'], 'LuCI wireless recipe version differs')
    return manifest


def vendor_wireless_manifest():
    """The active MediaTek page is a layer over the exact DB-country postimage."""
    manifest = json.loads(regular(ASSETS / 'patches/mtwifi-wireless-manifest.json', ASSETS))
    prefix = 'package/mtk/applications/luci-app-mtwifi-cfg/'
    allowed = {prefix + 'Makefile': None,
               prefix + 'root/usr/share/luci-app-mtwifi-cfg/wireless-mtk.js': 'usr/share/luci-app-mtwifi-cfg/wireless-mtk.js',
               prefix + 'root/etc/uci-defaults/luci-app-mtwifi-cfg.default': 'etc/uci-defaults/luci-app-mtwifi-cfg.default'}
    need(manifest.get('schema_version') == 1 and manifest.get('source_commit') == SOURCE_COMMIT and
         manifest.get('requires_country_postimage') == '612' and
         manifest.get('package_version') == VENDOR_WIRELESS_VERSION and
         manifest.get('patch') == 'mtwifi-wireless-mesh.patch', 'MediaTek vendor wireless manifest differs')
    need(set(manifest['files']) == set(allowed) and
         all(item['image_path'] == allowed[name] and item['mode'] == 0o644
             for name, item in manifest['files'].items()), 'Unexpected MediaTek vendor wireless target')
    need(manifest.get('runtime_copies') == {'usr/share/luci-app-mtwifi-cfg/wireless-mtk.js':
         'www/luci-static/resources/view/network/wireless.js'}, 'MediaTek vendor wireless lifecycle differs')
    import vendor_country
    need(manifest['files'][prefix + 'root/usr/share/luci-app-mtwifi-cfg/wireless-mtk.js']['before_sha256'] == vendor_country.POSTIMAGES['612'][0] and
         manifest['files'][prefix + 'Makefile']['before_sha256'] == vendor_country.POSTIMAGES['612'][1],
         'MediaTek vendor wireless country layer differs')
    images = wireless_images(manifest)
    recipe = images[prefix + 'Makefile'].decode()
    need(re.findall(r'^PKG_VERSION:=(.+)$', recipe, re.M) == ['1'] and
         re.findall(r'^PKG_RELEASE:=(.+)$', recipe, re.M) == ['3'], 'MediaTek vendor wireless recipe differs')
    return manifest


def wireless_images(manifest, *, after=True):
    """Full-context patch carries authenticated source preimages and postimages."""
    patch = regular(ASSETS / 'patches' / manifest['patch'], ASSETS)
    need(digest(patch) == manifest['sha256'], 'LuCI wireless patch hash differs')
    files, current = {}, None
    for line in patch.decode().splitlines(keepends=True):
        if line.startswith('diff --git '):
            current = line.split(' b/', 1)[1].strip()
            need(current in manifest['files'] and current not in files, 'Unexpected LuCI addition header')
            files[current] = []
        elif line.startswith('--- a/'):
            current = line[6:].strip()
            need(current in manifest['files'] and current not in files, 'Unexpected LuCI wireless patch header')
            files[current] = []
        elif line.startswith(('+++ ', '@@', '--- /dev/null')):
            continue
        elif current and line[:1] in (' ', '+' if after else '-'):
            files[current].append(line[1:])
    result = {name: ''.join(lines).encode() for name, lines in files.items()}
    field = 'after_sha256' if after else 'before_sha256'
    need(set(result) == set(manifest['files']) and
         all((not after and manifest['files'][name][field] is None and data == b'') or
             digest(data) == manifest['files'][name][field] for name, data in result.items()),
         'LuCI wireless full-context image hash differs')
    return result


def wireless_targets(source, manifest):
    targets, states = {}, set()
    for relative, hashes in manifest['files'].items():
        target = source / relative
        if hashes['before_sha256'] is None and not target.exists():
            need(not any(path.is_symlink() for path in (target, *target.parents)), 'Linked LuCI patch addition refused')
            actual = None
        else:
            data = regular(target, source)
            actual = digest(data)
        need(actual in (hashes['before_sha256'], hashes['after_sha256']),
             'LuCI wireless preimage hash differs: ' + relative)
        targets[relative] = target
        states.add(actual == hashes['after_sha256'])
    need(len(states) == 1, 'LuCI wireless patch has mixed before/after state')
    return targets, states == {True}


def provenance(profile):
    need(validate(profile), 'MediaTek mesh provenance requires explicit opt-in')
    manifest = json.loads(regular(ASSETS / 'patches/mtwifi-manifest.json', ASSETS))
    need(manifest['source_commit'] == SOURCE_COMMIT, 'MediaTek mtwifi patch source differs')
    patch = regular(ASSETS / 'patches' / manifest['patch'], ASSETS)
    need(digest(patch) == manifest['sha256'], 'MediaTek mtwifi patch hash differs')
    luci = wireless_manifest(profile)
    vendor = vendor_wireless_manifest()
    return {'schema_version': 1, 'source_commit': SOURCE_COMMIT,
            'luci_wireless': {'package_version': luci['package_version'], 'feed_commit': luci['feed_commit'], 'patch_sha256': luci['sha256'], 'files': luci['files']},
            'vendor_wireless': vendor,
            'mtwifi_patch_sha256': manifest['sha256'], 'firmware_abi': ABI_MARKER,
            'wapp_uapi': UAPI_HEADERS,
            'vendor_driver': {'package': 'kmod-mt_wifi', 'version': '7.6.7.3', 'release': 2,
                              'flags': {flag: 'y' for flag in FLAGS}, 'defines': {'MAP_MLO_UPLINK': 1}},
            'packages': {name: tree(ASSETS / 'packages' / name) for name in LOCAL_PACKAGES}}


def patch_targets(source, manifest):
    result = {}
    # Existing targets identify the native/SDK vendor root for reviewed additions.
    entries = sorted(manifest['files'].items(), key=lambda item: item[1]['before_sha256'] is None)
    for relative, hashes in entries:
        candidates = [source / relative, source / 'feeds/base_root' / relative,
                      source / 'feeds/base' / relative.removeprefix('package/')]
        found = {path.resolve() for path in candidates if path.is_file()}
        if hashes['before_sha256'] is None and not found:
            driver = 'package/mtk/drivers/mt_wifi/'
            need(relative.startswith(driver), 'Unsupported MediaTek source patch addition')
            target = result[driver + 'Makefile'].parent / relative.removeprefix(driver)
        else:
            need(len(found) == 1, 'MediaTek mtwifi patch requires one native/SDK source: ' + relative)
            target = found.pop()
        need(target.resolve().is_relative_to(source.resolve()) and not target.is_symlink(),
             'MediaTek mtwifi patch escapes source')
        actual = digest(target.read_bytes()) if target.is_file() else None
        need(actual in (hashes['before_sha256'], hashes['after_sha256']),
             'MediaTek mtwifi patch preimage hash differs: ' + relative)
        result[relative] = target
    states = {path.is_file() and digest(path.read_bytes()) == manifest['files'][relative]['after_sha256']
              for relative, path in result.items()}
    need(len(states) == 1, 'MediaTek mtwifi patch has mixed before/after state')
    return result, states == {True}


def configure(profile, source, *, native=False, check_only=False):
    if not validate(profile):
        return None
    source = Path(source).resolve()
    # This gate precedes source inspection and all writes. The native SDK bank
    # is authenticated by the existing SDK manifest/archive verification.
    if not native:
        baseline_path = source / 'ax6000-baseline/manifest.json'
        need(baseline_path.is_file() and not baseline_path.is_symlink(), 'MediaTek mesh requires its newly built native SDK')
        baseline = json.loads(baseline_path.read_bytes())
        need(baseline.get('source_commit') == SOURCE_COMMIT and baseline.get('mediatek_mesh'),
             'Older native SDK cannot retrofit MediaTek mesh')
        verify_sdk_uapi(source)
    manifest = json.loads(regular(ASSETS / 'patches/mtwifi-manifest.json', ASSETS))
    targets, patched = patch_targets(source, manifest)
    luci_manifest = wireless_manifest(profile)
    luci_targets, luci_patched = wireless_targets(source, luci_manifest)
    vendor_manifest = vendor_wireless_manifest()
    vendor_targets, vendor_patched = patch_targets(source, vendor_manifest)
    proof = provenance(profile)
    if not native:
        need(baseline['mediatek_mesh'] == proof, 'Native SDK MediaTek mesh recipe provenance differs')
    receipt = source / RECEIPT
    if receipt.exists() or receipt.is_symlink():
        need(json.loads(regular(receipt, source)) == proof, 'MediaTek mesh source receipt differs')
    else:
        need(not check_only, 'MediaTek mesh source receipt absent')
    marker = source / 'files' / ABI_PATH
    if native:
        need(not any(path.is_symlink() for path in (marker, *marker.parents)), 'Linked MediaTek mesh ABI marker refused')
        if marker.exists():
            need(regular(marker, source) == abi_bytes() and marker.stat().st_mode & 0o777 == 0o644,
                 'Native MediaTek mesh ABI marker differs')
        else:
            need(not check_only, 'Native MediaTek mesh ABI marker absent')
    destination = source / 'package/ax6000-overrides'
    for name in LOCAL_PACKAGES:
        target = destination / name
        need(not any(path.is_symlink() for path in (target, *target.parents)), 'Linked MediaTek mesh package destination refused')
        if target.exists():
            need(tree(target) == proof['packages'][name], 'MediaTek mesh copied package differs: ' + name)
        else:
            need(not check_only, 'MediaTek mesh copied package absent: ' + name)
    if check_only:
        need(patched, 'MediaTek mtwifi patch is not applied')
        need(luci_patched, 'LuCI wireless patch is not applied')
        need(vendor_patched, 'MediaTek vendor wireless patch is not applied')
        return proof
    # Preflight the complete patch in a temporary canonical tree before copying
    # any package or changing any real upstream file.
    updates = {}
    all_targets = {**targets, **luci_targets, **vendor_targets}
    for active_manifest, active_targets, already_patched in ((manifest, targets, patched),
                                                            (luci_manifest, luci_targets, luci_patched),
                                                            (vendor_manifest, vendor_targets, vendor_patched)):
        if already_patched:
            continue
        with tempfile.TemporaryDirectory(prefix='ax6000-mesh-source-patch-') as temporary:
            temporary = Path(temporary)
            for relative, path in active_targets.items():
                staged = temporary / relative
                staged.parent.mkdir(parents=True, exist_ok=True)
                if path.is_file():
                    staged.write_bytes(path.read_bytes())
            patch = ASSETS / 'patches' / active_manifest['patch']
            subprocess.run(['git', 'apply', '--check', str(patch)], cwd=temporary, check=True, capture_output=True)
            subprocess.run(['git', 'apply', str(patch)], cwd=temporary, check=True, capture_output=True)
            for relative in active_targets:
                data = (temporary / relative).read_bytes()
                need(digest(data) == active_manifest['files'][relative]['after_sha256'], 'MediaTek patched source hash differs')
                updates[relative] = data
    for name in LOCAL_PACKAGES:
        if not (destination / name).exists():
            shutil.copytree(ASSETS / 'packages' / name, destination / name)
    for relative, data in updates.items():
        all_targets[relative].parent.mkdir(parents=True, exist_ok=True)
        all_targets[relative].write_bytes(data)
    if native and not marker.exists():
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_bytes(abi_bytes())
        marker.chmod(0o644)
    receipt.write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    return proof


def verify(profile, source, *, native=False):
    if not validate(profile):
        return None
    proof = configure(profile, source, native=native, check_only=True)
    config = regular(Path(source) / '.config', Path(source)).decode()
    for flag in FLAGS:
        need(re.findall(r'^CONFIG_' + re.escape(flag) + r'=(.+)$', config, re.M) == ['y'],
             'MediaTek mesh build flag differs: ' + flag)
    if native:
        for name in PACKAGES:
            need(re.findall(r'^CONFIG_PACKAGE_' + re.escape(name) + r'=(.+)$', config, re.M) == ['y'],
                 'MediaTek mesh native image package is absent: ' + name)
    return proof


def expected(profile):
    """Independent local script/default bytes; compiled ELF is checked separately."""
    if not validate(profile):
        return {'files': {}, 'hashes': {}, 'versions': {}, 'version_suffixes': {}}
    provenance(profile)
    files, versions = {ABI_PATH: (abi_bytes(), 0o644)}, {}
    for name in LOCAL_PACKAGES:
        package = ASSETS / 'packages' / name
        recipe = regular(package / 'Makefile', package).decode()
        version = re.findall(r'^PKG_VERSION\s*:?=\s*([^\s]+)\s*$', recipe, re.M)
        release = re.findall(r'^PKG_RELEASE\s*:?=\s*([0-9]+)\s*$', recipe, re.M)
        need(len(version) == len(release) == 1 and '$' not in version[0], 'MediaTek mesh package version is not pinned: ' + name)
        if name != 'mapfilter':
            versions[name] = version[0] + '-r' + release[0]
        # Our runtime package installs files verbatim; LuCI's standard helper
        # installs root at / and htdocs at /www. Vendor package mappings are
        # explicit in their recipes and inspected from native package payloads.
        prefixes = [('files', '')] if name == 'ax6000-mesh' else [('root', ''), ('htdocs', 'www/')] if name.startswith('luci-app-') else []
        for folder, prefix in prefixes:
            directory = package / folder
            if not directory.exists():
                continue
            for path in sorted(directory.rglob('*')):
                if path.is_file():
                    files[prefix + path.relative_to(directory).as_posix()] = (regular(path, package), path.stat().st_mode & 0o777)
    patch_manifest = json.loads((ASSETS / 'patches/mtwifi-manifest.json').read_bytes())
    hashes = {relative.split('/files/', 1)[1]: item['after_sha256']
              for relative, item in patch_manifest['files'].items() if '/files/' in relative}
    luci_manifest = wireless_manifest(profile)
    for relative, data in wireless_images(luci_manifest).items():
        image_path = luci_manifest['files'][relative]['image_path']
        if image_path is not None:
            files[image_path] = (data, 0o644)
    vendor_manifest = vendor_wireless_manifest()
    for relative, data in wireless_images(vendor_manifest).items():
        item = vendor_manifest['files'][relative]
        if item['image_path'] is not None:
            files[item['image_path']] = (data, item['mode'])
    versions['luci-app-mtwifi-cfg'] = vendor_manifest['package_version']
    versions['luci-mod-network'] = luci_manifest['package_version']
    versions['mtwifi-cfg-ucode'] = '3-r3'
    versions['kmod-mt_wifi'] = '6.12.108.7.6.7.3-r2'
    return {'files': files, 'hashes': hashes, 'versions': versions,
            'runtime_copies': vendor_manifest['runtime_copies'],
            'version_suffixes': {'luci-i18n-ax6000-mesh-ru': ''}}


def verify_payloads(profile, payloads, read_file, check_mode=None):
    """Match actual image daemon/library bytes to authenticated native APKs."""
    if not validate(profile):
        return {}
    required = {'usr/bin/wapp', 'usr/bin/wappctrl', 'usr/bin/mapd', 'usr/bin/mapd_cli',
                'usr/bin/p1905_managerd', 'usr/bin/1905ctrl'}
    files = {}
    total = 0
    for name, payload in payloads.items():
        need(name in PACKAGES or name == 'mtwifi-cfg-ucode', 'Unexpected MediaTek mesh native package')
        for path, data in payload.items():
            need(path not in files, 'MediaTek mesh native payload collision: ' + path)
            total += len(data)
            need(total <= 128 * 1024**2, 'MediaTek mesh native payload byte cap exceeded')
            actual = read_file(path, max(4096, len(data)))
            need(actual == data, 'Actual image MediaTek mesh native bytes differ: ' + path)
            files[path] = {'sha256': digest(data), 'size': len(data), 'package': name}
    need(required <= files.keys(), 'Actual image MediaTek mesh native daemon payload is incomplete')
    if check_mode is not None:
        for path in sorted(required):
            check_mode(path, 0o755)
            files[path]['mode'] = '0755'
    need(any(path.startswith('usr/lib/libmapd_interface_client.so') for path in files)
         and any(path.startswith('usr/lib/libeth_1905ops.so') for path in files),
         'Actual image MediaTek mesh native libraries are incomplete')
    return files


def verify_sdk_uapi(sdk):
    sdk = Path(sdk)
    for name, expected_hash in UAPI_HEADERS.items():
        path = sdk / SDK_UAPI / name
        need(path.is_file() and path.stat().st_size <= 1024 * 1024,
             'Native SDK WAPP UAPI header absent: ' + name)
        need(digest(regular(path, sdk)) == expected_hash, 'Native SDK WAPP UAPI header hash differs: ' + name)
    return dict(UAPI_HEADERS)


def export_sdk_uapi(profile, source, kernel, sdk):
    if not validate(profile):
        return None
    source, kernel, sdk = Path(source), Path(kernel), Path(sdk)
    native = {'wapp_cmm_type.h': kernel.parent / 'mt_wifi/mt_wifi/embedded/include/wapp/wapp_cmm_type.h',
              'mt_wlan_cmm_oid.h': kernel / 'include/uapi/linux/wapp/mt_wlan_cmm_oid.h'}
    contents = {}
    for name, path in native.items():
        data = regular(path, source)
        need(digest(data) == UAPI_HEADERS[name], 'Native WAPP UAPI header hash differs: ' + name)
        contents[name] = data
    destination = sdk / SDK_UAPI
    need(not destination.exists() and not any(path.is_symlink() for path in (destination, *destination.parents)),
         'Native SDK WAPP UAPI header destination already exists or is linked')
    destination.mkdir(parents=True)
    for name, data in contents.items():
        path = destination / name
        path.write_bytes(data)
        path.chmod(0o644)
    return verify_sdk_uapi(sdk)
