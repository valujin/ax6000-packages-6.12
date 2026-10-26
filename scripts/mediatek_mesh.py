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
              'driver': '7.6.7.3', 'release': 2, 'flags': {flag: 'y' for flag in FLAGS}}


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


def provenance(profile):
    need(validate(profile), 'MediaTek mesh provenance requires explicit opt-in')
    manifest = json.loads(regular(ASSETS / 'patches/mtwifi-manifest.json', ASSETS))
    need(manifest['source_commit'] == SOURCE_COMMIT, 'MediaTek mtwifi patch source differs')
    patch = regular(ASSETS / 'patches' / manifest['patch'], ASSETS)
    need(digest(patch) == manifest['sha256'], 'MediaTek mtwifi patch hash differs')
    return {'schema_version': 1, 'source_commit': SOURCE_COMMIT,
            'mtwifi_patch_sha256': manifest['sha256'], 'firmware_abi': ABI_MARKER,
            'vendor_driver': {'package': 'kmod-mt_wifi', 'version': '7.6.7.3', 'release': 2,
                              'flags': {flag: 'y' for flag in FLAGS}},
            'packages': {name: tree(ASSETS / 'packages' / name) for name in LOCAL_PACKAGES}}


def patch_targets(source, manifest):
    result = {}
    for relative, hashes in manifest['files'].items():
        candidates = [source / relative, source / 'feeds/base_root' / relative,
                      source / 'feeds/base' / relative.removeprefix('package/')]
        found = {path.resolve() for path in candidates if path.is_file()}
        need(len(found) == 1, 'MediaTek mtwifi patch requires one native/SDK source: ' + relative)
        target = found.pop()
        need(target.is_relative_to(source.resolve()) and target.is_file(), 'MediaTek mtwifi patch escapes source')
        need(digest(target.read_bytes()) in (hashes['before_sha256'], hashes['after_sha256']),
             'MediaTek mtwifi patch preimage hash differs: ' + relative)
        result[relative] = target
    states = {digest(path.read_bytes()) == manifest['files'][relative]['after_sha256'] for relative, path in result.items()}
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
    manifest = json.loads(regular(ASSETS / 'patches/mtwifi-manifest.json', ASSETS))
    targets, patched = patch_targets(source, manifest)
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
        return proof
    # Preflight the complete patch in a temporary canonical tree before copying
    # any package or changing any real upstream file.
    updates = {}
    if not patched:
        with tempfile.TemporaryDirectory(prefix='ax6000-mtwifi-patch-') as temporary:
            temporary = Path(temporary)
            for relative, path in targets.items():
                staged = temporary / relative
                staged.parent.mkdir(parents=True, exist_ok=True)
                staged.write_bytes(path.read_bytes())
            patch = ASSETS / 'patches' / manifest['patch']
            subprocess.run(['git', 'apply', '--check', str(patch)], cwd=temporary, check=True, capture_output=True)
            subprocess.run(['git', 'apply', str(patch)], cwd=temporary, check=True, capture_output=True)
            for relative in targets:
                data = (temporary / relative).read_bytes()
                need(digest(data) == manifest['files'][relative]['after_sha256'], 'MediaTek mtwifi patched hash differs')
                updates[relative] = data
    for name in LOCAL_PACKAGES:
        if not (destination / name).exists():
            shutil.copytree(ASSETS / 'packages' / name, destination / name)
    for relative, data in updates.items():
        targets[relative].write_bytes(data)
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
    versions['mtwifi-cfg-ucode'] = '3-r2'
    versions['kmod-mt_wifi'] = '6.12.108.7.6.7.3-r2'
    return {'files': files, 'hashes': hashes, 'versions': versions,
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
