"""AX6000 layout discovery and pure immutable download catalog policy.

Name/metadata checks identify artifacts. They do not replace independent FIT,
UBI, partition or root filesystem payload validation before flashing.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import urlsplit

DEVICES = {f'xiaomi_redmi-router-ax6000-{layout}': layout
           for layout in ('stock', 'mtkuboot', 'ubootmod')}
SUFFIXES = {
    'stock': {'squashfs-sysupgrade.bin': 'sysupgrade', 'initramfs-kernel.bin': 'initramfs',
              'initramfs-factory.ubi': 'recovery'},
    'mtkuboot': {'squashfs-sysupgrade.bin': 'sysupgrade', 'squashfs-factory.bin': 'factory',
                 'initramfs-kernel.bin': 'initramfs'},
    'ubootmod': {'squashfs-sysupgrade.itb': 'sysupgrade', 'initramfs-recovery.itb': 'recovery',
                 'initramfs-factory.ubi': 'recovery', 'preloader.bin': 'bootloader',
                 'bl31-uboot.fip': 'bootloader'},
}
BUILDINFO = {'config.buildinfo', 'feeds.buildinfo', 'version.buildinfo', 'profiles.json',
             'sha256sums', 'SHA256SUMS', 'immortalwrt-mediatek-filogic.manifest'}
SHA = re.compile(r'[0-9a-f]{64}')
ABI = re.compile(r'(\d+\.\d+\.\d+)~([0-9a-f]{32})-r(\d+)')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_devices(profile):
    firmware = profile.get('firmware', {})
    if 'channel' not in profile and 'devices' not in firmware:
        require(firmware.get('device', profile.get('build_source', {}).get('device')) == next(iter(DEVICES)),
                'legacy firmware supports only AX6000 stock')
        return {next(iter(DEVICES)): 'stock'}
    require(profile.get('channel') in ('recommended', 'latest'), 'invalid firmware channel')
    require(profile.get('id') == 'redmi-ax6000-612-' + profile['channel'], 'channel/profile identity mismatch')
    expected = [{'device': device, 'layout': layout} for device, layout in DEVICES.items()]
    require(firmware.get('devices') == expected, 'firmware.devices must contain exactly ordered stock/mtkuboot/ubootmod')
    require(firmware.get('device') == next(iter(DEVICES)), 'primary firmware device must be stock')
    if 'build_source' in profile:
        require(profile['build_source'].get('device') == next(iter(DEVICES)), 'primary source device must be stock')
    return dict(DEVICES)


def firmware_release_url(profile, filename):
    publication = profile.get('publication', {})
    repository = publication.get('repository')
    require(repository == 'valujin/ax6000-packages-6.12'
            and publication.get('firmware_assets') == 'github-release', 'untrusted firmware publication repository')
    build = profile.get('build_id')
    require(isinstance(build, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{1,180}', build), 'invalid firmware build_id')
    require(isinstance(filename, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*', filename), 'invalid asset filename')
    return f'https://github.com/{repository}/releases/download/firmware-{build}/{filename}'


def classify_filename(filename, profile):
    """Return layout policy fields, None for unrelated target build artifacts."""
    require(isinstance(filename, str), "artifact filename must be a string")
    for device, layout in validate_devices(profile).items():
        marker = '-mediatek-filogic-' + device + '-'
        if marker in filename:
            prefix, suffix = filename.split(marker, 1)
            require(re.fullmatch(r'immortalwrt(?:-[A-Za-z0-9_.+-]+)?', prefix) is not None,
                    f'unrecognized firmware image prefix: {filename}')
            require(suffix in SUFFIXES[layout], f'artifact is not allowed for {layout}: {filename}')
            return {'device': device, 'layout': layout, 'kind': SUFFIXES[layout][suffix],
                    'supported_devices': [device.replace('xiaomi_', 'xiaomi,')]}
    if filename in BUILDINFO:
        return {'device': None, 'layout': None, 'kind': 'buildinfo', 'supported_devices': []}
    # Some releases name manifests per-device. Do not admit arbitrary *.manifest.
    for device, layout in validate_devices(profile).items():
        if filename == f'immortalwrt-mediatek-filogic-{device}.manifest':
            return {'device': device, 'layout': layout, 'kind': 'manifest',
                    'supported_devices': [device.replace('xiaomi_', 'xiaomi,')]}
    return None


def _mandatory(records, profile):
    names = [record['filename'] for record in records]
    require(len(names) == len(set(names)), 'duplicate firmware download filename')
    for device, layout in validate_devices(profile).items():
        require(sum(x.get('device') == device and x.get('kind') == 'sysupgrade' for x in records) == 1,
                f'firmware downloads require exactly one {layout} sysupgrade')
    require(sum(x.get('kind') == 'sdk' for x in records) == 1, 'firmware downloads require exactly one SDK')


def collect_firmware_assets(raw, profile, firmware_manifest):
    raw = Path(raw)
    validate_devices(profile)
    require(firmware_manifest.get('build_id') == profile.get('build_id')
            and firmware_manifest.get('source_commit') == profile['firmware']['commit']
            and firmware_manifest.get('kernel_version') == profile['firmware']['kernel_version'],
            'firmware manifest generation identity mismatch')
    inventory = {}
    for item in firmware_manifest.get('files', []):
        require(isinstance(item, dict), 'invalid firmware inventory record')
        relative = item.get('path')
        require(isinstance(relative, str) and PurePosixPath(relative).as_posix() == relative
                and not PurePosixPath(relative).is_absolute() and '..' not in PurePosixPath(relative).parts,
                'unsafe firmware manifest path')
        require(relative not in inventory, 'duplicate firmware manifest path')
        inventory[relative] = item
    target = raw / 'bin/targets/mediatek/filogic'
    require(target.is_dir() and not target.is_symlink() and target.resolve().is_relative_to(raw.resolve()),
            'firmware target directory is absent or outside raw')
    native_path = target / 'profiles.json'
    require(native_path.is_file() and not native_path.is_symlink(), 'native firmware profiles.json missing')
    native = json.loads(native_path.read_text())
    firmware = profile['firmware']
    match = ABI.fullmatch(firmware.get('kernel_version', ''))
    require(match is not None, 'invalid built kernel ABI')
    require(native.get('target') == 'mediatek/filogic' and native.get('arch_packages') == firmware['architecture'],
            'native firmware target/architecture mismatch')
    require(native.get('linux_kernel') == dict(zip(('version', 'vermagic', 'release'), match.groups())),
            'native firmware kernel ABI mismatch')
    native_devices = native.get('profiles', {})
    require(set(native_devices) == set(validate_devices(profile)), 'native profiles include foreign or missing layouts')
    if 'version_code' in native:
        revision = re.fullmatch(r'r\d+(?:\+\d+)?-([0-9a-f]{7,40})', native['version_code'])
        require(revision and firmware['commit'].startswith(revision[1]), 'native firmware source revision mismatch')
    native_images = {}
    for device, layout in validate_devices(profile).items():
        info = native_devices[device]
        expected = [device.replace('xiaomi_', 'xiaomi,')]
        require(info.get('supported_devices') == expected, f'native supported_devices mismatch for {layout}')
        for image in info.get('images', []):
            name = image.get('name')
            require(name not in native_images, 'duplicate native image name')
            policy = classify_filename(name, profile)
            require(policy and policy['device'] == device and policy['kind'] not in ('manifest', 'buildinfo'),
                    f'native image is outside selected layout policy: {name}')
            native_images[name] = image
    sdk_filename = PurePosixPath(urlsplit(profile['sdk']['url']).path).name
    require(profile['sdk']['url'] == firmware_release_url(profile, sdk_filename), 'SDK URL is not this immutable generation')
    records = []
    for path in sorted(target.iterdir()):
        if path.is_dir():
            continue
        policy = classify_filename(path.name, profile)
        if path.name == sdk_filename:
            require(re.fullmatch(r'immortalwrt-sdk[^/]*\.tar\.(?:xz|gz|zst)', path.name), 'unrecognized SDK filename')
            policy = {'device': None, 'layout': None, 'kind': 'sdk', 'supported_devices': []}
        if policy is None:
            continue
        require(path.is_file() and not path.is_symlink(), f'download asset is not a regular file: {path.name}')
        relative = path.relative_to(raw).as_posix()
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        size = path.stat().st_size
        require(0 < size < 2 * 1024 ** 3, f'download asset size outside Release limits: {path.name}')
        require(relative in inventory and inventory[relative].get('size') == size
                and inventory[relative].get('sha256') == digest, f'firmware manifest hash/size mismatch: {path.name}')
        if policy['kind'] not in ('sdk', 'buildinfo', 'manifest'):
            require(path.name in native_images and native_images[path.name].get('sha256') == digest,
                    f'native image missing or checksum mismatch: {path.name}')
        if policy['kind'] == 'sdk':
            require(digest == profile['sdk']['sha256'], 'SDK checksum mismatch')
        records.append({'path': relative, 'filename': path.name, **policy, 'size': size, 'sha256': digest})
    require(set(native_images) <= {x['filename'] for x in records}, 'native image artifact is missing')
    _mandatory(records, profile)
    return records


def validate_download_catalog(catalog, profile):
    validate_devices(profile)
    required = {'schema_version', 'channel', 'profile_id', 'build_id', 'firmware', 'sdk', 'assets'}
    require(isinstance(catalog, dict) and required <= catalog.keys()
            and set(catalog) <= required | {'release'}, 'invalid download catalog fields')
    require(catalog['schema_version'] == 1 and catalog['channel'] == profile['channel']
            and catalog['profile_id'] == profile['id'] and catalog['build_id'] == profile['build_id']
            and catalog['firmware'] == profile['firmware'] and catalog['sdk'] == profile['sdk'],
            'download catalog channel/source/ABI/SDK identity mismatch')
    if 'release' in catalog:
        release = catalog['release']
        require(isinstance(release, dict) and set(release) == {'repository', 'id', 'tag', 'recipe_commit'}
                and release['repository'] == profile['publication']['repository']
                and type(release['id']) is int and release['id'] > 0
                and release['tag'] == 'firmware-' + profile['build_id']
                and isinstance(release['recipe_commit'], str) and re.fullmatch(r'[0-9a-f]{40}', release['recipe_commit']),
                'download catalog release identity mismatch')
    records = catalog['assets']
    require(isinstance(records, list), 'download catalog assets must be a list')
    asset_ids = set()
    sdk_name = PurePosixPath(urlsplit(profile['sdk']['url']).path).name
    for record in records:
        fields = {'filename', 'device', 'layout', 'kind', 'supported_devices', 'size', 'sha256', 'url'}
        require(isinstance(record, dict) and fields <= record.keys()
                and set(record) <= fields | {'asset_id', 'updated_at'}, 'invalid download asset fields')
        name = record['filename']
        require(isinstance(name, str), 'invalid download asset filename')
        policy = classify_filename(name, profile)
        if name == sdk_name:
            policy = {'device': None, 'layout': None, 'kind': 'sdk', 'supported_devices': []}
            require(record['sha256'] == profile['sdk']['sha256'] and record['url'] == profile['sdk']['url'],
                    'catalog SDK identity mismatch')
        require(policy is not None and all(record[k] == v for k, v in policy.items()), 'foreign download artifact/layout')
        require(type(record['size']) is int and 0 < record['size'] < 2 * 1024 ** 3
                and isinstance(record['sha256'], str) and SHA.fullmatch(record['sha256']), 'invalid download size/hash')
        require(record['url'] == firmware_release_url(profile, name), 'download URL is outside immutable generation')
        if 'asset_id' in record:
            require(type(record['asset_id']) is int and record['asset_id'] > 0 and record['asset_id'] not in asset_ids,
                    'invalid or duplicate asset ID')
            asset_ids.add(record['asset_id'])
        if 'updated_at' in record:
            require(isinstance(record['updated_at'], str)
                    and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', record['updated_at']),
                    'invalid asset update timestamp')
    _mandatory(records, profile)
    return catalog
