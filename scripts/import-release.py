#!/usr/bin/env python3
"""Verify and import a raw build bundle without executing anything inside it."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit

SPEC = importlib.util.spec_from_file_location('release_prepare', Path(__file__).with_name('prepare.py'))
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


def release_identity(release, asset_names=('raw.tar.zst', 'raw.tar.zst.sha256')):
    if not isinstance(release, dict) or release.get('immutable') is not True:
        raise ValueError('The source release must be immutable')
    if release.get('draft') is not False:
        raise ValueError('Publish the draft release after all asset uploads finish')
    if (not isinstance(asset_names, (tuple, list)) or not asset_names
            or any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*', name)
                   for name in asset_names) or len(set(asset_names)) != len(asset_names)):
        raise ValueError('Release asset names must be unique safe filenames')
    assets = []
    for name in asset_names:
        matches = [asset for asset in release.get('assets', []) if asset.get('name') == name]
        if len(matches) != 1 or matches[0].get('state') != 'uploaded':
            raise ValueError(f'Release must contain exactly one uploaded {name}')
        asset = matches[0]
        assets.append((asset['id'], asset['name'], asset['size'], asset['updated_at'], asset.get('digest')))
    return release['id'], release['tag_name'], release['draft'], release['immutable'], tuple(assets)


def read_json(path):
    if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError(f'Missing or oversized metadata: {path.name}')
    return json.loads(path.read_text())


def validate_inventory(raw, profile, manifest):
    entries = manifest.get('files')
    if not isinstance(entries, list) or not entries:
        raise ValueError('Firmware manifest must contain a nonempty bin file inventory')
    inventory = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('Invalid firmware manifest inventory entry')
        path, size, digest = entry.get('path'), entry.get('size'), entry.get('sha256')
        if not isinstance(path, str):
            raise ValueError('Invalid firmware manifest inventory path')
        relative = PurePosixPath(path)
        if (relative.is_absolute() or len(relative.parts) < 2 or relative.parts[0] != 'bin'
                or '..' in relative.parts or '\\' in path or '\x00' in path
                or relative.as_posix() != path):
            raise ValueError(f'Unsafe or noncanonical firmware manifest inventory path: {path}')
        if path in inventory:
            raise ValueError(f'Duplicate firmware manifest inventory path: {path}')
        if type(size) is not int or size < 0 or not isinstance(digest, str) \
                or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError(f'Invalid firmware manifest size or checksum: {path}')
        inventory[path] = entry
    binary = raw / 'bin'
    if binary.is_symlink() or not binary.is_dir():
        raise ValueError('Firmware manifest bin inventory directory is missing')
    actual = {}
    for path in binary.rglob('*'):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError(f'Firmware manifest inventory contains a link or special file: {path}')
        if path.is_file():
            actual[path.relative_to(raw).as_posix()] = path
    if set(actual) != set(inventory):
        missing = sorted(set(inventory) - set(actual))
        extra = sorted(set(actual) - set(inventory))
        raise ValueError(f'Firmware manifest inventory differs: missing={missing[:10]}, extra={extra[:10]}')
    if profile.get('package_manager', 'opkg') == 'apk' and any(path.endswith('.ipk') for path in actual):
        raise ValueError('APK firmware inventory contains foreign IPK archives')
    for name, path in actual.items():
        entry = inventory[name]
        if path.stat().st_size != entry['size']:
            raise ValueError(f'Firmware manifest size mismatch: {name}')
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != entry['sha256']:
            raise ValueError(f'Firmware manifest checksum mismatch: {name}')
    firmware = profile['firmware']
    target = binary / 'targets' / firmware['target'] / firmware['subtarget']
    sdk_name = PurePosixPath(urlsplit(profile['sdk']['url']).path).name
    sdk = target / sdk_name
    candidates = sorted(target.glob('*sdk*.tar.*'))
    if len(candidates) != 1 or candidates[0] != sdk or sdk.relative_to(raw).as_posix() not in inventory:
        raise ValueError('Firmware inventory must contain exactly one matching profile SDK archive')
    if inventory[sdk.relative_to(raw).as_posix()]['sha256'] != profile['sdk']['sha256']:
        raise ValueError('Firmware SDK archive checksum differs from the generated profile')
    if profile.get('channel'):
        from firmware_layouts import collect_firmware_assets
        collect_firmware_assets(raw, profile, manifest)
    else:
        images = list(target.glob('*-xiaomi_redmi-router-ax6000-stock-squashfs-sysupgrade.bin'))
        if len(images) != 1 or images[0].relative_to(raw).as_posix() not in inventory:
            raise ValueError('Firmware inventory must contain exactly one recorded stock sysupgrade image')


def validate_metadata(raw, expected_profile, *, expected_producer_commit=None):
    profile_path = raw / 'profile.json'
    profile = read_json(profile_path)
    lock = read_json(raw / 'lock.json')
    expected = read_json(expected_profile)
    prepare.validate(profile, lock)
    actual_manager = profile.get('package_manager', 'opkg')
    if actual_manager not in ('opkg', 'apk') or actual_manager != expected.get('package_manager', 'opkg'):
        raise ValueError('Imported package manager differs from source profile')
    if actual_manager == 'apk':
        if (profile.get('apk_key_sha256') != expected.get('apk_key_sha256')
                or not re.fullmatch(r'[a-f0-9]{64}', profile.get('apk_key_sha256', ''))):
            raise ValueError('Imported APK public key differs from source profile')
    for field in ('repository', 'commit', 'device', 'target', 'subtarget', 'architecture'):
        if profile['firmware'].get(field) != expected['firmware'].get(field):
            raise ValueError(f'Imported firmware {field} differs from the checked-in source profile')
    if profile['id'] != expected['id']:
        raise ValueError('Imported profile id differs from source profile')
    if profile.get('channel') != expected.get('channel'):
        raise ValueError('Imported channel differs from source profile')
    if profile.get('channel'):
        for field in ('publication', 'build_source', 'exclude_asu', 'mediatek_mesh'):
            if profile.get(field) != expected.get(field):
                raise ValueError(f'Imported {field} differs from source profile')
        if profile['firmware'].get('devices') != expected['firmware'].get('devices'):
            raise ValueError('Imported firmware layouts differ from source profile')
    expected_abi = expected['firmware'].get('kernel_version')
    if expected_abi is not None and profile['firmware']['kernel_version'] != expected_abi:
        raise ValueError('Imported firmware kernel ABI differs from source profile')
    if lock.get('schema_version') != 1 or lock.get('profile_id') != profile['id']:
        raise ValueError('Invalid release lock identity')
    if lock.get('profile_sha256') != hashlib.sha256(profile_path.read_bytes()).hexdigest():
        raise ValueError('Release lock does not match profile checksum')
    if lock.get('firmware') != profile['firmware']:
        raise ValueError('Release lock firmware differs from profile')
    if lock.get('sdk') != profile['sdk']:
        raise ValueError('Release lock SDK differs from profile')
    if actual_manager == 'apk' and (lock.get('package_manager') != 'apk'
            or lock.get('apk_key_sha256') != profile['apk_key_sha256']):
        raise ValueError('Release lock APK manager/key differs from profile')
    if lock.get('feeds', {}).get('base') != profile['firmware']['commit']:
        raise ValueError('Release lock base feed differs from firmware source commit')
    manifest = read_json(raw / 'firmware-manifest.json')
    if expected_producer_commit is not None:
        if (not isinstance(expected_producer_commit, str) or not re.fullmatch('[0-9a-f]{40}', expected_producer_commit)
                or manifest.get('recipe_commit') != expected_producer_commit
                or profile.get('asu') != expected.get('asu')):
            raise ValueError('Imported native producer or ASU policy differs from authenticated producer profile')
    if actual_manager == 'apk' and manifest.get('package_manager') != 'apk':
        raise ValueError('Release firmware manifest package manager differs from profile')
    if actual_manager == 'apk' and manifest.get('apk_key_sha256') != profile['apk_key_sha256']:
        raise ValueError('Release firmware manifest APK key differs from profile')
    if (manifest.get('source_commit') != profile['firmware']['commit'] or
            manifest.get('kernel_version') != profile['firmware']['kernel_version']):
        raise ValueError('Release firmware manifest source or kernel ABI differs from profile')
    if profile.get('channel') and (manifest.get('channel') != profile['channel']
            or manifest.get('build_id') != profile['build_id']
            or manifest.get('devices') != profile['firmware']['devices']):
        raise ValueError('Release firmware manifest channel, build or layouts differ from profile')
    validate_inventory(raw, profile, manifest)
    return {'profile': profile, 'lock': lock, 'manifest': manifest}


def import_bundle(archive, checksum, output, expected_profile, *, max_bytes=8 * 1024 ** 3, expected_producer_commit=None):
    archive, checksum, output = Path(archive), Path(checksum), Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('Import output must be a fresh directory')
    if checksum.stat().st_size > 1024:
        raise ValueError('Invalid release checksum file')
    match = re.fullmatch(r'([0-9a-fA-F]{64})[ \t]+\*?raw\.tar\.zst\n?', checksum.read_text())
    if not match:
        raise ValueError('Release checksum must contain exactly one raw.tar.zst entry')
    with archive.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != match[1].lower():
        raise ValueError('Release archive checksum mismatch')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.release-import-', dir=output.parent))
    process = None
    try:
        process = subprocess.Popen(['zstd', '--decompress', '--stdout', '--', str(archive)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        seen = set()
        total = 0
        with tarfile.open(fileobj=process.stdout, mode='r|') as bundle:
            for count, member in enumerate(bundle, 1):
                if count > 100000:
                    raise ValueError('Release archive exceeds member limit')
                name = PurePosixPath(member.name)
                if (name.is_absolute() or '..' in name.parts or '\\' in member.name or
                        '\x00' in member.name):
                    raise ValueError(f'Unsafe release archive path: {member.name}')
                if not member.isdir() and not member.isreg():
                    raise ValueError(f'Release archive links and special files are forbidden: {member.name}')
                if not name.parts:
                    if member.isdir():
                        continue
                    raise ValueError('Release archive root must be a directory')
                canonical = name.as_posix()
                if canonical in seen:
                    raise ValueError(f'Release archive has duplicate path: {canonical}')
                seen.add(canonical)
                total += member.size
                if member.size < 0 or total > max_bytes:
                    raise ValueError('Release archive exceeds unpacked size limit')
                destination = temporary.joinpath(*name.parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.extractfile(member) as source, destination.open('xb') as target:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                    destination.chmod(0o644)
        process.stdout.close()
        error = process.communicate()[1]
        if process.returncode:
            raise ValueError('Release zstd decompression failed: ' + error.decode(errors='replace')[:500])
        validate_metadata(temporary, Path(expected_profile), expected_producer_commit=expected_producer_commit)
        temporary.rename(output)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.communicate()
        if process is not None:
            process.stdout.close()
            process.stderr.close()
        if temporary.exists():
            shutil.rmtree(temporary)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--checksum', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--expected-profile', type=Path)
    parser.add_argument('--expected-producer-commit', help='Exact producer authenticated by immutable generation transport')
    parser.add_argument('--release-metadata', type=Path)
    parser.add_argument('--previous-release-metadata', type=Path)
    args = parser.parse_args()
    try:
        if args.release_metadata:
            identity = release_identity(read_json(args.release_metadata))
            if (args.previous_release_metadata and
                    identity != release_identity(read_json(args.previous_release_metadata))):
                raise ValueError('Release changed during download; use a new immutable release')
            print('Verified immutable release and build assets')
            return
        if args.previous_release_metadata:
            parser.error('--previous-release-metadata requires --release-metadata')
        if not all((args.archive, args.checksum, args.output, args.expected_profile)):
            parser.error('import requires --archive, --checksum, --output and --expected-profile')
        import_bundle(args.archive, args.checksum, args.output, args.expected_profile,
                      expected_producer_commit=args.expected_producer_commit)
    except (ValueError, OSError, tarfile.TarError) as error:
        parser.exit(1, f'import-release: {error}\n')
    print(f'Imported validated raw build into {args.output}')


if __name__ == '__main__':
    main()
