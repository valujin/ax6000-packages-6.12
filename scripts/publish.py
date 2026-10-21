#!/usr/bin/env python3
"""Validate native packages and publish a signed cohort feed. Never rewrite kernel dependencies."""
import argparse
import base64
import gzip
import hashlib
import html
import importlib.util
from functools import lru_cache
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit


@lru_cache(maxsize=1)
def package_format():
    spec = importlib.util.spec_from_file_location('publisher_package_format', Path(__file__).with_name('package_format.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


PROTECTED = {'kernel', 'libc', 'base-files', 'busybox', 'opkg'}
APK_PROTECTED = PROTECTED | {'apk', 'apk-openssl', 'apk-mbedtls', 'libgcc', 'libstdcpp',
                             'libpthread', 'librt', 'libatomic', 'musl', 'openwrt-keyring', 'usign'}
APK_CORE_ABIS = {'libgcc': '1', 'libstdcpp': '6', 'libatomic': '1'}
# Compatibility providers are tied to their actual native package base; they
# do not become globally allowed essential/provider names.
APK_COMPAT_PROVIDERS = {'openwrt-keyring': {'lede-keyring'}}


def native_provider_names(control, profile):
    """Only pinned-source essential names and their declared, known ABI aliases."""
    base = control.get('Base-Package', control.get('Package'))
    name = control.get('Package')
    if base not in APK_PROTECTED:
        raise ValueError('Native provider is outside the essential package allowlist')
    abi = control.get('ABIVersion', '')
    if abi and APK_CORE_ABIS.get(base) != abi:
        raise ValueError('Unknown native essential package ABI alias')
    if name != base + abi or control.get('APK-Name', name) != name:
        raise ValueError('Native essential package name/ABI mismatch')
    validate_package(control, profile)
    if base == 'kernel' and control['Version'] != profile['firmware']['kernel_version']:
        raise ValueError('Native kernel provider ABI mismatch')
    allowed = APK_PROTECTED | {key + value for key, value in APK_CORE_ABIS.items()}
    names = {name, base}
    for token in control.get('Provides', '').split(','):
        if not token.strip():
            continue
        match = re.fullmatch(r'\s*(@?[A-Za-z0-9_.+:-]+)(?:\s*\([<>=~]+\s+[^\s()]+\))?\s*', token)
        if match is None:
            raise ValueError('Malformed native essential provider')
        provided = match[1]
        normalized = provided.removeprefix('@').removesuffix('-any')
        if normalized not in allowed and provided not in APK_COMPAT_PROVIDERS.get(base, set()):
            raise ValueError('Native essential package provides an unrelated name')
        names.add(provided)
    return names


def native_provider_inventory(profile, controls):
    records = []
    names = set()
    for path, control in controls:
        native_provider_names(control, profile)
        if path.name!=control['Package']+'-'+control['Version']+'.apk' or not re.fullmatch(r'[A-Za-z0-9_.+~-]+\.apk',path.name):
            raise ValueError('Native essential APK filename differs from its control')
        if control['Package'] in names:
            raise ValueError('Duplicate native essential package')
        names.add(control['Package'])
        fields = {key: control[key] for key in ('Package', 'Base-Package', 'APK-Name', 'ABIVersion',
                   'Version', 'Architecture', 'Provides') if key in control}
        fields.update(Filename=path.name, Size=str(path.stat().st_size), SHA256sum=sha256_file(path))
        records.append(fields)
    return {'schema_version': 1, 'kind': 'native-providers', 'profile_id': profile['id'],
            'build_id': profile.get('build_id'), 'sdk_sha256': profile.get('sdk', {}).get('sha256'),
            'kernel_version': profile['firmware']['kernel_version'],
            'architecture': profile['firmware']['architecture'], 'packages': records}


def protected_package(control, profile):
    protected = APK_PROTECTED if package_format().manager(profile) == 'apk' else PROTECTED
    names = {control['Package'], control.get('Base-Package', control['Package'])}
    names.update(re.findall(r'(?:^|,)\s*([A-Za-z0-9_.+-]+)', control.get('Provides', '')))
    if package_format().manager(profile) == 'apk':
        protected = protected | {key + value for key, value in APK_CORE_ABIS.items()}
        names.update(name.removesuffix('-any') for name in list(names))
    return bool(names & protected)


def index_control(control):
    # The raw ADB object is compared separately, never interpolated into a text index.
    return {k: v for k, v in control.items() if k != 'APK-Raw'}


def sha256_file(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def firmware_build_id(profile):
    commit = profile['firmware']['commit']
    if not re.fullmatch(r'[a-fA-F0-9]{40}', commit):
        raise ValueError('Invalid firmware source commit')
    prefix = profile['id'] + '-' + commit[:12]
    build_id = profile.get('build_id', prefix)
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,127}', build_id):
        raise ValueError('Invalid firmware build id')
    if 'build_id' in profile:
        digest = profile.get('sdk', {}).get('sha256', '')
        if not re.fullmatch(r'[a-f0-9]{64}', digest) or build_id != prefix + '-' + digest[:12]:
            raise ValueError('Firmware build id must identify the exact SDK checksum')
    return build_id


def read_control(path, apk=None):
    """Compatibility entry point backed by the common native package reader."""
    return package_format().read_control(path, apk=apk)


def validate_package(control, profile):
    for field in ('Package', 'Version', 'Architecture'):
        if not control.get(field):
            raise ValueError(f'Missing {field}')
    if not re.fullmatch(r'[A-Za-z0-9_.+\-]+', control['Package']):
        raise ValueError('Invalid package name')
    firmware = profile['firmware']
    if control['Architecture'] not in (firmware['architecture'], 'all', 'noarch'):
        raise ValueError(f"Wrong architecture for {control['Package']}: {control['Architecture']}")
    deps = control.get('Depends', '')
    kernel = re.findall(r'(?:^|,)\s*kernel\s*\(\s*=\s*([^\s)]+)\s*\)', deps)
    if control['Package'].startswith('kmod-') or re.search(r'(?:^|,)\s*kernel\b', deps):
        expected = firmware['kernel_version']
        if kernel != [expected]:
            raise ValueError(f"kernel ABI mismatch for {control['Package']}: {kernel!r}; expected {expected}")
        if control['Architecture'] != firmware['architecture']:
            raise ValueError('Kernel modules require target architecture')


def validate_apk_key(profile, public_key):
    if public_key is None or not Path(public_key).is_file() or Path(public_key).is_symlink():
        raise ValueError('APK requires an explicit pinned public PEM key')
    if profile.get('apk_key_sha256') != sha256_file(Path(public_key)):
        raise ValueError('APK public key differs from authenticated profile checksum')
    subprocess.run(['openssl', 'pkey', '-pubin', '-in', str(public_key), '-noout'],
                   check=True, capture_output=True, timeout=30)


def validate_apk_signer(profile, key, public_key):
    validate_apk_key(profile, public_key)
    if key is None or not Path(key).is_file() or Path(key).is_symlink():
        raise ValueError('APK signing requires an explicit private key')
    derived = subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'], timeout=30)
    trusted = subprocess.check_output(['openssl', 'pkey', '-pubin', '-in', str(public_key), '-outform', 'DER'], timeout=30)
    if derived != trusted:
        raise ValueError('APK signing key differs from pinned public key')


def verify_apk_index(feed, profile, apk, public_key, controls=None):
    """Authenticate ADB, then reproduce its complete inventory from archive bytes.

    APK's native identity is a metadata digest rather than whole-file SHA256.
    Native verify checks payload integrity; the signed audit index additionally
    binds every whole-file SHA256. Re-indexing checks all ADB metadata and hashes.
    """
    validate_apk_key(profile, public_key)
    fmt = package_format()
    if apk is None:
        raise ValueError('trusted host apk binary is required')
    apk = str(Path(apk).resolve())
    feed = Path(feed)
    packages = sorted(feed.glob('*.apk'))
    if not packages:
        raise ValueError('Empty APK repository')
    with tempfile.TemporaryDirectory(prefix='ax6000-apk-index-') as temporary:
        work = Path(temporary)
        keys = work / 'keys'; keys.mkdir()
        shutil.copyfile(public_key, keys / 'repository-apk.pem')
        subprocess.run([apk, '--no-network', '--keys-dir', str(keys), 'verify', str(feed / 'packages.adb')],
                       check=True, capture_output=True, timeout=120)
        for path in packages:
            subprocess.run([apk, '--no-network', '--allow-untrusted', 'verify', str(path)],
                           check=True, capture_output=True, timeout=120)
        rebuilt = work / 'packages.adb'
        subprocess.run([apk, '--no-network', 'mkndx', '--allow-untrusted', '--output', str(rebuilt),
                        *map(str, packages)], check=True, capture_output=True, timeout=120)
        actual = fmt.index_info(feed / 'packages.adb', apk)
        expected = fmt.index_info(rebuilt, apk)
        if {item['Package']:item for item in actual} != {item['Package']:item for item in expected}:
            raise ValueError('Signed APK index inventory/identity differs from package archives')
        if controls is not None:
            indexed = {item['Package']: item for item in actual}
            if set(indexed) != {item['Package'] for item in controls}:
                raise ValueError('Signed APK index package inventory differs')
            for control in controls:
                info = indexed[control['Package']]['APK-Raw']
                # mkndx adds the archive length and native identity digest.
                raw = {key: value for key, value in info.items() if key not in ('file-size', 'hashes')}
                if raw != {key: value for key, value in control['APK-Raw'].items() if key not in ('file-size', 'hashes')}:
                    raise ValueError('APK index metadata differs from archive control')


def stage_feed(raw, output, profile, *, apk=None, apk_key=None, apk_public_key=None):
    if profile.get('enabled') is not True:
        raise ValueError('Profile disabled; supply matching firmware SDK first')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]*', profile['id']):
        raise ValueError('Invalid profile id')
    expected = profile['firmware']['kernel_version']
    if not re.fullmatch(r'[A-Za-z0-9.~+_-]+', expected):
        raise ValueError('Invalid kernel version')
    fmt = package_format()
    manager = fmt.manager(profile)
    suffix = fmt.suffix(profile)
    if manager == 'apk':
        if apk is not None and Path(apk).resolve().is_relative_to(Path(raw).resolve()):
            raise ValueError('Imported RAW executable is not a trusted host APK tool')
        validate_apk_signer(profile, apk_key, apk_public_key)
        if apk is None:
            raise ValueError('trusted host apk binary is required')
        if any(Path(raw).rglob('*.ipk')):
            raise ValueError('APK publication contains foreign IPK packages')
    validated = []
    native_controls = []
    names = set()
    for path in sorted(Path(raw).rglob('*.' + suffix)):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Package must be a regular file')
        control = read_control(path, apk=apk)
        if manager == 'apk':
            subprocess.run([str(Path(apk).resolve()), '--no-network', '--allow-untrusted', 'verify', str(path)],
                           check=True, capture_output=True, timeout=120)
        # A supplemental feed must never offer to replace the firmware/kernel/C library.
        if protected_package(control, profile):
            if manager == 'apk' and control.get('Base-Package') in APK_PROTECTED:
                native_controls.append((path, control))
            continue
        validate_package(control, profile)
        if control['Package'] in names:
            raise ValueError(f"Duplicate package: {control['Package']}")
        names.add(control['Package'])
        if not re.fullmatch(r'[A-Za-z0-9_.+~\-]+\.' + suffix, path.name):
            raise ValueError(f'Invalid package filename: {path.name}')
        if manager == 'apk' and path.name != control['Package'] + '-' + control['Version'] + '.apk':
            raise ValueError('APK filename differs from native name/version')
        validated.append((path, control))
    if not validated:
        raise ValueError('Build has no packages (empty feed)')
    providers = native_provider_inventory(profile, native_controls) if manager == 'apk' else None
    # Validate every archive before touching output; deployment is handled atomically by Pages.
    feed = Path(output) / 'feeds' / profile['id'] / expected
    if feed.exists():
        raise ValueError('Output feed already exists; use a fresh staging directory')
    feed.mkdir(parents=True)
    paragraphs = []
    for path, control in validated:
        target = feed / path.name
        shutil.copy2(path, target)
        fields = {k: v for k, v in index_control(control).items() if k not in ('Filename', 'Size', 'SHA256sum')}
        fields.update(Filename=path.name, Size=str(target.stat().st_size),
                      SHA256sum=sha256_file(target))
        paragraphs.append('\n'.join(f'{key}: {value}' for key, value in fields.items()))
    index = ('\n\n'.join(paragraphs) + '\n\n').encode()
    (feed / 'Packages').write_bytes(index)
    (feed / 'Packages.gz').write_bytes(gzip.compress(index, mtime=0))
    if manager == 'apk':
        subprocess.run([str(Path(apk).resolve()), '--no-network', 'mkndx', '--allow-untrusted', '--sign',
                        str(Path(apk_key).resolve()), '--output', str(feed / 'packages.adb'),
                        *[str(feed / path.name) for path, _ in validated]],
                       check=True, capture_output=True, timeout=120)
        verify_apk_index(feed, profile, apk, apk_public_key, [control for _, control in validated])
        (Path(output) / 'native-providers.json').write_text(json.dumps(providers, sort_keys=True, indent=2) + '\n')
    return feed


def stage_firmware(raw, output, profile):
    if not (Path(raw) / 'bin').is_dir():
        return None
    targets = Path(raw) / 'bin' / 'targets' / profile['firmware']['target'] / profile['firmware']['subtarget']
    if not targets.is_dir():
        return None
    build_id = firmware_build_id(profile)
    destination = Path(output) / 'firmware' / build_id
    sdk = profile.get('sdk', {})
    sdk_name = Path(urlsplit(sdk.get('url', '')).path).name
    # RAM BL2 variants and generic kernel components share BIN_DIR with device
    # images. Offer only complete stock sysupgrade/recovery images here.
    device = profile['firmware'].get('device')
    images = []
    if device == 'xiaomi_redmi-router-ax6000-stock':
        marker = '-' + device + '-'
        images = [p for p in targets.iterdir() if p.is_file() and marker in p.name
                  and (p.name.endswith(marker + 'squashfs-sysupgrade.bin')
                       or p.name.endswith(marker + 'initramfs-kernel.bin'))]
    metadata = {'config.buildinfo', 'feeds.buildinfo', 'version.buildinfo', 'profiles.json'}
    for image in images:
        prefix = image.name.split('-' + device + '-', 1)[0]
        metadata.update({prefix + '.manifest', prefix + '-' + device + '.manifest'})
    image_names = {p.name for p in images}
    files = [p for p in targets.iterdir() if p.is_file() and
             (p.name in image_names or p.name in metadata or (sdk_name and p.name == sdk_name))]
    if not files:
        return None
    for source in files:
        if source.name == sdk_name and sha256_file(source) != sdk.get('sha256'):
            raise ValueError('Firmware SDK archive does not match the published profile checksum')
    destination.mkdir(parents=True)
    for source in files:
        shutil.copy2(source, destination / source.name)
    checksums = ''.join(sha256_file(p) + '  ' + p.name + '\n' for p in sorted(destination.iterdir()))
    for filename in ('sha256sums', 'SHA256SUMS'):
        (destination / filename).write_text(checksums)
    return destination


def public_from_secret(key):
    """Decode OpenWrt usign's unencrypted Ed25519 key container.

    Format: openwrt/usign main.c struct seckey (104 bytes); the generated
    private container includes its public key. usign verifies the final index.
    """
    lines = Path(key).read_text().splitlines()
    if len(lines) != 2 or not lines[0].startswith('untrusted comment:'):
        raise ValueError('Invalid usign secret key format')
    data = base64.b64decode(lines[1], validate=True)
    if len(data) != 104 or data[:4] != b'EdBK' or data[4:8] != bytes(4):
        raise ValueError('Only unencrypted OpenWrt usign Ed25519 keys are supported')
    if hashlib.sha512(data[40:104]).digest()[:8] != data[24:32]:
        raise ValueError('Corrupted usign secret key')
    public = data[:2] + data[32:40] + data[72:104]
    return 'untrusted comment: ax6000-packages public key\n' + base64.b64encode(public).decode() + '\n'


def public_key_payload(text):
    """Compare the usign key payload, whose comment is intentionally untrusted."""
    lines = text.splitlines()
    if len(lines) != 2 or not lines[0].startswith('untrusted comment:'):
        raise ValueError('Invalid pinned public key')
    try:
        data = base64.b64decode(lines[1], validate=True)
    except ValueError as error:
        raise ValueError('Invalid pinned public key') from error
    if len(data) != 42 or data[:2] != b'Ed':
        raise ValueError('Invalid pinned public key')
    return data


def validate_external_catalog(catalog_path, signature, metadata_path, profile, public_key, usign):
    spec = importlib.util.spec_from_file_location('publisher_snapshot', Path(__file__).with_name('channel-snapshot.py'))
    snapshot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(snapshot)
    metadata = snapshot.read_json(metadata_path)
    if metadata.get('draft') is not False or metadata.get('immutable') is not True:
        raise ValueError('Firmware asset release must be immutable')
    with tempfile.TemporaryDirectory(prefix='ax6000-catalog-') as temporary:
        tree = Path(temporary)
        shutil.copyfile(catalog_path, tree / 'downloads.json')
        shutil.copyfile(signature, tree / 'downloads.sig')
        catalog = snapshot.catalog_identity(tree, profile, public_key, usign)
    release = catalog['release']
    if metadata.get('id') != release['id'] or metadata.get('tag_name') != release['tag']:
        raise ValueError('Catalog generation release identity mismatch')
    assets = {}
    for asset in metadata.get('assets', []):
        if asset.get('name') in assets or asset.get('state') != 'uploaded':
            raise ValueError('Duplicate or incomplete generation asset')
        assets[asset['name']] = asset
    for record in catalog['assets']:
        asset = assets.get(record['filename'], {})
        if (asset.get('id') != record['asset_id'] or asset.get('size') != record['size']
                or asset.get('digest') not in (None, 'sha256:' + record['sha256'])
                or asset.get('updated_at') != record['updated_at']):
            raise ValueError('Catalog asset API identity mismatch')
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--public-key', type=Path,
                        help='Require the signing secret to match this pinned usign public key')
    parser.add_argument('--usign', required=True, type=Path)
    parser.add_argument('--apk', type=Path, help='Trusted host apk-tools; never an executable from imported RAW')
    parser.add_argument('--apk-key', type=Path, help='Explicit APK signing private PEM')
    parser.add_argument('--apk-public-key', type=Path, help='Pinned APK public PEM matching profile apk_key_sha256')
    parser.add_argument('--lock', required=True, type=Path)
    parser.add_argument('--external-assets', type=Path)
    parser.add_argument('--external-assets-signature', type=Path)
    parser.add_argument('--generation-release-metadata', type=Path)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text())
    if not args.key.is_file() or not args.usign.is_file():
        raise ValueError('Signing key or SDK usign is missing')
    if args.output.exists():
        raise ValueError('Publication output must be a fresh directory')
    lock = json.loads(args.lock.read_text())
    if lock.get('profile_sha256') != hashlib.sha256(args.profile.read_bytes()).hexdigest():
        raise ValueError('Lock does not match profile')
    derived_public = public_from_secret(args.key)
    if args.public_key is not None:
        try:
            pinned_public = args.public_key.read_text()
        except (OSError, UnicodeError) as error:
            raise ValueError('Invalid pinned public key') from error
        if public_key_payload(pinned_public) != public_key_payload(derived_public):
            raise ValueError('Signing key differs from pinned public key')
    catalog = None
    external = (args.external_assets, args.external_assets_signature, args.generation_release_metadata)
    if any(external) or profile.get('channel') is not None:
        if not all(external) or args.public_key is None:
            raise ValueError('Channel publication requires signed immutable external assets and a pinned key')
        catalog = validate_external_catalog(*external, profile, args.public_key, args.usign)
    manager = package_format().manager(profile)
    if manager == 'apk' and args.apk is not None and args.apk.resolve().is_relative_to(args.input.resolve()):
        raise ValueError('Imported RAW executable is not a trusted host APK tool')
    feed = stage_feed(args.input, args.output, profile, apk=args.apk, apk_key=args.apk_key,
                      apk_public_key=args.apk_public_key)
    public_key = args.output / 'repository.pub'
    usign = str(args.usign.resolve())
    public_key.write_text(derived_public)
    subprocess.run([usign, '-S', '-m', str(feed / 'Packages'), '-s', str(args.key.resolve()),
                    '-x', str(feed / 'Packages.sig')], check=True)
    subprocess.run([usign, '-V', '-m', str(feed / 'Packages'), '-p', str(public_key),
                    '-x', str(feed / 'Packages.sig')], check=True)
    if args.public_key is not None:
        subprocess.run([usign, '-V', '-m', str(feed / 'Packages'),
                        '-p', str(args.public_key.resolve()),
                        '-x', str(feed / 'Packages.sig')], check=True)
    firmware_dir = None if catalog is not None else stage_firmware(args.input, args.output, profile)
    if catalog is not None:
        shutil.copyfile(args.external_assets, args.output / 'downloads.json')
        shutil.copyfile(args.external_assets_signature, args.output / 'downloads.sig')
    state = args.output / 'state'
    state.mkdir()
    shutil.copy2(args.lock, state / 'lock.json')
    # The lock fingerprints these exact bytes; snapshots must preserve that identity.
    shutil.copyfile(args.profile, args.output / 'profile.json')
    if manager == 'apk':
        shutil.copyfile(args.apk_public_key, args.output / 'repository-apk.pem')
        subprocess.run([usign, '-S', '-m', str(args.output / 'profile.json'), '-s', str(args.key.resolve()),
                        '-x', str(args.output / 'profile.sig')], check=True)
        subprocess.run([usign, '-V', '-m', str(args.output / 'profile.json'), '-p', str(public_key),
                        '-x', str(args.output / 'profile.sig')], check=True)
    for name in ('build-selection.json', 'build-provenance.json', 'firmware-manifest.json', 'build.config'):
        if (args.input / name).is_file():
            shutil.copy2(args.input / name, args.output / name)
    (args.output / '.nojekyll').touch()
    downloads = ''
    if catalog is not None:
        downloads = '<ul>' + ''.join(
            f'<li>{html.escape(record.get("layout") or record["kind"])}: '
            f'<a href="{html.escape(record["url"], quote=True)}">{html.escape(record["filename"])}</a>'
            f' (SHA256 {record["sha256"]})</li>' for record in catalog['assets']) + '</ul>'
    if firmware_dir:
        downloads = '<ul>' + ''.join(
            f'<li><a href="{html.escape(p.relative_to(args.output).as_posix(), quote=True)}">'
            f'{html.escape(p.name)}</a></li>'
            for p in sorted(firmware_dir.iterdir()) if p.is_file()
        ) + '</ul>'
    (args.output / 'index.html').write_text('<!doctype html><meta charset="utf-8"><title>AX6000 packages</title>'
        f'<h1>AX6000 packages</h1><p>Signed supplemental {manager} repository.</p>'
        '<p><a href="profile.json">Firmware compatibility</a> · '
        '<a href="repository.pub">Signing public key</a> · '
        '<a href="state/lock.json">Source versions</a></p>'
        f'<p><a href="{feed.relative_to(args.output).as_posix()}/{"packages.adb" if manager == "apk" else "Packages"}">Package index</a></p>' +
        (f'<p>Kernel ABI: <code>{html.escape(profile["firmware"]["kernel_version"])}</code></p>'
         '<p>Firmware and SDK for Redmi AX6000 stock layout. Install the matching firmware '
         'before using these kernel modules.</p>' + downloads if firmware_dir else downloads))
    print(f'Validated and signed feed: {feed}')


if __name__ == '__main__':
    main()
