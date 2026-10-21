#!/usr/bin/env python3
"""Verify three native AX6000 sysupgrades against a trusted completed source tree.

Read-only inputs; bounded inspection files and JSON evidence are the only outputs.
This verifies payloads and SDK identity, not hardware boot or flash suitability.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import resource
import selectors
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
import zlib

from fit_payload import MIB, cell, extract_fit, read_fdt, require, stringlist, text
import stock_factory
import package_format
import apk_world
import image_features
import host_apk_bundle

PINS = {'recommended': 'ae65e1de69971b5a2e3cf7e39390ee93f274d488',
        'latest': 'a99b0888b88f134f56bcb2a7d93027b5d20638a9'}
DEVICES = {layout: 'xiaomi_redmi-router-ax6000-' + layout
           for layout in ('stock', 'mtkuboot', 'ubootmod')}
PARTITIONS = {'stock': {'ubi_kernel': (0x600000, 0x1e00000), 'ubi': (0x2400000, 0x5000000)},
              'mtkuboot': {'ubi': (0x600000, 0x6e00000)},
              'ubootmod': {'ubi': (0x580000, 0x7a80000)}}
VENDOR = {'kmod-mt_wifi', 'kmod-conninfra', 'kmod-warp', 'kmod-mediatek_hnat'}
UCODE = {'mtwifi-cfg-ucode', 'iwinfo-ucode', 'wifi-scripts', 'ucode-mod-datconf',
         'ucode-mod-l1parser', 'ucode-mod-iwinfo', 'ucode-mod-fs', 'ucode-mod-log',
         'ucode-mod-ubus', 'ucode-mod-uci'}
CONTEXTS = ('.config', '.config.set', '.vermagic', 'Module.symvers',
            'modules.builtin.modinfo', 'include/config/kernel.release', 'include/generated/autoconf.h')
DISTFEEDS = (b'# Packages for this firmware require its exact kernel ABI.\n'
             b'# Connect the signed matching repository with ax6000-install-feed.\n'
             b'# Moving official snapshot feeds are deliberately not configured.\n')


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path, cap, *, allow_empty=False):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), f'Input is not a regular file: {path}')
    require((0 if allow_empty else 1) <= path.stat().st_size <= cap, f'Input byte cap exceeded: {path}')
    return path


def safe_path(root, relative):
    require(isinstance(relative, str), 'Unsafe relative path type')
    p = PurePosixPath(relative)
    require(p.parts and not p.is_absolute() and '..' not in p.parts and '\x00' not in relative,
            f'Unsafe relative path: {relative}')
    target = Path(root) / p
    require(target.resolve().is_relative_to(Path(root).resolve()), f'Unsafe path escapes root: {relative}')
    require(not any(t.is_symlink() for t in (target, *target.parents) if t != Path(root)
                    and t.is_relative_to(Path(root))), f'Unsafe symlink path: {relative}')
    return target


def json_bytes(data):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, f'Duplicate JSON key: {key}')
            obj[key] = value
        return obj
    return json.loads(data, object_pairs_hook=unique)


def read_json(path, cap=16 * MIB):
    return json_bytes(regular(path, cap).read_bytes())


def child_limits(file_cap=None):
    resource.setrlimit(resource.RLIMIT_AS, (512 * MIB, 512 * MIB))
    resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
    if file_cap:
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_cap, file_cap))
    if hasattr(os, 'sched_getaffinity'):
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})


def run_bounded(command, cap, *, timeout=60, destination=None, file_cap=None):
    """Bound stdout during execution, including a silent/hung subprocess."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               preexec_fn=lambda: child_limits(file_cap))
    output = destination.open('xb') if destination else io.BytesIO()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    count, deadline = 0, time.monotonic() + timeout
    try:
        while selector.get_map():
            require(time.monotonic() < deadline, 'Trusted tool timeout')
            for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, min(MIB, cap - count + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                count += len(chunk)
                require(count <= cap, 'Trusted tool stdout byte cap exceeded')
                output.write(chunk)
        require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                f'Trusted tool failed: {Path(command[0]).name}')
        return count if destination else output.getvalue()
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        output.close()


def copy_member(stream, output, length):
    with output.open('wb') as dest:
        while length:
            chunk = stream.read(min(length, MIB))
            require(bool(chunk), 'Truncated archive payload')
            dest.write(chunk)
            length -= len(chunk)


def extract_tar(path, layout, work):
    require(layout in ('stock', 'mtkuboot'), 'Wrong layout for TAR sysupgrade')
    prefix = 'sysupgrade-' + DEVICES[layout]
    allowed = {prefix, prefix + '/CONTROL', prefix + '/kernel', prefix + '/root'}
    found, payloads, last = set(), {}, 0
    with tarfile.open(path, 'r:') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            require(name not in found, 'Duplicate sysupgrade TAR member')
            found.add(name)
            require(len(found) <= 4 and name in allowed and not member.pax_headers,
                    'Unsafe/unexpected sysupgrade TAR member')
            require(member.sparse is None, 'Sparse sysupgrade TAR member')
            if name == prefix:
                require(member.isdir() and member.size == 0, 'Invalid TAR root directory')
            else:
                require(member.isfile(), 'Nonregular sysupgrade TAR payload')
                role = name.split('/')[-1]
                bound = {'CONTROL': 4096, 'kernel': 0x1e00000,
                         'root': 0x5000000 if layout == 'stock' else 0x6e00000}[role]
                require(0 < member.size < bound, f'{layout} {role} partition byte cap exceeded')
                with archive.extractfile(member) as stream:
                    if role == 'CONTROL':
                        require(stream.read(4097) == ('BOARD=' + DEVICES[layout] + '\n').encode(),
                                'Sysupgrade CONTROL board differs')
                    else:
                        payloads[role] = Path(work) / (role + '.tar-payload')
                        copy_member(stream, payloads[role], member.size)
            last = max(last, member.offset_data + ((member.size + 511) // 512) * 512)
    require(found == allowed and set(payloads) == {'kernel', 'root'}, 'Missing sysupgrade TAR payload')
    with Path(path).open('rb') as stream:
        stream.seek(last)
        first = stream.read(1024)
        require(first == b'\0' * 1024, 'Missing canonical sysupgrade TAR end markers')
        while chunk := stream.read(MIB):
            require(not any(chunk), 'Nonzero trailing sysupgrade TAR bytes')
    if layout == 'mtkuboot':
        require(sum(p.stat().st_size for p in payloads.values()) < 0x6e00000,
                'MTK U-Boot combined payload partition cap exceeded')
    require(payloads['root'].stat().st_size % 1024 == 0, 'Non-native TAR root alignment')
    return payloads


def verify_kernel(path, compression, expected, output, cap=64 * MIB):
    require(compression in ('gzip', 'lzma'), 'Unsupported kernel compression')
    decoder = (zlib.decompressobj(16 + zlib.MAX_WBITS) if compression == 'gzip' else
               lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=256 * MIB))
    count = 0
    with Path(path).open('rb') as stream, Path(output).open('wb') as dest:
        while chunk := stream.read(64 * 1024):
            require(not decoder.eof, 'Compressed kernel has trailing data')
            pending = chunk
            while True:
                decoded = decoder.decompress(pending, max_length=min(MIB, cap - count + 1))
                count += len(decoded)
                require(count <= cap, 'Uncompressed kernel byte cap exceeded')
                dest.write(decoded)
                if decoder.eof:
                    require(not decoder.unused_data, 'Compressed kernel has trailing data')
                    break
                if compression == 'gzip':
                    pending = decoder.unconsumed_tail
                    if not pending:
                        break
                else:
                    if decoder.needs_input:
                        break
                    pending = b''
        require(decoder.eof, 'Truncated compressed kernel')
    with Path(output).open('rb') as stream:
        header = stream.read(64)
    require(len(header) == 64 and header[56:60] == b'ARM\x64', 'Not an ARM64 Linux Image')
    regular(expected, cap)
    actual = sha256(output)
    require(count == Path(expected).stat().st_size and actual == sha256(expected),
            'Sysupgrade kernel differs from trusted KDIR/Image snapshot')
    return {'size': count, 'sha256': actual, 'expected_input': str(expected),
            'capture_stage': 'Kernel/CompileImage/Default -> Kernel/CopyImage before Initramfs'}


def verify_dtb(path, layout):
    tree = read_fdt(path, 256 * 1024)
    compatible = stringlist(tree.nodes['/'].get('compatible', b''))
    expected = 'xiaomi,redmi-router-ax6000-' + layout
    require(expected in compatible and 'mediatek,mt7986a' in compatible
            and not any('redmi-router-ax6000-' in v and v != expected for v in compatible),
            'Nested DTB compatible differs from layout')
    geometry, nodes = {}, {}
    for name, properties in tree.nodes.items():
        if 'label' not in properties:
            continue
        label = text(properties['label'])
        if label not in ('ubi', 'ubi_kernel'):
            continue
        require(label not in geometry and len(properties.get('reg', b'')) == 8,
                'Duplicate/invalid nested DTB partition geometry')
        geometry[label] = struct.unpack('>II', properties['reg'])
        nodes[label] = name
    require(geometry == PARTITIONS[layout], 'Nested DTB partition geometry differs')
    if layout == 'ubootmod':
        chosen = tree.nodes.get('/chosen', {})
        require('root=/dev/fit0' in text(chosen.get('bootargs-append', b'')), 'DTB FIT root bootargs differ')
        handle = cell(chosen.get('rootdisk', b''))
        matches = [(n, p) for n, p in tree.nodes.items() if 'phandle' in p and cell(p['phandle']) == handle]
        require(len(matches) == 1 and matches[0][0].startswith(nodes['ubi'] + '/volumes/')
                and text(matches[0][1].get('volname', b'')) == 'fit', 'DTB rootdisk does not point at FIT UBI volume')
    return {'layout': layout, 'compatible': compatible, 'sha256': sha256(path),
            'partitions': {k: {'offset': v[0], 'size': v[1]} for k, v in geometry.items()}}


def control_fields(data):
    require(len(data) <= 4 * MIB, 'Package control byte cap exceeded')
    fields, previous = {}, None
    for line in data.decode('utf-8').splitlines():
        if line.startswith((' ', '\t')) and previous:
            fields[previous] += '\n' + line
        elif ':' in line:
            key, value = line.split(':', 1)
            require(key not in fields, 'Duplicate package control field')
            fields[key], previous = value.strip(), key
        elif line:
            raise ValueError('Malformed package control line')
    return fields


def parse_status(data):
    require(0 < len(data) <= 4 * MIB, 'Embedded opkg status byte cap exceeded')
    result = {}
    for paragraph in re.split(rb'\n\s*\n', data.strip()):
        fields = control_fields(paragraph)
        name = fields.get('Package', '')
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*', name), 'Malformed embedded Package name')
        require(name not in result, 'Duplicate embedded status Package')
        require(fields.get('Status', '').split()[-1:] == ['installed'], 'Embedded package Status is not installed')
        require(fields.get('Version') and fields.get('Architecture'), 'Embedded package lacks Version/Architecture')
        result[name] = fields
    return result


def file_mode(listing, path):
    pattern = rb'^(\S+)\s+[^\n]*\s+squashfs-root/' + re.escape(path.encode()) + rb'$'
    modes = re.findall(pattern, listing, re.M)
    require(len(modes) == 1, f'Ambiguous/absent SquashFS file listing: {path}')
    return modes[0].decode('ascii')


def require_mode(listing, path, mode):
    if mode is None:
        actual = file_mode(listing, path)
        require(len(actual) == 10 and actual.startswith('-') and actual[5] != 'w' and actual[8] != 'w',
                'SquashFS feature file must be regular without group/other write: ' + path)
        return
    expected = {0o755: '-rwxr-xr-x', 0o644: '-rw-r--r--', 0o600: '-rw-------'}[mode]
    require(file_mode(listing, path) == expected, f'SquashFS {path} must be regular with mode {mode:04o}')


def squash_read(binary, root, path, cap=4096, listing=False):
    return run_bounded([str(binary), '-processors', '1', '-data-queue', '8', '-frag-queue', '8',
                        '-no-wildcards', '-lln' if listing else '-cat', str(root), path], cap)


def repository_expected(repo, profile):
    if profile.get('package_manager', 'opkg') == 'apk':
        return apk_repository_expected(repo, profile)
    public = regular(repo / 'keys/repository.pub', 4096).read_bytes()
    lines = public.decode('ascii').splitlines()
    require(len(lines) == 2 and lines[0].startswith('untrusted comment:'), 'Invalid trusted repository key')
    key = base64.b64decode(lines[1], validate=True)
    require(len(key) == 42 and key[:2] == b'Ed', 'Invalid trusted usign public key')
    fingerprint = key[2:10].hex()
    installer = regular(repo / 'scripts/install-feed.sh', 16 * 1024).read_bytes()
    require(b'expected_fingerprint=' + fingerprint.encode() + b'\n' in installer,
            'Trusted installer and key fingerprint differ')
    site = 'https://valujin.github.io/ax6000-packages-6.12'
    require(profile.get('publication', {}).get('site_url') == site, 'Unexpected 6.12 publication site')
    url = site + '/channels/' + profile['channel']
    require(profile.get('build_source', {}).get('publication_url') == url, 'Channel publication URL differs')
    installer, count = re.subn(rb'^base=\$\{PACKAGE_REPOSITORY_URL:-[^\n}]+\}$',
                             b'base=${PACKAGE_REPOSITORY_URL:-' + url.encode() + b'}', installer, flags=re.M)
    require(count == 1, 'Cannot independently render trusted channel installer')
    return {'etc/opkg/distfeeds.conf': (DISTFEEDS, 0o644),
            'etc/opkg/keys/' + fingerprint: (public, 0o644),
            'usr/sbin/ax6000-install-feed': (installer, 0o755)}, fingerprint


def apk_repository_expected(repo, profile):
    require(package_format.manager(profile) == 'apk', 'APK repository renderer requires explicit APK cohort')
    public = regular(repo / 'keys/repository-apk.pem', 4096).read_bytes()
    digest = hashlib.sha256(public).hexdigest()
    require(digest == profile.get('apk_key_sha256') and public.startswith(b'-----BEGIN PUBLIC KEY-----\n')
            and public.endswith(b'-----END PUBLIC KEY-----\n'), 'Trusted APK public key/profile differs')
    metadata_public = regular(repo / 'keys/repository.pub', 4096).read_bytes()
    lines = metadata_public.decode('ascii').splitlines()
    require(len(lines) == 2 and lines[0].startswith('untrusted comment:'), 'Invalid trusted catalog public key')
    decoded = base64.b64decode(lines[1], validate=True)
    require(len(decoded) == 42 and decoded[:2] == b'Ed', 'Invalid trusted catalog key bytes')
    fingerprint = decoded[2:10].hex()
    installer = regular(repo / 'scripts/install-feed-apk.sh', 32 * 1024).read_bytes()
    require(b'expected_fingerprint=' + fingerprint.encode() + b'\n' in installer
            and b'expected_apk_sha256=' + digest.encode() + b'\n' in installer,
            'Trusted APK installer/key fingerprints differ')
    site = 'https://valujin.github.io/ax6000-packages-6.12'
    require(profile.get('publication', {}).get('site_url') == site, 'Unexpected APK publication site')
    url = site + '/channels/' + profile['channel']
    require(profile.get('build_source', {}).get('publication_url') == url, 'APK channel publication URL differs')
    before = b'base=${PACKAGE_REPOSITORY_URL:-' + site.encode() + b'/channels/recommended}'
    require(installer.count(before) == 1, 'Trusted APK installer default anchor differs')
    installer = installer.replace(before, b'base=${PACKAGE_REPOSITORY_URL:-' + url.encode() + b'}')
    feeds = (b'# Public userspace packages; explicitly select with @public.\n'
             b'# Core, kernel and vendor packages stay bound to this image.\n')
    feeds += b''.join(b'@public https://downloads.immortalwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/'
                      + feed.encode() + b'/packages.adb\n' for feed in
                      ('base', 'luci', 'packages', 'routing', 'telephony'))
    return {'etc/apk/repositories.d/distfeeds.list': (feeds, 0o644),
            'etc/apk/repositories.d/customfeeds.list':
                (b'# The signed matching AX6000 APK repository is installed by ax6000-install-feed.\n', 0o644),
            'etc/apk/keys/repository-apk.pem': (public, 0o644),
            'etc/ax6000/repository.pub': (metadata_public, 0o644),
            'usr/sbin/ax6000-install-feed': (installer, 0o755)}, fingerprint


def package_contents(path, *, payload=False, apk=None):
    if Path(path).suffix == '.ipk':
        return ipk_contents(path, payload=payload)
    regular(path, 128 * MIB)
    control = package_format.read_control(path, apk=apk)
    files = package_format.payload_files(path, apk=apk) if payload else {}
    return control, files


def trusted_apk_argument(value, raw):
    require(value, 'APK verification requires explicit --apk trusted HOST tool')
    path = regular(Path(value).absolute(), 64 * MIB)
    require(not path.resolve().is_relative_to(raw) and os.access(path, os.X_OK),
            'Never execute an APK tool from untrusted raw artifacts')
    with path.open('rb') as stream:
        header = stream.read(20)
    require(header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\x3e\x00',
            'APK inspection requires an x86_64 HOST ELF executable')
    version = run_bounded([str(path), '--version'], 4096).decode('ascii')
    require('apk-tools 3.0.5' in version and 'x86_64' in version, 'Unapproved host APK version/architecture')
    return path


def apk_root_policy(binary, root, profile, installed, actual_paths, source, apk):
    require(source is not None and apk is not None, 'APK root inspection requires trusted source and host APK')
    require('usr/lib/opkg/status' not in actual_paths and not any(p.startswith('usr/lib/opkg/info/') for p in actual_paths),
            'APK image retains OPKG database/metadata')
    require(not any(name in actual_paths for name in ('bin/opkg', 'usr/bin/opkg')), 'APK image retains OPKG executable')
    require_mode(squash_read(binary, root, 'usr/bin/apk', listing=True), 'usr/bin/apk', 0o755)
    configurations = {name for name in actual_paths if name.startswith('etc/apk/repositories.d/') and name.endswith('.list')}
    if 'etc/apk/repositories' in actual_paths:
        configurations.add('etc/apk/repositories')
    require({'etc/apk/repositories.d/distfeeds.list', 'etc/apk/repositories.d/customfeeds.list'} <= configurations
            and len(configurations) <= 16, 'Cannot enumerate APK repository configuration')
    expected_public, _ = apk_repository_expected(Path(__file__).resolve().parents[1], profile)
    expected_lines = [line for line in expected_public['etc/apk/repositories.d/distfeeds.list'][0].splitlines()
                      if line and not line.startswith(b'#')]
    active = []
    for path in configurations:
        data = squash_read(binary, root, path, 32 * 1024)
        rows = [line.strip() for line in data.splitlines() if line.strip() and not line.lstrip().startswith(b'#')]
        require(not rows or path == 'etc/apk/repositories.d/distfeeds.list', 'APK image enables an unreviewed repository')
        active.extend(rows)
    require(active == expected_lines, 'APK public repositories differ from reviewed tagged userspace list')
    known = {'etc/apk/keys/immortalwrt-25.12.pem': 'c0da9b5747f3fb16ea64fa37acda4df3723ac22ec30ca0dc6f5c89efc0161f1f',
             'etc/apk/keys/openwrt-25.12.pem': '27d61d827d64ccf2f46dce5f52aec6279404d4a00686dafb22f52f3b4ee675f8'}
    for path, digest in known.items():
        data = squash_read(binary, root, path, 4096)
        require(hashlib.sha256(data).hexdigest() == digest, 'APK official keyring public key differs: ' + path)
        require_mode(squash_read(binary, root, path, listing=True), path, 0o644)
    keys = [name for name in actual_paths if name.startswith('etc/apk/keys/') and name.endswith('.pem')]
    require(3 <= len(keys) <= 16, 'APK key directory inventory differs')
    native_public = regular(Path(source) / 'public-key.pem', 4096).read_bytes()
    allowed_keys = set(known.values()) | {profile['apk_key_sha256'], hashlib.sha256(native_public).hexdigest()}
    for path in keys:
        data = squash_read(binary, root, path, 4096)
        require(hashlib.sha256(data).hexdigest() in allowed_keys, 'APK image contains an unapproved signing key: ' + path)
        require(data.startswith(b'-----BEGIN PUBLIC KEY-----\n') and data.endswith(b'-----END PUBLIC KEY-----\n'),
                'APK image key is not public PEM only: ' + path)
    apk_world.configure_source(profile, Path(source), check_only=True)
    policy = apk_world.configure_policy(profile, Path(source), check_only=True)
    records = []
    for name, item in installed.items():
        records.append({'name': name, 'version': item['Version'],
                        'depends': item.get('APK-Depends', '').split(),
                        'provides': item.get('APK-Provides', '').split(),
                        'tags': ['openwrt:abiversion=' + item['ABIVersion']] if item.get('ABIVersion') else []})
    pins = apk_world.protected_packages(records, policy, apk)
    expected_pins = ''.join(name + '=' + version + '\n' for name, version in sorted(pins.items())).encode()
    protected = squash_read(binary, root, 'etc/apk/ax6000-protected.list', MIB)
    require(protected == expected_pins, 'Actual APK protected native package list differs')
    world = squash_read(binary, root, 'etc/apk/world', MIB).decode('ascii')
    require(world.endswith('\n'), 'Actual APK world is truncated')
    rows = {}; actual_pins = {}
    for line in world.splitlines():
        token = apk_world.parse_token(line, world=True)
        require(token[1] not in rows, 'Duplicate APK world constraint')
        rows[token[1]] = token
    for name, version in pins.items():
        require(rows.get(name) == (False, name, None, '=', version), 'Actual APK world lost an exact native pin: ' + name)
        actual_pins[name] = version
    return {'package_manager': 'apk', 'public_opt_in_feeds': len(active), 'protected_packages': len(pins),
            'protected_sha256': hashlib.sha256(protected).hexdigest(), 'public_keys': sorted(keys),
            'world_sha256': hashlib.sha256(world.encode()).hexdigest()}


class CappedReader:
    def __init__(self, stream, cap, deadline=None):
        self.stream, self.cap, self.count, self.deadline = stream, cap, 0, deadline

    def read(self, size=-1):
        require(size >= 0, 'Unbounded archive stream read')
        if self.deadline is not None:
            require(time.monotonic() < self.deadline, 'SDK inspection timeout')
        data = self.stream.read(min(size, self.cap - self.count + 1))
        self.count += len(data)
        require(self.count <= self.cap, 'Archive uncompressed byte cap exceeded')
        return data


def ipk_contents(path, *, payload=False):
    """Inspect native tar.gz IPKs; bound both archive layers, never extract links."""
    regular(path, 128 * MIB)
    captured, seen, declared = {}, set(), 0
    with gzip.open(path, 'rb') as raw:
        stream = CappedReader(raw, 256 * MIB)
        with tarfile.open(fileobj=stream, mode='r|') as archive:
            for member in archive:
                name = member.name.removeprefix('./')
                require(name not in seen and len(seen) < 8, 'Duplicate/excess IPK outer members')
                seen.add(name)
                require(member.isfile() and name in {'control.tar.gz', 'data.tar.gz', 'debian-binary'},
                        'Unexpected native IPK outer member')
                declared += member.size
                require(declared <= 256 * MIB, 'IPK declared byte cap exceeded')
                if name == 'control.tar.gz' or (payload and name == 'data.tar.gz'):
                    cap = 4 * MIB if name == 'control.tar.gz' else 64 * MIB
                    require(0 < member.size <= cap, 'Nested IPK compressed byte cap exceeded')
                    with archive.extractfile(member) as content:
                        captured[name] = content.read(cap + 1)
                    require(len(captured[name]) == member.size, 'Truncated IPK nested archive')
        while stream.read(MIB):
            pass
    require(seen == {'control.tar.gz', 'data.tar.gz', 'debian-binary'}, 'Incomplete native IPK')
    control, files = None, {}
    for name, data in captured.items():
        names, count, total = set(), 0, 0
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            stream = CappedReader(compressed, 128 * MIB)
            with tarfile.open(fileobj=stream, mode='r|') as archive:
                for member in archive:
                    count += 1
                    require(count <= 8192, 'Nested IPK member cap exceeded')
                    relative = member.name
                    while relative.startswith('./'):
                        relative = relative[2:]
                    if relative in ('', '.') and member.isdir():
                        continue
                    p = PurePosixPath(relative)
                    require(p.parts and not p.is_absolute() and '..' not in p.parts,
                            'Unsafe nested IPK path')
                    relative = p.as_posix()
                    require(relative not in names, 'Duplicate nested IPK path')
                    names.add(relative)
                    total += member.size
                    require(total <= 128 * MIB and member.sparse is None, 'Nested IPK byte/sparse cap exceeded')
                    if name == 'control.tar.gz' and relative == 'control':
                        require(control is None and member.isfile() and member.size <= MIB,
                                'Invalid IPK control member')
                        control = control_fields(archive.extractfile(member).read(MIB + 1))
                    elif name == 'data.tar.gz' and (relative.endswith('.ko') or relative.startswith('lib/firmware/') or relative.endswith('.lmo')):
                        # Firmware aliases are not executed/extracted. Concrete firmware
                        # files and all .ko files must match the actual image bytes.
                        if member.issym() and not relative.endswith('.ko'):
                            continue
                        require(member.isfile() and 0 < member.size <= 32 * MIB,
                                'Invalid native vendor module/firmware member')
                        value = archive.extractfile(member).read(member.size + 1)
                        require(len(value) == member.size, 'Truncated native module/firmware')
                        files[relative] = value
            while stream.read(MIB):
                pass
    require(control is not None, 'Native IPK has no control')
    return control, files


def module_info(data, version, kernel_config):
    require(64 <= len(data) <= 32 * MIB and data[:6] == b'\x7fELF\x02\x01', 'Module is not ELF64 little-endian')
    require(struct.unpack_from('<HH', data, 16) == (1, 183), 'Module ELF is not relocatable AArch64')
    start = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, names_index = struct.unpack_from('<HHH', data, 58)
    require(entsize == 64 and 0 < count <= 4096 and names_index < count
            and start + count * entsize <= len(data), 'Invalid module ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, start + i * entsize) for i in range(count)]
    names = sections[names_index]
    require(names[4] + names[5] <= len(data) and names[5] <= MIB, 'Invalid ELF section names')
    names_data = data[names[4]:names[4] + names[5]]
    found = []
    for entry in sections:
        require(entry[0] < len(names_data), 'Invalid ELF section name offset')
        end = names_data.find(b'\0', entry[0])
        require(end >= 0, 'Unterminated ELF section name')
        if names_data[entry[0]:end] == b'.modinfo':
            require(entry[4] + entry[5] <= len(data) and entry[5] <= 256 * 1024, 'Invalid ELF modinfo span')
            found.append(data[entry[4]:entry[4] + entry[5]])
    require(len(found) == 1, 'Missing/duplicate module modinfo')
    values = [p.removeprefix(b'vermagic=').decode('ascii') for p in found[0].split(b'\0')
              if p.startswith(b'vermagic=')]
    require(len(values) == 1, 'Missing/duplicate module vermagic')
    words = values[0].split()
    require(words and words[0] == version and 'aarch64' in words, 'Module native kernel release/arch differs')
    for symbol, token in [('SMP', 'SMP'), ('MODULE_UNLOAD', 'mod_unload'), ('MODVERSIONS', 'modversions')]:
        enabled = re.search(rb'^CONFIG_' + symbol.encode() + rb'=y$', kernel_config, re.M) is not None
        require((token in words) == enabled, 'Module native vermagic config flags differ')
    return {'vermagic': values[0], 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def inspect_root(root, layout, binary, profile, controls, ipks, expected_files,
                 fingerprint, kernel_config, manifest_packages, feature_lock=None, feature_source=None, apk=None):
    regular(root, 0x7a80000)
    with root.open('rb') as stream:
        superblock = stream.read(96)
    require(len(superblock) == 96 and superblock[:4] == b'hsqs', 'Root is not little-endian SquashFS')
    major, minor = struct.unpack_from('<HH', superblock, 28)
    used = struct.unpack_from('<Q', superblock, 40)[0]
    blocksize = struct.unpack_from('<I', superblock, 12)[0]
    compression = struct.unpack_from('<H', superblock, 20)[0]
    require((major, minor) == (4, 0) and 96 <= used <= root.stat().st_size,
            'Invalid SquashFS version/bytes_used')
    require(blocksize in (65536, 131072, 262144, 524288, 1048576) and compression == 4,
            'Unexpected native SquashFS compression/block size')
    alignment = 4096 if layout == 'ubootmod' else 1024
    require(root.stat().st_size % alignment == 0, 'Root filesystem padding alignment differs')
    with root.open('rb') as stream:
        stream.seek(used)
        while chunk := stream.read(MIB):
            require(not any(chunk), 'Nonzero bytes after SquashFS filesystem')
    manager = package_format.manager(profile)
    database = 'lib/apk/db/installed' if manager == 'apk' else 'usr/lib/opkg/status'
    status = (stock_factory.apk_status_packages if manager == 'apk' else parse_status)(
        squash_read(binary, root, database, 4 * MIB))
    package_only = stock_factory.package_policy(profile)
    actual_paths, symlinks = {}, {}
    if package_only or manager == 'apk':
        listing = run_bounded([str(binary), '-processors', '1', '-data-queue', '8', '-frag-queue', '8',
                               '-no-wildcards', '-lln', str(root)], 4 * MIB)
        actual_paths, symlinks = {}, {}
        for line in listing.decode('utf-8').splitlines():
            match = re.search(r'\ssquashfs-root/(.+?)(?: -> (.*))?$', line)
            if match:
                name = stock_factory.canonical(match[1])
                require(name not in actual_paths, 'Duplicate actual SquashFS file listing')
                actual_paths[name] = True
                if match[2] is not None:
                    symlinks[name] = match[2].encode('utf-8')
        require(actual_paths and len(actual_paths) <= 30000, 'Cannot enumerate actual SquashFS file inventory')
        stock_factory.assert_absent(package_only, status, actual_paths, symlinks)
    required = VENDOR | UCODE | ({'kernel', 'apk-openssl', 'openwrt-keyring'} if manager == 'apk' else {'kernel', 'opkg'}) | set(profile.get('image_packages', []))
    available = set(status) | {record.get('Base-Package', name) for name, record in status.items()}
    require(required <= available, 'Actual root omits required packages: ' + ', '.join(sorted(required - available)))
    forbidden = ({'opkg', 'apk-mbedtls'} if manager == 'apk' else {'apk-openssl', 'apk-mbedtls', 'apk'}) | {
                 'kmod-mt7915e', 'kmod-mt7986-firmware', 'mtwifi-cfg', 'iwinfo'}
    require(not forbidden & status.keys() and not any(n.startswith('kmod-mt76') for n in status),
            'Actual root has conflicting APK/radio/config packages')
    require(set(status) == set(manifest_packages), 'Embedded status differs from external device package manifest')
    abi, arch = profile['firmware']['kernel_version'], profile['firmware']['architecture']
    require(status['kernel']['Version'] == abi and status['kernel']['Architecture'] == arch,
            'Actual root kernel ABI/architecture differs')
    for name, fields in status.items():
        require(name in controls and fields['Version'] == controls[name]['Version']
                and fields['Architecture'] == controls[name]['Architecture']
                and fields['Version'] == manifest_packages[name], 'Actual root/native IPK identity differs: ' + name)
    release = squash_read(binary, root, 'etc/openwrt_release', 16 * 1024).decode('ascii')
    require("DISTRIB_TARGET='mediatek/filogic'" in release and "DISTRIB_ARCH='" + arch + "'" in release,
            'Actual root distribution target/architecture differs')
    revisions = re.findall(r"^DISTRIB_REVISION='r[0-9]+(?:\+[0-9]+)?-([0-9a-f]{7,40})'$", release, re.M)
    require(len(revisions) == 1 and profile['firmware']['commit'].startswith(revisions[0]),
            'Actual root source revision differs')
    overlay = {}
    for path, (expected, mode) in expected_files.items():
        actual = squash_read(binary, root, path, 16 * 1024 if mode == 0o755 else 4096)
        require(actual == expected, 'Actual root trusted repository bytes differ: ' + path)
        require_mode(squash_read(binary, root, path, listing=True), path, mode)
        overlay[path] = {'sha256': hashlib.sha256(actual).hexdigest(), 'mode': f'{mode:04o}'}
    apk_policy = None
    if manager == 'apk':
        apk_policy = apk_root_policy(binary, root, profile, status, actual_paths, feature_source, apk)
    else:
        # Read every actual opkg *.conf discovered by a successful bounded listing.
        listing = squash_read(binary, root, 'etc/opkg', 32 * 1024, listing=True)
        paths = re.findall(rb'\s+squashfs-root/(etc/opkg/[^\s]+\.conf)$', listing, re.M)
        configs = {'etc/opkg.conf'} | {p.decode('ascii') for p in paths}
        require('etc/opkg/distfeeds.conf' in configs and len(configs) <= 16, 'Cannot enumerate actual opkg configuration')
        for path in configs:
            data = squash_read(binary, root, path, 16 * 1024)
            require(not re.search(rb'^\s*src(?:/\S+)?(?:\s|$)', data, re.M), 'Actual root enables a moving feed')
            if path == 'etc/opkg.conf':
                require(re.search(rb'^\s*option\s+check_signature(?:\s+1)?\s*$', data, re.M),
                        'Actual opkg signature checks are disabled')
        opkg = 'bin/opkg'
        require_mode(squash_read(binary, root, opkg, listing=True), opkg, 0o755)
        bin_listing = squash_read(binary, root, 'bin', 256 * 1024, listing=True)
        usr_listing = squash_read(binary, root, 'usr/bin', 256 * 1024, listing=True)
        require(not re.search(rb'\s+squashfs-root/(?:usr/)?bin/apk(?:\s|$)', bin_listing + usr_listing, re.M),
                'Actual root contains an APK executable')
    modules, firmware, inspected = {}, {}, 0
    version = abi.split('~')[0]
    for package in sorted({n for n in status if n.startswith('kmod-')}):
        control, files = package_contents(ipks[package], payload=True, apk=apk)
        require(control == controls[package], 'Native IPK changed during root inspection')
        found_modules = 0
        for path, value in files.items():
            if not path.endswith('.ko') and package not in VENDOR:
                continue
            inspected += len(value)
            require(inspected <= 128 * MIB, 'Root module/firmware inspection byte cap exceeded')
            actual = squash_read(binary, root, path, len(value))
            require(actual == value, 'Actual root native module/firmware bytes differ: ' + path)
            if path.endswith('.ko'):
                info = module_info(value, version, kernel_config)
                info['package'] = package
                modules[path] = info
                found_modules += 1
            else:
                firmware[path] = {'package': package, 'size': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
        if package in VENDOR:
            require(found_modules > 0, 'Native vendor package has no inspected module: ' + package)
    native_translations = {}
    for package in sorted(n for n in status if n.startswith('luci-i18n-pbr-') or n == 'luci-i18n-attendedsysupgrade-ru'):
        native_control, payload = package_contents(ipks[package], payload=True, apk=apk)
        require(native_control == controls[package], 'Native translation package changed during image inspection')
        native_translations.update({path: data for path, data in payload.items() if path.endswith('.lmo')})
    feature_record = image_features.verify(profile, feature_lock or {}, status,
        lambda path, cap: squash_read(binary, root, path, cap),
        lambda path, mode: require_mode(squash_read(binary, root, path, listing=True), path, mode),
        source=feature_source, native_translations=native_translations)
    return {'sha256': sha256(root), 'size': root.stat().st_size, 'squashfs_bytes_used': used,
            'installed_kernel': status['kernel'], 'installed_packages': sorted(status),
            'vendor_packages': sorted(VENDOR), 'ucode_packages': sorted(UCODE),
            'modules': modules, 'firmware': firmware, 'trusted_key_fingerprint': fingerprint,
            'repository_files': overlay, 'active_feeds': apk_policy['public_opt_in_feeds'] if apk_policy else 0,
            'apk_executable_present': manager == 'apk', 'package_manager': manager, 'apk_policy': apk_policy,
            'package_only_absent': package_only, 'optional_features': feature_record}


class PipeReader:
    def __init__(self, pipe, deadline):
        self.pipe, self.deadline = pipe, deadline

    def read(self, size):
        with selectors.DefaultSelector() as selector:
            selector.register(self.pipe, selectors.EVENT_READ)
            while True:
                remaining = self.deadline - time.monotonic()
                require(remaining > 0, 'SDK decompression timeout')
                if selector.select(min(remaining, 0.2)):
                    return os.read(self.pipe.fileno(), min(size, MIB))


def trusted_strip_argument(value=None, raw=None):
    selected = value or shutil.which('strip')
    require(selected is not None, 'A trusted GNU strip tool is required for the APK SDK source transformation')
    requested = Path(selected).absolute()
    path = regular(requested.resolve(), 64 * MIB)
    require(os.access(path, os.X_OK), 'Trusted GNU strip is not executable')
    require(raw is None or not any(p.is_relative_to(Path(raw).resolve()) for p in (requested, path)),
            'GNU strip must not come from untrusted raw artifacts')
    with path.open('rb') as stream:
        header = stream.read(64)
    require(header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\x3e\x00',
            'Trusted GNU strip must be a native x86_64 ELF')
    return path


def verify_sdk_source_transform(proof, native_tool, records, work, stripper=None):
    if proof['kind'] == 'native-elf-v1':
        return None
    tool = trusted_strip_argument(stripper)
    transform = proof['source_transform']
    require(transform['name'] == 'strip' and transform['sha256'] == sha256(tool),
            'APK SDK source-transform GNU strip tool identity differs')
    version = run_bounded([str(tool), '--version'], 64 * 1024, timeout=15)
    require(version.startswith(b'GNU strip '), 'APK SDK source-transform tool is not GNU strip')
    # Only the trusted host tool executes; the copied native APK is data for strip.
    with tempfile.TemporaryDirectory(prefix='sdk-native-apk-strip-', dir=work) as temporary:
        candidate = Path(temporary) / 'native-apk'
        shutil.copy2(native_tool, candidate)
        require(sha256(candidate) == proof['native_source']['sha256'],
                'Native APK source changed before independent strip verification')
        run_bounded([str(tool), str(candidate)], 64 * 1024, timeout=30, file_cap=64 * MIB)
        digest = sha256(regular(candidate, 64 * MIB))
    require(digest == transform['result_sha256'] == records[host_apk_bundle.HIDDEN]['sha256'],
            'APK SDK hidden executable differs from independently stripped native source')
    return {'tool_sha256': sha256(tool), 'result_sha256': digest, 'independently_recomputed': True}


def inspect_sdk(archive, kernel, source, work, profile, native_controls=None, native_packages=None, stripper=None):
    relative = kernel.relative_to(source).as_posix()
    wanted = {relative + '/' + name for name in CONTEXTS}
    wanted |= {'Config-build.in', 'include/version.mk'}
    apk_sdk = package_format.manager(profile) == 'apk'
    if apk_sdk:
        wanted |= {'ax6000-baseline/manifest.json', 'staging_dir/host/bin/apk'}
    baseline_packages, bundle_records = {}, {}
    captured, names, declared, members, top = {}, set(), 0, 0, None
    process, raw = None, None
    if archive.name.endswith('.zst'):
        zstd = shutil.which('zstd')
        require(zstd is not None, 'Trusted local zstd is needed for the SDK archive')
        process = subprocess.Popen([zstd, '-d', '-c', '--', str(archive)], stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, preexec_fn=child_limits)
        reader = CappedReader(PipeReader(process.stdout, time.monotonic() + 900), 16 * 1024**3)
        mode = 'r|'
    else:
        raw = archive.open('rb')
        reader = CappedReader(raw, 4 * 1024**3)
        mode = 'r|*'
    try:
        with tarfile.open(fileobj=reader, mode=mode) as tar:
            for entry in tar:
                members += 1
                require(members <= 200000, 'SDK member cap exceeded')
                p = PurePosixPath(entry.name)
                require(p.parts and not p.is_absolute() and '..' not in p.parts, 'Unsafe SDK archive path')
                normalized = p.as_posix()
                require(normalized not in names, 'Duplicate SDK archive path')
                names.add(normalized)
                top = top or p.parts[0]
                require(p.parts[0] == top, 'Multiple SDK archive roots')
                require(entry.isfile() or entry.isdir() or entry.issym() or entry.islnk(), 'Unsupported SDK member')
                if entry.issym() or entry.islnk():
                    require(not entry.linkname.startswith('/'), 'Absolute SDK archive link')
                    linked = posixpath.normpath(posixpath.join(str(p.parent), entry.linkname)
                                               if entry.issym() else entry.linkname)
                    target = PurePosixPath(linked)
                    require(target.parts and target.parts[0] == top and '..' not in target.parts,
                            'SDK archive link escapes its root')
                name = PurePosixPath(*p.parts[1:]).as_posix()
                bundle_member = apk_sdk and host_apk_bundle.is_bundle_path(name)
                if bundle_member and not entry.isdir():
                    require(not entry.islnk(), 'APK SDK host runtime must not use hardlinks')
                    if entry.issym():
                        bundle_records[name] = {'type': 'symlink', 'target': entry.linkname, 'mode': entry.mode}
                if not entry.isfile():
                    continue
                declared += entry.size
                require(declared <= 16 * 1024**3, 'SDK declared byte cap exceeded')
                if apk_sdk:
                    require(PurePosixPath(name).name != 'private-key.pem', 'APK SDK must not export a PEM private signing key')
                    require(not name.startswith('ax6000-baseline/ipks/'), 'APK SDK contains a legacy IPK baseline')
                    if name.startswith('ax6000-baseline/apks/'):
                        require(name.endswith('.apk') and len(PurePosixPath(name).parts) == 3 and 0 < entry.size <= 128 * MIB,
                                'APK SDK baseline member path/size differs')
                        digest = hashlib.sha256(); count = 0
                        with tar.extractfile(entry) as stream:
                            while chunk := stream.read(MIB):
                                count += len(chunk); digest.update(chunk)
                        require(count == entry.size, 'Truncated APK SDK baseline package')
                        baseline_packages[name.removeprefix('ax6000-baseline/')] = {'sha256': digest.hexdigest(), 'size': count}
                if bundle_member:
                    require(0 < entry.size <= 64 * MIB and len(bundle_records) < 4096,
                            'APK SDK host runtime byte/member cap exceeded')
                    digest = hashlib.sha256(); count = 0; header = b''; wrapper = bytearray()
                    with tar.extractfile(entry) as stream:
                        while chunk := stream.read(MIB):
                            count += len(chunk); digest.update(chunk)
                            if len(header) < 64: header += chunk[:64 - len(header)]
                            if name == 'staging_dir/host/bin/apk':
                                require(count <= 64 * MIB, 'APK SDK entrypoint byte cap exceeded')
                                wrapper.extend(chunk)
                    require(count == entry.size, 'Truncated APK SDK host runtime')
                    bundle_records[name] = {'type': 'file', 'sha256': digest.hexdigest(), 'size': count,
                                            'mode': entry.mode, 'header': header.hex()}
                    if name == 'staging_dir/host/bin/apk': captured[name] = bytes(wrapper)
                    continue
                if name not in wanted:
                    continue
                cap = 4 * MIB
                require(entry.size <= cap and name not in captured, 'SDK context byte/duplicate cap exceeded')
                with tar.extractfile(entry) as stream:
                    captured[name] = stream.read(cap + 1)
                require(len(captured[name]) == entry.size, 'Truncated SDK context')
        while reader.read(MIB):
            pass
        if process:
            require(process.wait(timeout=10) == 0, 'SDK zstd decompression failed')
    finally:
        if process:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
        if raw:
            raw.close()
    require(set(captured) == wanted, 'SDK lacks required kernel contexts/target defaults')
    baseline_proof = None
    if apk_sdk:
        baseline = json_bytes(captured['ax6000-baseline/manifest.json'])
        require(baseline.get('package_manager') == 'apk' and baseline.get('schema_version') == 1
                and baseline.get('source_commit') == profile['firmware']['commit']
                and baseline.get('kernel_version') == profile['firmware']['kernel_version']
                and baseline.get('architecture') == profile['firmware']['architecture'], 'APK SDK baseline cohort identity differs')
        tool = baseline.get('host_apk', {})
        host_apk_bundle.verify_records(tool, bundle_records, captured['staging_dir/host/bin/apk'])
        native_tool = regular(source / 'staging_dir/host/bin/apk', 64 * MIB)
        native_source = tool.get('native_source', {})
        with native_tool.open('rb') as stream:
            native_header = stream.read(64)
        require(native_source.get('sha256') == sha256(native_tool)
                and native_source.get('size') == native_tool.stat().st_size
                and native_source.get('machine') == host_apk_bundle.elf_machine(native_header)
                and native_header[:7] == b'\x7fELF\x02\x01\x01' and native_header[18:20] == b'\x3e\x00',
                'APK SDK host runtime native-source provenance differs from actual source executable')
        bundler = regular(source / 'scripts/bundle-libraries.sh', MIB)
        require(sha256(bundler) == tool.get('bundler_sha256'),
                'APK SDK host runtime bundler differs from actual source script')
        source_transform_proof = verify_sdk_source_transform(tool, native_tool, bundle_records, work, stripper)
        records = baseline.get('files')
        require(isinstance(records, list) and records and len(records) <= 10000, 'APK SDK baseline package inventory absent')
        seen, identities = set(), {}
        for record in records:
            require(isinstance(record, dict) and set(record) == {'package', 'version', 'path', 'sha256'}, 'Malformed APK SDK baseline entry')
            name, path = record['package'], record['path']
            require(name not in identities and path not in seen and path in baseline_packages, 'APK SDK baseline duplicate/missing package')
            require(record['sha256'] == baseline_packages[path]['sha256'], 'APK SDK baseline archive bytes differ')
            if native_controls is not None:
                require(name in native_controls and record['version'] == native_controls[name]['Version'], 'APK SDK/native baseline package identity differs')
                actual = native_packages[name]
                require(sha256(actual) == record['sha256'] and actual.stat().st_size == baseline_packages[path]['size'],
                        'APK SDK frozen archive differs from actual native package')
            identities[name] = record; seen.add(path)
        require(seen == set(baseline_packages) and set(identities) == set(baseline.get('frozen_packages', [])),
                'APK SDK actual/frozen package inventory differs')
        require(set(baseline.get('frozen_kmods', [])) == {name for name in identities if name.startswith('kmod-')}
                and 'kernel' in identities, 'APK SDK frozen kernel/module bank differs')
        if native_controls is not None:
            core = set(apk_world.core_recipe_roots(regular(source / 'tmp/.packageinfo', 64 * MIB).read_text()))
            refreshed = (set(profile.get('packages', [])) - core) & {name for name in native_controls if name.startswith('kmod-')}
            require(set(baseline['frozen_kmods']) == {name for name in native_controls if name.startswith('kmod-')} - refreshed,
                    'APK SDK omits a native frozen kernel module')
        context = baseline.get('kernel_context', {})
        require(context.get('path') == relative and set(context.get('files', {})) ==
                {'.config', 'Module.symvers', 'include/generated/autoconf.h', 'include/config/kernel.release'},
                'APK SDK baseline kernel context inventory differs')
        for name, record in context['files'].items():
            value = captured[relative + '/' + name]
            require(record == {'sha256': hashlib.sha256(value).hexdigest(), 'size': len(value)}, 'APK SDK baseline prepared context differs')
        baseline_proof = {'packages': len(identities), 'frozen_kmods': len(baseline['frozen_kmods']),
                          'manifest_sha256': hashlib.sha256(captured['ax6000-baseline/manifest.json']).hexdigest(),
                          'host_apk': tool, 'source_transform': source_transform_proof,
                          'whole_native_archive_bytes_matched': native_controls is not None}
    hashes = {}
    for name in CONTEXTS:
        data = regular(kernel / name, 4 * MIB).read_bytes()
        require(data == captured[relative + '/' + name], 'Source/SDK kernel context differs: ' + name)
        hashes[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
    defaults = captured['Config-build.in'].decode('utf-8')
    for symbol, expected in [('TARGET_BOARD', 'mediatek'), ('TARGET_SUBTARGET', 'filogic'),
                             ('TARGET_ARCH_PACKAGES', 'aarch64_cortex-a53')]:
        blocks = re.findall(r'^config\s+' + symbol + r'\s*\n(.*?)(?=^config\s|\Z)', defaults, re.M | re.S)
        require(len(blocks) == 1 and re.findall(r'^\s*default\s+"([^"\n]+)"\s*$', blocks[0], re.M) == [expected],
                'SDK target default differs: ' + symbol)
    revision = re.findall(r'^REVISION\s*:?=\s*r[0-9]+(?:\+[0-9]+)?-([0-9a-f]{7,40})\s*$',
                          captured['include/version.mk'].decode(), re.M)
    require(len(revision) == 1 and profile['firmware']['commit'].startswith(revision[0]), 'SDK source revision differs')
    config_set = captured[relative + '/.config.set']
    lines = sorted(line for line in config_set.splitlines() if re.search(rb'=[ym]', line))
    computed = hashlib.md5(b''.join(line + b'\n' for line in lines)).hexdigest()
    stored = captured[relative + '/.vermagic'].decode().strip()
    expected = re.fullmatch(r'(6\.12\.[0-9]+)~([0-9a-f]{32})-r([0-9]+)', profile['firmware']['kernel_version'])
    require(expected is not None and computed == stored == expected[2], 'Native kernel .config.set ABI hash differs')
    release = captured[relative + '/include/config/kernel.release'].decode().strip()
    require(release == expected[1], 'Native source/SDK kernel release differs')
    config = captured[relative + '/.config']
    modversions = re.search(rb'^CONFIG_MODVERSIONS=y$', config, re.M) is not None
    symvers = captured[relative + '/Module.symvers']
    rows = [row.split() for row in symvers.splitlines() if row.strip()]
    require(rows and all(len(row) >= 4 and re.fullmatch(rb'0x[0-9a-fA-F]{8}', row[0]) for row in rows),
            'Malformed Module.symvers export table')
    return {'sdk_sha256': sha256(archive), 'members': members, 'declared_bytes': declared,
            'package_manager': 'apk' if apk_sdk else 'opkg', 'apk_baseline': baseline_proof,
            'kernel_relative_path': relative, 'matching_contexts': hashes, 'kernel_release': release,
            'native_abi_hash': stored, 'modversions': modversions,
            'export_rows': len(rows), 'export_crc_all_zero': all(int(row[0], 16) == 0 for row in rows),
            'crc_scope': 'Export-table identity only; zero CRCs are not MODVERSIONS validation' if not modversions
                         else 'Matching native export table and MODVERSIONS-enabled context'}, config


def verify_metadata(metadata, layout, profile):
    require(metadata.get('metadata_version') == '1.1', 'Unsupported sysupgrade metadata version')
    supported = metadata.get('new_supported_devices', metadata.get('supported_devices'))
    expected = 'xiaomi,redmi-router-ax6000-' + layout
    require(isinstance(supported, list) and len(supported) == 1 and supported[0] == expected,
            'Sysupgrade metadata supported board differs')
    version = metadata.get('version', {})
    require(version.get('target') == 'mediatek/filogic' and version.get('board') == DEVICES[layout],
            'Sysupgrade metadata target/board differs')
    revision = re.fullmatch(r'r[0-9]+(?:\+[0-9]+)?-([0-9a-f]{7,40})', version.get('revision', ''))
    require(revision and profile['firmware']['commit'].startswith(revision[1]), 'Sysupgrade metadata source revision differs')


def device_manifest(path):
    result = {}
    for line in regular(path, 4 * MIB).read_text().splitlines():
        match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9+_.-]*) - (\S+)', line)
        require(match and match[1] not in result, 'Malformed/duplicate device package manifest entry')
        result[match[1]] = match[2]
    require(result, 'Empty device package manifest')
    return result


def resolve_device_manifest(target, layout, profile, image, source_target):
    """Native MULTI_PROFILE exports one common manifest from TARGET_DIR_ORIG.

    Accept it only with matching native metadata and files. inspect_root still
    compares the complete embedded package/version inventory for every layout.
    """
    matches = list(target.glob('*-' + DEVICES[layout] + '.manifest'))
    require(len(matches) <= 1, 'Ambiguous device package manifest: ' + layout)
    if matches:
        return matches[0]
    native = read_json(safe_path(target, 'profiles.json'))
    require(sha256(target / 'profiles.json') == sha256(regular(source_target / 'profiles.json', 16 * MIB)),
            'Exported profiles differ from native build')
    firmware = profile['firmware']
    kernel = native.get('linux_kernel', {})
    require(native.get('target') == 'mediatek/filogic'
            and native.get('arch_packages') == firmware['architecture']
            and firmware['kernel_version'] == str(kernel.get('version')) + '~' + str(kernel.get('vermagic')) + '-r' + str(kernel.get('release')),
            'Common manifest native target/architecture/kernel ABI differs')
    revision = re.fullmatch(r'r[0-9]+(?:\+[0-9]+)?-([0-9a-f]{7,40})', native.get('version_code', ''))
    require(revision and firmware['commit'].startswith(revision[1]), 'Common manifest native source revision differs')
    profiles = native.get('profiles', {})
    require(isinstance(profiles, dict) and set(profiles) == set(DEVICES.values()),
            'Common manifest native device inventory differs')
    prefix = 'immortalwrt-mediatek-filogic'
    for board_layout, device in DEVICES.items():
        board = profiles[device]
        require(board.get('image_prefix') == prefix + '-' + device
                and board.get('supported_devices') == ['xiaomi,redmi-router-ax6000-' + board_layout],
                'Common manifest native supported device differs')
    images = profiles[DEVICES[layout]].get('images', [])
    require(isinstance(images, list), 'Common manifest native image records invalid')
    sysupgrades = [r for r in images if r.get('type') == 'sysupgrade' and r.get('filesystem') == 'squashfs']
    require(len(sysupgrades) == 1 and sysupgrades[0].get('name') == image.name
            and sysupgrades[0].get('size') == image.stat().st_size and sysupgrades[0].get('sha256') == sha256(image),
            'Common manifest native sysupgrade identity differs')
    common = safe_path(target, prefix + '.manifest')
    require(sha256(regular(common, 4 * MIB)) == sha256(regular(source_target / common.name, 4 * MIB)),
            'Exported common manifest differs from native build')
    return common


def main(args):
    repo, source, raw = (Path(getattr(args, key)).resolve() for key in ('repo', 'source', 'raw'))
    require(all(p.is_dir() for p in (repo, source, raw)), 'Trusted repo/source/raw directories must exist')
    output = Path(args.output).absolute()
    require(not any(output.resolve().is_relative_to(p) for p in (repo, source, raw)), 'Evidence output overlaps readonly inputs')
    if args.work_dir:
        work = Path(args.work_dir).absolute()
        require(not work.exists() and not any(work.resolve().is_relative_to(p) or p.is_relative_to(work.resolve())
                                            for p in (repo, source, raw)), 'Use a fresh inspection directory outside inputs')
        work.mkdir(parents=True)
    else:
        work = Path(tempfile.mkdtemp(prefix='ax6000-612-verify-'))
    profile, manifest = read_json(raw / 'profile.json'), read_json(raw / 'firmware-manifest.json')
    channel = profile.get('channel')
    firmware = profile.get('firmware', {})
    commit = PINS.get(channel)
    require(commit is not None and firmware.get('commit') == commit, 'Unapproved 6.12 channel/source pin')
    require(firmware.get('devices') == [{'device': device, 'layout': layout} for layout, device in DEVICES.items()]
            and firmware.get('device') == DEVICES['stock'], 'Profile does not describe the three allowlisted layouts')
    require((firmware.get('target'), firmware.get('subtarget'), firmware.get('architecture')) ==
            ('mediatek', 'filogic', 'aarch64_cortex-a53'), 'Profile target/architecture differs')
    approved = read_json(repo / 'profiles' / ('redmi-ax6000-612-' + channel + '-new.json'))
    for field in ('id', 'channel', 'packages', 'image_packages', 'package_only', 'luci_languages', 'publication', 'build_source', 'asu', 'pbr_source', 'vendor_country_db', 'package_manager', 'apk_key_sha256'):
        require(profile.get(field) == approved.get(field), 'Exported profile differs from reviewed recipe: ' + field)
    manager = package_format.manager(profile)
    apk = trusted_apk_argument(getattr(args, 'apk', None), raw) if manager == 'apk' else None
    package_only = stock_factory.package_policy(profile)
    require({k: v for k, v in firmware.items() if k != 'kernel_version'} ==
            {k: v for k, v in approved['firmware'].items() if k != 'kernel_version'},
            'Exported firmware identity differs from reviewed recipe')
    require(profile.get('all_kmods') is False and profile.get('feeds') ==
            [{'name': 'base', 'url': firmware['repository'], 'commit': commit, 'root': 'package'}] + approved['feeds'],
            'Exported SDK feeds/frozen kernel selection differ from reviewed recipe')
    actual_commit = run_bounded(['git', '-C', str(source), 'rev-parse', 'HEAD'], 128).decode().strip()
    require(actual_commit == commit == manifest.get('source_commit'), 'Actual source/export manifest commit differs')
    require(firmware.get('kernel_version') == manifest.get('kernel_version'), 'Export kernel ABI identity differs')
    require(manifest.get('channel') == channel and manifest.get('devices') == firmware['devices'],
            'Export manifest channel/devices differ')
    if manager == 'apk':
        require(manifest.get('package_manager') == 'apk' and manifest.get('apk_key_sha256') == profile.get('apk_key_sha256'),
                'Export manifest APK format/key identity differs')
    else:
        require(manifest.get('package_manager', 'opkg') == 'opkg', 'Legacy OPKG manifest format differs')
    sdk_hash = profile.get('sdk', {}).get('sha256', '')
    build_id = profile.get('build_id', '')
    require(re.fullmatch(r'[0-9a-f]{64}', sdk_hash) and build_id == profile['id'] + '-' + commit[:12] + '-' + sdk_hash[:12]
            and manifest.get('build_id') == build_id, 'Immutable firmware/SDK build ID differs')
    lock = read_json(raw / 'lock.json')
    require(lock.get('firmware') == firmware and lock.get('sdk') == profile['sdk']
            and lock.get('profile_sha256') == sha256(raw / 'profile.json'), 'Export lock/profile identity differs')
    if manager == 'apk':
        require(lock.get('package_manager') == 'apk' and lock.get('apk_key_sha256') == profile.get('apk_key_sha256'),
                'Export lock APK format/key identity differs')
    config = regular(raw / 'build.config', 4 * MIB).read_bytes()
    require(config == regular(source / '.config', 4 * MIB).read_bytes(), 'Exported build config differs from actual source')
    disabled = ('CLEAN_IPKG', 'PACKAGE_opkg', 'PACKAGE_apk-mbedtls') if manager == 'apk' else ('USE_APK', 'CLEAN_IPKG')
    for symbol in disabled:
        if manager == 'apk' and symbol == 'CLEAN_IPKG':
            # Native Kconfig omits this symbol when its !USE_APK dependency is false.
            declarations = [line for line in config.splitlines()
                            if re.match(rb'[ \t]*(?:#[ \t]*)?CONFIG_CLEAN_IPKG\b', line)]
            require(declarations in ([], [b'# CONFIG_CLEAN_IPKG is not set']),
                    'Native APK CLEAN_IPKG must be absent or explicitly disabled')
        else:
            require(b'# CONFIG_' + symbol.encode() + b' is not set\n' in config, 'Required configuration disabled-state absent: ' + symbol)
    for symbol in ('SDK', 'DEVEL', 'ALL_KMODS', 'SIGNED_PACKAGES', 'SIGNATURE_CHECK', 'TARGET_MULTI_PROFILE', 'TARGET_PER_DEVICE_ROOTFS'):
        require(b'CONFIG_' + symbol.encode() + b'=y\n' in config, 'Required configuration lost: ' + symbol)
    if manager == 'apk':
        for symbol in ('USE_APK', 'PACKAGE_apk-openssl', 'PACKAGE_openwrt-keyring'):
            require(b'CONFIG_' + symbol.encode() + b'=y\n' in config, 'Native APK provider/keyring configuration differs: ' + symbol)
    for package in package_only:
        require(b'CONFIG_PACKAGE_' + package.encode() + b'=m\n' in config,
                'package_only must be compiled as a downloadable module: ' + package)
    vendor_symbols = (b'CONFIG_MTK_CHIP_MT7986=y', b'CONFIG_MTK_WARP_V2=y',
                      b'CONFIG_MTK_WIFI_SKU_TYPE="AX6000"', b'CONFIG_WARP_CHIPSET="mt7986"',
                      b'CONFIG_WARP_VERSION=2')
    require(all(value + b'\n' in config for value in vendor_symbols), 'Actual source dropped MT7986/AX6000 vendor configuration')
    devices = set(re.findall(rb'^CONFIG_TARGET_DEVICE_([^=\n]+)=y$', config, re.M))
    require(devices == {('mediatek_filogic_DEVICE_' + d).encode() for d in DEVICES.values()}, 'Actual build selected other/missing devices')
    expected_files, fingerprint = repository_expected(repo, profile)
    feature_expected = image_features.expected(profile, lock, source=source)
    for name in ('etc/asu-cohort.json', 'etc/uci-defaults/99-ax6000-asu'):
        if name in feature_expected['files']:
            expected_files[name] = feature_expected['files'][name]
    for path, (data, mode) in expected_files.items():
        overlay = safe_path(source, 'files/' + path)
        require(regular(overlay, 16 * 1024).read_bytes() == data and overlay.stat().st_mode & 0o7777 == mode,
                'Trusted source overlay differs from independently rendered repository files')
    fwrecipe = regular(source / 'package/system/fwtool/Makefile', 64 * 1024).read_text()
    require('04cd252e4e9394ffacd51f56f1f124abc534f715' in fwrecipe, 'Unexpected native 6.12 fwtool recipe revision')
    tools = {}
    for name in ('fwtool', 'unsquashfs4'):
        path = source / 'staging_dir/host/bin' / name
        require(path.resolve().is_relative_to(source) and path.is_file() and os.access(path, os.X_OK), 'Missing trusted built native tool: ' + name)
        tools[name] = path
    entries = manifest.get('files')
    require(isinstance(entries, list) and 0 < len(entries) <= 20000, 'Invalid export manifest inventory')
    inventory = {}
    for entry in entries:
        name = entry.get('path')
        require(name not in inventory, 'Duplicate export manifest path')
        path = safe_path(raw, name)
        require(name.startswith('bin/') and isinstance(entry.get('size'), int)
                and 0 <= entry['size'] <= 4 * 1024**3, 'Invalid export file size/path')
        regular(path, 4 * 1024**3, allow_empty=True)
        require(path.stat().st_size == entry['size'] and sha256(path) == entry.get('sha256'), 'Export whole-file SHA256/size differs: ' + name)
        inventory[name] = path
    actual = set()
    for path in (raw / 'bin').rglob('*'):
        require(not path.is_symlink(), 'Symlink in raw export inventory')
        if path.is_file():
            actual.add(path.relative_to(raw).as_posix())
    require(actual == set(inventory), 'Actual raw bin inventory differs from manifest')
    controls, ipks = {}, {}
    for name, path in inventory.items():
        if not name.endswith(('.ipk', '.apk')):
            continue
        require(name.endswith('.apk' if manager == 'apk' else '.ipk'), 'Mixed package archive formats in native export')
        control, _ = package_contents(path, apk=apk)
        package = control.get('Package', '')
        require(package and package not in controls and control.get('Version')
                and control.get('Architecture') in ('all', 'noarch', firmware['architecture']), 'Invalid/duplicate native IPK control')
        if package.startswith('kmod-'):
            dependencies = re.findall(r'(?:^|,)\s*kernel\s*\(\s*=\s*([^\s)]+)\s*\)', control.get('Depends', ''))
            require(dependencies == [firmware['kernel_version']], 'Native IPK kernel dependency differs: ' + package)
        controls[package], ipks[package] = control, path
    require(controls.get('kernel', {}).get('Version') == firmware['kernel_version'], 'Native kernel IPK ABI differs')
    selection = read_json(raw / 'build-selection.json')
    source_selection = read_json(source / 'build-selection.json')
    for field in ('selected_packages', 'candidate_kmods', 'selected_kmods', 'incompatible_kmods', 'source_patches', 'devices', 'channel', 'apk_world'):
        require(selection.get(field) == source_selection.get(field), 'Actual source/export selection differs: ' + field)
    require(selection.get('firmware') == firmware and set(selection.get('built_packages', [])) == set(controls),
            'Exported selection firmware/built package inventory differs')
    require(manifest.get('source_patches', []) == selection.get('source_patches', []),
            'Export manifest/selection source patch provenance differs')
    if manager == 'apk':
        guard = apk_world.configure_source(profile, source, check_only=True)
        apk_world.configure_policy(profile, source, check_only=True)
        expected_guard = {**guard, 'policy_sha256': sha256(source / 'ax6000-apk-world-policy.json')}
        require(manifest.get('apk_world') == selection.get('apk_world') == expected_guard,
                'Actual native APK rootfs/core policy provenance differs')
    patch_record = source / 'firmware-source-patches.json'
    if patch_record.is_file():
        require(read_json(patch_record).get('patches') == selection.get('source_patches', []),
                'Actual source patch record differs from export')
    available = set(controls) | {control.get('Base-Package', name) for name, control in controls.items()}
    require(set(profile['packages']) <= available and set(selection.get('selected_kmods', [])) <= available,
            'Export omits requested packages or selected kernel modules')
    selected = set(v.decode() for v in re.findall(rb'^CONFIG_PACKAGE_([^=\n]+)=[my]$', config, re.M))
    require(selected == set(selection.get('selected_packages', [])), 'Actual selected package configuration differs')
    packageinfo = regular(source / 'tmp/.packageinfo', 64 * MIB).read_text()
    for block in re.split(r'^Package: ', packageinfo, flags=re.M)[1:]:
        name = block.splitlines()[0]
        if name not in selected or not re.search(r'^Type:\s*ipkg$', block, re.M):
            continue
        values = re.findall(r'^ABI-Version:([^\n]*)$', block, re.M)
        require(len(values) <= 1, 'Duplicate selected native ABI-Version')
        suffix = values[0].strip() if values else ''
        require(not suffix or re.fullmatch(r'[A-Za-z0-9_.+-]+', suffix), 'Malformed selected native ABI-Version')
        suffix = (('-' if name[-1:].isdigit() else '') + suffix) if suffix and not name.startswith('kmod-') else ''
        actual_name = name + suffix
        require(actual_name in controls, 'Export omits selected native IPK: ' + actual_name)
        if suffix:
            require(controls[actual_name].get('ABIVersion') == suffix
                    and (controls[actual_name].get('Base-Package') == name if manager == 'apk' else
                         name in {v.strip() for v in controls[actual_name].get('Provides', '').split(',')}),
                    'Selected native package ABI alias differs: ' + actual_name)
    abi = re.fullmatch(r'(6\.12\.[0-9]+)~([0-9a-f]{32})-r([0-9]+)', firmware['kernel_version'])
    require(abi is not None, 'Malformed native 6.12 kernel ABI')
    kernels = [p.parent for p in source.glob('build_dir/target-*/linux-*/linux-*/.vermagic')
               if regular(p, 128).read_text().strip() == abi[2]]
    require(len(kernels) == 1, 'Cannot identify unique trusted native kernel context')
    kernel = kernels[0]
    expected_kernel = regular(kernel.parent / 'Image', 64 * MIB)
    sdk_name = PurePosixPath(urlsplit(profile['sdk']['url']).path).name
    sdk = safe_path(raw, 'bin/targets/mediatek/filogic/' + sdk_name)
    require(sdk in inventory.values() and sha256(sdk) == sdk_hash, 'Exact exported SDK is absent or changed')
    stripper = trusted_strip_argument(getattr(args, 'strip', None), raw) if manager == 'apk' else None
    context, kernel_config = inspect_sdk(sdk, kernel, source, work, profile, native_controls=controls, native_packages=ipks, stripper=stripper)
    target = raw / 'bin/targets/mediatek/filogic'
    records = {}
    for layout, device in DEVICES.items():
        extension = '.itb' if layout == 'ubootmod' else '.bin'
        images = list(target.glob('*-' + device + '-squashfs-sysupgrade' + extension))
        require(len(images) == 1, 'Cannot identify exactly one ' + layout + ' sysupgrade')
        image = regular(images[0], 128 * MIB)
        location = work / layout
        location.mkdir()
        metadata_file, stripped = location / 'metadata.json', location / 'stripped-image'
        before = sha256(image)
        run_bounded([str(tools['fwtool']), '-i', str(metadata_file), '-T', str(image)],
                    image.stat().st_size, destination=stripped, timeout=120, file_cap=32 * 1024)
        require(sha256(image) == before, 'Native fwtool modified the input image')
        metadata = read_json(metadata_file, 32 * 1024)
        verify_metadata(metadata, layout, profile)
        if layout == 'ubootmod':
            require(stripped.stat().st_size < 0x7a80000, 'FIT payload exceeds UBI partition upper bound')
            fit = extract_fit(stripped, location, external=True)
            root = fit['root']['path']
        else:
            payload = extract_tar(stripped, layout, location)
            fit = extract_fit(payload['kernel'], location, external=False)
            root = payload['root']
        kernel_record = verify_kernel(fit['kernel']['path'], fit['kernel']['compression'], expected_kernel,
                                      location / 'kernel.Image')
        dt_record = verify_dtb(fit['fdt']['path'], layout)
        package_manifest = resolve_device_manifest(target, layout, profile, image, source / 'bin/targets/mediatek/filogic')
        root_record = inspect_root(root, layout, tools['unsquashfs4'], profile, controls, ipks,
                                   expected_files, fingerprint, kernel_config, device_manifest(package_manifest),
                                   feature_lock=lock, feature_source=source, apk=apk)
        root_record['package_manifest'] = {'filename': package_manifest.name, 'sha256': sha256(package_manifest)}
        fit_record = {k: {key: value for key, value in v.items() if key != 'path'} for k, v in fit.items()}
        records[layout] = {'image': image.name, 'image_sha256': before, 'image_size': image.stat().st_size,
                           'stripped_sha256': sha256(stripped), 'stripped_size': stripped.stat().st_size,
                           'metadata': metadata, 'metadata_sha256': sha256(metadata_file),
                           'fit_payloads': fit_record, 'kernel': kernel_record, 'device_tree': dt_record,
                           'root': root_record, 'partition_check': 'Necessary raw size/DT geometry only; UBI overhead and hardware boot are not verified'}
    require(len({r['kernel']['sha256'] for r in records.values()}) == 1, 'Three layouts do not share actual sysupgrade kernel')
    optional_inputs = {}
    arch_image = kernel / 'arch/arm64/boot/Image'
    candidates = [arch_image] + sorted(kernel.parent.glob('Image-initramfs*')) + sorted(kernel.parent.glob('initrd.*.cpio.xz'))
    require(len(candidates) <= 16, 'Initramfs provenance input count cap exceeded')
    for path in candidates:
        if path.is_file():
            regular(path, 64 * MIB)
            optional_inputs[path.relative_to(source).as_posix()] = {'sha256': sha256(path), 'size': path.stat().st_size}
    optional_sizes = {}
    stock_factory_proof = None
    for layout, device in DEVICES.items():
        limit = PARTITIONS[layout]['ubi_kernel' if layout == 'stock' else 'ubi'][1]
        factories = list(target.glob('*-' + device + '-initramfs-factory.ubi'))
        if layout == 'mtkuboot':
            factories += list(target.glob('*-' + device + '-squashfs-factory.bin'))
        require(len(factories) <= 2, 'Ambiguous optional factory artifact inventory')
        for path in factories:
            regular(path, limit)
            optional_sizes[path.name] = {'size': path.stat().st_size, 'partition_upper_bound': limit,
                                         'payload_verified': False}
            if layout == 'stock':
                ram_images = list(target.glob('*-' + device + '-initramfs-kernel.bin'))
                require(len(ram_images) == 1, 'Stock factory requires exactly one corresponding native RAM FIT')
                ram_image = regular(ram_images[0], 64 * MIB)
                require(sha256(ram_image) == sha256(regular(source / 'bin/targets/mediatek/filogic' / ram_image.name, 64 * MIB)),
                        'Stock RAM FIT differs from actual native build')
                kernel_inputs = sorted(kernel.parent.glob('Image-initramfs*'))
                stock_factory_proof = stock_factory.verify_native_factory(ram_image, path,
                    package_only=package_only,
                    expected_packages={name: controls[name] for name in records['stock']['root']['installed_packages']},
                    expected_dtb_sha256=records['stock']['device_tree']['sha256'], kernel_inputs=kernel_inputs,
                    package_manager=manager, expected_files=expected_files, expected_hashes={name: item['sha256'] for name, item in
                        records['stock']['root']['optional_features']['files'].items()})
                optional_sizes[path.name]['payload_verified'] = True
    if 'tailscale' in package_only:
        require(stock_factory_proof is not None, 'Native stock factory UBI is mandatory for package_only Tailscale')
    result = {'schema_version': 1, 'ok': True, 'channel': channel, 'build_id': build_id,
              'package_manager': manager, 'host_apk': {'path': str(apk), 'sha256': sha256(apk)} if apk else None,
              'source_commit': commit, 'kernel_abi': firmware['kernel_version'], 'layouts': records,
              'sdk_context': context, 'sysupgrade_input': {'path': str(expected_kernel),
                  'sha256': sha256(expected_kernel), 'size': expected_kernel.stat().st_size,
                  'stage': 'KDIR/Image copied before Initramfs'},
              'trusted_tools': {n: {'path': str(p), 'sha256': sha256(p)} for n, p in tools.items()},
              'vendor_source_symbols': [v.decode() for v in vendor_symbols],
              'post_initramfs_inputs': optional_inputs, 'optional_factory_size_checks': optional_sizes,
              'stock_factory': stock_factory_proof,
              'recovery_payloads_verified': False,
              'work_dir': str(work), 'hardware_boot_verified': False, 'flash_verified': False,
              'sdk_compile_verified': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + '.tmp')
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    temporary.replace(output)
    print(json.dumps({'ok': True, 'channel': channel, 'build_id': build_id, 'layouts': list(records),
                      'kernel_abi': firmware['kernel_version'], 'evidence': str(output)}, sort_keys=True))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'source', 'raw', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--apk', help='Explicit trusted x86_64 host apk-tools 3.0.5 (required for APK images)')
    parser.add_argument('--strip', help='Trusted native GNU strip matching SDK source-transform proof (default: local strip)')
    parser.add_argument('--work-dir', help='Fresh inspection directory outside readonly inputs (default: /tmp)')
    args = parser.parse_args()
    try:
        child_limits()
        main(args)
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, sort_keys=True), file=sys.stderr)
        sys.exit(1)
