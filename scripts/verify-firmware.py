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
    expected = {0o755: '-rwxr-xr-x', 0o644: '-rw-r--r--'}[mode]
    require(file_mode(listing, path) == expected, f'SquashFS {path} must be regular with mode {mode:04o}')


def squash_read(binary, root, path, cap=4096, listing=False):
    return run_bounded([str(binary), '-processors', '1', '-data-queue', '8', '-frag-queue', '8',
                        '-no-wildcards', '-lln' if listing else '-cat', str(root), path], cap)


def repository_expected(repo, profile):
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
                    elif name == 'data.tar.gz' and (relative.endswith('.ko') or relative.startswith('lib/firmware/')):
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
                 fingerprint, kernel_config, manifest_packages):
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
    status = parse_status(squash_read(binary, root, 'usr/lib/opkg/status', 4 * MIB))
    required = VENDOR | UCODE | {'kernel', 'opkg'} | set(profile.get('image_packages', []))
    require(required <= status.keys(), 'Actual root omits required packages: ' + ', '.join(sorted(required - status.keys())))
    forbidden = {'apk-openssl', 'apk-mbedtls', 'apk', 'kmod-mt7915e', 'kmod-mt7986-firmware',
                 'mtwifi-cfg', 'iwinfo'}
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
        control, files = ipk_contents(ipks[package], payload=True)
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
    return {'sha256': sha256(root), 'size': root.stat().st_size, 'squashfs_bytes_used': used,
            'installed_kernel': status['kernel'], 'installed_packages': sorted(status),
            'vendor_packages': sorted(VENDOR), 'ucode_packages': sorted(UCODE),
            'modules': modules, 'firmware': firmware, 'trusted_key_fingerprint': fingerprint,
            'repository_files': overlay, 'active_feeds': 0, 'apk_executable_present': False}


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


def inspect_sdk(archive, kernel, source, work, profile):
    relative = kernel.relative_to(source).as_posix()
    wanted = {relative + '/' + name for name in CONTEXTS}
    wanted |= {'Config-build.in', 'include/version.mk'}
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
                if not entry.isfile():
                    continue
                declared += entry.size
                require(declared <= 16 * 1024**3, 'SDK declared byte cap exceeded')
                name = PurePosixPath(*p.parts[1:]).as_posix()
                if name not in wanted:
                    continue
                require(entry.size <= 4 * MIB and name not in captured, 'SDK context byte/duplicate cap exceeded')
                with tar.extractfile(entry) as stream:
                    captured[name] = stream.read(4 * MIB + 1)
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
    for field in ('id', 'channel', 'packages', 'image_packages', 'luci_languages', 'publication', 'build_source'):
        require(profile.get(field) == approved.get(field), 'Exported profile differs from reviewed recipe: ' + field)
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
    sdk_hash = profile.get('sdk', {}).get('sha256', '')
    build_id = profile.get('build_id', '')
    require(re.fullmatch(r'[0-9a-f]{64}', sdk_hash) and build_id == profile['id'] + '-' + commit[:12] + '-' + sdk_hash[:12]
            and manifest.get('build_id') == build_id, 'Immutable firmware/SDK build ID differs')
    lock = read_json(raw / 'lock.json')
    require(lock.get('firmware') == firmware and lock.get('sdk') == profile['sdk']
            and lock.get('profile_sha256') == sha256(raw / 'profile.json'), 'Export lock/profile identity differs')
    config = regular(raw / 'build.config', 4 * MIB).read_bytes()
    require(config == regular(source / '.config', 4 * MIB).read_bytes(), 'Exported build config differs from actual source')
    for symbol in ('USE_APK', 'CLEAN_IPKG'):
        require(b'# CONFIG_' + symbol.encode() + b' is not set\n' in config, 'Required configuration disabled-state absent: ' + symbol)
    for symbol in ('SDK', 'DEVEL', 'ALL_KMODS', 'SIGNED_PACKAGES', 'SIGNATURE_CHECK', 'TARGET_MULTI_PROFILE', 'TARGET_PER_DEVICE_ROOTFS'):
        require(b'CONFIG_' + symbol.encode() + b'=y\n' in config, 'Required configuration lost: ' + symbol)
    vendor_symbols = (b'CONFIG_MTK_CHIP_MT7986=y', b'CONFIG_MTK_WARP_V2=y',
                      b'CONFIG_MTK_WIFI_SKU_TYPE="AX6000"', b'CONFIG_WARP_CHIPSET="mt7986"',
                      b'CONFIG_WARP_VERSION=2')
    require(all(value + b'\n' in config for value in vendor_symbols), 'Actual source dropped MT7986/AX6000 vendor configuration')
    devices = set(re.findall(rb'^CONFIG_TARGET_DEVICE_([^=\n]+)=y$', config, re.M))
    require(devices == {('mediatek_filogic_DEVICE_' + d).encode() for d in DEVICES.values()}, 'Actual build selected other/missing devices')
    expected_files, fingerprint = repository_expected(repo, profile)
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
        if not name.endswith('.ipk'):
            continue
        control, _ = ipk_contents(path)
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
    for field in ('selected_packages', 'candidate_kmods', 'selected_kmods', 'incompatible_kmods', 'source_patches', 'devices', 'channel'):
        require(selection.get(field) == source_selection.get(field), 'Actual source/export selection differs: ' + field)
    require(selection.get('firmware') == firmware and set(selection.get('built_packages', [])) == set(controls),
            'Exported selection firmware/built package inventory differs')
    require(manifest.get('source_patches', []) == selection.get('source_patches', []),
            'Export manifest/selection source patch provenance differs')
    patch_record = source / 'firmware-source-patches.json'
    if patch_record.is_file():
        require(read_json(patch_record).get('patches') == selection.get('source_patches', []),
                'Actual source patch record differs from export')
    require(set(profile['packages']) <= controls.keys() and set(selection.get('selected_kmods', [])) <= controls.keys(),
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
                    and name in {v.strip() for v in controls[actual_name].get('Provides', '').split(',')},
                    'Selected native IPK ABI alias differs: ' + actual_name)
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
    context, kernel_config = inspect_sdk(sdk, kernel, source, work, profile)
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
        manifests = list(target.glob('*-' + device + '.manifest'))
        require(len(manifests) == 1, 'Cannot identify exact device package manifest: ' + layout)
        root_record = inspect_root(root, layout, tools['unsquashfs4'], profile, controls, ipks,
                                   expected_files, fingerprint, kernel_config, device_manifest(manifests[0]))
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
    result = {'schema_version': 1, 'ok': True, 'channel': channel, 'build_id': build_id,
              'source_commit': commit, 'kernel_abi': firmware['kernel_version'], 'layouts': records,
              'sdk_context': context, 'sysupgrade_input': {'path': str(expected_kernel),
                  'sha256': sha256(expected_kernel), 'size': expected_kernel.stat().st_size,
                  'stage': 'KDIR/Image copied before Initramfs'},
              'trusted_tools': {n: {'path': str(p), 'sha256': sha256(p)} for n, p in tools.items()},
              'vendor_source_symbols': [v.decode() for v in vendor_symbols],
              'post_initramfs_inputs': optional_inputs, 'optional_factory_size_checks': optional_sizes,
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
    parser.add_argument('--work-dir', help='Fresh inspection directory outside readonly inputs (default: /tmp)')
    args = parser.parse_args()
    try:
        child_limits()
        main(args)
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, sort_keys=True), file=sys.stderr)
        sys.exit(1)
