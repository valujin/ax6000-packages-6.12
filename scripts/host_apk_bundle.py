"""Authenticate OpenWrt's portable HOST apk entrypoint without executing imports.

describe() is used only on a newly built trusted SDK/IB. verify_records() is
streaming/archive friendly and executes nothing; a signed whole SDK/IB digest
is still the authority for the captured native bundle and source provenance.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import shutil
import subprocess
import tempfile

BUNDLER_SHA256 = '5cfe9a8dcd9c6cca60d94e8e51f15ae79ffb84dbd403d2d4f17d55d9063a3036'
ENTRY = 'staging_dir/host/bin/apk'
HIDDEN = 'staging_dir/host/bin/.apk.bin'
LIBRARY_ROOT = 'staging_dir/host/lib'
USR_LIB = 'staging_dir/host/usr/lib'
SHA = re.compile(r'[0-9a-f]{64}\Z')
MACHINES = {62, 183}


def require(ok, message):
    if not ok: raise ValueError(message)


def is_bundle_path(name):
    path = PurePosixPath(name)
    return name in (ENTRY, HIDDEN, USR_LIB) or (
        name.startswith(LIBRARY_ROOT + '/') and (path.name.endswith('.so') or '.so.' in path.name))


def safe_relative(name):
    require(isinstance(name, str) and name and PurePosixPath(name).as_posix() == name
            and not name.startswith('/') and '..' not in PurePosixPath(name).parts,
            'unsafe host APK bundle path')


def wrapper(loader):
    require(re.fullmatch(r'ld-[A-Za-z0-9_+.\-]+', loader), 'invalid host APK bundled loader name')
    return ('#!/usr/bin/env bash\n'
            'dir="$(dirname "$0")"\n'
            'export RUNAS_ARG0="$0"\n'
            'export LD_PRELOAD="${LD_PRELOAD:+$LD_PRELOAD:}$dir/../lib/runas.so"\n'
            f'exec "$dir/../lib/{loader}" --library-path "$dir/../lib/" "$dir/.apk.bin" "$@"\n').encode()


def elf_machine(header):
    if isinstance(header, str):
        try: header = bytes.fromhex(header)
        except ValueError: raise ValueError('invalid host APK ELF header')
    require(isinstance(header, bytes) and len(header) >= 20 and header[:6] == b'\x7fELF\x02\x01',
            'host APK bundle requires a native 64-bit little-endian ELF')
    machine = int.from_bytes(header[18:20], 'little')
    require(machine in MACHINES, 'host APK bundle contains an unsupported/target ELF')
    return machine


def record(path):
    stat = path.lstat(); mode = stat.st_mode & 0o777
    if path.is_symlink():
        return {'type': 'symlink', 'mode': mode, 'target': os.readlink(path)}
    require(path.is_file() and 0 < stat.st_size <= 512 * 1024**2, 'invalid host APK bundle member')
    with path.open('rb') as stream:
        header = stream.read(64); stream.seek(0); digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'type': 'file', 'mode': mode, 'size': stat.st_size, 'sha256': digest, 'header': header.hex()}


def records_from_tree(root):
    root = Path(root).resolve(); records = {}
    for name in (ENTRY, HIDDEN, USR_LIB):
        path = root / name
        if name == USR_LIB and path.is_dir() and not path.is_symlink(): continue
        if path.exists() or path.is_symlink(): records[name] = record(path)
    library = root / LIBRARY_ROOT
    if library.exists():
        require(library.is_dir() and not library.is_symlink(), 'host APK library root must be a real directory')
        for path in library.rglob('*'):
            name = path.relative_to(root).as_posix()
            if is_bundle_path(name): records[name] = record(path)
    for name in records:
        path = root / name
        require(path.resolve().is_relative_to(root), 'host APK bundle member escapes its root')
        for parent in path.parents:
            if parent == root: break
            require(not parent.is_symlink(), 'host APK bundle parent is a symlink')
    return records


def verify_records(proof, records, wrapper_data):
    require(isinstance(proof, dict) and proof.get('schema_version') == 1
            and proof.get('kind') in ('openwrt-bundle-v1', 'native-elf-v1')
            and proof.get('path') == ENTRY and proof.get('bundler_sha256') == BUNDLER_SHA256,
            'host APK bundle proof differs from reviewed format/bundler')
    expected = proof.get('files')
    require(isinstance(expected, list) and expected and len(expected) <= 10000, 'host APK bundle inventory missing or too large')
    expected_map = {}
    for item in expected:
        require(isinstance(item, dict), 'invalid host APK inventory record')
        item = dict(item); name = item.pop('path', None); safe_relative(name)
        require(is_bundle_path(name) and name not in expected_map, 'foreign/duplicate host APK bundle member')
        expected_map[name] = item
    require(isinstance(records, dict) and set(expected_map) == set(records),
            'host APK bundle member set differs from its native inventory')
    require(expected_map == records, 'host APK bundle member hash, size, mode or link differs')
    source = proof.get('native_source')
    require(isinstance(source, dict) and source.get('version') == '3.0.5'
            and isinstance(source.get('sha256'), str) and SHA.fullmatch(source['sha256'])
            and type(source.get('size')) is int and source['size'] > 64 and source.get('machine') in MACHINES,
            'host APK source ELF provenance missing')
    machine = source['machine']
    entry = records.get(ENTRY)
    require(isinstance(entry, dict) and entry.get('type') == 'file' and type(entry.get('mode')) is int and entry['mode'] & 0o111
            and entry.get('sha256') == proof.get('sha256') and entry.get('size') == proof.get('size'),
            'host APK entrypoint identity differs')
    for name, item in records.items():
        safe_relative(name)
        require(type(item.get('mode')) is int and 0 <= item['mode'] <= 0o777, 'invalid host APK member mode')
        if item.get('type') == 'symlink':
            target = item.get('target')
            require(isinstance(target, str) and target and not target.startswith('/'), 'host APK bundle link must remain relative')
            resolved = posixpath.normpath(posixpath.join(str(PurePosixPath(name).parent), target))
            safe_relative(resolved)
            require((name == USR_LIB and resolved == LIBRARY_ROOT) or resolved in records,
                    'host APK bundle link escapes its declared context')
        else:
            require(item.get('type') == 'file' and type(item.get('size')) is int and item['size'] > 0
                    and isinstance(item.get('sha256'), str) and SHA.fullmatch(item['sha256']), 'invalid host APK member digest')
            if name != ENTRY or proof['kind'] == 'native-elf-v1':
                require(elf_machine(item.get('header')) == machine, 'host APK bundle ELF architecture differs from its source')
    for name, item in records.items():
        if item['type'] != 'symlink': continue
        seen = set(); current = name
        while records[current]['type'] == 'symlink':
            require(current not in seen, 'host APK bundle contains a symlink cycle')
            seen.add(current)
            target = records[current]['target']
            resolved = posixpath.normpath(posixpath.join(str(PurePosixPath(current).parent), target))
            if current == USR_LIB and resolved == LIBRARY_ROOT: break
            require(resolved in records, 'host APK bundle link target is undeclared')
            current = resolved
    if proof['kind'] == 'native-elf-v1':
        require(entry['sha256'] == source['sha256'] and entry['size'] == source['size'],
                'direct native APK ELF differs from source provenance')
    else:
        loader = proof.get('loader')
        require(isinstance(loader, str) and loader.startswith(LIBRARY_ROOT + '/')
                and loader == LIBRARY_ROOT + '/' + PurePosixPath(loader).name, 'invalid bundled APK loader path')
        require(loader in records and HIDDEN in records and LIBRARY_ROOT + '/runas.so' in records,
                'portable APK bundle lacks loader, hidden ELF or preload library')
        require(isinstance(wrapper_data, bytes) and wrapper_data == wrapper(PurePosixPath(loader).name)
                and hashlib.sha256(wrapper_data).hexdigest() == entry['sha256'],
                'host APK wrapper differs from the exact reviewed bundler template')
        transform = proof.get('source_transform')
        require(isinstance(transform, dict) and transform.get('name') in ('strip', 'sstrip')
                and isinstance(transform.get('sha256'), str) and SHA.fullmatch(transform['sha256'])
                and transform.get('result_sha256') == records[HIDDEN]['sha256'], 'host APK stripped source provenance missing')
    return ENTRY


def describe(root, native_source_apk, source_bundler, *, stripper=None):
    root = Path(root).resolve(); source = Path(native_source_apk); bundler = Path(source_bundler)
    require(source.is_file() and not source.is_symlink() and bundler.is_file()
            and hashlib.sha256(bundler.read_bytes()).hexdigest() == BUNDLER_SHA256,
            'native host APK or reviewed bundler is unavailable')
    source_record = record(source); machine = elf_machine(source_record['header'])
    records = records_from_tree(root); entry = records.get(ENTRY)
    require(entry is not None, 'SDK/IB has no host APK entrypoint')
    data = (root / ENTRY).read_bytes()
    proof = {'schema_version': 1, 'kind': 'native-elf-v1' if data.startswith(b'\x7fELF') else 'openwrt-bundle-v1',
        'path': ENTRY, 'sha256': entry.get('sha256'), 'size': entry.get('size'), 'bundler_sha256': BUNDLER_SHA256,
        'native_source': {'sha256': source_record['sha256'], 'size': source_record['size'], 'machine': machine, 'version': '3.0.5'},
        'files': [dict(path=name, **value) for name, value in sorted(records.items())]}
    if proof['kind'] == 'openwrt-bundle-v1':
        match = re.search(rb'exec "\$dir/\.\./lib/(ld-[A-Za-z0-9_+.\-]+)"', data)
        require(match is not None, 'SDK/IB APK wrapper is not the reviewed portable entrypoint')
        proof['loader'] = LIBRARY_ROOT + '/' + match[1].decode()
        strip_tool = Path(stripper or shutil.which('strip') or '').resolve()
        require(strip_tool.is_file() and os.access(strip_tool, os.X_OK), 'trusted native APK stripper unavailable')
        require(elf_machine(record(strip_tool)['header']) == machine, 'native APK stripper architecture differs')
        with tempfile.TemporaryDirectory(prefix='ax6000-apk-source-strip-') as temporary:
            candidate = Path(temporary) / 'apk'; shutil.copy2(source, candidate)
            subprocess.run([str(strip_tool), str(candidate)], check=True, capture_output=True, timeout=30)
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        require(HIDDEN in records and records[HIDDEN].get('sha256') == digest,
                'SDK/IB hidden APK is not the reviewed stripped native source ELF')
        proof['source_transform'] = {'name': 'sstrip' if strip_tool.name == 'sstrip' else 'strip',
                                    'sha256': record(strip_tool)['sha256'], 'result_sha256': digest}
    verify_records(proof, records, data)
    return proof


def verify(root, proof):
    root = Path(root).resolve(); records = records_from_tree(root)
    data = (root / ENTRY).read_bytes()
    verify_records(proof, records, data)
    require(proof['native_source']['machine'] == {'x86_64': 62, 'aarch64': 183}.get(platform.machine()),
            'host APK cannot execute a foreign architecture')
    return root / ENTRY
