"""Explicit package-format boundary for existing OPKG and new 6.12 APK cohorts.

APK metadata is decoded by a caller-selected trusted HOST apk-tools binary;
package scripts and target binaries are never executed. Signature/index and
native-bank identity verification belong to callers, not this parser.
"""
import io
import json
import os
from pathlib import Path
import re
import subprocess
import selectors
import time
import tarfile

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+:-]*')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+~:-]*')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def manager(profile):
    value = profile.get('package_manager', 'opkg')
    require(value in ('opkg', 'apk'), 'unsupported package_manager')
    if value == 'apk':
        require(profile.get('channel') in ('recommended', 'latest')
                and profile.get('id') == 'redmi-ax6000-612-' + profile['channel'],
                'APK requires an explicitly selected 6.12 cohort')
    return value


def suffix(profile):
    return 'apk' if manager(profile) == 'apk' else 'ipk'


def read_ipk_control(path):
    with tarfile.open(path, 'r:*') as package:
        members = [m for m in package.getmembers() if m.name.lstrip('./') == 'control.tar.gz']
        require(len(members) == 1 and members[0].isfile() and members[0].size <= 4 * 1024**2, 'Invalid control archive')
        data = package.extractfile(members[0]).read()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = [m for m in archive.getmembers() if m.name.lstrip('./') == 'control']
        require(len(members) == 1 and members[0].isfile() and members[0].size <= 1024**2, 'Invalid control')
        text = archive.extractfile(members[0]).read().decode('utf-8')
    fields, previous = {}, None
    for line in text.splitlines():
        if line.startswith((' ', '\t')) and previous:
            fields[previous] += '\n' + line
        elif ':' in line:
            key, value = line.split(':', 1)
            require(key not in fields, 'Duplicate control field: ' + key)
            fields[key], previous = value.strip(), key
        elif line:
            raise ValueError('Malformed package control')
    return fields



def bounded_output(command, limit=32 * 1024**2, timeout=120):
    """Enforce the stdout ceiling while the host child is running."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline, output = time.monotonic() + timeout, bytearray()
    try:
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'host APK metadata command timed out')
                for event, _ in selector.select(min(remaining, 1)):
                    chunk = os.read(event.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(event.fileobj)
                    else:
                        require(len(output) + len(chunk) <= limit, 'APK metadata exceeds limit')
                        output.extend(chunk)
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'host APK metadata command timed out')
        status = process.wait(timeout=remaining)
        if status:
            raise subprocess.CalledProcessError(status, command)
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def apk_json(path, apk):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size < 2 * 1024**3,
            'APK metadata source must be a regular bounded file')
    require(apk is not None, 'trusted host apk binary is required')
    apk = Path(apk)
    require(apk.is_file() and not apk.is_symlink() and os.access(apk, os.X_OK), 'trusted host apk binary missing')
    data = bounded_output([str(apk.resolve()), '--no-network', 'adbdump', '--format', 'json', str(path.resolve())])
    require(len(data) <= 32 * 1024**2, 'APK metadata exceeds limit')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate APK JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def dependency_tokens(value):
    require(isinstance(value, list) and all(isinstance(x, str) and x and not re.search(r'\s|,|[()]', x) for x in value),
            'invalid APK dependency tokens')
    require(len(value) == len(set(value)), 'duplicate APK dependency tokens')
    return value


def normalized_dependencies(value):
    result = []
    for token in dependency_tokens(value):
        found = re.fullmatch(r'(!?[A-Za-z0-9][A-Za-z0-9_.+:-]*)([<>=~]+)?([^\s,()]*)', token)
        require(found is not None, 'unsupported APK dependency expression')
        name, operator, version = found.groups()
        require(bool(operator) == bool(version), 'invalid APK dependency version expression')
        result.append(name + (' (' + operator + ' ' + version + ')' if operator else ''))
    return ', '.join(result)


def normalize_apk_info(info):
    require(isinstance(info, dict), 'APK info must be an object')
    name, version, arch = (info.get(x) for x in ('name', 'version', 'arch'))
    require(isinstance(name, str) and NAME.fullmatch(name), 'invalid APK package name')
    require(isinstance(version, str) and VERSION.fullmatch(version), 'invalid APK package version')
    require(isinstance(arch, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_+-]*', arch), 'invalid APK architecture')
    tags = info.get('tags', [])
    require(isinstance(tags, list) and all(isinstance(x, str) for x in tags), 'invalid APK tags')
    abi = [x.split('=', 1)[1] for x in tags if x.startswith('openwrt:abiversion=')]
    require(len(abi) <= 1 and (not abi or (abi[0] and name.endswith(abi[0]) and len(name) > len(abi[0]))),
            'APK ABI suffix tag does not match actual package name')
    base = name[:-len(abi[0])] if abi else name
    fields = {'Package': name, 'Base-Package': base, 'Version': version, 'Architecture': arch,
              'APK-Name': name, 'APK-Raw': info}
    if abi:
        fields['ABIVersion'] = abi[0]
    for original, field in [('depends', 'Depends'), ('provides', 'Provides'), ('replaces', 'Replaces'), ('install-if', 'Install-If')]:
        if original in info:
            fields[field] = normalized_dependencies(info[original])
    for original, field in [('description', 'Description'), ('license', 'License'), ('origin', 'Source'), ('url', 'URL'), ('maintainer', 'Maintainer')]:
        if original in info:
            require(isinstance(info[original], str), 'invalid APK string metadata')
            fields[field] = info[original]
    if 'installed-size' in info:
        require(type(info['installed-size']) is int and info['installed-size'] >= 0, 'invalid APK installed size')
        fields['Installed-Size'] = str(info['installed-size'])
    return fields


def read_control(path, apk=None):
    path = Path(path)
    if path.name.endswith('.ipk'):
        return read_ipk_control(path)
    require(path.name.endswith('.apk'), 'unsupported package file format')
    data = apk_json(path, apk)
    require(isinstance(data, dict) and isinstance(data.get('info'), dict), 'not an APKv3 package metadata object')
    return normalize_apk_info(data['info'])


def read_package(path, format=None, apk=None):
    if format is not None:
        require(format in ('opkg', 'ipk', 'apk'), 'unsupported package format')
        require(Path(path).suffix == ('.apk' if format == 'apk' else '.ipk'), 'package suffix differs from selected format')
    return read_control(path, apk=apk)


def index_info(path, apk):
    data = apk_json(path, apk)
    require(isinstance(data, dict) and isinstance(data.get('packages'), list), 'not an APKv3 package index')
    packages = [normalize_apk_info(info) for info in data['packages']]
    require(len({x['Package'] for x in packages}) == len(packages), 'duplicate APK index package name')
    return packages


def payload_files(path, apk=None):
    """Return regular payload bytes; package install scripts are never invoked.

    APKv3 target entries include symlinks/hardlinks encoded in metadata. Reject
    writes through any such entry before invoking the trusted extract applet.
    Absolute symlinks themselves are valid router payload but are never read.
    """
    import tempfile
    from pathlib import PurePosixPath
    path = Path(path)
    if path.name.endswith('.ipk'):
        with tarfile.open(path, 'r:*') as outer:
            members = [m for m in outer.getmembers() if m.name.lstrip('./') == 'data.tar.gz']
            require(len(members) == 1 and members[0].isfile(), 'IPK payload missing')
            data = outer.extractfile(members[0]).read()
        result = {}
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as payload:
            for member in payload:
                name = member.name.removeprefix('./')
                relative = PurePosixPath(name)
                require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe IPK payload path')
                if member.isfile():
                    require(name not in result and member.size <= 512 * 1024**2, 'duplicate/oversized IPK payload file')
                    result[name] = payload.extractfile(member).read()
        return result
    data = apk_json(path, apk)
    require(isinstance(data, dict) and isinstance(data.get('paths'), list), 'APK paths metadata missing')
    directories, files, links = set(), {}, set()
    total = 0
    for directory in data['paths']:
        require(isinstance(directory, dict), 'invalid APK payload directory')
        name = directory.get('name', '')
        require(isinstance(name, str), 'invalid APK payload directory name')
        relative = PurePosixPath(name)
        require( (name == '' or (str(relative) == name and not relative.is_absolute()
                and '..' not in relative.parts and '\\' not in name)), 'unsafe APK payload directory')
        require(name not in directories, 'duplicate APK payload directory')
        directories.add(name)
        require(isinstance(directory.get('files', []), list), 'invalid APK payload files')
        for item in directory.get('files', []):
            require(isinstance(item, dict), 'invalid APK payload file')
            leaf = item.get('name')
            require(isinstance(leaf, str) and leaf not in ('', '.', '..') and '/' not in leaf and '\\' not in leaf,
                    'unsafe APK payload filename')
            full = name + '/' + leaf if name else leaf
            require(full not in files, 'duplicate APK payload file')
            size = item.get('size', 0)
            require(type(size) is int and 0 <= size <= 512 * 1024**2, 'APK payload file exceeds limit')
            files[full] = item
            total += size
            if 'target' in item:
                try:
                    target = bytes.fromhex(item['target'])
                except (TypeError, ValueError) as error:
                    raise ValueError('invalid APK link metadata') from error
                require(len(target) >= 2 and int.from_bytes(target[:2], 'little') in (0xA000, 0x8000), 'unsupported APK special payload file')
                if int.from_bytes(target[:2], 'little') == 0x8000:
                    linked = target[2:].decode('utf-8')
                    linkpath = PurePosixPath(linked)
                    require(not linkpath.is_absolute() and '..' not in linkpath.parts, 'unsafe APK hardlink target')
                links.add(full)
    require(total <= 1024**3 and len(files) <= 100000, 'APK payload exceeds inventory limit')
    require(not (directories & set(files)), 'APK payload file/directory collision')
    for name in list(directories) + list(files):
        require(not any(str(parent) in links for parent in PurePosixPath(name).parents), 'APK payload writes through a link')
    with tempfile.TemporaryDirectory(prefix='ax6000-apk-payload-') as temporary:
        destination = Path(temporary)
        subprocess.run([str(Path(apk).resolve()), '--no-network', '--allow-untrusted', 'extract', '--no-chown',
                        '--destination', str(destination), str(path.resolve())], check=True, stdout=subprocess.DEVNULL, timeout=120)
        result = {}
        for name, item in files.items():
            if name in links:
                continue
            target = destination / name
            require(target.is_file() and not target.is_symlink() and target.resolve().is_relative_to(destination),
                    'APK extracted payload is not regular or escapes root')
            content = target.read_bytes()
            require(len(content) == item.get('size', 0), 'APK payload file size differs from metadata')
            result[name] = content
        return result


def installed_controls(root, apk):
    """Read the installed package DB with a trusted host query, never scripts."""
    root, apk = Path(root), Path(apk)
    require(root.is_dir() and not root.is_symlink() and apk.is_file() and not apk.is_symlink(), 'installed APK database/tool missing')
    raw = bounded_output([str(apk.resolve()), '--no-network', '--root', str(root.resolve()),
        '--repositories-file', '/dev/null', 'query', '--format', 'json', '--fields',
        'name,version,arch,depends,provides,tags', '--installed', '*'])
    require(len(raw) <= 32 * 1024**2, 'installed APK database exceeds limit')
    data = json.loads(raw)
    require(isinstance(data, list), 'invalid installed APK query result')
    controls = [normalize_apk_info(info) for info in data]
    require(len({x['Package'] for x in controls}) == len(controls), 'duplicate installed APK package identity')
    return controls
