#!/usr/bin/env python3
"""Bounded static verification of a native stock AX6000 factory UBI.

No target code, SDK executable, filesystem extraction, flash or network access.
UBI constants follow Linux drivers/mtd/ubi/ubi-media.h; newc follows the
Linux initramfs format. The original FIT must be pinned by the caller AND
the native firmware manifest. Static checks do not establish hardware boot.
"""
import hashlib
import lzma
import re
import stat
import struct
import zlib
from pathlib import Path, PurePosixPath

MIB = 1024 ** 2
PEB, PAGE, DATA, LEB = 131072, 2048, 4096, 126976
LIMIT = 30720 * 1024
LAYOUT = 0x7fffefff
DEVICE = 'xiaomi_redmi-router-ax6000-stock'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bounded(path, cap):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= cap,
         'Missing, linked or oversized input: ' + str(path))
    data = path.read_bytes()
    need(len(data) <= cap, 'Input grew while reading')
    return data


def align(value, n=4):
    return (value + n - 1) // n * n


def text(value):
    need(value.endswith(b'\0') and value.count(b'\0') == 1, 'Invalid FIT string')
    return value[:-1].decode('ascii')


def fdt(data, cap=64 * MIB):
    need(40 <= len(data) <= cap, 'FDT size cap')
    magic, total, off, strings, reserve, version, last, _, slen, dlen = struct.unpack_from('>10I', data)
    need(magic == 0xd00dfeed and version == 17 and last <= 17 and total == len(data), 'FDT header/size')
    spans = [(off, off + dlen), (strings, strings + slen)]
    need(off % 4 == 0 and reserve % 8 == 0 and all(40 <= a < b <= total for a, b in spans), 'FDT spans')
    need(spans[0][1] <= spans[1][0] or spans[1][1] <= spans[0][0], 'FDT overlapping spans')
    r = reserve
    for _ in range(256):
        need(40 <= reserve and r + 16 <= total, 'FDT reserve map')
        pair = struct.unpack_from('>QQ', data, r); r += 16
        if pair == (0, 0):
            break
    else:
        raise ValueError('FDT reserve cap')
    need(all(r <= a or b <= reserve for a, b in spans), 'FDT reserve overlap')
    nodes, stack, props = {}, [], 0
    end = off + dlen
    while off < end:
        need(off + 4 <= end, 'FDT token truncated')
        token = struct.unpack_from('>I', data, off)[0]; off += 4
        if token == 1:
            nul = data.find(b'\0', off, end)
            need(0 <= nul - off <= 255, 'FDT node name')
            name = data[off:nul].decode('ascii'); off = align(nul + 1)
            need('/' not in name and name not in ('.', '..'), 'FDT unsafe node')
            need((not stack and not name and not nodes) or (stack and name), 'FDT root')
            path = (stack[-1].rstrip('/') + '/' + name) if stack else '/'
            need(path not in nodes, 'FDT duplicate node')
            nodes[path] = {}; stack.append(path)
            need(len(stack) <= 64 and len(nodes) <= 4096, 'FDT nodes cap')
        elif token == 2:
            need(bool(stack), 'FDT unbalanced node'); stack.pop()
        elif token == 3:
            need(stack and off + 8 <= end, 'FDT property truncated')
            length, nameoff = struct.unpack_from('>II', data, off); off += 8
            need(nameoff < slen and off + length <= end, 'FDT property span')
            start = strings + nameoff; nul = data.find(b'\0', start, strings + slen)
            need(0 <= nul - start <= 255, 'FDT property name')
            name = data[start:nul].decode('ascii')
            need(name and '/' not in name and name not in nodes[stack[-1]], 'FDT duplicate property')
            nodes[stack[-1]][name] = data[off:off + length]; off = align(off + length)
            props += 1; need(props <= 16384, 'FDT properties cap')
        elif token == 4:
            pass
        elif token == 9:
            need(not stack and not any(data[off:end]), 'FDT trailing structure')
            return nodes
        else:
            raise ValueError('FDT unknown token')
        need(off <= end, 'FDT alignment cap')
    raise ValueError('FDT missing end')


def stock_dtb(data):
    tree = fdt(data, MIB)
    compatible = tree['/'].get('compatible', b'').split(b'\0')
    need(b'xiaomi,redmi-router-ax6000-stock' in compatible and b'mediatek,mt7986a' in compatible,
         'Wrong stock DT compatible')
    expected = {'ubi_kernel': (0x600000, 0x1e00000), 'ubi': (0x2400000, 0x5000000)}
    actual = {}
    for node in tree.values():
        if node.get('label') in (b'ubi_kernel\0', b'ubi\0'):
            name = text(node['label']); need(name not in actual and len(node.get('reg', b'')) == 8, 'Duplicate/invalid stock partition')
            actual[name] = struct.unpack('>II', node['reg'])
    need(actual == expected, 'Wrong stock NAND partition geometry')


def fit(data):
    tree = fdt(data)
    need(len(tree['/'].get('timestamp', b'')) == 4, 'FIT timestamp absent')
    need(text(tree.get('/configurations', {}).get('default', b'')) == 'config-1', 'FIT default config')
    config = tree.get('/configurations/config-1', {})
    need({k: text(config.get(k, b'')) for k in ('kernel', 'fdt', 'ramdisk')} ==
         {'kernel': 'kernel-1', 'fdt': 'fdt-1', 'ramdisk': 'initrd-1'}, 'FIT boot references')
    need('loadables' not in config and [p for p in tree if p.startswith('/configurations/')].__len__() == 1,
         'Unexpected FIT configurations/loadables')
    payloads = {}
    for name, kind in [('kernel-1', 'kernel'), ('fdt-1', 'flat_dt'), ('initrd-1', 'ramdisk')]:
        path = '/images/' + name; node = tree.get(path, {})
        need(text(node.get('type', b'')) == kind and text(node.get('arch', b'')) == 'arm64', 'FIT payload type/architecture')
        need('data' in node and not any(k in node for k in ('data-offset', 'data-position', 'data-size')), 'FIT must have inline data')
        content = node['data']; need(bool(content), 'FIT empty payload')
        if kind == 'kernel':
            need(text(node.get('compression', b'')) == 'lzma' and text(node.get('os', b'')) == 'linux', 'FIT kernel encoding')
            need(node.get('load') == node.get('entry') == struct.pack('>I', 0x48000000), 'FIT kernel address')
        elif kind == 'flat_dt':
            need(text(node.get('compression', b'')) == 'none', 'FIT DT compression')
            stock_dtb(content)
        else:
            need(text(node.get('os', b'')) == 'linux' and node.get('compression', b'none\0') == b'none\0', 'FIT ramdisk encoding')
            need(content.startswith(b'\xfd7zXZ\x00'), 'Expected XZ separate ramdisk')
        hashes = [p for p in tree if p.startswith(path + '/')]
        need(len(hashes) == 2 and all('/' not in p[len(path) + 1:] for p in hashes), 'FIT hash nodes')
        algorithms = set()
        for h in hashes:
            item = tree[h]; algorithm = text(item.get('algo', b'')); need(algorithm not in algorithms, 'FIT duplicate hash')
            algorithms.add(algorithm)
            need(algorithm in ('crc32', 'sha1', 'sha256'), 'Unsupported FIT hash')
            expected = struct.pack('>I', zlib.crc32(content)) if algorithm == 'crc32' else hashlib.new(algorithm, content).digest()
            need(item.get('value') == expected, 'FIT payload hash mismatch')
        need('crc32' in algorithms and bool(algorithms & {'sha1', 'sha256'}), 'FIT hash algorithms')
        payloads[kind] = content
    need({p for p in tree if p.startswith('/images/') and p.count('/') == 2} ==
         {'/images/kernel-1', '/images/fdt-1', '/images/initrd-1'}, 'Unexpected FIT image')
    payloads['timestamp'] = struct.unpack('>I', tree['/']['timestamp'])[0]
    return payloads


def canonical(name):
    need('\x00' not in name and '\\' not in name and not name.startswith('/'), 'Unsafe CPIO name')
    original = name
    if name.startswith('./'):
        name = name[2:]
    need(name == '.' or (name and PurePosixPath(name).as_posix() == name and '..' not in PurePosixPath(name).parts), 'Noncanonical CPIO path')
    need(original == name or original == './' + name, 'CPIO path prefix')
    return name


def cpio(compressed):
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=128 * MIB)
    data = dec.decompress(compressed, max_length=256 * MIB + 1)
    need(len(data) <= 256 * MIB and dec.eof and not dec.unused_data, 'XZ cap/truncation/concatenated stream')
    pos, entries, total = 0, {}, 0
    while True:
        start = pos; need(pos + 110 <= len(data), 'CPIO header truncated')
        header = data[pos:pos + 110]; pos += 110
        need(header[:6] == b'070701' and re.fullmatch(b'[0-9a-fA-F]{104}', header[6:]), 'CPIO newc header')
        values = tuple(int(header[6 + i * 8:14 + i * 8], 16) for i in range(13))
        ino, mode, uid, gid, nlink, mtime, size, devmaj, devmin, rmaj, rmin, namesize, check = values
        need(1 <= namesize <= 4096 and nlink >= 1 and check == 0 and size <= 128 * MIB, 'CPIO member bounds')
        need(pos + namesize <= len(data) and data[pos + namesize - 1] == 0 and b'\0' not in data[pos:pos + namesize - 1], 'CPIO name truncated')
        name = data[pos:pos + namesize - 1].decode('utf-8'); pos += namesize
        aligned = align(pos); need(not any(data[pos:aligned]), 'CPIO name padding'); pos = aligned
        need(pos + size <= len(data), 'CPIO data truncated'); content = memoryview(data)[pos:pos + size]; pos += size
        aligned = align(pos); need(not any(data[pos:aligned]), 'CPIO data padding'); pos = aligned
        if name == 'TRAILER!!!':
            need(size == 0 and not any(data[pos:]) and len(data) - pos < 512, 'CPIO trailer/padding')
            break
        name = canonical(name); need(name not in entries and len(entries) < 30000, 'CPIO duplicate/count')
        kind = stat.S_IFMT(mode)
        need(kind in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK), 'CPIO member type')
        need(kind not in (stat.S_IFDIR, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK) or size == 0, 'CPIO special member data')
        capture = (kind == stat.S_IFLNK or name in ('usr/lib/opkg/status', 'lib/apk/db/installed')
                   or (name.startswith(('usr/lib/opkg/info/', 'lib/apk/packages/')) and name.endswith('.list')))
        need(not capture or size <= (4 * MIB if name == 'lib/apk/db/installed' else MIB), 'CPIO metadata cap')
        entries[name] = {'values': values, 'kind': kind, 'raw_sha256': sha(memoryview(data)[start:pos]),
                         'data_sha256': sha(content), 'size': size, 'data': bytes(content) if capture else None}
        total += size; need(total <= 256 * MIB, 'CPIO declared byte cap')
    for name in entries:
        for parent in PurePosixPath(name).parents:
            if parent.as_posix() != '.':
                need(parent.as_posix() not in entries or entries[parent.as_posix()]['kind'] == stat.S_IFDIR,
                     'CPIO traversal through non-directory')
    return entries


def link_target(name, target):
    need(b'\0' not in target, 'Symlink NUL')
    target = target.decode('utf-8')
    parts = [] if target.startswith('/') else list(PurePosixPath(name).parent.parts)
    for part in target.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            need(bool(parts), 'Symlink escapes root'); parts.pop()
        else:
            parts.append(part)
    return '/'.join(parts)


ESSENTIAL = ('init', 'bin/busybox', 'sbin/init', 'sbin/procd', 'usr/sbin/dropbear',
             'etc/init.d/dropbear', 'sbin/netifd', 'etc/init.d/network',
             'etc/board.d/02_network', 'sbin/sysupgrade', 'lib/upgrade/nand.sh',
             'lib/upgrade/platform.sh', 'lib/upgrade/common.sh', 'lib/functions.sh',
             'bin/ubus', 'sbin/ubusd', 'sbin/uci', 'usr/bin/jsonfilter',
             'usr/sbin/ubiformat', 'usr/sbin/ubiattach', 'usr/sbin/ubidetach', 'usr/sbin/ubimkvol',
             'usr/sbin/ubirmvol', 'usr/sbin/ubiupdatevol', 'usr/bin/fwtool',
             'usr/sbin/fw_printenv', 'usr/sbin/fw_setenv', 'etc/uci-defaults/30_uboot-envtools')


def ubi_crc(data):
    return zlib.crc32(data) ^ 0xffffffff


def ubi(data, expected_fit, image_seq=None):
    need(0 < len(data) <= LIMIT and len(data) % PEB == 0, 'UBI stock 30MiB/PEB size bound')
    records, seqs, eof = {}, set(), 0
    for offset in range(0, len(data), PEB):
        block = memoryview(data)[offset:offset + PEB]; ec = block[:64]
        magic, version = struct.unpack_from('>IB', ec)
        counter, vid, start, seq = struct.unpack_from('>QIII', ec, 8)
        need(magic == 0x55424923 and version == 1 and counter == 0 and (vid, start) == (PAGE, DATA), 'UBI EC geometry/version/counter')
        need(ec[5:8] in (b'\0\0\0', b'EOF') and not any(ec[28:60]) and struct.unpack_from('>I', ec, 60)[0] == ubi_crc(ec[:60]), 'UBI EC CRC/padding')
        seqs.add(seq); need(len(seqs) == 1, 'UBI image sequence differs')
        need(image_seq is None or image_seq == seq, 'UBI image sequence differs from original FIT timestamp')
        if ec[5:8] == b'EOF':
            need(all(v == 255 for v in block[64:]), 'UBI EOF marker payload')
            eof += 1
            continue
        need(eof == 0, 'UBI EOF marker is not at image end')
        need(all(v == 255 for v in block[64:PAGE]), 'UBI EC page padding')
        header = block[PAGE:PAGE + 64]
        magic, version, kind, copy, compat, volid, lnum = struct.unpack_from('>IBBBBII', header)
        size, used, pad, crc = struct.unpack_from('>IIII', header, 20)
        sqnum = struct.unpack_from('>Q', header, 40)[0]
        need(magic == 0x55424921 and version == 1 and kind == 1 and copy == 0 and
             volid in (0, LAYOUT) and compat == (5 if volid == LAYOUT else 0), 'UBI VID volume/type/compatibility')
        need(size == used == pad == crc == sqnum == 0 and not any(header[16:20]) and not any(header[36:40]) and not any(header[48:60]), 'UBI dynamic VID fields')
        need(struct.unpack_from('>I', header, 60)[0] == ubi_crc(header[:60]), 'UBI VID CRC')
        need(all(v == 255 for v in block[PAGE + 64:DATA]), 'UBI VID page padding')
        key = (volid, lnum); need(key not in records, 'UBI duplicate logical block'); records[key] = bytes(block[DATA:])
    need(eof == 5, 'UBI must contain exactly five native EOF markers')
    need((LAYOUT, 0) in records and (LAYOUT, 1) in records, 'UBI redundant layout blocks absent')
    table = records.pop((LAYOUT, 0)); need(table == records.pop((LAYOUT, 1)), 'UBI redundant volume tables differ')
    need(all(v == 255 for v in table[128 * 172:]), 'UBI volume table padding')
    nblocks = (len(expected_fit) + LEB - 1) // LEB
    for index in range(128):
        row = table[index * 172:(index + 1) * 172]
        need(struct.unpack_from('>I', row, 168)[0] == ubi_crc(row[:168]), 'UBI volume table CRC')
        if index == 0:
            reserved, alignment, pad, kind, update, namelen = struct.unpack_from('>IIIBBH', row)
            need((reserved, alignment, pad, kind, update, namelen) == (nblocks, 1, 0, 1, 0, 6), 'UBI kernel volume table geometry')
            need(row[16:22] == b'kernel' and not any(row[22:168]), 'UBI kernel name/flags/autoresize')
        else:
            need(not any(row[:168]), 'UBI extra user volume')
    need(set(records) == {(0, i) for i in range(nblocks)}, 'UBI kernel volume LEB coverage/foreign volume')
    payload = b''.join(records[(0, i)] for i in range(nblocks))
    need(payload[:len(expected_fit)] == expected_fit and all(v == 255 for v in payload[len(expected_fit):]), 'UBI kernel payload/padding differs from bootstrap FIT')
    return {'peb_size': PEB, 'min_io_size': PAGE, 'vid_offset': PAGE, 'data_offset': DATA,
            'erase_counter': 0, 'eof_markers': eof, 'kernel_volume_id': 0, 'kernel_volume_type': 'dynamic',
            'autoresize': False, 'layout_copies': 2, 'kernel_blocks': nblocks,
            'partition_limit': LIMIT, 'spare_partition_blocks': LIMIT // PEB - len(data) // PEB}


PACKAGE_PATHS = {'tailscale': {'usr/sbin/tailscale', 'usr/bin/tailscale',
                 'usr/sbin/tailscaled', 'usr/bin/tailscaled', 'etc/init.d/tailscale',
                 'etc/config/tailscale', 'lib/upgrade/keep.d/tailscale'}}


def package_policy(profile):
    names = profile.get('package_only', [])
    need(isinstance(names, list) and len(names) == len(set(names)) and
         all(isinstance(name, str) and name in PACKAGE_PATHS for name in names),
         'Unsupported/duplicate package_only policy')
    need(set(names) <= set(profile.get('packages', [])) and not set(names) & set(profile.get('image_packages', [])),
         'package_only must remain downloadable and be excluded from image_packages')
    return names


def status_packages(data):
    need(len(data) <= 4 * MIB, 'Initramfs status byte cap')
    result = {}
    for block in data.decode('utf-8').split('\n\n'):
        if not block.strip():
            continue
        fields = {}
        for line in block.splitlines():
            if line.startswith((' ', '\t')):
                need(fields, 'Orphan initramfs status continuation')
                continue
            # opkg writes a bare Conffiles: header before continuation rows.
            match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9-]*):[ \t]*(.*)', line)
            need(match is not None, 'Malformed initramfs status line')
            key, value = match.groups()
            need(key not in fields, 'Duplicate initramfs status field'); fields[key] = value
        name = fields.get('Package')
        need(name and name not in result and fields.get('Version') and fields.get('Architecture'),
             'Missing/duplicate initramfs status identity')
        # Native toolchain packages carry PKG_FLAGS:=hold. This opkg flag is
        # independent of the third token, which records installation state.
        need(fields.get('Status') in ('install ok installed', 'install hold installed'),
             'Initramfs package is not installed with an approved flag: ' + name)
        result[name] = fields
    need(result, 'Empty initramfs package status')
    return result


def apk_status_packages(data):
    """Read APK's installed text DB offline, retaining actual ABI package names.

    File ownership records (F/R/a/Z...) may repeat and are not package fields.
    Logical aliases strip only the exact declared openwrt:abiversion suffix.
    Neither apk scripts nor target APK executables are invoked.
    """
    need(isinstance(data, bytes) and 0 < len(data) <= 4 * MIB and data.endswith(b'\n\n'),
         'APK installed database bounds/truncation')
    result, bases = {}, set()
    for paragraph in data.decode('utf-8').split('\n\n'):
        if not paragraph.strip():
            continue
        fields, tags = {}, []
        for line in paragraph.splitlines():
            need(len(line) >= 2 and line[1] == ':' and line[0].isascii() and line[0].isalpha(),
                 'Malformed APK installed database line')
            key, value = line[0], line[2:]
            if key in ('P', 'V', 'A', 'D', 'p'):
                need(key not in fields, 'Duplicate APK installed identity field')
                fields[key] = value
            elif key == 'g':
                tags.extend(value.split())
        name, version, arch = (fields.get(key, '') for key in ('P', 'V', 'A'))
        need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+:-]*', name)
             and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+~:-]*', version)
             and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_+-]*', arch), 'Malformed APK installed identity')
        need(name not in result, 'Duplicate APK installed Package')
        abi = [tag.split('=', 1)[1] for tag in tags if tag.startswith('openwrt:abiversion=')]
        need(len(abi) <= 1 and (not abi or (abi[0] and len(name) > len(abi[0]) and name.endswith(abi[0]))),
             'APK installed ABI suffix tag mismatch')
        base = name[:-len(abi[0])] if abi else name
        need(base not in bases, 'Duplicate APK installed logical package')
        bases.add(base)
        record = {'Package': name, 'APK-Name': name, 'Base-Package': base,
                  'Version': version, 'Architecture': arch, 'Status': 'install ok installed'}
        if abi:
            record['ABIVersion'] = abi[0]
        if 'D' in fields:
            record['APK-Depends'] = fields['D']
        if 'p' in fields:
            record['APK-Provides'] = fields['p']
        result[name] = record
    need(result, 'Empty APK installed database')
    return result


def assert_absent(package_names, installed, paths, symlinks=None):
    """Use actual file inventory/status, never infer absence from source selections."""
    paths = set(paths)
    for package in package_names:
        need(package in PACKAGE_PATHS and package not in installed, 'package_only is installed: ' + package)
        need(not paths & PACKAGE_PATHS[package], 'package_only payload remains in image: ' + package)
        need(not any(name.startswith(('usr/lib/opkg/info/' + package + '.', 'lib/apk/packages/' + package + '.')) for name in paths),
             'package_only metadata remains in image: ' + package)
        need(not any(name.startswith('etc/rc.d/') and name.rsplit('/', 1)[-1].endswith(package) for name in paths),
             'package_only service symlink remains in image: ' + package)
        for name, target in (symlinks or {}).items():
            need(link_target(name, target) not in PACKAGE_PATHS[package],
                 'Retained symlink targets package_only payload: ' + package)


def verify_native_factory(ram_fit, factory_ubi, *, package_only=(), expected_packages=None,
                          expected_dtb_sha256=None, kernel_inputs=None, package_manager='opkg', expected_files=None, expected_hashes=None, exclude_asu=False):
    """Require factory's one kernel volume to be the exact native full RAM FIT.

    kernel_inputs are trusted KDIR/Image-initramfs* snapshots, distinct from
    the pre-initramfs KDIR/Image used by sysupgrade. They are never executed.
    """
    ram = bounded(ram_fit, 64 * MIB)
    factory = bounded(factory_ubi, LIMIT)
    blobs = fit(ram)
    geometry = ubi(factory, ram, blobs['timestamp'])
    entries = cpio(blobs['ramdisk'])
    need(package_manager in ('opkg', 'apk'), 'Unsupported factory package manager')
    database = 'lib/apk/db/installed' if package_manager == 'apk' else 'usr/lib/opkg/status'
    other = 'usr/lib/opkg/status' if package_manager == 'apk' else 'lib/apk/db/installed'
    need(database in entries and other not in entries, 'Initramfs package database absent or mixed manager')
    installed = (apk_status_packages if package_manager == 'apk' else status_packages)(entries[database]['data'])
    if package_manager == 'apk':
        need('usr/bin/apk' in entries and not any(name in entries for name in ('bin/opkg', 'usr/bin/opkg')),
             'Initramfs APK executable absent or OPKG executable retained')
        need(any(name.startswith('etc/apk/keys/') and name.endswith('.pem') for name in entries),
             'Initramfs APK PEM public key absent')
        need('etc/apk/repositories.d/distfeeds.list' in entries, 'Initramfs APK repository list absent')
        need('etc/apk/world' in entries, 'Initramfs APK world policy absent')
    for name, (expected, mode) in (expected_files or {}).items():
        need(name in entries, 'Initramfs trusted overlay absent: ' + name)
        item = entries[name]
        need(item['kind'] == stat.S_IFREG and item['data_sha256'] == sha(expected)
             and item['size'] == len(expected) and item['values'][1] & 0o7777 == mode
             and item['values'][2:4] == (0, 0), 'Initramfs trusted overlay differs: ' + name)
    for name, digest in (expected_hashes or {}).items():
        need(re.fullmatch(r'[0-9a-f]{64}', digest) and name in entries,
             'Initramfs expected feature hash/path absent: ' + name)
        item = entries[name]
        need(item['kind'] == stat.S_IFREG and item['data_sha256'] == digest
             and item['values'][2:4] == (0, 0) and not item['values'][1] & 0o022,
             'Initramfs optional feature bytes/owner/mode differ: ' + name)
    symlinks = {name: item['data'] for name, item in entries.items() if item['kind'] == stat.S_IFLNK}
    assert_absent(package_only, installed, entries, symlinks)
    if exclude_asu:
        import importlib.util
        spec = importlib.util.spec_from_file_location("factory_no_asu", Path(__file__).with_name("no_asu.py"))
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        helper.assert_absent(installed, entries, symlinks)
    essential = ESSENTIAL + (('usr/bin/apk',) if package_manager == 'apk' else ())
    for name in essential:
        need(name in entries, 'Initramfs essential absent: ' + name)
        item = entries[name]
        if item['kind'] == stat.S_IFLNK:
            target = link_target(name, item['data'])
            need(target in entries, 'Initramfs essential symlink is dangling: ' + name)
            item = entries[target]
        need(item['kind'] == stat.S_IFREG and item['size'] > 0 and item['values'][2:4] == (0, 0),
             'Initramfs essential type/size/owner: ' + name)
        executable = name == 'init' or name.startswith(('bin/', 'sbin/', 'usr/bin/', 'usr/sbin/', 'etc/init.d/'))
        need(item['values'][1] & (0o111 if executable else 0o400) and not item['values'][1] & 0o022,
             'Initramfs essential mode: ' + name)
    loaders = [name for name in entries if name.startswith('lib/ld-musl-')]
    need(len(loaders) == 1, 'Initramfs musl loader missing/ambiguous')
    if expected_packages is not None:
        need(set(installed) == set(expected_packages), 'Initramfs packages differ from actual stock sysupgrade')
        for name, record in installed.items():
            need(all(record.get(key) == expected_packages[name].get(key) for key in ('Version', 'Architecture')),
                 'Initramfs/native IPK package identity differs: ' + name)
    if expected_dtb_sha256 is not None:
        need(sha(blobs['flat_dt']) == expected_dtb_sha256, 'Factory RAM FIT DTB differs from verified stock sysupgrade')
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 * MIB)
    kernel = dec.decompress(blobs['kernel'], max_length=64 * MIB + 1)
    need(len(kernel) <= 64 * MIB and dec.eof and not dec.unused_data and
         len(kernel) >= 64 and kernel[56:60] == b'ARM\x64', 'Factory RAM FIT kernel compression/ARM64 image')
    kernel_sha = sha(kernel)
    matched = []
    if kernel_inputs is not None:
        need(1 <= len(kernel_inputs) <= 8, 'Trusted native initramfs kernel input count')
        for path in kernel_inputs:
            path = Path(path)
            if sha(bounded(path, 64 * MIB)) == kernel_sha:
                matched.append(str(path))
        need(matched, 'Factory RAM FIT kernel differs from trusted KDIR/Image-initramfs inputs')
    return {'ok': True, 'ram_fit': {'sha256': sha(ram), 'size': len(ram)},
            'factory_ubi': {'sha256': sha(factory), 'size': len(factory)},
            'kernel_sha256': kernel_sha, 'compressed_kernel_sha256': sha(blobs['kernel']),
            'fdt_sha256': sha(blobs['flat_dt']), 'ramdisk_sha256': sha(blobs['ramdisk']),
            'kernel_inputs_matched': matched, 'installed_packages': sorted(installed),
            'package_only_absent': list(package_only), 'essential_paths': list(essential),
            'package_manager': package_manager, 'package_database': database,
            'verified_overlay_files': sorted(expected_files or {}),
            'verified_feature_files': sorted(expected_hashes or {}),
            'cpio_entries': len(entries), 'ubi_geometry': geometry,
            'hardware_boot_verified': False, 'flash_verified': False}

