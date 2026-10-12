"""Bounded, read-only FDT/FIT payload parsing; never executes imported tools."""
import hashlib
from pathlib import Path
import struct
import zlib

MIB = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def align4(number):
    return (number + 3) & ~3


def stringlist(value):
    value = bytes(value)
    require(0 < len(value) <= 4096 and value.endswith(b'\0'), 'Invalid FDT string list')
    result = value[:-1].split(b'\0')
    require(all(result), 'Empty FDT string')
    try:
        return [part.decode('ascii') for part in result]
    except UnicodeDecodeError as exc:
        raise ValueError('Non-ASCII FDT string') from exc


def text(value):
    values = stringlist(value)
    require(len(values) == 1, 'Expected exactly one FDT string')
    return values[0]


def cell(value):
    require(len(value) == 4, 'Expected one big-endian 32-bit FDT cell')
    return struct.unpack('>I', value)[0]


class FDT:
    """Parse a bounded FDT, retaining property ranges for inline FIT data."""
    def __init__(self, data, max_nodes=4096, max_properties=16384):
        require(len(data) >= 40, 'Truncated FDT header')
        (magic, total, structure, strings, reserve, version, last, _,
         strings_size, structure_size) = struct.unpack_from('>10I', data)
        require(magic == 0xd00dfeed, 'Invalid FDT magic')
        require(version == 17 and last <= 17, 'Unsupported FDT version')
        require(40 <= total <= len(data), 'Invalid FDT total size')
        require(structure % 4 == 0 and reserve % 8 == 0, 'Unaligned FDT header span')
        spans = [(structure, structure + structure_size), (strings, strings + strings_size)]
        require(all(40 <= a < b <= total for a, b in spans), 'Invalid FDT structure/string span')
        require(spans[0][1] <= spans[1][0] or spans[1][1] <= spans[0][0], 'Overlapping FDT spans')
        require(40 <= reserve < total, 'Invalid FDT reserve span')
        cursor = reserve
        for _ in range(256):
            require(cursor + 16 <= total, 'Unterminated FDT memory reserve map')
            pair = struct.unpack_from('>QQ', data, cursor)
            cursor += 16
            if pair == (0, 0):
                break
        else:
            raise ValueError('FDT memory reserve map cap exceeded')
        require(all(cursor <= a or b <= reserve for a, b in spans), 'Overlapping FDT reserve map')
        self.total = total
        self.nodes = {}
        self.ranges = {}
        view = memoryview(data)
        stack = []
        pos, end = structure, structure + structure_size
        properties = 0
        finished = False
        while pos < end:
            require(pos + 4 <= end, 'Truncated FDT token')
            token = struct.unpack_from('>I', view, pos)[0]
            pos += 4
            if token == 1:
                nul = data.find(b'\0', pos, end)
                require(nul >= pos and nul - pos <= 255, 'Invalid FDT node name')
                try:
                    name = data[pos:nul].decode('ascii')
                except UnicodeDecodeError as exc:
                    raise ValueError('Invalid FDT node name') from exc
                require('/' not in name and name not in ('.', '..'), 'Unsafe FDT node name')
                require((not stack and not name and not self.nodes) or (stack and name), 'Invalid FDT root')
                path = (stack[-1] + '/' + name) if stack and stack[-1] != '/' else '/' + name
                require(path not in self.nodes, 'Duplicate FDT node')
                self.nodes[path] = {}
                stack.append(path)
                require(len(stack) <= 64 and len(self.nodes) <= max_nodes, 'FDT node/depth cap exceeded')
                pos = align4(nul + 1)
            elif token == 2:
                require(bool(stack), 'Unbalanced FDT END_NODE')
                stack.pop()
            elif token == 3:
                require(stack and pos + 8 <= end, 'Invalid FDT property token')
                length, offset = struct.unpack_from('>II', view, pos)
                pos += 8
                require(offset < strings_size and pos + length <= end, 'Invalid FDT property range')
                start = strings + offset
                nul = data.find(b'\0', start, strings + strings_size)
                require(nul >= start and nul - start <= 255, 'Invalid FDT property name')
                name = data[start:nul].decode('ascii')
                require(name and '/' not in name, 'Invalid FDT property name')
                require(name not in self.nodes[stack[-1]], 'Duplicate FDT property')
                self.nodes[stack[-1]][name] = view[pos:pos + length]
                self.ranges[(stack[-1], name)] = (pos, length)
                properties += 1
                require(properties <= max_properties, 'FDT property cap exceeded')
                pos = align4(pos + length)
            elif token == 4:
                continue
            elif token == 9:
                require(not stack and '/' in self.nodes, 'Unbalanced FDT END')
                require(not any(view[pos:end]), 'Unexpected data after FDT END')
                finished = True
                break
            else:
                raise ValueError('Unknown FDT structure token')
            require(pos <= end, 'FDT alignment exceeds structure')
        require(finished, 'Missing FDT END token')

    def children(self, path):
        prefix = path.rstrip('/') + '/'
        return [p for p in self.nodes if p.startswith(prefix) and '/' not in p[len(prefix):]]


def read_fdt(path, cap):
    with Path(path).open('rb') as stream:
        head = stream.read(40)
        require(len(head) == 40, 'Truncated FDT header')
        total = struct.unpack_from('>I', head, 4)[0]
        require(40 <= total <= cap, 'FDT header byte cap exceeded')
        data = head + stream.read(total - 40)
    require(len(data) == total, 'Truncated FDT')
    return FDT(data)


def extract_fit(path, work, *, external, allow_offset=False):
    """Resolve native sysupgrade FIT refs, hash exact ranges, copy bounded blobs."""
    path, work = Path(path), Path(work)
    size = path.stat().st_size
    require(40 <= size <= 128 * MIB, 'FIT image byte cap exceeded')
    tree = read_fdt(path, 64 * 1024 if external else 32 * MIB)
    if not external:
        require(size == tree.total, 'Unexpected trailing inline FIT data')
    require('/configurations' in tree.nodes and '/images' in tree.nodes, 'Missing FIT configurations/images')
    default = text(tree.nodes['/configurations'].get('default', b''))
    require(default == 'config-1', 'Unexpected FIT default configuration')
    config = tree.nodes.get('/configurations/' + default)
    require(config is not None and 'ramdisk' not in config, 'Invalid sysupgrade FIT configuration')
    refs = {'kernel': text(config.get('kernel', b'')), 'fdt': text(config.get('fdt', b''))}
    if external:
        loadables = stringlist(config.get('loadables', b''))
        require(loadables == ['rootfs-1'], 'Invalid FIT root loadables references')
        refs['root'] = loadables[0]
    else:
        require('loadables' not in config, 'Unexpected inline FIT loadables')
    require(refs == ({'kernel': 'kernel-1', 'fdt': 'fdt-1', 'root': 'rootfs-1'} if external else
                     {'kernel': 'kernel-1', 'fdt': 'fdt-1'}), 'Unexpected FIT image references')
    require(set(tree.children('/images')) == {'/images/' + n for n in refs.values()}, 'Unexpected FIT images')
    require(tree.children('/configurations') == ['/configurations/config-1'], 'Unexpected FIT configurations')
    ranges, result = [], {}
    for role, name in refs.items():
        node = '/images/' + name
        props = tree.nodes[node]
        typ = {'kernel': 'kernel', 'fdt': 'flat_dt', 'root': 'filesystem'}[role]
        compression = ('gzip' if external else 'lzma') if role == 'kernel' else 'none'
        require(text(props.get('type', b'')) == typ and text(props.get('compression', b'')) == compression
                and text(props.get('arch', b'')) == 'arm64', 'FIT image type/arch/compression differs')
        if role == 'kernel':
            require(text(props.get('os', b'')) == 'linux', 'FIT kernel OS differs')
        data_fields = set(props) & {'data', 'data-position', 'data-offset', 'data-size'}
        if external:
            require('data' not in data_fields, 'Ambiguous inline/external FIT data')
            mode = 'data-position'
            if allow_offset and data_fields == {'data-offset', 'data-size'}:
                mode = 'data-offset'
            require(data_fields == {mode, 'data-size'}, 'Expected static FIT data-position/size')
            start, length = cell(props[mode]), cell(props['data-size'])
            if mode == 'data-offset':
                start += align4(tree.total)
            require(start >= align4(tree.total), 'FIT data points inside header')
            if mode == 'data-position':
                require(start >= 4096 and start % 4096 == 0, 'Unaligned static FIT data-position')
        else:
            require(data_fields == {'data'}, 'Expected inline FIT data')
            start, length = tree.ranges[(node, 'data')]
            mode = 'inline'
        cap = {'kernel': 32 * MIB, 'fdt': 256 * 1024, 'root': 0x7a80000}[role]
        require(0 < length <= cap and start + length <= size, 'FIT payload exceeds range/byte cap')
        ranges.append((start, start + length))
        result[role] = {'node': name, 'offset': start, 'size': length, 'mode': mode,
                        'compression': compression, 'path': work / (role + '.payload')}
    ordered = sorted(ranges)
    require(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), 'FIT payload ranges overlap')
    if external and not allow_offset:
        require(tree.total == 4096, 'Native static FIT header must be padded to 4096')
        next_position = 4096
        for role in ('kernel', 'fdt', 'root'):
            require(result[role]['offset'] == next_position, 'Non-native static FIT data-position sequence')
            next_position = (next_position + result[role]['size'] + 4095) & ~4095
        require(size == next_position, 'Unexpected trailing static FIT data')
        with path.open('rb') as stream:
            for start, end in ranges:
                stream.seek(end)
                require(not any(stream.read((-end) % 4096)), 'Nonzero static FIT data alignment padding')
    with path.open('rb') as stream:
        for role, record in result.items():
            node = '/images/' + record['node']
            hashes = tree.children(node)
            require(set(hashes) == {node + '/hash-1', node + '/hash-2'}, 'Missing/unexpected FIT hash nodes')
            expected = {}
            for child in hashes:
                props = tree.nodes[child]
                algo = text(props.get('algo', b''))
                require(algo in ('crc32', 'sha1') and algo not in expected, 'Invalid FIT hash algorithm')
                expected[algo] = bytes(props.get('value', b''))
            require(len(expected.get('crc32', b'')) == 4 and len(expected.get('sha1', b'')) == 20,
                    'Invalid FIT hash length')
            stream.seek(record['offset'])
            remaining, crc, sha1, sha256 = record['size'], 0, hashlib.sha1(), hashlib.sha256()
            with record['path'].open('wb') as output:
                while remaining:
                    chunk = stream.read(min(remaining, MIB))
                    require(bool(chunk), 'Truncated FIT data')
                    output.write(chunk)
                    remaining -= len(chunk)
                    crc = zlib.crc32(chunk, crc)
                    sha1.update(chunk)
                    sha256.update(chunk)
            require(struct.pack('>I', crc) == expected['crc32'] and sha1.digest() == expected['sha1'],
                    'FIT payload hash mismatch')
            record.update(sha256=sha256.hexdigest(), hash_algorithms=['crc32', 'sha1'])
    return result
