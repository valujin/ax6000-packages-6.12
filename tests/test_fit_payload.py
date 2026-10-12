"""Independent binary fixtures: no production serializer or image classifier."""
import gzip
import hashlib
import lzma
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
try:
    import fit_payload as fit
except ImportError:
    fit = None


def cell(n):
    return struct.pack('>I', n)


def string(s):
    return s.encode() + b'\0'


def fdt(tree):
    """Small spec-based FDT serializer used only by independent fixtures."""
    names = {}
    strings = bytearray()
    data = bytearray()
    def emit(name, props, children):
        data.extend(cell(1) + string(name))
        data.extend(b'\0' * (-len(data) % 4))
        for key, value in props:
            if key not in names:
                names[key] = len(strings)
                strings.extend(string(key))
            data.extend(cell(3) + cell(len(value)) + cell(names[key]) + value)
            data.extend(b'\0' * (-len(data) % 4))
        for child in children:
            emit(*child)
        data.extend(cell(2))
    emit(*tree)
    data.extend(cell(9))
    start = 56
    total = start + len(data) + len(strings)
    return struct.pack('>10I', 0xd00dfeed, total, start, start + len(data), 40,
                       17, 16, 0, len(strings), len(data)) + b'\0' * 16 + data + strings


def fit_fixture(external=True, relative=False, bad_hash=False, overlap=False,
                root_ref='rootfs-1', ambiguity=False, wide_cell=False,
                kernel_data=b'pre-initramfs-kernel', dtb_data=None):
    kernel = gzip.compress(kernel_data, mtime=0) if external else lzma.compress(
        kernel_data, format=lzma.FORMAT_ALONE)
    dtb = dtb_data or fdt(('', [('compatible', string('xiaomi,redmi-router-ax6000-ubootmod'))], []))
    blobs = [('kernel-1', kernel, 'kernel', 'gzip' if external else 'lzma'),
             ('fdt-1', dtb, 'flat_dt', 'none')]
    if external:
        blobs.append(('rootfs-1', b'hsqs' + b'\0' * 4092, 'filesystem', 'none'))
    children = []
    for i, (name, value, typ, compression) in enumerate(blobs):
        position = 4096 * (i + 1)
        if overlap and i == 2:
            position = 4096
        props = [('type', string(typ)), ('arch', string('arm64')),
                 ('compression', string(compression))]
        if typ == 'kernel':
            props.append(('os', string('linux')))
        if external:
            props += [('data-offset' if relative else 'data-position',
                       b'\0' * 4 + cell(position) if wide_cell else cell(position)),
                      ('data-size', cell(len(value)))]
            if ambiguity and i == 0:
                props.append(('data', value))
        else:
            props.append(('data', value))
        digest = hashlib.sha1(value).digest()
        if bad_hash and i == 0:
            digest = b'X' * 20
        hashes = [('hash-1', [('algo', string('crc32')), ('value', cell(zlib.crc32(value)))], []),
                  ('hash-2', [('algo', string('sha1')), ('value', digest)], [])]
        children.append((name, props, hashes))
    props = [('kernel', string('kernel-1')), ('fdt', string('fdt-1'))]
    if external:
        props.append(('loadables', string(root_ref)))
    tree = ('', [], [('images', [], children),
                    ('configurations', [('default', string('config-1'))],
                     [('config-1', props, [])])])
    header = fdt(tree)
    if not external:
        return header
    if not relative:
        header = bytearray(header)
        struct.pack_into('>I', header, 4, 4096)
        header.extend(b'\0' * (4096 - len(header)))
    # For offset-mode fixtures the native relative base is align4(totalsize).
    base = (len(header) + 3) & ~3 if relative else 0
    data = bytearray(header)
    for i, (_, value, _, _) in enumerate(blobs):
        pos = base + 4096 * (i + 1)
        data.extend(b'\0' * max(0, pos - len(data)))
        data[pos:pos + len(value)] = value
    data.extend(b'\0' * (-len(data) % 4096))
    return bytes(data)


class FitPayloadTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(fit, 'fit_payload implementation is missing')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def inspect(self, data, external=True, allow_offset=False):
        p = self.root / 'input.fit'
        p.write_bytes(data)
        out = self.root / 'out'
        out.mkdir(exist_ok=True)
        return fit.extract_fit(p, out, external=external, allow_offset=allow_offset)

    def test_absolute_position_is_not_relative_to_fdt_end(self):
        records = self.inspect(fit_fixture())
        self.assertEqual(records['kernel']['offset'], 4096)
        self.assertEqual(records['kernel']['path'].read_bytes(), gzip.compress(b'pre-initramfs-kernel', mtime=0))
        self.assertEqual(records['root']['offset'], 12288)

    def test_inline_lzma_kernel_and_dtb(self):
        records = self.inspect(fit_fixture(external=False), external=False)
        self.assertEqual(set(records), {'kernel', 'fdt'})
        self.assertEqual(records['kernel']['compression'], 'lzma')

    def test_generic_offset_mode_is_explicitly_opt_in(self):
        data = fit_fixture(relative=True)
        with self.assertRaisesRegex(ValueError, 'position'):
            self.inspect(data)
        records = self.inspect(data, allow_offset=True)
        self.assertEqual(records['kernel']['path'].read_bytes(), gzip.compress(b'pre-initramfs-kernel', mtime=0))

    def test_sha1_tampering_rejected(self):
        with self.assertRaisesRegex(ValueError, 'hash'):
            self.inspect(fit_fixture(bad_hash=True))

    def test_overlapping_ranges_rejected(self):
        with self.assertRaisesRegex(ValueError, 'overlap'):
            self.inspect(fit_fixture(overlap=True))

    def test_ambiguous_inline_external_rejected(self):
        with self.assertRaisesRegex(ValueError, 'data'):
            self.inspect(fit_fixture(ambiguity=True))

    def test_wide_position_cell_rejected(self):
        with self.assertRaisesRegex(ValueError, 'cell'):
            self.inspect(fit_fixture(wide_cell=True))

    def test_wrong_loadables_reference_rejected(self):
        with self.assertRaisesRegex(ValueError, 'root|references'):
            self.inspect(fit_fixture(root_ref='kernel-1'))

    def test_corrupt_header_and_duplicate_property_rejected(self):
        raw = bytearray(fit_fixture())
        raw[:4] = struct.pack('<I', 0xd00dfeed)
        with self.assertRaisesRegex(ValueError, 'magic'):
            self.inspect(raw)
        raw = fdt(('', [('compatible', string('a')), ('compatible', string('b'))], []))
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            fit.FDT(raw)

    def test_bad_structure_token_and_span_rejected(self):
        raw = bytearray(fdt(('', [], [])))
        raw[56:60] = cell(7)
        with self.assertRaises(ValueError):
            fit.FDT(raw)
        raw[12:16] = cell(57)
        with self.assertRaises(ValueError):
            fit.FDT(raw)


if __name__ == '__main__':
    unittest.main()
