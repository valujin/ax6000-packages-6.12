"""Independent native stock factory on-flash fixtures; no target execution."""
import copy, hashlib, lzma, os, stat, struct, subprocess, sys, tempfile, unittest, zlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import stock_factory as v

def native_kernel():
    data=bytearray(128);data[56:60]=b'ARM\x64';return bytes(data)

def status(names):
    return b'\n'.join(('Package: '+n+'\nVersion: 1\nArchitecture: all\nStatus: install ok installed\n').encode() for n in names)

def align(data, size=4):
    return data + b'\0' * (-len(data) % size)


def fdt(nodes):
    names = sorted({key for _, props in nodes for key in props})
    strings = b''; offsets = {}
    for name in names:
        offsets[name] = len(strings); strings += name.encode() + b'\0'
    body = b''; stack = []
    for path, props in nodes:
        parts = [] if path == '/' else path.strip('/').split('/')
        while stack and (len(stack) > len(parts) or stack != parts[:len(stack)]):
            body += struct.pack('>I', 2); stack.pop()
        if path == '/':
            body += struct.pack('>I', 1) + b'\0\0\0\0'
        else:
            assert len(parts) == len(stack) + 1
            body += struct.pack('>I', 1) + align(parts[-1].encode() + b'\0'); stack.append(parts[-1])
        for name, value in props.items():
            body += struct.pack('>III', 3, len(value), offsets[name]) + align(value)
    body += struct.pack('>I', 2) * (len(stack) + 1) + struct.pack('>I', 9)
    header = struct.pack('>10I', 0xd00dfeed, 56 + len(body) + len(strings), 56, 56 + len(body), 40, 17, 16, 0, len(strings), len(body))
    return header + bytes(16) + body + strings


def board_dtb(wrong=False):
    return fdt([('/', {'compatible': b'xiaomi,redmi-router-ax6000-stock\0mediatek,mt7986a\0'}),
                ('/partitions', {}),
                ('/partitions/kernel', {'label': b'ubi_kernel\0', 'reg': struct.pack('>II', 0x600000, 0x1e00000 if not wrong else 0x2000000)}),
                ('/partitions/root', {'label': b'ubi\0', 'reg': struct.pack('>II', 0x2400000, 0x5000000)})])


def fit(ramdisk, *, kernel=None, dtb=None, bad_hash=False):
    kernel = kernel if kernel is not None else lzma.compress(native_kernel(), format=lzma.FORMAT_ALONE)
    nodes = [('/', {'description': b'Independent fixture\0', 'timestamp': struct.pack('>I', 1234)}), ('/images', {})]
    for name, kind, content in [('kernel-1', 'kernel', kernel), ('initrd-1', 'ramdisk', ramdisk), ('fdt-1', 'flat_dt', dtb or board_dtb())]:
        props = {'data': content, 'type': kind.encode() + b'\0', 'arch': b'arm64\0'}
        if kind == 'kernel':
            props.update({'os': b'linux\0', 'compression': b'lzma\0', 'load': struct.pack('>I', 0x48000000), 'entry': struct.pack('>I', 0x48000000)})
        elif kind == 'flat_dt':
            props['compression'] = b'none\0'
        else:
            props['os'] = b'linux\0'
        nodes += [('/images/' + name, props),
                  ('/images/' + name + '/hash-1', {'algo': b'crc32\0', 'value': struct.pack('>I', zlib.crc32(content))}),
                  ('/images/' + name + '/hash-2', {'algo': b'sha1\0', 'value': hashlib.sha1(content).digest() if not bad_hash else bytes(20)})]
    nodes += [('/configurations', {'default': b'config-1\0'}), ('/configurations/config-1', {'kernel': b'kernel-1\0', 'fdt': b'fdt-1\0', 'ramdisk': b'initrd-1\0'})]
    return fdt(nodes)


def entry(name, data=b'payload', mode=stat.S_IFREG | 0o755, ino=1, nlink=1):
    return {'name': name, 'data': data, 'mode': mode, 'ino': ino, 'nlink': nlink}


def newc(entries):
    out = b''
    for item in list(entries) + [entry('TRAILER!!!', b'', mode=0)]:
        name = item['name'].encode() + b'\0'; data = item['data']
        fields = [item['ino'], item['mode'], 0, 0, item['nlink'], 1234, len(data), 0, 0, 0, 0, len(name), 0]
        out += align(b'070701' + b''.join(f'{x:08x}'.encode() for x in fields) + name) + align(data)
    return align(out, 512)


def compressed(entries):
    return lzma.compress(newc(entries), format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32)


def roots():
    before = [entry(name) for name in v.ESSENTIAL]
    before += [entry('lib/ld-musl-aarch64.so.1'), entry('lib/shared-hardlink', b'', ino=400, nlink=2),
               entry('lib/shared-hardlink-data', b'library', ino=400, nlink=2)]
    tail = ['usr/sbin/tailscale', 'usr/sbin/tailscaled', 'etc/config/tailscale', 'etc/init.d/tailscale']
    before += [entry(name, b'Tailscale only') for name in tail]
    before += [entry('usr/lib/opkg/info/tailscale.list', ''.join('/' + n + '\n' for n in tail).encode()),
               entry('usr/lib/opkg/info/tailscale.control', b'Package: tailscale\n'),
               entry('usr/lib/opkg/info/dropbear.list', b'/usr/sbin/dropbear\n'),
               entry('etc/rc.d/S90tailscale', b'../init.d/tailscale', stat.S_IFLNK | 0o777),
               entry('usr/lib/opkg/status', status(['base-files', 'tailscale', 'dropbear']))]
    remove = set(tail + ['usr/lib/opkg/info/tailscale.list', 'usr/lib/opkg/info/tailscale.control', 'etc/rc.d/S90tailscale'])
    after = [copy.deepcopy(item) for item in before if item['name'] not in remove]
    next(item for item in after if item['name'] == 'usr/lib/opkg/status')['data'] = status(['base-files', 'dropbear'])
    return before, after


def raw_ubi(fit_bytes):
    n = (len(fit_bytes) + v.LEB - 1) // v.LEB
    # UBI's CRC has no final inversion; intentionally independent of verifier helper.
    def crc(data): return struct.pack('>I', zlib.crc32(data) ^ 0xffffffff)
    table = b''
    for i in range(128):
        row = bytearray(168)
        if i == 0:
            struct.pack_into('>IIIBBH', row, 0, n, 1, 0, 1, 0, 6); row[16:22] = b'kernel'
        table += row + crc(row)
    blocks = []
    for volid, lnum, payload in [(0x7fffefff, 0, table), (0x7fffefff, 1, table)] + [(0, i, fit_bytes[i * v.LEB:(i + 1) * v.LEB]) for i in range(n)]:
        ec = bytearray(60); struct.pack_into('>IB', ec, 0, 0x55424923, 1); struct.pack_into('>QIII', ec, 8, 0, 2048, 4096, 1234)
        vid = bytearray(60); struct.pack_into('>IBBBBII', vid, 0, 0x55424921, 1, 1, 0, 5 if volid else 0, volid, lnum)
        blocks.append(bytes(ec) + crc(ec) + bytes([255]) * (2048 - 64) + bytes(vid) + crc(vid) + bytes([255]) * (2048 - 64) + payload + bytes([255]) * (v.LEB - len(payload)))
    ec = bytearray(60); struct.pack_into('>IB', ec, 0, 0x55424923, 1); struct.pack_into('>QIII', ec, 8, 0, 2048, 4096, 1234); ec[5:8] = b'EOF'
    return b''.join(blocks) + (bytes(ec) + crc(ec) + bytes([255]) * (v.PEB - 64)) * 5


class NativeFactoryTests(unittest.TestCase):
    def setUp(self):
        self.before, self.entries = roots()
        self.fit = fit(compressed(self.entries)); self.ubi = raw_ubi(self.fit)

    def verify(self, ram=None, ubi=None, expected=None, kernel=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'ram.bin').write_bytes(ram or self.fit); (root / 'factory.ubi').write_bytes(ubi or self.ubi)
            args = {'package_only': ['tailscale'], 'expected_dtb_sha256': hashlib.sha256(board_dtb()).hexdigest()}
            if expected is not None: args['expected_packages'] = expected
            if kernel is not None:
                (root / 'Image-initramfs.fixture').write_bytes(kernel); args['kernel_inputs'] = [root / 'Image-initramfs.fixture']
            return v.verify_native_factory(root / 'ram.bin', root / 'factory.ubi', **args)

    def test_independent_complete_positive(self):
        proof = self.verify(kernel=native_kernel())
        self.assertTrue(proof['ok']); self.assertEqual(proof['ubi_geometry']['eof_markers'], 5)
        self.assertEqual(proof['ubi_geometry']['erase_counter'], 0); self.assertFalse(proof['hardware_boot_verified'])
        self.assertTrue(proof['kernel_inputs_matched']); self.assertEqual(proof['package_only_absent'], ['tailscale'])

    def test_ec_crc_corruption(self):
        data = bytearray(self.ubi); data[10] ^= 1; self.assertRaises(ValueError, self.verify, ubi=bytes(data))

    def test_vid_crc_corruption(self):
        data = bytearray(self.ubi); data[2048 + 44] ^= 1; self.assertRaises(ValueError, self.verify, ubi=bytes(data))

    def test_wrong_volume_id_even_with_valid_crc(self):
        data = bytearray(self.ubi); pos = 2 * v.PEB + 2048; struct.pack_into('>I', data, pos + 8, 1); struct.pack_into('>I', data, pos + 60, zlib.crc32(data[pos:pos + 60]) ^ 0xffffffff)
        self.assertRaises(ValueError, self.verify, ubi=bytes(data))

    def test_redundant_table_corruption(self):
        data = bytearray(self.ubi); data[v.PEB + v.DATA + 16] ^= 1; self.assertRaises(ValueError, self.verify, ubi=bytes(data))

    def test_table_crc_corruption_both_copies(self):
        data = bytearray(self.ubi)
        for i in (0, 1): data[i * v.PEB + v.DATA + 168] ^= 1
        self.assertRaises(ValueError, self.verify, ubi=bytes(data))

    def test_autoresize_rejected_with_recomputed_crc(self):
        data = bytearray(self.ubi)
        for i in (0, 1):
            pos=i*v.PEB+v.DATA; data[pos+144]=1; struct.pack_into('>I',data,pos+168,zlib.crc32(data[pos:pos+168])^0xffffffff)
        self.assertRaises(ValueError,self.verify,ubi=bytes(data))

    def test_missing_layout_copy(self): self.assertRaises(ValueError,self.verify,ubi=self.ubi[v.PEB:])
    def test_missing_eof_marker(self): self.assertRaises(ValueError,self.verify,ubi=self.ubi[:-v.PEB])
    def test_extra_eof_marker(self): self.assertRaises(ValueError,self.verify,ubi=self.ubi+self.ubi[-v.PEB:])
    def test_oversized_ubi(self): self.assertRaises(ValueError,v.ubi,bytes(v.LIMIT+1),self.fit)

    def test_wrong_geometry_with_recomputed_crc(self):
        data=bytearray(self.ubi);struct.pack_into('>I',data,16,512);struct.pack_into('>I',data,60,zlib.crc32(data[:60])^0xffffffff)
        self.assertRaises(ValueError,self.verify,ubi=bytes(data))

    def test_ubi_payload_differs(self):
        data=bytearray(self.ubi);data[2*v.PEB+v.DATA+100]^=1;self.assertRaises(ValueError,self.verify,ubi=bytes(data))

    def test_foreign_dtb(self):
        other=fit(compressed(self.entries),dtb=board_dtb(wrong=True));self.assertRaises(ValueError,self.verify,ram=other,ubi=raw_ubi(other))

    def test_foreign_kernel_input(self): self.assertRaises(ValueError,self.verify,kernel=b'wrong pre-initramfs Image')
    def test_bad_fit_hash(self): self.assertRaises(ValueError,self.verify,ram=fit(compressed(self.entries),bad_hash=True))
    def test_concatenated_xz(self): self.assertRaises(ValueError,v.cpio,compressed(self.entries)+compressed(self.entries))
    def test_truncated_xz(self): self.assertRaises(ValueError,v.cpio,compressed(self.entries)[:-10])
    def test_duplicate_cpio_path(self): self.assertRaises(ValueError,v.cpio,compressed(self.entries+[self.entries[0]]))
    def test_traversal_cpio_path(self): self.assertRaises(ValueError,v.cpio,compressed(self.entries+[entry('../escape')]))

    def test_essential_removed(self):
        changed=fit(compressed([i for i in self.entries if i['name']!='sbin/sysupgrade']));self.assertRaises(ValueError,self.verify,ram=changed,ubi=raw_ubi(changed))

    def test_nonexecutable_busybox(self):
        next(i for i in self.entries if i['name']=='bin/busybox')['mode']=stat.S_IFREG|0o644
        changed=fit(compressed(self.entries));self.assertRaises(ValueError,self.verify,ram=changed,ubi=raw_ubi(changed))

    def test_native_status_package_inventory_mismatch(self):
        self.assertRaises(ValueError,self.verify,expected={})
        expected={n:{'Version':'1','Architecture':'all'} for n in ('base-files','dropbear')}
        self.assertTrue(self.verify(expected=expected)['ok']);expected['dropbear']['Version']='wrong'
        self.assertRaises(ValueError,self.verify,expected=expected)

    def test_package_only_in_status_rejected(self):
        changed=fit(compressed(self.before));self.assertRaises(ValueError,self.verify,ram=changed,ubi=raw_ubi(changed))

    def test_package_payload_without_status_rejected(self):
        changed=fit(compressed(self.entries+[entry('usr/sbin/tailscale')]));self.assertRaises(ValueError,self.verify,ram=changed,ubi=raw_ubi(changed))

    def test_package_metadata_without_status_rejected(self):
        changed=fit(compressed(self.entries+[entry('usr/lib/opkg/info/tailscale.list',b'')]));self.assertRaises(ValueError,self.verify,ram=changed,ubi=raw_ubi(changed))

    def test_package_service_alias_rejected(self):
        v.assert_absent(['tailscale'],{}, {'etc/rc.d/S90alias'}, {})
        self.assertRaises(ValueError,v.assert_absent,['tailscale'],{}, {'etc/rc.d/S90alias'}, {'etc/rc.d/S90alias':b'../init.d/tailscale'})

    def test_package_policy(self):
        self.assertEqual(v.package_policy({'packages':['tailscale'],'image_packages':[],'package_only':['tailscale']}),['tailscale'])
        for profile in ({'packages':[],'package_only':['tailscale']},{'packages':['tailscale'],'image_packages':['tailscale'],'package_only':['tailscale']},{'packages':['tailscale'],'package_only':['tailscale','tailscale']},{'packages':['other'],'package_only':['other']}):
            self.assertRaises(ValueError,v.package_policy,profile)

    @unittest.skipUnless(os.environ.get('AX6000_NATIVE_UBINIZE'),'Explicit trusted native ubinize not supplied')
    def test_actual_native_ubinize_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'kernel.itb').write_bytes(self.fit)
            (root/'volume.ini').write_text('[kernel]\nmode=ubi\nvol_id=0\nvol_type=dynamic\nvol_name=kernel\nimage='+str(root/'kernel.itb')+'\n')
            subprocess.run([os.environ['AX6000_NATIVE_UBINIZE'],'-p','128KiB','-m','2048','-O','2048','-E','5','-Q','1234','-o',str(root/'factory.ubi'),str(root/'volume.ini')],check=True,capture_output=True)
            self.assertTrue(self.verify(ubi=(root/'factory.ubi').read_bytes())['ok'])


if __name__=='__main__':unittest.main()

