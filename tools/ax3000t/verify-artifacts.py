#!/usr/bin/env python3
"""Offline native AX3000T stock verifier. Never executes target code.

Generic bounded FDT/CPIO/APK/UBI parsers adapted from recipe/scripts/stock_factory.py.
Host tools must be trusted independently of firmware. Successful checks establish
static artifact consistency, not hardware boot or cross-device Mesh operation.
"""
import argparse
import hashlib
import json
import lzma
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import zlib
from pathlib import Path, PurePosixPath
MIB = 1024 ** 2
PEB, PAGE, DATA, LEB = 131072, 2048, 4096, 126976
LIMIT, ROOT_LIMIT = 34 * MIB, 78 * MIB
LAYOUT = 0x7fffefff
DEVICE = 'xiaomi_mi-router-ax3000t'
BOARD = 'xiaomi,mi-router-ax3000t'


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
        capture = (kind == stat.S_IFLNK or name.startswith(('etc/apk/', 'etc/uci-defaults/')) or name in ('usr/lib/opkg/status', 'lib/apk/db/installed', 'etc/wireless/l1profile.dat', 'etc/config/ax6000_mesh', 'etc/openwrt_release', 'etc/os-release', 'etc/banner')
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

def ubi_crc(data):
    return zlib.crc32(data) ^ 0xffffffff

def ubi(data, expected_fit, image_seq=None):
    need(0 < len(data) <= LIMIT and len(data) % PEB == 0, 'UBI stock 34MiB/PEB size bound')
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

REQUIRED = {'apk-mbedtls', 'kmod-mt_wifi', 'wifi-dats', 'kmod-conninfra',
            'kmod-warp', 'mtwifi-cfg-ucode', 'wapp', '1905daemon', 'mapd',
            'libmapd', 'kmod-mapfilter', 'ax6000-mesh', 'luci-app-ax6000-mesh',
            'luci-theme-argon'}
FORBIDDEN = {'tailscale', 'tailscaled', 'luci-app-attendedsysupgrade',
             'auc', 'owut', 'opkg', 'kmod-mt7915e', 'kmod-mt7986-firmware'}


def run(command, cap=8*MIB, *, sidefile_cap=None):
    # Output is spooled to disk, not accumulated without bounds in RAM.
    import resource
    def limits():
        file_limit=max(cap, sidefile_cap or 0)
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        result = subprocess.run([str(x) for x in command], stdout=out, stderr=err,
                                timeout=65, preexec_fn=limits)
        err.seek(0)
        need(result.returncode == 0, 'Host tool failed: '+str(command[0])+': '+err.read(2048).decode(errors='replace'))
        out.seek(0); data=out.read(cap+1)
        need(len(data)<=cap, 'Host tool output cap')
        return data


def metadata_check(data):
    need(data.get('supported_devices') == [BOARD], 'Wrong sysupgrade metadata board')
    version=data.get('version', {})
    need(version.get('target') == 'mediatek/filogic', 'Wrong metadata target')


def dtb_check(data):
    tree=fdt(data, MIB)
    compat=tree['/'].get('compatible', b'').split(b'\0')
    need(BOARD.encode() in compat and b'mediatek,mt7981' in compat,
         'Wrong MT7981 stock DT compatible')
    need(not any(b'ubootmod' in x or b'ax6000' in x for x in compat), 'Foreign DT compatible')
    actual={}
    for node in tree.values():
        if node.get('label') in (b'ubi_kernel\0', b'ubi\0'):
            label=text(node['label'])
            need(label not in actual and len(node.get('reg', b''))==8, 'Invalid partition label/reg')
            actual[label]=struct.unpack('>II', node['reg'])
    need(actual == {'ubi_kernel': (0x600000, LIMIT), 'ubi': (0x2800000, ROOT_LIMIT)}, 'Wrong stock partition geometry')
    nand=[n for n in tree.values() if n.get('compatible') == b'spi-nand\0']
    need(len(nand)==1 and 'mediatek,nmbm' in nand[0] and
         nand[0].get('mediatek,bmt-mtd-overridden-oobsize')==struct.pack('>I',64), 'Missing stock NMBM/OOB geometry')
    return actual


def fit_check(path, work, tools, ramdisk=False):
    data=bounded(path,LIMIT); tree=fdt(data)
    default=text(tree.get('/configurations',{}).get('default',b''))
    conf=tree.get('/configurations/'+default,{})
    needed={'kernel','fdt'} | ({'ramdisk'} if ramdisk else set())
    need(needed <= conf.keys() and ('ramdisk' in conf)==ramdisk and 'loadables' not in conf, 'Wrong FIT boot references')
    images=[x for x in tree if x.startswith('/images/') and x.count('/')==2]
    refs={role:text(conf[role]) for role in needed}
    need(set(images)=={'/images/'+x for x in refs.values()}, 'Unexpected FIT images')
    run([tools['dumpimage'],'-l',path])
    result={}
    for role,name in refs.items():
        nodepath='/images/'+name; node=tree[nodepath]
        need(text(node.get('arch',b''))=='arm64', 'Wrong FIT architecture')
        need(text(node.get('type',b''))=={'fdt':'flat_dt','kernel':'kernel','ramdisk':'ramdisk'}[role], 'Wrong FIT type')
        need('data' in node and not {'data-offset','data-position'} & node.keys(), 'FIT must use inline payload')
        content=node['data']; need(content,'Empty FIT payload')
        algos=set()
        for p,v in tree.items():
            if p.startswith(nodepath+'/'):
                algo=text(v.get('algo',b'')); need(algo in ('crc32','sha1','sha256') and algo not in algos,'Unexpected FIT hash')
                algos.add(algo)
                digest=struct.pack('>I',zlib.crc32(content)) if algo=='crc32' else hashlib.new(algo,content).digest()
                need(v.get('value')==digest,'FIT payload hash mismatch')
        need('crc32' in algos and bool(algos & {'sha1','sha256'}), 'Missing FIT integrity hashes')
        payload=work/(Path(path).name+'.'+role)
        run([tools['dumpimage'],'-T','flat_dt','-p',images.index(nodepath),'-o',payload,path], sidefile_cap=len(content))
        need(bounded(payload,LIMIT)==content,'dumpimage payload mismatch')
        result[role]=content
        if role=='fdt':
            dtb_check(content)
            run([tools['dtc'],'-I','dtb','-O','dts',payload])
            got=run([tools['fdtget'],payload,'/','compatible']).decode().split()
            need(BOARD in got and 'mediatek,mt7981' in got,'fdtget incompatible DT')
        elif role=='kernel':
            need(text(node.get('compression',b''))=='lzma','Wrong kernel compression')
            dec=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE,memlimit=256*MIB)
            raw=dec.decompress(content,max_length=64*MIB+1)
            need(len(raw)<=64*MIB and dec.eof and not dec.unused_data and raw[56:60]==b'ARM\x64','Invalid ARM64 kernel')
        else:
            need(node.get('compression',b'none\0')==b'none\0','Wrong ramdisk compression')
    return result


def tar_check(path, work):
    prefix='sysupgrade-'+DEVICE
    allowed={prefix,prefix+'/CONTROL',prefix+'/kernel',prefix+'/root'}
    seen=set(); result={}
    with tarfile.open(path,'r:') as archive:
        for m in archive:
            name=m.name.rstrip('/')
            need(name in allowed and name not in seen and not m.pax_headers and m.sparse is None,'Unexpected/duplicate TAR entry')
            seen.add(name)
            if name==prefix:
                need(m.isdir() and m.size==0,'Invalid TAR root'); continue
            role=name.split('/')[-1]
            cap={'CONTROL':4096,'kernel':LIMIT,'root':ROOT_LIMIT}[role]
            need(m.isfile() and 0<m.size<cap,'TAR partition size/type bound')
            blob=archive.extractfile(m).read(cap+1)
            need(len(blob)==m.size,'Truncated TAR entry')
            if role=='CONTROL': need(blob==('BOARD='+DEVICE+'\n').encode(),'Wrong TAR board')
            else:
                result[role]=work/role; result[role].write_bytes(blob)
    need(seen==allowed,'Missing TAR members')
    # Include physical eraseblock overhead, two layout PEBs and conservative
    # bad-block reserve. Never treat kernel and root as a combined partition.
    for role,cap in [('kernel',LIMIT),('root',ROOT_LIMIT)]:
        blocks=(result[role].stat().st_size+LEB-1)//LEB
        need(blocks+2+4+20<=cap//PEB, role+' has insufficient UBI overhead/reserve')
    return result


def packages_check(db, paths):
    records=apk_status_packages(db)
    packages={v['Base-Package'] for v in records.values()}
    # apk-openssl is another valid OpenWrt APK provider.
    required=REQUIRED-{'apk-mbedtls'}
    need(required<=packages,'Missing required packages: '+','.join(sorted(required-packages)))
    need(bool({'apk-mbedtls','apk-openssl','apk'}&packages),'APK executable package absent')
    need(not FORBIDDEN&packages,'Forbidden packages: '+','.join(sorted(FORBIDDEN&packages)))
    need(all(v['Architecture'] in ('aarch64_cortex-a53','all','noarch') for v in records.values()),'Wrong APK architecture')
    paths=set(paths)
    for path in paths:
        low=path.lower()
        need(not any(x in low for x in ('tailscale','attendedsysupgrade','ax6000-installer','ax6000-packages','mt7986-ax6000.dbdc')),'Forbidden/inherited image path: '+path)
    need('lib/apk/db/installed' in paths and 'usr/lib/opkg/status' not in paths,'Mixed/missing package database')
    for path in ('etc/wireless/mediatek/mt7981.dbdc.b0.dat','etc/wireless/mediatek/mt7981.dbdc.b1.dat',
                 'etc/wireless/l1profile.dat','etc/init.d/ax6000-mesh'):
        need(path in paths,'Missing native payload: '+path)
    return sorted(packages)


def config_check(config, driver):
    expected=('TARGET_mediatek','TARGET_mediatek_filogic','PACKAGE_kmod-mt_wifi',
              'MTK_CHIP_MT7981','MTK_FIRST_IF_MT7981','MTK_CONNINFRA_APSOC_MT7981',
              'MTK_MAP_SUPPORT','MTK_MAP_R2_VER_SUPPORT','MTK_MAP_R3_VER_SUPPORT',
              'MTK_MAP_R2_6E_SUPPORT','MTK_MAP_R3_6E_SUPPORT','MTK_DFS_SLAVE_SUPPORT')
    for flag in expected:
        need(re.search(r'^CONFIG_'+re.escape(flag)+r'=y$',config,re.M),'Missing expected config '+flag)
    need('CONFIG_first_card_name="MT7981"' in config,'Wrong vendor card')
    need(not re.search(r'^CONFIG_MTK_(CHIP_MT7986|FIRST_IF_MT7986|CONNINFRA_APSOC_MT7986)=y$',config,re.M),'MT7986 native selection retained')
    need(re.search(r'^CONFIG_TARGET_(?:DEVICE_)?mediatek_filogic_DEVICE_'+DEVICE+r'=y$',config,re.M),'Wrong device selection')
    active=re.findall(r'^CONFIG_TARGET_(?:DEVICE_)?mediatek_filogic_DEVICE_(.+)=y$',config,re.M)
    need(set(active)=={DEVICE},'Foreign device profile selected')
    native_chip_check(driver)


def native_chip_check(driver):
    # Kbuild .cmd files preserve genuine compiler arguments. Match whole
    # whitespace-delimited macro tokens, never MT7981-related filenames or
    # feature macros such as -DPRE_CAL_MT7981_SUPPORT.
    config81 = re.search(r'^(?:CONFIG_)?CHIP_MT7981=y$', driver, re.M)
    header81 = re.search(r'^\s*#define\s+(?:CONFIG_)?CHIP_MT7981\s+1\s*$', driver, re.M)
    compiler81 = re.search(r'(?<!\S)-DMT7981(?:=1)?(?!\S)', driver)
    config86 = re.search(r'^(?:CONFIG_)?CHIP_MT7986=y$', driver, re.M)
    header86 = re.search(r'^\s*#define\s+(?:CONFIG_)?CHIP_MT7986(?:\s|$)', driver, re.M)
    # Even =0 defines a macro for #ifdef; mixed-chip evidence must fail.
    compiler86 = re.search(r'(?<!\S)-DMT7986(?:=[^\s]+)?(?!\S)', driver)
    need(not (config86 or header86 or compiler86), 'Native driver compiled for MT7986')
    need(config81 or header81 or compiler81, 'No independent native MT7981 compile evidence')



def identity_check(path, data):
    need(not re.search(rb'(?:ax6000-packages|redmi-ax6000-612|ax6000-installer|ax6000-activation)',data,re.I), 'Inherited AX6000 feed/installer identity: '+path)


def clean_mesh_check(config, paths):
    import shlex
    section=None; enabled=[]
    for line in config.decode().splitlines():
        tokens=shlex.split(line,comments=True)
        if not tokens: continue
        if tokens[0]=='config':
            section=tokens[2] if len(tokens)>2 else None
        elif tokens[0]=='option':
            need(len(tokens)==3,'Malformed Mesh UCI option')
            if section=='main' and tokens[1]=='enabled': enabled.append(tokens[2])
            need(not re.search(r'(?:key|password|secret|session)',tokens[1],re.I) or not tokens[2],
                 'Embedded Mesh credential in initial config')
    need(enabled==['0'],'Initial Mesh must explicitly be disabled exactly once')
    for path in paths:
        need(not (path=='etc/ax6000-mesh' or path.startswith(('etc/ax6000-mesh/','etc/ax6000-mesh.',
                    'var/run/ax6000-mesh','tmp/ax6000-mesh'))), 'Pre-enrollment Mesh state: '+path)
        leaf=PurePosixPath(path).name.lower()
        need(leaf not in ('authorized_keys','authorized_keys2','id_rsa','id_ed25519','id_ecdsa','id_dsa')
             and not re.search(r'(?:session[-_]?key|private[-_]?key)',leaf), 'Embedded credential path: '+path)


def mesh_assets_check(assets, root_hashes, initramfs_entries):
    need(assets.is_dir() and not assets.is_symlink(),'Reviewed Mesh assets directory missing')
    expected={}
    for path in sorted(assets.rglob('*')):
        need(not path.is_symlink(),'Reviewed Mesh asset cannot be symlink: '+str(path))
        if path.is_file(): expected[path.relative_to(assets).as_posix()]=sha(bounded(path,4*MIB))
    need({'usr/libexec/ax6000-mesh-control','usr/libexec/ax6000-mesh-hardware','usr/bin/wifi_config_save',
          'etc/config/ax6000_mesh'}<=expected.keys(),'Incomplete reviewed Mesh assets')
    for path,digest in expected.items():
        need(root_hashes.get(path)==digest,'Squashfs Mesh payload differs from reviewed asset: '+path)
        entry=initramfs_entries.get(path,{})
        need(entry.get('kind')==stat.S_IFREG and entry.get('data_sha256')==digest,
             'Initramfs Mesh payload differs from reviewed asset: '+path)
    return expected


def main(args):
    tools={}
    for name,alternatives in {'fwtool':['fwtool'],'dumpimage':['dumpimage'],
                             'dtc':['dtc'],'fdtget':['fdtget'],'unsquashfs':['unsquashfs4','unsquashfs']}.items():
        candidates=[args.tools/n for n in alternatives]+[Path(x) for n in alternatives if (x:=shutil.which(n))]
        tools[name]=next((p.resolve() for p in candidates if p.is_file()),None)
        need(tools[name] is not None,'Missing trusted host tool '+name)
    config_check(bounded(args.config,4*MIB).decode(),bounded(args.driver_config,4*MIB).decode())
    original={str(p):sha(bounded(p,128*MIB)) for p in (args.sysupgrade,args.factory,args.initramfs)}
    with tempfile.TemporaryDirectory(prefix='ax3000t-verify-') as tmp:
        work=Path(tmp); metadata=work/'metadata.json'
        stripped=work/'stripped.tar'
        stripped.write_bytes(run([tools['fwtool'],'-i',metadata,'-T',args.sysupgrade],128*MIB))
        metadata_check(json.loads(bounded(metadata,32768)))
        payloads=tar_check(stripped,work)
        boot=fit_check(payloads['kernel'],work,tools)
        ram=fit_check(args.initramfs,work,tools,True)
        need(boot['fdt']==ram['fdt'],'Sysupgrade/initramfs DTB mismatch')
        geometry=ubi(bounded(args.factory,LIMIT),bounded(args.initramfs,LIMIT))
        entries=cpio(ram['ramdisk'])
        need('lib/apk/db/installed' in entries,'Initramfs APK DB missing')
        ram_packages=packages_check(entries['lib/apk/db/installed']['data'],entries)
        for name,entry in entries.items():
            if entry['kind']==stat.S_IFREG and (name.startswith(('etc/apk/','etc/uci-defaults/')) or name in ('etc/openwrt_release','etc/os-release','etc/banner')):
                identity_check(name,entry['data'])
        need(b'INDEX0=MT7981\n' in entries['etc/wireless/l1profile.dat']['data'],'Wrong initramfs l1profile')
        root=payloads['root']
        listing=run([tools['unsquashfs'],'-ls',root],16*MIB).decode()
        paths=[line[len('squashfs-root/'):] for line in listing.splitlines() if line.startswith('squashfs-root/')]
        def read(path,cap=4*MIB): return run([tools['unsquashfs'],'-cat',root,path],cap)
        root_packages=packages_check(read('lib/apk/db/installed'),paths)
        clean_mesh_check(read('etc/config/ax6000_mesh'),paths)
        clean_mesh_check(entries['etc/config/ax6000_mesh']['data'],entries)
        asset_paths=[p.relative_to(args.mesh_assets).as_posix() for p in args.mesh_assets.rglob('*') if p.is_file()]
        root_hashes={p:sha(read(p)) for p in asset_paths if p in paths}
        mesh_hashes=mesh_assets_check(args.mesh_assets,root_hashes,entries)
        need(root_packages==ram_packages,'Initramfs/root package inventories differ')
        l1=read('etc/wireless/l1profile.dat')
        need(b'INDEX0=MT7981\n' in l1 and b'mt7981.dbdc.b0.dat' in l1 and b'mt7981.dbdc.b1.dat' in l1,'Wrong image l1profile')
        modules=[p for p in paths if re.fullmatch(r'lib/modules/[^/]+/mt_wifi\.ko',p)]
        need(len(modules)==1,'Native driver module missing/ambiguous')
        need(modules[0] in entries and entries[modules[0]]['data_sha256']==sha(bounded(args.driver_module,32*MIB)), 'Initramfs native module differs from independent input')
        need(sha(read(modules[0],32*MIB))==sha(bounded(args.driver_module,32*MIB)),'Installed driver differs from independent native module input')
        # Inspect identity-bearing files only, not generic board support scripts
        # which legitimately contain other supported router names.
        identity_paths=[p for p in paths if p.startswith(('etc/apk/','etc/opkg/','etc/uci-defaults/')) or p in ('etc/openwrt_release','etc/os-release','etc/banner')]
        for p in identity_paths:
            # -ll inventory identifies regular files; skip directory paths.
            info=run([tools['unsquashfs'],'-ll',root,p],MIB).decode()
            if any(line.startswith('-') and line.endswith('squashfs-root/'+p) for line in info.splitlines()): identity_check(p,read(p))
        report={'device':DEVICE,'partitions':{'kernel':LIMIT,'root':ROOT_LIMIT},'ubi':geometry,
                'reviewed_mesh_assets':{'path':str(args.mesh_assets),'sha256':mesh_hashes},
                'artifacts':original,'package_count':len(root_packages),
                'inputs':{str(p):sha(bounded(p,32*MIB)) for p in (args.config,args.driver_config,args.driver_module)},
                'tools':{k:{'path':str(v),'sha256':sha(v.read_bytes())} for k,v in tools.items()},
                'scope':'Static verification only; no hardware boot or Mesh interoperability claim'}
    need(original=={str(p):sha(bounded(p,128*MIB)) for p in (args.sysupgrade,args.factory,args.initramfs)},'Input artifact modified')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('sysupgrade','factory','initramfs','config','driver-config','driver-module','tools','mesh-assets'):
        parser.add_argument('--'+name,type=Path,required=True)
    try: main(parser.parse_args())
    except (ValueError,OSError,subprocess.SubprocessError,tarfile.TarError,lzma.LZMAError) as error:
        parser.exit(1,'FAIL: '+str(error)+'\n')
