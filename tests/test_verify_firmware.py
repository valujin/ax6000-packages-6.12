"""Payload verification fixtures constructed independently from production code."""
import gzip
import hashlib
import importlib.util
import io
import lzma
from pathlib import Path
import struct
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from test_fit_payload import cell, fdt, string, fit_fixture
try:
    spec = importlib.util.spec_from_file_location('verify_firmware', ROOT / 'scripts/verify-firmware.py')
    verify = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verify)
except FileNotFoundError:
    verify = None


def image_kernel(marker):
    data = bytearray(128)
    data[56:60] = b'ARM\x64'
    data[64:64 + len(marker)] = marker
    return bytes(data)


def dtb_fixture(layout, geometry=None, wrong_rootdisk=False):
    specs = {'stock': [('ubi_kernel', 0x600000, 0x1e00000), ('ubi', 0x2400000, 0x5000000)],
             'mtkuboot': [('ubi', 0x600000, 0x6e00000)],
             'ubootmod': [('ubi', 0x580000, 0x7a80000)]}
    children = []
    for label, offset, size in geometry or specs[layout]:
        sub = []
        if layout == 'ubootmod':
            sub = [('volumes', [], [('ubi-volume-fit', [('volname', string('fit')), ('phandle', cell(73))], [])])]
        children.append(('partition@' + format(offset, 'x'), [('label', string(label)),
                         ('reg', cell(offset) + cell(size))], sub))
    chosen = [('rootdisk', cell(99 if wrong_rootdisk else 73)),
              ('bootargs-append', string(' root=/dev/fit0 rootwait'))] if layout == 'ubootmod' else []
    return fdt(('', [('compatible', string('xiaomi,redmi-router-ax6000-' + layout) + string('mediatek,mt7986a'))],
                [('chosen', chosen, []), ('partitions', [], children)]))


def elf_fixture(version='6.12.108'):
    names = b'\0.shstrtab\0.modinfo\0'
    info = ('vermagic=' + version + ' SMP mod_unload aarch64\0').encode()
    data = bytearray(448)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, 1, 183)
    struct.pack_into('<Q', data, 40, 256)
    struct.pack_into('<HHH', data, 58, 64, 3, 1)
    data[64:64 + len(names)] = names
    data[128:128 + len(info)] = info
    struct.pack_into('<IIQQQQIIQQ', data, 320, 1, 3, 0, 0, 64, len(names), 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 384, 11, 1, 0, 0, 128, len(info), 0, 0, 1, 0)
    return bytes(data)


def make_ipk(path, control, files):
    def tar_content(values):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w', format=tarfile.GNU_FORMAT) as tar:
            for name, data in values.items():
                member = tarfile.TarInfo('./' + name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
        return gzip.compress(buf.getvalue())
    control_data = ''.join(k + ': ' + v + '\n' for k, v in control.items()).encode()
    path.write_bytes(tar_content({'debian-binary': b'2.0\n',
                                 'control.tar.gz': tar_content({'control': control_data}),
                                 'data.tar.gz': tar_content(files)}))


class FirmwareVerificationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(verify, 'verify-firmware implementation is missing')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def tar(self, extra=None, control=None):
        p = self.root / 'image.tar'
        prefix = 'sysupgrade-xiaomi_redmi-router-ax6000-stock'
        with tarfile.open(p, 'w', format=tarfile.GNU_FORMAT) as out:
            d = tarfile.TarInfo(prefix)
            d.type = tarfile.DIRTYPE
            out.addfile(d)
            for name, content in [('CONTROL', control or b'BOARD=xiaomi_redmi-router-ax6000-stock\n'),
                                  ('kernel', b'kernel'), ('root', b'hsqs' + b'\0' * 1020)] + (extra or []):
                member = tarfile.TarInfo(prefix + '/' + name)
                member.size = len(content)
                out.addfile(member, io.BytesIO(content))
        return p

    def test_strict_tar_valid_and_duplicate_root_rejected(self):
        out = self.root / 'out'
        out.mkdir()
        data = verify.extract_tar(self.tar(), 'stock', out)
        self.assertEqual(data['root'].read_bytes()[:4], b'hsqs')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            verify.extract_tar(self.tar(extra=[('root', b'fake')]), 'stock', out)

    def test_wrong_board_traversal_and_nonzero_tar_tail_rejected(self):
        for extra, control in [([('../root', b'bad')], None), ([], b'BOARD=another-layout\n')]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                verify.extract_tar(self.tar(extra, control), 'stock', self.root)
        p = self.tar()
        with p.open('ab') as out:
            out.write(b'evil')
        with self.assertRaisesRegex(ValueError, 'trailing'):
            verify.extract_tar(p, 'stock', self.root)

    def test_kernel_compared_to_kdir_snapshot_not_post_initramfs_arch_image(self):
        original = image_kernel(b'original')
        post = image_kernel(b'initramfs')
        expected = self.root / 'Image'
        expected.write_bytes(original)
        arch = self.root / 'arch-Image'
        arch.write_bytes(post)
        compressed = self.root / 'kernel.gz'
        compressed.write_bytes(gzip.compress(original))
        record = verify.verify_kernel(compressed, 'gzip', expected, self.root / 'decoded')
        self.assertEqual(record['expected_input'], str(expected))
        compressed.write_bytes(gzip.compress(post))
        with self.assertRaisesRegex(ValueError, 'KDIR'):
            verify.verify_kernel(compressed, 'gzip', expected, self.root / 'decoded')

    def test_all_three_actual_fit_formats_share_pre_initramfs_kernel(self):
        original = image_kernel(b'common-sysupgrade')
        expected = self.root / 'Image'
        expected.write_bytes(original)
        records = []
        for layout in ('stock', 'mtkuboot', 'ubootmod'):
            work = self.root / layout
            work.mkdir()
            external = layout == 'ubootmod'
            path = work / 'kernel.fit'
            path.write_bytes(fit_fixture(external=external, kernel_data=original, dtb_data=dtb_fixture(layout)))
            actual = verify.extract_fit(path, work, external=external)
            verify.verify_dtb(actual['fdt']['path'], layout)
            record = verify.verify_kernel(actual['kernel']['path'], actual['kernel']['compression'],
                                           expected, work / 'decoded')
            records.append(record['sha256'])
        self.assertEqual(len(set(records)), 1)

    def test_lzma_trailing_stream_and_expansion_cap_rejected(self):
        original = image_kernel(b'ok')
        expected = self.root / 'Image'
        expected.write_bytes(original)
        p = self.root / 'kernel.lzma'
        p.write_bytes(lzma.compress(original, format=lzma.FORMAT_ALONE))
        verify.verify_kernel(p, 'lzma', expected, self.root / 'decoded')
        p.write_bytes(p.read_bytes() + b'extra')
        with self.assertRaisesRegex(ValueError, 'trailing'):
            verify.verify_kernel(p, 'lzma', expected, self.root / 'decoded')
        p.write_bytes(lzma.compress(original * 100, format=lzma.FORMAT_ALONE))
        with self.assertRaisesRegex(ValueError, 'cap'):
            verify.verify_kernel(p, 'lzma', expected, self.root / 'decoded', cap=1024)

    def test_all_layouts_nested_partition_geometry(self):
        p = self.root / 'device.dtb'
        for layout in ('stock', 'mtkuboot', 'ubootmod'):
            p.write_bytes(dtb_fixture(layout))
            result = verify.verify_dtb(p, layout)
            self.assertEqual(result['layout'], layout)
        p.write_bytes(dtb_fixture('stock'))
        with self.assertRaisesRegex(ValueError, 'compatible'):
            verify.verify_dtb(p, 'mtkuboot')
        p.write_bytes(dtb_fixture('stock', [('ubi_kernel', 0x600000, 0x1e00001), ('ubi', 0x2400000, 0x5000000)]))
        with self.assertRaisesRegex(ValueError, 'geometry'):
            verify.verify_dtb(p, 'stock')
        p.write_bytes(dtb_fixture('ubootmod', wrong_rootdisk=True))
        with self.assertRaisesRegex(ValueError, 'rootdisk'):
            verify.verify_dtb(p, 'ubootmod')

    def test_status_duplicate_missing_and_arch_rejected(self):
        control = b'Package: kernel\nVersion: 6.12.112~' + b'a' * 32 + b'-r1\nArchitecture: aarch64_cortex-a53\nStatus: install ok installed\n'
        parsed = verify.parse_status(control)
        self.assertEqual(parsed['kernel']['Architecture'], 'aarch64_cortex-a53')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            verify.parse_status(control + b'\n' + control)
        with self.assertRaisesRegex(ValueError, 'Status'):
            verify.parse_status(control.replace(b'Status: install ok installed\n', b''))

    def test_installer_mode_is_regular_0755(self):
        path = 'usr/sbin/ax6000-install-feed'
        valid = b'-rwxr-xr-x 0/0 123 2026-01-01 00:00 squashfs-root/' + path.encode() + b'\n'
        self.assertEqual(verify.file_mode(valid, path), '-rwxr-xr-x')
        for mode in (b'-rw-r--r--', b'lrwxrwxrwx'):
            listing = valid.replace(b'-rwxr-xr-x', mode)
            with self.assertRaisesRegex(ValueError, '0755'):
                verify.require_mode(listing, path, 0o755)

    def test_duplicate_json_keys_and_manifest_traversal_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            verify.json_bytes(b'{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            verify.safe_path(self.root, '../elsewhere')

    def test_bounded_process_and_deadline(self):
        with self.assertRaisesRegex(ValueError, 'cap'):
            verify.run_bounded([sys.executable, '-c', 'print("x"*2000)'], 10)
        with self.assertRaisesRegex(ValueError, 'timeout'):
            verify.run_bounded([sys.executable, '-c', 'import time;time.sleep(2)'], 10, timeout=0.1)

    def test_elf_actual_version_arch_and_flags(self):
        config = b'CONFIG_SMP=y\nCONFIG_MODULE_UNLOAD=y\n# CONFIG_MODVERSIONS is not set\n'
        info = verify.module_info(elf_fixture(), '6.12.108', config)
        self.assertTrue(info['vermagic'].startswith('6.12.108 '))
        with self.assertRaisesRegex(ValueError, 'release'):
            verify.module_info(elf_fixture('6.6.133'), '6.12.108', config)
        with self.assertRaisesRegex(ValueError, 'flags'):
            verify.module_info(elf_fixture(), '6.12.108', config + b'CONFIG_MODVERSIONS=y\n')
        bad = bytearray(elf_fixture())
        struct.pack_into('<H', bad, 18, 62)
        with self.assertRaisesRegex(ValueError, 'AArch64'):
            verify.module_info(bad, '6.12.108', config)

    def test_native_ipk_layers_and_payload_bytes(self):
        ipk = self.root / 'module.ipk'
        controls = {'Package': 'kmod-example', 'Version': '1-r1', 'Architecture': 'aarch64_cortex-a53'}
        files = {'lib/modules/6.12.108/example.ko': elf_fixture()}
        make_ipk(ipk, controls, files)
        actual, payload = verify.ipk_contents(ipk, payload=True)
        self.assertEqual(actual, controls)
        self.assertEqual(payload, files)

    def test_sdk_all_seven_contexts_and_recomputed_abi(self):
        source = self.root / 'source'
        relative = Path('build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/linux-6.12.108')
        kernel = source / relative
        config_set = b'CONFIG_MODULE_UNLOAD=y\nCONFIG_SMP=y\n'
        magic = hashlib.md5(config_set).hexdigest()
        values = {'.config': config_set + b'# CONFIG_MODVERSIONS is not set\n',
                  '.config.set': config_set, '.vermagic': (magic + '\n').encode(),
                  'Module.symvers': b'0x00000000\tfixture_symbol\tvmlinux\tEXPORT_SYMBOL\n',
                  'modules.builtin.modinfo': b'fixture.license=GPL\0',
                  'include/config/kernel.release': b'6.12.108\n',
                  'include/generated/autoconf.h': b'#define CONFIG_SMP 1\n'}
        for name, data in values.items():
            path = kernel / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        extra = {'Config-build.in': b'config TARGET_BOARD\n\tstring\n\tdefault "mediatek"\n'
                 b'config TARGET_SUBTARGET\n\tstring\n\tdefault "filogic"\n'
                 b'config TARGET_ARCH_PACKAGES\n\tstring\n\tdefault "aarch64_cortex-a53"\n',
                 'include/version.mk': b'REVISION:=r1-ae65e1de6997\n'}
        archive = self.root / 'sdk.tar'
        with tarfile.open(archive, 'w') as out:
            for name, data in {**{str(relative / k): v for k, v in values.items()}, **extra}.items():
                member = tarfile.TarInfo('sdk/' + name)
                member.size = len(data)
                out.addfile(member, io.BytesIO(data))
        profile = {'firmware': {'commit': 'ae65e1de69971b5a2e3cf7e39390ee93f274d488',
                               'kernel_version': '6.12.108~' + magic + '-r1'}}
        record, _ = verify.inspect_sdk(archive, kernel, source, self.root, profile)
        self.assertEqual(len(record['matching_contexts']), 7)
        self.assertTrue(record['export_crc_all_zero'])
        self.assertFalse(record['modversions'])
        (kernel / 'include/generated/autoconf.h').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'autoconf'):
            verify.inspect_sdk(archive, kernel, source, self.root, profile)

    def test_repo_renderer_matches_channel_but_rejects_foreign_url(self):
        profile = {'channel': 'recommended',
                   'publication': {'site_url': 'https://valujin.github.io/ax6000-packages-6.12'},
                   'build_source': {'publication_url': 'https://valujin.github.io/ax6000-packages-6.12/channels/recommended'}}
        values, fingerprint = verify.repository_expected(ROOT, profile)
        self.assertIn(b'/channels/recommended}', values['usr/sbin/ax6000-install-feed'][0])
        self.assertEqual(len(fingerprint), 16)
        profile['build_source']['publication_url'] += '-wrong'
        with self.assertRaisesRegex(ValueError, 'URL'):
            verify.repository_expected(ROOT, profile)

    @unittest.skipUnless(shutil.which('mksquashfs') and shutil.which('unsquashfs'), 'SquashFS tools needed for real fixture')
    def test_actual_squashfs_root_vendor_bytes_and_negative_cases(self):
        tree = self.root / 'root-tree'
        tree.mkdir()
        profile = {'channel': 'recommended',
                   'publication': {'site_url': 'https://valujin.github.io/ax6000-packages-6.12'},
                   'build_source': {'publication_url': 'https://valujin.github.io/ax6000-packages-6.12/channels/recommended'},
                   'firmware': {'commit': 'ae65e1de69971b5a2e3cf7e39390ee93f274d488',
                                'kernel_version': '6.12.108~' + 'a' * 32 + '-r1',
                                'architecture': 'aarch64_cortex-a53'}, 'image_packages': []}
        expected, fp = verify.repository_expected(ROOT, profile)
        def write(path, data, mode=0o644):
            dest = tree / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            dest.chmod(mode)
        for path, (data, mode) in expected.items():
            write(path, data, mode)
        write('etc/opkg.conf', b'option check_signature\n')
        write('bin/opkg', b'fixture executable, never run\n', 0o755)
        write('usr/bin/fixture', b'placeholder')
        write('etc/openwrt_release', b"DISTRIB_TARGET='mediatek/filogic'\nDISTRIB_ARCH='aarch64_cortex-a53'\nDISTRIB_REVISION='r1-ae65e1de6997'\n")
        controls, ipks, manifest, paragraphs = {}, {}, {}, []
        for name in sorted(verify.VENDOR | verify.UCODE | {'opkg', 'kernel'}):
            version = profile['firmware']['kernel_version'] if name == 'kernel' else '1-r1'
            control = {'Package': name, 'Version': version, 'Architecture': 'aarch64_cortex-a53'}
            controls[name] = control
            manifest[name] = version
            paragraphs.append(''.join(k + ': ' + v + '\n' for k, v in control.items()) + 'Status: install ok installed\n')
            if name in verify.VENDOR:
                module = 'lib/modules/6.12.108/' + name + '.ko'
                data = elf_fixture()
                write(module, data)
                path = self.root / (name + '.ipk')
                make_ipk(path, control, {module: data})
                ipks[name] = path
        status = '\n'.join(paragraphs).encode()
        write('usr/lib/opkg/status', status)
        config = b'CONFIG_SMP=y\nCONFIG_MODULE_UNLOAD=y\n# CONFIG_MODVERSIONS is not set\n'
        binary = Path(shutil.which('unsquashfs'))
        def pack():
            p = self.root / 'actual-root.squashfs'
            subprocess.run([shutil.which('mksquashfs'), str(tree), str(p), '-noappend', '-processors', '1',
                            '-comp', 'xz', '-b', '131072', '-no-xattrs'], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with p.open('ab') as stream:
                stream.write(b'\0' * (-p.stat().st_size % 4096))
            return p
        def inspect():
            return verify.inspect_root(pack(), 'stock', binary, profile, controls, ipks, expected, fp, config, manifest)
        record = inspect()
        self.assertEqual(len(record['modules']), 4)
        self.assertEqual(record['installed_kernel']['Version'], profile['firmware']['kernel_version'])
        installer = tree / 'usr/sbin/ax6000-install-feed'
        installer.chmod(0o644)
        with self.assertRaisesRegex(ValueError, '0755'):
            inspect()
        installer.chmod(0o755)
        write('etc/opkg/distfeeds.conf', b'src/gz moving https://example.invalid/feed\n')
        with self.assertRaisesRegex(ValueError, 'repository'):
            inspect()
        write('etc/opkg/distfeeds.conf', expected['etc/opkg/distfeeds.conf'][0])
        module = tree / 'lib/modules/6.12.108/kmod-mt_wifi.ko'
        module.write_bytes(elf_fixture('6.6.133'))
        with self.assertRaisesRegex(ValueError, 'module/firmware bytes'):
            inspect()
        module.write_bytes(elf_fixture())
        write('usr/lib/opkg/status', status.replace(profile['firmware']['kernel_version'].encode(), b'6.6.133~old-r1'))
        with self.assertRaisesRegex(ValueError, 'kernel ABI'):
            inspect()


if __name__ == '__main__':
    unittest.main()
