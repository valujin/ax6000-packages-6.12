"""Real APK v3 installation and SquashFS inspection, no target execution."""
import hashlib
import gzip
import copy
import io
import tarfile
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

from test_verify_firmware import verify, elf_fixture
import apk_world
import package_format
import image_features
import asu_client
import vendor_country
import host_apk_bundle

ROOT = Path(__file__).resolve().parents[1]
APK = os.environ.get('AX6000_HOST_APK') or os.environ.get('AX6000_APK')


@unittest.skipUnless(APK and shutil.which('mksquashfs') and shutil.which('unsquashfs'), 'trusted host APK and SquashFS tools required')
class NativeApkImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-apk-image-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.tree = self.root / 'tree'; self.bank = self.root / 'bank'; self.bank.mkdir()
        self.source = self.root / 'source'; (self.source / 'include').mkdir(parents=True)
        self.abi = '6.12.108~' + hashlib.md5(b'CONFIG_MODULE_UNLOAD=y\nCONFIG_SMP=y\n').hexdigest() + '-r1'
        self.profile = {'id': 'redmi-ax6000-612-recommended', 'channel': 'recommended', 'package_manager': 'apk',
            'apk_key_sha256': hashlib.sha256((ROOT / 'keys/repository-apk.pem').read_bytes()).hexdigest(),
            'publication': {'site_url': 'https://valujin.github.io/ax6000-packages-6.12'},
            'build_source': {'publication_url': 'https://valujin.github.io/ax6000-packages-6.12/channels/recommended'},
            'firmware': {'commit': verify.PINS['recommended'], 'kernel_version': self.abi,
                         'architecture': 'aarch64_cortex-a53'}, 'image_packages': [],
            'packages': ['tailscale'], 'package_only': ['tailscale'], 'vendor_country_db': True,
            'asu': {'enabled': True, 'cohort': '612-recommended', 'server_url': 'https://asu.ezon.by/612/recommended', 'seed': 'a' * 64}}
        self.features = image_features.expected(self.profile, {})
        self.lmo = b'compiled Russian translation fixture'
        self.db = vendor_country._patched_js(gzip.decompress((ROOT / 'tests/fixtures/vendor-country/612-wireless-mtk.js.gz').read_bytes()))
        (self.source / 'include/rootfs.mk').write_bytes((ROOT / 'tests/fixtures/apk-rootfs.mk').read_bytes())
        apk_world.configure_source(self.profile, self.source)
        (self.source / 'tmp').mkdir()
        names = verify.VENDOR | verify.UCODE | {'kernel', 'apk-openssl', 'openwrt-keyring', 'base-files', 'busybox', 'libc'} | set(asu_client.REQUIRED_PACKAGES) | {'luci-app-mtwifi-cfg'}
        (self.source / 'tmp/.packageinfo').write_text('Source-Makefile: package/fixtures/Makefile\n' +
                                                  ''.join('Package: ' + name + '\n' for name in sorted(names)))
        apk_world.configure_policy(self.profile, self.source)
        (self.source / 'public-key.pem').write_bytes((ROOT / 'keys/repository-apk.pem').read_bytes())
        self.controls, self.archives = {}, {}
        for name in sorted(names):
            payload = self.root / ('payload-' + name); payload.mkdir()
            def file(path, data, mode=0o644):
                target = payload / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data); target.chmod(mode)
            version = self.abi if name == 'kernel' else self.features['versions'].get(name, '1-r0')
            if name == 'luci-i18n-attendedsysupgrade-ru': version = '26.123.12345'
            if name == 'luci-app-attendedsysupgrade':
                for target, (data, mode) in self.features['files'].items():
                    if target.startswith(('www/', 'usr/share/rpcd/')): file(target, data, mode)
            if name == 'attendedsysupgrade-common':
                file('etc/uci-defaults/50-attendedsysupgrade', self.features['files']['etc/uci-defaults/50-attendedsysupgrade'][0])
            if name == 'luci-i18n-attendedsysupgrade-ru': file('usr/lib/lua/luci/i18n/attendedsysupgrade.ru.lmo', self.lmo)
            if name == 'luci-app-mtwifi-cfg': file('usr/share/luci-app-mtwifi-cfg/wireless-mtk.js', self.db)
            if name in verify.VENDOR:
                file('lib/modules/6.12.108/' + name + '.ko', elf_fixture())
                if name == 'kmod-mt_wifi': file('lib/firmware/mt7986.fixture.bin', b'actual native fixture firmware')
            if name == 'apk-openssl': file('usr/bin/apk', b'ARM APK fixture, never executed', 0o755)
            if name == 'openwrt-keyring':
                for key in ['immortalwrt-25.12.pem', 'openwrt-25.12.pem']:
                    file('etc/apk/keys/' + key, (ROOT / 'tests/fixtures/apk-keys' / key).read_bytes())
            archive = self.bank / (name + '-' + version + '.apk')
            command = [APK, '--no-network', 'mkpkg', '--info', 'name:' + name, '--info', 'version:' + version,
                       '--info', 'arch:aarch64_cortex-a53', '--files', str(payload), '--output', str(archive)]
            if name.startswith('kmod-'): command += ['--info', 'depends:kernel=' + self.abi]
            subprocess.run(command, check=True, capture_output=True)
            self.controls[name] = package_format.read_control(archive, apk=APK); self.archives[name] = archive
        index = self.bank / 'packages.adb'
        subprocess.run([APK, '--no-network', 'mkndx', '--allow-untrusted', '--output', str(index),
                        *map(str, self.archives.values())], check=True, capture_output=True)
        subprocess.run([APK, '--root', str(self.tree), '--usermode', '--arch', 'aarch64_cortex-a53',
                        '--no-network', '--repositories-file', '/dev/null', '--repository', 'file://' + str(index),
                        '--no-scripts', '--no-commit-hooks', '--allow-untrusted', 'add', '--initdb',
                        *sorted(names)], check=True, capture_output=True)
        self.expected, self.fingerprint = verify.repository_expected(ROOT, self.profile)
        for name in ['etc/asu-cohort.json', 'etc/uci-defaults/99-ax6000-asu']:
            self.expected[name] = self.features['files'][name]
        for path, (data, mode) in self.expected.items():
            target = self.tree / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data); target.chmod(mode)
        (self.tree / 'etc/openwrt_release').write_bytes(b"DISTRIB_TARGET='mediatek/filogic'\nDISTRIB_ARCH='aarch64_cortex-a53'\nDISTRIB_REVISION='r0+38427-ae65e1de6997'\n")
        policy = json.loads((self.source / 'ax6000-apk-world-policy.json').read_text())
        apk_world.pin_root(self.tree, Path(APK), policy)
        self.manifest = {name: control['Version'] for name, control in self.controls.items()}

    def inspect(self):
        image = self.root / 'root.squashfs'
        subprocess.run([shutil.which('mksquashfs'), str(self.tree), str(image), '-noappend', '-processors', '1',
                        '-comp', 'xz', '-b', '131072', '-no-xattrs'], check=True, capture_output=True)
        return verify.inspect_root(image, 'stock', Path(shutil.which('unsquashfs')), self.profile,
            self.controls, self.archives, self.expected, self.fingerprint,
            b'CONFIG_SMP=y\nCONFIG_MODULE_UNLOAD=y\n', self.manifest, feature_source=self.source, apk=Path(APK))

    def test_real_apk_image_preserves_native_modules_and_exact_guard(self):
        proof = self.inspect()
        self.assertEqual(proof['package_manager'], 'apk')
        self.assertTrue(proof['apk_executable_present'])
        self.assertEqual(len(proof['modules']), 4)
        self.assertEqual(proof['active_feeds'], 6)
        self.assertGreater(proof['apk_policy']['protected_packages'], 4)
        self.assertEqual(proof['package_only_absent'], ['tailscale'])
        self.assertGreaterEqual(len(proof['optional_features']['files']), 9)
        lmo = self.tree / 'usr/lib/lua/luci/i18n/attendedsysupgrade.ru.lmo'
        lmo.write_bytes(self.lmo + b'corrupted compiled translation')
        with self.assertRaisesRegex(ValueError, 'translation differs'): self.inspect()
        lmo.write_bytes(self.lmo)
        world = self.tree / 'etc/apk/world'; original = world.read_bytes()
        world.write_bytes(original.replace(('kernel=' + self.abi).encode(), b'kernel'))
        with self.assertRaisesRegex(ValueError, 'exact native pin'): self.inspect()
        world.write_bytes(original)
        module = self.tree / 'lib/modules/6.12.108/kmod-mt_wifi.ko'; actual = module.read_bytes()
        module.write_bytes(elf_fixture('6.6.133'))
        with self.assertRaisesRegex(ValueError, 'module/firmware bytes'): self.inspect()
        module.write_bytes(actual)
        metadata = self.tree / 'lib/apk/packages/tailscale.list'; metadata.parent.mkdir(exist_ok=True)
        metadata.write_bytes(b'/usr/sbin/tailscale\n')
        with self.assertRaisesRegex(ValueError, 'metadata remains'): self.inspect()

    def test_rejects_foreign_repository_key_and_mixed_manager(self):
        dist = self.tree / 'etc/apk/repositories.d/distfeeds.list'; original = dist.read_bytes()
        dist.write_bytes(original + b'https://foreign.invalid/targets/mediatek/filogic/packages.adb\n')
        with self.assertRaisesRegex(ValueError, 'repository bytes'): self.inspect()
        dist.write_bytes(original)
        key = self.tree / 'etc/apk/keys/openwrt-25.12.pem'; original = key.read_bytes(); key.write_bytes(original + b'wrong')
        with self.assertRaisesRegex(ValueError, 'official keyring'): self.inspect()
        key.write_bytes(original)
        old = self.tree / 'usr/lib/opkg/status'; old.parent.mkdir(parents=True); old.write_bytes(b'old OPKG metadata')
        with self.assertRaisesRegex(ValueError, 'OPKG database'): self.inspect()

    def test_sdk_apk_native_bank_tool_and_prepared_kernel_are_all_bound(self):
        relative = Path('build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/linux-6.12.108')
        kernel = self.source / relative
        config_set = b'CONFIG_MODULE_UNLOAD=y\nCONFIG_SMP=y\n'
        magic = hashlib.md5(config_set).hexdigest()
        contexts = {'.config': config_set + b'# CONFIG_MODVERSIONS is not set\n', '.config.set': config_set,
                    '.vermagic': (magic + '\n').encode(),
                    'Module.symvers': b'0x00000000\tfixture_symbol\tvmlinux\tEXPORT_SYMBOL\n',
                    'modules.builtin.modinfo': b'fixture.license=GPL\0',
                    'include/config/kernel.release': b'6.12.108\n',
                    'include/generated/autoconf.h': b'#define CONFIG_SMP 1\n'}
        for name, data in contexts.items():
            path = kernel / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        tool = self.source / 'staging_dir/host/bin/apk'; tool.parent.mkdir(parents=True); shutil.copy2(APK, tool)
        bundler = self.source / 'scripts/bundle-libraries.sh'; bundler.parent.mkdir(exist_ok=True)
        bundler_data = gzip.decompress((ROOT / 'tests/fixtures/sdk-bundle-libraries.sh.gz').read_bytes())
        self.assertEqual(hashlib.sha256(bundler_data).hexdigest(),
                         '5cfe9a8dcd9c6cca60d94e8e51f15ae79ffb84dbd403d2d4f17d55d9063a3036')
        bundler.write_bytes(bundler_data)
        sdk = self.root / 'sdk-bundle'; sdk_host = sdk / 'staging_dir/host'
        bundled = sdk_host / 'bin/apk'; bundled.parent.mkdir(parents=True); shutil.copy2(APK, bundled)
        subprocess.run(['bash', str(bundler), str(sdk_host), str(bundled)], check=True, capture_output=True)
        # Native target/sdk/Makefile strips all bin files and host/lib/*.so*, including .apk.bin.
        for path in sdk_host.rglob('*'):
            if path.is_file() and not path.is_symlink() and (path.parent == bundled.parent or '.so' in path.name):
                subprocess.run(['strip', str(path)], capture_output=True)
        tool_proof = host_apk_bundle.describe(sdk, tool, bundler)
        self.assertTrue(bundled.read_bytes().startswith(b'#!/usr/bin/env bash\n'))
        self.assertNotEqual((sdk_host / 'bin/.apk.bin').read_bytes(), tool.read_bytes())
        baseline = {'schema_version': 1, 'package_manager': 'apk', 'source_commit': self.profile['firmware']['commit'],
                    'kernel_version': self.abi, 'architecture': 'aarch64_cortex-a53',
                    'frozen_packages': sorted(self.controls), 'frozen_kmods': sorted(verify.VENDOR),
                    'files': [{'package': name, 'version': self.controls[name]['Version'],
                               'path': 'apks/' + path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                              for name, path in sorted(self.archives.items())],
                    'host_apk': tool_proof,
                    'kernel_context': {'path': relative.as_posix(), 'files': {name:
                        {'sha256': hashlib.sha256(contexts[name]).hexdigest(), 'size': len(contexts[name])}
                        for name in ['.config', 'Module.symvers', 'include/generated/autoconf.h', 'include/config/kernel.release']}}}
        values = {str(relative / name): data for name, data in contexts.items()}
        values.update({'Config-build.in': b'config TARGET_BOARD\n string\n default "mediatek"\n'
                       b'config TARGET_SUBTARGET\n string\n default "filogic"\n'
                       b'config TARGET_ARCH_PACKAGES\n string\n default "aarch64_cortex-a53"\n',
                       'include/version.mk': b'REVISION:=r0+38427-ae65e1de6997\n',
                       'staging_dir/host/bin/apk': bundled.read_bytes()})
        bundle_modes, bundle_links = {}, {}
        for path in sdk.rglob('*'):
            name = path.relative_to(sdk).as_posix()
            if path.is_symlink(): bundle_links[name] = os.readlink(path)
            elif path.is_file():
                values[name] = path.read_bytes(); bundle_modes[name] = stat.S_IMODE(path.stat().st_mode)
        values.update({'ax6000-baseline/apks/' + path.name: path.read_bytes() for path in self.archives.values()})
        def inspect(changes=None, metadata=None):
            contents = {**values, 'ax6000-baseline/manifest.json': json.dumps(metadata or baseline).encode(), **(changes or {})}
            archive = self.root / 'sdk.tar'
            with tarfile.open(archive, 'w') as tar:
                for name, data in contents.items():
                    member = tarfile.TarInfo('sdk/' + name); member.size = len(data)
                    member.mode = bundle_modes.get(name, 0o644); tar.addfile(member, io.BytesIO(data))
                for name, target in bundle_links.items():
                    member = tarfile.TarInfo('sdk/' + name); member.type = tarfile.SYMTYPE
                    member.mode = 0o777; member.linkname = target; tar.addfile(member)
            return verify.inspect_sdk(archive, kernel, self.source, self.root, self.profile,
                                      native_controls=self.controls, native_packages=self.archives)[0]
        proof = inspect()
        self.assertEqual(proof['apk_baseline']['frozen_kmods'], 4)
        self.assertTrue(proof['apk_baseline']['whole_native_archive_bytes_matched'])
        self.assertTrue(proof['apk_baseline']['source_transform']['independently_recomputed'])
        name = next(name for name in values if name.startswith('ax6000-baseline/apks/'))
        with self.assertRaisesRegex(ValueError, 'archive bytes'): inspect({name: values[name] + b'corruption'})
        wrong = copy.deepcopy(baseline); wrong['host_apk']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'host|entrypoint'): inspect(metadata=wrong)
        with self.assertRaisesRegex(ValueError, 'host|bundle|wrapper'):
            inspect({'staging_dir/host/bin/apk': b'#!/bin/sh\nexit 0\n'})
        library = next(name for name in values if name.startswith('staging_dir/host/lib/') and 'libcrypto.so' in name)
        with self.assertRaisesRegex(ValueError, 'host|bundle|hash'):
            inspect({library: values[library] + b'corruption'})
        wrong = copy.deepcopy(baseline); wrong['host_apk']['native_source']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'native-source provenance'): inspect(metadata=wrong)
        # Static inventory checks alone accept a self-consistent replacement ELF;
        # source-backed inspection must reproduce strip from the actual native APK.
        foreign_elf = Path(shutil.which('true')).resolve().read_bytes()
        forged = copy.deepcopy(baseline)
        foreign_sha = hashlib.sha256(foreign_elf).hexdigest()
        for member in forged['host_apk']['files']:
            if member['path'] == host_apk_bundle.HIDDEN:
                member.update(sha256=foreign_sha, size=len(foreign_elf), header=foreign_elf[:64].hex())
        forged['host_apk']['source_transform']['result_sha256'] = foreign_sha
        forged_records = {entry['path']: {k: value for k, value in entry.items() if k != 'path'}
                          for entry in forged['host_apk']['files']}
        host_apk_bundle.verify_records(forged['host_apk'], forged_records, bundled.read_bytes())
        with self.assertRaisesRegex(ValueError, 'independently stripped native source'):
            inspect({host_apk_bundle.HIDDEN: foreign_elf}, metadata=forged)
        wrong = copy.deepcopy(baseline); wrong['host_apk']['source_transform']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'GNU strip tool identity'):
            inspect(metadata=wrong)
        with self.assertRaisesRegex(ValueError, 'private signing key'): inspect({'private-key.pem': b'non-secret fixture marker'})

    def test_trusted_host_tool_boundary_and_apk_payload_identity(self):
        self.assertEqual(verify.trusted_apk_argument(APK, self.root), Path(APK).absolute())
        fake = self.root / 'raw/apk'; fake.parent.mkdir(); shutil.copy2(APK, fake)
        with self.assertRaisesRegex(ValueError, 'untrusted raw'): verify.trusted_apk_argument(fake, fake.parent)
        strip = verify.trusted_strip_argument()
        copied_strip = fake.parent / 'strip'; shutil.copy2(strip, copied_strip)
        with self.assertRaisesRegex(ValueError, 'untrusted raw'):
            verify.trusted_strip_argument(copied_strip, fake.parent)
        control, files = verify.package_contents(self.archives['kmod-mt_wifi'], payload=True, apk=APK)
        self.assertEqual(control, self.controls['kmod-mt_wifi'])
        self.assertEqual(files['lib/modules/6.12.108/kmod-mt_wifi.ko'], elf_fixture())


if __name__ == '__main__': unittest.main()
