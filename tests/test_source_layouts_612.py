"""Pinned source fixture proves configuration, reviewed patch and channel overlay."""
import copy
import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('source_612', ROOT / 'scripts/prepare-firmware.py')
firmware = importlib.util.module_from_spec(spec); spec.loader.exec_module(firmware)


def profile(channel='recommended'):
    return json.loads((ROOT / f'tests/fixtures/legacy612-{channel}-source-profile.json').read_text())


class Source612Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.profile = profile()
        baseline = self.source / self.profile['build_source']['defconfig']; baseline.parent.mkdir(parents=True)
        baseline.write_bytes(gzip.decompress((ROOT / 'tests/fixtures/ax6000-612-defconfig.gz').read_bytes()))

    def test_profiles_are_pinned_distinct_and_complete(self):
        for channel in ('recommended', 'latest'):
            p = profile(channel); firmware.validate(p, {})
            self.assertIsNone(p['firmware']['kernel_version'])
            self.assertIsNone(p['sdk']['url'])
            self.assertEqual([x['layout'] for x in p['firmware']['devices']], ['stock', 'mtkuboot', 'ubootmod'])
            self.assertTrue({'geoip-shell', 'geoview', 'geoipupdate'} <= set(p['packages']))
            self.assertFalse({'geoip-shell', 'geoview', 'geoipupdate'} & set(p['image_packages']))
            self.assertNotIn('luci-i18n-wireguard-ru', p['packages'])
        self.assertNotEqual(profile()['firmware']['commit'], profile('latest')['firmware']['commit'])

    def test_configure_preserves_vendor_and_selects_only_three_layouts(self):
        firmware.configure(self.profile, {}, self.source)
        config = (self.source / '.config').read_text()
        selected = {line.split('=')[0].removeprefix('CONFIG_TARGET_DEVICE_')
                    for line in config.splitlines() if line.startswith('CONFIG_TARGET_DEVICE_') and line.endswith('=y')}
        self.assertEqual(selected, {'mediatek_filogic_DEVICE_' + x['device'] for x in self.profile['firmware']['devices']})
        for symbol in ('TARGET_MULTI_PROFILE','TARGET_PER_DEVICE_ROOTFS','ALL_KMODS','SDK','SIGNED_PACKAGES','SIGNATURE_CHECK',
                       'PACKAGE_opkg','WIFI_SCRIPTS_UCODE','PACKAGE_iwinfo-ucode','PACKAGE_mtwifi-cfg-ucode',
                       'PACKAGE_ucode-mod-iwinfo','PACKAGE_kmod-leds-ws2812b','TARGET_ROOTFS_SQUASHFS',
                       'TARGET_ROOTFS_INITRAMFS','TARGET_ROOTFS_INITRAMFS_SEPARATE','TARGET_INITRAMFS_COMPRESSION_XZ'):
            self.assertIn('CONFIG_' + symbol + '=y\n', config)
        for symbol in ('USE_APK','CLEAN_IPKG','PACKAGE_iwinfo','PACKAGE_mtwifi-cfg','TARGET_ALL_PROFILES','TARGET_ROOTFS_EXT4FS'):
            self.assertIn('# CONFIG_' + symbol + ' is not set\n', config)
        self.assertIn('CONFIG_MTK_FIRST_IF_MT7986=y',config)
        self.assertIn('CONFIG_MTK_WIFI_SKU_TYPE="AX6000"',config)
        installer = self.source / 'files/usr/sbin/ax6000-install-feed'
        self.assertIn(b'ax6000-packages-6.12/channels/recommended}', installer.read_bytes())
        self.assertEqual(installer.stat().st_mode & 0o777, 0o755)
        firmware.repository_files(self.source, profile=self.profile, check_only=True)
        with self.assertRaises(ValueError):
            firmware.repository_files(self.source, profile=profile('latest'), check_only=True)

    def test_select_and_verify_three_layouts_and_rejects_native_wifi_install(self):
        firmware.configure(self.profile, {}, self.source)
        self.source.joinpath('tmp').mkdir()
        packages = set(self.profile['packages']) | set(firmware.source_symbols(self.profile))
        packages = {p.removeprefix('PACKAGE_') for p in packages if p.startswith('PACKAGE_')} | set(self.profile['packages'])
        packages |= {'kmod-test-compatible', 'kmod-test-incompatible'}
        (self.source/'tmp/.packageinfo').write_text(''.join(
            'Source-Makefile: package/fixture/'+p+'/Makefile\nPackage: '+p+'\n' for p in sorted(packages)))
        (self.source/'tmp/.config-package.in').write_text('config LUCI_LANG_ru\n' + ''.join('config PACKAGE_'+p+'\n' for p in sorted(packages)))
        (self.source/'tmp/.config-target.in').write_text(''.join('config TARGET_DEVICE_mediatek_filogic_DEVICE_'+d+'\n' for d in [x['device'] for x in self.profile['firmware']['devices']] + ['foreign_router']))
        self.patch_fixture()
        firmware.vendor_fixes(self.profile, self.source)
        firmware.select(self.profile, self.source)
        config=(self.source/'.config').read_text()
        self.assertIn('# CONFIG_TARGET_DEVICE_mediatek_filogic_DEVICE_foreign_router is not set',config)
        self.assertIn('CONFIG_PACKAGE_kmod-test-compatible=m',config)
        self.assertIn('CONFIG_PACKAGE_kmod-leds-ws2812b=y',config)
        self.assertIn('CONFIG_PACKAGE_tailscale=m',config)
        # Independent post-defconfig fixture: one unavailable kmod is legitimately discarded.
        config=firmware.set_symbols(config, {'TARGET_ARCH_PACKAGES':'"aarch64_cortex-a53"','PACKAGE_kmod-test-incompatible':'n'})
        (self.source/'.config').write_text(config)
        report=firmware.verify(self.profile,self.source)
        self.assertEqual(report['devices'],self.profile['firmware']['devices'])
        self.assertIn('kmod-test-incompatible',report['incompatible_kmods'])
        (self.source/'.config').write_text(firmware.set_symbols(config,{'PACKAGE_kmod-mt7915e':'y'}))
        with self.assertRaisesRegex(ValueError,'native WiFi'):
            firmware.verify(self.profile,self.source)

    def patch_fixture(self, channel='recommended'):
        for relative, payload in [('include/kernel-defaults.mk', gzip.decompress((ROOT/'tests/fixtures/ax6000-612-kernel-defaults.gz').read_bytes())),
                                  ('target/linux/generic/config-6.12',gzip.decompress((ROOT/f'tests/fixtures/ax6000-612-{channel}-generic-config.gz').read_bytes())),
                                  ('target/linux/mediatek/Makefile',b'KERNEL_PATCHVER:=6.12\n'),
                                  ('target/linux/mediatek/image/filogic.mk',gzip.decompress((ROOT/f'tests/fixtures/ax6000-612-{channel}-filogic.mk.gz').read_bytes())),
                                  ('package/kernel/linux/modules/netdevices.mk',gzip.decompress((ROOT/'tests/fixtures/ax6000-612-netdevices.gz').read_bytes())),
                                  ('feeds/packages/net/openvswitch/Makefile',gzip.decompress((ROOT/'tests/fixtures/openvswitch-packages-52ddbd1-Makefile.gz').read_bytes())),
                                  ('package/network/config/wifi-scripts/files/lib/netifd/wireless-device.uc',gzip.decompress((ROOT/'tests/fixtures/mtwifi-wireless-device-ae65e1d.uc.gz').read_bytes()))]:
            target=self.source/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(payload)

    def test_patched_native_compressor_command_has_one_worker_for_every_layout(self):
        self.patch_fixture()
        firmware.vendor_fixes(self.profile,self.source)
        line=next(line.strip() for line in (self.source/'include/kernel-defaults.mk').read_text().splitlines()
                  if '/bin/xz ' in line)
        command=line.split(';)')[0]
        host=self.source/'host';(host/'bin').mkdir(parents=True)
        capture=self.source/'captured';tool=host/'bin/xz'
        tool.write_text('#!/bin/sh\nfor arg do printf "%s\\n" "$arg"; done > "'+str(capture)+'"\n')
        tool.chmod(0o755)
        makefile=self.source/'compressor.mk'
        # Expand the exact source command with native GNU Make variables. Fake xz
        # captures argv, so this checks NPROC/layout expansion without compression.
        makefile.write_text('STAGING_DIR_HOST := '+str(host)+'\nKERNEL_BUILD_DIR := '+str(self.source)+'\n'
                            'define compress\n\t'+command+'\nendef\n'
                            'all:\n\t$(call compress,,-$(LAYOUT))\n')
        for layout in ('stock','mtkuboot','ubootmod'):
            for nproc in ('1','4','8'):
                subprocess.run(['make','--no-print-directory','-f',str(makefile),'NPROC='+nproc,'LAYOUT='+layout],
                               cwd=self.source,check=True,stdout=subprocess.DEVNULL)
                self.assertEqual(capture.read_text().splitlines(),
                                 ['-T1','-9','-fz','--check=crc32',str(self.source/('initrd-'+layout+'.cpio'))])

    def test_exact_patch_for_both_pins_idempotent_and_rejects_drift(self):
        self.patch_fixture()
        for channel in ('recommended','latest'):
            with self.subTest(channel=channel):
                self.patch_fixture(channel)
                patches=firmware.vendor_fixes(profile(channel),self.source)
                output=(self.source/'include/kernel-defaults.mk').read_text()
                self.assertIn('/bin/xz -T1 -9 -fz --check=crc32',output)
                self.assertNotIn('-T$(if',output)
                self.assertEqual(len(patches),8 if channel == 'recommended' else 7)
                firmware.vendor_fixes(profile(channel),self.source,check_only=True)
                firmware.vendor_fixes(profile(channel),self.source)
        target=self.source/'include/kernel-defaults.mk';target.write_text(target.read_text()+'# unexpected drift\n')
        with self.assertRaises(ValueError):
            firmware.vendor_fixes(profile('latest'),self.source)


if __name__=='__main__': unittest.main()
