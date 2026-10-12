"""Evaluate the pinned native KernelPackage DUMP/install rules for the renamed PHY."""
import gzip
import hashlib
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from test_source_layouts_612 import ROOT, firmware


ORIGINAL_SHA = 'bbaf34425009736eb81ea371e38284ed048ded112d912bfc1327f3ad6e012af6'
PACKAGE = 'phy-aeonsemi-as21xxx'


class As21xxx612Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.original = gzip.decompress((ROOT/'tests/fixtures/ax6000-612-netdevices.gz').read_bytes())
        self.assertEqual(hashlib.sha256(self.original).hexdigest(), ORIGINAL_SHA)
        with tarfile.open(ROOT/'tests/fixtures/openwrt-kconfig-tools-ae65e1d.tar.gz') as archive:
            manifest = json.load(archive.extractfile('fixture-manifest.json'))
            self.kernel_rules = archive.extractfile('include/kernel.mk').read()
            self.assertEqual(hashlib.sha256(self.kernel_rules).hexdigest(), manifest['files']['include/kernel.mk'])

    def make_package(self, recipe, destination):
        text = recipe.decode()
        section = text[text.index('define KernelPackage/'+PACKAGE+'\n'):text.index('define KernelPackage/'+PACKAGE+'/description')]
        rules = self.kernel_rules.decode()
        # These are the original complete KernelPackage and ModuleAutoLoad rules,
        # not a copy of the install algorithm. Only unrelated framework hooks are stubbed.
        rules = rules[rules.index('define KernelPackage/Defaults'):rules.index('version_field=')]
        linux = self.work/'linux'; (linux/'drivers/net/phy').mkdir(parents=True, exist_ok=True)
        (linux/'modules.builtin').touch()
        (linux/'drivers/net/phy/aeon_as21xxx.ko').write_bytes(b'fixture native module bytes\x00')
        prefix = ('DUMP:=1\nPKG_NAME:=kernel\nCONFIG_AS21XXX_PHY:=m\nCONFIG_PACKAGE_kmod-'+PACKAGE+':=m\n'
                  'LINUX_DIR:='+str(linux)+'\nMODULES_SUBDIR:=lib/modules/6.12.108\nCP:=cp -fpR\n'
                  'STAMP_BUILT:='+str(self.work/'built')+'\nIPKG_kmod-'+PACKAGE+':='+str(self.work/'ignored.ipk')+'\n')
        makefile = prefix+rules+section+'\n$(eval $(call KernelPackage,'+PACKAGE+'))\n'
        makefile += '$(info KCONFIG=$(KCONFIG))\n$(info DEPENDS=$(DEPENDS))\n$(info FILES=$(FILES))\n$(info AUTOLOAD=$(AUTOLOAD))\n'
        makefile += 'define fixture_install\nall:\n\t$(call Package/kmod-'+PACKAGE+'/install,'+str(destination)+')\nendef\n$(eval $(fixture_install))\n'
        return subprocess.run(['make','--no-print-directory','-f','-','all'], input=makefile,
                              text=True,capture_output=True,cwd=self.work,timeout=5)

    def test_native_dump_and_install_for_both_pins(self):
        old = self.make_package(self.original, self.work/'old')
        self.assertNotEqual(old.returncode, 0)
        self.assertIn('as21xxx.ko\' is missing', old.stderr)
        for channel in ('recommended','latest'):
            with self.subTest(channel=channel):
                directory = ROOT/'patches/firmware-6.12'/channel
                manifest = json.loads((directory/'manifest.json').read_text())
                spec = next((p for p in manifest['patches'] if p['path']=='package/kernel/linux/modules/netdevices.mk'), None)
                self.assertIsNotNone(spec, 'both pinned channels need the packaging correction')
                self.assertEqual(spec['before_sha256'], ORIGINAL_SHA)
                target = self.work/spec['path']; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(self.original)
                firmware.apply_source_patch(self.work, spec, directory/spec['patch'])
                updated = target.read_bytes()
                # Exactly two substitutions; kernel selection and dependencies stay identical.
                expected = self.original.replace(b'/phy/as21xxx.ko', b'/phy/aeon_as21xxx.ko').replace(
                    b'AutoLoad,18,as21xxx)', b'AutoLoad,18,aeon_as21xxx)')
                self.assertEqual(updated, expected)
                firmware.apply_source_patch(self.work, spec, directory/spec['patch'], check_only=True)
                firmware.apply_source_patch(self.work, spec, directory/spec['patch'])
                dest = self.work/channel
                new = self.make_package(updated, dest)
                self.assertEqual(new.returncode, 0, new.stdout+new.stderr)
                self.assertIn('KCONFIG=CONFIG_AS21XXX_PHY\n', new.stdout)
                self.assertIn('DEPENDS=+aeonsemi-as21xxx-firmware +kmod-libphy\n', new.stdout)
                self.assertIn('AUTOLOAD=18 0 aeon_as21xxx\n', new.stdout)
                self.assertEqual((dest/'lib/modules/6.12.108/aeon_as21xxx.ko').read_bytes(), b'fixture native module bytes\x00')
                self.assertEqual((dest/('etc/modules.d/18-'+PACKAGE)).read_text(), 'aeon_as21xxx\n')
                self.assertFalse((dest/'etc/modules-boot.d').exists())
                self.assertFalse(list(dest.rglob('as21xxx.ko')))
                target.write_bytes(updated+b'# drift\n')
                with self.assertRaises(ValueError):
                    firmware.apply_source_patch(self.work, spec, directory/spec['patch'])

    def test_source_and_patch_hash_drift_refuse_before_mutation(self):
        for channel in ('recommended','latest'):
            with self.subTest(channel=channel):
                directory = ROOT/'patches/firmware-6.12'/channel
                manifest = json.loads((directory/'manifest.json').read_text())
                spec = next(p for p in manifest['patches'] if p['path']=='package/kernel/linux/modules/netdevices.mk')
                target = self.work/spec['path']; target.parent.mkdir(parents=True, exist_ok=True)
                before = self.original+b'# upstream drift\n'; target.write_bytes(before)
                with self.assertRaises(ValueError):
                    firmware.apply_source_patch(self.work, spec, directory/spec['patch'])
                self.assertEqual(target.read_bytes(), before)
                target.write_bytes(self.original)
                bad_patch = self.work/'untrusted.patch'
                bad_patch.write_bytes((directory/spec['patch']).read_bytes()+b'# patch drift\n')
                with self.assertRaises(ValueError):
                    firmware.apply_source_patch(self.work, spec, bad_patch)
                self.assertEqual(target.read_bytes(), self.original)


if __name__ == '__main__': unittest.main()
