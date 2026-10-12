"""Execute native package install/strip expansion under the real 25.12 sstrip default."""
import gzip
import hashlib
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_prepare import prepare, ROOT
from test_verify_firmware import elf_fixture


NATIVE_FILES = {
    'rules.mk': '11a51c7597da4d013e24b3e670e6760f2392e258b90951bba2db2b91154edef5',
    'include-package-pack.mk': '5aa1d250eca44dc47c650a005b24a09077c5fdd9f61389fccfe9fba206fc525f',
    'scripts-rstrip.sh': '89bd54e8ce186f49b881aa0d72919495a15d716e9f69d9b266ab0ca28265d87d',
}


@unittest.skipUnless(shutil.which('make') and shutil.which('file'), 'GNU make and file required')
class TailscaleStaticStripTests(unittest.TestCase):
    def test_native_packaging_keeps_prebuilt_bytes_and_bumps_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = {}
            # These complete native files are byte-identical in both source pins.
            for name,digest in NATIVE_FILES.items():
                data = gzip.decompress((ROOT/'tests/fixtures'/('ax6000-612-'+name+'.gz')).read_bytes())
                self.assertEqual(hashlib.sha256(data).hexdigest(),digest);native[name]=data.decode()
            scripts=root/'scripts'; scripts.mkdir()
            rstrip=scripts/'rstrip.sh'; rstrip.write_text(native['scripts-rstrip.sh']); rstrip.chmod(0o755)
            host=root/'host/bin'; host.mkdir(parents=True)
            marker=root/'strip-called'
            mock=host/'sstrip';mock.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "'+str(marker)+'"\nfor arg do case "$arg" in -*) ;; *) printf X >> "$arg";; esac; done\n');mock.chmod(0o755)
            patchelf=host/'patchelf';patchelf.write_text('#!/bin/sh\nexit 0\n');patchelf.chmod(0o755)
            files=root/'files';files.mkdir()
            for name in ('tailscale.init','tailscale.conf'): (files/name).write_text('pinned '+name+'\n')
            binaries={}
            build=root/'build/tailscale_1.104.1_arm64';build.mkdir(parents=True)
            for name in ('tailscale','tailscaled'):
                binary=bytearray(elf_fixture());struct.pack_into('<H',binary,16,2)
                binaries[name]=bytes(binary)+name.encode();(build/name).write_bytes(binaries[name])
            native_rules=native['rules.mk'].split('# strip an entire directory\n',1)[1].split('\nNINJA =',1)[0]
            # Expand the exact native package post-install command (including its
            # deferred IDIR), rather than calling RSTRIP directly in a test recipe.
            strip_line=next(line for line in native['include-package-pack.mk'].splitlines()
                            if line.strip()=='$(RSTRIP) $$(IDIR_$(1))')
            (root/'rules.mk').write_text(native_rules)
            include=root/'include';include.mkdir()
            (include/'package.mk').write_text('define BuildPackage\nall:\n\t$(call Package/$(1)/install,$(IDIR_$(1)))\n'+strip_line+'\nendef\n')
            recipe=prepare.static_tailscale_recipe({'version':'1.104.1','sha256':'f'*64})
            self.assertIn('PKG_RELEASE:=2\n',recipe)
            self.assertIn('RSTRIP:=:\n',recipe)
            common=('TOPDIR:='+str(root)+'\nINCLUDE_DIR:='+str(include)+'\nBUILD_DIR:='+str(root/'build')+'\n'
                    'SCRIPT_DIR:='+str(scripts)+'\nSTAGING_DIR_HOST:='+str(root/'host')+'\n'
                    'CONFIG_USE_SSTRIP:=y\nCONFIG_SSTRIP_DISCARD_TRAILING_ZEROES:=y\n'
                    'INSTALL_DIR:=install -d -m0755\nINSTALL_BIN:=install -m0755\nINSTALL_DATA:=install -m0644\n')
            # Control proves native sstrip would touch these ELF fixtures without
            # the package-specific override; global defaults remain enabled.
            for label,content in [('control',recipe.replace('RSTRIP:=:\n','')),('fixed',recipe)]:
                dest=root/label
                makefile=common+'IDIR_tailscale:='+str(dest)+'\n'+content
                subprocess.run(['make','--no-print-directory','-f','-','all'],input=makefile,cwd=root,
                               text=True,check=True,capture_output=True,timeout=5)
                for name,original in binaries.items():
                    actual=(dest/'usr/sbin'/name).read_bytes()
                    self.assertEqual(actual,original+b'X' if label=='control' else original)
                    self.assertEqual((dest/'usr/sbin'/name).stat().st_mode & 0o777,0o755)
                if label=='control':
                    calls=marker.read_text().splitlines();self.assertEqual(len(calls),2)
                    self.assertTrue(all(line.startswith('-z ') for line in calls));marker.unlink()
                else:
                    self.assertFalse(marker.exists())
                    self.assertEqual((dest/'etc/init.d/tailscale').read_text(),'pinned tailscale.init\n')
                    self.assertEqual((dest/'etc/config/tailscale').read_text(),'pinned tailscale.conf\n')


if __name__=='__main__':unittest.main()
