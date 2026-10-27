"""Native 25.12 metadata/conf regression for unsupported OVS in-tree variants."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from test_source_layouts_612 import firmware, profile, ROOT


class OpenVSwitch612Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.source=Path(self.temp.name)
        for relative,data in [('include/kernel-defaults.mk',gzip.decompress((ROOT/'tests/fixtures/ax6000-612-kernel-defaults.gz').read_bytes())),
            ('target/linux/generic/config-6.12',gzip.decompress((ROOT/'tests/fixtures/ax6000-612-recommended-generic-config.gz').read_bytes())),
            ('target/linux/mediatek/Makefile',b'KERNEL_PATCHVER:=6.12\n'),
            ('target/linux/mediatek/image/filogic.mk',gzip.decompress((ROOT/'tests/fixtures/ax6000-612-recommended-filogic.mk.gz').read_bytes())),
            ('package/kernel/linux/modules/netdevices.mk',gzip.decompress((ROOT/'tests/fixtures/ax6000-612-netdevices.gz').read_bytes())),
            ('package/network/config/wifi-scripts/files/lib/netifd/wireless-device.uc',gzip.decompress((ROOT/'tests/fixtures/mtwifi-wireless-device-ae65e1d.uc.gz').read_bytes())),
            ('feeds/packages/net/openvswitch/Makefile',gzip.decompress((ROOT/'tests/fixtures/openvswitch-packages-52ddbd1-Makefile.gz').read_bytes()))]:
            p=self.source/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)

    def test_source_lock_pin_drift_refuses_before_any_source_mutation(self):
        p=profile();before={f:f.read_bytes() for f in self.source.rglob('*') if f.is_file()}
        with self.assertRaisesRegex(ValueError,'reviewed.*packages|packages.*reviewed'):
            firmware.validate(p,{'feeds':{'packages':'0'*40}})
        self.assertEqual(before,{f:f.read_bytes() for f in self.source.rglob('*') if f.is_file()})

    @unittest.skipUnless(shutil.which('cc') and shutil.which('perl'),'C compiler and Perl required')
    def test_native_conf_removes_only_six_intree_keeps_four_upstream(self):
        recipe=self.source/'feeds/packages/net/openvswitch/Makefile';original=recipe.read_text()
        firmware.vendor_fixes(profile(),self.source)
        tools=self.source/'native-tools';tools.mkdir()
        with tarfile.open(ROOT/'tests/fixtures/openwrt-kconfig-tools-ae65e1d.tar.gz') as archive:
            manifest=json.load(archive.extractfile('fixture-manifest.json'))
            self.assertEqual(manifest['source_commit'],profile()['firmware']['commit'])
            for name,digest in manifest['files'].items():
                data=archive.extractfile(name).read();self.assertEqual(hashlib.sha256(data).hexdigest(),digest)
                target=tools/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        conf=tools/'conf';config_sources=tools/'scripts/config'
        subprocess.run(['cc','-O0','-I',str(config_sources),'-o',str(conf)]+[str(config_sources/name) for name in
               ('conf.c','confdata.c','expr.c','lexer.lex.c','menu.c','parser.tab.c','preprocess.c','symbol.c','util.c')],
               check=True,capture_output=True,timeout=30)
        kernel=(tools/'include/kernel.mk').read_text();comparison=kernel[kernel.index('version_field='):]
        (tools/'package/fixture').mkdir(parents=True);(tools/'package/fixture/image-config.in').touch()
        metadata=tools/'packages.info'
        (tools/'Kconfig').write_text('mainmenu "Native 6.12 OVS regression"\nconfig MODULES\n\tmodules\n\tbool\n\tdefault y\n'+
            ''.join('config '+symbol+'\n\tbool\n\tdefault y\n' for symbol in ('ALL_KMODS','DEVEL','IPV6','LINUX_6_12'))+'source "packages.in"\n')
        defaults=tools/'defaults';defaults.write_text('CONFIG_ALL_KMODS=y\nCONFIG_LINUX_6_12=y\n')
        def solve(text,output_name):
            section=text[text.index('ovs_kmod_packages:='):text.index('# Dependency review')]
            metadata.write_text('Source-Makefile: feeds/packages/net/openvswitch/Makefile\n')
            writer='''
define emit
$(eval $(call KernelPackage/$(1)))
$(file >>$(OUT),Package: kmod-$(1))
$(file >>$(OUT),Submenu: $(SUBMENU))
$(file >>$(OUT),Category: $(CATEGORY))
$(file >>$(OUT),Title: $(TITLE))
$(file >>$(OUT),Depends: $(DEPENDS))
$(file >>$(OUT),Provides: $(PROVIDES))
$(file >>$(OUT),Type: ipkg)
$(file >>$(OUT),Description: $(TITLE))
$(file >>$(OUT),@@)
$(file >>$(OUT), )
endef
$(foreach p,$(ovs_kmod_packages),$(eval $(call emit,$(p))))
all:
\t@:
'''
            subprocess.run(['make','--no-print-directory','-f','-'],input='DUMP:=1\nKERNEL_PATCHVER:=6.12\nOUT:='+str(metadata)+'\n'+comparison+section+writer,
                           text=True,check=True,capture_output=True,timeout=5)
            dump=metadata.read_text();names=set(re.findall(r'^Package: (.+)$',dump,re.M))
            dependencies={token.split(':')[-1].lstrip('+') for line in re.findall(r'^Depends: (.*)$',dump,re.M)
                          for token in line.split() if token.startswith('+')}
            with metadata.open('a') as out:
                for name in sorted(dependencies-names):
                    out.write('\nSource-Makefile: package/support/'+name+'/Makefile\nPackage: '+name+'\nCategory: Kernel modules\nTitle: '+name+'\nType: ipkg\nDescription: fixture\n@@\n')
            parsed=subprocess.check_output(['perl',str(tools/'scripts/package-metadata.pl'),'config',str(metadata)],cwd=tools,text=True,timeout=5)
            (tools/'packages.in').write_text(parsed)
            output=tools/output_name
            subprocess.run([str(conf),'--defconfig='+str(defaults),'Kconfig'],cwd=tools,
                           env={**os.environ,'KCONFIG_CONFIG':str(output)},check=True,capture_output=True,timeout=5)
            return dict(re.findall(r'^CONFIG_([^=]+)=([my])$',output.read_text(),re.M))
        old=solve(original,'old.config');new=solve(recipe.read_text(),'new.config')
        removed={'PACKAGE_kmod-openvswitch'+suffix+'-intree' for suffix in ('','-gre','-vxlan','-geneve','-lisp','-stt')}
        self.assertEqual({name:old[name] for name in removed},dict.fromkeys(removed,'m'))
        self.assertEqual(set(old)-set(new),removed)
        self.assertEqual({name:value for name,value in old.items() if name not in removed},new)
        for suffix in ('','-gre','-vxlan','-geneve'):
            self.assertEqual(new['PACKAGE_kmod-openvswitch'+suffix],'m')
        self.assertEqual(new['LINUX_6_12'],'y')


if __name__=='__main__':unittest.main()
