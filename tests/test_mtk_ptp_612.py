"""Vendor Ethernet must link to a reachable PTP core for either source pin."""
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

from test_source_layouts_612 import firmware, ROOT


TARGET = 'target/linux/mediatek/patches-6.12/999-zzz-5400-net-mediatek-select-reachable-ptp-clock.patch'


class MediatekPtp612Tests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'), 'native C compiler required')
    def test_both_pins_keep_builtin_ethernet_with_reachable_ptp_and_valid_conditions(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            with tarfile.open(ROOT/'tests/fixtures/openwrt-kconfig-tools-ae65e1d.tar.gz') as archive:
                manifest = json.load(archive.extractfile('fixture-manifest.json'))
                for name, digest in manifest['files'].items():
                    data = archive.extractfile(name).read()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                    p = work/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
            tools = work/'scripts/config'; conf = work/'conf'
            subprocess.run(['cc','-O0','-I',str(tools),'-o',str(conf)] + [str(tools/name) for name in
                ('conf.c','confdata.c','expr.c','lexer.lex.c','menu.c','parser.tab.c','preprocess.c','symbol.c','util.c')],
                check=True, capture_output=True, timeout=30)
            vendor = gzip.decompress((ROOT/'tests/fixtures/ax6000-612-vendor-ethernet-Kconfig.gz').read_bytes())
            self.assertEqual(hashlib.sha256(vendor).hexdigest(),
                             '445828a4f42e7849e957cf728552d8b2608899ea9ca4522c83c175eb25f9c11f')
            ptp_bytes = gzip.decompress((ROOT/'tests/fixtures/linux-6.12.108-ptp-Kconfig.gz').read_bytes())
            self.assertEqual(hashlib.sha256(ptp_bytes).hexdigest(),
                             'bafed28cb70ccc59035deae6dbcda7df7e6265c5210834ded49d2ea9207a2d47')
            ptp = ptp_bytes.decode()
            # The real core and OPTIONAL symbol are sufficient to exercise the
            # dependency. Hardware-specific clocks later in this file are excluded.
            (work/'ptp.in').write_text(ptp[:ptp.index('config PTP_1588_CLOCK_DTE')]+'endmenu\n')
            prefix = ('mainmenu "MediaTek PTP regression"\n'
                'config MODULES\n\tmodules\n\tbool\n\tdefault y\n'
                'config NET\n\tbool "Network"\n'
                'config NETDEVICES\n\tbool "Devices"\n\tdepends on NET\n'
                'config POSIX_TIMERS\n\tbool "POSIX"\n'
                'config ETHERNET\n\tbool\n\tdefault y\n'
                'config ARCH_MEDIATEK\n\tbool\n\tdefault y\n'
                'config PPS\n\ttristate\n'
                'config NET_PTP_CLASSIFY\n\tbool\n'
                'source "ptp.in"\nif NETDEVICES\nsource "mediatek.in"\nendif\n')
            (work/'Kconfig').write_text(prefix)
            def solve(data, soc='y', ptp_value='m', posix='y', net='y'):
                (work/'mediatek.in').write_bytes(data)
                config=work/'output.config'
                config.write_text(f'CONFIG_MODULES=y\nCONFIG_NET={net}\nCONFIG_NETDEVICES={net}\n'
                    f'CONFIG_POSIX_TIMERS={posix}\nCONFIG_NET_VENDOR_MEDIATEK=y\n'
                    f'CONFIG_NET_MEDIATEK_SOC={soc}\nCONFIG_PTP_1588_CLOCK={ptp_value}\n')
                result=subprocess.run([str(conf),'--olddefconfig','Kconfig'],cwd=work,
                    env={**os.environ,'KCONFIG_CONFIG':str(config)},text=True,capture_output=True,check=True,timeout=5)
                self.assertNotIn('unmet direct dependencies',result.stderr)
                return dict(re.findall(r'^CONFIG_([^=]+)=(.+)$',config.read_text(),re.M))
            old=solve(vendor)
            self.assertEqual(old['NET_MEDIATEK_SOC'],'y');self.assertEqual(old['PTP_1588_CLOCK'],'m')
            for channel in ('recommended','latest'):
                with self.subTest(channel=channel):
                    directory=ROOT/f'patches/firmware-6.12/{channel}'
                    specs=json.loads((directory/'manifest.json').read_text())['patches']
                    spec=next(p for p in specs if p['path']==TARGET)
                    self.assertEqual(spec['operation'],'add');self.assertIsNone(spec['before_sha256'])
                    source=work/channel;source.mkdir()
                    firmware.apply_source_patch(source,spec,directory/spec['patch'])
                    kernel=source/'drivers/net/ethernet/mediatek/Kconfig'
                    kernel.parent.mkdir(parents=True);kernel.write_bytes(vendor)
                    subprocess.run(['patch','-s','-p1'],cwd=source,input=(source/TARGET).read_bytes(),
                                   check=True,capture_output=True,timeout=5)
                    patched=kernel.read_bytes()
                    new=solve(patched)
                    self.assertEqual(new['NET_MEDIATEK_SOC'],'y')
                    self.assertEqual(new['PTP_1588_CLOCK'],'y');self.assertEqual(new['PPS'],'y')
                    changes={key:(old.get(key),new.get(key)) for key in old.keys()|new.keys() if old.get(key)!=new.get(key)}
                    self.assertEqual(changes,{'PTP_1588_CLOCK':('m','y'),'PTP_1588_CLOCK_OPTIONAL':('m','y'),'PPS':('m','y')})
                    modular=solve(patched,soc='m')
                    self.assertEqual(modular['NET_MEDIATEK_SOC'],'m');self.assertEqual(modular['PTP_1588_CLOCK'],'m')
                    no_timers=solve(patched,posix='n')
                    self.assertEqual(no_timers['NET_MEDIATEK_SOC'],'y');self.assertNotIn('PTP_1588_CLOCK',no_timers)
                    no_net=solve(patched,net='n')
                    self.assertNotIn('NET_MEDIATEK_SOC',no_net);self.assertNotIn('PTP_1588_CLOCK',no_net)
                    firmware.apply_source_patch(source,spec,directory/spec['patch'],check_only=True)
                    (source/TARGET).write_bytes((source/TARGET).read_bytes()+b'# drift\n')
                    with self.assertRaisesRegex(ValueError,'source hash differs'):
                        firmware.apply_source_patch(source,spec,directory/spec['patch'])


if __name__=='__main__':
    unittest.main()
