"""Explicit stable-kernel defaults avoid unattended syncconfig prompts."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from test_source_layouts_612 import firmware, profile, ROOT


class KernelConfig612Tests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'), 'native C compiler required')
    def test_both_pinned_defaults_resolve_only_two_new_pressure_symbols(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            with tarfile.open(ROOT/'tests/fixtures/openwrt-kconfig-tools-ae65e1d.tar.gz') as archive:
                manifest = json.load(archive.extractfile('fixture-manifest.json'))
                for name, digest in manifest['files'].items():
                    data = archive.extractfile(name).read()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                    target = work/name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
            tools = work/'scripts/config'
            conf = work/'conf'
            subprocess.run(['cc','-O0','-I',str(tools),'-o',str(conf)] + [str(tools/name) for name in
                ('conf.c','confdata.c','expr.c','lexer.lex.c','menu.c','parser.tab.c','preprocess.c','symbol.c','util.c')],
                check=True, capture_output=True, timeout=30)
            pressure = gzip.decompress((ROOT/'tests/fixtures/linux-6.12.108-pressure-Kconfig.gz').read_bytes())
            self.assertEqual(hashlib.sha256(pressure).hexdigest(),
                             '34ee2b270b82d98ca9be7d2f269ce71fd8501f48ec03d90e1b6dcee4bd16c00d')
            (work/'pressure.in').write_bytes(pressure)
            (work/'Kconfig').write_text('mainmenu "Pressure stable defaults"\n'
                'config MODULES\n\tmodules\n\tbool\n\tdefault y\n'
                'config I2C\n\tbool\n\tdefault y\n'
                'config SPI\n\tbool\n\tdefault y\n'
                'config IIO_BUFFER\n\tbool\n\tdefault y\n'
                'config IIO_TRIGGERED_BUFFER\n\ttristate\n'
                'config REGMAP_I2C\n\ttristate\n'
                'config REGMAP_SPI\n\ttristate\n'
                'config VENDOR_PRESERVED\n\tbool\n\tdefault y\n'
                'source "pressure.in"\n')
            def solve(data, mode, name):
                config = work/name
                config.write_bytes(data)
                result = subprocess.run([str(conf), mode, 'Kconfig'], cwd=work,
                    env={**os.environ, 'KCONFIG_CONFIG':str(config)}, check=True,
                    capture_output=True, text=True, timeout=5)
                return result.stdout, config.read_bytes()
            for channel in ('recommended','latest'):
                with self.subTest(channel=channel):
                    original = gzip.decompress((ROOT/f'tests/fixtures/ax6000-612-{channel}-generic-config.gz').read_bytes())
                    specs = json.loads((ROOT/f'patches/firmware-6.12/{channel}/manifest.json').read_text())['patches']
                    spec = next(p for p in specs if p['path']=='target/linux/generic/config-6.12')
                    self.assertEqual(hashlib.sha256(original).hexdigest(), spec['before_sha256'])
                    target = work/'target/linux/generic/config-6.12'
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(original)
                    directory = ROOT/f'patches/firmware-6.12/{channel}'
                    firmware.apply_source_patch(work, spec, directory/spec['patch'])
                    patched = target.read_bytes()
                    self.assertEqual(patched, original.replace(b'# CONFIG_ZSWAP is not set\n',
                        b'# CONFIG_ZSWAP is not set\n# CONFIG_ZTS8032 is not set\n# CONFIG_ZTS8232 is not set\n'))
                    extra = b'CONFIG_MODULES=y\nCONFIG_I2C=y\nCONFIG_SPI=y\nCONFIG_IIO_BUFFER=y\nCONFIG_BMP280=m\nCONFIG_DPS310=m\nCONFIG_VENDOR_PRESERVED=y\n'
                    before, _ = solve(original+extra, '--listnewconfig', channel+'-new.config')
                    self.assertEqual(set(before.splitlines()), {'CONFIG_ZTS8032=n','CONFIG_ZTS8232=n'})
                    after, _ = solve(patched+extra, '--listnewconfig', channel+'-patched.config')
                    self.assertEqual(after, '')
                    _, normalized_before = solve(original+extra, '--olddefconfig', channel+'-old.config')
                    _, normalized_after = solve(patched+extra, '--olddefconfig', channel+'-fixed.config')
                    # Explicit n has the exact native default semantics; existing
                    # driver/vendor assignments and dependency choices survive.
                    self.assertEqual(normalized_before, normalized_after)
                    for symbol, value in [('BMP280','m'),('DPS310','m'),('VENDOR_PRESERVED','y')]:
                        self.assertIn(f'CONFIG_{symbol}={value}\n'.encode(), normalized_after)
                    firmware.apply_source_patch(work, spec, directory/spec['patch'], check_only=True)
                    target.write_bytes(patched+b'# unexpected drift\n')
                    with self.assertRaisesRegex(ValueError, 'source hash differs'):
                        firmware.apply_source_patch(work, spec, directory/spec['patch'])


if __name__ == '__main__':
    unittest.main()
