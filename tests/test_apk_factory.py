"""Real host APK DB plus complete FIT/UBI/CPIO fixtures; never run target code."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from test_stock_factory_payload import entry, compressed, fit, raw_ubi, roots
import stock_factory as factory

APK = os.environ.get('AX6000_HOST_APK')


class ApkDatabaseTests(unittest.TestCase):
    def test_offline_db_exact_identity_alias_and_mutations(self):
        data = b'P:libfixture9\nV:1.2-r4\nA:aarch64_cortex-a53\ng:openwrt:abiversion=9\nF:usr\nR:a\nR:b\n\n'
        records = factory.apk_status_packages(data)
        self.assertEqual(records['libfixture9']['Base-Package'], 'libfixture')
        self.assertEqual(records['libfixture9']['Version'], '1.2-r4')
        for bad in [data + data, data.rstrip(), data.replace(b'abiversion=9', b'abiversion=8'),
                    data.replace(b'V:1.2-r4', b'V:1-r1\nV:2-r1'), data.replace(b'P:libfixture9', b'P:../escape')]:
            with self.subTest(bad=bad):
                self.assertRaises(ValueError, factory.apk_status_packages, bad)
        for name in ['lib/apk/packages/tailscale.list', 'lib/apk/packages/tailscale.conffiles']:
            with self.assertRaisesRegex(ValueError, 'metadata'):
                factory.assert_absent(['tailscale'], records, [name])

    @unittest.skipUnless(APK, 'AX6000_HOST_APK must select trusted host apk-tools 3')
    def test_real_apk_installed_database_in_factory_and_reject_payload_metadata(self):
        with tempfile.TemporaryDirectory(prefix='factory-apk-') as tmp:
            root = Path(tmp)
            payload = root / 'payload'; payload.mkdir()
            (payload / 'fixture').write_bytes(b'host-generated APK fixture, never executed\n')
            apk = Path(APK).resolve(strict=True)
            archive = root / 'libfixture9.apk'
            subprocess.run([str(apk), '--no-network', 'mkpkg', '--info', 'name:libfixture9',
                            '--info', 'version:1-r1', '--info', 'arch:aarch64_cortex-a53',
                            '--info', 'tags:openwrt:abiversion=9', '--files', str(payload), '--output', str(archive)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            installed = root / 'installed'; installed.mkdir()
            subprocess.run([str(apk), '--root', str(installed), '--usermode', '--arch', 'aarch64_cortex-a53',
                            '--no-network', '--no-scripts', '--no-commit-hooks', '--allow-untrusted',
                            '--repositories-file', '/dev/null', 'add', '--initdb', str(archive)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            data = (installed / 'lib/apk/db/installed').read_bytes()
            records = factory.apk_status_packages(data)
            self.assertEqual(records['libfixture9']['Base-Package'], 'libfixture')
            _, original = roots()
            entries = [item for item in original if not item['name'].startswith('usr/lib/opkg/')]
            expected = {'etc/asu-cohort.json': (b'{"fixture":true}\n', 0o644)}
            entries += [entry('lib/apk/db/installed', data, stat.S_IFREG | 0o644),
                        entry('lib/apk/packages/libfixture9.list', b'/fixture\n', stat.S_IFREG | 0o644),
                        entry('usr/bin/apk', b'ARM APK fixture not executed', stat.S_IFREG | 0o755),
                        entry('etc/apk/world', b'libfixture9\n', stat.S_IFREG | 0o644),
                        entry('etc/apk/keys/project.pem', b'public key fixture', stat.S_IFREG | 0o644),
                        entry('etc/apk/repositories.d/distfeeds.list', b'# frozen cohort\n', stat.S_IFREG | 0o644),
                        entry('etc/asu-cohort.json', expected['etc/asu-cohort.json'][0], stat.S_IFREG | 0o644)]
            def verify(items, packages=records):
                ram = fit(compressed(items)); image = raw_ubi(ram)
                ram_path = root / 'ram.bin'; ram_path.write_bytes(ram)
                ubi_path = root / 'factory.ubi'; ubi_path.write_bytes(image)
                return factory.verify_native_factory(ram_path, ubi_path, package_manager='apk',
                    package_only=['tailscale'], expected_packages=packages, expected_files=expected)
            proof = verify(entries)
            self.assertEqual(proof['package_manager'], 'apk')
            self.assertEqual(proof['package_only_absent'], ['tailscale'])
            self.assertIn('usr/bin/apk', proof['essential_paths'])
            with self.assertRaisesRegex(ValueError, 'metadata'):
                verify(entries + [entry('lib/apk/packages/tailscale.list', b'/usr/sbin/tailscale\n')])
            with self.assertRaisesRegex(ValueError, 'mixed manager'):
                verify(entries + [entry('usr/lib/opkg/status', b'old OPKG database')])
            with self.assertRaisesRegex(ValueError, 'overlay differs'):
                verify([item if item['name'] != 'etc/asu-cohort.json' else entry(item['name'], b'foreign', stat.S_IFREG | 0o644) for item in entries])
            with self.assertRaisesRegex(ValueError, 'package identity'):
                verify(entries, {'libfixture9': {**records['libfixture9'], 'Version': '2-r1'}})


if __name__ == '__main__':
    unittest.main()
