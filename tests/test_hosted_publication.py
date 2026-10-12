import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hosted_scope', ROOT/'scripts/hosted-publication.py')
hosted = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hosted)


class HostedResourceScope(unittest.TestCase):
    def test_half_memory_and_cpu_budget(self):
        memory, cpus = hosted.resource_budget('MemTotal:  16777216 kB\n', {0, 1, 2, 3})
        self.assertEqual(memory, 8*1024**3)
        self.assertEqual(cpus, 2)
        self.assertEqual(hosted.resource_budget('MemTotal: 8388608 kB\n', {0})[1], 1)

    def test_payload_has_no_credentials_in_arguments_and_drops_root(self):
        command = hosted.scope_command(8*1024**3, 2, 1001, ['python3', 'scripts/channel-snapshot.py', 'refresh'])
        self.assertIn('--uid=1001', command)
        self.assertIn('--property=MemorySwapMax=0', command)
        self.assertIn('--property=CPUQuota=200%', command)
        self.assertIn('--property=MemoryMax=8589934592', command)
        self.assertIn('--preserve-env='+','.join(hosted.PRESERVE), command)
        self.assertNotIn('OPKG_SIGNING_KEY', ','.join(command))
        self.assertEqual(command[-3:], ['python3', 'scripts/channel-snapshot.py', 'refresh'])

    def test_actual_scope_files_verified_before_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);group=root/'system.slice/ax6000.scope';group.mkdir(parents=True)
            (group/'memory.max').write_text('8388608\n')
            (group/'memory.swap.max').write_text('0\n')
            (group/'cpu.max').write_text('200000 100000\n')
            self.assertEqual(hosted.verify_scope(8388608,2,'0::/system.slice/ax6000.scope\n',root),group)
            for name, wrong in [('memory.max','max'),('memory.swap.max','1024'),('cpu.max','400000 100000')]:
                original=(group/name).read_text();(group/name).write_text(wrong)
                with self.assertRaises(ValueError):hosted.verify_scope(8388608,2,'0::/system.slice/ax6000.scope\n',root)
                (group/name).write_text(original)

    def test_scope_escape_and_invalid_budget_rejected(self):
        with self.assertRaises(ValueError):hosted.verify_scope(8388608,2,'0::/../../escape\n')
        with self.assertRaises(ValueError):hosted.resource_budget('MemAvailable: 100 kB', {0})


if __name__ == '__main__':unittest.main()
