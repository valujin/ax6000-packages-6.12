"""Round-trip Mesh state through the pinned sysupgrade selector and real tar."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest

from tests import test_mesh_transaction as transaction

ROOT = Path(__file__).resolve().parents[1]
FILES = transaction.FILES
SELECTOR = ROOT / 'tests/fixtures/mesh-runtime/sysupgrade-list-static.sh'
KEEP = FILES / 'lib/upgrade/keep.d/ax6000-mesh'


@unittest.skipUnless(shutil.which('busybox'), 'BusyBox ash and tar required')
class MeshSysupgrade(unittest.TestCase):
    setUp = transaction.MeshTransaction.setUp
    write_tool = transaction.MeshTransaction.write_tool
    call = transaction.MeshTransaction.call
    begin = transaction.MeshTransaction.begin

    def generated_configuration(self):
        self.begin()
        self.assertEqual(self.call('prepare-agent').returncode, 0)
        table = transaction.HELPER.read_text().split("cat <<'PATHS'\n", 1)[1].split('\nPATHS', 1)[0]
        self.live = []
        for line in table.splitlines():
            _, path = line.split()
            target = self.root / path.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                target.write_text('generated configuration fixture\n')
                target.chmod(0o600)
            self.live.append(target)
        mesh = self.root / 'etc/config/ax6000_mesh'
        config = json.loads(mesh.read_text()); config['main.enabled'] = '1'
        mesh.write_text(json.dumps(config, sort_keys=True))
        for band in ('b0', 'b1'):
            path = self.root / f'etc/wireless/mediatek/mt7986-ax6000.dbdc.{band}.dat'
            path.write_text(path.read_text().replace('SSID1=original', 'SSID1=enrolled-fixture'))
        state = self.root / 'etc/ax6000-mesh'
        (state / 'backhaul-key').write_text('synthetic private fixture\n')
        (state / 'backhaul-key').chmod(0o600)
        (self.root / 'var/run/ax6000-mesh-operation').write_text('volatile')
        (self.root / 'tmp').mkdir(exist_ok=True)
        (self.root / 'tmp/ax6000-mesh-pairing').write_text('volatile')
        self.assertEqual(self.call('seal').returncode, 0)

    def roundtrip(self):
        self.assertEqual(hashlib.sha256(SELECTOR.read_bytes()).hexdigest(),
                         '1f90f2bb00e7f376e5e769ff896d27696188669d1d9048cd88372e7501a10041')
        keep_dir = self.root / 'lib/upgrade/keep.d'; keep_dir.mkdir(parents=True)
        text = KEEP.read_text()
        text = re.sub(r'(?m)^(/[^\n]+)$', lambda m: str(self.root) + m[1], text)
        (keep_dir / 'ax6000-mesh').write_text(text)
        # The pinned package packer emits directory conffiles as keep.d rules.
        # These are the existing base-files and wifi-dats directory contracts.
        (keep_dir / 'base-files').write_text(str(self.root / 'etc/config') + '/\n')
        (keep_dir / 'wifi-dats').write_text(str(self.root / 'etc/wireless') + '/\n')
        (self.root / 'etc/sysupgrade.conf').touch()
        script = self.root / 'selector'
        script.write_text(SELECTOR.read_text().replace('/etc/sysupgrade.conf', str(self.root / 'etc/sysupgrade.conf'))
                          .replace('/lib/upgrade/keep.d/', str(keep_dir) + '/') + '\nlist_static_conffiles\n')
        result = subprocess.run(['busybox', 'ash', str(script)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        selected = sorted(set(str(Path(p).relative_to(self.root)) for p in result.stdout.splitlines()))
        self.assertNotIn('var/run/ax6000-mesh-operation', selected)
        self.assertNotIn('tmp/ax6000-mesh-pairing', selected)
        listing = self.root / 'archive.list'; listing.write_text('\n'.join(selected) + '\n')
        archive = self.root / 'backup.tar'
        # Ubuntu BusyBox omits -T; pass the same selected files as arguments.
        create = subprocess.run(['busybox', 'tar', 'cf', str(archive), '-C', str(self.root), *selected],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(create.returncode, 0, create.stderr)
        old = self.root / 'old-etc'; (self.root / 'etc').rename(old)
        (self.root / 'etc').mkdir()
        shutil.copytree(old / 'init.d', self.root / 'etc/init.d')
        extract = subprocess.run(['busybox', 'tar', 'xf', str(archive), '-C', str(self.root)],
                                 capture_output=True, text=True, timeout=5)
        self.assertEqual(extract.returncode, 0, extract.stderr)
        (self.root / 'proc/sys/kernel/random/boot_id').write_text('after-sysupgrade-boot\n')
        return selected

    def test_committed_upgrade_retains_all_enrolled_vendor_files_and_valid_snapshot(self):
        self.generated_configuration()
        self.assertEqual(self.call('commit').returncode, 0)
        expected = {str(p.relative_to(self.root)): p.read_bytes() for p in self.live}
        snapshot = self.root / 'etc/ax6000-mesh'
        original_names = {str(p.relative_to(self.root)) for p in snapshot.iterdir() if p.is_file()}
        selected = self.roundtrip()
        self.assertTrue(original_names.issubset(selected), 'A snapshot member was omitted from backup')
        for path, data in expected.items():
            self.assertTrue((self.root / path).exists(), path)
            self.assertEqual((self.root / path).read_bytes(), data, path)
        self.assertEqual(self.call('recover-boot').returncode, 0)
        self.assertEqual(self.call('present').returncode, 0)
        self.assertEqual(self.call('check').returncode, 0)
        self.assertEqual(json.loads(self.call('status').stdout)['state'], 'committed')

    def test_pending_upgrade_recovers_complete_original_before_network_start(self):
        self.generated_configuration()
        self.roundtrip()
        self.log.write_text('')
        self.assertEqual(self.call('recover-boot').returncode, 0)
        for path, data in self.original.items(): self.assertEqual((self.root / path).read_bytes(), data, path)
        self.assertFalse((self.root / 'etc/ax6000-mesh').exists())
        self.assertNotIn('network reload', self.log.read_text())
        self.assertNotIn('dnsmasq start', self.log.read_text())
        self.assertNotIn('restore-radios', self.log.read_text())

    def test_committed_boot_repairs_snapshot_directory_privacy_after_tar_restore(self):
        self.generated_configuration()
        self.assertEqual(self.call('commit').returncode, 0)
        self.roundtrip()
        state = self.root / 'etc/ax6000-mesh'
        # The pinned selector archives files/symlinks, not directory headers.
        state.chmod(0o755)
        self.assertEqual(self.call('recover-boot').returncode, 0)
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        self.assertEqual(json.loads(self.call('status').stdout)['state'], 'committed')


if __name__ == '__main__': unittest.main()
