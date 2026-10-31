import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-hardware'

class HardwareSelection(unittest.TestCase):
    def test_supported_boards_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            board = Path(tmp) / 'board'
            helper = Path(tmp) / 'hardware'
            profile = Path(tmp) / 'l1profile.dat'
            helper.write_text(HELPER.read_text().replace('/tmp/sysinfo/board_name', str(board)).replace('/etc/wireless/l1profile.dat', str(profile)))
            for name, prefix in [('xiaomi,redmi-router-ax6000-stock', 'mt7986-ax6000'), ('xiaomi,mi-router-ax3000t', 'mt7981')]:
                board.write_text(name + '\n')
                chip = 'MT7981' if prefix == 'mt7981' else 'MT7986'
                profile.write_text(f'INDEX0={chip}\nINDEX0_profile_path=/etc/wireless/mediatek/{prefix}.dbdc.b0.dat;/etc/wireless/mediatek/{prefix}.dbdc.b1.dat\n')
                for i in (0, 1):
                    p = subprocess.run(['sh', str(helper), f'dat{i}'], capture_output=True, text=True)
                    self.assertEqual(p.returncode, 0)
                    self.assertEqual(p.stdout.strip(), f'/etc/wireless/mediatek/{prefix}.dbdc.b{i}.dat')
            board.write_text('xiaomi,mi-router-ax3000t\n')
            profile.write_text('INDEX0=MT7986\nINDEX0_profile_path=/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat;/etc/wireless/mediatek/mt7986-ax6000.dbdc.b1.dat\n')
            self.assertNotEqual(subprocess.run(['sh', str(helper), 'dat0']).returncode, 0)
            board.write_text('xiaomi,mi-router-ax3000t-ubootmod\n')
            self.assertNotEqual(subprocess.run(['sh', str(helper), 'dat0']).returncode, 0)
