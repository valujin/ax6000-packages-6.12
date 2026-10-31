"""AX3000T snapshot/rollback using real UCI and the reviewed board selector."""
import os
import unittest
from pathlib import Path
from test_mesh_network_materialize import UCI
from tests import test_mesh_transaction as transaction

class AX3000TRealUCI(unittest.TestCase):
    write_tool = transaction.MeshTransaction.write_tool
    call = transaction.MeshTransaction.call
    begin = transaction.MeshTransaction.begin
    # Inherit fixture mechanics only; parent tests exercise their own fixtures.
    def setUp(self):
        transaction.MeshTransaction.setUp(self)
        (self.root / 'board_name').write_text('xiaomi,mi-router-ax3000t\n')
        (self.root / 'etc/wireless/l1profile.dat').write_text('INDEX0=MT7981\nINDEX0_profile_path=/etc/wireless/mediatek/mt7981.dbdc.b0.dat;/etc/wireless/mediatek/mt7981.dbdc.b1.dat\n')
        for i in (0, 1):
            old = self.root / f'etc/wireless/mediatek/mt7986-ax6000.dbdc.b{i}.dat'
            old.rename(self.root / f'etc/wireless/mediatek/mt7981.dbdc.b{i}.dat')
        configs = {
            'network': "config interface 'lan'\n option device 'br-lan'\n option proto 'static'\n option ipaddr '192.168.1.1'\n option netmask '255.255.255.0'\nconfig device 'brlan'\n option name 'br-lan'\n option type 'bridge'\n list ports 'lan2'\n list ports 'lan3'\n list ports 'lan4'\nconfig interface 'wan'\n option device 'wan'\n option proto 'dhcp'\nconfig interface 'wan6'\n option device '@wan'\n",
            'wireless': "config wifi-device 'MT7981_1_1'\n option type 'mtwifi'\n option band '2g'\nconfig wifi-device 'MT7981_1_2'\n option type 'mtwifi'\n option band '5g'\n",
            'dhcp': "config dhcp 'lan'\n option interface 'lan'\n",
            'ax6000_mesh': "config mesh 'main'\n option enabled '0'\n option role 'controller'\n option backhaul 'wired'\n",
        }
        for name, content in configs.items(): (self.root / 'etc/config' / name).write_text(content)
        uci = self.root / 'bin/uci'
        uci.write_text(f'#!/bin/sh\nexec "{UCI}" -c "{self.root}/etc/config" -t "{self.root}/uci-delta" "$@"\n')
        uci.chmod(0o755)
        (self.root / 'uci-delta').mkdir()
        self.env['LD_LIBRARY_PATH'] = '/tmp/mesh-materialize-uci-build:' + self.env.get('LD_LIBRARY_PATH', '')

    def test_real_uci_controller_snapshot_and_rollback_mt7981_dats(self):
        paths = [self.root / f'etc/wireless/mediatek/mt7981.dbdc.b{i}.dat' for i in (0, 1)]
        original = [p.read_bytes() for p in paths]
        self.begin('controller', 'wired')
        state = self.root / 'etc/ax6000-mesh'
        for i, p in enumerate(paths):
            self.assertEqual((state / f'original-dat{i}').read_bytes(), original[i])
            p.write_text('enrollment mutation\n')
        result = self.call('rollback', 'boot')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([p.read_bytes() for p in paths], original)

class AX3000TRealEnrollment(unittest.TestCase):
    def exercise_lifecycle(self, role, backhaul):
        import json
        import subprocess
        from tests import test_mesh_runtime as runtime
        fixture = runtime.RuntimeLifecycle(methodName='runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        root = fixture.root
        (root / 'board_name').write_text('xiaomi,mi-router-ax3000t\n')
        (root / 'etc/wireless/l1profile.dat').write_text('INDEX0=MT7981\nINDEX0_profile_path=/etc/wireless/mediatek/mt7981.dbdc.b0.dat;/etc/wireless/mediatek/mt7981.dbdc.b1.dat\n')
        for i in (0, 1):
            (root / f'etc/wireless/mediatek/mt7986-ax6000.dbdc.b{i}.dat').rename(root / f'etc/wireless/mediatek/mt7981.dbdc.b{i}.dat')
        for tool in ('ubus', 'jsonfilter', 'rmmod'):
            p = root / 'bin' / tool
            p.write_text(p.read_text().replace('MT7986_', 'MT7981_').replace('mt7986-ax6000.dbdc', 'mt7981.dbdc'))
        for name in ('network', 'dhcp', 'wireless', 'ax6000_mesh'):
            path = root / 'etc/config' / name
            data = json.loads(path.read_text())
            if name == 'wireless':
                data = {k.replace('MT7986_', 'MT7981_'): (v.replace('MT7986_', 'MT7981_') if isinstance(v, str) else v) for k, v in data.items()}
            lines = []
            for key, value in data.items():
                if '.' not in key:
                    lines.append(f"config {value} '{key}'")
                    for opt, val in data.items():
                        if opt.startswith(key + '.'):
                            for item in val if isinstance(val, list) else [val]:
                                lines.append(f" {'list' if isinstance(val, list) else 'option'} {opt[len(key)+1:]} '{item}'")
            path.write_text('\n'.join(lines) + '\n')
        uci = root / 'bin/uci'
        uci.write_text(f'#!/bin/sh\nexec "{UCI}" -c "{root}/etc/config" -t "{root}/uci-delta" "$@"\n')
        uci.chmod(0o755)
        (root / 'uci-delta').mkdir()
        fixture.env['LD_LIBRARY_PATH'] = '/tmp/mesh-materialize-uci-build:' + fixture.env.get('LD_LIBRARY_PATH', '')
        for key, value in [('role', role), ('backhaul', backhaul)]:
            subprocess.run([str(uci), 'set', f'ax6000_mesh.main.{key}={value}'], env=fixture.env, check=True, capture_output=True)
        subprocess.run([str(uci), 'commit', 'ax6000_mesh'], env=fixture.env, check=True, capture_output=True)
        original = {name: (root / 'etc/config' / name).read_bytes() for name in ('network', 'dhcp', 'wireless')}
        dats = [root / f'etc/wireless/mediatek/mt7981.dbdc.b{i}.dat' for i in (0, 1)]
        original_dats = [p.read_bytes() for p in dats]
        result = fixture.run_control('apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / 'etc/ax6000-mesh/role').read_text().strip(), role)
        self.assertEqual((root / 'etc/ax6000-mesh/backhaul').read_text().strip(), backhaul)
        for i, expected in enumerate(original_dats):
            self.assertEqual((root / f'etc/ax6000-mesh/original-dat{i}').read_bytes(), expected)
        result = fixture.run_control('disable')
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, expected in original.items(): self.assertEqual((root / 'etc/config' / name).read_bytes(), expected)
        self.assertEqual([p.read_bytes() for p in dats], original_dats)

    def test_real_uci_controller_wired(self):
        self.exercise_lifecycle('controller', 'wired')

    def test_real_uci_agent_wired(self):
        self.exercise_lifecycle('agent', 'wired')

    def test_real_uci_agent_wireless(self):
        self.exercise_lifecycle('agent', 'wireless')
