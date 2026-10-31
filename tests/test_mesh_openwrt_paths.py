"""Use pinned OpenWrt installation paths, with no host networking fallback."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from mesh_openwrt_layout import COMMAND_PATHS, install_commands, sandbox_commands
from test_mesh_slot_allocation import LIB, NATIVE


class OpenWrtCommandPaths(unittest.TestCase):
    def test_pinned_ip_bridge_package_installs_only_usr_sbin(self):
        recipe = NATIVE.parents[1] / 'package/network/utils/iproute2/Makefile'
        if not recipe.exists():
            self.skipTest('Pinned native iproute2 recipe unavailable')
        block = re.search(r'define Package/ip-bridge/install\n(.*?)\nendef', recipe.read_text(), re.S)
        self.assertIsNotNone(block)
        self.assertRegex(block[1], r'\$\(INSTALL_BIN\)\s+\$\(PKG_BUILD_DIR\)/bridge/bridge\s+\$\(1\)/usr/sbin/')
        self.assertEqual(COMMAND_PATHS['bridge'], '/usr/sbin/bridge')

    def test_target_has_no_sbin_bridge_alias_and_wrong_path_returns_127(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stub = root / 'stub'
            stub.write_text('#!/bin/sh\nprintf "OPENWRT_BRIDGE\\n"\n')
            stub.chmod(0o700)
            target = install_commands(root, {'bridge': stub})
            self.assertFalse((target / 'sbin/bridge').exists())
            for path, status in [('/sbin/bridge', 127), ('/usr/sbin/bridge', 0)]:
                with self.subTest(path=path):
                    result = subprocess.run(['busybox', 'ash', '-c', sandbox_commands(path + ' -j vlan show', target)],
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, status)
                    if status == 0:
                        self.assertEqual(result.stdout, 'OPENWRT_BRIDGE\n')

    def test_runtime_contains_no_uninstalled_absolute_bridge_path(self):
        for helper in LIB.glob('ax6000-mesh-*'):
            if helper.is_file():
                with self.subTest(helper=helper.name):
                    self.assertIsNone(re.search(r'(?<![A-Za-z0-9_/])/sbin/bridge\b', helper.read_text()), helper.name)
