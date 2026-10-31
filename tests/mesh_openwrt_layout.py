"""Sandbox target paths without hiding differences between /sbin and /usr/sbin."""
from pathlib import Path
import re

# Pinned package/network/utils/iproute2/Makefile installs ip-bridge here;
# ip-full exposes /sbin/ip. Keep /sbin/bridge absent in the sandbox.
COMMAND_PATHS = {'ip': '/sbin/ip', 'bridge': '/usr/sbin/bridge', 'uci': '/sbin/uci'}


def install_commands(root, commands):
    target = Path(root) / 'openwrt'
    for name, executable in commands.items():
        path = target / COMMAND_PATHS[name].lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(executable)
    return target


def sandbox_commands(source, target):
    # Prefix the original path, including a wrong one, so an unavailable target
    # command fails with 127 instead of resolving to a host networking utility.
    return re.sub(r'/(?:usr/)?sbin/(?:ip|bridge|uci)\b',
                  lambda match: str(target) + match[0], source)
