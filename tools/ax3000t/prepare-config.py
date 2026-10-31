#!/usr/bin/env python3
"""Write a reviewable AX3000T config to a NEW output path; never modifies source."""
import argparse
import hashlib
import json
from pathlib import Path
import re

STOCK = 'CONFIG_TARGET_DEVICE_mediatek_filogic_DEVICE_xiaomi_mi-router-ax3000t'
VENDOR = ('CONFIG_MTK_', 'CONFIG_CONNINFRA_', 'CONFIG_FPGA_', 'CONFIG_WARP_', 'CONFIG_WED_', 'CONFIG_first_card', 'CONFIG_second_card', 'CONFIG_third_card')
MESH_FLAGS = ('CONFIG_MTK_MAP_SUPPORT', 'CONFIG_MTK_MAP_R2_VER_SUPPORT', 'CONFIG_MTK_MAP_R3_VER_SUPPORT', 'CONFIG_MTK_MAP_R2_6E_SUPPORT', 'CONFIG_MTK_MAP_R3_6E_SUPPORT', 'CONFIG_MTK_DFS_SLAVE_SUPPORT')

def parse(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'(CONFIG_\w[\w+-]*)=(.*)', line)
        unset = re.fullmatch(r'# (CONFIG_\w[\w+-]*) is not set', line)
        if match:
            result[match[1]] = match[2]
        elif unset:
            result[unset[1]] = 'n'
    return result

def prepare(base, donor):
    for key, expected in {'CONFIG_MTK_CHIP_MT7981':'y', 'CONFIG_MTK_FIRST_IF_MT7981':'y', 'CONFIG_WARP_CHIPSET':'"mt7981"'}.items():
        if donor.get(key) != expected:
            raise ValueError('Unexpected MT7981 donor: ' + key)
    out = dict(base)
    for key, value in list(out.items()):
        if key.startswith('CONFIG_TARGET_DEVICE_'):
            if '_PACKAGES_' in key:
                del out[key]
            else:
                out[key] = 'n'
        if key.startswith(VENDOR):
            if value in ('y', 'm', 'n'):
                out[key] = 'n'
            else:
                del out[key]
        if key.startswith('CONFIG_PACKAGE_') and not key.startswith('CONFIG_PACKAGE_kmod-') and value == 'm':
            out[key] = 'n'
    for key, value in donor.items():
        if key.startswith(VENDOR):
            out[key] = value
    for key in MESH_FLAGS:
        out[key] = base.get(key, 'n')
    out[STOCK] = 'y'
    out['CONFIG_TARGET_DEVICE_PACKAGES_mediatek_filogic_DEVICE_xiaomi_mi-router-ax3000t'] = '""'
    for key in ('CONFIG_IB', 'CONFIG_SDK', 'CONFIG_ALL_KMODS', 'CONFIG_ALL', 'CONFIG_ALL_NONSHARED', 'CONFIG_PACKAGE_tailscale', 'CONFIG_PACKAGE_luci-app-attendedsysupgrade', 'CONFIG_PACKAGE_luci-app-tailscale-community', 'CONFIG_PACKAGE_u-boot-mt7986_xiaomi_redmi-router-ax6000'):
        out[key] = 'n'
    out['CONFIG_TARGET_ROOTFS_INITRAMFS'] = 'y'
    return out

def render(config):
    return ''.join(f'# {k} is not set\n' if v == 'n' else f'{k}={v}\n' for k,v in sorted(config.items()))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    baseline = args.source / '.config'
    donor = args.source / 'defconfig/mt7981-ax3000.config'
    if args.output.exists() or args.report.exists():
        parser.error('Output and report must both be new paths')
    before = parse(baseline.read_text())
    after = prepare(before, parse(donor.read_text()))
    report = {
        'source':str(args.source.resolve()),
        'baseline_sha256':hashlib.sha256(baseline.read_bytes()).hexdigest(),
        'donor_sha256':hashlib.sha256(donor.read_bytes()).hexdigest(),
        'changes': {k:{'before':before.get(k), 'after':after.get(k)} for k in sorted(before.keys() | after.keys()) if before.get(k) != after.get(k)},
        'kernel_policy':'All CONFIG_KERNEL_* and PACKAGE_kmod-* selections preserved to retain warm kernel configuration. ALL_KMODS disabled; explicit m kmods remain.',
        'next_step':'Review config, install into isolated source, then make defconfig; compare resulting actual kernel config and ABI before reuse.',
    }
    with args.output.open('x') as handle:
        handle.write(render(after))
    with args.report.open('x') as handle:
        json.dump(report, handle, indent=2); handle.write('\n')

if __name__ == '__main__':
    main()
