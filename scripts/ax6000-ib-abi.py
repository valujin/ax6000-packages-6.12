#!/usr/bin/env python3
"""Resolve an IB package's exact ABI with the trusted host APK solver.

An unqualified logical name with multiple ABI providers is rejected. ASU uses
catalog-verified actual package names, which remain unambiguous across feeds.
"""
import argparse
import json
import os
import re
import subprocess
import sys

import package_format

SENTINEL = 'AX6000_ABI_RESOLUTION_FAILED'


def resolve(command, name, tag='', version=''):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*', name):
        raise ValueError('invalid APK package name')
    if tag and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', tag):
        raise ValueError('invalid APK repository tag')
    if version and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+~:-]*', version):
        raise ValueError('invalid APK package version')
    command = list(command)
    environment = {}
    while command and '=' in command[0] and not command[0].startswith('/'):
        key, value = command.pop(0).split('=', 1)
        if key != 'IPKG_INSTROOT':
            raise ValueError('unexpected host APK environment override')
        environment[key] = value
    if not command:
        raise ValueError('host APK command missing')
    # bounded_output deliberately inherits the regular process environment.
    # IPKG_INSTROOT is needed only for install script handling, never queries.
    raw = package_format.bounded_output(command + ['query', '--all-matches', '--match', 'name,provides',
        '--format', 'json', '--fields', 'name,version,arch,tags', name], limit=4 * 1024**2)
    decoded = json.loads(raw)
    if not isinstance(decoded, list):
        raise ValueError('invalid host APK query result')
    controls = [package_format.normalize_apk_info(info) for info in decoded]
    exact = [x for x in controls if x['Package'] == name]
    candidates = exact or [x for x in controls if x['Base-Package'] == name]
    if version:
        candidates = [x for x in candidates if x['Version'] == version]
    if not candidates:
        raise ValueError('requested APK package/version is unavailable')
    actual_names = {x['Package'] for x in candidates}
    if len(actual_names) != 1:
        raise ValueError('logical APK name has ambiguous ABI providers; use the catalog actual package name')
    actual = next(iter(actual_names))
    spec = actual + ('@' + tag if tag else '') + ('=' + version if version else '')
    selected = json.loads(package_format.bounded_output(command + ['query', '--recursive', '--format', 'json',
        '--fields', 'name,version,arch,tags', spec], limit=4 * 1024**2))
    if not isinstance(selected, list):
        raise ValueError('invalid APK solver query result')
    selected = [package_format.normalize_apk_info(info) for info in selected]
    chosen = [x for x in selected if x['Package'] == actual]
    if len(chosen) != 1 or (version and chosen[0]['Version'] != version):
        raise ValueError('APK solver did not select the exact requested package/version')
    return chosen[0].get('ABIVersion', '')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--tag', default='')
    parser.add_argument('--version', default='')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    try:
        print(resolve(command, args.name, args.tag, args.version))
    except (ValueError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(SENTINEL)
        print('ImageBuilder APK ABI resolution: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
