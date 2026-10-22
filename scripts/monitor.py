#!/usr/bin/env python3
"""Resolve compatible feeds, official Tailscale and opt-in stable author PBR."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def fetch(url):
    request = urllib.request.Request(url, headers={'User-Agent':'ax6000-packages/1'})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError('Source response too large')
    return data


def tailscale_artifact(manifest, checksum):
    version = manifest.get('TarballsVersion', '')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid stable Tailscale version')
    filename = f'tailscale_{version}_arm64.tgz'
    if manifest.get('Tarballs', {}).get('arm64') != filename:
        raise ValueError('Unexpected official ARM64 archive name')
    digest = checksum.strip().split()[0] if checksum.strip() else ''
    if not re.fullmatch(r'[a-fA-F0-9]{64}', digest):
        raise ValueError('Invalid Tailscale SHA256')
    return {'version':version, 'artifact':'static',
            'url':'https://pkgs.tailscale.com/stable/' + filename, 'sha256':digest.lower()}


def resolve_tailscale_source(version):
    spec = importlib.util.spec_from_file_location('_ax6000_tailscale_source', ROOT / 'scripts/tailscale_source.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.resolve(version)


def resolve_feed(feed):
    url = feed['url']
    if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?', url):
        raise ValueError('Feeds must use unambiguous official GitHub HTTPS URLs')
    ref = feed.get('monitor_ref')
    if not ref:
        pin = feed['commit']
    else:
        if not re.fullmatch(r'refs/(?:heads|tags)/[A-Za-z0-9_./-]+', ref) or '..' in ref:
            raise ValueError('Invalid monitored feed ref')
        result = subprocess.run(['git','ls-remote','--exit-code',url,ref],
                                text=True, capture_output=True, check=True, timeout=60)
        lines = result.stdout.strip().splitlines()
        if len(lines) != 1:
            raise ValueError(f'Feed ref must resolve once: {ref}')
        pin = lines[0].split()[0]
    if not re.fullmatch(r'[a-fA-F0-9]{40}', pin):
        raise ValueError('Feed must resolve to full commit SHA')
    return feed['name'], pin.lower()


def recipe_digest():
    digest = hashlib.sha256()
    files = sorted([*ROOT.glob('scripts/*.py'), *ROOT.glob('scripts/*.sh'),
                    *ROOT.glob('.github/workflows/*.yml'),
                    *(path for path in (ROOT / 'files/asu-client').rglob('*') if path.is_file())])
    for path in files:
        digest.update(path.relative_to(ROOT).as_posix().encode() + b'\0')
        digest.update(path.read_bytes() + b'\0')
    return digest.hexdigest()


def changed(previous, current):
    return previous != current


def resolve_author_pbr(profile, feeds):
    spec = importlib.util.spec_from_file_location('_ax6000_pbr_sources', ROOT / 'scripts/pbr_sources.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.resolve(profile, feeds)


def resolve(profile_path, pinned_feeds=False):
    profile = json.loads(profile_path.read_text())
    if profile.get('schema_version') != 1:
        raise ValueError('Unsupported profile schema')
    manifest = json.loads(fetch('https://pkgs.tailscale.com/stable/?mode=json'))
    version = manifest.get('TarballsVersion', '')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid Tailscale release manifest')
    if pinned_feeds:
        # Native source patches and translation bytes must use the same reviewed
        # pins. Resolve PBR only after these pins are fixed, never reset afterwards.
        feeds = dict(resolve_feed(dict(feed, monitor_ref=None)) for feed in profile['feeds'])
    else:
        with ThreadPoolExecutor(max_workers=4) as pool:
            feeds = dict(pool.map(resolve_feed, profile['feeds']))
    result = {'schema_version':1, 'profile_id':profile['id'],
            'profile_sha256':hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            'recipe_sha256':recipe_digest(), 'firmware':profile['firmware'],
            'sdk':profile['sdk'], 'feeds':feeds,
            'tailscale':resolve_tailscale_source(version)}
    manager = profile.get('package_manager', 'opkg')
    if manager not in ('opkg', 'apk'):
        raise ValueError('Unsupported package manager')
    if manager == 'apk':
        key_hash = profile.get('apk_key_sha256')
        if not isinstance(key_hash, str) or not re.fullmatch(r'[a-f0-9]{64}', key_hash):
            raise ValueError('APK profile requires a pinned public key SHA256')
        result.update(package_manager='apk', apk_key_sha256=key_hash)
    if profile.get('pbr_source') is not None:
        result['pbr'] = resolve_author_pbr(profile, feeds)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--previous', type=Path)
    parser.add_argument('--pinned-feeds', action='store_true', help='Use reviewed native feed commits before resolving package sources')
    args = parser.parse_args()
    lock = resolve(args.profile, pinned_feeds=args.pinned_feeds)
    previous = json.loads(args.previous.read_text()) if args.previous else None
    updated = changed(previous, lock)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(lock, indent=2, sort_keys=True) + '\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
            out.write(f'changed={str(updated).lower()}\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write(f"Resolved Tailscale **{lock['tailscale']['version']}** (full-feature source multicall + pinned Go/UPX). "
                          f'Source inputs changed: **{updated}**.\n\n')
            for name, pin in lock['feeds'].items():
                summary.write(f'- `{name}`: `{pin}`\n')
            if 'pbr' in lock:
                summary.write(f"- Author PBR/LuCI stable pair: **{lock['pbr']['version']}-r{lock['pbr']['release']}**\n")
    print(json.dumps({'changed':updated, 'tailscale':lock['tailscale']['version'], 'feeds':lock['feeds']}))


if __name__ == '__main__':
    main()
