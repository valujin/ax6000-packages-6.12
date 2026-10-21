"""Independently expected optional feature bytes for native image inspection.

Render from the reviewed recipe checkout and locked author source archives, not
from the potentially modified source-tree overlay or configuration assertions.
The caller reads actual SquashFS/CPIO bytes without running router programs.
"""
from pathlib import Path
import hashlib
import json
import re
import os
import resource
import subprocess
import tempfile

import asu_client
import pbr_sources
import vendor_country


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def minified_js(data, source):
    config = Path(source) / '.config'
    if not config.is_file() or not re.search(rb'^CONFIG_LUCI_JSMIN=y$', config.read_bytes(), re.M):
        return data
    root = Path(source).resolve(strict=True)
    tool = root / 'staging_dir/hostpkg/bin/jsmin'
    need(tool.is_file() and not tool.is_symlink() and tool.resolve().is_relative_to(root)
         and os.access(tool, os.X_OK), 'Trusted native LuCI minifier absent')
    header = tool.open('rb').read(20)
    need(header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\x3e\x00',
         'Native LuCI minifier must be x86_64 host ELF')
    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024**2, 8 * 1024**2))
    with tempfile.TemporaryFile() as output:
        process = subprocess.run([str(tool)], input=data, stdout=output, stderr=subprocess.DEVNULL,
                                 timeout=15, preexec_fn=limits)
        need(process.returncode == 0, 'Trusted native LuCI minifier failed')
        output.seek(0); result = output.read(8 * 1024**2 + 1)
    need(len(result) <= 8 * 1024**2, 'Native LuCI minifier output cap')
    return result


def expected(profile, lock, source=None):
    files, hashes, versions, suffixes = {}, {}, {}, {}
    asu = asu_client.policy(profile)
    if asu:
        manager = asu_client.package_manager(profile)
        identity = {'schema_version': 1, 'cohort': asu['cohort'], 'seed': asu['seed'],
                    'package_manager': manager}
        files['etc/asu-cohort.json'] = ((json.dumps(identity, sort_keys=True) + '\n').encode(), 0o644)
        files['etc/uci-defaults/99-ax6000-asu'] = ((
            "#!/bin/sh\n# Bind upgrades to this image's kernel cohort; preserve client preferences.\n"
            "uci -q set attendedsysupgrade.server=server\n"
            f"uci -q set attendedsysupgrade.server.url='{asu['server_url']}'\n"
            "uci -q commit attendedsysupgrade\nexit 0\n").encode(), 0o755)
        series = '66' if asu['cohort'] == '66' else '612'
        originals = asu_client._originals(series)
        files['www/luci-static/resources/view/attendedsysupgrade/overview.js'] = (
            asu_client.patch_overview(originals['overview.js']), 0o644)
        files['www/luci-static/resources/view/status/include/11_upgrades.js'] = (
            asu_client.patch_status(originals['status.js']), 0o644)
        module = Path(asu_client.__file__).resolve().parents[1] / 'files/asu-client/ax6000_asu.js'
        need(module.is_file() and not module.is_symlink(), 'Trusted ASU client module absent')
        files['www/luci-static/resources/ax6000_asu.js'] = (module.read_bytes(), 0o644)
        files['usr/share/rpcd/acl.d/luci-app-attendedsysupgrade.json'] = (asu_client._acl(originals['acl.json']), 0o644)
        files['etc/uci-defaults/50-attendedsysupgrade'] = (
            originals['common.defaults'].replace(b'https://sysupgrade.kyarucloud.moe', asu['server_url'].encode()), 0o644)
        versions['attendedsysupgrade-common'] = ('9' if series == '66' else '10') + '-r' + asu_client.common_release(profile)
        versions['luci-app-attendedsysupgrade'] = asu_client.APP_VERSION + '-r' + asu_client.release(profile)
        # Presence and native-control equality are checked even though LMO is
        # a compiled translation, not a byte-for-byte PO source copy.
        suffixes['luci-i18n-attendedsysupgrade-ru'] = ''
    if profile.get('vendor_country_db'):
        series = '66' if profile['firmware']['commit'].startswith('ec9ef10') else '612'
        hashes['usr/share/luci-app-mtwifi-cfg/wireless-mtk.js'] = vendor_country.POSTIMAGES[series][0]
        versions['luci-app-mtwifi-cfg'] = '1-r' + (vendor_country.RELEASES[series] if hasattr(vendor_country, 'RELEASES') else vendor_country.RELEASE)
    pair = pbr_sources.validate(profile, lock)
    if pair:
        for name in pbr_sources.PACKAGES:
            versions[name] = f"{pair['version']}-r{pair['release']}"
        for language in pair.get('translations', {}):
            versions['luci-i18n-pbr-' + language] = pair['translation_version']
        need(source is not None, 'PBR image verification requires the locked author archive cache')
        archives = {}
        for name, meta in pair['packages'].items():
            path = pbr_sources.cached_archive_path(Path(source), name, meta)
            need(path.is_file() and not path.is_symlink(), 'Locked PBR author archive cache absent')
            archives[name] = pbr_sources.read_archive(name, meta, pair, path.read_bytes())
        pbr_sources.verify_compatibility(archives)
        pbr = archives['pbr']
        selected = ['etc/init.d/pbr', 'etc/config/pbr', 'etc/uci-defaults/90-pbr',
                    'usr/share/pbr/.keep', 'usr/share/pbr/pbr.user.dnsprefetch',
                    'usr/share/pbr/pbr.user.aws.uc', 'usr/share/pbr/pbr.user.netflix.uc']
        selected += ['lib/pbr/' + name + '.uc' for name in
                     ('pbr', 'pkg', 'cli', 'sys', 'validators', 'output', 'config', 'platform', 'network', 'nft')]
        for path in selected:
            need('files/' + path in pbr, 'Locked PBR archive omits reviewed runtime file: ' + path)
            data = pbr['files/' + path]
            if path == 'lib/pbr/pkg.uc':
                before = b"\tversion: 'dev-test',"
                need(data.count(before) == 1, 'Locked PBR version substitution anchor differs')
                data = data.replace(before, ("\tversion: '" + pair['version'] + '-r' + str(pair['release']) + "',").encode(), 1)
            mode = 0o755 if path in ('etc/init.d/pbr', 'etc/uci-defaults/90-pbr') else (0o600 if path == 'etc/config/pbr' else 0o644)
            files[path] = (data, mode)
        for path, data in archives['luci-app-pbr'].items():
            if path.startswith('root/'):
                files[path[5:]] = (data, 0o644)
            elif path.startswith('htdocs/'):
                files['www/' + path[7:]] = (minified_js(data, source) if path.endswith('.js') else data, 0o644)
    return {'files': files, 'hashes': hashes, 'versions': versions, 'version_suffixes': suffixes}


def verify(profile, lock, installed, read_file, check_mode, source=None, native_translations=None):
    policy = expected(profile, lock, source)
    for name, version in policy['versions'].items():
        need(name in installed and installed[name].get('Version') == version,
             'Actual image optional feature package version differs: ' + name)
    for name, suffix in policy['version_suffixes'].items():
        need(name in installed and installed[name].get('Version', '').endswith(suffix),
             'Actual image ASU package absent or release differs: ' + name)
    verified = {}
    for path, (data, mode) in policy['files'].items():
        actual = read_file(path, max(4096, len(data)))
        need(actual == data, 'Actual image optional feature bytes differ: ' + path)
        check_mode(path, mode)
        verified[path] = {'sha256': sha(actual), 'size': len(actual)}
        if mode is not None:
            verified[path]['mode'] = f'{mode:04o}'
    for path, digest in policy['hashes'].items():
        actual = read_file(path, 2 * 1024**2)
        need(sha(actual) == digest, 'Actual image vendor DB country JavaScript differs: ' + path)
        check_mode(path, 0o644)
        verified[path] = {'sha256': digest, 'size': len(actual), 'mode': '0644'}
    translations = []
    if profile.get('asu'):
        translations.append('usr/lib/lua/luci/i18n/attendedsysupgrade.ru.lmo')
    pair = lock.get('pbr') if profile.get('pbr_source') else None
    if pair:
        translations += ['usr/lib/lua/luci/i18n/pbr.' + language.replace('_', '-') + '.lmo'
                         for language in pair.get('translations', {})]
    for path in translations:
        data = read_file(path, 2 * 1024**2)
        need(data and len(data) >= 16, 'Actual image Russian translation absent or empty: ' + path)
        if native_translations is not None:
            need(native_translations.get(path) == data, 'Actual image translation differs from native package: ' + path)
        check_mode(path, 0o644)
        verified[path] = {'sha256': sha(data), 'size': len(data)}
    return {'files': verified, 'packages': {name: installed[name]['Version'] for name in
            sorted(set(policy['versions']) | set(policy['version_suffixes']))},
            'package_manager': profile.get('package_manager', 'opkg')}
