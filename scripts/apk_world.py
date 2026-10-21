#!/usr/bin/env python3
"""Pin the installed native core/vendor dependency closure using host APK only.

Copied unchanged into native source and ImageBuilder. No target binary or
package script executes. Public userspace additions keep their original world
constraints; only native core/vendor roots and all installed kmods are pinned.
"""
import argparse
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile

ROOTFS_SHA256 = '502ee81027a310f84345471c27c2c6d3ee212456bda6da5e1e7410f8c24d669d'
ANCHOR = '\t$(call mklibs,$(1))\n\t$(if $(SOURCE_DATE_EPOCH),'
HOOK = ('\t$(call mklibs,$(1))\n'
        '\t$(if $(CONFIG_USE_APK),$(STAGING_DIR_HOST)/bin/python3 $(TOPDIR)/scripts/ax6000-apk-world.py '
        '--root "$(1)" --apk "$(STAGING_DIR_HOST)/bin/apk" --policy "$(TOPDIR)/ax6000-apk-world-policy.json")\n'
        '\t$(if $(SOURCE_DATE_EPOCH),')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+:-]*\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+~:-]*\Z')
TOKEN = re.compile(r'(!?)([A-Za-z0-9][A-Za-z0-9_.+:-]*)(?:@([A-Za-z0-9][A-Za-z0-9_.+-]*))?([<>=~]+)?([^\s]*)\Z')
ESSENTIAL = {'kernel', 'libc', 'base-files', 'busybox'}
APK_PROVIDERS = {'apk-openssl', 'apk-mbedtls'}
VENDOR = {'kmod-mt_wifi', 'kmod-conninfra', 'kmod-warp', 'kmod-mediatek_hnat',
          'mtwifi-cfg-ucode', 'iwinfo-ucode', 'ucode-mod-iwinfo', 'ucode-mod-datconf',
          'ucode-mod-l1parser', 'wifi-dats', 'libiwinfo', 'luci-app-mtwifi-cfg'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def safe(root, relative, required=False):
    root = Path(root).absolute()
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root,
            'APK policy root is outside source or a symlink')
    relative = PurePosixPath(relative)
    require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe APK policy path')
    path = root / relative
    require(not path.is_symlink() and path.resolve().is_relative_to(root)
            and not any(parent.is_symlink() for parent in path.parents if parent != root and parent.is_relative_to(root)),
            'APK policy path is outside root or a symlink: ' + str(relative))
    require(not path.exists() or path.is_file(), 'APK policy path is not a regular file: ' + str(relative))
    require(not required or path.is_file(), 'APK policy file missing: ' + str(relative))
    return path


def write_atomic(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def configure_source(profile, source, check_only=False):
    if profile.get('package_manager', 'opkg') != 'apk': return None
    require(profile.get('channel') in {'recommended', 'latest'}, 'APK guard requires a reviewed native source cohort')
    source = Path(source).absolute()
    target = safe(source, 'include/rootfs.mk', required=True)
    helper = safe(source, 'scripts/ax6000-apk-world.py')
    original = target.read_bytes()
    if hashlib.sha256(original).hexdigest() == ROOTFS_SHA256:
        require(original.decode().count(ANCHOR) == 1, 'reviewed rootfs hook anchor differs')
        transformed = original.decode().replace(ANCHOR, HOOK).encode()
        require(not check_only, 'reviewed APK rootfs hook is missing')
    else:
        require(original.decode().count(HOOK) == 1, 'rootfs differs from reviewed APK hook')
        before = original.decode().replace(HOOK, ANCHOR).encode()
        require(hashlib.sha256(before).hexdigest() == ROOTFS_SHA256, 'rootfs differs from reviewed source preimage')
        transformed = original
    script = Path(__file__).read_bytes()
    require(not helper.exists() or helper.read_bytes() == script, 'reviewed APK world helper differs')
    require(not check_only or helper.is_file(), 'reviewed APK world helper is missing')
    if not check_only:
        write_atomic(helper, script)
        if original != transformed: write_atomic(target, transformed)
    return {'rootfs_before_sha256': ROOTFS_SHA256, 'rootfs_after_sha256': hashlib.sha256(transformed).hexdigest(),
            'helper_sha256': hashlib.sha256(script).hexdigest()}


def core_recipe_roots(metadata):
    roots = set(); recipe = None
    for line in metadata.splitlines():
        if line.startswith('Source-Makefile:'):
            recipe = line.split(':', 1)[1].strip()
            path = PurePosixPath(recipe)
            require(not path.is_absolute() and '..' not in path.parts and path.name == 'Makefile', 'unsafe core recipe metadata')
        elif line.startswith('Package:'):
            name = line.split(':', 1)[1].strip()
            require(NAME.fullmatch(name), 'invalid core recipe package name')
            if recipe and recipe.startswith('package/') and not recipe.startswith(('package/feeds/', 'package/ax6000-overrides/')):
                roots.add(name)
    return sorted(roots)


def configure_policy(profile, source, check_only=False):
    if profile.get('package_manager', 'opkg') != 'apk': return None
    metadata = safe(source, 'tmp/.packageinfo', required=True)
    roots = set(core_recipe_roots(metadata.read_text())) | ESSENTIAL | VENDOR | APK_PROVIDERS
    policy = {'schema_version': 1, 'package_manager': 'apk', 'cohort': '612-' + profile['channel'],
              'protected_roots': sorted(roots)}
    content = (json.dumps(policy, indent=2, sort_keys=True) + '\n').encode()
    path = safe(source, 'ax6000-apk-world-policy.json')
    require(not path.exists() or path.read_bytes() == content, 'APK core/vendor policy differs from source metadata')
    require(not check_only or path.is_file(), 'APK core/vendor policy missing')
    if not check_only: write_atomic(path, content)
    return policy


def trusted_apk(apk):
    apk = Path(apk).absolute()
    require(apk.is_file() and not apk.is_symlink() and os.access(apk, os.X_OK), 'trusted host APK tool unavailable')
    return apk


def unique_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate installed APK JSON field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def installed_packages(root, apk):
    database = safe(root, 'lib/apk/db/installed', required=True)
    require(0 < database.stat().st_size <= 32 * 1024**2, 'invalid installed APK database size')
    result = subprocess.check_output([str(trusted_apk(apk)), '--root', str(Path(root).absolute()),
                                      '--no-network', '--repositories-file', '/dev/null', 'query', '--installed',
                                      '--format', 'json', '--fields', 'name,version,depends,provides,tags', '*'], timeout=120)
    require(len(result) <= 32 * 1024**2, 'installed APK query output exceeds limit')
    parsed = unique_json(result)
    require(isinstance(parsed, list) and 0 < len(parsed) <= 10000, 'installed APK query must return packages')
    return parsed


def parse_token(token, *, world=False, provides=False):
    require(isinstance(token, str) and token and not re.search(r'\s', token), 'malformed APK world/dependency token')
    found = TOKEN.fullmatch(token)
    require(found is not None, 'malformed APK world/dependency token: ' + token)
    conflict, name, tag, operator, version = found.groups()
    require(not conflict or not (world or provides), 'negative APK world/provider token')
    require(not tag or world, 'tagged APK dependency/provider token')
    require(bool(operator) == bool(version), 'malformed APK world/dependency version')
    # APK legitimately stores local archive content hashes using ><Q1BASE64=.
    if world and operator == '><':
        require(re.fullmatch(r'Q[12][A-Za-z0-9+/]+={0,2}', version), 'malformed APK world content pin')
    else:
        require(operator in (None, '=', '<', '>', '<=', '>=', '~', '~='), 'unsupported APK dependency operator')
        require(not version or VERSION.fullmatch(version), 'malformed APK world/dependency version')
    require(not provides or operator in (None, '='), 'APK provider version must be exact')
    return bool(conflict), name, tag, operator, version


def protected_packages(installed, policy, apk):
    require(isinstance(policy, dict) and set(policy) == {'schema_version', 'package_manager', 'cohort', 'protected_roots'}
            and policy.get('schema_version') == 1 and policy.get('package_manager') == 'apk'
            and policy.get('cohort') in {'612-recommended', '612-latest'}, 'invalid APK core/vendor policy')
    roots = policy['protected_roots']
    require(isinstance(roots, list) and roots == sorted(set(roots)) and all(isinstance(x, str) and NAME.fullmatch(x) for x in roots),
            'invalid APK protected root names')
    packages, providers, base_names = {}, {}, {}
    for item in installed:
        require(isinstance(item, dict), 'invalid installed APK package')
        name, version = item.get('name'), item.get('version')
        require(isinstance(name, str) and NAME.fullmatch(name) and isinstance(version, str) and VERSION.fullmatch(version),
                'invalid installed APK identity')
        require(name not in packages, 'duplicate installed APK package')
        packages[name] = item
        tags = item.get('tags', [])
        require(isinstance(tags, list) and all(isinstance(x, str) for x in tags), 'invalid installed APK tags')
        abi = [x.split('=', 1)[1] for x in tags if x.startswith('openwrt:abiversion=')]
        require(len(abi) <= 1 and (not abi or (abi[0] and name.endswith(abi[0]) and len(name) > len(abi[0]))), 'APK ABI tag/name mismatch')
        base = name[:-len(abi[0])] if abi else name
        base_names.setdefault(base, set()).add(name)
        providers.setdefault(name, {})[name] = version
        for field in ('depends', 'provides'):
            tokens = item.get(field, [])
            require(isinstance(tokens, list) and all(isinstance(x, str) for x in tokens)
                    and len(tokens) == len(set(tokens)), 'invalid installed APK ' + field)
            for token in tokens:
                conflict, virtual, _, operator, offered = parse_token(token, provides=field == 'provides')
                if field == 'provides':
                    require(virtual not in providers or name not in providers[virtual] or providers[virtual][name] == offered,
                            'conflicting APK provider identity')
                    providers.setdefault(virtual, {})[name] = offered
    require(ESSENTIAL <= packages.keys(), 'installed APK root omits essential native packages')
    require(len(APK_PROVIDERS & packages.keys()) == 1, 'installed APK root requires exactly one native APK provider')
    pending = set()
    for name in roots:
        candidates = base_names.get(name, set())
        require(len(candidates) <= 1, 'ambiguous installed APK ABI root: ' + name)
        pending.update(candidates)
    pending.update(name for name in packages if name.startswith('kmod-'))
    pending.update(ESSENTIAL | (APK_PROVIDERS & packages.keys()))

    @lru_cache(maxsize=None)
    def compare(left, right):
        result = subprocess.check_output([str(trusted_apk(apk)), 'version', '-t', left, right], timeout=30).decode().strip()
        require(result in {'<', '=', '>'}, 'host APK returned invalid version comparison')
        return result

    protected = set()
    while pending:
        name = pending.pop()
        if name in protected: continue
        protected.add(name)
        for token in packages[name].get('depends', []):
            conflict, dependency, _, operator, version = parse_token(token)
            if conflict: continue
            candidates = providers.get(dependency, {})
            require(candidates, 'missing installed native dependency: ' + name + ' -> ' + dependency)
            require(len(candidates) == 1, 'ambiguous installed virtual dependency: ' + name + ' -> ' + dependency)
            provider, offered = next(iter(candidates.items()))
            if operator:
                require(offered, 'versioned native dependency has an unversioned virtual provider')
                if operator in {'~', '~='}:
                    valid = offered == version or (offered.startswith(version) and offered[len(version):len(version)+1] in {'.', '_', '-', '+'})
                else:
                    relation = compare(offered, version)
                    valid = relation in {'=': {'='}, '<': {'<'}, '>': {'>'}, '<=': {'<', '='}, '>=': {'>', '='}}[operator]
                require(valid, 'installed native dependency version mismatch: ' + name + ' -> ' + token)
            pending.add(provider)
    return {name: packages[name]['version'] for name in sorted(protected)}


def pin_root(root, apk, policy):
    root = Path(root).absolute()
    world = safe(root, 'etc/apk/world', required=True)
    protected_file = safe(root, 'etc/apk/ax6000-protected.list')
    require(world.stat().st_size <= 1024**2, 'APK world exceeds size limit')
    original = world.read_text()
    require(not original or original.endswith('\n'), 'malformed APK world newline')
    rows, seen = [], set()
    for line in original.splitlines():
        token = parse_token(line, world=True)
        require(token[1] not in seen, 'duplicate APK world package constraint')
        seen.add(token[1]); rows.append((line, token))
    installed = installed_packages(root, apk)
    pins = protected_packages(installed, policy, apk)
    protected_aliases = set()
    for item in installed:
        if item['name'] not in pins: continue
        for tag in item.get('tags', []):
            if tag.startswith('openwrt:abiversion='):
                suffix = tag.split('=', 1)[1]
                protected_aliases.add(item['name'][:-len(suffix)])
        for provided in item.get('provides', []):
            protected_aliases.add(parse_token(provided, provides=True)[1])
    protected_aliases.difference_update(pins)
    require(not any(token[1] in protected_aliases for _, token in rows),
            'APK world uses an alias for a protected native package')
    # Remove only old constraints for the actual protected package names. ABI-base
    # aliases have no authority to replace another actual installed identity.
    retained = [line for line, token in rows if token[1] not in pins]
    for name in pins:
        require(not any(token[1] == name and token[2] is not None for _, token in rows),
                'protected APK world package cannot select a public repository tag')
    output = ''.join(line + '\n' for line in retained + [name + '=' + version for name, version in pins.items()])
    protected = ''.join(name + '=' + version + '\n' for name, version in pins.items())
    if protected_file.exists():
        require(protected_file.stat().st_size <= 1024**2, 'APK protected list exceeds size limit')
        for line in protected_file.read_text().splitlines():
            found = parse_token(line, world=True)
            require(not found[2] and found[3] == '=', 'malformed existing APK protected list')
    # Every path, installed identity, dependency and world entry passes before mutation.
    write_atomic(world, output.encode())
    write_atomic(protected_file, protected.encode())
    return {'protected_packages': len(pins), 'protected_sha256': hashlib.sha256(protected.encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--apk', required=True, type=Path)
    parser.add_argument('--policy', required=True, type=Path)
    args = parser.parse_args()
    try:
        require(args.policy.is_file() and not args.policy.is_symlink() and args.policy.stat().st_size <= 1024**2,
                'invalid APK source policy file')
        pin_root(args.root, args.apk, unique_json(args.policy.read_bytes()))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'apk-world: {error}\n')


if __name__ == '__main__': main()
