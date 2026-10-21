"""Matching native ImageBuilder export. No target binaries are executed here.

The exported bank is immutable and complete (including core packages). Updating
ASU packages means adding a separately authenticated immutable feed, never
reindexing or silently replacing this native bank.
"""
import argparse
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile

from publish import read_control
import package_format
import host_apk_bundle

FORMAT = 1
REPOSITORIES = 'src imagebuilder file:packages\noption check_signature\n'
FROZEN_MARKER = '# AX6000 immutable native package bank; never regenerate its signed index.\n'
APK_REPOSITORIES = '# Native signed packages.adb is passed explicitly by ImageBuilder.\n'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def enabled(profile):
    asu = profile.get('asu', {})
    require(isinstance(asu, dict), 'asu must be an object')
    return asu.get('enabled') is True


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def record(path, root):
    require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(Path(root).resolve()),
            'ImageBuilder evidence must be a regular file inside its root: ' + str(path))
    return {'path': path.relative_to(root).as_posix(), 'size': path.stat().st_size, 'sha256': sha256(path)}


def safe_extract(archive, destination):
    """Accept standard internal symlinks/hardlinks, reject escapes and alias writes."""
    archive, destination = Path(archive), Path(destination)
    require(not destination.exists(), 'ImageBuilder destination already exists')
    with tempfile.TemporaryDirectory(prefix='imagebuilder-unpack-', dir=destination.parent) as tmp:
        unpacked = archive
        if archive.name.endswith('.zst'):
            unpacked = Path(tmp) / 'archive.tar'
            with unpacked.open('wb') as stream:
                subprocess.run(['zstd', '-d', '-c', '--', str(archive)], stdout=stream, check=True)
        with tarfile.open(unpacked, 'r:*') as tar:
            members = tar.getmembers()
            require(0 < len(members) <= 200000, 'invalid ImageBuilder archive member count')
            require(sum(m.size for m in members if m.isfile()) <= 16 * 1024**3,
                    'ImageBuilder archive expands beyond limit')
            paths, roots = {}, set()
            for member in members:
                path = PurePosixPath(member.name)
                require(path.parts and str(path) == member.name.rstrip('/') and not path.is_absolute()
                        and '..' not in path.parts, 'unsafe ImageBuilder archive path: ' + member.name)
                require(str(path) not in paths, 'duplicate ImageBuilder archive path: ' + member.name)
                require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                        'unsupported ImageBuilder member: ' + member.name)
                paths[str(path)] = member
                roots.add(path.parts[0])
            require(len(roots) == 1, 'ImageBuilder archive requires one root')
            for name, member in paths.items():
                path = PurePosixPath(name)
                for parent in path.parents:
                    require(str(parent) not in paths or paths[str(parent)].isdir(),
                            'ImageBuilder archive writes through non-directory: ' + name)
                if member.issym() or member.islnk():
                    require(not member.linkname.startswith('/'), 'absolute ImageBuilder archive link: ' + name)
                    linked = posixpath.join(str(path.parent), member.linkname) if member.issym() else member.linkname
                    linked = PurePosixPath(posixpath.normpath(linked))
                    require(linked.parts and linked.parts[0] == path.parts[0] and '..' not in linked.parts,
                            'ImageBuilder archive link escapes root: ' + name)
                    if member.islnk():
                        require(str(linked) in paths and paths[str(linked)].isfile(),
                                'ImageBuilder hardlink must name a regular archive member')
            require(hasattr(tarfile, 'data_filter'), 'tarfile data_filter support is required')
            destination.mkdir(parents=True)
            tar.extractall(destination, members=members, filter='data')
    root = destination / next(iter(roots))
    require((root / 'Makefile').is_file() and not (root / 'Makefile').is_symlink(), 'ImageBuilder Makefile missing')
    return root



APK_FORMAT_PACKAGES = """define FormatPackages
$(strip $(foreach pkg,$(strip $(subst ",,$(1))),
  $(eval pkg_spec:=$(firstword $(subst =, ,$(pkg))))
  $(eval pkg_name:=$(firstword $(subst @, ,$(pkg_spec))))
  $(eval pkg_tag:=$(if $(findstring @,$(pkg_spec)),@$(lastword $(subst @, ,$(pkg_spec)))))
  $(eval pkg_ver:=$(if $(findstring =,$(pkg)),=$(lastword $(subst =, ,$(pkg)))))
  $(eval pkg_abi:=$(call GetABISuffix,$(pkg_name),$(patsubst @%,%,$(pkg_tag)),$(patsubst =%,%,$(pkg_ver))))
  $(pkg_name)$(if $(and $(pkg_abi),$(filter-out %$(pkg_abi),$(pkg_name))),$(pkg_abi))$(pkg_tag)$(pkg_ver)
))
endef"""


def apk_format_packages(text):
    pattern = r'define FormatPackages\n.*?\nendef'
    matches = re.findall(pattern, text, re.S)
    require(len(matches) == 1, 'unrecognized native ImageBuilder APK FormatPackages')
    original = matches[0]
    require('$(eval pkg_name:=$(firstword $(subst =, ,$(pkg))))' in original
            and '$(pkg_name)$(call GetABISuffix,$(pkg_name))$(pkg_ver)' in original,
            'native ImageBuilder APK FormatPackages source changed')
    text = text.replace(original, APK_FORMAT_PACKAGES)
    query_pattern = r'define GetABISuffix\n.*?\nendef'
    queries = re.findall(query_pattern, text, re.S)
    require(len(queries) == 1 and '$(APK) query --fields tags --match provides $(1)' in queries[0],
            'native ImageBuilder APK GetABISuffix source changed')
    replacement = '''define GetABISuffix
$(strip $(eval ax6000_abi:=$(shell $(STAGING_DIR_HOST)/bin/python3 $(TOPDIR)/scripts/ax6000-ib-abi.py --name '$(1)' --tag '$(2)' --version '$(3)' -- $(APK) || echo AX6000_ABI_RESOLUTION_FAILED))$(if $(filter AX6000_ABI_RESOLUTION_FAILED,$(ax6000_abi)),$(error APK ABI resolution failed for $(1)),$(ax6000_abi)))
endef'''
    return text.replace(queries[0], replacement)


FROZEN_KEY_POLICY = '''# AX6000 fixed public trust: no ephemeral signing identities.
ifneq ($(strip $(ADD_LOCAL_KEY)),)
$(error ADD_LOCAL_KEY is forbidden for immutable AX6000 ImageBuilder)
endif
'''


FROZEN_KEY_TARGET = '''
_check_keys: FORCE
\t@test ! -e "$(BUILD_KEY)" && test ! -e "$(BUILD_KEY).ucert" && test ! -e "$(BUILD_KEY_APK_SEC)" && test ! -e "$(TOPDIR)/private-key.pem" || { echo "Private signing keys or local certificates are forbidden in AX6000 ImageBuilder" >&2; exit 1; }
ifeq ($(CONFIG_USE_APK),)
\t"$(STAGING_DIR_HOST)/bin/usign" -V -P "$(OPKG_KEYS)" -m "$(PACKAGE_DIR)/Packages" -x "$(PACKAGE_DIR)/Packages.sig"
else
\t"$(STAGING_DIR_HOST)/bin/apk" --no-network --keys-dir "$(APK_KEYS)" verify "$(PACKAGE_DIR)/packages.adb"
endif

image:
'''


def verify_key_lifecycle(text):
    require(text.startswith(FROZEN_KEY_POLICY), "ImageBuilder fixed public key policy missing")
    matches = re.findall(r"\n_check_keys: FORCE\n.*?\nimage:\n", text, re.S)
    require(matches == [FROZEN_KEY_TARGET] and "$(SCRIPT_DIR)/opkg-key add" not in text
            and "cp $(BUILD_KEY_APK_PUB)" not in text, "ImageBuilder may generate or inject ephemeral signing keys")


def freeze_key_lifecycle(text):
    """Remove all key/certificate generation and rootfs key injection hooks."""
    pattern = r'\n_check_keys: FORCE\n.*?\nimage:\n'
    matches = re.findall(pattern, text, re.S)
    require(len(matches) == 1 and 'Generate local signing keys' in matches[0]
            and '$(BUILD_KEY).ucert' in matches[0] and 'ecparam -name prime256v1' in matches[0],
            'unrecognized native ImageBuilder signing key lifecycle')
    replacement = FROZEN_KEY_TARGET
    text = text.replace(matches[0], replacement)
    pattern = r'(\nprepare_rootfs: FORCE\n.*?\t\$\(CP\) \$\(TARGET_DIR\) \$\(TARGET_DIR_ORIG\)\n).*?(\n\t\$\(call prepare_rootfs,\$\(TARGET_DIR\),\$\(USER_FILES\),\$\(DISABLED_SERVICES\)\))'
    matches = list(re.finditer(pattern, text, re.S))
    require(len(matches) == 1 and '$(ADD_LOCAL_KEY)' in matches[0].group(0)
            and '$(SCRIPT_DIR)/opkg-key add $(BUILD_KEY).pub' in matches[0].group(0)
            and 'cp $(BUILD_KEY_APK_PUB)' in matches[0].group(0),
            'unrecognized native ImageBuilder rootfs signing key injection')
    match = matches[0]
    text = text[:match.start()] + match.group(1) + match.group(2) + text[match.end():]
    help_line = '\tmake image ADD_LOCAL_KEY=1 # store locally generated signing key in built images'
    require(text.count(help_line) == 1, 'unrecognized native ImageBuilder signing key help')
    text = text.replace(help_line, '\tSigning trust is fixed by the immutable AX6000 generation.')
    return FROZEN_KEY_POLICY + text



def freeze_makefile(text, package_manager="opkg"):
    require(FROZEN_MARKER not in text, 'ImageBuilder Makefile already rewritten')
    require(text.count('\npackage_index: FORCE\n') == 1 and text.count('\npackage_reload:\n') == 1
            and text.count('\npackage_list: FORCE\n') == 1, 'unrecognized native ImageBuilder package lifecycle')
    start, end = text.index('\npackage_index: FORCE\n'), text.index('\npackage_list: FORCE\n')
    frozen = ('\n' + FROZEN_MARKER + 'package_index: FORCE\n'
              '\t@echo "Refusing to regenerate immutable native package bank" >&2\n\t@false\n\n'
              'package_reload:\n\tmkdir -p $(TARGET_DIR)/tmp\n\t$(OPKG) update >&2\n')
    if package_manager == 'apk':
        text = apk_format_packages(text)
        # Re-evaluate offsets after the independently reviewed FormatPackages fix.
        start, end = text.index('\npackage_index: FORCE\n'), text.index('\npackage_list: FORCE\n')
        frozen = ('\n' + FROZEN_MARKER + 'package_index: FORCE\n'
                  '\t@echo "Refusing to regenerate immutable native package bank" >&2\n\t@false\n\n'
                  'package_reload:\n\tmkdir -p $(TARGET_DIR)/tmp\n'
                  '\t$(APK) add --arch $(ARCH_PACKAGES) --initdb\n\t$(APK) update >&2\n')
    return freeze_key_lifecycle(text[:start] + frozen + text[end:])


def native_context(source, abi):
    source = Path(source)
    version = abi.split('~', 1)[0]
    kernels = [p.parent.parent.parent for p in (source / 'build_dir').glob('target-*/linux-*/linux-*/include/config/kernel.release')
               if p.read_text().strip() == version]
    require(len(kernels) == 1, 'cannot identify exactly one native prepared ImageBuilder kernel')
    kernel = kernels[0]
    require((kernel / '.config').is_file(), 'native kernel .config missing')
    paths = [kernel / '.config', kernel.parent / 'Image', source / 'tmp/.targetinfo', source / 'tmp/.packageinfo']
    paths += sorted(p for p in (kernel / 'arch/arm64/boot/dts').rglob('*.dtb') if p.is_file())
    paths += sorted(p for p in kernel.parent.glob('*.dtb') if p.is_file())
    for images in sorted((source / 'staging_dir').glob('target-*/image')):
        paths += sorted(p for p in images.rglob('*') if p.is_file())
    policy = source / 'ax6000-apk-world-policy.json'
    if policy.exists():
        paths += [policy, source / 'scripts/ax6000-apk-world.py', source / 'include/rootfs.mk']
    require(any(p.suffix == '.dtb' for p in paths), 'native ImageBuilder DTBs missing')
    return [record(p, source) for p in paths]


def package_bank(packages, profile, apk=None):
    packages = list(packages)
    require(packages, 'empty native ImageBuilder package bank')
    result, names, filenames = [], set(), set()
    manager = package_format.manager(profile)
    suffix = 'apk' if manager == 'apk' else 'ipk'
    abi = profile['firmware']['kernel_version']
    arch = profile['firmware']['architecture']
    for path in sorted(packages, key=lambda item: (item.name, str(item))):
        require(path.is_file() and not path.is_symlink() and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+~-]*\.' + suffix, path.name),
                'unsafe native package filename')
        control = package_format.read_control(path, apk=apk) if manager == 'apk' else read_control(path)
        name = control.get('Package', '')
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*', name) and control.get('Version'), 'invalid ImageBuilder package control')
        require(name not in names and path.name not in filenames, 'duplicate native package identity')
        require(control.get('Architecture') in (arch, 'all', 'noarch'), 'foreign ImageBuilder package architecture')
        if name == 'kernel':
            require(control['Version'] == abi, 'foreign ImageBuilder kernel ABI')
        if name.startswith('kmod-'):
            depends = re.findall(r'(?:^|,)\s*kernel\s*\(\s*=\s*([^\s)]+)\s*\)', control.get('Depends', ''))
            require(depends == [abi], 'foreign ImageBuilder kmod ABI: ' + name)
        names.add(name)
        filenames.add(path.name)
        result.append({'filename': path.name, 'package': name, 'version': control['Version'],
                       'architecture': control['Architecture'], 'size': path.stat().st_size, 'sha256': sha256(path),
                       'control': control})
    core = {'kernel', 'libc', 'base-files', 'busybox'}
    if manager == 'apk':
        require('opkg' not in names and len(names & {'apk-openssl', 'apk-mbedtls'}) == 1, 'ImageBuilder native APK manager bank invalid')
    else:
        core.add('opkg')
    require(core <= names, 'ImageBuilder native core package bank incomplete')
    available = names | {x['control'].get('Base-Package', x['package']) for x in result}
    require(set(profile['packages']) <= available, 'ImageBuilder requested package bank incomplete')
    return result


def package_index(bank):
    paragraphs = []
    for item in bank:
        # Preserve all control fields including dependency/Provides/ABI metadata.
        fields = {k: v for k, v in item['control'].items() if k not in ('Filename', 'Size', 'SHA256sum')}
        fields.update({'Filename': item['filename'], 'Size': str(item['size']), 'SHA256sum': item['sha256']})
        paragraphs.append('\n'.join(k + ': ' + v for k, v in fields.items()))
    return ('\n\n'.join(paragraphs) + '\n\n').encode()


def _sign(usign, key, public_key, index):
    subprocess.run([str(usign), '-S', '-m', str(index), '-s', str(key), '-x', str(index) + '.sig'], check=True)
    subprocess.run([str(usign), '-V', '-m', str(index), '-p', str(public_key), '-x', str(index) + '.sig'], check=True)


def _identity(profile):
    value = {'build_id': profile['build_id'], 'source_commit': profile['firmware']['commit'],
            'kernel_version': profile['firmware']['kernel_version'], 'architecture': profile['firmware']['architecture'],
            'target': profile['firmware']['target'] + '/' + profile['firmware']['subtarget']}
    if package_format.manager(profile) == 'apk':
        value['package_manager'] = 'apk'
    return value


def verify_tree(tree, profile, public_key, usign, source=None, native_packages=None, *, apk=None, public_apk_key=None):
    if package_format.manager(profile) == 'apk':
        return verify_apk_tree(tree, profile, public_key, apk, public_apk_key, source, native_packages)
    tree = Path(tree)
    metadata = json.loads((tree / 'ax6000-imagebuilder.json').read_text())
    require(metadata.get('schema_version') == FORMAT and metadata.get('identity') == _identity(profile),
            'ImageBuilder generation/source/kernel identity mismatch')
    require((tree / 'repositories.conf').read_text() == REPOSITORIES, 'ImageBuilder enables moving or foreign repositories')
    require(not (tree / 'repositories').exists(), 'APK ImageBuilder is unsupported')
    config = (tree / '.config').read_text()
    require('CONFIG_USE_APK=y' not in config and 'CONFIG_IB_STANDALONE=y' in config,
            'ImageBuilder must be standalone OPKG')
    for symbol, value in [('TARGET_BOARD', profile['firmware']['target']), ('TARGET_SUBTARGET', profile['firmware']['subtarget']),
                          ('TARGET_ARCH_PACKAGES', profile['firmware']['architecture'])]:
        require(f'CONFIG_{symbol}="{value}"' in config, 'ImageBuilder target configuration mismatch: ' + symbol)
    revision = re.findall(r'^REVISION\s*:?=\s*r\d+(?:\+\d+)?-([0-9a-f]{7,40})\s*$', (tree / 'include/version.mk').read_text(), re.M)
    require(len(revision) == 1 and profile['firmware']['commit'].startswith(revision[0]), 'ImageBuilder baked source revision mismatch')
    require(FROZEN_MARKER in (tree / 'Makefile').read_text(), 'ImageBuilder mutable package lifecycle')
    verify_key_lifecycle((tree / 'Makefile').read_text())
    if source is not None:
        require((tree / 'Makefile').read_text() == freeze_makefile((Path(source) / 'target/imagebuilder/files/Makefile').read_text()),
                'ImageBuilder Makefile differs from approved native transformation')
    keys = list((tree / 'keys').iterdir())
    require(isinstance(metadata.get('native_key_fingerprint'), str)
            and re.fullmatch(r'[a-f0-9]{16}', metadata['native_key_fingerprint']), 'invalid native key fingerprint metadata')
    native_key = tree / 'keys' / metadata['native_key_fingerprint']
    require(len(keys) == 2 and all(p.is_file() and not p.is_symlink() for p in keys)
            and any(p.read_bytes() == Path(public_key).read_bytes() for p in keys),
            'ImageBuilder trusted repository public key differs')
    require(metadata['public_key_sha256'] == sha256(public_key)
            and sha256(native_key) == metadata['native_public_key_sha256'], 'ImageBuilder public key metadata differs')
    fingerprint = subprocess.check_output([str(usign), '-F', '-p', str(native_key)], text=True).strip()
    require(fingerprint == metadata['native_key_fingerprint'], 'ImageBuilder native public key fingerprint differs')
    bank = package_bank((tree / 'packages').glob('*.ipk'), profile)
    require(bank == metadata['packages'], 'ImageBuilder native package bank/index identity differs')
    index = tree / 'packages/Packages'
    require(index.read_bytes() == package_index(bank), 'ImageBuilder package index metadata differs')
    require(gzip.decompress((tree / 'packages/Packages.gz').read_bytes()) == index.read_bytes(), 'ImageBuilder compressed index differs')
    subprocess.run([str(usign), '-V', '-m', str(index), '-p', str(native_key), '-x', str(index) + '.sig'], check=True)
    if source is not None:
        require(native_key.read_bytes() == (Path(source) / 'key-build.pub').read_bytes(), 'ImageBuilder native signing key differs from source')
    if native_packages is not None:
        require(bank == package_bank(native_packages, profile), 'ImageBuilder bank differs from actual native IPKs')
    contexts = metadata['context']
    require(isinstance(contexts, list) and contexts and len({x['path'] for x in contexts}) == len(contexts), 'invalid ImageBuilder context inventory')
    for item in contexts:
        path = PurePosixPath(item['path'])
        require(not path.is_absolute() and '..' not in path.parts and str(path) == item['path'], 'unsafe ImageBuilder context path')
        require(record(tree / path, tree) == item, 'ImageBuilder native context bytes differ: ' + str(path))
        if item['path'].startswith('tmp/'):
            require((tree / path.name).is_file() and not (tree / path.name).is_symlink()
                    and sha256(tree / path.name) == item['sha256'], 'ImageBuilder active target/package metadata differs')
    if source is not None:
        require(contexts == native_context(source, profile['firmware']['kernel_version']), 'ImageBuilder differs from actual native kernel/DTB/vendor context')
    return {'schema_version': FORMAT, 'identity': metadata['identity'], 'packages': len(bank),
            'kmods': sum(x['package'].startswith('kmod-') for x in bank), 'context_files': len(contexts),
            'public_key_sha256': metadata['public_key_sha256'], 'native_make_executed': False}


def export_archive(profile, source, archive, public_key, signing_key, usign, normalizer=None, native_public_key=None, *, apk=None, public_apk_key=None):
    """Rewrite a locally produced standalone IB, then verify before atomic replace.

    normalizer may be prepare-firmware.normalize_local_sdk, to translate only its
    reviewed host-tool absolute symlinks; externally downloaded archives never
    receive that local-source exception.
    """
    require(enabled(profile), 'ImageBuilder export requires explicit ASU opt-in')
    if package_format.manager(profile) == 'apk':
        return export_apk_archive(profile, source, archive, public_key, signing_key, native_public_key, apk, public_apk_key, normalizer)
    source, archive = Path(source), Path(archive)
    native_public_key = Path(native_public_key) if native_public_key else source / 'key-build.pub'
    require(Path(signing_key).is_file() and native_public_key.is_file(), 'native ImageBuilder signing key pair missing')
    require(native_public_key.read_bytes() != Path(public_key).read_bytes(), 'native and repository signing keys must be separate')
    require(archive.is_file() and not archive.is_symlink(), 'matching ImageBuilder archive missing')
    before_sha256 = sha256(archive)
    with tempfile.TemporaryDirectory(prefix='ax6000-imagebuilder-', dir=source.parent) as tmp:
        tmp = Path(tmp)
        unpacked = archive
        if archive.name.endswith('.zst'):
            unpacked = tmp / 'native.tar'
            with unpacked.open('wb') as stream:
                subprocess.run(['zstd', '-d', '-c', '--', str(archive)], stdout=stream, check=True)
        if normalizer:
            normalized = tmp / 'normalized.tar'
            normalizer(unpacked, normalized, source)
            unpacked = normalized
        tree = safe_extract(unpacked, tmp / 'extracted')
        secret = Path(signing_key).read_bytes()
        require(secret and len(secret) <= 16384, 'invalid native signing key size')
        for path in tree.rglob('*'):
            if path.is_file() and not path.is_symlink():
                require(path.name != 'key-build' and not path.name.endswith('-private-key.pem'), 'private key path in ImageBuilder')
                if path.stat().st_size <= 16384:
                    require(path.read_bytes() != secret, 'native private key leaked into ImageBuilder')
        paths = list((source / 'bin').rglob('*.ipk'))
        bank = package_bank(paths, profile)
        # Native standalone completeness is checked before replacing the bank.
        require(package_bank((tree / 'packages').glob('*.ipk'), profile) == bank,
                'native standalone ImageBuilder omitted or changed packages')
        (tree / 'repositories.conf').write_text(REPOSITORIES)
        require(not (tree / 'repositories').exists(), 'APK ImageBuilder is unsupported')
        keys = tree / 'keys'
        if keys.exists():
            require(keys.is_dir() and not keys.is_symlink(), 'unsafe ImageBuilder keys directory')
            shutil.rmtree(keys)
        keys.mkdir()
        fingerprint = subprocess.check_output([str(usign), '-F', '-p', str(public_key)], text=True).strip()
        require(re.fullmatch(r'[a-f0-9]{16}', fingerprint), 'invalid public signing key fingerprint')
        shutil.copy2(public_key, keys / fingerprint)
        native_fingerprint = subprocess.check_output([str(usign), '-F', '-p', str(native_public_key)], text=True).strip()
        require(re.fullmatch(r'[a-f0-9]{16}', native_fingerprint) and native_fingerprint != fingerprint, 'invalid native public key fingerprint')
        shutil.copy2(native_public_key, keys / native_fingerprint)
        (tree / 'Makefile').write_text(freeze_makefile((tree / 'Makefile').read_text()))
        index = tree / 'packages/Packages'
        index.write_bytes(package_index(bank))
        (tree / 'packages/Packages.gz').write_bytes(gzip.compress(index.read_bytes(), mtime=0))
        _sign(usign, signing_key, native_public_key, index)
        metadata = {'schema_version': FORMAT, 'identity': _identity(profile), 'public_key_sha256': sha256(public_key),
                    'native_public_key_sha256': sha256(native_public_key), 'native_key_fingerprint': native_fingerprint,
                    'packages': bank, 'context': native_context(source, profile['firmware']['kernel_version'])}
        # .targetinfo/.packageinfo are relocated by the native IB Makefile.
        for item in metadata['context']:
            if item['path'].startswith('tmp/'):
                native = tree / PurePosixPath(item['path']).name
                require(record(native, tree)['sha256'] == item['sha256'], 'ImageBuilder native metadata differs')
                (tree / 'tmp').mkdir(exist_ok=True)
                shutil.copy2(native, tree / item['path'])
        (tree / 'ax6000-imagebuilder.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
        result = verify_tree(tree, profile, public_key, usign, source, paths)
        partial = archive.with_name(archive.name + '.partial')
        try:
            if archive.name.endswith('.zst'):
                with partial.open('wb') as out:
                    process = subprocess.Popen(['zstd', '-T1', '-10', '-c'], stdin=subprocess.PIPE, stdout=out)
                    try:
                        with tarfile.open(fileobj=process.stdin, mode='w|') as tar:
                            tar.add(tree, arcname=tree.name)
                    finally:
                        process.stdin.close()
                    require(process.wait() == 0, 'failed to compress exported ImageBuilder')
            else:
                mode = 'w:xz' if archive.name.endswith('.xz') else 'w:gz' if archive.name.endswith('.gz') else 'w'
                with tarfile.open(partial, mode) as tar:
                    tar.add(tree, arcname=tree.name)
            partial.replace(archive)
        finally:
            if partial.exists():
                partial.unlink()
    return {**result, 'filename': archive.name, 'sha256': sha256(archive), 'size': archive.stat().st_size,
            'native_archive_sha256': before_sha256, 'transformations': ['portable-local-host-links', 'immutable-signed-native-bank', 'fixed-local-repositories', 'native-and-production-public-keys', 'context-attestation']}


def validate_artifact(target, profile, required=True):
    """Authenticate the one native archive against the generated profile.

    Reference-only consumers may explicitly use required=False after restoring
    an authenticated native generation; importing a native RAW always requires
    its physical archive. The URL must remain that immutable generation.
    """
    target = Path(target)
    archives = sorted(p for p in target.iterdir() if 'imagebuilder' in p.name and '.tar' in p.name)
    if not enabled(profile):
        require(not archives and 'imagebuilder' not in profile, 'ImageBuilder requires explicit ASU opt-in')
        return None
    identity = profile.get('imagebuilder')
    require(isinstance(identity, dict) and set(identity) == {'url', 'sha256', 'size'}, 'ASU generation ImageBuilder identity missing')
    require(isinstance(identity['url'], str), 'invalid ImageBuilder URL')
    name = PurePosixPath(urlsplit(identity['url']).path).name
    require(re.fullmatch(r'immortalwrt-imagebuilder(?:-[A-Za-z0-9_.+-]+)?-mediatek-filogic\.Linux-x86_64\.tar\.(?:xz|gz|zst)', name),
            'unrecognized ImageBuilder archive filename')
    repository = 'valujin/ax6000-packages-6.12' if profile.get('channel') else 'valujin/ax6000-packages'
    build_id = profile.get('build_id')
    require(isinstance(build_id, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{1,180}', build_id), 'invalid ImageBuilder build ID')
    require(identity['url'] == f'https://github.com/{repository}/releases/download/firmware-{build_id}/{name}',
            'ImageBuilder URL must name its immutable generation Release')
    require(isinstance(identity['sha256'], str) and re.fullmatch(r'[a-f0-9]{64}', identity['sha256'])
            and type(identity['size']) is int and 0 < identity['size'] < 2 * 1024**3, 'invalid ImageBuilder hash/size')
    require(len(archives) <= 1 and (not archives or archives[0].name == name), 'unknown or extra ImageBuilder archive')
    if not archives:
        require(not required, 'matching ImageBuilder archive missing')
        return {'filename': name, **identity}
    archive = archives[0]
    require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size == identity['size']
            and sha256(archive) == identity['sha256'], 'ImageBuilder archive checksum/size differs from profile')
    return {'filename': name, **identity}


def verify_archive(archive, profile, public_key, usign, work, source=None, native_packages=None, *, apk=None, public_apk_key=None):
    archive = Path(archive)
    require(archive.is_file() and not archive.is_symlink(), 'ImageBuilder archive argument must be a regular file')
    if 'imagebuilder' in profile:
        selected = validate_artifact(archive.parent, profile)
        require(archive.name == selected['filename'] and archive.stat().st_size == selected['size']
                and sha256(archive) == selected['sha256'], 'ImageBuilder archive argument differs from pinned artifact')
    tree = safe_extract(archive, work)
    result = verify_tree(tree, profile, public_key, usign, source, native_packages, apk=apk, public_apk_key=public_apk_key)
    return {**result, 'filename': Path(archive).name, 'sha256': sha256(archive), 'size': Path(archive).stat().st_size}


def _apk_index_matches(bank, index, apk):
    # APK package info may use sha256-160, while mkndx uses full sha256.
    # Recompute the expected index with the trusted host tool rather than
    # confusing either internal ADB identity with the whole archive SHA256.
    with tempfile.TemporaryDirectory(prefix='ax6000-apk-index-check-') as temporary:
        expected = Path(temporary) / 'packages.adb'
        subprocess.run([str(Path(apk).resolve()), '--no-network', 'mkndx', '--allow-untrusted', '--output', str(expected)]
                       + [str((index.parent / item['filename']).resolve()) for item in bank], check=True, capture_output=True)
        actual_info = package_format.index_info(index, apk)
        expected_info = package_format.index_info(expected, apk)
        require({x['Package']: x['APK-Raw'] for x in actual_info} == {x['Package']: x['APK-Raw'] for x in expected_info},
                'ImageBuilder APK signed index differs from actual native package content')



def _verify_apk_context(tree, metadata, profile, source):
    contexts = metadata['context']
    require(isinstance(contexts, list) and contexts and len({x['path'] for x in contexts}) == len(contexts), 'invalid ImageBuilder context inventory')
    for item in contexts:
        path = PurePosixPath(item['path'])
        require(not path.is_absolute() and '..' not in path.parts and str(path) == item['path'], 'unsafe ImageBuilder context path')
        require(record(tree / path, tree) == item, 'ImageBuilder native context bytes differ: ' + str(path))
        if item['path'].startswith('tmp/'):
            require((tree / path.name).is_file() and not (tree / path.name).is_symlink()
                    and sha256(tree / path.name) == item['sha256'], 'ImageBuilder active target/package metadata differs')
    if source is not None:
        require(contexts == native_context(source, profile['firmware']['kernel_version']), 'ImageBuilder differs from actual native kernel/DTB/vendor context')
    return contexts


def verify_apk_tree(tree, profile, public_key, apk, public_apk_key, source=None, native_packages=None):
    require(apk is not None and public_apk_key is not None, 'trusted host apk and production APK public key are required')
    tree = Path(tree)
    metadata = json.loads((tree / 'ax6000-imagebuilder.json').read_text())
    require(metadata.get('schema_version') == FORMAT and metadata.get('identity') == _identity(profile),
            'ImageBuilder generation/source/kernel/package-manager identity mismatch')
    bundle = metadata.get('host_apk')
    host_apk_bundle.verify(tree, bundle)
    require(metadata.get('native_host_apk_sha256') == bundle['native_source']['sha256'],
            'ImageBuilder native host APK source provenance differs')
    if source is not None:
        original = Path(source) / 'staging_dir/host/bin/apk'
        require(original.is_file() and not original.is_symlink() and sha256(original) == bundle['native_source']['sha256']
                and original.stat().st_size == bundle['native_source']['size'],
                'ImageBuilder unbundled native host APK differs from actual build source')
        independently_described = host_apk_bundle.describe(tree, original, Path(source) / 'scripts/bundle-libraries.sh',
            stripper=Path(source) / 'staging_dir/host/bin/sstrip')
        require(independently_described == bundle, 'ImageBuilder portable host APK transformation differs from native source')
    require((tree / 'repositories').read_text() == APK_REPOSITORIES and not (tree / 'repositories.conf').exists(),
            'APK ImageBuilder enables moving, foreign, or OPKG repositories')
    config = (tree / '.config').read_text()
    require('CONFIG_USE_APK=y' in config and 'CONFIG_IB_STANDALONE=y' in config
            and 'CONFIG_SIGNATURE_CHECK=y' in config, 'ImageBuilder must be standalone signed APK')
    for symbol, value in [('TARGET_BOARD', profile['firmware']['target']), ('TARGET_SUBTARGET', profile['firmware']['subtarget']),
                          ('TARGET_ARCH_PACKAGES', profile['firmware']['architecture'])]:
        require(f'CONFIG_{symbol}="{value}"' in config, 'ImageBuilder target configuration mismatch: ' + symbol)
    version = (tree / 'include/version.mk').read_text()
    revision = re.findall(r'^REVISION\s*:?=\s*r\d+(?:\+\d+)?-([0-9a-f]{7,40})\s*$', version, re.M)
    require(len(revision) == 1 and profile['firmware']['commit'].startswith(revision[0]), 'ImageBuilder baked source revision mismatch')
    require(FROZEN_MARKER in (tree / 'Makefile').read_text(), 'ImageBuilder mutable package lifecycle')
    verify_key_lifecycle((tree / 'Makefile').read_text())
    require('--repository $(PACKAGE_DIR)/packages.adb' in (tree / 'Makefile').read_text(), 'ImageBuilder APK native bank is not selected')
    helper_records = metadata.get('host_helpers')
    require(isinstance(helper_records, list) and {x['path'] for x in helper_records} == {'scripts/ax6000-ib-abi.py', 'scripts/package_format.py'},
            'ImageBuilder APK ABI host helper inventory missing')
    for item in helper_records:
        require(record(tree / item['path'], tree) == item, 'ImageBuilder APK ABI host helper bytes differ')
        if source is not None:
            require(item['sha256'] == sha256(Path(__file__).with_name(PurePosixPath(item['path']).name)),
                    'ImageBuilder APK ABI host helper differs from reviewed recipe')
    if source is not None:
        require((tree / 'Makefile').read_text() == freeze_makefile((Path(source) / 'target/imagebuilder/files/Makefile').read_text(), 'apk'),
                'ImageBuilder APK Makefile differs from approved native transformation')
    keys = tree / 'keys'
    expected_keys = {'ax6000-native.pem', 'ax6000-repository.pem'}
    require({x.name for x in keys.iterdir()} == expected_keys and all(x.is_file() and not x.is_symlink() for x in keys.iterdir()),
            'ImageBuilder APK trusted key set differs')
    native_key, production_key = keys / 'ax6000-native.pem', keys / 'ax6000-repository.pem'
    require(profile.get('apk_key_sha256') == sha256(public_apk_key), 'ImageBuilder production APK key differs from profile')
    require(production_key.read_bytes() == Path(public_apk_key).read_bytes()
            and metadata['apk_public_key_sha256'] == sha256(public_apk_key)
            and metadata['native_apk_public_key_sha256'] == sha256(native_key), 'ImageBuilder APK public key metadata differs')
    require(metadata['public_key_sha256'] == sha256(public_key), 'ImageBuilder production catalog key metadata differs')
    for key in (native_key, production_key):
        subprocess.run(['openssl', 'pkey', '-pubin', '-in', str(key), '-noout'], check=True, capture_output=True)
    if source is not None:
        require(native_key.read_bytes() == (Path(source) / 'public-key.pem').read_bytes(), 'ImageBuilder native APK public key differs from source')
    bank = package_bank((tree / 'packages').glob('*.apk'), profile, apk=apk)
    require(not list((tree / 'packages').glob('*.ipk')), 'APK ImageBuilder contains an OPKG bank')
    require(bank == metadata['packages'], 'ImageBuilder native APK bank/index identity differs')
    index = tree / 'packages/packages.adb'
    require(record(index, tree) == metadata['apk_index'], 'ImageBuilder signed APK index hash differs')
    subprocess.run([str(Path(apk).resolve()), '--no-network', '--keys-dir', str(keys), 'verify', str(index)], check=True, capture_output=True)
    _apk_index_matches(bank, index, apk)
    if native_packages is not None:
        require(bank == package_bank(native_packages, profile, apk=apk), 'ImageBuilder bank differs from actual native APKs')
    contexts = _verify_apk_context(tree, metadata, profile, source)
    return {'schema_version': FORMAT, 'identity': metadata['identity'], 'packages': len(bank),
            'kmods': sum(x['package'].startswith('kmod-') for x in bank), 'context_files': len(contexts),
            'public_key_sha256': metadata['public_key_sha256'], 'apk_public_key_sha256': metadata['apk_public_key_sha256'],
            'host_apk': bundle, 'native_host_apk_sha256': metadata['native_host_apk_sha256'],
            'native_make_executed': False}


def _pack_imagebuilder(tree, archive):
    partial = archive.with_name(archive.name + '.partial')
    try:
        if archive.name.endswith('.zst'):
            with partial.open('wb') as out:
                process = subprocess.Popen(['zstd', '-T1', '-10', '-c'], stdin=subprocess.PIPE, stdout=out)
                try:
                    with tarfile.open(fileobj=process.stdin, mode='w|') as tar:
                        tar.add(tree, arcname=tree.name)
                finally:
                    process.stdin.close()
                require(process.wait() == 0, 'failed to compress exported ImageBuilder')
        else:
            mode = 'w:xz' if archive.name.endswith('.xz') else 'w:gz' if archive.name.endswith('.gz') else 'w'
            with tarfile.open(partial, mode) as tar:
                tar.add(tree, arcname=tree.name)
        partial.replace(archive)
    finally:
        if partial.exists():
            partial.unlink()


def export_apk_archive(profile, source, archive, public_key, signing_key, native_public_key, apk, public_apk_key, normalizer):
    require(apk is not None and public_apk_key is not None, 'trusted host apk and production APK public key are required')
    source, archive = Path(source), Path(archive)
    signing_key = Path(signing_key)
    native_public_key = Path(native_public_key) if native_public_key else source / 'public-key.pem'
    require(archive.is_file() and not archive.is_symlink(), 'matching ImageBuilder archive missing')
    require(signing_key.is_file() and not signing_key.is_symlink() and native_public_key.is_file(), 'native APK signing key pair missing')
    require(native_public_key.read_bytes() != Path(public_apk_key).read_bytes(), 'native and repository APK signing keys must be separate')
    before_sha256 = sha256(archive)
    with tempfile.TemporaryDirectory(prefix='ax6000-apk-imagebuilder-', dir=source.parent) as temporary:
        temporary = Path(temporary)
        unpacked = archive
        if archive.name.endswith('.zst'):
            unpacked = temporary / 'native.tar'
            with unpacked.open('wb') as stream:
                subprocess.run(['zstd', '-d', '-c', '--', str(archive)], stdout=stream, check=True)
        if normalizer:
            normalized = temporary / 'normalized.tar'
            normalizer(unpacked, normalized, source)
            unpacked = normalized
        tree = safe_extract(unpacked, temporary / 'extracted')
        secret = signing_key.read_bytes()
        require(secret and len(secret) <= 16384, 'invalid native APK signing key size')
        for path in tree.rglob('*'):
            if path.is_file() and not path.is_symlink():
                require(path.name not in ('private-key.pem', 'local-private-key.pem', 'key-build'), 'private key path in ImageBuilder')
                if path.stat().st_size <= 16384:
                    require(secret not in path.read_bytes(), 'native private key leaked into ImageBuilder')
        policy = source / 'ax6000-apk-world-policy.json'
        require(policy.is_file() and not policy.is_symlink(), 'native APK world policy missing')
        shutil.copy2(policy, tree / policy.name)
        native_packages = list((source / 'bin').rglob('*.apk'))
        bank = package_bank(native_packages, profile, apk=apk)
        require(not list((tree / 'packages').glob('*.ipk')), 'APK ImageBuilder contains an OPKG bank')
        require(package_bank((tree / 'packages').glob('*.apk'), profile, apk=apk) == bank,
                'native standalone ImageBuilder omitted or changed APKs')
        require(not (tree / 'repositories.conf').exists(), 'APK ImageBuilder contains OPKG repositories')
        (tree / 'repositories').write_text(APK_REPOSITORIES)
        keys = tree / 'keys'
        if keys.exists():
            require(keys.is_dir() and not keys.is_symlink(), 'unsafe ImageBuilder keys directory')
            shutil.rmtree(keys)
        keys.mkdir()
        shutil.copy2(public_apk_key, keys / 'ax6000-repository.pem')
        shutil.copy2(native_public_key, keys / 'ax6000-native.pem')
        (tree / 'Makefile').write_text(freeze_makefile((tree / 'Makefile').read_text(), 'apk'))
        helpers = []
        for name in ('ax6000-ib-abi.py', 'package_format.py'):
            origin = Path(__file__).with_name(name)
            target = tree / 'scripts' / name
            target.parent.mkdir(exist_ok=True)
            shutil.copy2(origin, target)
            helpers.append(record(target, tree))
        index = tree / 'packages/packages.adb'
        subprocess.run([str(Path(apk).resolve()), '--no-network', '--keys-dir', str(keys), 'mkndx', '--allow-untrusted',
                        '--sign', str(signing_key.resolve()), '--output', str(index)]
                       + [str((tree / 'packages' / item['filename']).resolve()) for item in bank], check=True, capture_output=True)
        bundle = host_apk_bundle.describe(tree, apk, source / 'scripts/bundle-libraries.sh',
                                          stripper=source / 'staging_dir/host/bin/sstrip')
        metadata = {'schema_version': FORMAT, 'identity': _identity(profile), 'public_key_sha256': sha256(public_key),
                    'host_apk': bundle, 'native_host_apk_sha256': sha256(apk),
                    'apk_public_key_sha256': sha256(public_apk_key), 'native_apk_public_key_sha256': sha256(native_public_key),
                    'apk_index': record(index, tree), 'packages': bank, 'host_helpers': helpers,
                    'context': native_context(source, profile['firmware']['kernel_version'])}
        for item in metadata['context']:
            if item['path'].startswith('tmp/'):
                native = tree / PurePosixPath(item['path']).name
                require(record(native, tree)['sha256'] == item['sha256'], 'ImageBuilder native metadata differs')
                (tree / 'tmp').mkdir(exist_ok=True)
                shutil.copy2(native, tree / item['path'])
        (tree / 'ax6000-imagebuilder.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
        result = verify_apk_tree(tree, profile, public_key, apk, public_apk_key, source, native_packages)
        _pack_imagebuilder(tree, archive)
    return {**result, 'filename': archive.name, 'sha256': sha256(archive), 'size': archive.stat().st_size,
            'native_archive_sha256': before_sha256, 'transformations': ['portable-local-host-links', 'immutable-native-signed-ADB-bank',
                'fixed-local-APK-repositories', 'native-and-production-APK-public-keys', 'context-attestation']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--usign', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--apk', type=Path)
    parser.add_argument('--public-apk-key', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify_archive(args.archive, json.loads(args.profile.read_text()), args.public_key,
                                        args.usign, args.work, args.source, apk=args.apk, public_apk_key=args.public_apk_key), indent=2))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'imagebuilder: ' + str(error) + '\n')
