#!/usr/bin/env python3
"""Manual real-SDK Tailscale package acceptance; never sign, install or publish."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile

import package_format as formats
import tailscale_source as source

ALIASES = {name: 'tailscale.multicall' for name in ('usr/sbin/tailscale', 'usr/sbin/tailscaled')}
BINARY = 'usr/sbin/tailscale.multicall'
WRAPPERS = {'etc/init.d/tailscale': 'tailscale.init', 'etc/config/tailscale': 'tailscale.conf'}
CONFFILES = {'apk': ['/etc/config/tailscale', '/etc/tailscale/'], 'opkg': ['/etc/config/tailscale']}
REFERENCES = {
    'apk': {
        'url': 'https://valujin.github.io/ax6000-packages-6.12/channels/recommended/feeds/redmi-ax6000-612-recommended/6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1/tailscale-1.104.2-r2.apk',
        'sha256': '021bfd0cc9e453004d7d359c1690d01d871c1fa5047f1fe14a229923c61e3898', 'size': 36830795,
        'provenance': {'snapshot_manifest_sha256': 'abe8541e34b2d302497ec38bbc39e040d96fe0f10c67684c6094c5f80cb25212',
                       'https_readback_files_sha256': '6ace8a0b7dceef5fa71eb6d816ad4f9c5273c50b4110ea2441b4fa4bf999f90b'}},
    'opkg': {
        'url': 'https://valujin.github.io/ax6000-packages/feeds/redmi-ax6000/6.6.133~6ea4b96ad26e951cc0b4fa9296a521d3-r1/tailscale_1.104.2-r2_aarch64_cortex-a53.ipk',
        'sha256': '66fec5f0e2cf4eab5d45bb73f94b1f067ec555ea8ab1aece9bb14c984b80c224', 'size': 36887351,
        'provenance': {'snapshot_manifest_sha256': '145f6926552a1deed5589a9df4a884e03000f94c5149d3cd18102cc74d157d6b',
                       'deployed_catalog_sha256': '90f17c130bd35acda7e2c16dc53e300e7560e8a66ef78fffb0ad22059bd4f595'}}}


def need(value, message):
    if not value: raise ValueError(message)


def record(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'Expected a regular file: ' + str(path))
    with path.open('rb') as stream: checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'sha256': checksum, 'size': path.stat().st_size}


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def tar_data(path, member):
    with tarfile.open(path, 'r:*') as outer:
        matches = [m for m in outer if m.name.removeprefix('./') == member]
        need(len(matches) == 1 and matches[0].isfile() and matches[0].size <= 256 * 1024**2,
             'Missing/oversized package archive member')
        return outer.extractfile(matches[0]).read()


def package_payload(path, apk):
    """Inventory real archive entries without executing any package script."""
    files = formats.payload_files(path, apk=apk)
    inventory = {}
    if Path(path).suffix == '.ipk':
        with tarfile.open(fileobj=io.BytesIO(tar_data(path, 'data.tar.gz')), mode='r:gz') as payload:
            for item in payload:
                name = item.name.removeprefix('./').rstrip('/')
                if item.isdir(): continue
                need(name not in inventory and not PurePosixPath(name).is_absolute()
                     and '..' not in PurePosixPath(name).parts, 'Invalid IPK payload identity')
                need(item.isfile() or item.issym(), 'Unexpected IPK special payload')
                inventory[name] = {'type': 'symlink' if item.issym() else 'file', 'mode': item.mode & 0o7777}
                if item.issym(): inventory[name]['target'] = item.linkname
        with tarfile.open(fileobj=io.BytesIO(tar_data(path, 'control.tar.gz')), mode='r:gz') as control:
            matches = [m for m in control if m.name.removeprefix('./') == 'conffiles']
            need(len(matches) == 1 and matches[0].isfile() and matches[0].size < 4096, 'IPK conffiles missing')
            conffiles = control.extractfile(matches[0]).read().decode().splitlines()
    else:
        metadata = formats.apk_json(path, apk)
        for directory in metadata['paths']:
            for item in directory.get('files', []):
                name = '/'.join(filter(None, (directory.get('name', ''), item['name'])))
                need(name not in inventory, 'Duplicate APK payload identity')
                inventory[name] = {'type': 'symlink' if 'target' in item else 'file', 'mode': item['acl']['mode']}
                if 'target' in item:
                    target = bytes.fromhex(item['target'])
                    need(target[:2] == b'\x00\xa0', 'Unexpected APK hardlink/special payload')
                    inventory[name]['target'] = target[2:].decode()
        conffiles = files.get('lib/apk/packages/tailscale.conffiles', b'').decode().splitlines()
    for name, data in files.items(): inventory[name].update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    return files, inventory, conffiles


def validate_payload(files, inventory, conffiles, wrappers, manager):
    expected = {BINARY, *WRAPPERS, *ALIASES}
    if manager == 'apk':
        expected |= {'lib/apk/packages/tailscale.' + tail for tail in ('list', 'conffiles', 'conffiles_static')}
    need(set(inventory) == expected, 'Unexpected package payload inventory')
    need({name: item.get('target') for name, item in inventory.items() if item['type'] == 'symlink'} == ALIASES,
         'Package aliases must be the two exact relative symlinks')
    need(set(files) == expected - ALIASES.keys(), 'Unexpected regular package payload inventory')
    need(conffiles == CONFFILES[manager], 'Package conffiles differ from unchanged native format')
    for name in WRAPPERS:
        need(files[name] == wrappers[name], 'Pinned service/config bytes changed')
    for name, mode in [(BINARY, 0o755), ('etc/init.d/tailscale', 0o755), ('etc/config/tailscale', 0o644)]:
        need(inventory[name]['mode'] == mode, 'Package executable/config mode differs')


def validate_control(control, baseline, lock, architecture):
    version = lock['version'] + '-r3'
    need((control.get('Package'), control.get('Version'), control.get('Architecture')) ==
         ('tailscale', version, architecture), 'Package identity differs from source release/target')
    for field in ('Depends', 'Provides'):
        def tokens(value):
            return {x.strip() for x in value.split(',') if x.strip()}
        expected = baseline.get(field, '').replace(baseline['Version'], version)
        need(tokens(control.get(field, '')) == tokens(expected), 'Package ' + field + ' differs from native baseline')


def validate_native_wrappers(wrappers, baseline_files, baseline_conffiles, manager):
    need(all(baseline_files.get(name) == content for name, content in wrappers.items())
         and baseline_conffiles == CONFFILES[manager],
         'Pinned service/config/conffiles differ from the actual native package')


def compile_plan(jobs):
    need(type(jobs) is int and 1 <= jobs <= 4, 'jobs must be 1..4')
    return [['make', '-j' + str(jobs), 'package/ax6000-overrides/tailscale/compile', 'V=s']]


def probe_inputs(profile, lock):
    """Change only this manual probe's selection; never rewrite a live profile."""
    derived, narrowed = copy.deepcopy(profile), copy.deepcopy(lock)
    derived.update(packages=['tailscale'], package_only=['tailscale'], all_kmods=False, luci_languages=[])
    for field in ('pbr_source', 'asu', 'vendor_country_db'): derived.pop(field, None)
    narrowed.pop('pbr', None)
    need(not narrowed.get('packages'), 'Manual probe accepts only the reviewed Tailscale override')
    narrowed['profile_sha256'] = hashlib.sha256((json.dumps(derived, indent=2, sort_keys=True) + '\n').encode()).hexdigest()
    return derived, narrowed


def validate_build_proof(proof, lock, binary):
    checksum = hashlib.sha256(binary).hexdigest()
    need(proof['lock'] == lock and proof['packed_sha256'] == checksum
         and proof['packed_size'] == len(binary) and proof['upx_test_and_exact_roundtrip'] is True
         and proof['offline_compile'] is True and proof['feature_reducing_tags'] == [],
         'Packaged ELF differs from actual source-helper Make output')
    return checksum


def kernel_and_bank(sdk):
    """Keep complete before/after bytes, including any exported functional Image."""
    manifest_path = sdk / 'ax6000-baseline/manifest.json'
    manifest = json.loads(manifest_path.read_text())
    result = {'ax6000-baseline/manifest.json': record(manifest_path)}
    for item in manifest['files']:
        relative = PurePosixPath(item['path'])
        need(not relative.is_absolute() and '..' not in relative.parts, 'Invalid native bank path')
        path = sdk / 'ax6000-baseline' / relative
        observed = record(path); need(observed['sha256'] == item['sha256'], 'Native bank archive differs')
        result[path.relative_to(sdk).as_posix()] = observed
    kernels = [p for p in (sdk / 'build_dir').glob('target-*/linux-*/linux-*') if (p / 'Makefile').is_file()]
    need(len(kernels) == 1, 'Expected one prepared native kernel')
    kernel = kernels[0]
    for name in ('.config', 'Module.symvers', 'include/config/kernel.release', 'include/generated/autoconf.h'):
        result[(kernel / name).relative_to(sdk).as_posix()] = record(kernel / name)
    # Older SDKs may bake vermagic in kernel.mk; normal check_kernel validates
    # that value. Preserve the exact source and actual role presence as well.
    result['include/kernel.mk'] = record(sdk / 'include/kernel.mk')
    for name in ('.config.set', 'modules.builtin.modinfo'):
        path = kernel / name
        if manifest.get('package_manager', 'opkg') == 'apk':
            need(path.is_file(), 'APK SDK is missing its native kernel role: ' + name)
        result[path.relative_to(sdk).as_posix()] = record(path) if path.exists() else None
    for path in (kernel / '.vermagic', kernel / 'Image', kernel.parent / 'Image', kernel / 'arch/arm64/boot/Image'):
        relative = path.relative_to(sdk).as_posix()
        result[relative] = record(path) if path.exists() else None
    return result


def load_prepare(recipe):
    sys.path.insert(0, str(recipe / 'scripts'))
    spec = importlib.util.spec_from_file_location('acceptance_prepare', recipe / 'scripts/prepare.py')
    prepare = importlib.util.module_from_spec(spec); spec.loader.exec_module(prepare)
    return prepare


def build(recipe, profile_path, lock_path, work, output, expected_sdk, jobs):
    recipe, profile_path, lock_path, work, output = map(lambda p: Path(p).resolve(), (recipe, profile_path, lock_path, work, output))
    need(not work.exists() and not output.exists(), 'Work and output must be fresh')
    original, original_lock = json.loads(profile_path.read_text()), json.loads(lock_path.read_text())
    profile, lock = original, original_lock
    source.validate(lock['tailscale'])
    need(lock['tailscale'] == json.loads((Path(__file__).parents[1] / 'tests/fixtures/tailscale-source-1.104.2.json').read_text()),
         'SDK acceptance needs the exact reviewed source lock')
    need(re.fullmatch(r'[0-9a-f]{64}', expected_sdk) and profile['sdk']['sha256'] == expected_sdk,
         'Profile SDK differs from explicit reviewed SDK anchor')
    need(profile['firmware']['architecture'] == 'aarch64_cortex-a53'
         and 'tailscale' in profile['package_only'] and 'tailscale' not in profile.get('image_packages', []),
         'Tailscale must remain a separate AX6000 userspace package')
    need(record(recipe / 'scripts/tailscale_source.py') == record(Path(__file__).with_name('tailscale_source.py')),
         'Package recipe does not use the identical reviewed source helper')
    prepare = load_prepare(recipe); prepare.validate(profile, lock)
    need(lock.get('profile_sha256') == record(profile_path)['sha256'] and lock.get('sdk') == profile['sdk']
         and lock.get('firmware') == profile['firmware'], 'Resolved input lock differs from original profile')
    profile, lock = probe_inputs(original, original_lock); prepare.validate(profile, lock)
    work.mkdir(parents=True); output.mkdir(parents=True)
    if os.environ.get('HOME') == '/out/home': Path('/out/home').mkdir(exist_ok=True)
    commands = []
    def run(argv, cwd=None, capture=False):
        commands.append(list(map(str, argv)))
        return subprocess.run(argv, cwd=cwd, check=True, text=True,
                              stdout=subprocess.PIPE if capture else None).stdout
    def download(pin, path, limit):
        run(['curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
             '--retry', '3', '--connect-timeout', '30', '--max-time', '1800', '--max-filesize', str(limit),
             '--limit-rate', '8M', '--output', str(path), '--', pin['url']])
        observed = record(path)
        need(observed['sha256'] == pin['sha256'] and ('size' not in pin or observed['size'] == pin['size']),
             'Downloaded pinned SDK/reference SHA256 or size differs')
    archive = work / 'sdk.archive'
    download(profile['sdk'], archive, 1024**3)
    extract = archive
    if profile['sdk']['url'].endswith('.zst'):
        extract = work / 'sdk.tar'
        with extract.open('wb') as stream:
            commands.append(['zstd', '-d', '-c', str(archive)])
            subprocess.run(commands[-1], stdout=stream, check=True)
    sdk = Path(prepare.extract_sdk(extract, work / 'extracted')).resolve()
    if extract != archive: extract.unlink()
    before = kernel_and_bank(sdk)
    prepare.check_kernel(original, sdk)
    prepare.baseline_packages(original, sdk)
    apk = prepare.sdk_apk(profile, sdk) if profile.get('package_manager', 'opkg') == 'apk' else None
    manager = profile.get('package_manager', 'opkg')
    reference = REFERENCES[manager]; reference_path = work / ('reference' + ('.apk' if manager == 'apk' else '.ipk'))
    download(reference, reference_path, 64 * 1024**2)
    baseline_control = formats.read_control(reference_path, apk=apk)
    need((baseline_control.get('Package'), baseline_control.get('Version'), baseline_control.get('Architecture')) ==
         ('tailscale', lock['tailscale']['version'] + '-r2', original['firmware']['architecture']),
         'Pinned comparison package differs from issued native package identity')
    baseline_files, _, baseline_conffiles = package_payload(reference_path, apk)
    prepare.configure_feeds(profile, lock, sdk)
    run(['./scripts/feeds', 'update', '-a'], sdk); prepare.verify_feeds(profile, lock, sdk)
    run(['./scripts/feeds', 'install', '-a'], sdk); prepare.apply_overrides(lock, sdk, profile)
    overlay = sdk / 'package/ax6000-overrides/tailscale'
    need((overlay / 'Makefile').read_text() == source.recipe(lock['tailscale'])
         and record(overlay / 'files/tailscale_source.py') == record(Path(__file__).with_name('tailscale_source.py')),
         'Generated native Makefile/helper differs from reviewed override')
    wrappers = {name: (overlay / 'files' / original).read_bytes() for name, original in WRAPPERS.items()}
    validate_native_wrappers(wrappers, baseline_files, baseline_conffiles, manager)
    del baseline_files
    run(['make', '-j' + str(jobs), 'defconfig'], sdk)
    prepare.check_sdk_identity(original, sdk); prepare.check_kernel(original, sdk)
    prepare.select_packages(profile, sdk); run(['make', '-j' + str(jobs), 'defconfig'], sdk)
    for _ in range(8):
        if not prepare.close_native(profile, sdk): break
        run(['make', '-j' + str(jobs), 'defconfig'], sdk)
    else: raise ValueError('Native dependency closure did not converge')
    prepare.verify_selection(profile, sdk)
    for command in compile_plan(jobs): run(command, sdk)
    prepare.check_sdk_identity(original, sdk); prepare.check_kernel(original, sdk)
    need(kernel_and_bank(sdk) == before, 'Native kernel/bank changed during userspace compilation')
    run(['make', '-j' + str(jobs), 'package/index', 'V=s'], sdk)
    exported = work / 'export'
    prepare.export_packages(profile, lock, sdk, exported, archive)
    extension = '.apk' if manager == 'apk' else '.ipk'
    matches = [(p, formats.read_control(p, apk=apk)) for p in (exported / 'bin/packages').glob('*' + extension)
               if p.name.startswith('tailscale')]
    matches = [(p, c) for p, c in matches if c.get('Package') == 'tailscale']
    need(len(matches) == 1, 'Expected one exported real Tailscale package')
    package, control = matches[0]; validate_control(control, baseline_control, lock['tailscale'], profile['firmware']['architecture'])
    files, inventory, conffiles = package_payload(package, apk)
    validate_payload(files, inventory, conffiles, wrappers, manager)
    proofs = list((sdk / 'build_dir').glob('target-*/tailscale-' + lock['tailscale']['commit'] + '/tailscale.multicall.proof.json'))
    need(len(proofs) == 1, 'Normal Make compile did not emit one shared-helper proof')
    proof = json.loads(proofs[0].read_text())
    binary_sha = validate_build_proof(proof, lock['tailscale'], files[BINARY])
    after = kernel_and_bank(sdk); need(after == before, 'Native kernel/bank changed during index/export')
    shutil.copy2(package, output / package.name)
    (output / 'tailscale.multicall').write_bytes(files[BINARY]); (output / 'tailscale.multicall').chmod(0o755)
    shutil.copy2(proofs[0], output / 'source-helper-proof.json')
    for name, path in [('profile.json', profile_path), ('lock.json', lock_path), ('source-lock.json', overlay / 'files/source-lock.json')]:
        shutil.copy2(path, output / name)
    write(output / 'probe-profile.json', profile); write(output / 'probe-lock.json', lock)
    result = {'schema_version': 1, 'kind': 'tailscale-real-sdk-package-acceptance', 'ok': True,
              'package_manager': manager, 'recipe_commit': run(['git', '-C', str(recipe), 'rev-parse', 'HEAD'], capture=True).strip(),
              'profile': record(profile_path), 'sdk': dict(profile['sdk'], **record(archive)), 'build_id': profile.get('build_id'),
              'probe_profile': record(output / 'probe-profile.json'), 'probe_lock': record(output / 'probe-lock.json'),
              'selection_derivation': {'packages': ['tailscale'], 'package_only': ['tailscale'], 'all_kmods': False,
                  'luci_languages': [], 'removed_unrelated_hooks': sorted(set(original) - set(profile)),
                  'original_profile_unchanged': True, 'kernel_guard_uses_original_profile': True},
              'reference_package': dict(reference, control=baseline_control),
              'package': dict(record(output / package.name), filename=package.name, control=control),
              'payload': inventory, 'conffiles': conffiles, 'source_helper': record(recipe / 'scripts/tailscale_source.py'),
              'packaged_elf_sha256': binary_sha, 'normal_make_configure_compile_install_export': True,
              'native_kernel_and_bank_before': before, 'native_kernel_and_bank_after': after,
              'commands': commands, 'signed_or_published': False, 'package_installed': False,
              'qemu_runtime_tested': False, 'actual_router_tested': False}
    write(output / 'package-proof.json', result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('recipe', 'profile', 'lock', 'work', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-sdk-sha256', required=True); parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args(); compile_plan(args.jobs)
    build(args.recipe, args.profile, args.lock, args.work, args.output, args.expected_sdk_sha256, args.jobs)


if __name__ == '__main__': main()
