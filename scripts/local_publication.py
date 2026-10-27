#!/usr/bin/env python3
"""Bind genuine local native/SDK verification to a signing-only handoff.

This records local-server execution. It does not assert a GitHub producer run,
repeat native compilation, or execute any SDK program in the signing phase.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTEXTS = {'.config', '.config.set', '.vermagic', 'Module.symvers', 'modules.builtin.modinfo',
            'include/config/kernel.release', 'include/generated/autoconf.h'}
INPUTS = {'raw.tar.zst', 'raw.tar.zst.sha256', 'native-verification.json', 'sdk-acceptance.json'}
REQUIRED = {'wapp', 'mapd', '1905daemon', 'libmapd', 'ax6000-mesh', 'luci-app-ax6000-mesh', 'tailscale'}
CAP = 8 * 1024**3


def need(ok, message):
    if not ok:
        raise ValueError(message)


def module(name):
    spec = importlib.util.spec_from_file_location('_local_' + name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def regular(path, cap=CAP):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and not any(p.is_symlink() for p in path.parents),
         'Local publication input must be regular: ' + path.name)
    need(0 < path.stat().st_size <= cap, 'Local publication input size differs: ' + path.name)
    return path


def sha(path):
    with regular(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'Duplicate local publication JSON key')
            result[key] = value
        return result
    return json.loads(regular(path, 8 * 1024**2).read_bytes(), object_pairs_hook=unique)


def write(path, value):
    path = Path(path)
    need(not path.exists() and not path.is_symlink(), 'Evidence destination already exists')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def identity(raw):
    return {name + '_sha256': sha(Path(raw) / filename) for name, filename in
            (('profile', 'profile.json'), ('lock', 'lock.json'), ('manifest', 'firmware-manifest.json'))}


def validate_native(profile, manifest, native):
    expected = {'schema_version': 1, 'ok': True, 'channel': profile['channel'],
                'build_id': profile['build_id'], 'source_commit': profile['firmware']['commit'],
                'kernel_abi': profile['firmware']['kernel_version'], 'package_manager': 'apk'}
    need(native.get('ok') is True and type(native.get('schema_version')) is int
         and all(native.get(k) == v for k, v in expected.items()), 'Local native verification identity/result differs')
    need(profile.get('channel') == 'recommended' and profile.get('package_manager') == 'apk'
         and profile.get('exclude_asu') is True and profile.get('mediatek_mesh') is True and 'asu' not in profile,
         'Local publication requires reviewed recommended Mesh APK firmware without ASU')
    need(isinstance(native.get('stock_factory'), dict) and native['stock_factory'].get('ok') is True,
         'Local native stock factory verification absent')
    context = native.get('sdk_context', {})
    need(context.get('sdk_sha256') == profile['sdk']['sha256']
         and set(context.get('matching_contexts', {})) == CONTEXTS, 'Local native SDK context differs')
    for record in context['matching_contexts'].values():
        need(isinstance(record, dict) and set(record) == {'sha256', 'size'}
             and re.fullmatch('[a-f0-9]{64}', record.get('sha256', ''))
             and type(record.get('size')) is int and 0 < record['size'] <= 4 * 1024**2,
             'Local native kernel context record differs')
    images = {PurePosixPath(entry['path']).name: entry for entry in manifest['files']}
    need(set(native.get('layouts', {})) == {'stock', 'mtkuboot', 'ubootmod'}, 'Local native image layout inventory differs')
    for layout in native['layouts'].values():
        record = images.get(layout.get('image'))
        need(record is not None and record['sha256'] == layout.get('image_sha256')
             and record['size'] == layout.get('image_size'), 'Local native image bytes differ')


def metadata(raw, producer, producer_commit):
    need(re.fullmatch('[a-f0-9]{40}', producer_commit or ''), 'Full local producer commit required')
    actual = subprocess.check_output(['git', '-C', str(producer), 'rev-parse', 'HEAD'], text=True).strip()
    need(actual == producer_commit, 'Local producer checkout differs')
    need(not subprocess.check_output(['git', '-C', str(producer), 'status', '--porcelain', '--untracked-files=no']),
         'Local producer checkout has tracked changes')
    return module('import-release').validate_metadata(Path(raw), Path(producer) / 'profiles/redmi-ax6000-612-recommended-new.json',
                                                     expected_producer_commit=producer_commit)


def accept_sdk(raw, producer, producer_commit, native_path, sdk, sdk_raw, sdk_archive, apk, output):
    import prepare
    raw, sdk, sdk_raw = map(Path, (raw, sdk, sdk_raw))
    values = metadata(raw, producer, producer_commit)
    profile, manifest = values['profile'], values['manifest']
    native = read(native_path)
    validate_native(profile, manifest, native)
    need(sha(sdk_archive) == profile['sdk']['sha256'], 'Local SDK input archive checksum differs')
    prepare.check_sdk_identity(profile, sdk)
    prepare.check_kernel(profile, sdk)
    import mediatek_mesh
    mediatek_mesh.verify(profile, sdk)
    context = native['sdk_context']
    relative = PurePosixPath(context['kernel_relative_path'])
    need(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe local SDK kernel path')
    for name, expected in context['matching_contexts'].items():
        path = regular(sdk / relative / name, 4 * 1024**2)
        need(expected == {'sha256': sha(path), 'size': path.stat().st_size}, 'Local SDK compilation changed native kernel context: ' + name)
    baseline_hash = sha(sdk / 'ax6000-baseline/manifest.json')
    need(baseline_hash == context['apk_baseline']['manifest_sha256'], 'Local SDK changed native frozen-bank manifest')
    baseline = prepare.baseline_packages(profile, sdk)
    protected = prepare.baseline_protected_packages(profile, sdk)
    required = set(profile['packages']) - protected - {name for name in baseline if name.startswith('kmod-')}
    need(REQUIRED <= required, 'Local SDK required Mesh package closure differs')
    compiled = {}
    for path in (sdk / 'bin').rglob('*.apk'):
        control = prepare.read_package_control(regular(path), apk=apk)
        name = control['Package']
        need(name not in compiled, 'Duplicate compiled local SDK package')
        compiled[name] = {'version': control['Version'], 'sha256': sha(path), 'size': path.stat().st_size}
    need(required | {'kmod-amneziawg'} <= compiled.keys(), 'Local SDK omits compiled requested packages: ' + ', '.join(sorted(required - compiled.keys())))
    need((sdk_raw / 'profile.json').read_bytes() == (raw / 'profile.json').read_bytes(), 'Local SDK export changed generated profile')
    exported = {}
    for path in (sdk_raw / 'bin').rglob('*.apk'):
        control = prepare.read_package_control(regular(path), apk=apk)
        name = control['Package']
        need(name not in exported, 'Duplicate exported local SDK package')
        exported[name] = sha(path)
    for name in required | {'kmod-amneziawg'}:
        need(exported.get(name) == compiled[name]['sha256'], 'Local SDK export package bytes differ: ' + name)
    proof = {'schema_version': 1, 'execution': 'local-server', 'ok': True, 'producer_commit': producer_commit,
             'build_id': profile['build_id'], 'sdk_sha256': profile['sdk']['sha256'],
             'kernel_context': context['matching_contexts'], 'baseline_manifest_sha256': baseline_hash,
             'compiled_requested_packages': sorted(required),
             'compiled_packages': {name: compiled[name] for name in sorted(required | {'kmod-amneziawg'})},
             'compiled_amneziawg': True, 'native_verification_sha256': sha(native_path), **identity(raw)}
    write(output, proof)
    return proof


def handoff(profile, manifest, inputs):
    need(set(inputs) == INPUTS, 'Local publication input inventory differs')
    return {'schema_version': 1, 'execution': 'local-server', 'producer_commit': manifest['recipe_commit'],
            'build_id': profile['build_id'], 'sdk_sha256': profile['sdk']['sha256'],
            'files': {name: {'sha256': sha(path), 'size': regular(path).stat().st_size} for name, path in sorted(inputs.items())}}


def validate_files(directory, receipt):
    need(receipt.get('schema_version') == 1 and receipt.get('execution') == 'local-server', 'Require truthful local-server provenance')
    need(re.fullmatch('[a-f0-9]{40}', receipt.get('producer_commit', '')), 'Full local producer commit required')
    need(set(receipt.get('files', {})) == INPUTS, 'Local publication input inventory differs')
    for name, expected in receipt['files'].items():
        path = regular(Path(directory) / name)
        need(expected == {'sha256': sha(path), 'size': path.stat().st_size}, 'Local publication input checksum/size differs: ' + name)


def validate_sdk(profile, native, sdk_proof, raw, native_path, producer_commit):
    expected_proof = {'schema_version': 1, 'execution': 'local-server', 'ok': True, 'producer_commit': producer_commit,
                      'build_id': profile['build_id'], 'sdk_sha256': profile['sdk']['sha256'],
                      'compiled_amneziawg': True, 'native_verification_sha256': sha(native_path),
                      'kernel_context': native['sdk_context']['matching_contexts'],
                      'baseline_manifest_sha256': native['sdk_context']['apk_baseline']['manifest_sha256'], **identity(raw)}
    need(sdk_proof.get('ok') is True and sdk_proof.get('compiled_amneziawg') is True
         and type(sdk_proof.get('schema_version')) is int
         and all(sdk_proof.get(k) == v for k, v in expected_proof.items()),
         'Local SDK acceptance belongs to different native input')
    requested = set(sdk_proof.get('compiled_requested_packages', []))
    need(REQUIRED <= requested and requested <= set(profile['packages']), 'Local SDK requested Mesh package evidence differs')
    need(requested | {'kmod-amneziawg'} == set(sdk_proof.get('compiled_packages', {})), 'Local SDK compiled package evidence incomplete')
    for record in sdk_proof['compiled_packages'].values():
        need(isinstance(record, dict) and set(record) == {'version', 'sha256', 'size'}
             and isinstance(record.get('version'), str) and bool(record['version'])
             and re.fullmatch('[a-f0-9]{64}', record.get('sha256', ''))
             and type(record.get('size')) is int and 0 < record['size'] <= 128 * 1024**2,
             'Local SDK compiled package record differs')


def verify(directory, producer, producer_commit, manifest_sha, output):
    directory, output = Path(directory), Path(output)
    receipt_path = directory / 'local-publication.json'
    need(re.fullmatch('[a-f0-9]{64}', manifest_sha or '') and sha(receipt_path) == manifest_sha,
         'Local publication handoff checksum differs')
    receipt = read(receipt_path)
    validate_files(directory, receipt)
    need(receipt['producer_commit'] == producer_commit, 'Local handoff producer commit differs')
    expected = Path(producer) / 'profiles/redmi-ax6000-612-recommended-new.json'
    module('import-release').import_bundle(directory / 'raw.tar.zst', directory / 'raw.tar.zst.sha256', output, expected,
                                          expected_producer_commit=producer_commit)
    values = metadata(output, producer, producer_commit)
    profile, manifest = values['profile'], values['manifest']
    need(receipt['build_id'] == profile['build_id'] and receipt['sdk_sha256'] == profile['sdk']['sha256'], 'Local handoff firmware/SDK identity differs')
    native, sdk_proof = read(directory / 'native-verification.json'), read(directory / 'sdk-acceptance.json')
    validate_native(profile, manifest, native)
    validate_sdk(profile, native, sdk_proof, output, directory / 'native-verification.json', producer_commit)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    accept = sub.add_parser('accept-sdk')
    for name in ('raw', 'producer', 'producer-commit', 'native', 'sdk', 'sdk-raw', 'sdk-archive', 'apk', 'output'):
        accept.add_argument('--' + name, required=True)
    stage = sub.add_parser('stage')
    for name in ('raw', 'producer', 'producer-commit', 'native', 'sdk-proof', 'archive', 'checksum', 'output'):
        stage.add_argument('--' + name, required=True)
    check = sub.add_parser('verify')
    for name in ('input', 'producer', 'producer-commit', 'manifest-sha256', 'output'):
        check.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if args.command == 'accept-sdk':
        accept_sdk(args.raw, args.producer, args.producer_commit, args.native, args.sdk, args.sdk_raw, args.sdk_archive, args.apk, args.output)
    elif args.command == 'stage':
        values = metadata(args.raw, args.producer, args.producer_commit)
        validate_native(values['profile'], values['manifest'], read(args.native))
        destination = Path(args.output)
        need(not destination.exists(), 'Use a fresh local publication staging directory')
        destination.mkdir(parents=True)
        inputs = {'raw.tar.zst': args.archive, 'raw.tar.zst.sha256': args.checksum,
                  'native-verification.json': args.native, 'sdk-acceptance.json': args.sdk_proof}
        for name, path in inputs.items():
            shutil.copyfile(regular(path), destination / name)
        receipt = handoff(values['profile'], values['manifest'], {name: destination / name for name in INPUTS})
        write(destination / 'local-publication.json', receipt)
        # Validate the exact transported archive and both genuine receipts before upload.
        import tempfile
        with tempfile.TemporaryDirectory(prefix='local-generation-stage-') as temporary:
            verify(destination, args.producer, args.producer_commit, sha(destination / 'local-publication.json'), Path(temporary) / 'raw')
        print(json.dumps({'manifest_sha256': sha(destination / 'local-publication.json'), 'producer_commit': args.producer_commit}))
    else:
        verify(args.input, args.producer, args.producer_commit, args.manifest_sha256, args.output)
        print(json.dumps({'ok': True, 'execution': 'local-server', 'producer_commit': args.producer_commit}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print('local-publication: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
