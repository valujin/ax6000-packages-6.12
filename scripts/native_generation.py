"""Finite REC APK native generation replacement; never a supplemental exception."""
import hashlib
import json
import copy
import argparse
import importlib.util
import base64
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

SOURCE = 'ae65e1de69971b5a2e3cf7e39390ee93f274d488'
ABI = '6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1'
COHORT = '612-recommended'
MIB = 1024 ** 2
SHA = re.compile('[0-9a-f]{64}')
APP = 'luci-app-attendedsysupgrade-20261021.2-r'
SDK_ROLES = ('.config', '.config.set', '.vermagic', 'Module.symvers',
             'modules.builtin.modinfo', 'include/config/kernel.release', 'include/generated/autoconf.h')
ROOT = Path(__file__).resolve().parents[1]
KIND = 'rec-native-apk-generation-transition-v1'
OLD_PRODUCER = 'ea6de11283a6d83728e50b4b9ced214761ecc1c0'
MODULE = 'www/luci-static/resources/ax6000_asu.js'
MODULE_SHA = 'cbafbc641774f22ad1e47cbe8e1a8af80a8c1e36383c1d66d54dc40926ff23ff'
INSTALLER = 'usr/sbin/ax6000-install-feed'
CLIENT = 'feeds/luci/applications/luci-app-attendedsysupgrade/'
CHANGED = {CLIENT + 'Makefile', CLIENT + 'htdocs/luci-static/resources/ax6000_asu.js',
           'files/etc/asu-cohort.json', 'files/' + INSTALLER}
POSTIMAGES = CHANGED | {CLIENT + x for x in (
    'htdocs/luci-static/resources/view/attendedsysupgrade/overview.js',
    'htdocs/luci-static/resources/view/status/include/11_upgrades.js',
    'root/usr/share/rpcd/acl.d/luci-app-attendedsysupgrade.json')} | {
    'feeds/packages/utils/attendedsysupgrade-common/Makefile',
    'feeds/packages/utils/attendedsysupgrade-common/files/attendedsysupgrade.defaults',
    'files/etc/apk/keys/repository-apk.pem', 'files/etc/apk/repositories.d/customfeeds.list',
    'files/etc/apk/repositories.d/distfeeds.list', 'files/etc/ax6000/repository.pub',
    'files/etc/uci-defaults/99-ax6000-asu'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def module(name):
    spec = importlib.util.spec_from_file_location('native_generation_' + name, ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def validate_profiles(old, new):
    need(old.get('id') == new.get('id') == 'redmi-ax6000-' + COHORT
         and old.get('channel') == new.get('channel') == 'recommended'
         and old.get('package_manager') == new.get('package_manager') == 'apk',
         'Native replacement requires two REC APK generations')
    firmware = old.get('firmware', {})
    need(firmware.get('commit') == SOURCE and firmware.get('kernel_version') == ABI,
         'Native replacement is restricted to the enrolled REC source and ABI')
    allowed = {'build_id', 'sdk', 'imagebuilder', 'asu'}
    need({k: v for k, v in old.items() if k not in allowed}
         == {k: v for k, v in new.items() if k not in allowed},
         'Native replacement changes source, layouts, packages, key or unrelated policy')
    before, after = old.get('asu', {}), new.get('asu', {})
    need(isinstance(before, dict) and isinstance(after, dict)
         and {k: v for k, v in before.items() if k != 'seed'}
         == {k: v for k, v in after.items() if k != 'seed'}
         and before.get('enabled') is True and before.get('cohort') == COHORT
         and before.get('server_url') == 'https://asu.ezon.by/612/recommended',
         'Native replacement changes ASU policy beyond its seed')
    need(all(isinstance(x.get('seed'), str) and re.fullmatch('[0-9a-f]{64}', x['seed'])
             for x in (before, after)) and before['seed'] != after['seed'],
         'Native replacement requires distinct valid producer-bound seeds')
    for name in ('build_id', 'sdk', 'imagebuilder'):
        need(old.get(name) is not None and new.get(name) is not None
             and old[name] != new[name], 'Native replacement needs a new ' + name)
    need(old.get('package_only') == ['tailscale']
         and 'tailscale' in old.get('packages', [])
         and 'tailscale' not in old.get('image_packages', []),
         'Native replacement must retain the reviewed Tailscale package-only policy')


def regular(path, cap=2 * 1024 ** 3):
    need(isinstance(path, (str, Path)), 'Missing actual native file')
    path = Path(path)
    need(path.is_absolute() and path.as_posix() == str(path.resolve())
         and path.is_file() and not any(x.is_symlink() for x in (path, *path.parents))
         and 0 < path.stat().st_size <= cap, 'Unsafe, absent or oversized actual native file')
    return path


def identity(path):
    path = regular(path)
    with path.open('rb') as stream:
        return {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(), 'size': path.stat().st_size}


def full_ref(path):
    return {'path': str(regular(path)), **identity(path)}


def checked_ref(ref, cap=2 * 1024 ** 3):
    need(isinstance(ref, dict) and set(ref) == {'path', 'sha256', 'size'}
         and isinstance(ref['sha256'], str) and SHA.fullmatch(ref['sha256'])
         and type(ref['size']) is int and 0 < ref['size'] <= cap, 'Invalid actual native file reference')
    path = regular(ref['path'], cap)
    need(identity(path) == {k: ref[k] for k in ('sha256', 'size')}, 'Actual native file bytes changed')
    return path


def read_json(path):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, 'Duplicate native proof JSON field')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('Nonfinite native proof JSON')
    return json.loads(regular(path, 8 * MIB).read_bytes(), object_pairs_hook=unique, parse_constant=constant)


def relative(value):
    need(isinstance(value, str), 'Missing native relative path')
    path = PurePosixPath(value)
    need(value and path.as_posix() == value and not path.is_absolute()
         and '..' not in path.parts and '\\' not in value, 'Unsafe native relative path')
    return value


def json_sha(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest()


def manifest_bank(manifest):
    """Portable archive identities from an authenticated native manifest, without local paths."""
    need(isinstance(manifest.get('files'), list) and 0 < len(manifest['files']) <= 20000, 'Native manifest inventory absent')
    bank, seen = {}, set()
    for row in manifest['files']:
        need(isinstance(row, dict) and set(row) == {'path', 'sha256', 'size'}, 'Malformed native manifest record')
        name = relative(row['path'])
        need(name.startswith('bin/') and name not in seen and isinstance(row['sha256'], str)
             and SHA.fullmatch(row['sha256']) and type(row['size']) is int and 0 <= row['size'] <= 2 * 1024 ** 3,
             'Invalid native manifest path/identity')
        seen.add(name)
        if name.endswith('.apk'):
            leaf = PurePosixPath(name).name
            need(leaf not in bank and 0 < row['size'] <= 128 * MIB, 'Duplicate/oversized native APK manifest record')
            bank[leaf] = {k: row[k] for k in ('sha256', 'size')}
    need(bank, 'Native manifest lacks an APK bank')
    return bank


def native_bank(raw, manifest):
    """Read real whole APK bytes, including packages omitted from the public feed."""
    raw = Path(raw); files = manifest.get('files')
    need(isinstance(files, list) and 0 < len(files) <= 20000, 'Missing native manifest inventory')
    expected, names, total = {}, {}, 0
    for item in files:
        name = relative(item.get('path'))
        need(name.startswith('bin/') and name not in expected, 'Duplicate/outside native manifest entry')
        expected[name] = item
        if not name.endswith('.apk'):
            continue
        path = regular(raw / name, 128 * MIB); row = identity(path)
        need(row == {k: item.get(k) for k in ('sha256', 'size')}, 'Native APK differs from firmware manifest')
        total += row['size']; need(total <= 8 * 1024 ** 3, 'Native APK inventory byte cap')
        need(path.name not in names, 'Duplicate native APK basename')
        names[path.name] = row
    actual = set()
    for path in (raw / 'bin').rglob('*'):
        need(not path.is_symlink(), 'Linked native RAW inventory')
        if path.is_file() and path.suffix == '.apk':
            actual.add(path.relative_to(raw).as_posix())
    need(actual == {name for name in expected if name.endswith('.apk')} and names,
         'Extra/missing native APK inventory')
    return names


def compare_banks(before, after):
    before = dict(before); after = dict(after)
    need(APP + '2.apk' in before and APP + '3.apk' in after, 'Missing exact native APP2/APP3 archives')
    before.pop(APP + '2.apk'); after.pop(APP + '3.apk')
    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
    need(not changed, 'Unreviewed native archive changes (including core/vendor/common/translations): ' + ', '.join(changed[:20]))


def production_completion(data, producer, metadata, evidence, staging, source_context, sdk_context, profile, manifest):
    """Consume real successful process inspections; staging is never completion."""
    need(isinstance(data, dict) and set(data) == {'schema_version', 'kind', 'producer_commit',
         'source_commit', 'staging_receipt', 'native_evidence', 'raw_metadata4', 'stages', 'completed', 'phase_receipts'}
         and type(data['schema_version']) is int and data['schema_version'] == 1
         and data['kind'] == 'rec-native-producer-completion-v1'
         and data['producer_commit'] == producer and data['source_commit'] == SOURCE
         and data['staging_receipt'] == staging and data['native_evidence'] is None
         and data['raw_metadata4'] == metadata and data['completed'] is True, 'Actual native completion identity/bindings differ')
    for ref in [evidence, staging, *metadata.values()]:
        checked_ref(ref)
    stages = data['stages']; need(isinstance(stages, list) and 1 <= len(stages) <= 3, 'Actual native stages required')
    steps, ids = [], set()
    for stage in stages:
        need(isinstance(stage, dict) and set(stage) == {'steps', 'inspect'}
             and isinstance(stage['steps'], list) and stage['steps'], 'Malformed native production stage')
        inspect = read_json(checked_ref(stage['inspect'], 8 * MIB))
        if isinstance(inspect, list):
            need(len(inspect) == 1, 'Ambiguous native container inspection'); inspect = inspect[0]
        need(isinstance(inspect, dict) and re.fullmatch('[0-9a-f]{64}', inspect.get('Id', ''))
             and inspect['Id'] not in ids, 'Missing/duplicate real native producer container')
        state = inspect.get('State', {})
        need(state.get('Status') == 'exited' and state.get('Running') is False
             and state.get('OOMKilled') is False and type(state.get('ExitCode')) is int
             and state['ExitCode'] == 0, 'Native stage did not actually exit successfully')
        ids.add(inspect['Id']); steps.extend(stage['steps'])
    need(steps == ['world', 'imagebuilder', 'export'], 'Incomplete, replayed or reordered native production steps')
    phases = ('after-prepare', 'after-world', 'after-imagebuilder', 'after-export')
    need(isinstance(data['phase_receipts'], dict) and set(data['phase_receipts']) == set(phases), 'All four actual native phase receipts required')
    five = {name: source_context[name] for name in ('.config', '.vermagic', 'Module.symvers', 'include/config/kernel.release', 'KDIR/Image')}
    seven = {name: source_context[name] for name in SDK_ROLES}
    for name in phases:
        phase = read_json(checked_ref(data['phase_receipts'][name], 8 * MIB))
        need(phase.get('phase') == name and phase.get('native_context') == five
             and phase.get('source_context7') == seven
             and phase.get('source_config_sha256') == metadata['build.config']['sha256']
             and phase.get('original_source_readonly_guards_passed') is True,
             'Actual native phase/source context differs: ' + name)
        for ref in [*five.values(), *seven.values()]: checked_ref(ref)
        if name == 'after-export':
            export = phase.get('export', {})
            need(export.get('source_equals_raw_current_final_archives') is True
                 and export.get('sdk_context') == sdk_context
                 and export.get('sdk', {}).get('sha256') == profile['sdk']['sha256']
                 and export.get('imagebuilder') == {k: profile['imagebuilder'][k] for k in ('sha256', 'size')},
                 'Actual final native SDK/IB/context binding differs')
            for ref in sdk_context.values(): checked_ref(ref)
            expected = {row['path']: {k: row[k] for k in ('sha256', 'size')} for row in manifest['files']}
            actual = export.get('source_bin', {})
            sums = {'bin/targets/mediatek/filogic/' + filename for filename in ('sha256sums', 'SHA256SUMS')}
            need(set(actual) == set(expected) and all(actual[path] == row for path, row in expected.items() if path not in sums),
                 'Final full source/RAW native inventory differs')


def git_blob(recipe, commit, name):
    need(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit), 'Exact producer commit required')
    relative(name)
    args = ['/usr/bin/git', '-C', str(recipe)]
    try:
        size = int(subprocess.check_output(args + ['cat-file', '-s', commit + ':' + name], stderr=subprocess.DEVNULL))
        need(0 <= size <= 8 * MIB, 'Producer Git blob cap exceeded')
        result = subprocess.check_output(args + ['show', commit + ':' + name], stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, ValueError) as error:
        raise ValueError('Pinned producer Git blob unavailable: ' + name) from error
    need(len(result) == size, 'Producer Git blob size changed')
    return result


def producer_seed(recipe, commit, profile):
    """Replay the frozen seed formula over actual producer blobs, never publisher HEAD."""
    try:
        names = subprocess.check_output(['/usr/bin/git', '-C', str(recipe), 'ls-tree', '-rz', '--name-only', commit],
                                        stderr=subprocess.DEVNULL).decode().split('\0')
    except subprocess.CalledProcessError as error:
        raise ValueError('Pinned producer Git tree unavailable') from error
    need(len(names) <= 10000, 'Producer tree entry cap')
    selected = [name for name in names if name and (
        (PurePosixPath(name).parent.as_posix() == 'scripts' and name.endswith(('.py', '.sh')))
        or (PurePosixPath(name).parent.as_posix() == '.github/workflows' and name.endswith('.yml'))
        or name.startswith('files/asu-client/'))]
    need(selected, 'Producer recipe closure absent')
    digest = hashlib.sha256()
    for name in sorted(selected):
        digest.update(name.encode() + b'\0' + git_blob(recipe, commit, name) + b'\0')
    source = copy.deepcopy(profile)
    need(isinstance(source.get('asu'), dict), 'ASU source profile missing')
    source['asu'].pop('seed', None)
    payload = {'recipe_contract': 'ax6000-native-asu-v1', 'source_profile': source,
               'recipe_sha256': digest.hexdigest()}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def context_records(refs, expected):
    need(isinstance(refs, dict) and set(refs) == set(SDK_ROLES)
         and isinstance(expected, dict) and set(expected) == set(SDK_ROLES), 'All seven actual SDK/source contexts required')
    result = {name: identity(checked_ref(refs[name], 4 * MIB)) for name in SDK_ROLES}
    need(result == expected, 'Actual SDK/source prepared contexts differ from native verification')
    return result


def generated_profile(source, actual):
    """Exact native export transformation, without running producer Python."""
    expected = copy.deepcopy(source)
    expected['firmware']['kernel_version'] = ABI
    expected['all_kmods'] = False
    expected['feeds'].insert(0, {'name': 'base', 'url': source['firmware']['repository'],
                                'commit': SOURCE, 'root': 'package'})
    for field in ('build_id', 'sdk', 'imagebuilder'):
        expected[field] = actual[field]
    need(expected == actual, 'Generated native profile differs from its exact declared producer source profile')
    need(actual['build_id'] == actual['id'] + '-' + SOURCE[:12] + '-' + actual['sdk']['sha256'][:12],
         'Native build ID differs from source and actual SDK')


def check_baseline(ref, proof, bank):
    path = checked_ref(ref, 8 * MIB); baseline = read_json(path)
    need(isinstance(proof, dict) and proof.get('manifest_sha256') == ref['sha256']
         and proof.get('whole_native_archive_bytes_matched') is True,
         'SDK baseline is not authenticated by full native verification')
    need(baseline.get('schema_version') == 1 and baseline.get('package_manager') == 'apk'
         and baseline.get('source_commit') == SOURCE and baseline.get('kernel_version') == ABI
         and baseline.get('architecture') == 'aarch64_cortex-a53', 'SDK baseline native identity differs')
    files = baseline.get('files'); need(isinstance(files, list) and 0 < len(files) <= 10000, 'SDK baseline files absent')
    names, paths = set(), set()
    for row in files:
        need(isinstance(row, dict) and set(row) == {'package', 'version', 'path', 'sha256'}, 'Malformed SDK native bank record')
        name = row['package']; filename = PurePosixPath(relative(row['path'])).name
        need(isinstance(name, str) and name and name not in names and filename not in paths
             and filename in bank and bank[filename]['sha256'] == row['sha256'], 'SDK native bank/archive mismatch')
        names.add(name); paths.add(filename)
    frozen = baseline.get('frozen_packages'); protected = baseline.get('protected_packages')
    kmods = baseline.get('frozen_kmods')
    need(isinstance(frozen, list) and len(frozen) == len(set(frozen)) and set(frozen) == names
         and isinstance(protected, list) and len(protected) == len(set(protected)) and set(protected) <= names
         and isinstance(kmods, list) and len(kmods) == len(set(kmods))
         and set(kmods) == {name for name in names if name.startswith('kmod-')} and 'kernel' in names,
         'SDK protected/frozen native inventory differs')
    need(type(proof.get('packages')) is int and proof['packages'] == len(names)
         and type(proof.get('frozen_kmods')) is int and proof['frozen_kmods'] == len(kmods), 'Native verifier/SDK bank counts differ')
    return baseline


def sibling(path, name, expected):
    path = regular(Path(path).parent / name, 8 * MIB)
    need(identity(path)['sha256'] == expected, 'Independent IB component bytes differ: ' + name)
    return read_json(path)


def check_ib(side, profile, bank):
    ref = side['ib_approval']; path = checked_ref(ref, 8 * MIB); proof = read_json(path)
    need(proof.get('kind') == 'ax6000-imagebuilder-approval' and proof.get('approved') is True
         and proof.get('recipe_commit') == side['producer_commit'] and proof.get('source_commit') == SOURCE
         and proof.get('cohort') == COHORT and proof.get('package_manager') == 'apk'
         and proof.get('build_id') == profile['build_id'] and proof.get('kernel_version') == ABI
         and proof.get('archive_sha256') == profile['imagebuilder']['sha256']
         and proof.get('archive_size') == profile['imagebuilder']['size']
         and proof.get('profile_sha256') == side['metadata']['profile.json']['sha256']
         and proof.get('full_native_status_sha256') == side['native_status']['sha256']
         and proof.get('full_native_evidence_sha256') == side['native_evidence']['sha256'],
         'Actual independent IB approval identity differs')
    for field in ('source_context_verified', 'native_bank_verified', 'signatures_verified', 'private_keys_absent'):
        need(proof.get(field) is True, 'Incomplete independent IB approval: ' + field)
    result = sibling(path, 'verification-result.json', proof.get('verification_result_sha256'))
    expected = {'build_id': profile['build_id'], 'source_commit': SOURCE, 'kernel_version': ABI,
                'architecture': profile['firmware']['architecture'], 'target': 'mediatek/filogic', 'package_manager': 'apk'}
    need(result.get('identity') == expected and result.get('packages') == len(bank)
         and result.get('apk_public_key_sha256') == profile['apk_key_sha256'], 'Actual IB verifier result differs')
    transform = sibling(path, 'source-transform.json', proof.get('source_transform_sha256'))
    need(transform.get('producer_commit') == side['producer_commit'] and transform.get('source_commit') == SOURCE
         and transform.get('native_status_sha256') == side['native_status']['sha256']
         and transform.get('full_source_checks_retained') is True
         and transform.get('imported_raw_tool_execution') is False and transform.get('vendor_elf_execution') is False,
         'IB independent source verification scope differs')
    for name, field in [('layout-context.json', 'layout_context_sha256'),
                        ('private-key-context-scan.json', 'private_key_scan_sha256'),
                        ('apk-semantic.json', 'apk_semantic_verification_sha256')]:
        sibling(path, name, proof.get(field))
    return proof


def asset(raw, manifest, filename, expected):
    rows = [row for row in manifest['files'] if PurePosixPath(relative(row['path'])).name == filename]
    need(len(rows) == 1, 'Missing/ambiguous actual native asset: ' + filename)
    row = rows[0]; current = identity(regular(Path(raw) / row['path']))
    need(current == {k: row.get(k) for k in ('sha256', 'size')}
         and all(current[k] == value for k, value in expected.items()), 'Actual native asset differs: ' + filename)
    return current


def side_records(side):
    fields = {'raw', 'source', 'recipe', 'producer_commit', 'source_profile', 'native_status',
              'native_evidence', 'sdk_baseline', 'source_context', 'sdk_context', 'ib_approval'}
    need(isinstance(side, dict) and set(side) == fields, 'Exact actual native side inputs required')
    for name in ('raw', 'source', 'recipe'):
        path = Path(side[name])
        need(path.is_absolute() and str(path) == str(path.resolve()) and path.is_dir()
             and not any(x.is_symlink() for x in (path, *path.parents)), 'Aliased/missing native directory: ' + name)
    raw = Path(side['raw'])
    metadata = {name: full_ref(raw / name) for name in ('profile.json', 'lock.json', 'firmware-manifest.json', 'build.config')}
    profile, lock, manifest = (read_json(raw / name) for name in ('profile.json', 'lock.json', 'firmware-manifest.json'))
    evidence = read_json(checked_ref(side['native_evidence'], 8 * MIB))
    status = read_json(checked_ref(side['native_status'], 8 * MIB))
    need(status.get('kind') == 'ax6000-native-completion-acceptance-v2' and status.get('schema_version') == 2
         and status.get('ok') is True and status.get('all_layouts_verified') is True
         and status.get('strict_accepted_context_unchanged') is True, 'Actual completed native acceptance required')
    for field, value in [('producer_commit', side['producer_commit']), ('source_commit', SOURCE),
                         ('build_id', profile['build_id']), ('kernel_abi', ABI), ('seed', profile['asu']['seed'])]:
        need(status.get(field) == value, 'Native acceptance identity differs: ' + field)
    need(status.get('evidence_sha256') == side['native_evidence']['sha256']
         and status.get('native_inputs') == {name: {k: metadata[name][k] for k in ('sha256', 'size')}
                                            for name in ('profile.json', 'lock.json', 'firmware-manifest.json')},
         'Native status does not bind actual evidence and RAW metadata')
    need(manifest.get('recipe_commit') == side['producer_commit'] and manifest.get('source_commit') == SOURCE
         and manifest.get('kernel_version') == ABI and manifest.get('build_id') == profile['build_id']
         and lock.get('firmware') == profile['firmware'] and lock.get('sdk') == profile['sdk']
         and lock.get('profile_sha256') == metadata['profile.json']['sha256'], 'Native RAW generation bindings differ')
    need(evidence.get('ok') is True and evidence.get('package_manager') == 'apk'
         and evidence.get('source_commit') == SOURCE and evidence.get('kernel_abi') == ABI
         and evidence.get('build_id') == profile['build_id'] and evidence.get('channel') == 'recommended'
         and set(evidence.get('layouts', {})) == {'stock', 'mtkuboot', 'ubootmod'}, 'Actual full native verification required')
    migration = module('kernel_migration'); CONTEXT, IMAGES = migration.CONTEXT, migration.IMAGES
    contexts = {name: value for name, value in side['source_context'].items() if name != 'KDIR/Image'}
    expected = evidence.get('sdk_context', {}).get('matching_contexts')
    source_records = context_records(contexts, expected); context_records(side['sdk_context'], expected)
    need(set(side['source_context']) == set(SDK_ROLES) | {'KDIR/Image'}
         and all(source_records.get(name) == value for name, value in CONTEXT.items()), 'Enrolled native ABI context changed')
    kernel = Path(side['source']) / relative(evidence['sdk_context']['kernel_relative_path'])
    for name in SDK_ROLES:
        need(side['source_context'][name]['path'] == str(kernel / name), 'Actual source context path differs')
    image = identity(checked_ref(side['source_context']['KDIR/Image'], 64 * MIB))
    need(side['source_context']['KDIR/Image']['path'] == str(kernel.parent / 'Image')
         and image == IMAGES['after'] and image == {k: evidence.get('sysupgrade_input', {}).get(k) for k in ('sha256', 'size')},
         'Whole accepted functional native Image changed')
    for layout in evidence['layouts'].values():
        need({k: layout['kernel'].get(k) for k in ('sha256', 'size')} == image, 'Actual layout kernel differs')
        asset(raw, manifest, layout['image'], {'sha256': layout['image_sha256'], 'size': layout['image_size']})
    factory = evidence.get('stock_factory')
    need(isinstance(factory, dict) and factory.get('ok') is True and factory.get('package_only_absent') == ['tailscale'],
         'Verified stock factory/Tailscale proof required')
    for suffix, identity_name in [('-stock-initramfs-factory.ubi', 'factory_ubi'), ('-stock-initramfs-kernel.bin', 'ram_fit')]:
        names = [PurePosixPath(row['path']).name for row in manifest['files'] if row['path'].endswith(suffix)]
        need(len(names) == 1, 'Actual stock factory asset required'); asset(raw, manifest, names[0], factory[identity_name])
    for name in ('sdk', 'imagebuilder'):
        filename = profile[name]['url'].rsplit('/', 1)[-1]
        asset(raw, manifest, filename, {k: profile[name][k] for k in ('sha256', 'size') if k in profile[name]})
    need(evidence['sdk_context'].get('sdk_sha256') == profile['sdk']['sha256'], 'Full native SDK verification differs')
    bank = native_bank(raw, manifest)
    baseline = check_baseline(side['sdk_baseline'], evidence['sdk_context'].get('apk_baseline'), bank)
    bound = {**side, 'metadata': metadata}
    check_ib(bound, profile, bank)
    source_profile = read_json(checked_ref(side['source_profile'], 8 * MIB))
    expected_profile = git_blob(side['recipe'], side['producer_commit'], 'profiles/redmi-ax6000-612-recommended-new.json')
    need(regular(side['source_profile']['path']).read_bytes() == expected_profile
         and source_profile['asu'] == profile['asu']
         and producer_seed(side['recipe'], side['producer_commit'], source_profile) == profile['asu']['seed'],
         'Native seed/source profile is not bound to its actual producer')
    generated_profile(source_profile, profile)
    return {'profile': profile, 'manifest': manifest, 'metadata': metadata, 'evidence': evidence,
            'bank': bank, 'baseline': baseline, 'context': source_records, 'image': image}


def staged_source(data, before, after):
    """Authenticate copy history and read actual source postimages; this grants no native acceptance."""
    need(data.get('kind') == 'ax6000-rec-genuine-warm-fork-preparation-v2'
         and data.get('execute') is True and data.get('stage_complete') is True
         and data.get('source_commit') == SOURCE and data.get('source') == before['source']
         and data.get('destination') == after['source'] and data.get('old_recipe_commit') == OLD_PRODUCER
         and data.get('producer_commit') == after['producer_commit']
         and data.get('source_profile') == after['source_profile']
         and all(data.get(name, False) is None for name in ('native_build', 'native_verification', 'router_execution')),
         'Actual independent native source staging required')
    binding = read_json(checked_ref(data.get('input_binding'), 8 * MIB))
    images = read_json(checked_ref(data.get('postimages'), 8 * MIB))
    need(binding.get('postimages') == data['postimages'] and binding.get('source') == before['source']
         and binding.get('destination') == after['source'] and binding.get('source_commit') == SOURCE
         and binding.get('old_recipe_commit') == OLD_PRODUCER
         and binding.get('new_recipe_commit') == after['producer_commit']
         and set(binding.get('changed_paths', [])) == CHANGED, 'Reviewed source staging binding differs')
    copied = data.get('copy', {})
    need(isinstance(copied.get('inventory_sha256'), str) and SHA.fullmatch(copied['inventory_sha256'])
         and type(copied.get('regular_files')) is int and copied['regular_files'] > 0
         and type(copied.get('regular_file_bytes')) is int and copied['regular_file_bytes'] > 0
         and copied.get('all_bytes_and_modes_compared') is True
         and copied.get('cross_tree_regular_hardlinks') is False, 'Actual independent complete-copy proof missing')
    need(set(images.get('before', {})) == set(images.get('after', {})) == POSTIMAGES,
         'Reviewed fourteen native postimages required')
    rows = {}
    for phase, side in [('before', before), ('after', after)]:
        for name, expected in images[phase].items():
            need(set(expected) == {'content_base64', 'sha256', 'size', 'mode'}, 'Malformed source postimage')
            try:
                payload = base64.b64decode(expected['content_base64'], validate=True)
            except (ValueError, TypeError) as error:
                raise ValueError('Invalid source postimage content') from error
            path = regular(Path(side['source']) / relative(name), 2 * MIB)
            need(path.read_bytes() == payload and identity(path) == {k: expected[k] for k in ('sha256', 'size')}
                 and path.stat().st_mode & 0o7777 == expected['mode'], 'Actual native source postimage differs: ' + name)
        profile = read_json(checked_ref(side['source_profile'], 8 * MIB))
        helper = git_blob(side['recipe'], side['producer_commit'], 'files/asu-client/ax6000_asu.js')
        installer = git_blob(side['recipe'], side['producer_commit'], 'scripts/install-feed-apk.sh')
        cohort = (json.dumps({'schema_version': 1, 'cohort': COHORT, 'seed': profile['asu']['seed'],
                              'package_manager': 'apk'}, sort_keys=True) + '\n').encode()
        expected_content = {CLIENT + 'htdocs/luci-static/resources/ax6000_asu.js': helper,
                            'files/' + INSTALLER: installer, 'files/etc/asu-cohort.json': cohort}
        for name, payload in expected_content.items():
            need(base64.b64decode(images[phase][name]['content_base64']) == payload,
                 'Source postimage differs from trusted producer bytes: ' + name)
        rows[phase] = expected_content
    need({name for name in POSTIMAGES if images['before'][name] != images['after'][name]} == CHANGED
         and data.get('changed_files') == {name: {phase: images[phase][name] for phase in ('before', 'after')}
                                           for name in CHANGED}, 'Source delta is not the exact four reviewed files')
    for phase, version, digest in [('before', b'2', '6c3e1489551d35c218ba363d4727a0e52e69a98a30a1546722d91e131d48f54f'),
                                   ('after', b'3', '12c62440fbe9b5ee6b568fbe9253d90bc40d29edf3959375c7cbc8a21ecb6674')]:
        makefile = images[phase][CLIENT + 'Makefile']
        need(makefile['sha256'] == digest and b'PKG_RELEASE:=' + version + b'\n' in base64.b64decode(makefile['content_base64']),
             'APP source revision differs from the exact reviewed Makefile')
    need(hashlib.sha256(rows['after'][CLIENT + 'htdocs/luci-static/resources/ax6000_asu.js']).hexdigest() == MODULE_SHA,
         'APP constructor is not the reviewed APP3 module')
    need(data.get('source_config_before_sha256') == data.get('source_config_after_sha256')
         == identity(Path(before['source']) / '.config')['sha256']
         == identity(Path(after['source']) / '.config')['sha256'], 'Native source top config changed')
    for phase, side in [('before', before), ('after', after)]:
        # Both staging measurements genuinely occurred at the independent copy.
        # The original source identities are compared separately, never relabelled.
        expected = {name: {**side['source_context'][name], 'path': after['source_context'][name]['path']}
                    for name in ('.config', '.vermagic', 'Module.symvers', 'include/config/kernel.release', 'KDIR/Image')}
        need(data.get('native_context_' + phase) == expected, 'Measured staging native five-context proof differs')
        seven = {name: {**side['source_context'][name], 'path': after['source_context'][name]['path']} for name in SDK_ROLES}
        need(data.get('source_context7_' + phase) == seven, 'Measured staging copy seven-context proof differs')
    return images


def root_delta(before, after, images):
    stable = ('installed_kernel', 'installed_packages', 'vendor_packages', 'ucode_packages', 'modules',
              'firmware', 'trusted_key_fingerprint', 'active_feeds', 'apk_executable_present',
              'package_manager', 'apk_policy', 'package_only_absent')
    for layout in ('stock', 'mtkuboot', 'ubootmod'):
        old, new = before['layouts'][layout]['root'], after['layouts'][layout]['root']
        need(all(name in old and old[name] == new.get(name) for name in stable), 'Unreviewed native root policy/vendor/module change')
        old_features, new_features = old['optional_features'], new['optional_features']
        old_versions = dict(old_features['packages']); new_versions = dict(new_features['packages'])
        need(old_versions.pop('luci-app-attendedsysupgrade', None) == '20261021.2-r2'
             and new_versions.pop('luci-app-attendedsysupgrade', None) == '20261021.2-r3'
             and old_versions == new_versions and new_versions.get('attendedsysupgrade-common') == '10-r2',
             'Native feature versions changed beyond APP3')
        for phase, root in [('before', old), ('after', new)]:
            for root_name, source_name in [(MODULE, CLIENT + 'htdocs/luci-static/resources/ax6000_asu.js'),
                                            ('etc/asu-cohort.json', 'files/etc/asu-cohort.json')]:
                expected = images[phase][source_name]
                need(root['optional_features']['files'].get(root_name)
                     == {'sha256': expected['sha256'], 'size': expected['size'], 'mode': '0644'},
                     'Actual root feature differs from trusted source: ' + root_name)
            for root_name, source_name, mode in [(INSTALLER, 'files/' + INSTALLER, '0755'),
                                                  ('etc/asu-cohort.json', 'files/etc/asu-cohort.json', '0644')]:
                expected = images[phase][source_name]
                need(root['repository_files'].get(root_name) == {'sha256': expected['sha256'], 'mode': mode},
                     'Actual root repository file differs from trusted source: ' + root_name)
        need({k: v for k, v in old_features['files'].items() if k not in (MODULE, 'etc/asu-cohort.json')}
             == {k: v for k, v in new_features['files'].items() if k not in (MODULE, 'etc/asu-cohort.json')}
             and {k: v for k, v in old['repository_files'].items() if k not in (INSTALLER, 'etc/asu-cohort.json')}
             == {k: v for k, v in new['repository_files'].items() if k not in (INSTALLER, 'etc/asu-cohort.json')},
             'Unreviewed native feature/repository payload change')


def app_payload(before, after, apk_ref):
    apk = checked_ref(apk_ref, 8 * MIB)
    need(apk_ref['sha256'] == 'ec6f3df6b3e295ad4395649bfd5bc5ca8f2afe52c8fe7bff04df3617f78952f8', 'Exact trusted EC6 APK required')
    fmt = module('package_format'); controls, payloads, metadata = {}, {}, {}
    for phase, side, release in [('before', before, '2'), ('after', after, '3')]:
        candidates = list(Path(side['raw']).joinpath('bin').rglob(APP + release + '.apk'))
        need(len(candidates) == 1, 'Actual APP archive missing/ambiguous')
        path = regular(candidates[0], 16 * MIB)
        need(not apk.is_relative_to(Path(side['raw'])) and not apk.is_relative_to(Path(side['source'])), 'RAW/native tool must not execute')
        control = fmt.read_control(path, apk=apk)
        need(control.get('Package') == 'luci-app-attendedsysupgrade' and control.get('Version') == '20261021.2-r' + release,
             'Actual native APP control differs')
        controls[phase] = {k: v for k, v in control.items() if k not in ('Version', 'Installed-Size', 'APK-Raw')}
        raw_info = {k: v for k, v in control['APK-Raw'].items() if k not in ('version', 'hashes', 'installed-size')}
        controls[phase]['APK-Raw-policy'] = raw_info
        payloads[phase] = fmt.payload_files(path, apk=apk)
        paths = fmt.apk_json(path, apk)['paths']
        metadata[phase] = [{**directory, 'files': [{k: v for k, v in item.items() if k not in (
            ('hash', 'size') if (directory.get('name', '') + '/' + item['name']).lstrip('/') == MODULE else ())}
            for item in directory.get('files', [])]} for directory in paths]
    need(controls['before'] == controls['after'] and metadata['before'] == metadata['after'], 'Native APP control/modes changed beyond revision/module data')
    need(hashlib.sha256(payloads['after'].get(MODULE, b'')).hexdigest() == MODULE_SHA,
         'Actual APP payload is not the reviewed constructor module')
    need({k: v for k, v in payloads['before'].items() if k != MODULE}
         == {k: v for k, v in payloads['after'].items() if k != MODULE}, 'Native APP changed unrelated regular payloads')


def predecessor(inputs, before):
    """Authenticate the retained live state/snapshot; publication later rechecks its pointer."""
    tree = Path(inputs['predecessor_root'])
    state_path = checked_ref(inputs['predecessor_site_state'], 8 * MIB)
    snapshot_path = checked_ref(inputs['predecessor_snapshot'], 8 * MIB)
    need(snapshot_path == tree / 'snapshot-manifest.json', 'Actual restored predecessor snapshot required')
    public = regular(Path(inputs['before']['recipe']) / 'keys/repository.pub', 4096)
    need(public.read_bytes() == git_blob(inputs['before']['recipe'], OLD_PRODUCER, 'keys/repository.pub'), 'Predecessor signing key differs from frozen native recipe')
    usign = checked_ref(inputs['trusted_usign'], 8 * MIB)
    need(inputs['trusted_usign']['sha256'] == 'e2ec131e367995a6540cdd20797cfda0a51af84ecc4f334deacd49fd7fbd3dfc', 'Known trusted USIGN required')
    for side in (inputs['before'], inputs['after']):
        need(not usign.is_relative_to(Path(side['raw'])) and not usign.is_relative_to(Path(side['source'])), 'Native/RAW USIGN must not run')
    for message, signature in [(state_path, state_path.with_suffix('.sig')),
                               (snapshot_path, tree / 'snapshot-manifest.sig')]:
        regular(signature, 4096)
        try:
            subprocess.run([str(usign), '-V', '-m', str(message), '-p', str(public), '-x', str(signature)],
                           check=True, capture_output=True, timeout=30)
        except subprocess.CalledProcessError as error:
            raise ValueError('Predecessor state/snapshot signature invalid') from error
    state, snapshot = read_json(state_path), read_json(snapshot_path)
    pointer = state.get('channels', {}).get('recommended')
    need(state.get('repository') == 'valujin/ax6000-packages-6.12'
         and isinstance(pointer, dict) and pointer.get('manifest_sha256') == inputs['predecessor_snapshot']['sha256']
         and pointer.get('build_id') == before['profile']['build_id']
         and snapshot.get('kind') == 'channel-snapshot' and snapshot.get('channel') == 'recommended'
         and snapshot.get('build_id') == before['profile']['build_id'], 'Authenticated predecessor identity differs')
    inventory = snapshot.get('files', [])
    for name in ('profile.json', 'firmware-manifest.json', 'build.config'):
        actual = regular(tree / 'channel' / name)
        need(identity(actual) == {k: before['metadata'][name][k] for k in ('sha256', 'size')}
             and len([x for x in inventory if x.get('path') == name and
                      {k: x.get(k) for k in ('sha256', 'size')} == identity(actual)]) == 1,
             'Signed predecessor inventory differs from actual native RAW: ' + name)
    return pointer


def evaluate(inputs):
    fields = {'schema_version', 'kind', 'before', 'after', 'staging_receipt', 'production_receipt',
              'trusted_apk', 'trusted_usign', 'predecessor_root', 'predecessor_site_state', 'predecessor_snapshot'}
    need(isinstance(inputs, dict) and set(inputs) == fields and type(inputs['schema_version']) is int
         and inputs['schema_version'] == 1 and inputs['kind'] == 'rec-native-apk-replacement-inputs-v1',
         'Exact actual native replacement inputs required; pending/null staging cannot pass')
    before, after = inputs['before'], inputs['after']
    need(isinstance(before, dict) and isinstance(after, dict) and before.get('producer_commit') == OLD_PRODUCER
         and isinstance(after.get('producer_commit'), str) and re.fullmatch('[0-9a-f]{40}', after['producer_commit'])
         and after['producer_commit'] != OLD_PRODUCER, 'Actual old/new native producers required')
    left, right = side_records(before), side_records(after)
    validate_profiles(left['profile'], right['profile'])
    compare_banks(left['bank'], right['bank'])
    for name in ('protected_packages', 'frozen_packages', 'frozen_kmods'):
        need(left['baseline'][name] == right['baseline'][name], 'Native SDK protected/frozen package set changed')
    need(left['context'] == right['context'] and left['image'] == right['image']
         and left['manifest'].get('source_patches', []) == right['manifest'].get('source_patches', [])
         and {k: left['metadata']['build.config'][k] for k in ('sha256', 'size')}
         == {k: right['metadata']['build.config'][k] for k in ('sha256', 'size')},
         'Native ABI/config/source patch ledger changed')
    staging = read_json(checked_ref(inputs['staging_receipt'], 8 * MIB))
    images = staged_source(staging, before, after)
    production_completion(read_json(checked_ref(inputs['production_receipt'], 8 * MIB)), after['producer_commit'],
                          right['metadata'], after['native_evidence'], inputs['staging_receipt'],
                          after['source_context'], after['sdk_context'], right['profile'], right['manifest'])
    root_delta(left['evidence'], right['evidence'], images)
    app_payload(before, after, inputs['trusted_apk'])
    pointer = predecessor(inputs, left)
    summary = {'predecessor_build_id': left['profile']['build_id'], 'successor_build_id': right['profile']['build_id'],
               'predecessor_pointer': pointer, 'source_commit': SOURCE, 'kernel_abi': ABI,
               'producer_commit': after['producer_commit'], 'native_context': left['context'], 'functional_image': left['image'],
               'unchanged_native_archives': len(left['bank']) - 1,
               'protected_baseline_packages': len(left['baseline']['protected_packages']),
               'changed_source_paths': sorted(CHANGED), 'new_app_version': '20261021.2-r3',
               'before_metadata': {name: {k: row[k] for k in ('sha256', 'size')} for name, row in left['metadata'].items()},
               'after_metadata': {name: {k: row[k] for k in ('sha256', 'size')} for name, row in right['metadata'].items()},
               'native_archive_inventory_sha256': {'before': json_sha(left['bank']), 'after': json_sha(right['bank'])},
               'source_patch_ledger': left['manifest'].get('source_patches', []),
               'source_postimages': {phase: {name: {k: row[k] for k in ('sha256', 'size', 'mode')}
                                            for name, row in images[phase].items()} for phase in ('before', 'after')},
               'source_profile': {phase: {k: side['source_profile'][k] for k in ('sha256', 'size')}
                                  for phase, side in [('before', before), ('after', after)]},
               'seeds': {'before': left['profile']['asu']['seed'], 'after': right['profile']['asu']['seed']},
               'local_proof_sha256': {phase: {name: side[name]['sha256'] for name in
                                             ('native_status', 'native_evidence', 'sdk_baseline', 'ib_approval')}
                                      for phase, side in [('before', before), ('after', after)]},
               'staging_receipt_sha256': inputs['staging_receipt']['sha256'],
               'production_receipt_sha256': inputs['production_receipt']['sha256']}
    return left['profile'], right['profile'], summary


def load_receipt(old, new, path, pin):
    validate_profiles(old, new)
    need(isinstance(pin, str) and SHA.fullmatch(pin), 'Explicit reviewed native replacement proof SHA required')
    path = regular(path, 8 * MIB)
    need(identity(path)['sha256'] == pin, 'Reviewed native replacement proof SHA differs')
    proof = read_json(path)
    need(isinstance(proof, dict) and set(proof) == {'schema_version', 'kind', 'summary'}
         and type(proof['schema_version']) is int and proof['schema_version'] == 1 and proof['kind'] == KIND,
         'Actual native replacement receipt required')
    summary = proof.get('summary', {})
    need(isinstance(summary, dict) and summary.get('predecessor_build_id') == old.get('build_id')
         and summary.get('successor_build_id') == new.get('build_id')
         and summary.get('source_commit') == SOURCE and summary.get('kernel_abi') == ABI,
         'Native replacement proof generation identity differs')
    return proof


def validate_receipt(old, new, path, pin, *, predecessor_pointer=None, old_tree=None, new_tree=None):
    proof = load_receipt(old, new, path, pin)
    summary = proof['summary']
    fields = {'predecessor_build_id', 'successor_build_id', 'predecessor_pointer', 'source_commit', 'kernel_abi',
              'producer_commit', 'native_context', 'functional_image', 'unchanged_native_archives',
              'protected_baseline_packages', 'changed_source_paths', 'new_app_version', 'before_metadata', 'after_metadata',
              'native_archive_inventory_sha256', 'source_patch_ledger', 'source_postimages', 'source_profile', 'seeds',
              'local_proof_sha256', 'staging_receipt_sha256', 'production_receipt_sha256'}
    need(set(summary) == fields, 'Unexpected portable native approval fields')
    migration = module('kernel_migration')
    need(summary['functional_image'] == migration.IMAGES['after']
         and isinstance(summary['native_context'], dict) and set(summary['native_context']) == set(SDK_ROLES)
         and all(summary['native_context'].get(name) == row for name, row in migration.CONTEXT.items()),
         'Portable native approval changes complete Image or enrolled ABI contexts')
    def valid_identity(row):
        return isinstance(row, dict) and set(row) == {'sha256', 'size'} and isinstance(row['sha256'], str) \
            and SHA.fullmatch(row['sha256']) and type(row['size']) is int and 0 < row['size'] <= 64 * MIB
    need(all(valid_identity(row) for row in summary['native_context'].values())
         and isinstance(summary['producer_commit'], str) and re.fullmatch('[0-9a-f]{40}', summary['producer_commit'])
         and summary['producer_commit'] != OLD_PRODUCER and summary['new_app_version'] == '20261021.2-r3'
         and summary['changed_source_paths'] == sorted(CHANGED), 'Invalid portable native approval identities')
    need(summary['seeds'] == {'before': old['asu']['seed'], 'after': new['asu']['seed']}, 'Portable native producer seeds differ')
    digests = [summary['staging_receipt_sha256'], summary['production_receipt_sha256']]
    need(isinstance(summary['local_proof_sha256'], dict) and set(summary['local_proof_sha256']) == {'before', 'after'}
         and isinstance(summary['source_profile'], dict) and set(summary['source_profile']) == {'before', 'after'}
         and isinstance(summary['native_archive_inventory_sha256'], dict)
         and set(summary['native_archive_inventory_sha256']) == {'before', 'after'}, 'Both actual local native proof scopes required')
    for phase in ('before', 'after'):
        need(set(summary['local_proof_sha256'][phase]) == {'native_status', 'native_evidence', 'sdk_baseline', 'ib_approval'}
             and valid_identity(summary['source_profile'][phase]), 'Actual native/SDK/IB/source-profile approval facts required')
        digests.extend(summary['local_proof_sha256'][phase].values())
        metadata = summary[phase + '_metadata']
        need(set(metadata) == {'profile.json', 'lock.json', 'firmware-manifest.json', 'build.config'}
             and all(valid_identity(row) for row in metadata.values()), 'Actual native metadata approval facts required')
    need(all(isinstance(value, str) and SHA.fullmatch(value) for value in digests), 'Missing actual local verification proof digest')
    images = summary['source_postimages']
    need(set(images) == {'before', 'after'} and set(images['before']) == set(images['after']) == POSTIMAGES
         and {name for name in POSTIMAGES if images['before'][name] != images['after'][name]} == CHANGED,
         'Portable approval changes native source beyond exact reviewed four paths')
    for phase, profile, makefile_sha in [('before', old, '6c3e1489551d35c218ba363d4727a0e52e69a98a30a1546722d91e131d48f54f'),
                                       ('after', new, '12c62440fbe9b5ee6b568fbe9253d90bc40d29edf3959375c7cbc8a21ecb6674')]:
        for row in images[phase].values():
            need(isinstance(row, dict) and set(row) == {'sha256', 'size', 'mode'}
                 and valid_identity({k: row[k] for k in ('sha256', 'size')}) and type(row['mode']) is int
                 and row['mode'] in (0o644, 0o755), 'Invalid portable source postimage')
        cohort = (json.dumps({'schema_version': 1, 'cohort': COHORT, 'seed': profile['asu']['seed'], 'package_manager': 'apk'}, sort_keys=True) + '\n').encode()
        need(images[phase]['files/etc/asu-cohort.json'] == {'sha256': hashlib.sha256(cohort).hexdigest(), 'size': len(cohort), 'mode': 0o644}
             and images[phase][CLIENT + 'Makefile']['sha256'] == makefile_sha, 'Portable APP revision/cohort postimage differs')
    need(images['after'][CLIENT + 'htdocs/luci-static/resources/ax6000_asu.js']['sha256'] == MODULE_SHA,
         'Portable APP3 constructor postimage differs')
    if predecessor_pointer is not None:
        need(summary['predecessor_pointer'] == predecessor_pointer, 'Native replacement predecessor differs from authenticated live pointer')
    need(old_tree is not None and new_tree is not None, 'Actual authenticated native metadata trees required')
    manifests = {}
    for tree, field in ((old_tree, 'before_metadata'), (new_tree, 'after_metadata')):
        for name in ('profile.json', 'firmware-manifest.json', 'build.config'):
            need(identity(Path(tree) / name) == summary[field][name], 'Publication tree differs from reviewed native proof: ' + name)
        phase = 'before' if field == 'before_metadata' else 'after'
        manifest = read_json(Path(tree) / 'firmware-manifest.json'); manifests[phase] = manifest
        profile = old if phase == 'before' else new
        need(read_json(Path(tree) / 'profile.json') == profile and manifest.get('source_commit') == SOURCE
             and manifest.get('kernel_version') == ABI and manifest.get('build_id') == profile['build_id']
             and manifest.get('recipe_commit') == (OLD_PRODUCER if phase == 'before' else summary['producer_commit'])
             and manifest.get('source_patches', []) == summary['source_patch_ledger'], 'Portable receipt native manifest/source ledger differs')
        need(json_sha(manifest_bank(manifest)) == summary['native_archive_inventory_sha256'][phase], 'Portable native archive inventory digest differs')
    left, right = (manifest_bank(manifests[phase]) for phase in ('before', 'after'))
    compare_banks(left, right)
    need(type(summary['unchanged_native_archives']) is int and summary['unchanged_native_archives'] == len(left) - 1
         and type(summary['protected_baseline_packages']) is int and 0 < summary['protected_baseline_packages'] <= len(left)
         and summary['before_metadata']['build.config'] == summary['after_metadata']['build.config'], 'Native protected/archive/config facts differ')
    return summary


def validate_payloads(old_tree, new_tree, summary, read, transport, cache, budget):
    """Reuse the existing bounded immutable-asset decoder; no local operator paths."""
    proof = {'predecessor_build_id': summary['predecessor_build_id'], 'successor_build_id': summary['successor_build_id'],
             'functional_image': {phase: summary['functional_image'] for phase in ('before', 'after')},
             'firmware_manifest_sha256': {phase: summary[phase + '_metadata']['firmware-manifest.json']['sha256']
                                        for phase in ('before', 'after')}}
    module('kernel_migration').validate_payloads([('before', old_tree), ('after', new_tree)], proof, read, transport, cache, budget)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true'); parser.add_argument('--inputs', type=Path)
    parser.add_argument('--inputs-sha256'); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({'execute': False, 'actual_native_acceptance': None, 'kind': KIND,
                          'requires': 'SHA-bound actual native/SDK/IB/source/completion and authenticated predecessor inputs'}))
        return
    need(args.inputs is not None and args.output is not None, 'Actual reviewed inputs and fresh proof output required')
    need(isinstance(args.inputs_sha256, str) and SHA.fullmatch(args.inputs_sha256)
         and identity(regular(args.inputs, 8 * MIB))['sha256'] == args.inputs_sha256, 'Explicit reviewed actual inputs SHA required')
    need(args.output.is_absolute() and str(args.output) == str(args.output.resolve())
         and args.output.parent.is_dir() and not args.output.exists() and not args.output.is_symlink()
         and not any(x.is_symlink() for x in args.output.parents), 'Fresh proof output required')
    _, _, summary = evaluate(read_json(args.inputs))
    value = {'schema_version': 1, 'kind': KIND, 'summary': summary}
    with args.output.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps(full_ref(args.output)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        sys.exit('native-generation: ' + str(error))
