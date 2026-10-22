#!/usr/bin/env python3
"""One finite LATEST existing-context migration; no SDK compiler claim or build."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

MIB = 1024 ** 2
SOURCE = 'a99b0888b88f134f56bcb2a7d93027b5d20638a9'
ABI = '6.12.112~d405163bfdb42254c245797a894994c0-r1'
OLD_BUILD = 'redmi-ax6000-612-latest-a99b0888b88f-0b1249707848'
NEW_BUILD = 'redmi-ax6000-612-latest-a99b0888b88f-31599e148e45'
IMAGE = {'size': 14661640, 'sha256': 'a1db81320a822eab661310185948456cef216faa7fac0a11d689ce61233a8681'}
MANIFESTS = {'before': '459a7e06661b22e3b21a66ecb2e67d4416c3e0b1aef8c279305c97e0a1f49567',
             'after': '0f8095952e7e4444dc464865d4b9608f507b56035f67e8df01e90fc6bd7a3ff2'}
REVIEWED_CONTEXT = {'kind': 'latest-accepted-existing-context-v1',
                    'native_acceptance_sha256': 'ef3920c9c2ac506d9a230c9eeda9d2b557d430c1673326a4f2fd0103cadf44f8',
                    'root_decision_sha256': '4ba65dc1f31383a40f538ddc5c1c6ad29dc5ba12c7885771b04d9d5ac303a1e9',
                    'hosted_context_sha256': '428ef4d3df486f2e9ad85876915c04e5749aad4d1662f1d4e43908ebae96930f'}
PATCHES_SHA = '5171842104d55f6885a142a7f9ae827722d3782c4be33641ea3f2403a73c531e'
CONTEXT = {'.config': {'sha256': '355fb252048e9cc3448aa12efdd8e7d3cf0d92143d4f092a3bb3de067126b177',
             'size': 216472},
 '.config.set': {'sha256': '454dc126d759d8df5af0ee2abbcbbf181984d691b4840ecd7b525bad4d9f78c7',
                 'size': 288687},
 '.vermagic': {'sha256': 'bfd25ae6e6d2c2a7f4ee66e523cc45af696b6db67f87ed638043ad90fd2bcc7e', 'size': 33},
 'Module.symvers': {'sha256': 'a10a247bc0b3cf9738c49631dcfeeb7cb4e6bed04f6eb4ff7cd3a8b05a5fe939',
                    'size': 890860},
 'include/config/kernel.release': {'sha256': '2749ccde17f026de34696677d00a322e7f3046c29ee8a7550d7d8782a3e61783',
                                   'size': 9},
 'include/generated/autoconf.h': {'sha256': '2f7948708021aa3b5ffd8f2113ba48476b890e73e631cfbf2480610522aeaca1',
                                  'size': 96028},
 'modules.builtin.modinfo': {'sha256': 'a3e566ab54c5cc030c7c2cb58e9cbadae7264215626c6636061a58a1cea9f6e9',
                             'size': 30961},
 'retained/.config': {'sha256': '355fb252048e9cc3448aa12efdd8e7d3cf0d92143d4f092a3bb3de067126b177',
                      'size': 216472},
 'retained/Image': {'sha256': 'a1db81320a822eab661310185948456cef216faa7fac0a11d689ce61233a8681',
                    'size': 14661640},
 'retained/Module.symvers': {'sha256': 'a10a247bc0b3cf9738c49631dcfeeb7cb4e6bed04f6eb4ff7cd3a8b05a5fe939',
                             'size': 890860}}
POINTER = {'archive_sha256': '5f261e4480d32d4237df0f6318290f0aa6b3ba32c62c802a4c756ee4050920f8',
 'archive_size': 107107048,
 'asset_id': 661561069,
 'build_id': 'redmi-ax6000-612-latest-a99b0888b88f-0b1249707848',
 'channel': 'latest',
 'kernel_version': '6.12.112~d405163bfdb42254c245797a894994c0-r1',
 'manifest_sha256': '074e68e5f9d0105e2f3f19719271f5a68ff5339ab7dcfe6baac0b7f2b1619ea3',
 'profile_id': 'redmi-ax6000-612-latest',
 'release_id': 419221190,
 'tag': 'packages-latest-074e68e5f9d0105e2f3f19719271f5a68ff5339ab7dcfe6baac0b7f2b1619ea3'}
FIELDS = {'schema_version', 'kind', 'cohort', 'predecessor_build_id', 'successor_build_id',
          'source_commit', 'kernel_version', 'kernel_context', 'functional_image',
          'reviewed_context', 'source_patches', 'firmware_manifest_sha256', 'predecessor_pointer'}


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_checked(path, expected):
    path = Path(path)
    need(path.is_absolute() and str(path) == str(path.resolve()) and path.is_file()
         and not any(p.is_symlink() for p in (path, *path.parents))
         and 0 < path.stat().st_size <= MIB, 'Missing/linked/oversized migration metadata')
    data = path.read_bytes()
    need(digest(data) == expected, 'Migration metadata checksum differs')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'Duplicate migration metadata field')
            result[key] = value
        return result
    def finite(_):
        raise ValueError('Nonfinite migration metadata')
    return json.loads(data.decode(), object_pairs_hook=unique, parse_constant=finite)


def validate_receipt(old, new, proof):
    need(isinstance(proof, dict) and set(proof) == FIELDS
         and type(proof['schema_version']) is int and proof['schema_version'] == 3
         and proof['kind'] == 'asu-apk-native-migration' and proof['cohort'] == '612-latest',
         'Finite LATEST same-Image schema3 receipt required')
    need(old.get('build_id') == proof['predecessor_build_id'] == OLD_BUILD
         and new.get('build_id') == proof['successor_build_id'] == NEW_BUILD
         and old.get('id') == new.get('id') == 'redmi-ax6000-612-latest'
         and old.get('channel') == new.get('channel') == 'latest'
         and old.get('package_manager', 'opkg') == 'opkg' and new.get('package_manager') == 'apk'
         and old.get('firmware') == new.get('firmware')
         and old['firmware'].get('commit') == proof['source_commit'] == SOURCE
         and old['firmware'].get('kernel_version') == proof['kernel_version'] == ABI,
         'LATEST migration changes its exact generations/source/ABI/layouts')
    need(proof['kernel_context'] == {name: {'before': row, 'after': row} for name, row in CONTEXT.items()}
         and proof['functional_image'] == {'before': IMAGE, 'after': IMAGE},
         'LATEST migration requires all ten unchanged roles and the same complete Image')
    for pair in [proof['functional_image'], *proof['kernel_context'].values()]:
        need(all(type(row['size']) is int for row in pair.values()), 'Migration identity sizes must be integers')
    need(proof['reviewed_context'] == REVIEWED_CONTEXT and proof['firmware_manifest_sha256'] == MANIFESTS,
         'LATEST migration context or actual manifest authority differs')
    need(proof['predecessor_pointer'] == POINTER
         and all(type(proof['predecessor_pointer'][k]) is int for k in ('release_id', 'asset_id', 'archive_size')),
         'LATEST migration must bind the exact reviewed authenticated predecessor')
    patches = proof['source_patches']
    need(isinstance(patches, dict) and set(patches) == {'before', 'after'}
         and isinstance(patches['before'], list) and patches['before'] == patches['after']
         and digest(json.dumps(patches['before'], sort_keys=True, separators=(',', ':')).encode()) == PATCHES_SHA,
         'LATEST migration source patch ledger differs')


def validate_manifests(snapshot, old_tree, new_tree, proof, predecessor_pointer):
    old_tree, new_tree = Path(old_tree), Path(new_tree)
    validate_receipt(snapshot.read_json(old_tree/'profile.json'), snapshot.read_json(new_tree/'profile.json'), proof)
    need(predecessor_pointer == proof['predecessor_pointer'], 'LATEST migration authenticated predecessor changed')
    with tempfile.TemporaryDirectory(prefix='ax6000-latest-migration-metadata-') as temporary:
        before = old_tree
        path = before/'firmware-manifest.json'
        if not path.exists() and not path.is_symlink():
            before = snapshot.legacy_migration_metadata(old_tree, proof, temporary)
        trees = [('before', before), ('after', new_tree)]
        for phase, tree in trees:
            manifest = read_checked(Path(tree)/'firmware-manifest.json', proof['firmware_manifest_sha256'][phase])
            need(manifest.get('build_id') == proof[phase == 'before' and 'predecessor_build_id' or 'successor_build_id']
                 and manifest.get('source_commit') == SOURCE and manifest.get('kernel_version') == ABI
                 and manifest.get('source_patches') == proof['source_patches'][phase],
                 'LATEST migration actual native manifest/source ledger differs')
        snapshot.module('kernel_migration').validate_payloads(
            trees, proof, snapshot.read_json, snapshot.module('publication_api'),
            snapshot._MIGRATION_IMAGE_CACHE, snapshot._MIGRATION_DOWNLOAD_BUDGET)


def from_accepted_metadata(paths):
    # This projects already accepted native facts, never a new SDK compilation,
    # hardware test, IB smoke or fresh local source verification claim.
    accepted = read_checked(paths['accepted_status'], REVIEWED_CONTEXT['native_acceptance_sha256'])
    decision = read_checked(paths['root_decision'], REVIEWED_CONTEXT['root_decision_sha256'])
    hosted = read_checked(paths['hosted_context'], REVIEWED_CONTEXT['hosted_context_sha256'])
    old = read_checked(paths['old_profile'], 'aeef60180ae24f1c35a35281de5d9c81856b98e3e20460bca956e8acfc45327d')
    new = read_checked(paths['new_profile'], '6923e6be2fbfd2f4c880afc62b1b97053d71448c2686dd41e87829a773bd23b7')
    before = read_checked(paths['old_manifest'], MANIFESTS['before'])
    after = read_checked(paths['new_manifest'], MANIFESTS['after'])
    read_checked(paths['old_snapshot'], POINTER['manifest_sha256'])
    need(accepted.get('ok') is True and accepted.get('native_acceptance_granted') is True
         and accepted.get('all_layouts_verified') is True and accepted.get('prior_opkg_kernel_migration_verified') is True
         and accepted.get('new_kernel_context_enrolled') is False and decision.get('approved') is True
         and decision.get('required_roles') == CONTEXT and decision.get('old_guards_relaxed') is False
         and hosted.get('receipts', {}).get('native_acceptance', {}).get('sha256') == REVIEWED_CONTEXT['native_acceptance_sha256']
         and {k: hosted['functional_kernel'][k] for k in ('sha256', 'size')} == IMAGE,
         'Actual accepted existing native-context metadata required')
    proof = {'schema_version': 3, 'kind': 'asu-apk-native-migration', 'cohort': '612-latest',
             'predecessor_build_id': OLD_BUILD, 'successor_build_id': NEW_BUILD,
             'source_commit': SOURCE, 'kernel_version': ABI,
             'kernel_context': {name: {'before': copy.deepcopy(row), 'after': copy.deepcopy(row)} for name, row in CONTEXT.items()},
             'functional_image': {p: copy.deepcopy(IMAGE) for p in ('before', 'after')},
             'reviewed_context': copy.deepcopy(REVIEWED_CONTEXT),
             'source_patches': {'before': before['source_patches'], 'after': after['source_patches']},
             'firmware_manifest_sha256': copy.deepcopy(MANIFESTS), 'predecessor_pointer': copy.deepcopy(POINTER)}
    validate_receipt(old, new, proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    names = ('accepted-status', 'root-decision', 'hosted-context', 'old-profile', 'new-profile',
             'old-manifest', 'new-manifest', 'old-snapshot')
    for name in names:
        parser.add_argument('--'+name, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({'execute': False, 'publication_performed': False}))
        return
    need(all(value is not None for key, value in vars(args).items() if key != 'execute'), 'Actual metadata files and fresh proof output required')
    paths = {name.replace('-', '_'): getattr(args, name.replace('-', '_')) for name in names}
    output = args.output
    need(output.is_absolute() and str(output) == str(output.resolve()) and output.parent.is_dir()
         and not output.exists() and not any(p.is_symlink() for p in (output, *output.parents)), 'Fresh canonical output required')
    need(not any(output.is_relative_to(path.parent.resolve()) for path in paths.values()), 'Output overlaps original accepted metadata directory')
    proof = from_accepted_metadata(paths)
    with output.open('x') as stream:
        json.dump(proof, stream, indent=2, sort_keys=True); stream.write('\n')


if __name__ == '__main__':
    main()
