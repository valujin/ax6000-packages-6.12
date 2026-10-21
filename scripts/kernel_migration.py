"""One reviewed REC Image transition; full payload hashes, never note masking."""
import hashlib
import importlib.util
import lzma
from pathlib import Path
import re
import tarfile
import tempfile
import zlib

MIB = 1024 ** 2
SOURCE = 'ae65e1de69971b5a2e3cf7e39390ee93f274d488'
ABI = '6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1'
IMAGES = {
    'before': {'size': 14661640, 'sha256': 'ac19e2c554e40219aed043a0760aef2a609743ec0437d295c4f7f15f51886d8f'},
    'after': {'size': 14661640, 'sha256': '5a0eedece2116a8dd046bd8337b487bdfc6913eaf1465d3dc6b711d0851ad611'},
}
CONTEXT = {
    '.config': {'size': 216405, 'sha256': 'f245fc96a9db54159662d86f32e57e86a07106bd029719ad5bdb7af6581e552e'},
    'Module.symvers': {'size': 889880, 'sha256': '405d5e270cb79b7e3acd8d8a0ec8b2c593f86d0a37342e3311a0e0f7ed8dcd41'},
    '.vermagic': {'size': 33, 'sha256': '555c28901ca8ca4023945b27b62b924fdbb3a2fc951bb234cca9b8ab8b61ec0b'},
    'include/config/kernel.release': {'size': 9, 'sha256': '70ab81f7d2e0021fb2fca26461be33b18a0dc73828a383953ef5693f222b36ed'},
}
REVIEW = {
    'kind': 'rec-gnu-build-id-notes-v1',
    'original_context_sha256': 'cddaaf6593c873326894003a3695b1083435447ba49556c744b0b0fd995fd87c',
    'accepted_context_sha256': '2d7dbf000444728dedd334a432445cf8aece08b2944e6d28e172d823490f8d15',
    'enrollment_sha256': 'c0b5ac9ba485f617662221dec2e9829772c4602f9091e0cda4297071d493cdea',
    'transition_proof_sha256': '5f958f7cb6569f34ef3f02602c86e00c918ed8b53db1f80800d8e4d17b68a01a',
}
LAYOUTS = ('stock', 'mtkuboot', 'ubootmod')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path, size=None, sha=None):
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)) and path.is_file(),
         'Migration firmware must be an actual regular file')
    need(0 < path.stat().st_size <= 128 * MIB, 'Migration firmware byte cap exceeded')
    need(size is None or path.stat().st_size == size, 'Migration firmware size differs')
    need(sha is None or digest(path) == sha, 'Migration firmware checksum differs')
    return path


def validate_receipt(old, new, proof):
    need(type(proof.get('schema_version')) is int and proof['schema_version'] == 2,
         'V2 migration requires integer schema version 2')
    need(set(proof) == {'schema_version', 'kind', 'predecessor_build_id', 'successor_build_id',
                       'source_commit', 'kernel_version', 'cohort', 'kernel_context',
                       'functional_image', 'reviewed_transition', 'source_patches',
                       'firmware_manifest_sha256'}, 'Unexpected v2 migration proof fields')
    need(old['id'] == new['id'] == 'redmi-ax6000-612-recommended'
         and old['channel'] == new['channel'] == 'recommended'
         and proof.get('cohort') == '612-recommended'
         and proof['source_commit'] == SOURCE and proof['kernel_version'] == ABI,
         'V2 migration is restricted to the reviewed REC source/cohort/predecessor')
    need(proof.get('functional_image') == IMAGES and proof.get('reviewed_transition') == REVIEW,
         'V2 migration requires the exact reviewed full Image pair and enrollment')
    need(proof.get('kernel_context') == {name: {'before': identity, 'after': identity}
                                        for name, identity in CONTEXT.items()},
         'V2 migration requires all four exact unchanged native ABI contexts')
    for identities in (proof['functional_image'], *proof['kernel_context'].values()):
        need(all(type(item['size']) is int for item in identities.values()),
             'V2 migration byte identities require integer sizes')
    manifests = proof.get('firmware_manifest_sha256')
    need(isinstance(manifests, dict) and set(manifests) == {'before', 'after'}
         and all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) for value in manifests.values()),
         'V2 migration requires exact native firmware manifest bindings')


def functional_image(image, layout, work):
    """Read actual TAR/FIT payloads, with bounded stdlib decompression only."""
    image = regular(image)
    work = Path(work)
    work.mkdir()
    if layout == 'ubootmod':
        fit_image = image
    else:
        need(layout in ('stock', 'mtkuboot'), 'Unsupported migration firmware layout')
        prefix = 'sysupgrade-xiaomi_redmi-router-ax6000-' + layout
        allowed = {prefix, prefix + '/CONTROL', prefix + '/kernel', prefix + '/root'}
        seen = set()
        with tarfile.open(image, 'r:') as archive:
            for member in archive:
                name = member.name.rstrip('/')
                need(name in allowed and name not in seen and not member.pax_headers
                     and member.sparse is None, 'Unsafe/duplicate migration TAR member')
                seen.add(name)
                if name == prefix:
                    need(member.isdir() and member.size == 0, 'Invalid migration TAR directory')
                    continue
                need(member.isfile() and 0 < member.size < (110 * MIB if name.endswith('/root') else 30 * MIB),
                     'Nonregular/oversized migration TAR payload')
                if name.endswith('/CONTROL'):
                    need(member.size <= 4096 and archive.extractfile(member).read(4097)
                         == ('BOARD=xiaomi_redmi-router-ax6000-' + layout + '\n').encode(),
                         'Migration TAR board identity differs')
                elif name.endswith('/kernel'):
                    fit_image = work / 'kernel.fit'
                    with archive.extractfile(member) as source, fit_image.open('xb') as output:
                        remaining = member.size
                        while remaining:
                            chunk = source.read(min(64 * 1024, remaining))
                            need(bool(chunk), 'Truncated migration TAR kernel')
                            output.write(chunk)
                            remaining -= len(chunk)
        need(seen == allowed, 'Missing migration TAR payloads')
        # Sysupgrade fwtool metadata follows the TAR end. The complete outer
        # asset is independently size/SHA-bound; it is never executed here.
    spec = importlib.util.spec_from_file_location('migration_fit', Path(__file__).with_name('fit_payload.py'))
    fit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fit)
    payload = fit.extract_fit(fit_image, work, external=layout == 'ubootmod')['kernel']
    compression = payload['compression']
    decoder = (zlib.decompressobj(16 + zlib.MAX_WBITS) if compression == 'gzip' else
               lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=256 * MIB))
    size = 0
    sha = hashlib.sha256()
    header = bytearray()
    with payload['path'].open('rb') as source:
        while chunk := source.read(64 * 1024):
            need(not decoder.eof, 'Compressed migration kernel has trailing data')
            pending = chunk
            while True:
                data = decoder.decompress(pending, max_length=min(MIB, 64 * MIB - size + 1))
                size += len(data)
                need(size <= 64 * MIB, 'Migration kernel decompression cap exceeded')
                header.extend(data[:max(0, 64 - len(header))])
                sha.update(data)
                if decoder.eof:
                    need(not decoder.unused_data, 'Compressed migration kernel has trailing data')
                    break
                if compression == 'gzip':
                    pending = decoder.unconsumed_tail
                    if not pending:
                        break
                elif decoder.needs_input:
                    break
                else:
                    pending = b''
    need(decoder.eof and len(header) == 64 and header[56:60] == b'ARM\x64',
         'Truncated/non-ARM64 migration Image')
    return {'size': size, 'sha256': sha.hexdigest()}


def manifest_assets(manifest):
    selected = {}
    seen = set()
    for item in manifest.get('files', []):
        path = item.get('path', '')
        need(isinstance(path, str) and path not in seen, 'Duplicate/invalid native manifest path')
        seen.add(path)
        for layout in LAYOUTS:
            extension = '.itb' if layout == 'ubootmod' else '.bin'
            suffix = '-xiaomi_redmi-router-ax6000-' + layout + '-squashfs-sysupgrade' + extension
            if path.startswith('bin/targets/mediatek/filogic/immortalwrt') and path.endswith(suffix):
                need(Path(path).as_posix() == path and len(Path(path).parts) == 5
                     and layout not in selected and type(item.get('size')) is int
                     and 0 < item['size'] <= 128 * MIB
                     and isinstance(item.get('sha256'), str) and re.fullmatch('[0-9a-f]{64}', item['sha256']),
                     'Invalid/ambiguous native migration firmware asset')
                selected[layout] = item
    need(set(selected) == set(LAYOUTS), 'Native migration requires all three actual sysupgrades')
    return selected


def validate_payloads(trees, proof, read_json, transport, cache, budget):
    """Compare local RAW or exact immutable catalog assets. Cache full identities."""
    phases = []
    for phase, tree in trees:
        manifest_path = Path(tree) / 'firmware-manifest.json'
        need(digest(manifest_path) == proof['firmware_manifest_sha256'][phase],
             'V2 migration native firmware manifest checksum differs: ' + phase)
        phases.append((phase, Path(tree), manifest_assets(read_json(manifest_path))))
    need(sum(item['size'] for _, _, assets in phases for item in assets.values()) <= 512 * MIB,
         'Aggregate migration firmware byte cap exceeded')
    for phase, tree, assets in phases:
        missing = any(not (tree / item['path']).exists() for item in assets.values())
        api = before = catalog = None
        if missing:
            catalog = read_json(tree / 'downloads.json')
            api = transport.ReleaseAPI('valujin/ax6000-packages-6.12')
            before = api.get_release(catalog['release']['id'])
            need(before is not None and before.get('draft') is False and before.get('immutable') is True
                 and before.get('tag_name') == 'firmware-' + proof[phase == 'after' and 'successor_build_id' or 'predecessor_build_id']
                 and before['tag_name'] == catalog['release']['tag']
                 and api.resolve_tag_commit(before['tag_name']) == catalog['release']['recipe_commit'],
                 'Migration firmware release is not the exact immutable catalog generation')
        with tempfile.TemporaryDirectory(prefix='ax6000-migration-images-') as temporary:
            for layout, item in assets.items():
                key = (item['sha256'], item['size'], layout, proof['functional_image'][phase]['sha256'])
                path = tree / item['path']
                if path.exists() or path.is_symlink():
                    regular(path, item['size'], item['sha256'])
                else:
                    name = Path(item['path']).name
                    records = [row for row in catalog['assets'] if row.get('filename') == name]
                    remote = [row for row in before['assets'] if row.get('name') == name]
                    need(len(records) == len(remote) == 1, 'Missing/ambiguous catalog migration asset')
                    record, asset = records[0], remote[0]
                    need(record.get('sha256') == item['sha256'] and record.get('size') == item['size']
                         and record.get('kind') == 'sysupgrade' and record.get('layout') == layout
                         and asset.get('id') == record.get('asset_id') and asset.get('state') == 'uploaded'
                         and asset.get('updated_at') == record.get('updated_at')
                         and asset.get('size') == item['size'] and asset.get('digest') == 'sha256:' + item['sha256'],
                         'Immutable migration asset metadata differs from signed native inventory')
                    if key in cache:
                        continue
                    budget['used'] += item['size']
                    need(budget['used'] <= 512 * MIB, 'Migration process download byte cap exceeded')
                    path = Path(temporary) / name
                    api.download_asset(before, asset, path, item['sha256'], item['size'])
                    regular(path, item['size'], item['sha256'])
                if key not in cache:
                    identity = functional_image(path, layout, Path(temporary) / layout)
                    need(identity == proof['functional_image'][phase],
                         'Actual full functional Image differs from reviewed migration: ' + phase + '/' + layout)
                    cache[key] = identity
                # Always rehash local inputs, including memoized assets.
                regular(path, item['size'], item['sha256'])
        if api is not None:
            need(transport.release_identity(before) == transport.release_identity(api.get_release(before['id']))
                 and api.resolve_tag_commit(before['tag_name']) == catalog['release']['recipe_commit'],
                 'Immutable migration release changed during verification')
