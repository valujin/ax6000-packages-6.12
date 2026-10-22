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
NEW_KIND = 'rec-native-apk-generation-transition-v2'
NEW_CONTEXT_KIND = 'rec-ae-b122-full-image-context-v1'
NEW_PRODUCER = 'b122c35046ab1c3cd03828aabd168bb35466e2c8'
P4_MANIFEST_SHA = '7e6ec14d7ace5439355331a78e94c5dfde28804a28704942664cc9775049aaa4'
CANDIDATE_SHA = '7198fc7893cb983354694167923236852fc40558d8ff327489461810a0e026f2'
WORLD_CUSTODY_SHA = '24df2dbb20d014de20ea8973a9aabbb4d29e6731162711fac310266f8364bd78'
DIAGNOSIS_SHA = 'e0ab55804a42a4972cb157c3cd19584b2dae57175a6bb6821bdc4c651823bec9'
NEW_IMAGES = {
    'before': {'size': 14661640, 'sha256': '5a0eedece2116a8dd046bd8337b487bdfc6913eaf1465d3dc6b711d0851ad611'},
    'after': {'size': 14661640, 'sha256': 'ac19e2c554e40219aed043a0760aef2a609743ec0437d295c4f7f15f51886d8f'},
}
NEW_CONTEXT7 = {
    '.config': {'size': 216405, 'sha256': 'f245fc96a9db54159662d86f32e57e86a07106bd029719ad5bdb7af6581e552e'},
    '.config.set': {'size': 288680, 'sha256': '0aa3b0483eb2142a107243fb7695df512de4fee95989ac82ffbc0bdb4f8c716c'},
    '.vermagic': {'size': 33, 'sha256': '555c28901ca8ca4023945b27b62b924fdbb3a2fc951bb234cca9b8ab8b61ec0b'},
    'Module.symvers': {'size': 889880, 'sha256': '405d5e270cb79b7e3acd8d8a0ec8b2c593f86d0a37342e3311a0e0f7ed8dcd41'},
    'modules.builtin.modinfo': {'size': 30961, 'sha256': 'a3e566ab54c5cc030c7c2cb58e9cbadae7264215626c6636061a58a1cea9f6e9'},
    'include/config/kernel.release': {'size': 9, 'sha256': '70ab81f7d2e0021fb2fca26461be33b18a0dc73828a383953ef5693f222b36ed'},
    'include/generated/autoconf.h': {'size': 95984, 'sha256': 'c44e5bc0b47b66fda079278dd8cdab4be33484c232b95b54f48175acc1d85168'},
}

# Exact root-reviewed whole archive pairs; no normalized payload identities.
REBUILT_BANK_POLICY = {'cohort': '612-recommended',
 'source_commit': 'ae65e1de69971b5a2e3cf7e39390ee93f274d488',
 'producer_commit': 'b122c35046ab1c3cd03828aabd168bb35466e2c8',
 'kernel_abi': '6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1',
 'build_id': 'redmi-ax6000-612-recommended-ae65e1de6997-50a1bd72eee1',
 'seed': '3254dd70ea96217f41221b29998780639bbf2e7f33deb735c8bd7b380274c4e3',
 'before_full_Image': {'sha256': '5a0eedece2116a8dd046bd8337b487bdfc6913eaf1465d3dc6b711d0851ad611',
                       'size': 14661640},
 'after_full_Image': {'sha256': 'ac19e2c554e40219aed043a0760aef2a609743ec0437d295c4f7f15f51886d8f',
                      'size': 14661640},
 'before_bank_inventory_sha256': 'eb74353e81799e2ea0451c207fea57ad6297c4613fa159ad555088add44a706d',
 'after_bank_inventory_sha256': '464d804889f430550d84a21bdaee9801043afcb4b1fb1192b2dd9ee30963f946',
 'unchanged_whole_archive_count': 1395,
 'rebuilt_same_path_archive_count': 10,
 'app_transition': {'after': {'path': 'bin/packages/aarch64_cortex-a53/luci/luci-app-attendedsysupgrade-20261021.2-r3.apk',
                              'sha256': '53a62fd5d393d1cfbe903f139b06c7be5a045da2e55bedfcab3fe30566e4bb4e',
                              'size': 12186},
                    'before': {'path': 'bin/packages/aarch64_cortex-a53/luci/luci-app-attendedsysupgrade-20261021.2-r2.apk',
                               'sha256': '9188d87fe19aaf186c4f164b3ff797e97d6df54b4e09c70893ee8af07f541bad',
                               'size': 12186}},
 'kind': 'rec-native-exact-rebuilt-bank-relation-v1',
 'decision_sha256': '1418d193361e2dca9931dec9fe6aef4cace1d8daad838d5b5cdba7b0530ff0aa',
 'proofs': {'after_manifest': {'sha256': 'bceaddf5185120fe57cba4d2ce9a6ce47806569750038bab256e63ae82aa5e17',
                               'size': 301249},
            'archive_diagnosis': {'sha256': '931d8eb4bcc442cb2533c48042b87fe9064c10d60b544f016fbd8b0cff4700c2',
                                  'size': 67068},
            'before_manifest': {'sha256': 'e82ee7868876b37d04ddaf460448d891cb19636c4592c4c99e411593932f8d20',
                                'size': 301249},
            'module_sections': {'sha256': '88023a2b3dbd8ce2af25702bb38c4b4d8722a20aa06778c32cc76b9824e148ca',
                                'size': 16826},
            'module_strings': {'sha256': '6954c6587787faeff0d4388ed61ba32c7238e0223af77904119e887529900f06',
                               'size': 3703},
            'new_IB_approval': {'sha256': '12d0488a8a748f00b7537557c499a04b4a78c8fce98e7f9bd7ae2904cb2e5d39',
                                'size': 4381},
            'new_native_acceptance': {'sha256': 'e7bfbf6ad2698eb05718b0c379c81468b681a5f84b07161d9da252dcc979dbf6',
                                      'size': 10188},
            'new_native_bank': {'sha256': 'ee9e9f5a2893b5b4a5a83e64d9d3fda34aca7cc3f09e160845ccfb7e8c53e5a5',
                                'size': 387515},
            'new_native_evidence': {'sha256': 'c71d134343482bd84c8cb9d465aeebdec38a203d4d53b20730186a3f68da46e0',
                                    'size': 229470}},
 'exact_rebuilt_archives': [{'archive': {'after': {'sha256': '3fd4d51fb8a0e7ae0c98589a3898a867c9b90cc2b6e90f5443db63fad9e21e67',
                                                   'size': 156566},
                                         'before': {'sha256': '8587ef03019f2c28e2468ef9bfc6bd2d05b790c96b8ea31d51d5fdcc92c8e584',
                                                    'size': 156566},
                                         'path': 'bin/packages/aarch64_cortex-a53/luci/luci-base-26.249.28459~d6167ea.apk'},
                             'classification': 'identical-complete-file-payloads-with-exact-recorded-build-mtimes-and-ADB-identity-change'},
                            {'archive': {'after': {'sha256': '929cde658fb0619cd28f775a504aecd135907c8596a825e92d85b9411008e32d',
                                                   'size': 4047},
                                         'before': {'sha256': 'e097f0024b88f053577d493f03478cd1d1088a0040f945bfe0a3d3bed9613c35',
                                                    'size': 4045},
                                         'path': 'bin/packages/aarch64_cortex-a53/luci/luci-i18n-attendedsysupgrade-ru-26.249.28459~d6167ea.apk'},
                             'classification': 'identical-complete-file-payloads-with-exact-recorded-build-mtimes-and-ADB-identity-change'},
                            {'archive': {'after': {'sha256': '49b8ca8d54ea2418872023e6bdc6311b2202969ab91a71c6417ed24e75e3504a',
                                                   'size': 3407},
                                         'before': {'sha256': '77fcc19d616ab842c8e1f3cba9bbb146b2c85b492123e8a414a0229e8e4e26b0',
                                                    'size': 3405},
                                         'path': 'bin/packages/aarch64_cortex-a53/luci/luci-i18n-attendedsysupgrade-zh-cn-26.249.28459~d6167ea.apk'},
                             'classification': 'identical-complete-file-payloads-with-exact-recorded-build-mtimes-and-ADB-identity-change'},
                            {'archive': {'after': {'sha256': '4966a5088a3ca80808201925157f4f7c30b0e88a67e1a1ce4010f0a73604a8d5',
                                                   'size': 82631},
                                         'before': {'sha256': 'aedd42f105c11e9ef52e471634d4313970fc9e0b4b918e031e1046a3bb231758',
                                                    'size': 82634},
                                         'path': 'bin/packages/aarch64_cortex-a53/luci/luci-i18n-base-ru-26.249.28459~d6167ea.apk'},
                             'classification': 'identical-complete-file-payloads-with-exact-recorded-build-mtimes-and-ADB-identity-change'},
                            {'archive': {'after': {'sha256': 'd4f91903a91bd060245f4bd91b5a5cad0c6f12c4d46d1b869cb44bfaabd00672',
                                                   'size': 65617},
                                         'before': {'sha256': '69c19327726062f5bbe6ba576fb71cd75b7b2f1f217f5b71f03e5aa8773aff89',
                                                    'size': 65615},
                                         'path': 'bin/packages/aarch64_cortex-a53/luci/luci-i18n-base-zh-cn-26.249.28459~d6167ea.apk'},
                             'classification': 'identical-complete-file-payloads-with-exact-recorded-build-mtimes-and-ADB-identity-change'},
                            {'archive': {'after': {'sha256': '26866b653c1ce1e075250256807c3a1d24d66bb45e86c167a7ab3a40f101fed8',
                                                   'size': 2543939},
                                         'before': {'sha256': 'e2a2056afaf53f0edb523ca699101f440c7f87ade8f1869a36810b5301d13017',
                                                    'size': 2543950},
                                         'path': 'bin/packages/aarch64_cortex-a53/packages/geoipupdate-8.0.0-r1.apk'},
                             'classification': 'Go-build-ID-descriptor-only-byte-change'},
                            {'archive': {'after': {'sha256': '55d0a1bf6935bdcd431d0a4546273c1caf36154672204232a55342aa9f2bb6e2',
                                                   'size': 2732596},
                                         'before': {'sha256': '1bd9e0208e2bdc1b0a5bcf098bdf92441ba78cac8bceaccc79657e2ef24f1814',
                                                    'size': 2732597},
                                         'path': 'bin/packages/aarch64_cortex-a53/packages/geoview-0.2.6-r1.apk'},
                             'classification': 'Go-build-ID-descriptor-only-byte-change'},
                            {'archive': {'after': {'sha256': '2cfc6ad9987543e4e7927c919ddc52e5bb037f969d28ba99f1402332264acaf8',
                                                   'size': 178216},
                                         'before': {'sha256': 'b29507266eaf9de14034317711fce2d84e0b5f293f40bab0e7aa74743f878650',
                                                    'size': 178186},
                                         'path': 'bin/targets/mediatek/filogic/packages/kmod-oaf-6.12.108.2026.04.20~569f93bf-r1.apk'},
                             'classification': 'nonloaded-debug-buildpath-string-order-and-corresponding-debug-relocations-plus-GNU-build-ID'},
                            {'archive': {'after': {'sha256': '6ffca2ba304716796592510137b5e630d0e407fa0a3fe17f61a3ee1056d4df88',
                                                   'size': 5880},
                                         'before': {'sha256': '9c2389e07f41bb75c5692b5a75de7e501527e8c59b3290b545712cafa55e9187',
                                                    'size': 5862},
                                         'path': 'bin/targets/mediatek/filogic/packages/kmod-usb-serial-dmx_usb_module-6.12.108.19.12.1-r2.apk'},
                             'classification': 'exact-source-buildpath-literal-in-diagnostic-strings-and-only-its-corresponding-relocation-addends'},
                            {'archive': {'after': {'sha256': '5deb200e700bbacc35b0e8477f15fab3015f6adf9efe1ccef19531aecd764af5',
                                                   'size': 21729},
                                         'before': {'sha256': '5ff8a3739555347b40535646c64f7ef6b382a283a0917c6dd17de0a41a14b633',
                                                    'size': 21716},
                                         'path': 'bin/targets/mediatek/filogic/packages/kmod-v4l2loopback-6.12.108.0.15.1-r1.apk'},
                             'classification': 'exact-source-buildpath-literal-in-diagnostic-strings-and-only-its-corresponding-relocation-addends'}]}

# Only the independently measured APP archive/timestamp pair in the new REC context.
APP_METADATA_RELATION = {'kind': 'rec-native-exact-app-metadata-relation-v1',
 'root_decision_sha256': '8b0abb2559ddb67e8683c03acb4dce7f4c0b509d7086a7d8b2e851da3e2dc1c0',
 'diagnosis_sha256': 'c7bb3d44f369dff984014878f7784b3d59f5f48d7224f311d14e3587ac989d83',
 'root_bank_decision_sha256': '1418d193361e2dca9931dec9fe6aef4cace1d8daad838d5b5cdba7b0530ff0aa',
 'archives': {'before': {'sha256': '9188d87fe19aaf186c4f164b3ff797e97d6df54b4e09c70893ee8af07f541bad',
                         'size': 12186},
              'after': {'sha256': '53a62fd5d393d1cfbe903f139b06c7be5a045da2e55bedfcab3fe30566e4bb4e',
                        'size': 12186}},
 'mtime': {'before': 1792597204, 'after': 1792626715},
 'exact_regular_paths': ['etc/uci-defaults/95-luci-app-attendedsysupgrade-housekeeping',
                         'lib/apk/packages/luci-app-attendedsysupgrade.list',
                         'usr/share/luci/menu.d/luci-app-attendedsysupgrade.json',
                         'usr/share/rpcd/acl.d/luci-app-attendedsysupgrade.json',
                         'www/luci-static/resources/ax6000_asu.js',
                         'www/luci-static/resources/view/attendedsysupgrade/configuration.js',
                         'www/luci-static/resources/view/attendedsysupgrade/overview.js',
                         'www/luci-static/resources/view/status/include/11_upgrades.js']}

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



def bank_decision_projection(data):
    """Strip operator-local paths; the whole original root decision is independently pinned."""
    fields = ('cohort', 'source_commit', 'producer_commit', 'kernel_abi', 'build_id', 'seed',
              'before_full_Image', 'after_full_Image', 'before_bank_inventory_sha256',
              'after_bank_inventory_sha256', 'unchanged_whole_archive_count',
              'rebuilt_same_path_archive_count', 'app_transition')
    result = {name: data[name] for name in fields}
    result.update(kind='rec-native-exact-rebuilt-bank-relation-v1',
                  decision_sha256=REBUILT_BANK_POLICY['decision_sha256'],
                  proofs={name: {k: ref[k] for k in ('sha256', 'size')} for name, ref in data['proofs'].items()},
                  exact_rebuilt_archives=[{k: row[k] for k in ('archive', 'classification')}
                                          for row in data['exact_rebuilt_archives']])
    return result


def compare_reviewed_banks(before, after, manifests, relation):
    """Only the ten literal reviewed rebuilt pairs in this complete REC native generation."""
    need(relation == REBUILT_BANK_POLICY, 'Unreviewed exact native bank decision/relation')
    for phase, bank in (('before', before), ('after', after)):
        manifest = manifests[phase]
        need(bank == manifest_bank(manifest) and len(bank) == 1406,
             'Reviewed native bank membership/count differs')
        paths = {row['path']: {k: row[k] for k in ('sha256', 'size')}
                 for row in manifest['files'] if row['path'].endswith('.apk')}
        digest = hashlib.sha256(json.dumps(paths, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        need(digest == relation[phase + '_bank_inventory_sha256'],
             'Reviewed whole native bank path/control/archive identity differs')
    left, right = dict(before), dict(after)
    for phase, bank in (('before', left), ('after', right)):
        app = relation['app_transition'][phase]; leaf = PurePosixPath(app['path']).name
        need(bank.pop(leaf, None) == {k: app[k] for k in ('sha256', 'size')},
             'Reviewed native APP2/APP3 archive differs')
    need(set(left) == set(right), 'Reviewed rebuilt native package membership differs')
    changed = {name: {'before': left[name], 'after': right[name]}
               for name in left if left[name] != right[name]}
    expected = {PurePosixPath(row['archive']['path']).name:
                {phase: row['archive'][phase] for phase in ('before', 'after')}
                for row in relation['exact_rebuilt_archives']}
    need(changed == expected and len(changed) == relation['rebuilt_same_path_archive_count'] == 10
         and len(left) - len(changed) == relation['unchanged_whole_archive_count'] == 1395,
         'Unreviewed rebuilt native archive row/hash/size/count')


def validate_bank_bindings(summary):
    relation = summary.get('bank_transition')
    need(relation == REBUILT_BANK_POLICY, 'Missing exact root-reviewed native bank authority')
    need(summary['functional_image'] == {'before': relation['before_full_Image'], 'after': relation['after_full_Image']}
         and summary['successor_build_id'] == relation['build_id']
         and summary['seeds']['after'] == relation['seed']
         and summary['source_commit'] == relation['source_commit']
         and summary['producer_commit'] == relation['producer_commit'], 'Reviewed bank generation/Image identity differs')
    for phase in ('before', 'after'):
        need(summary[phase + '_metadata']['firmware-manifest.json'] == relation['proofs'][phase + '_manifest'],
             'Reviewed bank native manifest identity differs')
    for field, name in (('native_status', 'new_native_acceptance'), ('native_evidence', 'new_native_evidence'),
                        ('ib_approval', 'new_IB_approval')):
        need(summary['local_proof_sha256']['after'][field] == relation['proofs'][name]['sha256'],
             'Reviewed rebuilt bank independent native/IB proof differs')


def local_bank_decision(ref, left, right, after):
    need(isinstance(ref, dict) and ref.get('sha256') == REBUILT_BANK_POLICY['decision_sha256'],
         'Exact root-reviewed bank decision SHA required')
    data = read_json(checked_ref(ref, 8 * MIB))
    need(data.get('kind') == 'rec-native-exact-rebuilt-bank-root-decision-v1'
         and type(data.get('schema_version')) is int and data['schema_version'] == 1
         and data.get('approved') is True and data.get('artifacts_mutated_or_normalized') is False
         and bank_decision_projection(data) == REBUILT_BANK_POLICY, 'Unreviewed rebuilt native bank decision')
    for proof in data['proofs'].values(): checked_ref(proof, 8 * MIB)
    need(data['proofs']['new_native_acceptance'] == after['native_status']
         and data['proofs']['new_native_evidence'] == after['native_evidence']
         and data['proofs']['new_IB_approval'] == after['ib_approval']
         and all(data['proofs'][phase + '_manifest'] == side['metadata']['firmware-manifest.json']
                 for phase, side in (('before', left), ('after', right))),
         'Root decision binds a different actual native generation')
    relation = copy.deepcopy(REBUILT_BANK_POLICY)
    compare_reviewed_banks(left['bank'], right['bank'],
                           {'before': left['manifest'], 'after': right['manifest']}, relation)
    return relation


def five_context(phase):
    return {**{k: NEW_CONTEXT7[k] for k in ('.config', '.vermagic', 'Module.symvers', 'include/config/kernel.release')},
            'KDIR/Image': NEW_IMAGES[phase]}


def validate_candidate(data):
    """Authenticate the typed candidate separately from any later native acceptance."""
    need(type(data.get('schema_version')) is int and data['schema_version'] == 1
         and data.get('kind') == 'rec-native-candidate-context-p5-v1'
         and data.get('native_acceptance', False) is None and data.get('independently_verified') is False
         and data.get('prior_image_equal') is False and data.get('prior_abi_context_equal') is True
         and data.get('sdk_context_expected') == NEW_CONTEXT7
         and data.get('diagnosis', {}).get('sha256') == DIAGNOSIS_SHA, 'New candidate is not the measured unaccepted REC context')
    old = data.get('original_context', {})
    need(old.get('kind') == 'ax6000-accepted-native-kernel-context-v2' and old.get('source_commit') == SOURCE
         and old.get('cohort') == COHORT and old.get('recipe_commit') == OLD_PRODUCER
         and old.get('kernel_abi') == ABI, 'Candidate original source/cohort differs')
    records = old.get('required_files', {})
    need(set(records) == set(five_context('before'))
         and all({k: row[k] for k in ('sha256', 'size')} == five_context('before')[name]
                 for name, row in records.items()), 'Candidate original complete context differs')
    for row in records.values(): relative(row['path'])
    expected = {'kind': 'rec-native-candidate-owned-context-p5-v1', 'kernel_abi': ABI,
                'required_files': copy.deepcopy(records), 'native_acceptance': None, 'independently_verified': False}
    expected['required_files']['KDIR/Image'].update(NEW_IMAGES['after'])
    need(data.get('owned_context') == expected, 'Candidate changes more than the exact full owned Image')


def new_context_status(status):
    """A schema3 independent verification status, never candidate-only approval."""
    need(type(status.get('schema_version')) is int and status['schema_version'] == 3
         and status.get('kind') == 'ax6000-native-new-context-acceptance-v1'
         and status.get('prior_image_equal') is False and status.get('prior_abi_context_equal') is True
         and status.get('strict_accepted_context_unchanged') is False
         and status.get('strict_new_context_unchanged') is True
         and status.get('original_source_readonly_guards_passed') is True
         and status.get('prior_kernel_image') == NEW_IMAGES['before']
         and status.get('accepted_kernel_image') == NEW_IMAGES['after']
         and status.get('prior_context') == status.get('original_source_context_before')
         == status.get('original_source_context_after') == five_context('before')
         and status.get('strict_context_before') == status.get('strict_context_after') == five_context('after')
         and status.get('source_context7') == NEW_CONTEXT7
         and type(status.get('container_exit_code')) is int and status['container_exit_code'] == 0
         and status.get('oom_killed') is False and status.get('full_native_verifier_unchanged') is True,
         'Actual independent new-context acceptance and truthful prior Image scope required')
    need(isinstance(status.get('original_source'), str) and Path(status['original_source']).is_absolute(),
         'Original source identity required')
    for name in ('candidate_context', 'world_success_custody', 'producer_completion', 'native_evidence'):
        checked_ref(status.get(name), 8 * MIB)
    need(status['candidate_context']['sha256'] == CANDIDATE_SHA
         and status['world_success_custody']['sha256'] == WORLD_CUSTODY_SHA,
         'New independent status references an unreviewed candidate or world custody')


def world_custody(ref):
    """Pin failed P4 history and its immutable checked-world call graph, not a fake completed world."""
    need(isinstance(ref, dict) and ref.get('sha256') == WORLD_CUSTODY_SHA, 'Unreviewed P4 world custody')
    data = read_json(checked_ref(ref, 8 * MIB))
    need(type(data.get('schema_version')) is int and data['schema_version'] == 1
         and data.get('kind') == 'rec-native-world-success-custody-v1'
         and data.get('producer_commit') == NEW_PRODUCER and data.get('source_commit') == SOURCE
         and data.get('world_command_exit_zero_inferred') is True and data.get('raw_process_wait_status', False) is None
         and data.get('producer_completed') is False and type(data.get('producer_exit_code')) is int
         and data['producer_exit_code'] == 1 and data.get('native_acceptance', False) is None,
         'P4 world custody must retain the actual failed producer and inferred subprocess scope')
    need(data['diagnosis']['sha256'] == DIAGNOSIS_SHA
         and data['runner_manifest']['sha256'] == P4_MANIFEST_SHA,
         'Unknown P4 diagnosis or immutable checked-world launcher')
    diagnosis = read_json(checked_ref(data['diagnosis'], 8 * MIB))
    manifest = read_json(checked_ref(data['runner_manifest'], 8 * MIB))
    need(set(data['producer_code']) == set(manifest['code']), 'Incomplete immutable P4 code custody')
    for name, row in data['producer_code'].items():
        checked_ref(row, 8 * MIB)
        need({k: row[k] for k in ('sha256', 'size')} == manifest['code'][name], 'P4 immutable code changed')
    for key, name in (('build_script', 'build.sh'), ('world_executor', 'world.py'), ('world_argv', 'world-argv.json')):
        need(data[key] == data['producer_code'][name], 'P4 checked world call graph differs')
    for key, name in (('producer_completion', 'producer-completion.json'), ('producer_inspect', 'output/terminal-inspect.json'),
                      ('result', 'output/result.json'), ('build_log', 'output/build.log')):
        checked_ref(data[key], 64 * MIB)
        need({k: data[key][k] for k in ('sha256', 'size')}
             == {k: diagnosis['inputs'][name][k] for k in ('sha256', 'size')}, 'P4 actual failure evidence differs')
    inspected, result, completion = (read_json(data[k]['path']) for k in ('producer_inspect', 'result', 'producer_completion'))
    state = inspected['State']
    need(inspected.get('Id') == '002de6aea85d64daa3e6098ad19019b7e7d12a37822c9f5963cefcffa6ad4fa0'
         and state.get('Status') == 'exited' and state.get('Running') is False and state.get('OOMKilled') is False
         and type(state.get('ExitCode')) is int and state['ExitCode'] == 1
         and type(result.get('exit_code')) is int and type(result.get('child_exit_code')) is int
         and result['exit_code'] == result['child_exit_code'] == 1 and result.get('termination_reason', False) is None
         and completion.get('completed') is False and completion.get('native_evidence', False) is None
         and completion.get('producer_commit') == NEW_PRODUCER and completion.get('source_commit') == SOURCE
         and len(completion.get('stages', [])) == 1 and completion['stages'][0].get('steps') == [],
         'P4 failure was relabelled as successful native production')
    need(diagnosis.get('world_shell_succeeded_before_strict_guard') is True
         and diagnosis.get('producer_completed') is False and diagnosis.get('full_Image_equal') is False
         and diagnosis.get('byte_normalization_performed') is False
         and data.get('guard_failure') == {'role': 'KDIR/Image', 'after_phase': 'after-world',
                                          'expected': NEW_IMAGES['before'], 'observed': NEW_IMAGES['after']},
         'P4 checked-world/strict-guard scope differs')
    for role, row in diagnosis['SDK7'].items():
        need(role in NEW_CONTEXT7 and all({k: row[phase][k] for k in ('sha256', 'size')} == NEW_CONTEXT7[role]
                                        for phase in ('current', 'original')), 'P4 diagnosed SDK context differs')
    need(set(diagnosis['SDK7']) == set(NEW_CONTEXT7), 'P4 diagnosed SDK7 incomplete')
    return data


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


def packaging_completion(data, before, after, right, staging):
    """Successful P5 IB/export with separately authenticated failed-P4 world custody."""
    fields = {'schema_version', 'kind', 'producer_commit', 'source_commit', 'completed', 'native_evidence',
              'staging_receipt', 'candidate_context', 'world_success_custody', 'raw_metadata4', 'stages', 'phase_receipts'}
    need(isinstance(data, dict) and set(data) == fields and type(data['schema_version']) is int
         and data['schema_version'] == 1 and data['kind'] == 'rec-native-packaging-completion-v1'
         and data['producer_commit'] == NEW_PRODUCER and data['source_commit'] == SOURCE
         and data['completed'] is True and data['native_evidence'] is None
         and data['raw_metadata4'] == right['metadata'] and data['staging_receipt'] == staging,
         'Actual completed P5 packaging and exact native metadata required')
    for ref in [staging, *right['metadata'].values()]: checked_ref(ref, 8 * MIB)
    need(isinstance(data['candidate_context'], dict) and data['candidate_context'].get('sha256') == CANDIDATE_SHA,
         'P5 candidate must be the exact reviewed new context')
    candidate = read_json(checked_ref(data['candidate_context'], 8 * MIB)); validate_candidate(candidate)
    world = world_custody(data['world_success_custody'])
    need(candidate['diagnosis'] == world['diagnosis']
         and all(right['status'].get(name) == data[name] for name in ('candidate_context', 'world_success_custody')),
         'P5 candidate/world custody differs from independent native acceptance')
    stages = data['stages']
    need(isinstance(stages, list) and len(stages) == 1 and set(stages[0]) == {'steps', 'inspect'}
         and stages[0]['steps'] == ['imagebuilder', 'export'], 'P5 must not claim a completed world production stage')
    inspected = read_json(checked_ref(stages[0]['inspect'], 8 * MIB))
    if isinstance(inspected, list):
        need(len(inspected) == 1, 'Ambiguous P5 producer inspection'); inspected = inspected[0]
    state = inspected.get('State', {})
    need(re.fullmatch('[0-9a-f]{64}', inspected.get('Id', ''))
         and state.get('Status') == 'exited' and state.get('Running') is False
         and state.get('OOMKilled') is False and type(state.get('ExitCode')) is int and state['ExitCode'] == 0,
         'P5 packaging did not actually exit successfully')
    phases = ('before-packaging', 'after-imagebuilder', 'after-export')
    need(isinstance(data['phase_receipts'], dict) and set(data['phase_receipts']) == set(phases),
         'All three actual P5 packaging phase receipts required')
    current = {name: after['source_context'][name] for name in five_context('after')}
    original = {name: before['source_context'][name] for name in five_context('before')}
    seven = {name: after['source_context'][name] for name in SDK_ROLES}
    observed = {}
    for name in phases:
        phase = read_json(checked_ref(data['phase_receipts'][name], 8 * MIB)); observed[name] = phase
        need(phase.get('phase') == name and phase.get('native_context') == current
             and phase.get('original_native_context') == original and phase.get('source_context7') == seven
             and phase.get('source_config_sha256') == right['metadata']['build.config']['sha256']
             and phase.get('original_source_readonly_guards_passed') is True
             and phase.get('prior_owned_Image_byte_identity') is False and phase.get('candidate_context') is True
             and phase.get('native_acceptance', False) is None, 'Actual new/original P5 phase context differs: ' + name)
    for ref in [*current.values(), *original.values(), *seven.values(), *after['sdk_context'].values()]:
        checked_ref(ref, 64 * MIB)
    pre = observed['before-packaging'].get('source_bin'); built = observed['after-imagebuilder'].get('source_bin')
    ib = 'bin/targets/mediatek/filogic/' + right['profile']['imagebuilder']['url'].rsplit('/', 1)[-1]
    need(isinstance(pre, dict) and isinstance(built, dict) and ib in pre and set(pre) == set(built)
         and all(pre[name] == built[name] for name in pre if name != ib),
         'P5 packaging changes native bank/firmware beyond the actual IB archive')
    pristine = observed['after-imagebuilder'].get('pristine_imagebuilder', {})
    need(built[ib] == pristine.get('archive'),
         'P5 after-imagebuilder archive differs from its actual pristine IB proof')
    expected = {row['path']: {k: row[k] for k in ('sha256', 'size')} for row in right['manifest']['files']}
    apks = {name: row for name, row in expected.items() if name.endswith('.apk')}
    need(apks and {name: row for name, row in pre.items() if name.endswith('.apk')} == apks,
         'P5 before-packaging bank is not the actual final native bank')
    export = observed['after-export'].get('export', {})
    need(export.get('source_equals_raw_current_final_archives') is True
         and export.get('sdk_context') == after['sdk_context']
         and export.get('sdk', {}).get('sha256') == right['profile']['sdk']['sha256']
         and export.get('imagebuilder') == {k: right['profile']['imagebuilder'][k] for k in ('sha256', 'size')},
         'P5 final actual SDK/IB/context binding differs')
    sums = {'bin/targets/mediatek/filogic/' + n for n in ('sha256sums', 'SHA256SUMS')}
    actual = export.get('source_bin', {})
    need(set(actual) - sums == set(expected) - sums
         and all(actual[name] == row for name, row in expected.items() if name not in sums)
         and actual.get(ib) == {k: right['profile']['imagebuilder'][k] for k in ('sha256', 'size')},
         'P5 final complete source/RAW inventory differs')
    return {'candidate_context_sha256': data['candidate_context']['sha256'],
            'world_success_custody_sha256': data['world_success_custody']['sha256']}


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


def new_status_bank(status, side, bank):
    """Bind schema3's complete independently decoded control inventory to actual whole archives."""
    path = regular(Path(side['native_status']['path']).parent / 'native-bank.json', 8 * MIB)
    need(identity(path)['sha256'] == status.get('native_bank_sha256'), 'New native bank proof digest differs')
    proof = read_json(path); rows = proof.get('packages')
    need(proof.get('all_packages_verified') is True and proof.get('kernel_abi') == ABI
         and type(proof.get('count')) is int and proof['count'] == 1406
         and type(proof.get('kmods')) is int and proof['kmods'] == 1079
         and isinstance(rows, list) and len(rows) == len(bank) == 1406, 'Complete accepted REC native bank proof required')
    actual, names, paths = {}, set(), set()
    for row in rows:
        need(isinstance(row, dict) and set(row) == {'path', 'package', 'version', 'sha256', 'size'}, 'Malformed decoded native bank row')
        name = relative(row['path']); leaf = PurePosixPath(name).name
        need(name.startswith('bin/') and name.endswith('.apk') and name not in paths and leaf not in actual
             and isinstance(row['package'], str) and row['package'] and row['package'] not in names
             and isinstance(row['version'], str) and row['version'], 'Ambiguous decoded native package inventory')
        actual[leaf] = {k: row[k] for k in ('sha256', 'size')}; names.add(row['package']); paths.add(name)
    need(actual == bank and sum(name.startswith('kmod-') for name in names) == 1079,
         'Independent full native control inventory differs from actual manifest archives')


def side_records(side, *, context_transition=None):
    need(context_transition in (None, NEW_CONTEXT_KIND), 'Unknown native context enrollment route')
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
    if context_transition is None:
        need(status.get('kind') == 'ax6000-native-completion-acceptance-v2' and status.get('schema_version') == 2
             and status.get('ok') is True and status.get('all_layouts_verified') is True
             and status.get('strict_accepted_context_unchanged') is True, 'Actual completed native acceptance required')
    else:
        new_context_status(status)
        need(side['producer_commit'] == NEW_PRODUCER and status.get('ok') is True
             and status.get('all_layouts_verified') is True and status.get('channel') == 'recommended'
             and status.get('cohort') == COHORT and status.get('package_manager') == 'apk',
             'New context requires independent accepted REC/b122 native verification')
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
    if context_transition is not None:
        need(source_records == NEW_CONTEXT7 and status.get('source') == side['source']
             and status.get('raw') == side['raw'] and status.get('sdk') == profile['sdk']
             and status.get('native_evidence') == side['native_evidence']
             and status.get('sdk_baseline') == side['sdk_baseline']
             and status.get('native_input_records') == {row['path']: {k: row[k] for k in ('sha256', 'size')}
                                                        for row in metadata.values()},
             'Independent new-context status does not bind actual source/RAW/SDK/evidence')
    kernel = Path(side['source']) / relative(evidence['sdk_context']['kernel_relative_path'])
    for name in SDK_ROLES:
        need(side['source_context'][name]['path'] == str(kernel / name), 'Actual source context path differs')
    image = identity(checked_ref(side['source_context']['KDIR/Image'], 64 * MIB))
    need(side['source_context']['KDIR/Image']['path'] == str(kernel.parent / 'Image')
         and image == (IMAGES['after'] if context_transition is None else NEW_IMAGES['after'])
         and image == {k: evidence.get('sysupgrade_input', {}).get(k) for k in ('sha256', 'size')},
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
    if context_transition is not None:
        new_status_bank(status, side, bank)
        need(all(len(item['root']['installed_packages']) == 293 for item in evidence['layouts'].values()),
             'Actual new native layout databases differ')
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
            'bank': bank, 'baseline': baseline, 'context': source_records, 'image': image, 'status': status}


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



def reviewed_app_paths(paths):
    """Permit exactly the eight measured timestamp pairs, preserving all other metadata."""
    views = {}
    for phase in ('before', 'after'):
        view = copy.deepcopy(paths[phase]); seen = set()
        for directory in view:
            for item in directory.get('files', []):
                name = (directory.get('name', '') + '/' + item['name']).lstrip('/')
                need(name in APP_METADATA_RELATION['exact_regular_paths'] and name not in seen
                     and type(item.get('mtime')) is int
                     and item['mtime'] == APP_METADATA_RELATION['mtime'][phase],
                     'APP timestamp/path differs from the exact reviewed eight-file relation')
                seen.add(name)
                # This comparison view is never written back to APKs or published metadata.
                item['mtime'] = APP_METADATA_RELATION['mtime']['before']
                if name == MODULE:
                    item.pop('hash', None); item.pop('size', None)
        need(seen == set(APP_METADATA_RELATION['exact_regular_paths']), 'Reviewed APP file inventory differs')
        views[phase] = view
    need(views['before'] == views['after'], 'Native APP modes/owners/hooks/path metadata changed')


def app_payload_new_context(before, after, apk_ref):
    """Finite new-context APP archive pair; the original V1 app_payload remains strict."""
    need(before.get('producer_commit') == OLD_PRODUCER and after.get('producer_commit') == NEW_PRODUCER,
         'Reviewed APP metadata relation is restricted to the enrolled REC producers')
    apk = checked_ref(apk_ref, 8 * MIB)
    need(apk_ref['sha256'] == 'ec6f3df6b3e295ad4395649bfd5bc5ca8f2afe52c8fe7bff04df3617f78952f8',
         'Exact trusted EC6 APK required')
    fmt = module('package_format'); controls, payloads, paths = {}, {}, {}
    for phase, side, release in [('before', before, '2'), ('after', after, '3')]:
        row = REBUILT_BANK_POLICY['app_transition'][phase]
        path = regular(Path(side['raw']) / relative(row['path']), 16 * MIB)
        need(identity(path) == APP_METADATA_RELATION['archives'][phase]
             == {k: row[k] for k in ('sha256', 'size')}, 'Exact reviewed native APP archive differs')
        need(not apk.is_relative_to(Path(side['raw'])) and not apk.is_relative_to(Path(side['source'])),
             'RAW/native tool must not execute')
        control = fmt.read_control(path, apk=apk)
        need(control.get('Package') == 'luci-app-attendedsysupgrade'
             and control.get('Version') == '20261021.2-r' + release, 'Actual native APP control differs')
        controls[phase] = {k: v for k, v in control.items() if k not in ('Version', 'Installed-Size', 'APK-Raw')}
        controls[phase]['APK-Raw-policy'] = {k: v for k, v in control['APK-Raw'].items()
                                           if k not in ('version', 'hashes', 'installed-size')}
        paths[phase] = fmt.apk_json(path, apk)['paths']
        payloads[phase] = fmt.payload_files(path, apk=apk)
    need(controls['before'] == controls['after'], 'Native APP controls changed beyond the reviewed revision')
    reviewed_app_paths(paths)
    need(hashlib.sha256(payloads['after'].get(MODULE, b'')).hexdigest() == MODULE_SHA,
         'Actual APP payload is not the reviewed constructor module')
    need(set(payloads['before']) == set(payloads['after']) == set(APP_METADATA_RELATION['exact_regular_paths'])
         and {k: v for k, v in payloads['before'].items() if k != MODULE}
         == {k: v for k, v in payloads['after'].items() if k != MODULE},
         'Native APP changed unrelated regular payloads/hooks')


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
    if isinstance(inputs, dict) and inputs.get('schema_version') == 2:
        fields.add('bank_transition_decision')
    need(isinstance(inputs, dict) and set(inputs) == fields and type(inputs['schema_version']) is int
         and ((inputs['schema_version'] == 1 and inputs['kind'] == 'rec-native-apk-replacement-inputs-v1')
              or (inputs['schema_version'] == 2 and inputs['kind'] == 'rec-native-apk-replacement-inputs-v2')),
         'Exact actual native replacement inputs required; pending/null staging cannot pass')
    new_context = inputs['schema_version'] == 2
    before, after = inputs['before'], inputs['after']
    need(isinstance(before, dict) and isinstance(after, dict) and before.get('producer_commit') == OLD_PRODUCER
         and isinstance(after.get('producer_commit'), str) and re.fullmatch('[0-9a-f]{40}', after['producer_commit'])
         and after['producer_commit'] != OLD_PRODUCER, 'Actual old/new native producers required')
    if new_context:
        need(after.get('producer_commit') == NEW_PRODUCER, 'New REC context is restricted to the measured b122 producer')
    left = side_records(before)
    right = side_records(after, context_transition=NEW_CONTEXT_KIND) if new_context else side_records(after)
    validate_profiles(left['profile'], right['profile'])
    if new_context:
        bank_relation = local_bank_decision(inputs['bank_transition_decision'], left, right, after)
    else:
        compare_banks(left['bank'], right['bank'])
    for name in ('protected_packages', 'frozen_packages', 'frozen_kmods'):
        need(left['baseline'][name] == right['baseline'][name], 'Native SDK protected/frozen package set changed')
    if new_context:
        need(left['context'] == right['context'] == NEW_CONTEXT7
             and left['image'] == NEW_IMAGES['before'] and right['image'] == NEW_IMAGES['after'],
             'New REC enrollment changes the measured whole-Image pair or ABI context')
    else:
        need(left['image'] == right['image'], 'Whole accepted functional native Image changed')
    need(left['context'] == right['context']
         and left['manifest'].get('source_patches', []) == right['manifest'].get('source_patches', [])
         and {k: left['metadata']['build.config'][k] for k in ('sha256', 'size')}
         == {k: right['metadata']['build.config'][k] for k in ('sha256', 'size')},
         'Native ABI/config/source patch ledger changed')
    staging = read_json(checked_ref(inputs['staging_receipt'], 8 * MIB))
    if new_context:
        # The genuine initial staging copy contained the old Image on both sides.
        # This historical view never replaces the actually verified new source context.
        copied_after = copy.deepcopy(after)
        copied_after['source_context']['KDIR/Image'] = {**before['source_context']['KDIR/Image'],
                                                        'path': after['source_context']['KDIR/Image']['path']}
        images = staged_source(staging, before, copied_after)
        need(right['status'].get('original_source') == before['source']
             and right['status'].get('producer_completion') == inputs['production_receipt'],
             'Independent new acceptance binds a different original source or P5 completion')
        transition_refs = packaging_completion(read_json(checked_ref(inputs['production_receipt'], 8 * MIB)),
                                               before, after, right, inputs['staging_receipt'])
    else:
        images = staged_source(staging, before, after)
        production_completion(read_json(checked_ref(inputs['production_receipt'], 8 * MIB)), after['producer_commit'],
                              right['metadata'], after['native_evidence'], inputs['staging_receipt'],
                              after['source_context'], after['sdk_context'], right['profile'], right['manifest'])
    root_delta(left['evidence'], right['evidence'], images)
    if new_context:
        app_payload_new_context(before, after, inputs['trusted_apk'])
    else:
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
    if new_context:
        summary.update(prior_image_equal=False, functional_image=copy.deepcopy(NEW_IMAGES),
                       bank_transition=bank_relation, unchanged_native_archives=1395)
        summary['context_transition'] = {
            'kind': NEW_CONTEXT_KIND, 'cohort': COHORT, 'source_commit': SOURCE, 'kernel_abi': ABI,
            'producer_commit': NEW_PRODUCER, 'diagnosis_sha256': DIAGNOSIS_SHA,
            'prior_image_equal': False, 'functional_image': copy.deepcopy(NEW_IMAGES), 'context7': left['context'],
            'native_acceptance_sha256': after['native_status']['sha256'], **transition_refs,
            'production_receipt_sha256': inputs['production_receipt']['sha256'],
            'prior_world_producer_completed': False, 'prior_world_process_wait_status': None,
            'prior_world_exit_code': 1, 'world_command_exit_zero_inferred': True,
            'app_metadata_relation': copy.deepcopy(APP_METADATA_RELATION)}
        validate_new_summary(summary)
    return left['profile'], right['profile'], summary


def validate_new_summary(summary):
    """Only the measured REC/b122 full-Image pair; candidate facts alone never approve it."""
    need(summary.get('prior_image_equal') is False and summary.get('functional_image') == NEW_IMAGES
         and summary.get('native_context') == NEW_CONTEXT7 and summary.get('producer_commit') == NEW_PRODUCER,
         'New REC context requires the exact distinct complete Images and all seven ABI roles')
    transition = summary.get('context_transition')
    fields = {'kind', 'cohort', 'source_commit', 'kernel_abi', 'producer_commit', 'diagnosis_sha256',
              'prior_image_equal', 'functional_image', 'context7', 'native_acceptance_sha256',
              'candidate_context_sha256', 'world_success_custody_sha256', 'production_receipt_sha256',
              'prior_world_producer_completed', 'prior_world_process_wait_status', 'prior_world_exit_code',
              'world_command_exit_zero_inferred', 'app_metadata_relation'}
    need(isinstance(transition, dict) and set(transition) == fields
         and transition['kind'] == NEW_CONTEXT_KIND and transition['cohort'] == COHORT
         and transition['source_commit'] == SOURCE and transition['kernel_abi'] == ABI
         and transition['producer_commit'] == NEW_PRODUCER and transition['diagnosis_sha256'] == DIAGNOSIS_SHA
         and transition['prior_image_equal'] is False and transition['functional_image'] == NEW_IMAGES
         and transition['context7'] == NEW_CONTEXT7, 'Unknown or unmeasured new native context relation')
    need(transition['native_acceptance_sha256'] == summary['local_proof_sha256']['after']['native_status']
         and transition['production_receipt_sha256'] == summary['production_receipt_sha256']
         and transition['candidate_context_sha256'] == CANDIDATE_SHA
         and transition['world_success_custody_sha256'] == WORLD_CUSTODY_SHA
         and all(isinstance(transition[k], str) and SHA.fullmatch(transition[k]) for k in
                 ('native_acceptance_sha256', 'candidate_context_sha256', 'world_success_custody_sha256', 'production_receipt_sha256')),
         'New context requires actual independent acceptance and packaging/world custody digests')
    need(transition['app_metadata_relation'] == APP_METADATA_RELATION,
         'Unreviewed native APP archive/timestamp authority')
    validate_bank_bindings(summary)
    need(transition['prior_world_producer_completed'] is False
         and transition['prior_world_process_wait_status'] is None
         and type(transition['prior_world_exit_code']) is int and transition['prior_world_exit_code'] == 1
         and transition['world_command_exit_zero_inferred'] is True,
         'P4 failed completion or inferred checked world status was relabelled')


def load_receipt(old, new, path, pin):
    validate_profiles(old, new)
    need(isinstance(pin, str) and SHA.fullmatch(pin), 'Explicit reviewed native replacement proof SHA required')
    path = regular(path, 8 * MIB)
    need(identity(path)['sha256'] == pin, 'Reviewed native replacement proof SHA differs')
    proof = read_json(path)
    need(isinstance(proof, dict) and set(proof) == {'schema_version', 'kind', 'summary'}
         and type(proof['schema_version']) is int
         and ((proof['schema_version'] == 1 and proof['kind'] == KIND)
              or (proof['schema_version'] == 2 and proof['kind'] == NEW_KIND)),
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
    if proof['schema_version'] == 2:
        fields |= {'prior_image_equal', 'context_transition', 'bank_transition'}
    need(set(summary) == fields, 'Unexpected portable native approval fields')
    migration = module('kernel_migration')
    if proof['schema_version'] == 2:
        validate_new_summary(summary)
    else:
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
    if proof['schema_version'] == 2:
        compare_reviewed_banks(left, right, manifests, summary['bank_transition'])
        unchanged = len(left) - 11
    else:
        compare_banks(left, right)
        unchanged = len(left) - 1
    need(type(summary['unchanged_native_archives']) is int and summary['unchanged_native_archives'] == unchanged
         and type(summary['protected_baseline_packages']) is int and 0 < summary['protected_baseline_packages'] <= len(left)
         and summary['before_metadata']['build.config'] == summary['after_metadata']['build.config'], 'Native protected/archive/config facts differ')
    return summary


def validate_payloads(old_tree, new_tree, summary, read, transport, cache, budget):
    """Reuse the existing bounded immutable-asset decoder; no local operator paths."""
    proof = {'predecessor_build_id': summary['predecessor_build_id'], 'successor_build_id': summary['successor_build_id'],
             'functional_image': (summary['functional_image'] if summary.get('prior_image_equal') is False
                                  else {phase: summary['functional_image'] for phase in ('before', 'after')}),
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
    new_context = summary.get('prior_image_equal') is False
    value = {'schema_version': 2 if new_context else 1, 'kind': NEW_KIND if new_context else KIND, 'summary': summary}
    with args.output.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps(full_ref(args.output)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        sys.exit('native-generation: ' + str(error))
