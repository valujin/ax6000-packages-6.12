#!/usr/bin/env python3
"""Signed immutable channel snapshots and atomic two-channel Pages composition."""
import argparse
import base64
import gzip
import hashlib
import html
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CHANNELS = ('recommended', 'latest')
MAX_SITE = 1_000_000_000
MAX_ASSET = 2 * 1024 ** 3 - 1
MAX_MEMBERS = 100000
METADATA = {'profile.json','repository.pub','downloads.json','downloads.sig','index.html','.nojekyll',
            'build-selection.json','build-provenance.json','firmware-manifest.json','build.config'}
APK_METADATA = {'profile.sig', 'repository-apk.pem', 'native-providers.json'}
_MIGRATION_IMAGE_CACHE = {}
_MIGRATION_DOWNLOAD_BUDGET = {'used': 0}


def apk_options(apk):
    return {} if apk is None else {'apk': apk}


def apk_publication_args(profile, apk, apk_key, apk_public_key):
    if module('package_format').manager(profile) != 'apk':
        return []
    if any(value is None for value in (apk, apk_key, apk_public_key)):
        raise ValueError('APK publication requires --apk, --apk-key and --apk-public-key')
    module('publish').validate_apk_signer(profile, apk_key, apk_public_key)
    return ['--apk', str(apk), '--apk-key', str(apk_key), '--apk-public-key', str(apk_public_key)]


def module(name):
    spec = importlib.util.spec_from_file_location('snapshot_'+name, ROOT/'scripts'/(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def sha256_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def canonical_json(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def read_json(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8*1024**2:
        raise ValueError('Missing, linked or oversized metadata')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('Duplicate JSON field')
            result[key]=value
        return result
    return json.loads(path.read_text(),object_pairs_hook=unique)


def verify(message,signature,public_key,usign):
    subprocess.run([str(usign),'-V','-m',str(message),'-p',str(public_key),'-x',str(signature)],
                   check=True,capture_output=True)


def signing_key(key,public_key):
    publisher=module('publish')
    derived=publisher.public_key_payload(publisher.public_from_secret(key))
    if derived != publisher.public_key_payload(Path(public_key).read_text()):
        raise ValueError('Signing key differs from pinned public key')


def sign(message,signature,key,public_key,usign):
    signing_key(key,public_key)
    subprocess.run([str(usign),'-S','-m',str(message),'-s',str(key),'-x',str(signature)],
                   check=True,capture_output=True)
    verify(message,signature,public_key,usign)


def fresh(path):
    path=Path(path)
    if path.exists() or path.is_symlink():raise ValueError('Output must be a fresh directory')
    if any(parent.is_symlink() for parent in path.parents):raise ValueError('Linked output ancestor')
    return path


def channel_identity(profile,lock,channel,repository):
    if channel not in CHANNELS or profile.get('channel') != channel or profile.get('id') != 'redmi-ax6000-612-'+channel:
        raise ValueError('Wrong channel/profile identity')
    if profile.get('schema_version') != 1 or profile.get('enabled') is not True:
        raise ValueError('Channel profile must be enabled schema 1')
    if profile.get('publication',{}).get('repository') != repository:
        raise ValueError('Wrong publication repository')
    publisher=module('publish')
    publisher.firmware_build_id(profile)
    if lock.get('schema_version') != 1 or lock.get('profile_id') != profile['id']:
        raise ValueError('Wrong channel lock identity')
    if lock.get('firmware') != profile['firmware'] or lock.get('sdk') != profile['sdk']:
        raise ValueError('Profile/lock generation mismatch')
    if lock.get('feeds',{}).get('base') != profile['firmware']['commit']:
        raise ValueError('Moving or mismatched base feed')
    if module('package_format').manager(profile)=='apk':
        if lock.get('package_manager')!='apk' or lock.get('apk_key_sha256')!=profile.get('apk_key_sha256'):
            raise ValueError('Channel APK profile/lock identity mismatch')


def cohort(profile):
    result = {key:profile[key] for key in ('id','channel','build_id','firmware','sdk')}
    if profile.get('package_manager', 'opkg') == 'apk':
        result.update(package_manager='apk', apk_key_sha256=profile.get('apk_key_sha256'))
    return result



def validate_generation_replacement(old,new,expected_build_id,*,allow_asu_apk_migration=False,migration_proof=None,
                                    allow_native_apk_replacement=False,native_replacement_proof=None,native_replacement_proof_sha256=None):
    """Authorize one same-ABI cohort replacement, never a moving kernel update."""
    if not expected_build_id or old.get('build_id')!=expected_build_id:
        raise ValueError('Replacement predecessor build ID differs from explicit authorization')
    if new.get('build_id')==expected_build_id or new.get('sdk')==old.get('sdk'):
        raise ValueError('Replacement must have a new build ID and SDK')
    if allow_native_apk_replacement:
        if allow_asu_apk_migration or migration_proof is not None:raise ValueError('Native replacement and OPKG migration are mutually exclusive')
        module('native_generation').load_receipt(old,new,native_replacement_proof,native_replacement_proof_sha256)
        return
    if native_replacement_proof is not None or native_replacement_proof_sha256 is not None:
        raise ValueError('Native replacement proof requires its explicit native flag')
    if allow_asu_apk_migration:
        validate_asu_apk_migration(old,new)
        validate_migration_proof(old,new,migration_proof)
        return
    allowed={'build_id','sdk','image_packages','package_only'}
    if {k:v for k,v in old.items() if k not in allowed}!={k:v for k,v in new.items() if k not in allowed}:
        raise ValueError('Replacement changes profile/source/kernel ABI/architecture/layouts or requested packages')
    if old.get('package_only',[]) not in ([],['tailscale']) or new.get('package_only')!=['tailscale']:
        raise ValueError('Replacement must preserve the reviewed Tailscale package-only policy')
    images=old.get('image_packages')
    if not isinstance(images,list) or new.get('image_packages')!=[name for name in images if name!='tailscale']:
        raise ValueError('Replacement changes image packages beyond removing Tailscale')
    if 'tailscale' not in new.get('packages',[]):
        raise ValueError('Replacement must retain the downloadable Tailscale package')


def validate_asu_apk_migration(old,new):
    """One explicit OPKG→new-firmware APK/ASU transition with fixed source ABI.

    This authorization only widens the reviewed manual publication path. Daily
    composition still rejects every generation change. It does not authorize
    changing requested applications or replacing a live router's package manager.
    """
    allowed={'build_id','sdk','imagebuilder','asu','package_manager','apk_key_sha256',
             'pbr_source','vendor_country_db','packages','image_packages','package_only'}
    if {k:v for k,v in old.items() if k not in allowed}!={k:v for k,v in new.items() if k not in allowed}:
        raise ValueError('ASU/APK migration changes source/kernel ABI/architecture/layouts or unrelated policy')
    if old.get('package_manager','opkg')!='opkg' or new.get('package_manager')!='apk' or old.get('asu') is not None:
        raise ValueError('ASU/APK migration requires an existing OPKG generation and a new APK generation')
    policy=module('asu_client').policy(new)
    if policy is None or policy['cohort']!='612-'+new['channel']:
        raise ValueError('ASU/APK migration requires the exact cohort ASU policy')
    if new.get('pbr_source')!='mossdef-stable' or new.get('vendor_country_db') is not True:
        raise ValueError('ASU/APK migration requires reviewed PBR and vendor country policies')
    if new.get('apk_key_sha256')!=sha256_file(ROOT/'keys/repository-apk.pem'):
        raise ValueError('ASU/APK migration APK key differs from reviewed repository key')
    ib=new.get('imagebuilder',{})
    if (not isinstance(ib,dict) or not re.fullmatch(r'[a-f0-9]{64}',ib.get('sha256',''))
            or type(ib.get('size')) is not int or ib['size']<=0
            or not ib.get('url','').startswith('https://github.com/'+new['publication']['repository']+'/releases/download/firmware-'+new['build_id']+'/')):
        raise ValueError('ASU/APK migration requires a new immutable matching ImageBuilder')
    required=set(module('asu_client').REQUIRED_PACKAGES)
    for field in ('packages','image_packages'):
        before=old.get(field);after=new.get(field)
        if (not isinstance(before,list) or not isinstance(after,list) or len(after)!=len(set(after))
                or set(after)!=set(before)|required or [name for name in after if name not in required]!=before):
            raise ValueError('ASU/APK migration may add only the reviewed three ASU client packages')
    if old.get('package_only')!=['tailscale'] or new.get('package_only')!=['tailscale'] or 'tailscale' in new['image_packages']:
        raise ValueError('ASU/APK migration must preserve the Tailscale package-only policy')


def validate_migration_proof(old,new,proof):
    """Require an operator-supplied actual native byte comparison receipt.

    The receipt is local reviewed authorization, not a replacement for archive
    verification. The required Image hash is over the uncompressed kernel bytes
    extracted from each real firmware image, never over an APK/IPK container.
    """
    if not isinstance(proof,dict):
        raise ValueError('ASU/APK migration requires an explicit native migration proof')
    version=proof.get('schema_version')
    expected={'schema_version':2 if version==2 else 1,'kind':'asu-apk-native-migration',
              'predecessor_build_id':old['build_id'],'successor_build_id':new['build_id'],
              'source_commit':old['firmware']['commit'],'kernel_version':old['firmware']['kernel_version']}
    if any(proof.get(key)!=value for key,value in expected.items()):
        raise ValueError('Native migration proof differs from the exact authorized generations')
    if version==2:
        module('kernel_migration').validate_receipt(old,new,proof)
    else:
        validate_equal_kernel_context(proof)
    patches=proof.get('source_patches')
    if (not isinstance(patches,dict) or set(patches)!={'before','after'}
            or not isinstance(patches['before'],list) or patches['before']!=patches['after']):
        raise ValueError('Native migration proof source patches differ')


def validate_equal_kernel_context(proof):
    """Legacy v1 keeps every original complete-byte equality requirement."""
    context=proof.get('kernel_context')
    required={'.config','Module.symvers','arch/arm64/boot/Image'}
    if not isinstance(context,dict) or not required <= set(context) or set(context)-required-{'vmlinux'}:
        raise ValueError('Native migration proof requires kernel configuration, symbols and actual Image bytes')
    for name,item in context.items():
        if not isinstance(item,dict) or set(item)!={'before','after'} or item['before']!=item['after']:
            raise ValueError('Native kernel byte comparison differs: '+name)
        identity=item['before']
        if (not isinstance(identity,dict) or set(identity)!={'sha256','size'}
                or not re.fullmatch(r'[a-f0-9]{64}',identity.get('sha256',''))
                or type(identity.get('size')) is not int or identity['size']<=0):
            raise ValueError('Invalid native kernel comparison identity: '+name)


def legacy_migration_metadata(tree,proof,workspace):
    """Resolve absent V2 predecessor metadata without changing its signed tree."""
    catalog=read_json(Path(tree)/'downloads.json')
    release=catalog.get('release',{})
    tag='firmware-'+proof['predecessor_build_id']
    if (not isinstance(release,dict) or release.get('repository')!='valujin/ax6000-packages-6.12'
            or type(release.get('id')) is not int or release['id']<=0
            or release.get('tag')!=tag or catalog.get('build_id')!=proof['predecessor_build_id']
            or not isinstance(release.get('recipe_commit'),str)
            or not re.fullmatch('[0-9a-f]{40}',release['recipe_commit'])):
        raise ValueError('Legacy migration catalog differs from the exact predecessor release')
    transport=module('publication_api')
    api=transport.ReleaseAPI(release['repository'])
    before=api.get_release(release['id'])
    if (not isinstance(before,dict) or before.get('id')!=release['id']
            or before.get('tag_name')!=tag or before.get('draft') is not False
            or before.get('immutable') is not True
            or api.resolve_tag_commit(tag)!=release['recipe_commit']):
        raise ValueError('Legacy migration metadata requires the exact immutable predecessor release')
    identity=transport.release_identity(before)
    assets=[asset for asset in before.get('assets',[]) if asset.get('name')=='firmware-manifest.json']
    expected=proof['firmware_manifest_sha256']['before']
    if (len(assets)!=1 or type(assets[0].get('size')) is not int
            or not 0<assets[0]['size']<=8*1024**2 or assets[0].get('digest')!='sha256:'+expected):
        raise ValueError('Legacy migration manifest asset differs from the reviewed proof')
    asset=assets[0]
    _MIGRATION_DOWNLOAD_BUDGET['used']+=asset['size']
    if _MIGRATION_DOWNLOAD_BUDGET['used']>512*1024**2:
        raise ValueError('Migration process download byte cap exceeded')
    resolved=Path(workspace)/'legacy-before';resolved.mkdir()
    for name in ('downloads.json','downloads.sig'):
        source=Path(tree)/name
        if source.is_symlink() or not source.is_file() or source.stat().st_size>8*1024**2:
            raise ValueError('Missing, linked or oversized legacy catalog metadata')
        shutil.copyfile(source,resolved/name)
    destination=resolved/'firmware-manifest.json'
    api.download_asset(before,asset,destination,expected,asset['size'])
    read_json(destination)
    if destination.stat().st_size!=asset['size'] or sha256_file(destination)!=expected:
        raise ValueError('Legacy migration native firmware manifest checksum differs')
    if (identity!=transport.release_identity(api.get_release(release['id']))
            or api.resolve_tag_commit(tag)!=release['recipe_commit']):
        raise ValueError('Immutable legacy migration release changed during verification')
    return resolved


def validate_migration_manifests(old_tree,new_tree,proof):
    with tempfile.TemporaryDirectory(prefix='ax6000-migration-metadata-') as workspace:
        trees=[]
        for phase,tree,build_id in [('before',old_tree,proof['predecessor_build_id']),
                                    ('after',new_tree,proof['successor_build_id'])]:
            path=Path(tree)/'firmware-manifest.json'
            if proof.get('schema_version')==2 and phase=='before' and not path.exists() and not path.is_symlink():
                tree=legacy_migration_metadata(tree,proof,workspace)
            manifest=read_json(Path(tree)/'firmware-manifest.json')
            if (manifest.get('build_id')!=build_id or manifest.get('source_commit')!=proof['source_commit']
                    or manifest.get('kernel_version')!=proof['kernel_version']
                    or manifest.get('source_patches',[])!=proof['source_patches'][phase]):
                raise ValueError('Native migration proof differs from actual '+phase+' firmware manifest')
            trees.append((phase,tree))
        if proof.get('schema_version')==2:
            module('kernel_migration').validate_payloads(
                trees,proof,read_json,module('publication_api'),
                _MIGRATION_IMAGE_CACHE,_MIGRATION_DOWNLOAD_BUDGET)


def restored_identity(restored,pointer,channel,repository,public_key,usign,*,apk=None):
    restored=Path(restored)
    verify(restored/'snapshot-manifest.json',restored/'snapshot-manifest.sig',public_key,usign)
    manifest=read_json(restored/'snapshot-manifest.json')
    validate_pointer(pointer,read_json(restored/'release.json'))
    profile,lock,files=validate_channel(restored/'channel',channel,repository,public_key,usign,**apk_options(apk))
    if manifest.get('files')!=files or sha256_file(restored/'snapshot-manifest.json')!=pointer.get('manifest_sha256'):
        raise ValueError('Restored channel/pointer mismatch')
    if any(pointer.get(k)!=manifest.get(k) for k in ('channel','profile_id','build_id','kernel_version')):
        raise ValueError('Restored channel identity differs from pointer')
    return profile,files


def catalog_identity(tree,profile,public_key,usign):
    verify(tree/'downloads.json',tree/'downloads.sig',public_key,usign)
    catalog=read_json(tree/'downloads.json')
    for key,expected in [('channel',profile['channel']),('profile_id',profile['id']),('build_id',profile['build_id']),
                         ('firmware',profile['firmware']),('sdk',profile['sdk'])]:
        if catalog.get(key) != expected:raise ValueError('Download catalog/profile mismatch')
    if profile.get('package_manager','opkg')=='apk':
        if catalog.get('package_manager')!='apk' or catalog.get('apk_key_sha256')!=profile.get('apk_key_sha256'):
            raise ValueError('Download catalog APK manager/key differs from profile')
    release=catalog.get('release',{})
    repository=profile['publication']['repository']
    if release.get('repository') != repository or release.get('tag') != 'firmware-'+profile['build_id']:
        raise ValueError('Wrong immutable generation reference')
    if type(release.get('id')) is not int or release['id'] <= 0:
        raise ValueError('Invalid generation release ID')
    if not re.fullmatch(r'[a-f0-9]{40}',release.get('recipe_commit','')):
        raise ValueError('Invalid generation recipe commit')
    assets=catalog.get('assets',[])
    if not assets:raise ValueError('Missing generation assets')
    names=set();ids=set()
    for asset in assets:
        name=asset.get('filename','')
        if not re.fullmatch(r'[A-Za-z0-9_.+~-]+',name) or name in names:
            raise ValueError('Duplicate or unsafe download asset')
        names.add(name)
        aid=asset.get('asset_id')
        if type(aid) is not int or aid <= 0 or aid in ids:raise ValueError('Invalid asset ID')
        ids.add(aid)
        if type(asset.get('size')) is not int or not 0 <= asset['size'] <= MAX_ASSET:
            raise ValueError('Invalid asset size')
        if not re.fullmatch(r'[a-f0-9]{64}',asset.get('sha256','')):raise ValueError('Invalid asset hash')
        expected=f'https://github.com/{repository}/releases/download/{release["tag"]}/{name}'
        if asset.get('url') != expected:raise ValueError('Foreign or mutable download URL')
    layout_path=ROOT/'scripts/firmware_layouts.py'
    if not layout_path.is_file():raise ValueError('Firmware layout validator missing')
    module('firmware_layouts').validate_download_catalog(catalog,profile)
    return catalog


def safe_name(name):
    path=PurePosixPath(name)
    if (not name or path.is_absolute() or '..' in path.parts or '\\' in name or '\x00' in name
            or path.as_posix()!=name):raise ValueError('Unsafe or noncanonical snapshot path')
    return path


def channel_files(tree,profile):
    files=[];total=0
    fmt=module('package_format');manager=fmt.manager(profile);suffix=fmt.suffix(profile)
    metadata=METADATA | (APK_METADATA if manager=='apk' else set())
    feed_prefix=f'feeds/{profile["id"]}/{profile["firmware"]["kernel_version"]}/'
    for path in sorted(Path(tree).rglob('*')):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError('Snapshot links and special files are forbidden')
        if path.is_dir():continue
        name=path.relative_to(tree).as_posix();safe_name(name)
        if name not in metadata and name!='state/lock.json':
            if not name.startswith(feed_prefix):raise ValueError('Unexpected snapshot file')
            leaf=name[len(feed_prefix):]
            indexes={'Packages','Packages.gz','Packages.sig'} | ({'packages.adb'} if manager=='apk' else set())
            if '/' in leaf or (leaf not in indexes and not re.fullmatch(r'[A-Za-z0-9_.+~-]+\.'+suffix,leaf)):
                raise ValueError('Unexpected feed file')
        total+=path.stat().st_size
        if total > MAX_SITE or len(files) >= MAX_MEMBERS:raise ValueError('Snapshot exceeds size/member bounds')
        files.append({'path':name,'size':path.stat().st_size,'sha256':sha256_file(path)})
    return files


def index_fields(text):
    fields={};previous=None
    for line in text.splitlines():
        if line.startswith((' ','\t')) and previous:fields[previous]+='\n'+line
        elif ':' in line:
            key,value=line.split(':',1)
            if key in fields:raise ValueError('Duplicate index field')
            fields[key]=value.strip();previous=key
        elif line:raise ValueError('Malformed index')
    return fields


def native_provider_identity(tree,profile):
    inventory=read_json(tree/'native-providers.json')
    expected={'schema_version':1,'kind':'native-providers','profile_id':profile['id'],
              'build_id':profile.get('build_id'),'sdk_sha256':profile.get('sdk',{}).get('sha256'),
              'kernel_version':profile['firmware']['kernel_version'],
              'architecture':profile['firmware']['architecture']}
    if any(inventory.get(key)!=value for key,value in expected.items()):
        raise ValueError('Native provider inventory differs from exact firmware/SDK cohort')
    records=inventory.get('packages')
    if not isinstance(records,list) or len(records)>100:
        raise ValueError('Invalid native essential package inventory')
    publisher=module('publish');provided=set();names=set()
    required={'Package','Base-Package','APK-Name','Version','Architecture','Filename','Size','SHA256sum'}
    for record in records:
        if not isinstance(record,dict) or not required<=set(record) or set(record)-required-{'ABIVersion','Provides'}:
            raise ValueError('Invalid native essential package record')
        if not all(isinstance(value,str) for value in record.values()):
            raise ValueError('Invalid native essential package fields')
        if (record['Filename']!=record['Package']+'-'+record['Version']+'.apk'
                or not re.fullmatch(r'[A-Za-z0-9_.+~-]+\.apk',record['Filename'])
                or not re.fullmatch(r'[1-9][0-9]*',record['Size'])
                or not re.fullmatch(r'[a-f0-9]{64}',record['SHA256sum']) or record['Package'] in names):
            raise ValueError('Duplicate or invalid native essential package identity')
        provided.update(publisher.native_provider_names(record,profile));names.add(record['Package'])
    return provided


def validate_feed(tree,profile,public_key,usign,*,apk=None):
    feed=tree/'feeds'/profile['id']/profile['firmware']['kernel_version']
    fmt=module('package_format');manager=fmt.manager(profile);suffix=fmt.suffix(profile)
    verify(feed/'Packages',feed/'Packages.sig',public_key,usign)
    if (feed/'Packages').stat().st_size > 8*1024**2:raise ValueError('Index too large')
    index=(feed/'Packages').read_bytes()
    with gzip.open(feed/'Packages.gz','rb') as stream:expanded=stream.read(8*1024**2+1)
    if expanded != index:raise ValueError('Compressed index differs')
    publisher=module('publish');names=set();filenames=set();controls=[]
    for paragraph in index.decode().strip().split('\n\n'):
        fields=index_fields(paragraph);filename=fields.get('Filename','')
        if not re.fullmatch(r'[A-Za-z0-9_.+~-]+\.'+suffix,filename) or filename in filenames:
            raise ValueError('Unsafe or duplicate index filename')
        package=feed/filename
        if not package.is_file() or str(package.stat().st_size)!=fields.get('Size') or sha256_file(package)!=fields.get('SHA256sum'):
            raise ValueError('Index package checksum/size mismatch')
        control=publisher.read_control(package,**apk_options(apk));publisher.validate_package(control,profile)
        if any(fields.get(k)!=v for k,v in publisher.index_control(control).items()):raise ValueError('Index differs from package control')
        if manager=='apk' and filename != control['Package']+'-'+control['Version']+'.apk':
            raise ValueError('APK filename differs from native name/version')
        if control['Package'] in names or publisher.protected_package(control,profile):
            raise ValueError('Duplicate or protected package')
        names.add(control['Package']);filenames.add(filename);controls.append(control)
    if not controls or {p.name for p in feed.glob('*.'+suffix)} != filenames:
        raise ValueError('Incomplete or empty feed inventory')
    if manager=='apk':
        publisher.verify_apk_index(feed,profile,apk,tree/'repository-apk.pem',controls)
    provided=set(names)|(publisher.APK_PROTECTED if manager=='apk' else publisher.PROTECTED)
    if manager=='apk':
        provided.update(native_provider_identity(tree,profile))
    for control in controls:
        provided.update(re.findall(r'(?:^|,)\s*([A-Za-z0-9_.+:-]+)',control.get('Provides','')))
    for control in controls:
        for dep in control.get('Depends','').split(','):
            if not dep.strip():continue
            if manager=='apk' and dep.strip().startswith('!'):continue
            pattern=r'\s*([A-Za-z0-9_.+:-]+)' if manager=='apk' else r'\s*([A-Za-z0-9_.+-]+)'
            alternatives=[re.match(pattern,item) for item in dep.split('|')]
            if not alternatives or any(match is None for match in alternatives) or not any(match[1] in provided for match in alternatives):
                raise ValueError(f'Unresolved package dependency: {control["Package"]}: {dep}')


def validate_channel(tree,channel,repository,public_key,usign,*,apk=None):
    tree=Path(tree);profile=read_json(tree/'profile.json');lock=read_json(tree/'state/lock.json')
    if tree.is_symlink() or not tree.is_dir():raise ValueError('Channel root must be a regular directory')
    channel_identity(profile,lock,channel,repository)
    if module('package_format').manager(profile)=='apk':
        verify(tree/'profile.json',tree/'profile.sig',public_key,usign)
        module('publish').validate_apk_key(profile,tree/'repository-apk.pem')
    if lock.get('profile_sha256') != sha256_file(tree/'profile.json'):raise ValueError('Profile checksum mismatch')
    publisher=module('publish')
    if publisher.public_key_payload((tree/'repository.pub').read_text()) != publisher.public_key_payload(Path(public_key).read_text()):
        raise ValueError('Snapshot key differs from trusted key')
    files=channel_files(tree,profile)
    catalog_identity(tree,profile,public_key,usign)
    validate_feed(tree,profile,public_key,usign,**apk_options(apk))
    return profile,lock,files


def pack_snapshot(tree,channel,repository,recipe_commit,key,public_key,usign,output,*,apk=None):
    output=fresh(output);signing_key(key,public_key)
    if not re.fullmatch(r'[a-f0-9]{40}',recipe_commit):raise ValueError('Invalid recipe commit')
    profile,lock,files=validate_channel(Path(tree),channel,repository,public_key,usign,**apk_options(apk))
    manifest={'schema_version':1,'kind':'channel-snapshot','repository':repository,'channel':channel,
              'profile_id':profile['id'],'build_id':profile['build_id'],'kernel_version':profile['firmware']['kernel_version'],
              'sdk_sha256':profile['sdk']['sha256'],'recipe_commit':recipe_commit,
              'profile_sha256':sha256_file(Path(tree)/'profile.json'),'lock_sha256':sha256_file(Path(tree)/'state/lock.json'),
              'files':files}
    payload=canonical_json(manifest);manifest_sha=hashlib.sha256(payload).hexdigest()
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.snapshot-pack-',dir=output.parent) as temporary:
        work=Path(temporary);(work/'snapshot-manifest.json').write_bytes(payload)
        sign(work/'snapshot-manifest.json',work/'snapshot-manifest.sig',key,public_key,usign)
        tar=work/'channel.tar'
        def normalized(item):
            item.mtime=0;item.uid=0;item.gid=0;item.uname='';item.gname='';item.mode=0o644
            return item
        with tarfile.open(tar,'w') as archive:
            for name in ('snapshot-manifest.json','snapshot-manifest.sig'):archive.add(work/name,arcname=name,recursive=False,filter=normalized)
            for entry in files:archive.add(Path(tree)/entry['path'],arcname='channel/'+entry['path'],recursive=False,filter=normalized)
        subprocess.run(['zstd','-q','-T1','-3','-o',str(work/'channel.tar.zst'),'--',str(tar)],check=True)
        archive=work/'channel.tar.zst'
        if archive.stat().st_size > MAX_ASSET:raise ValueError('Snapshot transport exceeds release asset bound')
        (work/'channel.tar.zst.sha256').write_text(sha256_file(archive)+'  channel.tar.zst\n')
        plan={'schema_version':1,'kind':'channel-snapshot','repository':repository,'channel':channel,
              'tag':'packages-'+channel+'-'+manifest_sha,'recipe_commit':recipe_commit,
              'manifest_sha256':manifest_sha,'profile_id':profile['id'],'build_id':profile['build_id'],
              'kernel_version':profile['firmware']['kernel_version'],
              'assets':[{'name':name,'path':str((output/name).absolute()),'size':(work/name).stat().st_size,'sha256':sha256_file(work/name)}
                        for name in ('channel.tar.zst','channel.tar.zst.sha256')]}
        (work/'snapshot-plan.json').write_bytes(canonical_json(plan))
        tar.unlink();work.rename(output)
    return plan


def release_assets(release):
    if release.get('draft') is not False or release.get('immutable') is not True:raise ValueError('Release must be published and immutable')
    result={}
    for asset in release.get('assets',[]):
        if asset.get('name') in result or asset.get('state')!='uploaded':raise ValueError('Duplicate or incomplete release assets')
        result[asset['name']]=asset
    if set(result)!={'channel.tar.zst','channel.tar.zst.sha256'}:raise ValueError('Unexpected snapshot release assets')
    return result


def validate_pointer(pointer,release):
    channel=pointer.get('channel')
    if channel not in CHANNELS or pointer.get('profile_id')!='redmi-ax6000-612-'+channel:raise ValueError('Wrong pointer channel')
    if not re.fullmatch(r'[a-f0-9]{64}',pointer.get('manifest_sha256','')):raise ValueError('Invalid manifest digest')
    if (not re.fullmatch(r'[a-f0-9]{64}',pointer.get('archive_sha256',''))
            or any(type(pointer.get(k)) is not int or pointer[k]<=0 for k in ('release_id','asset_id','archive_size'))
            or pointer['archive_size']>MAX_ASSET):raise ValueError('Invalid snapshot pointer bounds')
    if pointer.get('tag')!='packages-'+channel+'-'+pointer['manifest_sha256']:
        raise ValueError('Pointer tag differs from signed inventory')
    assets=release_assets(release);asset=assets['channel.tar.zst']
    if release.get('id')!=pointer.get('release_id') or release.get('tag_name')!=pointer['tag'] or asset.get('id')!=pointer.get('asset_id'):
        raise ValueError('Release/asset pointer differs')
    if asset.get('size')!=pointer.get('archive_size') or asset.get('digest') not in (None,'sha256:'+pointer.get('archive_sha256','')):
        raise ValueError('Release/asset checksum or size differs')
    return assets


def restore_snapshot(archive,pointer,before,after,expected,public_key,usign,output,*,apk=None):
    output=fresh(output);archive=Path(archive)
    assets=validate_pointer(pointer,before);validate_pointer(pointer,after)
    def identity(release):
        return (release['id'],release['tag_name'],[(name,a['id'],a['size'],a.get('digest'),a.get('updated_at')) for name,a in sorted(release_assets(release).items())])
    if identity(before)!=identity(after):raise ValueError('Release changed during download')
    if archive.stat().st_size!=pointer['archive_size'] or sha256_file(archive)!=pointer['archive_sha256']:
        raise ValueError('Snapshot transport checksum/size differs')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.snapshot-restore-',dir=output.parent) as temporary:
        work=Path(temporary);seen=set();total=0
        process=subprocess.Popen(['zstd','-q','-d','-c','--',str(archive)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            with tarfile.open(fileobj=process.stdout,mode='r|') as bundle:
                for count,item in enumerate(bundle,1):
                    path=safe_name(item.name)
                    if item.name in seen or count>MAX_MEMBERS or not item.isreg() or item.size<0:
                        raise ValueError('Duplicate, special or excessive snapshot archive')
                    seen.add(item.name);total+=item.size
                    if total>MAX_SITE+8*1024**2:raise ValueError('Snapshot unpacked size bound')
                    if item.name not in {'snapshot-manifest.json','snapshot-manifest.sig'} and (len(path.parts)<2 or path.parts[0]!='channel'):
                        raise ValueError('Unexpected snapshot envelope path')
                    target=work.joinpath(*path.parts);target.parent.mkdir(parents=True,exist_ok=True)
                    with bundle.extractfile(item) as source,target.open('xb') as destination:shutil.copyfileobj(source,destination,1024*1024)
                    target.chmod(0o644)
            process.stdout.close()
            if process.wait()!=0:raise ValueError('Snapshot decompression failed')
        finally:
            if process.poll() is None:process.terminate();process.wait()
            process.stdout.close()
        verify(work/'snapshot-manifest.json',work/'snapshot-manifest.sig',public_key,usign)
        manifest=read_json(work/'snapshot-manifest.json')
        if sha256_file(work/'snapshot-manifest.json')!=pointer['manifest_sha256']:
            raise ValueError('Signed manifest differs from pointer')
        profile,lock,files=validate_channel(work/'channel',pointer['channel'],manifest.get('repository'),public_key,usign,**apk_options(apk))
        if manifest.get('kind')!='channel-snapshot' or manifest.get('schema_version')!=1 or manifest.get('files')!=files:
            raise ValueError('Snapshot inventory differs')
        for key,value in [('channel',profile['channel']),('profile_id',profile['id']),('build_id',profile['build_id']),('kernel_version',profile['firmware']['kernel_version'])]:
            if manifest.get(key)!=value or pointer.get(key)!=value:raise ValueError('Snapshot identity differs from pointer')
        if cohort(profile)!=cohort(expected):raise ValueError('Snapshot differs from expected generation')
        if manifest.get('repository')!=expected.get('publication',{}).get('repository'):
            raise ValueError('Snapshot publication repository differs')
        if manifest.get('sdk_sha256')!=profile['sdk']['sha256'] or not re.fullmatch(r'[a-f0-9]{40}',manifest.get('recipe_commit','')):
            raise ValueError('Snapshot SDK/recipe identity differs')
        if manifest.get('profile_sha256')!=sha256_file(work/'channel/profile.json') or manifest.get('lock_sha256')!=sha256_file(work/'channel/state/lock.json'):
            raise ValueError('Snapshot profile/lock digest mismatch')
        (work/'release.json').write_bytes(canonical_json(after))
        work.rename(output)
    return output


def read_state(path,signature,repository,public_key,usign):
    verify(path,signature,public_key,usign);state=read_json(path)
    if state.get('schema_version')!=1 or state.get('repository')!=repository or set(state.get('channels',{}))!=set(CHANNELS):
        raise ValueError('Wrong signed site identity')
    return state


def compose_site(live_state,live_signature,channels,repository,key,public_key,usign,output,*,bootstrap=False,replacements=None,apk=None,allow_asu_apk_migration=False,migration_proof=None,
                 allow_native_apk_replacement=False,native_replacement_proof=None,native_replacement_proof_sha256=None):
    if allow_native_apk_replacement and (bootstrap or set(replacements or {})!={'recommended'}):
        raise ValueError('Native replacement requires exactly one authenticated REC predecessor')
    if allow_native_apk_replacement and (allow_asu_apk_migration or migration_proof is not None):
        raise ValueError('Native replacement and OPKG migration are mutually exclusive')
    if not allow_native_apk_replacement and (native_replacement_proof is not None or native_replacement_proof_sha256 is not None):
        raise ValueError('Native replacement proof requires its explicit native flag')
    output=fresh(output);signing_key(key,public_key)
    if live_state is None:
        if not bootstrap or live_signature is not None:raise ValueError('Explicit bootstrap required')
        previous={'schema_version':1,'repository':repository,'channels':{c:None for c in CHANNELS}}
    else:
        if bootstrap:raise ValueError('Cannot bootstrap over existing site')
        previous=read_state(live_state,live_signature,repository,public_key,usign)
    if set(channels)-set(CHANNELS):raise ValueError('Unknown publication channel')
    replacements=replacements or {}
    if set(replacements)-set(channels):raise ValueError('Replacement channel is absent')
    state={'schema_version':1,'repository':repository,'channels':{c:None for c in CHANNELS}}
    total=0
    for channel in CHANNELS:
        old=previous['channels'][channel]
        if channel not in channels:
            if old is not None:raise ValueError('Cannot remove an existing channel')
            continue
        restored,pointer=channels[channel];restored=Path(restored)
        profile,files=restored_identity(restored,pointer,channel,repository,public_key,usign,**apk_options(apk))
        if channel in replacements:
            predecessor,expected_build_id=replacements[channel]
            old_tree,old_pointer=predecessor
            if old is None or old_pointer!=old:
                raise ValueError('Replacement predecessor differs from authenticated live pointer')
            old_profile,_=restored_identity(old_tree,old_pointer,channel,repository,public_key,usign,**apk_options(apk))
            validate_generation_replacement(old_profile,profile,expected_build_id,allow_asu_apk_migration=allow_asu_apk_migration,migration_proof=migration_proof,
                                            allow_native_apk_replacement=allow_native_apk_replacement,native_replacement_proof=native_replacement_proof,native_replacement_proof_sha256=native_replacement_proof_sha256)
            if allow_native_apk_replacement:
                native=module('native_generation')
                reviewed=native.validate_receipt(old_profile,profile,native_replacement_proof,native_replacement_proof_sha256,
                    predecessor_pointer=old_pointer,old_tree=Path(old_tree)/'channel',new_tree=restored/'channel')
                native.validate_payloads(Path(old_tree)/'channel',restored/'channel',reviewed,read_json,module('publication_api'),_MIGRATION_IMAGE_CACHE,_MIGRATION_DOWNLOAD_BUDGET)
            if allow_asu_apk_migration:
                validate_migration_manifests(Path(old_tree)/'channel',restored/'channel',migration_proof)
        elif old is not None and any(old.get(k)!=pointer.get(k) for k in ('profile_id','build_id','kernel_version')):
            raise ValueError('Daily publication cannot switch firmware generation')
        total+=sum(item['size'] for item in files)
        state['channels'][channel]=pointer
    if total+len(canonical_json(state))+8192>MAX_SITE:raise ValueError('Combined Pages exceeds 1 GB')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.site-compose-',dir=output.parent) as temporary:
        work=Path(temporary)
        for channel,(restored,pointer) in channels.items():shutil.copytree(Path(restored)/'channel',work/'channels'/channel)
        (work/'site-state.json').write_bytes(canonical_json(state))
        sign(work/'site-state.json',work/'site-state.sig',key,public_key,usign)
        (work/'.nojekyll').touch()
        (work/'index.html').write_text('<!doctype html><meta charset="utf-8"><title>AX6000 6.12</title><h1>AX6000 6.12</h1><ul>'+''.join(f'<li><a href="channels/{c}/index.html">{html.escape(c)}</a></li>' for c in CHANNELS if state['channels'][c] is not None)+'</ul>')
        if sum(p.stat().st_size for p in work.rglob('*') if p.is_file())>MAX_SITE:raise ValueError('Combined Pages exceeds 1 GB')
        work.rename(output)
    return state


def asset_record(path,name=None):
    path=Path(path)
    return {'name':name or path.name,'path':str(path.absolute()),'size':path.stat().st_size,'sha256':sha256_file(path)}


def publish_snapshot(plan_path,repository,public_key,usign,output,*,apk=None):
    output=fresh(output);plan=read_json(plan_path)
    if plan.get('repository')!=repository or plan.get('kind')!='channel-snapshot':raise ValueError('Wrong snapshot plan repository/kind')
    if plan.get('tag')!='packages-'+plan.get('channel','')+'-'+plan.get('manifest_sha256',''):
        raise ValueError('Wrong snapshot plan tag')
    api=module('publication_api').ReleaseAPI(repository)
    # Authenticate the packed archive before permitting a remote write.
    by_name={item['name']:item for item in plan['assets']}
    if set(by_name)!={'channel.tar.zst','channel.tar.zst.sha256'} or len(plan['assets'])!=2:
        raise ValueError('Unexpected snapshot plan assets')
    if Path(by_name['channel.tar.zst.sha256']['path']).read_text()!=by_name['channel.tar.zst']['sha256']+'  channel.tar.zst\n':
        raise ValueError('Snapshot checksum file differs from archive plan')
    pointer={'channel':plan['channel'],'profile_id':plan['profile_id'],'build_id':plan['build_id'],
             'kernel_version':plan['kernel_version'],'manifest_sha256':plan['manifest_sha256'],
             'tag':plan['tag'],'release_id':1,'asset_id':2,
             'archive_sha256':by_name['channel.tar.zst']['sha256'],'archive_size':by_name['channel.tar.zst']['size']}
    fake={'id':1,'tag_name':plan['tag'],'draft':False,'immutable':True,'assets':[
        {'id':2+i,'name':item['name'],'size':item['size'],'digest':'sha256:'+item['sha256'],'state':'uploaded'} for i,item in enumerate(plan['assets'])]}
    with tempfile.TemporaryDirectory(prefix='ax6000-plan-check-') as temporary:
        expected=profile_from_archive(Path(by_name['channel.tar.zst']['path']))
        restored=Path(temporary)/'restored'
        restore_snapshot(Path(by_name['channel.tar.zst']['path']),pointer,fake,fake,expected,public_key,usign,restored,**apk_options(apk))
        if read_json(restored/'snapshot-manifest.json')['recipe_commit']!=plan.get('recipe_commit'):
            raise ValueError('Snapshot plan recipe differs from signed manifest')
    release=api.publish_release(plan)
    archive_asset=next(item for item in release['assets'] if item['name']=='channel.tar.zst')
    pointer.update(release_id=release['id'],asset_id=archive_asset['id'])
    output.mkdir(parents=True)
    (output/'release.json').write_bytes(canonical_json(release));(output/'pointer.json').write_bytes(canonical_json(pointer))
    return pointer


def profile_from_archive(archive):
    # Read only the bounded profile; this is NOT authentication. Restore verifies all bytes.
    process=subprocess.Popen(['zstd','-q','-d','-c','--',str(archive)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    try:
        with tarfile.open(fileobj=process.stdout,mode='r|') as bundle:
            for item in bundle:
                if item.name=='channel/profile.json':
                    if not item.isreg() or item.size>8*1024**2:raise ValueError('Invalid snapshot profile')
                    return json.loads(bundle.extractfile(item).read())
        raise ValueError('Snapshot profile absent')
    finally:
        process.stdout.close()
        if process.poll() is None:process.terminate()
        process.wait()


def restore_online(pointer,expected,repository,public_key,usign,output,*,apk=None):
    output=fresh(output)
    api=module('publication_api').ReleaseAPI(repository)
    before=api.get_release(pointer['release_id'])
    if before is None:raise ValueError('Snapshot release missing')
    assets=validate_pointer(pointer,before)
    if api.resolve_tag_commit(pointer['tag']) is None:raise ValueError('Invalid snapshot tag')
    with tempfile.TemporaryDirectory(prefix='ax6000-snapshot-download-') as temporary:
        archive=Path(temporary)/'channel.tar.zst'
        api.download_asset(before,assets['channel.tar.zst'],archive,pointer['archive_sha256'],pointer['archive_size'])
        after=api.get_release(pointer['release_id'])
        restore_snapshot(archive,pointer,before,after,expected,public_key,usign,output,**apk_options(apk))
        manifest=read_json(output/'snapshot-manifest.json')
        if api.resolve_tag_commit(pointer['tag'])!=manifest['recipe_commit']:
            shutil.rmtree(output)
            raise ValueError('Snapshot release tag differs from authenticated recipe commit')
    return output


def publish_generation(raw,expected_profile,archive,checksum,repository,key,public_key,usign,output,*,resume_draft_id=None):
    raw=Path(raw);output=fresh(output);signing_key(key,public_key)
    # A broken SDK relocation wrapper must fail before creating a remote draft.
    with tempfile.TemporaryDirectory(prefix='ax6000-signer-preflight-') as temporary:
        message=Path(temporary)/'signer.json'
        message.write_bytes(canonical_json({'purpose':'ax6000-generation-signer-preflight','repository':repository}))
        sign(message,Path(temporary)/'signer.sig',key,public_key,usign)
    validated=module('import-release').validate_metadata(raw,Path(expected_profile))
    profile,lock,manifest=validated['profile'],validated['lock'],validated['manifest']
    channel_identity(profile,lock,profile['channel'],repository)
    recipe=manifest.get('recipe_commit')
    if not re.fullmatch(r'[a-f0-9]{40}',recipe or ''):raise ValueError('Generation requires actual recipe commit')
    archive,checksum=Path(archive),Path(checksum)
    with tempfile.TemporaryDirectory(prefix='ax6000-generation-check-') as temporary:
        imported=Path(temporary)/'raw'
        module('import-release').import_bundle(archive,checksum,imported,Path(expected_profile))
        if any(sha256_file(imported/name)!=sha256_file(raw/name) for name in ('profile.json','lock.json','firmware-manifest.json')):
            raise ValueError('Generation archive differs from validated raw')
    records=module('firmware_layouts').collect_firmware_assets(raw,profile,manifest)
    core=[asset_record(raw/item['path'],item['filename']) for item in records]
    core.extend(asset_record(raw/name) for name in ('profile.json','lock.json','firmware-manifest.json'))
    core.extend([asset_record(archive,'raw.tar.zst'),asset_record(checksum,'raw.tar.zst.sha256')])
    api=module('publication_api').ReleaseAPI(repository)
    plan={'tag':'firmware-'+profile['build_id'],'recipe_commit':recipe,'assets':core}
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.generation-publish-',dir=output.parent) as temporary:
        work=Path(temporary)
        def finalize(release,*,reuse):
            by_name={asset['name']:asset for asset in release['assets']}
            assets=[]
            for record in records:
                asset=by_name[record['filename']]
                entry={key:value for key,value in record.items() if key!='path'}
                entry.update(asset_id=asset['id'],updated_at=asset['updated_at'],
                             url=f'https://github.com/{repository}/releases/download/{plan["tag"]}/{record["filename"]}')
                assets.append(entry)
            catalog={'schema_version':1,'channel':profile['channel'],'profile_id':profile['id'],'build_id':profile['build_id'],
                     'firmware':profile['firmware'],'sdk':profile['sdk'],'assets':assets,
                     'release':{'repository':repository,'id':release['id'],'tag':plan['tag'],'recipe_commit':recipe}}
            if profile.get('asu',{}).get('enabled') is True:
                catalog['imagebuilder']=profile['imagebuilder']
            if profile.get('package_manager','opkg')=='apk':
                catalog.update(package_manager='apk',apk_key_sha256=profile['apk_key_sha256'])
            module('firmware_layouts').validate_download_catalog(catalog,profile)
            (work/'downloads.json').write_bytes(canonical_json(catalog))
            sign(work/'downloads.json',work/'downloads.sig',key,public_key,usign)
            return [asset_record(work/name) for name in ('downloads.json','downloads.sig')]
        release=(api.publish_release(plan,finalize=finalize) if resume_draft_id is None
                 else api.resume_draft(plan,resume_draft_id,finalize=finalize))
        (work/'release.json').write_bytes(canonical_json(release))
        (work/'generation-pointer.json').write_bytes(canonical_json({'repository':repository,'release_id':release['id'],
                                                                  'tag':release['tag_name'],'build_id':profile['build_id']}))
        work.rename(output)
    return output


def fetch_live(site_url,repository,public_key,usign,output,*,bootstrap=False):
    import time
    import urllib.error
    import urllib.parse
    import urllib.request
    parsed=urllib.parse.urlsplit(site_url)
    if parsed.scheme!='https' or not parsed.netloc or parsed.query or parsed.fragment:raise ValueError('Site base must be HTTPS')
    output=fresh(output);output.mkdir(parents=True)
    missing=[]
    for name in ('site-state.json','site-state.sig'):
        request=urllib.request.Request(site_url.rstrip('/')+'/'+name+'?check='+str(time.time_ns()),headers={'Cache-Control':'no-cache'})
        try:
            with urllib.request.urlopen(request,timeout=30) as response:data=response.read(1024*1024+1)
        except urllib.error.HTTPError as error:
            if error.code!=404:raise
            missing.append(name);continue
        if len(data)>1024*1024:raise ValueError('Live state exceeds bound')
        (output/name).write_bytes(data)
    if missing:
        if len(missing)!=2 or not bootstrap:raise ValueError('Missing live state; explicit bootstrap required')
        return None
    return read_state(output/'site-state.json',output/'site-state.sig',repository,public_key,usign)


def restore_live_channels(state,profiles,repository,public_key,usign,work,*,apk=None):
    result={}
    if state is None:return result
    for channel in CHANNELS:
        pointer=state['channels'][channel]
        if pointer is None:continue
        profile=Path(profiles)/('redmi-ax6000-612-'+channel+'.json')
        if not profile.is_file():raise ValueError('Missing expected generated profile for live channel')
        output=Path(work)/('restored-'+channel)
        restore_online(pointer,read_json(profile),repository,public_key,usign,output,**apk_options(apk))
        result[channel]=(output,pointer)
    return result


def cleanup_owned_workspace(work, owned):
    """Remove only our fixed channel workspace, including read-only SDK directories."""
    work, owned = Path(work), Path(owned)
    if (owned.parent != work or owned.name not in {'build-' + c for c in CHANNELS}
            or work.is_symlink() or any(p.is_symlink() for p in work.parents)):
        raise ValueError('Refusing cleanup outside the owned channel workspace')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(work, flags)
    try:
        root = os.open(owned.name, flags, dir_fd=parent)
        try:
            device = os.fstat(parent).st_dev
            def writable_directories(descriptor):
                info = os.fstat(descriptor)
                if info.st_uid != os.getuid() or info.st_dev != device:
                    raise ValueError('Foreign owner/mount in owned cleanup workspace')
                os.fchmod(descriptor, info.st_mode | 0o700)
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                        child = os.open(entry.name, flags, dir_fd=descriptor)
                        try:
                            writable_directories(child)
                        finally:
                            os.close(child)
            writable_directories(root)
        finally:
            os.close(root)
        # fd-relative rmtree does not follow directory symlinks. No file chmods.
        shutil.rmtree(owned.name, dir_fd=parent)
    finally:
        os.close(parent)


def refresh(site_url,repository,profiles,work,key,public_key,usign,output,*,force=False,bootstrap=False,apk=None,apk_key=None,apk_public_key=None):
    work=fresh(work);output=fresh(output);signing_key(key,public_key);work.mkdir(parents=True)
    previous=fetch_live(site_url,repository,public_key,usign,work/'live',bootstrap=bootstrap)
    restored=restore_live_channels(previous,profiles,repository,public_key,usign,work,**apk_options(apk))
    changed=False;failures=[]
    for channel in CHANNELS:
        profile_path=Path(profiles)/('redmi-ax6000-612-'+channel+'.json')
        if not profile_path.is_file():
            source=Path(profiles)/('redmi-ax6000-612-'+channel+'-new.json')
            if source.is_file():
                subprocess.run(['python3',str(ROOT/'scripts/monitor.py'),'--profile',str(source),'--output',str(work/(channel+'-monitored.json'))],check=True)
            print(f'{channel}: generated daily profile absent; publication disabled')
            continue
        profile=read_json(profile_path)
        if profile.get('channel')!=channel:raise ValueError('Wrong daily profile channel')
        owned=work/('build-'+channel);owned.mkdir()
        lock=owned/'lock.json';args=['python3',str(ROOT/'scripts/monitor.py'),'--profile',str(profile_path),'--output',str(lock)]
        old=restored.get(channel)
        if old:args+=['--previous',str(old[0]/'channel/state/lock.json')]
        try:
            subprocess.run(args,check=True)
            if profile.get('enabled') is not True:
                print(f'{channel}: disabled; source monitoring completed');continue
            if old and cohort(read_json(old[0]/'channel/profile.json'))!=cohort(profile):raise ValueError('Daily generation migration refused')
            if old and read_json(lock)==read_json(old[0]/'channel/state/lock.json') and not force:
                print(f'{channel}: unchanged');continue
            if old is None:raise ValueError('Publish initial firmware generation and snapshot before enabling daily builds')
            apk_args=apk_publication_args(profile,apk,apk_key,apk_public_key)
            raw=owned/'raw'
            subprocess.run(['bash',str(ROOT/'scripts/build.sh'),'--profile',str(profile_path),'--lock',str(lock),
                            '--work-dir',str(owned/'sdk'),'--output-dir',str(raw)],check=True)
            catalog=read_json(old[0]/'channel/downloads.json')
            api=module('publication_api').ReleaseAPI(repository);generation=api.get_release(catalog['release']['id'])
            (owned/'generation.json').write_bytes(canonical_json(generation))
            subprocess.run(['python3',str(ROOT/'scripts/publish.py'),'--profile',str(profile_path),'--input',str(raw),
                            '--output',str(owned/'staged'),'--lock',str(lock),'--key',str(key),'--public-key',str(public_key),
                            '--usign',str(usign),'--external-assets',str(old[0]/'channel/downloads.json'),
                            '--external-assets-signature',str(old[0]/'channel/downloads.sig'),'--generation-release-metadata',str(owned/'generation.json'),*apk_args],check=True)
            recipe=os.environ.get('AX6000_RECIPE_COMMIT') or subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
            pack_snapshot(owned/'staged',channel,repository,recipe,key,public_key,usign,owned/'packed',**apk_options(apk))
            pointer=publish_snapshot(owned/'packed/snapshot-plan.json',repository,public_key,usign,owned/'published',**apk_options(apk))
            new=work/('new-restored-'+channel)
            restore_online(pointer,profile,repository,public_key,usign,new,**apk_options(apk))
            restored[channel]=(new,pointer);changed=True
        except (ValueError,OSError,subprocess.CalledProcessError) as error:
            failures.append(channel);print(f'{channel}: refresh failed: {error}')
        finally:
            # Successful, skipped and failed builds have the same owned cleanup.
            cleanup_owned_workspace(work, owned)
    if failures:
        summary=os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary,'a') as stream:stream.write('Channel refresh failed: '+', '.join(failures)+'. Previous deployed snapshots retained.\n')
    if not changed:
        print('No successful changed channel; deployment skipped')
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('deploy=false\n')
        if failures:raise ValueError('No channel refresh succeeded')
        return None
    compose_site(None if previous is None else work/'live/site-state.json',None if previous is None else work/'live/site-state.sig',
                 restored,repository,key,public_key,usign,output,bootstrap=previous is None,**apk_options(apk))
    latest=fetch_live(site_url,repository,public_key,usign,work/'live-recheck',bootstrap=previous is None)
    if latest!=previous:raise ValueError('Live predecessor changed; do not deploy')
    deployment_record(work,output,site_url,previous is None)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('deploy=true\n')
    return output


def select_generation_profile(catalog,repository,channel,output,*,recipe=ROOT):
    """Select data from the authenticated generation producer, never publisher HEAD."""
    if not isinstance(catalog,dict) or not isinstance(catalog.get('release'),dict):raise ValueError('Generation catalog identity missing')
    release=catalog['release'];commit=release.get('recipe_commit')
    if (channel not in CHANNELS or catalog.get('channel')!=channel
            or catalog.get('profile_id')!='redmi-ax6000-612-'+channel
            or release.get('repository')!=repository
            or not isinstance(commit,str) or not re.fullmatch('[0-9a-f]{40}',commit)
            or release.get('tag')!='firmware-'+catalog.get('build_id','')):
        raise ValueError('Authenticated generation producer/profile identity differs')
    output=fresh(output);recipe=Path(recipe)
    git=['/usr/bin/git','-C',str(recipe)]
    probe=subprocess.run(git+['cat-file','-e',commit+'^{commit}'],capture_output=True)
    if probe.returncode:
        # Public fixed repository, exact authenticated object; no checkout or code execution.
        if not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository):raise ValueError('Invalid producer repository')
        subprocess.run(git+['fetch','--no-tags','--depth=1','https://github.com/'+repository+'.git',commit],
                       check=True,capture_output=True,timeout=180)
    if subprocess.check_output(git+['rev-parse',commit+'^{commit}'],text=True).strip()!=commit:
        raise ValueError('Generation producer must be the exact commit object')
    native=module('native_generation')
    blob=native.git_blob(recipe,commit,'profiles/redmi-ax6000-612-'+channel+'-new.json')
    with tempfile.TemporaryDirectory(prefix='ax6000-producer-profile-') as temporary:
        path=Path(temporary)/'profile.json';path.write_bytes(blob);profile=native.read_json(path)
    if not isinstance(profile,dict) or profile.get('id')!=catalog['profile_id'] or profile.get('channel')!=channel:
        raise ValueError('Producer Git source profile identity differs')
    policy=profile.get('asu')
    if policy is not None and not isinstance(policy,dict):raise ValueError('Producer ASU policy must be an object')
    if policy is not None and policy.get('enabled') is True and policy.get('seed')!=native.producer_seed(recipe,commit,profile):
        raise ValueError('Producer source profile seed differs from its exact Git recipe')
    output.mkdir(parents=True)
    (output/'producer-profile.json').write_bytes(blob)
    (output/'producer-profile-proof.json').write_bytes(canonical_json({
        'producer_commit':commit,'channel':channel,'profile_id':profile['id'],
        'source_profile_sha256':hashlib.sha256(blob).hexdigest()}))
    return output


def fetch_generation(tag,repository,public_key,usign,output,*,channel=None):
    output=fresh(output);api=module('publication_api').ReleaseAPI(repository)
    before=api.get_release(tag)
    if before is None or before.get('draft') is not False or before.get('immutable') is not True:
        raise ValueError('Generation release must be published immutable')
    assets={a['name']:a for a in before['assets']}
    required=('raw.tar.zst','raw.tar.zst.sha256','downloads.json','downloads.sig')
    if len(assets)!=len(before['assets']) or not set(required)<=set(assets):raise ValueError('Generation assets missing/duplicated')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.generation-download-',dir=output.parent) as temporary:
        work=Path(temporary)
        for name in required:
            asset=assets[name];digest=asset.get('digest','')
            if not isinstance(digest,str) or not digest.startswith('sha256:'):raise ValueError('Generation asset API SHA256 missing')
            api.download_asset(before,asset,work/name,digest[7:],asset['size'])
        after=api.get_release(before['id'])
        if module('publication_api').release_identity(before)!=module('publication_api').release_identity(after):
            raise ValueError('Generation release changed during download')
        verify(work/'downloads.json',work/'downloads.sig',public_key,usign)
        catalog=read_json(work/'downloads.json')
        if catalog.get('release',{}).get('id')!=before['id'] or catalog['release'].get('repository')!=repository or catalog['release'].get('tag')!=tag:
            raise ValueError('Generation catalog release mismatch')
        if api.resolve_tag_commit(tag)!=catalog['release']['recipe_commit']:raise ValueError('Generation tag target mismatch')
        if channel is not None:select_generation_profile(catalog,repository,channel,work/'producer')
        (work/'release.json').write_bytes(canonical_json(after));work.rename(output)
    return output


def publish_channel(raw,catalog,signature,metadata,site_url,repository,profiles,work,key,public_key,usign,output,*,bootstrap=False,replace_build_id=None,apk=None,apk_key=None,apk_public_key=None,allow_asu_apk_migration=False,migration_proof=None,
                    allow_native_apk_replacement=False,native_replacement_proof=None,native_replacement_proof_sha256=None):
    if allow_native_apk_replacement:
        if allow_asu_apk_migration or migration_proof is not None:raise ValueError('Native replacement and OPKG migration are mutually exclusive')
        if bootstrap or not replace_build_id:raise ValueError('Native replacement requires an authenticated exact --replace-build-id and no bootstrap')
        if native_replacement_proof is None or not isinstance(native_replacement_proof_sha256,str) or not re.fullmatch('[0-9a-f]{64}',native_replacement_proof_sha256):
            raise ValueError('Native replacement requires its separate reviewed proof and SHA')
    elif native_replacement_proof is not None or native_replacement_proof_sha256 is not None:
        raise ValueError('Native replacement proof requires its explicit native flag')
    work=fresh(work);output=fresh(output);work.mkdir(parents=True)
    profile=read_json(Path(raw)/'profile.json');channel=profile['channel']
    if allow_asu_apk_migration and replace_build_id is None:
        raise ValueError('--allow-asu-apk-migration requires --replace-build-id')
    previous=fetch_live(site_url,repository,public_key,usign,work/'live',bootstrap=bootstrap)
    restored=restore_live_channels(previous,profiles,repository,public_key,usign,work,**apk_options(apk))
    old=restored.get(channel)
    replacements={}
    if replace_build_id is not None:
        if bootstrap or old is None:raise ValueError('Replacement requires an authenticated live predecessor')
        old_profile,_=restored_identity(old[0],old[1],channel,repository,public_key,usign,**apk_options(apk))
        validate_generation_replacement(old_profile,profile,replace_build_id,allow_asu_apk_migration=allow_asu_apk_migration,migration_proof=migration_proof,
                                        allow_native_apk_replacement=allow_native_apk_replacement,native_replacement_proof=native_replacement_proof,native_replacement_proof_sha256=native_replacement_proof_sha256)
        if allow_native_apk_replacement:
            native=module('native_generation')
            reviewed=native.validate_receipt(old_profile,profile,native_replacement_proof,native_replacement_proof_sha256,
                predecessor_pointer=old[1],old_tree=Path(old[0])/'channel',new_tree=raw)
            native.validate_payloads(Path(old[0])/'channel',raw,reviewed,read_json,module('publication_api'),_MIGRATION_IMAGE_CACHE,_MIGRATION_DOWNLOAD_BUDGET)
        if allow_asu_apk_migration:
            validate_migration_manifests(Path(old[0])/'channel',raw,migration_proof)
        replacements[channel]=(old,replace_build_id)
    elif old and cohort(read_json(old[0]/'channel/profile.json'))!=cohort(profile):
        raise ValueError('Manual generation migration requires --replace-build-id')
    apk_args=apk_publication_args(profile,apk,apk_key,apk_public_key)
    subprocess.run(['python3',str(ROOT/'scripts/publish.py'),'--profile',str(Path(raw)/'profile.json'),
                    '--input',str(raw),'--output',str(work/'staged'),'--lock',str(Path(raw)/'lock.json'),
                    '--key',str(key),'--public-key',str(public_key),'--usign',str(usign),
                    '--external-assets',str(catalog),'--external-assets-signature',str(signature),
                    '--generation-release-metadata',str(metadata),*apk_args],check=True)
    recipe=os.environ.get('AX6000_RECIPE_COMMIT') or subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
    pack_snapshot(work/'staged',channel,repository,recipe,key,public_key,usign,work/'packed',**apk_options(apk))
    pointer=publish_snapshot(work/'packed/snapshot-plan.json',repository,public_key,usign,work/'released',**apk_options(apk))
    restored_channel=work/('new-restored-'+channel)
    restore_online(pointer,profile,repository,public_key,usign,restored_channel,**apk_options(apk))
    restored[channel]=(restored_channel,pointer)
    compose_site(None if previous is None else work/'live/site-state.json',None if previous is None else work/'live/site-state.sig',
                 restored,repository,key,public_key,usign,output,bootstrap=previous is None,replacements=replacements,allow_asu_apk_migration=allow_asu_apk_migration,migration_proof=migration_proof,
                 allow_native_apk_replacement=allow_native_apk_replacement,native_replacement_proof=native_replacement_proof,native_replacement_proof_sha256=native_replacement_proof_sha256,**apk_options(apk))
    latest=fetch_live(site_url,repository,public_key,usign,work/'live-recheck',bootstrap=previous is None)
    if latest!=previous:raise ValueError('Live predecessor changed; do not deploy')
    deployment_record(work,output,site_url,previous is None)
    return output


def deployment_record(work,public,site_url,bootstrap):
    checks={'schema_version':1,'site_url':site_url,'before':None,'after':{}}
    if not bootstrap:checks['before']={name:sha256_file(Path(work)/'live'/name) for name in ('site-state.json','site-state.sig')}
    checks['after']={name:sha256_file(Path(public)/name) for name in ('site-state.json','site-state.sig')}
    (Path(work)/'deployment-check.json').write_bytes(canonical_json(checks))


def verify_deployment(check,phase):
    import time
    import urllib.error
    import urllib.parse
    import urllib.request
    check=read_json(check);names=('site-state.json','site-state.sig')
    if phase not in ('before','after') or check.get('schema_version')!=1:
        raise ValueError('Invalid authenticated deployment expectation')
    for label in ('before','after'):
        pair=check.get(label)
        if pair is None and label=='before':continue
        if (not isinstance(pair,dict) or set(pair)!=set(names)
                or any(not isinstance(value,str) or not re.fullmatch(r'[a-f0-9]{64}',value) for value in pair.values())):
            raise ValueError('Invalid authenticated deployment expectation')
    expected=check[phase];site=check['site_url']
    if urllib.parse.urlsplit(site).scheme!='https':raise ValueError('Deployment URL must use HTTPS')
    # Pages may briefly serve either authenticated generation, including a mixed
    # state/signature pair. Unknown bytes are never a propagation retry.
    deadline=time.monotonic()+60 if phase=='after' else None
    for attempt in range(12 if phase=='after' else 1):
        complete=True
        for name in names:
            timeout=30
            if deadline is not None:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise ValueError('Live site differs from authenticated deployment expectation')
                timeout=min(timeout,remaining)
            request=urllib.request.Request(site.rstrip('/')+'/'+name+'?verify='+str(time.time_ns()),headers={'Cache-Control':'no-cache'})
            try:
                with urllib.request.urlopen(request,timeout=timeout) as response:body=response.read(1024*1024+1)
            except urllib.error.HTTPError as error:
                if check['before'] is None and error.code==404:
                    complete=phase=='before' and complete
                    continue
                raise
            if len(body)>1024*1024:raise ValueError('Live site differs from authenticated deployment expectation')
            digest=hashlib.sha256(body).hexdigest()
            if phase=='before':
                if expected is None or digest!=expected[name]:
                    raise ValueError('Live site differs from authenticated deployment expectation')
            else:
                allowed={expected[name]}
                if check['before'] is not None:allowed.add(check['before'][name])
                if digest not in allowed:raise ValueError('Live site differs from authenticated deployment expectation')
                complete=complete and digest==expected[name]
        if complete:
            if deadline is not None and time.monotonic()>deadline:
                raise ValueError('Live site differs from authenticated deployment expectation')
            return
        if attempt==11 or deadline-time.monotonic()<=5:break
        time.sleep(5)
    raise ValueError('Live site differs from authenticated deployment expectation')



def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    def common(p,*,secret=False):
        p.add_argument('--repository',required=True);p.add_argument('--public-key',required=True,type=Path)
        p.add_argument('--usign',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
        p.add_argument('--apk',type=Path,help='Trusted host APK tool for APK snapshots')
        if secret:p.add_argument('--key',required=True,type=Path)
        if secret:
            p.add_argument('--apk-key',type=Path);p.add_argument('--apk-public-key',type=Path)
    pack=sub.add_parser('pack');common(pack,secret=True)
    pack.add_argument('--channel',choices=CHANNELS,required=True);pack.add_argument('--input',type=Path,required=True);pack.add_argument('--recipe-commit',required=True)
    gen=sub.add_parser('publish-generation');common(gen,secret=True)
    gen.add_argument('--resume-draft-id',type=int,help='Complete only this exact validated partial draft; never replace assets')
    for name in ('raw','expected-profile','raw-archive','checksum'):gen.add_argument('--'+name,type=Path,required=True)
    pub=sub.add_parser('publish-snapshot');common(pub);pub.add_argument('--plan',type=Path,required=True)
    restore=sub.add_parser('restore');common(restore);restore.add_argument('--pointer',type=Path,required=True);restore.add_argument('--expected-profile',type=Path,required=True)
    for name in ('archive','release-before','release-after'):restore.add_argument('--'+name,type=Path)
    compose=sub.add_parser('compose');common(compose,secret=True)
    compose.add_argument('--live-state',type=Path);compose.add_argument('--live-signature',type=Path);compose.add_argument('--bootstrap',action='store_true')
    for channel in CHANNELS:
        compose.add_argument('--'+channel,type=Path);compose.add_argument('--'+channel+'-pointer',type=Path)
    daily=sub.add_parser('refresh');common(daily,secret=True)
    daily.add_argument('--site-url',required=True);daily.add_argument('--profiles',type=Path,default=ROOT/'profiles');daily.add_argument('--work-root',type=Path,required=True)
    daily.add_argument('--force',action='store_true');daily.add_argument('--bootstrap',action='store_true')
    live=sub.add_parser('read-live');common(live);live.add_argument('--site-url',required=True);live.add_argument('--bootstrap',action='store_true')
    fetched=sub.add_parser('fetch-generation');common(fetched);fetched.add_argument('--release-tag',required=True)
    fetched.add_argument('--channel',choices=CHANNELS,help='Select this authenticated native producer source profile')
    publish=sub.add_parser('publish-channel');common(publish,secret=True)
    for name in ('raw','external-assets','external-assets-signature','generation-release-metadata','work-root'):publish.add_argument('--'+name,type=Path,required=True)
    publish.add_argument('--replace-build-id',help='Replace exactly this authenticated live build, preserving source/kernel ABI/layouts')
    publish.add_argument('--migration-proof',type=Path,help='Reviewed actual old/new native kernel byte comparison JSON')
    publish.add_argument('--allow-asu-apk-migration',action='store_true',help='Explicitly authorize the reviewed additive ASU/APK firmware migration')
    publish.add_argument('--allow-native-apk-replacement',action='store_true',help='Authorize the separately proved REC native APK APP3/installer generation replacement')
    publish.add_argument('--native-replacement-proof',type=Path)
    publish.add_argument('--native-replacement-proof-sha256')
    publish.add_argument('--site-url',required=True);publish.add_argument('--profiles',type=Path,default=ROOT/'profiles');publish.add_argument('--bootstrap',action='store_true')
    check=sub.add_parser('verify-deployment');check.add_argument('--check',type=Path,required=True);check.add_argument('--phase',choices=('before','after'),required=True)
    args=parser.parse_args()
    try:
        if args.command=='verify-deployment':verify_deployment(args.check,args.phase)
        elif args.command=='fetch-generation':fetch_generation(args.release_tag,args.repository,args.public_key,args.usign,args.output,channel=args.channel)
        elif args.command=='publish-channel':publish_channel(args.raw,args.external_assets,args.external_assets_signature,args.generation_release_metadata,args.site_url,args.repository,args.profiles,args.work_root,args.key,args.public_key,args.usign,args.output,bootstrap=args.bootstrap,replace_build_id=args.replace_build_id,allow_asu_apk_migration=args.allow_asu_apk_migration,migration_proof=None if args.migration_proof is None else read_json(args.migration_proof),apk=args.apk,apk_key=args.apk_key,apk_public_key=args.apk_public_key,
            allow_native_apk_replacement=args.allow_native_apk_replacement,native_replacement_proof=args.native_replacement_proof,native_replacement_proof_sha256=args.native_replacement_proof_sha256)
        elif args.command=='pack':pack_snapshot(args.input,args.channel,args.repository,args.recipe_commit,args.key,args.public_key,args.usign,args.output,**apk_options(args.apk))
        elif args.command=='publish-generation':publish_generation(args.raw,args.expected_profile,args.raw_archive,args.checksum,args.repository,args.key,args.public_key,args.usign,args.output,resume_draft_id=args.resume_draft_id)
        elif args.command=='publish-snapshot':publish_snapshot(args.plan,args.repository,args.public_key,args.usign,args.output,**apk_options(args.apk))
        elif args.command=='restore':
            pointer=read_json(args.pointer);expected=read_json(args.expected_profile)
            offline=(args.archive,args.release_before,args.release_after)
            if any(offline):
                if not all(offline):raise ValueError('Offline restore requires archive and before/after metadata')
                restore_snapshot(args.archive,pointer,read_json(args.release_before),read_json(args.release_after),expected,args.public_key,args.usign,args.output,**apk_options(args.apk))
            else:restore_online(pointer,expected,args.repository,args.public_key,args.usign,args.output,**apk_options(args.apk))
        elif args.command=='compose':
            channels={}
            for channel in CHANNELS:
                tree=getattr(args,channel);pointer=getattr(args,channel+'_pointer')
                if bool(tree)!=bool(pointer):raise ValueError('Channel directory and pointer are paired')
                if tree:channels[channel]=(tree,read_json(pointer))
            compose_site(args.live_state,args.live_signature,channels,args.repository,args.key,args.public_key,args.usign,args.output,bootstrap=args.bootstrap,**apk_options(args.apk))
        elif args.command=='refresh':refresh(args.site_url,args.repository,args.profiles,args.work_root,args.key,args.public_key,args.usign,args.output,force=args.force,bootstrap=args.bootstrap,apk=args.apk,apk_key=args.apk_key,apk_public_key=args.apk_public_key)
        elif args.command=='read-live':fetch_live(args.site_url,args.repository,args.public_key,args.usign,args.output,bootstrap=args.bootstrap)
    except (ValueError,OSError,subprocess.CalledProcessError,tarfile.TarError,KeyError) as error:
        parser.exit(1,f'channel-snapshot: {error}\n')



if __name__=='__main__':main()
