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


def cohort(profile):
    return {key:profile[key] for key in ('id','channel','build_id','firmware','sdk')}



def validate_generation_replacement(old,new,expected_build_id):
    """Authorize one same-ABI cohort replacement, never a moving kernel update."""
    if not expected_build_id or old.get('build_id')!=expected_build_id:
        raise ValueError('Replacement predecessor build ID differs from explicit authorization')
    if new.get('build_id')==expected_build_id or new.get('sdk')==old.get('sdk'):
        raise ValueError('Replacement must have a new build ID and SDK')
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


def restored_identity(restored,pointer,channel,repository,public_key,usign):
    restored=Path(restored)
    verify(restored/'snapshot-manifest.json',restored/'snapshot-manifest.sig',public_key,usign)
    manifest=read_json(restored/'snapshot-manifest.json')
    validate_pointer(pointer,read_json(restored/'release.json'))
    profile,lock,files=validate_channel(restored/'channel',channel,repository,public_key,usign)
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
    feed_prefix=f'feeds/{profile["id"]}/{profile["firmware"]["kernel_version"]}/'
    for path in sorted(Path(tree).rglob('*')):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError('Snapshot links and special files are forbidden')
        if path.is_dir():continue
        name=path.relative_to(tree).as_posix();safe_name(name)
        if name not in METADATA and name!='state/lock.json':
            if not name.startswith(feed_prefix):raise ValueError('Unexpected snapshot file')
            leaf=name[len(feed_prefix):]
            if '/' in leaf or (leaf not in {'Packages','Packages.gz','Packages.sig'} and not re.fullmatch(r'[A-Za-z0-9_.+~-]+\.ipk',leaf)):
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


def validate_feed(tree,profile,public_key,usign):
    feed=tree/'feeds'/profile['id']/profile['firmware']['kernel_version']
    verify(feed/'Packages',feed/'Packages.sig',public_key,usign)
    if (feed/'Packages').stat().st_size > 8*1024**2:raise ValueError('Index too large')
    index=(feed/'Packages').read_bytes()
    with gzip.open(feed/'Packages.gz','rb') as stream:expanded=stream.read(8*1024**2+1)
    if expanded != index:raise ValueError('Compressed index differs')
    publisher=module('publish');names=set();filenames=set();controls=[]
    for paragraph in index.decode().strip().split('\n\n'):
        fields=index_fields(paragraph);filename=fields.get('Filename','')
        if not re.fullmatch(r'[A-Za-z0-9_.+~-]+\.ipk',filename) or filename in filenames:
            raise ValueError('Unsafe or duplicate index filename')
        package=feed/filename
        if not package.is_file() or str(package.stat().st_size)!=fields.get('Size') or sha256_file(package)!=fields.get('SHA256sum'):
            raise ValueError('Index package checksum/size mismatch')
        control=publisher.read_control(package);publisher.validate_package(control,profile)
        if any(fields.get(k)!=v for k,v in control.items()):raise ValueError('Index differs from IPK control')
        if control['Package'] in names or control['Package'] in {'kernel','libc','base-files','busybox','opkg'}:
            raise ValueError('Duplicate or protected package')
        names.add(control['Package']);filenames.add(filename);controls.append(control)
    if not controls or {p.name for p in feed.glob('*.ipk')} != filenames:
        raise ValueError('Incomplete or empty feed inventory')
    provided=set(names)|{'kernel','libc','base-files','busybox','opkg'}
    for control in controls:
        provided.update(re.findall(r'(?:^|,)\s*([A-Za-z0-9_.+-]+)',control.get('Provides','')))
    for control in controls:
        for dep in control.get('Depends','').split(','):
            if not dep.strip():continue
            alternatives=[re.match(r'\s*([A-Za-z0-9_.+-]+)',item) for item in dep.split('|')]
            if not alternatives or any(match is None for match in alternatives) or not any(match[1] in provided for match in alternatives):
                raise ValueError(f'Unresolved package dependency: {control["Package"]}: {dep}')


def validate_channel(tree,channel,repository,public_key,usign):
    tree=Path(tree);profile=read_json(tree/'profile.json');lock=read_json(tree/'state/lock.json')
    if tree.is_symlink() or not tree.is_dir():raise ValueError('Channel root must be a regular directory')
    channel_identity(profile,lock,channel,repository)
    if lock.get('profile_sha256') != sha256_file(tree/'profile.json'):raise ValueError('Profile checksum mismatch')
    publisher=module('publish')
    if publisher.public_key_payload((tree/'repository.pub').read_text()) != publisher.public_key_payload(Path(public_key).read_text()):
        raise ValueError('Snapshot key differs from trusted key')
    files=channel_files(tree,profile)
    catalog_identity(tree,profile,public_key,usign)
    validate_feed(tree,profile,public_key,usign)
    return profile,lock,files


def pack_snapshot(tree,channel,repository,recipe_commit,key,public_key,usign,output):
    output=fresh(output);signing_key(key,public_key)
    if not re.fullmatch(r'[a-f0-9]{40}',recipe_commit):raise ValueError('Invalid recipe commit')
    profile,lock,files=validate_channel(Path(tree),channel,repository,public_key,usign)
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


def restore_snapshot(archive,pointer,before,after,expected,public_key,usign,output):
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
        profile,lock,files=validate_channel(work/'channel',pointer['channel'],manifest.get('repository'),public_key,usign)
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


def compose_site(live_state,live_signature,channels,repository,key,public_key,usign,output,*,bootstrap=False,replacements=None):
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
        profile,files=restored_identity(restored,pointer,channel,repository,public_key,usign)
        if channel in replacements:
            predecessor,expected_build_id=replacements[channel]
            old_tree,old_pointer=predecessor
            if old is None or old_pointer!=old:
                raise ValueError('Replacement predecessor differs from authenticated live pointer')
            old_profile,_=restored_identity(old_tree,old_pointer,channel,repository,public_key,usign)
            validate_generation_replacement(old_profile,profile,expected_build_id)
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


def publish_snapshot(plan_path,repository,public_key,usign,output):
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
        restore_snapshot(Path(by_name['channel.tar.zst']['path']),pointer,fake,fake,expected,public_key,usign,restored)
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


def restore_online(pointer,expected,repository,public_key,usign,output):
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
        restore_snapshot(archive,pointer,before,after,expected,public_key,usign,output)
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


def restore_live_channels(state,profiles,repository,public_key,usign,work):
    result={}
    if state is None:return result
    for channel in CHANNELS:
        pointer=state['channels'][channel]
        if pointer is None:continue
        profile=Path(profiles)/('redmi-ax6000-612-'+channel+'.json')
        if not profile.is_file():raise ValueError('Missing expected generated profile for live channel')
        output=Path(work)/('restored-'+channel)
        restore_online(pointer,read_json(profile),repository,public_key,usign,output)
        result[channel]=(output,pointer)
    return result


def refresh(site_url,repository,profiles,work,key,public_key,usign,output,*,force=False,bootstrap=False):
    work=fresh(work);output=fresh(output);signing_key(key,public_key);work.mkdir(parents=True)
    previous=fetch_live(site_url,repository,public_key,usign,work/'live',bootstrap=bootstrap)
    restored=restore_live_channels(previous,profiles,repository,public_key,usign,work)
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
                print(f'{channel}: disabled; source monitoring completed');shutil.rmtree(owned);continue
            if old and cohort(read_json(old[0]/'channel/profile.json'))!=cohort(profile):raise ValueError('Daily generation migration refused')
            if old and read_json(lock)==read_json(old[0]/'channel/state/lock.json') and not force:
                print(f'{channel}: unchanged');shutil.rmtree(owned);continue
            if old is None:raise ValueError('Publish initial firmware generation and snapshot before enabling daily builds')
            raw=owned/'raw'
            subprocess.run(['bash',str(ROOT/'scripts/build.sh'),'--profile',str(profile_path),'--lock',str(lock),
                            '--work-dir',str(owned/'sdk'),'--output-dir',str(raw)],check=True)
            catalog=read_json(old[0]/'channel/downloads.json')
            api=module('publication_api').ReleaseAPI(repository);generation=api.get_release(catalog['release']['id'])
            (owned/'generation.json').write_bytes(canonical_json(generation))
            subprocess.run(['python3',str(ROOT/'scripts/publish.py'),'--profile',str(profile_path),'--input',str(raw),
                            '--output',str(owned/'staged'),'--lock',str(lock),'--key',str(key),'--public-key',str(public_key),
                            '--usign',str(usign),'--external-assets',str(old[0]/'channel/downloads.json'),
                            '--external-assets-signature',str(old[0]/'channel/downloads.sig'),'--generation-release-metadata',str(owned/'generation.json')],check=True)
            recipe=os.environ.get('AX6000_RECIPE_COMMIT') or subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
            pack_snapshot(owned/'staged',channel,repository,recipe,key,public_key,usign,owned/'packed')
            pointer=publish_snapshot(owned/'packed/snapshot-plan.json',repository,public_key,usign,owned/'published')
            new=work/('new-restored-'+channel)
            restore_online(pointer,profile,repository,public_key,usign,new)
            restored[channel]=(new,pointer);changed=True
            # This fixed, newly created channel root is ours. Never remove source trees.
            shutil.rmtree(owned)
        except (ValueError,OSError,subprocess.CalledProcessError) as error:
            failures.append(channel);print(f'{channel}: refresh failed: {error}')
            # Hosted disk is bounded; an owned failed workspace can be discarded too.
            shutil.rmtree(owned)
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
                 restored,repository,key,public_key,usign,output,bootstrap=previous is None)
    latest=fetch_live(site_url,repository,public_key,usign,work/'live-recheck',bootstrap=previous is None)
    if latest!=previous:raise ValueError('Live predecessor changed; do not deploy')
    deployment_record(work,output,site_url,previous is None)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('deploy=true\n')
    return output


def fetch_generation(tag,repository,public_key,usign,output):
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
        (work/'release.json').write_bytes(canonical_json(after));work.rename(output)
    return output


def publish_channel(raw,catalog,signature,metadata,site_url,repository,profiles,work,key,public_key,usign,output,*,bootstrap=False,replace_build_id=None):
    work=fresh(work);output=fresh(output);work.mkdir(parents=True)
    profile=read_json(Path(raw)/'profile.json');channel=profile['channel']
    previous=fetch_live(site_url,repository,public_key,usign,work/'live',bootstrap=bootstrap)
    restored=restore_live_channels(previous,profiles,repository,public_key,usign,work)
    old=restored.get(channel)
    replacements={}
    if replace_build_id is not None:
        if bootstrap or old is None:raise ValueError('Replacement requires an authenticated live predecessor')
        old_profile,_=restored_identity(old[0],old[1],channel,repository,public_key,usign)
        validate_generation_replacement(old_profile,profile,replace_build_id)
        replacements[channel]=(old,replace_build_id)
    elif old and cohort(read_json(old[0]/'channel/profile.json'))!=cohort(profile):
        raise ValueError('Manual generation migration requires --replace-build-id')
    subprocess.run(['python3',str(ROOT/'scripts/publish.py'),'--profile',str(Path(raw)/'profile.json'),
                    '--input',str(raw),'--output',str(work/'staged'),'--lock',str(Path(raw)/'lock.json'),
                    '--key',str(key),'--public-key',str(public_key),'--usign',str(usign),
                    '--external-assets',str(catalog),'--external-assets-signature',str(signature),
                    '--generation-release-metadata',str(metadata)],check=True)
    recipe=os.environ.get('AX6000_RECIPE_COMMIT') or subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
    pack_snapshot(work/'staged',channel,repository,recipe,key,public_key,usign,work/'packed')
    pointer=publish_snapshot(work/'packed/snapshot-plan.json',repository,public_key,usign,work/'released')
    restored_channel=work/('new-restored-'+channel)
    restore_online(pointer,profile,repository,public_key,usign,restored_channel)
    restored[channel]=(restored_channel,pointer)
    compose_site(None if previous is None else work/'live/site-state.json',None if previous is None else work/'live/site-state.sig',
                 restored,repository,key,public_key,usign,output,bootstrap=previous is None,replacements=replacements)
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
    check=read_json(check);expected=check[phase];site=check['site_url']
    if urllib.parse.urlsplit(site).scheme!='https':raise ValueError('Deployment URL must use HTTPS')
    for name in ('site-state.json','site-state.sig'):
        request=urllib.request.Request(site.rstrip('/')+'/'+name+'?verify='+str(time.time_ns()),headers={'Cache-Control':'no-cache'})
        try:
            with urllib.request.urlopen(request,timeout=30) as response:body=response.read(1024*1024+1)
        except urllib.error.HTTPError as error:
            if expected is None and error.code==404:continue
            raise
        if expected is None or len(body)>1024*1024 or hashlib.sha256(body).hexdigest()!=expected[name]:
            raise ValueError('Live site differs from authenticated deployment expectation')



def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    def common(p,*,secret=False):
        p.add_argument('--repository',required=True);p.add_argument('--public-key',required=True,type=Path)
        p.add_argument('--usign',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
        if secret:p.add_argument('--key',required=True,type=Path)
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
    publish=sub.add_parser('publish-channel');common(publish,secret=True)
    for name in ('raw','external-assets','external-assets-signature','generation-release-metadata','work-root'):publish.add_argument('--'+name,type=Path,required=True)
    publish.add_argument('--replace-build-id',help='Replace exactly this authenticated live build, preserving source/kernel ABI/layouts')
    publish.add_argument('--site-url',required=True);publish.add_argument('--profiles',type=Path,default=ROOT/'profiles');publish.add_argument('--bootstrap',action='store_true')
    check=sub.add_parser('verify-deployment');check.add_argument('--check',type=Path,required=True);check.add_argument('--phase',choices=('before','after'),required=True)
    args=parser.parse_args()
    try:
        if args.command=='verify-deployment':verify_deployment(args.check,args.phase)
        elif args.command=='fetch-generation':fetch_generation(args.release_tag,args.repository,args.public_key,args.usign,args.output)
        elif args.command=='publish-channel':publish_channel(args.raw,args.external_assets,args.external_assets_signature,args.generation_release_metadata,args.site_url,args.repository,args.profiles,args.work_root,args.key,args.public_key,args.usign,args.output,bootstrap=args.bootstrap,replace_build_id=args.replace_build_id)
        elif args.command=='pack':pack_snapshot(args.input,args.channel,args.repository,args.recipe_commit,args.key,args.public_key,args.usign,args.output)
        elif args.command=='publish-generation':publish_generation(args.raw,args.expected_profile,args.raw_archive,args.checksum,args.repository,args.key,args.public_key,args.usign,args.output,resume_draft_id=args.resume_draft_id)
        elif args.command=='publish-snapshot':publish_snapshot(args.plan,args.repository,args.public_key,args.usign,args.output)
        elif args.command=='restore':
            pointer=read_json(args.pointer);expected=read_json(args.expected_profile)
            offline=(args.archive,args.release_before,args.release_after)
            if any(offline):
                if not all(offline):raise ValueError('Offline restore requires archive and before/after metadata')
                restore_snapshot(args.archive,pointer,read_json(args.release_before),read_json(args.release_after),expected,args.public_key,args.usign,args.output)
            else:restore_online(pointer,expected,args.repository,args.public_key,args.usign,args.output)
        elif args.command=='compose':
            channels={}
            for channel in CHANNELS:
                tree=getattr(args,channel);pointer=getattr(args,channel+'_pointer')
                if bool(tree)!=bool(pointer):raise ValueError('Channel directory and pointer are paired')
                if tree:channels[channel]=(tree,read_json(pointer))
            compose_site(args.live_state,args.live_signature,channels,args.repository,args.key,args.public_key,args.usign,args.output,bootstrap=args.bootstrap)
        elif args.command=='refresh':refresh(args.site_url,args.repository,args.profiles,args.work_root,args.key,args.public_key,args.usign,args.output,force=args.force,bootstrap=args.bootstrap)
        elif args.command=='read-live':fetch_live(args.site_url,args.repository,args.public_key,args.usign,args.output,bootstrap=args.bootstrap)
    except (ValueError,OSError,subprocess.CalledProcessError,tarfile.TarError,KeyError) as error:
        parser.exit(1,f'channel-snapshot: {error}\n')



if __name__=='__main__':main()
