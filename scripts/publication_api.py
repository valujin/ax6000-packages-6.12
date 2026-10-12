#!/usr/bin/env python3
"""Bounded GitHub immutable-release transport shared by local and hosted publishers."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

MAX_ASSET=2*1024**3-1


def sha256_file(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def release_identity(release):
    if not isinstance(release,dict):raise ValueError('Release metadata missing')
    assets=[];names=set();ids=set()
    for asset in release.get('assets',[]):
        name,identity=asset.get('name'),asset.get('id')
        if not isinstance(name,str) or name in names or type(identity) is not int or identity<=0 or identity in ids:
            raise ValueError('Duplicate or invalid release asset identity')
        names.add(name);ids.add(identity)
        if asset.get('state')!='uploaded':raise ValueError('Incomplete release asset')
        assets.append((name,identity,asset.get('size'),asset.get('digest'),asset.get('updated_at')))
    return (release.get('id'),release.get('tag_name'),release.get('draft'),release.get('immutable'),sorted(assets))


class ReleaseAPI:
    def __init__(self,repository,token=None):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository):raise ValueError('Invalid release repository')
        self.repository=repository
        self.token=token if token is not None else os.environ.get('GH_TOKEN','')
        self.base='https://api.github.com/repos/'+repository

    def request(self,method,endpoint,body=None,*,missing_ok=False):
        if not endpoint.startswith('/') or endpoint.startswith('//'):raise ValueError('Invalid API endpoint')
        headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10','User-Agent':'ax6000-publication/1'}
        if self.token:headers['Authorization']='Bearer '+self.token
        if body is not None:headers['Content-Type']='application/json'
        request=urllib.request.Request(self.base+endpoint,method=method,headers=headers,
                                       data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.urlopen(request,timeout=60) as response:data=response.read(8*1024**2+1)
        except urllib.error.HTTPError as error:
            if missing_ok and error.code==404:return None
            raise ValueError(f'GitHub API request failed: HTTP {error.code}') from None
        if len(data)>8*1024**2:raise ValueError('GitHub API response bound exceeded')
        return json.loads(data) if data else None

    def get_release(self,identity):
        endpoint='/releases/'+(str(identity) if type(identity) is int else 'tags/'+urllib.parse.quote(identity,safe=''))
        release=self.request('GET',endpoint,missing_ok=True)
        if release is None:return None
        assets=[]
        for page in range(1,1001):
            batch=self.request('GET',f'/releases/{release["id"]}/assets?per_page=100&page={page}')
            if not isinstance(batch,list):raise ValueError('Invalid release asset response')
            assets.extend(batch)
            if len(batch)<100:break
        else:raise ValueError('Release asset pagination bound exceeded')
        release['assets']=assets
        return release

    def resolve_tag_commit(self,tag,*,missing_ok=False):
        reference=self.request('GET','/git/ref/tags/'+urllib.parse.quote(tag,safe=''),missing_ok=missing_ok)
        if reference is None:return None
        item=reference['object']
        for _ in range(8):
            if item.get('type')=='commit':
                if not re.fullmatch(r'[a-f0-9]{40}',item.get('sha','')):raise ValueError('Invalid tag target')
                return item['sha']
            if item.get('type')!='tag':raise ValueError('Unsupported tag object')
            item=self.request('GET','/git/tags/'+item['sha'])['object']
        raise ValueError('Tag dereference bound exceeded')

    def preflight_assets(self,assets):
        names=set()
        for asset in assets:
            name=asset.get('name','');path=Path(asset['path'])
            if not re.fullmatch(r'[A-Za-z0-9_.+~-]+',name) or name in names:raise ValueError('Duplicate/unsafe release asset')
            names.add(name)
            if path.is_symlink() or not path.is_file() or any(p.is_symlink() for p in path.parents):
                raise ValueError('Release assets must be bounded regular files')
            if path.stat().st_size!=asset.get('size') or not 0<=path.stat().st_size<=MAX_ASSET or sha256_file(path)!=asset.get('sha256'):
                raise ValueError('Local release asset checksum/size drift')
        if not names:raise ValueError('Release has no assets')

    def verify_assets(self,release,expected,*,draft=False):
        if release.get('draft') is not draft or (not draft and release.get('immutable') is not True):
            raise ValueError('Release must be published and immutable')
        actual={}
        for asset in release.get('assets',[]):
            name=asset.get('name')
            if name in actual or asset.get('state')!='uploaded':raise ValueError('Duplicate/incomplete release asset')
            actual[name]=asset
        if set(actual)!={asset['name'] for asset in expected}:raise ValueError('Release asset inventory differs')
        for planned in expected:
            asset=actual[planned['name']]
            if asset.get('size')!=planned['size']:raise ValueError('Release asset size differs')
            digest=asset.get('digest')
            if digest is not None and digest!='sha256:'+planned['sha256']:raise ValueError('Release asset checksum differs')
            if digest is None:
                with __import__('tempfile').TemporaryDirectory(prefix='ax6000-asset-verify-') as directory:
                    self.download_asset(release,asset,Path(directory)/asset['name'],planned['sha256'],planned['size'])
        return actual

    def upload_asset(self,release,asset):
        expected=f'https://uploads.github.com/repos/{self.repository}/releases/{release["id"]}/assets'
        if release.get('upload_url','').split('{',1)[0]!=expected:raise ValueError('Foreign upload endpoint')
        if not self.token:raise ValueError('GH_TOKEN required for publication')
        connection=http.client.HTTPSConnection('uploads.github.com',timeout=120)
        try:
            endpoint=urllib.parse.urlsplit(expected).path+'?'+urllib.parse.urlencode({'name':asset['name']})
            connection.putrequest('POST',endpoint)
            for name,value in {'Authorization':'Bearer '+self.token,'Content-Type':'application/octet-stream',
                               'Content-Length':str(asset['size']),'User-Agent':'ax6000-publication/1',
                               'X-GitHub-Api-Version':'2026-03-10'}.items():connection.putheader(name,value)
            connection.endheaders()
            with Path(asset['path']).open('rb') as source:
                while chunk:=source.read(1024*1024):connection.send(chunk)
            response=connection.getresponse();data=response.read(1024*1024+1)
            if response.status!=201:raise ValueError(f'GitHub asset upload failed: HTTP {response.status}')
            if len(data)>1024*1024:raise ValueError('Upload response bound exceeded')
            result=json.loads(data)
            if result.get('state')!='uploaded' or result.get('name')!=asset['name'] or result.get('size')!=asset['size']:
                raise ValueError('Uploaded asset metadata differs')
            if result.get('digest') not in (None,'sha256:'+asset['sha256']):raise ValueError('Uploaded asset digest differs')
            return result
        finally:connection.close()

    def download_asset(self,release,asset,destination,digest,size):
        expected=f'https://github.com/{self.repository}/releases/download/{release["tag_name"]}/{asset["name"]}'
        if asset.get('browser_download_url',expected)!=expected:raise ValueError('Foreign download URL')
        if type(size) is not int or not 0<=size<=MAX_ASSET or not re.fullmatch(r'[a-f0-9]{64}',digest):
            raise ValueError('Invalid download bound/checksum')
        destination=Path(destination)
        if destination.exists() or destination.is_symlink():raise ValueError('Download output must be fresh')
        class HTTPSOnly(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,request,fp,code,msg,headers,newurl):
                if urllib.parse.urlsplit(newurl).scheme!='https':raise ValueError('Non-HTTPS asset redirect')
                return super().redirect_request(request,fp,code,msg,headers,newurl)
        opener=urllib.request.build_opener(HTTPSOnly())
        # Public asset request carries no token, including its CDN redirects.
        request=urllib.request.Request(expected,headers={'User-Agent':'ax6000-publication/1'})
        destination.parent.mkdir(parents=True,exist_ok=True)
        total=0;checksum=hashlib.sha256()
        try:
            with opener.open(request,timeout=120) as response,destination.open('xb') as target:
                while chunk:=response.read(1024*1024):
                    total+=len(chunk)
                    if total>size:raise ValueError('Download exceeds expected size')
                    checksum.update(chunk);target.write(chunk)
            if total!=size or checksum.hexdigest()!=digest:raise ValueError('Downloaded asset checksum/size differs')
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return destination

    def publish_release(self,plan,finalize=None):
        self.preflight_assets(plan['assets'])
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',plan.get('tag','')) or not re.fullmatch(r'[a-f0-9]{40}',plan.get('recipe_commit','')):
            raise ValueError('Invalid release tag/recipe commit')
        existing=self.get_release(plan['tag'])
        if existing is not None:
            if existing.get('draft') is not False or existing.get('immutable') is not True:raise ValueError('Existing draft or mutable release cannot be overwritten')
            if self.resolve_tag_commit(plan['tag'])!=plan['recipe_commit']:raise ValueError('Release tag points to another recipe')
            expected=plan['assets']
            if finalize is not None:expected=expected+finalize(existing,reuse=True)
            self.verify_assets(existing,expected)
            return existing
        target=self.resolve_tag_commit(plan['tag'],missing_ok=True)
        if target is not None and target!=plan['recipe_commit']:
            raise ValueError('Existing tag points to another recipe')
        setting=self.request('GET','/immutable-releases')
        if setting.get('enabled') is not True:raise ValueError('Enable immutable releases before publication')
        release=self.request('POST','/releases',{'tag_name':plan['tag'],'target_commitish':plan['recipe_commit'],
                                              'name':plan.get('title',plan['tag']),'body':plan.get('notes',''),'draft':True})
        for asset in plan['assets']:self.upload_asset(release,asset)
        uploaded=self.get_release(release['id']);self.verify_assets(uploaded,plan['assets'],draft=True)
        extras=[] if finalize is None else finalize(uploaded,reuse=False)
        self.preflight_assets(extras) if extras else None
        for asset in extras:self.upload_asset(release,asset)
        self.verify_assets(self.get_release(release['id']),plan['assets']+extras,draft=True)
        self.request('PATCH',f'/releases/{release["id"]}',{'draft':False})
        published=self.get_release(release['id']);self.verify_assets(published,plan['assets']+extras)
        if published['tag_name']!=plan['tag'] or self.resolve_tag_commit(plan['tag'])!=plan['recipe_commit']:
            raise ValueError('Published release tag identity differs')
        return published
