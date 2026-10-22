#!/usr/bin/env python3
"""Pinned full-feature ARM64 Tailscale multicall build, shared by SDK and hosted probe."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tarfile
import time
import urllib.request
from urllib.parse import urlsplit

UPX = {'version':'5.2.1', 'commit':'b4bdabf638ab6e3715a292182a9c613a4716d7c5',
       'url':'https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-amd64_linux.tar.xz',
       'sha256':'402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657', 'size':664048}
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\Z')


def need(value, message):
    if not value: raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


class MetadataNoRedirect(urllib.request.HTTPRedirectHandler):
    # Authenticated metadata must not forward credentials to another URL.
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def request_headers(url):
    headers={'User-Agent':'ax6000-tailscale-source/1'};parsed=urlsplit(url)
    if parsed.scheme=='https' and parsed.netloc=='api.github.com' and os.environ.get('GH_TOKEN'):
        headers['Authorization']='Bearer '+os.environ['GH_TOKEN']
    return headers


def fetch(url, limit=8*1024**2):
    headers=request_headers(url);request=urllib.request.Request(url, headers=headers)
    opener=urllib.request.build_opener(MetadataNoRedirect()).open if 'Authorization' in headers else urllib.request.urlopen
    with opener(request, timeout=30) as response: data=response.read(limit+1)
    need(len(data)<=limit, 'Tailscale metadata/source response exceeds bound')
    return data


def validate(lock):
    need(isinstance(lock,dict) and set(lock)=={'version','artifact','commit','url','sha256','go','upx'}, 'Incomplete Tailscale source lock')
    need(lock['artifact']=='source-multicall-upx' and isinstance(lock['version'],str) and VERSION.fullmatch(lock['version']), 'Invalid compact Tailscale version/artifact')
    need(isinstance(lock['commit'],str) and COMMIT.fullmatch(lock['commit']), 'Tailscale needs an immutable source commit')
    need(lock['url']=='https://codeload.github.com/tailscale/tailscale/tar.gz/'+lock['commit'], 'Tailscale source URL differs from commit')
    need(isinstance(lock['sha256'],str) and SHA.fullmatch(lock['sha256']), 'Tailscale needs source SHA256')
    go=lock['go']
    need(isinstance(go,dict) and set(go)=={'version','minimum_version','commit','url','sha256','size'}, 'Incomplete private Go toolchain pin')
    need(all(isinstance(go[k],str) and VERSION.fullmatch(go[k]) for k in ('version','minimum_version')), 'Invalid Go version')
    need(tuple(map(int,go['version'].split('.')))>=tuple(map(int,go['minimum_version'].split('.'))), 'Go toolchain is too old')
    need(isinstance(go['commit'],str) and COMMIT.fullmatch(go['commit']), 'Go toolchain needs exact commit')
    need(go['url']=='https://github.com/tailscale/go/releases/download/build-'+go['commit']+'/linux-amd64.tar.gz', 'Go toolchain URL differs from source pin')
    need(isinstance(go['sha256'],str) and SHA.fullmatch(go['sha256']) and type(go['size']) is int and 0<go['size']<=128*1024**2, 'Invalid Go archive identity')
    need(lock['upx']==UPX, 'Only the reviewed UPX release is supported')
    return lock


def resolve(version, fetcher=fetch):
    need(isinstance(version,str) and VERSION.fullmatch(version), 'Invalid Tailscale release version')
    obj=json.loads(fetcher('https://api.github.com/repos/tailscale/tailscale/git/ref/tags/v'+version))['object']
    for _ in range(3):
        need(isinstance(obj,dict) and COMMIT.fullmatch(obj.get('sha','')), 'Invalid Tailscale tag object')
        if obj.get('type')=='commit': break
        need(obj.get('type')=='tag', 'Tailscale tag must point to a commit')
        obj=json.loads(fetcher('https://api.github.com/repos/tailscale/tailscale/git/tags/'+obj['sha']))['object']
    need(obj.get('type')=='commit', 'Tailscale tag resolution depth exceeded')
    commit=obj['sha'];base='https://raw.githubusercontent.com/tailscale/tailscale/'+commit+'/'
    revision=fetcher(base+'go.toolchain.rev').decode().strip()
    need(COMMIT.fullmatch(revision), 'Invalid upstream Go toolchain revision')
    minimum=re.findall(r'^go ([0-9]+\.[0-9]+\.[0-9]+)$', fetcher(base+'go.mod').decode(), re.M)
    need(len(minimum)==1, 'Missing upstream minimum Go version')
    goversion=fetcher('https://raw.githubusercontent.com/tailscale/go/'+revision+'/VERSION').decode().splitlines()[0]
    need(goversion.startswith('go') and VERSION.fullmatch(goversion[2:]), 'Unsupported upstream Go release version')
    release=json.loads(fetcher('https://api.github.com/repos/tailscale/go/releases/tags/build-'+revision))
    need(release.get('tag_name')=='build-'+revision and not release.get('draft'), 'Wrong Go release')
    assets=[a for a in release.get('assets',[]) if a.get('name')=='linux-amd64.tar.gz']
    need(len(assets)==1, 'Go release must contain one official Linux AMD64 toolchain')
    asset=assets[0];checksum=asset.get('digest','')
    need(checksum.startswith('sha256:') and SHA.fullmatch(checksum[7:]), 'Go release needs GitHub SHA256 digest')
    url='https://codeload.github.com/tailscale/tailscale/tar.gz/'+commit
    result={'version':version,'artifact':'source-multicall-upx','commit':commit,'url':url,
            'sha256':hashlib.sha256(fetcher(url,32*1024**2)).hexdigest(),
            'go':{'version':goversion[2:],'minimum_version':minimum[0],'commit':revision,
                  'url':asset['browser_download_url'],'sha256':checksum[7:],'size':asset['size']},'upx':dict(UPX)}
    return validate(result)


def recipe(lock):
    validate(lock)
    return '''include $(TOPDIR)/rules.mk

PKG_NAME:=tailscale
PKG_VERSION:=%s
PKG_RELEASE:=3
PKG_SOURCE_VERSION:=%s
PKG_SOURCE:=tailscale-$(PKG_SOURCE_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/tailscale/tailscale/tar.gz/$(PKG_SOURCE_VERSION)?
PKG_HASH:=%s
PKG_BUILD_DIR:=$(BUILD_DIR)/tailscale-$(PKG_SOURCE_VERSION)
PKG_LICENSE:=BSD-3-Clause

include $(INCLUDE_DIR)/package.mk

# UPX-packed Go ELF must never be rewritten by the SDK's strip/sstrip pass.
RSTRIP:=:

define Download/tailscale-go
  FILE:=tailscale-go-%s-linux-amd64.tar.gz
  URL:=%s
  URL_FILE:=linux-amd64.tar.gz
  HASH:=%s
endef
$(eval $(call Download,tailscale-go))

define Download/tailscale-upx
  FILE:=upx-5.2.1-amd64_linux.tar.xz
  URL:=https://github.com/upx/upx/releases/download/v5.2.1
  HASH:=%s
endef
$(eval $(call Download,tailscale-upx))

define Package/tailscale
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Tailscale full-feature ARM64 multicall (UPX)
  URL:=https://tailscale.com
  DEPENDS:=@aarch64 +ca-bundle +kmod-tun
  PROVIDES:=tailscaled
endef

define Package/tailscale/conffiles
/etc/config/tailscale
/etc/tailscale/
endef

define Build/Configure
	$(RM) -r $(PKG_BUILD_DIR)/.ax6000-prefetch
	python3 ./files/tailscale_source.py build --prefetch-only --lock ./files/source-lock.json \
		--source-dir $(PKG_BUILD_DIR) --source-archive $(DL_DIR)/$(PKG_SOURCE) \
		--go-archive $(DL_DIR)/tailscale-go-%s-linux-amd64.tar.gz \
		--upx-archive $(DL_DIR)/upx-5.2.1-amd64_linux.tar.xz \
		--module-cache $(DL_DIR)/tailscale-go-mod-cache-$(PKG_SOURCE_VERSION) \
		--work $(PKG_BUILD_DIR)/.ax6000-prefetch --output $(PKG_BUILD_DIR)/prefetch-unused --jobs 4
endef

define Build/Compile
	$(RM) -r $(PKG_BUILD_DIR)/.ax6000-build
	$(RM) $(PKG_BUILD_DIR)/tailscale.multicall $(PKG_BUILD_DIR)/tailscale.multicall.unpacked $(PKG_BUILD_DIR)/tailscale.multicall.proof.json
	python3 ./files/tailscale_source.py build --offline --lock ./files/source-lock.json \
		--source-dir $(PKG_BUILD_DIR) --source-archive $(DL_DIR)/$(PKG_SOURCE) \
		--go-archive $(DL_DIR)/tailscale-go-%s-linux-amd64.tar.gz \
		--upx-archive $(DL_DIR)/upx-5.2.1-amd64_linux.tar.xz \
		--module-cache $(DL_DIR)/tailscale-go-mod-cache-$(PKG_SOURCE_VERSION) \
		--work $(PKG_BUILD_DIR)/.ax6000-build --output $(PKG_BUILD_DIR)/tailscale.multicall --jobs 4
endef

define Package/tailscale/install
\t$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
\t$(INSTALL_BIN) $(PKG_BUILD_DIR)/tailscale.multicall $(1)/usr/sbin/tailscale.multicall
\t$(LN) tailscale.multicall $(1)/usr/sbin/tailscale
\t$(LN) tailscale.multicall $(1)/usr/sbin/tailscaled
\t$(INSTALL_BIN) ./files/tailscale.init $(1)/etc/init.d/tailscale
\t$(INSTALL_DATA) ./files/tailscale.conf $(1)/etc/config/tailscale
endef

$(eval $(call BuildPackage,tailscale))
''' % (lock['version'],lock['commit'],lock['sha256'],lock['go']['commit'],lock['go']['url'].rsplit('/',1)[0],lock['go']['sha256'],UPX['sha256'],lock['go']['commit'],lock['go']['commit'])


def build_commands(lock, source, goroot, upxroot, work, output, jobs, module_cache=None, offline=False):
    validate(lock);need(type(jobs) is int and 1<=jobs<=4, 'Tailscale build jobs must be 1..4')
    source,goroot,upxroot,work,output=map(Path,(source,goroot,upxroot,work,output))
    env={k:v for k,v in os.environ.items() if not k.startswith(('GO','TS_','CGO_')) and k not in ('UPX','GH_TOKEN','GITHUB_TOKEN','OPKG_SIGNING_KEY','APK_SIGNING_KEY')}
    env.update(CGO_ENABLED='0',GOOS='linux',GOARCH='arm64',GOARM64='v8.0',GOTOOLCHAIN='local',GOENV='off',GOWORK='off',
               GOMAXPROCS=str(jobs),GOPATH=str(work/'gopath'),GOCACHE=str(work/'cache'),GOMODCACHE=str(Path(module_cache).resolve() if module_cache else work/'mod'),
               GOPROXY='off' if offline else 'https://proxy.golang.org',GOSUMDB='sum.golang.org',GONOSUMDB='',GOPRIVATE='',GONOPROXY='')
    flags='-s -w -X tailscale.com/version.shortStamp='+lock['version']+' -X tailscale.com/version.longStamp='+lock['version']+'-t'+lock['commit'][:9]+' -X tailscale.com/version.gitCommitStamp='+lock['commit']
    raw=work/'tailscale.multicall.unpacked';upx=str(upxroot/'upx')
    return env,{'prefetch':[str(goroot/'bin/go'),'mod','download'], 'compile':[str(goroot/'bin/go'),'build','-p',str(jobs),'-mod=readonly','-buildvcs=false','-tags','ts_include_cli','-trimpath','-ldflags',flags,'-o',str(raw),'./cmd/tailscaled'],
                'compress':[upx,'-7','--no-lzma','-o',str(output),str(raw)],'test':[upx,'-t',str(output)],
                'restore':[upx,'-d','-o',str(work/'restored.multicall'),str(output)]}


def unpack(archive, destination):
    destination=Path(destination);need(not destination.exists(), 'Extraction destination already exists');destination.mkdir(parents=True)
    with tarfile.open(archive) as bundle:
        members=bundle.getmembers();need(0<len(members)<100000 and sum(m.size for m in members)<2*1024**3,'Archive exceeds extraction bounds')
        roots={m.name.split('/',1)[0] for m in members};need(len(roots)==1,'Archive needs one root directory')
        bundle.extractall(destination, filter='data')
    root=destination/next(iter(roots));need(root.is_dir() and not root.is_symlink(), 'Invalid archive root')
    return root


def check_archive(path, pin, maximum):
    path=Path(path);need(path.is_file() and not path.is_symlink() and path.stat().st_size<=maximum, 'Missing or oversized pinned archive')
    need(digest(path)==pin['sha256'] and ('size' not in pin or path.stat().st_size==pin['size']), 'Pinned archive SHA256/size differs')


def elf_arm64(path):
    with Path(path).open('rb') as stream:
        header=stream.read(64);need(len(header)==64 and header[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',header,18)[0]==183,'Not an ARM64 ELF')
        offset=struct.unpack_from('<Q',header,32)[0];size,count=struct.unpack_from('<HH',header,54)
        need(size==56 and 0<count<=1024,'Invalid ELF program headers');stream.seek(offset);entries=stream.read(size*count)
        need(len(entries)==size*count and all(struct.unpack_from('<I',entries,i*size)[0] not in (2,3) for i in range(count)), 'CGO-free binary has dynamic loader/dependencies')


def build(lock, source_archive, go_archive, upx_archive, work, output, jobs, source=None, module_cache=None, offline=False, prefetch_only=False):
    validate(lock);need(platform.system()=='Linux' and platform.machine()=='x86_64','Build requires Linux AMD64 host')
    check_archive(source_archive,lock,32*1024**2);check_archive(go_archive,lock['go'],128*1024**2);check_archive(upx_archive,lock['upx'],4*1024**2)
    work=Path(work).resolve();output=Path(output).resolve();need(not work.exists() and not output.exists(),'Build/output must be fresh');work.mkdir(parents=True);output.parent.mkdir(parents=True,exist_ok=True)
    source=Path(source).resolve() if source else unpack(source_archive,work/'source')
    need((source/'go.toolchain.rev').read_text().strip()==lock['go']['commit'], 'Source Go revision differs')
    need(re.findall(r'^go ([0-9]+\.[0-9]+\.[0-9]+)$',(source/'go.mod').read_text(),re.M)==[lock['go']['minimum_version']], 'Source minimum Go version differs')
    need((source/'VERSION.txt').read_text().strip()==lock['version'],'Source Tailscale version differs')
    goroot=unpack(go_archive,work/'toolchain');upxroot=unpack(upx_archive,work/'compressor')
    env,commands=build_commands(lock,source,goroot,upxroot,work,output,jobs,module_cache,offline)
    version=subprocess.check_output([str(goroot/'bin/go'),'version'],env=env,text=True).strip()
    need(version.split()[:3]==['go','version','go'+lock['go']['version']], 'Actual isolated Go version differs')
    need((goroot/'VERSION').read_text().splitlines()[0]=='go'+lock['go']['version'],'Go archive VERSION differs')
    upxversion=subprocess.check_output([str(upxroot/'upx'),'--version'],env=env,text=True).splitlines()[0]
    need(upxversion.startswith('upx '+UPX['version']), 'Actual UPX version differs')
    inputs={name:digest(source/name) for name in ('go.mod','go.sum','go.toolchain.rev','VERSION.txt')}
    if prefetch_only:
        need(not offline, 'Prefetch requires the explicit online configure phase')
        subprocess.run(commands['prefetch'],cwd=source,env=env,check=True)
        need(inputs=={name:digest(source/name) for name in inputs}, 'Module prefetch changed pinned source inputs')
        return {'prefetched':True,'module_cache':env['GOMODCACHE'],'source_inputs':inputs}
    for key in ('compile','compress','test','restore'):

        subprocess.run(commands[key],cwd=source,env=env,check=True)
        if key=='compile':elf_arm64(work/'tailscale.multicall.unpacked')
    need(inputs=={name:digest(source/name) for name in inputs}, 'Build changed pinned Go module/source inputs')
    raw=work/'tailscale.multicall.unpacked';need(digest(raw)==digest(work/'restored.multicall'),'UPX roundtrip changed executable bytes')
    info=subprocess.check_output([str(goroot/'bin/go'),'version','-m',str(raw)],env=env,text=True)
    need('ts_include_cli' in info and 'ts_omit' not in info, 'Embedded feature build tags differ')
    proof={'schema_version':1,'kind':'tailscale-full-feature-multicall-upx','lock':lock,'go_version':version,'upx_version':upxversion,
           'commands':{k:commands[k] for k in ('compile','compress','test','restore')},'build_info':info,'source_sha256':digest(source_archive),'unpacked_sha256':digest(raw),'unpacked_size':raw.stat().st_size,
           'packed_sha256':digest(output),'packed_size':output.stat().st_size,'upx_test_and_exact_roundtrip':True,'feature_reducing_tags':[],
           'module_cache':env['GOMODCACHE'],'offline_compile':offline,'offline_compile_mechanism':'GOPROXY=off with prefetched cache; GOSUMDB remains enabled; helper does not disable the network namespace','source_inputs':inputs,'target_runtime_tested':False,'package_format':'agnostic','binary_paths':['usr/sbin/tailscale.multicall'],
           'relative_aliases':{'usr/sbin/tailscale':'tailscale.multicall','usr/sbin/tailscaled':'tailscale.multicall'}}
    output.with_name(output.name+'.proof.json').write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
    return proof



def downloads(lock, directory):
    validate(lock);directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    records=(('source',lock,'tailscale-'+lock['commit']+'.tar.gz',32*1024**2),
             ('go',lock['go'],'tailscale-go-'+lock['go']['commit']+'-linux-amd64.tar.gz',128*1024**2),
             ('upx',lock['upx'],'upx-5.2.1-amd64_linux.tar.xz',4*1024**2))
    result={}
    for name,pin,filename,limit in records:
        target=directory/filename
        if not target.exists():
            partial=target.with_name(target.name+'.partial');started=time.monotonic();size=0
            with urllib.request.urlopen(pin['url'],timeout=30) as response,partial.open('xb') as stream:
                while True:
                    data=response.read(256*1024)
                    if not data:break
                    size+=len(data);need(size<=limit,'Download exceeds pinned archive bound');stream.write(data)
                    pause=size/(8*1024**2)-(time.monotonic()-started)
                    if pause>0:time.sleep(pause)
            check_archive(partial,pin,limit);partial.rename(target)
        check_archive(target,pin,limit);result[name]=target
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    r=sub.add_parser('resolve');r.add_argument('--version',required=True);r.add_argument('--output',type=Path,required=True)
    v=sub.add_parser('verify-build');v.add_argument('--lock',type=Path,required=True);v.add_argument('--work',type=Path,required=True);v.add_argument('--output',type=Path,required=True);v.add_argument('--jobs',type=int,default=4)
    b=sub.add_parser('build')
    for name in ('lock','source-archive','go-archive','upx-archive','work','output'):b.add_argument('--'+name,type=Path,required=True)
    b.add_argument('--source-dir',type=Path);b.add_argument('--jobs',type=int,default=4)
    b.add_argument('--module-cache',type=Path);b.add_argument('--offline',action='store_true');b.add_argument('--prefetch-only',action='store_true')
    args=p.parse_args()
    if args.command=='resolve':args.output.write_text(json.dumps(resolve(args.version),indent=2,sort_keys=True)+'\n')
    elif args.command=='verify-build':
        lock=json.loads(args.lock.read_text());archives=downloads(lock,args.work/'downloads')
        build(lock,archives['source'],archives['go'],archives['upx'],args.work/'prefetch',args.output,args.jobs,module_cache=args.work/'mod-cache',prefetch_only=True)
        build(lock,archives['source'],archives['go'],archives['upx'],args.work/'build',args.output,args.jobs,module_cache=args.work/'mod-cache',offline=True)
    else:build(json.loads(args.lock.read_text()),args.source_archive,args.go_archive,args.upx_archive,args.work,args.output,args.jobs,args.source_dir,args.module_cache,args.offline,args.prefetch_only)

if __name__=='__main__':main()
