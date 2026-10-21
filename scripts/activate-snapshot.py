#!/usr/bin/env python3
"""Activate a prepublished, signed REC package snapshot without rebuilding RAW."""
import argparse
import base64
import binascii
import importlib.util
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
REPOSITORY='valujin/ax6000-packages-6.12'
PROFILE_SHA256='94dfcdca38c122a2ea0f8cac3a780d6cf6c6f91e12464a99caf0ffd9698ca9a9'
POINTER_FIELDS={'channel','profile_id','build_id','kernel_version','manifest_sha256','tag',
                'release_id','asset_id','archive_sha256','archive_size'}
MAX_POINTER=4096


def need(value,message):
    if not value:raise ValueError(message)


def snapshot_module():
    spec=importlib.util.spec_from_file_location('activation_snapshot',ROOT/'scripts/channel-snapshot.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def decode_pointer(encoded,channel):
    need(channel=='recommended','Only recommended snapshot activation is supported')
    need(isinstance(encoded,str) and 0<len(encoded)<=4*((MAX_POINTER+2)//3),'Missing or oversized snapshot pointer')
    try:
        raw=base64.b64decode(encoded,validate=True)
        need(len(raw)<=MAX_POINTER and base64.b64encode(raw).decode()==encoded,'Noncanonical or oversized snapshot pointer')
        def unique(pairs):
            result={}
            for key,value in pairs:
                need(key not in result,'Duplicate pointer JSON field');result[key]=value
            return result
        def finite(_):raise ValueError('Nonfinite pointer JSON value')
        pointer=json.loads(raw.decode('utf-8'),object_pairs_hook=unique,parse_constant=finite)
    except (binascii.Error,UnicodeError) as error:raise ValueError('Invalid base64 UTF-8 pointer') from error
    need(isinstance(pointer,dict) and set(pointer)==POINTER_FIELDS,'Incomplete or unknown snapshot pointer fields')
    need(pointer['channel']==channel and pointer['profile_id']=='redmi-ax6000-612-'+channel,'Pointer belongs to another channel')
    for key in ('manifest_sha256','archive_sha256'):
        need(isinstance(pointer[key],str) and re.fullmatch('[0-9a-f]{64}',pointer[key]),'Invalid pointer digest')
    need(pointer['tag']=='packages-'+channel+'-'+pointer['manifest_sha256'],'Pointer tag differs from manifest')
    for key in ('release_id','asset_id','archive_size'):
        need(type(pointer[key]) is int and pointer[key]>0,'Invalid pointer numeric identity')
    need(pointer['archive_size']<2*1024**3,'Snapshot archive exceeds transport bound')
    return pointer


def activate(encoded,channel,expected_predecessor,site_url,repository,profiles,work,key,public_key,usign,apk,output):
    pointer=decode_pointer(encoded,channel)
    need(repository==REPOSITORY,'Wrong publication repository')
    need(isinstance(expected_predecessor,str) and re.fullmatch('[0-9a-f]{64}',expected_predecessor),'Exact live predecessor manifest SHA256 required')
    snapshot=snapshot_module()
    active=Path(profiles)/'redmi-ax6000-612-recommended.json'
    profile=snapshot.read_json(active)
    need(snapshot.sha256_file(active)==PROFILE_SHA256,'Active recommended profile is not the accepted R5 APK profile')
    need(profile.get('package_manager')=='apk' and profile.get('channel')==channel,'Active profile is not recommended APK')
    for field,value in {'profile_id':profile['id'],'build_id':profile['build_id'],'kernel_version':profile['firmware']['kernel_version']}.items():
        need(pointer.get(field)==value,'Incoming snapshot changes the active firmware generation')
    work=snapshot.fresh(work);output=snapshot.fresh(output);work.mkdir(parents=True)
    previous=snapshot.fetch_live(site_url,repository,public_key,usign,work/'live')
    need(previous is not None and all(previous['channels'].get(name) is not None for name in ('recommended','latest')),'Both authenticated live channels are required')
    old=previous['channels']['recommended'];latest=previous['channels']['latest']
    need(old.get('manifest_sha256')==expected_predecessor,'Authenticated live predecessor differs from explicit authorization')
    need(pointer['manifest_sha256']!=expected_predecessor,'Incoming snapshot is already the live predecessor')
    for field in ('profile_id','build_id','kernel_version'):
        need(old.get(field)==pointer.get(field),'Snapshot activation cannot change firmware generation')
    # Restore both generations to authenticate complete profile bytes, not just
    # pointer fields. All signature/index/catalog/API checks stay in normal APIs.
    old_tree=work/'previous-recommended';incoming=work/'incoming-recommended';retained=work/'retained-latest'
    snapshot.restore_online(old,profile,repository,public_key,usign,old_tree,apk=apk)
    snapshot.restored_identity(old_tree,old,channel,repository,public_key,usign,apk=apk)
    need((old_tree/'channel/profile.json').read_bytes()==active.read_bytes(),'Live predecessor profile bytes differ from active R5')
    snapshot.restore_online(pointer,profile,repository,public_key,usign,incoming,apk=apk)
    snapshot.restored_identity(incoming,pointer,channel,repository,public_key,usign,apk=apk)
    need((incoming/'channel/profile.json').read_bytes()==active.read_bytes(),'Incoming profile bytes differ from active R5')
    retained_profile=snapshot.read_json(Path(profiles)/'redmi-ax6000-612-latest.json')
    snapshot.restore_online(latest,retained_profile,repository,public_key,usign,retained,apk=apk)
    snapshot.restored_identity(retained,latest,'latest',repository,public_key,usign,apk=apk)
    state=snapshot.compose_site(work/'live/site-state.json',work/'live/site-state.sig',
        {'recommended':(incoming,pointer),'latest':(retained,latest)},repository,key,public_key,usign,output,apk=apk)
    need(state['channels']['recommended']==pointer and state['channels']['latest']==latest,'Composition changed the requested/retained pointer')
    after=snapshot.fetch_live(site_url,repository,public_key,usign,work/'live-recheck')
    need(after==previous,'Authenticated live state changed; do not deploy')
    snapshot.deployment_record(work,output,site_url,False)
    return state


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--channel',required=True,choices=('recommended',))
    parser.add_argument('--pointer-base64',required=True)
    parser.add_argument('--expected-predecessor',required=True)
    for name in ('site-url','repository'):parser.add_argument('--'+name,required=True)
    for name in ('profiles','work-root','key','public-key','usign','apk','output'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    try:
        activate(args.pointer_base64,args.channel,args.expected_predecessor,args.site_url,args.repository,args.profiles,args.work_root,args.key,args.public_key,args.usign,args.apk,args.output)
    except (ValueError,OSError,KeyError) as error:parser.exit(1,'activate-snapshot: '+str(error)+'\n')

if __name__=='__main__':main()
