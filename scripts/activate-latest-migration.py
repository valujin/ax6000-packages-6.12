#!/usr/bin/env python3
"""Activate only the approved LATEST 31599 existing-context OPKG to APK migration.

The ticket is explicit SHA-bound operator authorization, not a claim that the
hosted runner independently repeated local smoke builds. Normal signed snapshot,
schema3 receipt, all six complete Images, predecessor and retained REC are replayed.
"""
import argparse,base64,binascii,hashlib,importlib.util,json,os,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
REPOSITORY='valujin/ax6000-packages-6.12'
SITE='https://valujin.github.io/ax6000-packages-6.12'
BUILD='redmi-ax6000-612-latest-a99b0888b88f-31599e148e45'
ABI='6.12.112~d405163bfdb42254c245797a894994c0-r1'
PROFILE='profiles/redmi-ax6000-612-latest-31599.json'
PINS={'profile_sha256': '6923e6be2fbfd2f4c880afc62b1b97053d71448c2686dd41e87829a773bd23b7', 'native_status_sha256': 'ef3920c9c2ac506d9a230c9eeda9d2b557d430c1673326a4f2fd0103cadf44f8', 'native_evidence_sha256': 'b8f289dc93d3e7bde0fe4990814e2c39b7d2bc688903d5f5764d15e97fcfca70', 'independent_artifact_sha256': '46cf44d7d9d56d69c9d35c53228430a594a53f02dfaab95c8ae22771ce7a9a6a', 'root_decision_sha256': '4ba65dc1f31383a40f538ddc5c1c6ad29dc5ba12c7885771b04d9d5ac303a1e9', 'hosted_context_sha256': '428ef4d3df486f2e9ad85876915c04e5749aad4d1662f1d4e43908ebae96930f', 'migration_proof_sha256': '2930d47d587077772c5382fa883869ea89d7e0b56d884f4a0a028297e12fcf58', 'sdk_sha256': '31599e148e45f95ec1d6bdfb36308c48e4ec12e3d489be302ef9c372acd2b6eb', 'imagebuilder_sha256': 'aac3e05c2d1465cf509d6c67db1eebacb87578bca4abd028455073c6a1e884c5', 'tail_sha256': '4600a0a499dd8484247c8217adf5f6a43cb86b44528c1afeec954ae188287a00'}
PREDECESSOR={'archive_sha256': '5f261e4480d32d4237df0f6318290f0aa6b3ba32c62c802a4c756ee4050920f8', 'archive_size': 107107048, 'asset_id': 661561069, 'build_id': 'redmi-ax6000-612-latest-a99b0888b88f-0b1249707848', 'channel': 'latest', 'kernel_version': '6.12.112~d405163bfdb42254c245797a894994c0-r1', 'manifest_sha256': '074e68e5f9d0105e2f3f19719271f5a68ff5339ab7dcfe6baac0b7f2b1619ea3', 'profile_id': 'redmi-ax6000-612-latest', 'release_id': 419221190, 'tag': 'packages-latest-074e68e5f9d0105e2f3f19719271f5a68ff5339ab7dcfe6baac0b7f2b1619ea3'}
RECOMMENDED={'archive_sha256': '5664f4ff3800e1840a6f7d033a69f6eb2e6d0ba18e424838bcfb1698154cec09', 'archive_size': 82922082, 'asset_id': 664771104, 'build_id': 'redmi-ax6000-612-recommended-ae65e1de6997-50a1bd72eee1', 'channel': 'recommended', 'kernel_version': '6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1', 'manifest_sha256': '878aa0b42652a3729c4cfdc72ce4bfe84d6fb24e87bf1d393ac7839f9e4eb4cc', 'profile_id': 'redmi-ax6000-612-recommended', 'release_id': 420336354, 'tag': 'packages-recommended-878aa0b42652a3729c4cfdc72ce4bfe84d6fb24e87bf1d393ac7839f9e4eb4cc'}
FIELDS={'schema_version','kind','eligible_for_normal_activation',*PINS,'snapshot_sha256','client_evidence_sha256','smoke_evidence_sha256','predecessor_pointer','recommended_pointer','pointer'}
POINTER_FIELDS={'channel','profile_id','build_id','kernel_version','manifest_sha256','tag','release_id','asset_id','archive_sha256','archive_size'}
PROOF_FIELDS={'reviewed_context', 'kernel_context', 'schema_version', 'functional_image', 'kernel_version', 'predecessor_pointer', 'firmware_manifest_sha256', 'predecessor_build_id', 'source_patches', 'source_commit', 'cohort', 'successor_build_id', 'kind'}

def need(value,message):
    if not value:raise ValueError(message)

def decode_json(encoded,cap):
    need(isinstance(encoded,str) and 0<len(encoded)<=4*((cap+2)//3),'Missing/oversized encoded proof')
    try:
        payload=base64.b64decode(encoded,validate=True)
        need(len(payload)<=cap and base64.b64encode(payload).decode()==encoded,'Noncanonical/oversized proof')
        def unique(pairs):
            result={}
            for key,value in pairs:need(key not in result,'Duplicate proof JSON field');result[key]=value
            return result
        def finite(_):raise ValueError('Nonfinite JSON')
        return json.loads(payload.decode(),object_pairs_hook=unique,parse_constant=finite)
    except (binascii.Error,UnicodeError) as error:raise ValueError('Invalid encoded proof') from error

def decode_pointer(encoded):
    pointer=decode_json(encoded,4096)
    need(isinstance(pointer,dict) and set(pointer)==POINTER_FIELDS,'Incomplete or unknown snapshot pointer fields')
    need(pointer['channel']=='latest' and pointer['profile_id']=='redmi-ax6000-612-latest' and pointer['build_id']==BUILD and pointer['kernel_version']==ABI,'Pointer belongs to another generation')
    for key in ('manifest_sha256','archive_sha256'):
        need(isinstance(pointer[key],str) and re.fullmatch('[0-9a-f]{64}',pointer[key]),'Invalid pointer digest')
    need(pointer['tag']=='packages-latest-'+pointer['manifest_sha256'],'Pointer tag differs from manifest')
    for key in ('release_id','asset_id','archive_size'):
        need(type(pointer[key]) is int and pointer[key]>0,'Invalid pointer numeric identity')
    need(pointer['archive_size']<2*1024**3,'Snapshot archive exceeds transport bound')
    return pointer

def validate_proof_transport(proof):
    need(isinstance(proof,dict) and set(proof)==PROOF_FIELDS and type(proof['schema_version']) is int and proof['schema_version']==3 and proof['kind']=='asu-apk-native-migration' and proof['cohort']=='612-latest','Only finite LATEST existing-context schema3 proof is allowed')

def validate_ticket(ticket,pointer,predecessor,proof_sha):
    need(isinstance(ticket,dict) and set(ticket)==FIELDS and type(ticket['schema_version']) is int and ticket['schema_version']==1 and ticket['kind']=='latest-31599-publication-activation-authorization' and ticket['eligible_for_normal_activation'] is True,'Explicit finite activation authorization required')
    need(all(ticket.get(k)==v for k,v in PINS.items()) and ticket['pointer']==pointer and pointer.get('build_id')==BUILD and ticket['snapshot_sha256']==pointer.get('manifest_sha256') and ticket['predecessor_pointer']==PREDECESSOR and ticket['recommended_pointer']==RECOMMENDED and predecessor==PREDECESSOR['manifest_sha256'] and proof_sha==PINS['migration_proof_sha256'],'Actual context/snapshot/predecessor/proof authorization differs')
    for row in (ticket['predecessor_pointer'],ticket['recommended_pointer']):
        need(all(type(row[k]) is int for k in ('release_id','asset_id','archive_size')),'Retained pointer numeric identity differs')
    for key in ('snapshot_sha256','client_evidence_sha256','smoke_evidence_sha256'):
        need(isinstance(ticket[key],str) and re.fullmatch('[a-f0-9]{64}',ticket[key]) and ticket[key]!='0'*64,'Missing actual local acceptance digest')

def checked_file(path,expected):
    path=Path(path)
    need(path.is_file() and not any(p.is_symlink() for p in (path,*path.parents)) and hashlib.sha256(path.read_bytes()).hexdigest()==expected,'Fixed accepted source profile/key differs')

def validate_fixed_profiles(profiles,public_key):
    need(Path(profiles).resolve()==ROOT/'profiles' and Path(public_key).resolve()==ROOT/'keys/repository.pub','Only fixed checkout profiles/key are allowed')
    for name,sha in {PROFILE:PINS['profile_sha256'],'profiles/redmi-ax6000-612-latest.json':'aeef60180ae24f1c35a35281de5d9c81856b98e3e20460bca956e8acfc45327d','profiles/redmi-ax6000-612-recommended.json':'a3575ff580b2495e5fde0b9d2164e8a84b27e65e0a0bf95d973954603818adb9','keys/repository.pub':'577aff0f82785ffef5db1279fa2962a5be1fcae9573b2fed2bf27e654bab88ad'}.items():checked_file(ROOT/name,sha)
    profile=json.loads((ROOT/PROFILE).read_bytes())
    need(profile['build_id']==BUILD and profile['sdk']['sha256']==PINS['sdk_sha256'] and profile['imagebuilder']['sha256']==PINS['imagebuilder_sha256'] and profile['package_only']==['tailscale'] and 'tailscale' not in profile['image_packages'],'Fixed generation/default-ROM policy differs')
    return profile

def authorize_transition(snapshot,old,new,old_tree,new_tree,old_pointer,proof):
    snapshot.validate_generation_replacement(old,new,old['build_id'],allow_asu_apk_migration=True,migration_proof=proof)
    snapshot.validate_migration_manifests(old_tree,new_tree,proof,predecessor_pointer=old_pointer)

def require_live_predecessor(previous,ticket,predecessor):
    need(previous is not None and set(previous['channels'])=={'recommended','latest'},'Both authenticated existing channels required')
    need(previous['channels']['latest']==ticket['predecessor_pointer']==PREDECESSOR and predecessor==PREDECESSOR['manifest_sha256'] and previous['channels']['recommended']==ticket['recommended_pointer']==RECOMMENDED,'Authenticated predecessor/retained REC changed')

def require_live_unchanged(snapshot,previous,site,public_key,usign,work):
    need(snapshot.fetch_live(site,REPOSITORY,public_key,usign,work/'live-recheck')==previous,'Authenticated live state changed; do not deploy')

def activate(snapshot,pointer,ticket,predecessor,proof,proof_sha,site,profiles,work,key,public_key,usign,apk,output):
    validate_ticket(ticket,pointer,predecessor,proof_sha)
    need(site==SITE,'Wrong finite activation site')
    incoming_profile=validate_fixed_profiles(profiles,public_key)
    work=snapshot.fresh(work);output=snapshot.fresh(output);work.mkdir(parents=True)
    previous=snapshot.fetch_live(site,REPOSITORY,public_key,usign,work/'live')
    require_live_predecessor(previous,ticket,predecessor)
    old_pointer=previous['channels']['latest'];recommended=previous['channels']['recommended']
    restored=snapshot.restore_live_channels(previous,profiles,REPOSITORY,public_key,usign,work,apk=apk)
    old_tree,_=restored['latest'];old,_=snapshot.restored_identity(old_tree,old_pointer,'latest',REPOSITORY,public_key,usign,apk=apk)
    incoming=work/'incoming-latest'
    snapshot.restore_online(pointer,incoming_profile,REPOSITORY,public_key,usign,incoming,apk=apk)
    snapshot.restored_identity(incoming,pointer,'latest',REPOSITORY,public_key,usign,apk=apk)
    need((incoming/'channel/profile.json').read_bytes()==(ROOT/PROFILE).read_bytes(),'Incoming complete signed profile differs')
    feed=incoming/'channel/feeds'/incoming_profile['id']/incoming_profile['firmware']['kernel_version']
    tails=list(feed.glob('tailscale-*.apk'));need(len(tails)==1 and tails[0].name=='tailscale-1.104.2-r3.apk' and tails[0].stat().st_size==11921395 and snapshot.sha256_file(tails[0])==PINS['tail_sha256'],'Authenticated compact supplement was downgraded/replaced')
    authorize_transition(snapshot,old,incoming_profile,Path(old_tree)/'channel',incoming/'channel',old_pointer,proof)
    replacement={'latest':((old_tree,old_pointer),old['build_id'])}
    restored['latest']=(incoming,pointer)
    state=snapshot.compose_site(work/'live/site-state.json',work/'live/site-state.sig',restored,REPOSITORY,key,public_key,usign,output,replacements=replacement,allow_asu_apk_migration=True,migration_proof=proof,apk=apk)
    need(state['channels']['latest']==pointer and state['channels']['recommended']==recommended,'Composition changed incoming or retained REC pointer')
    require_live_unchanged(snapshot,previous,site,public_key,usign,work)
    snapshot.deployment_record(work,output,site,False)
    return state

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('pointer-base64','expected-predecessor','migration-proof-base64','migration-proof-sha256','authorization-base64','authorization-sha256','site-url'):p.add_argument('--'+name)
    for name in ('profiles','work-root','output','key','public-key','usign','apk'):p.add_argument('--'+name,type=Path)
    p.add_argument('--repository',default=REPOSITORY)
    p.add_argument('--execute',action='store_true');p.add_argument('--check-inputs',action='store_true');a=p.parse_args()
    if not a.execute and not a.check_inputs:
        print(json.dumps({'execute':False,'pages_deployed':False}));return
    required=('pointer_base64','expected_predecessor','migration_proof_base64','migration_proof_sha256','authorization_base64','authorization_sha256','site_url','profiles','public_key')
    need(all(getattr(a,name) is not None for name in required),'All reviewed input arguments required')
    need(os.environ.get('GITHUB_REPOSITORY',REPOSITORY)==a.repository==REPOSITORY and a.site_url==SITE,'Wrong activation repository/site')
    pointer=decode_pointer(a.pointer_base64)
    proof=decode_json(a.migration_proof_base64,65536);validate_proof_transport(proof)
    raw=base64.b64decode(a.migration_proof_base64,validate=True)
    need(hashlib.sha256(raw).hexdigest()==a.migration_proof_sha256==PINS['migration_proof_sha256'],'Reviewed migration proof SHA differs')
    ticket=decode_json(a.authorization_base64,16384)
    need(hashlib.sha256(base64.b64decode(a.authorization_base64,validate=True)).hexdigest()==a.authorization_sha256,'Reviewed activation authorization SHA differs')
    validate_ticket(ticket,pointer,a.expected_predecessor,a.migration_proof_sha256)
    validate_fixed_profiles(a.profiles,a.public_key)
    if a.check_inputs:
        need(not a.execute,'Choose input check or execution')
        print(json.dumps({'eligible_for_normal_activation':True,'check_inputs_only':True,'pages_deployed':False}));return
    need(all(getattr(a,name) is not None for name in ('work_root','output','key','usign','apk')),'All reviewed execution arguments required')
    # Execute the authenticated checkout source, never a pre-existing bytecode cache.
    path=ROOT/'scripts/channel-snapshot.py'
    spec=importlib.util.spec_from_file_location('latest_activation_snapshot',path);snapshot=importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(),str(path),'exec'),snapshot.__dict__)
    activate(snapshot,pointer,ticket,a.expected_predecessor,proof,a.migration_proof_sha256,a.site_url,a.profiles,a.work_root,a.key,a.public_key,a.usign,a.apk,a.output)

if __name__=='__main__':main()
