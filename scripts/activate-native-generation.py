#!/usr/bin/env python3
"""Activate only the independently approved REC/b122 native generation.

The ticket is explicit SHA-bound operator authorization, not a claim that the
hosted runner independently repeated local smoke builds. Normal signed snapshot,
portable native receipt, complete Image, predecessor and latest checks are replayed.
"""
import argparse,base64,binascii,hashlib,importlib.util,json,os,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
REPOSITORY='valujin/ax6000-packages-6.12'
SITE='https://valujin.github.io/ax6000-packages-6.12'
BUILD='redmi-ax6000-612-recommended-ae65e1de6997-50a1bd72eee1'
PROFILE_SHA='a3575ff580b2495e5fde0b9d2164e8a84b27e65e0a0bf95d973954603818adb9'
PROFILE='profiles/redmi-ax6000-612-recommended-b122.json'
PINS={'profile_sha256':PROFILE_SHA,'native_status_sha256':'e7bfbf6ad2698eb05718b0c379c81468b681a5f84b07161d9da252dcc979dbf6','native_evidence_sha256':'c71d134343482bd84c8cb9d465aeebdec38a203d4d53b20730186a3f68da46e0','sdk_sha256':'50a1bd72eee117acf22d353e11b93930820f3a5c72fbf1cead663043320b163d','imagebuilder_sha256':'952871ae7a71285445fd68c01df13ee68b9be51da1d51ef0e2b9fe549adcb5e2','tail_sha256':'4600a0a499dd8484247c8217adf5f6a43cb86b44528c1afeec954ae188287a00'}
FIELDS={'schema_version','kind','eligible_for_normal_activation','snapshot_sha256',*PINS,'client_evidence_sha256','smoke_evidence_sha256','portable_proof_sha256','predecessor_pointer','latest_pointer','pointer'}

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

def validate_proof_transport(proof):
    need(isinstance(proof,dict) and set(proof)=={'schema_version','kind','summary'} and type(proof['schema_version']) is int and proof['schema_version']==2 and proof['kind']=='rec-native-apk-generation-transition-v2' and isinstance(proof['summary'],dict),'Only finite new-context native-v2 proof is allowed')

def validate_ticket(ticket,pointer,predecessor,proof_sha):
    need(isinstance(ticket,dict) and set(ticket)==FIELDS and type(ticket['schema_version']) is int and ticket['schema_version']==1 and ticket['kind']=='rec-b122-publication-activation-authorization' and ticket['eligible_for_normal_activation'] is True,'Explicit finite activation authorization required')
    need(all(ticket.get(k)==v for k,v in PINS.items()) and ticket['pointer']==pointer and pointer.get('build_id')==BUILD and ticket['snapshot_sha256']==pointer.get('manifest_sha256') and ticket['predecessor_pointer'].get('manifest_sha256')==predecessor and ticket['portable_proof_sha256']==proof_sha,'Actual native/snapshot/predecessor/proof authorization differs')
    for key in ('snapshot_sha256','client_evidence_sha256','smoke_evidence_sha256','portable_proof_sha256'):
        need(isinstance(ticket[key],str) and re.fullmatch('[a-f0-9]{64}',ticket[key]),'Missing actual local acceptance digest')

def authorize_transition(snapshot,old,new,old_tree,new_tree,old_pointer,proof_path,proof_sha):
    snapshot.validate_generation_replacement(old,new,old['build_id'],allow_native_apk_replacement=True,native_replacement_proof=proof_path,native_replacement_proof_sha256=proof_sha)
    native=snapshot.module('native_generation')
    reviewed=native.validate_receipt(old,new,proof_path,proof_sha,predecessor_pointer=old_pointer,old_tree=old_tree,new_tree=new_tree)
    native.validate_payloads(old_tree,new_tree,reviewed,snapshot.read_json,snapshot.module('publication_api'),snapshot._MIGRATION_IMAGE_CACHE,snapshot._MIGRATION_DOWNLOAD_BUDGET)
    return reviewed

def require_live_predecessor(previous,ticket,predecessor):
    need(previous is not None and set(previous['channels'])=={'recommended','latest'},'Both authenticated existing channels required')
    need(previous['channels']['recommended']==ticket['predecessor_pointer'] and previous['channels']['recommended']['manifest_sha256']==predecessor and previous['channels']['latest']==ticket['latest_pointer'],'Authenticated predecessor/latest changed')

def require_live_unchanged(snapshot,previous,site,public_key,usign,work):
    need(snapshot.fetch_live(site,REPOSITORY,public_key,usign,work/'live-recheck')==previous,'Authenticated live state changed; do not deploy')

def activate(snapshot,pointer,ticket,predecessor,proof_path,proof_sha,site,profiles,work,key,public_key,usign,apk,output):
    validate_ticket(ticket,pointer,predecessor,proof_sha)
    need(site==SITE,'Wrong finite activation site')
    need(snapshot.sha256_file(ROOT/PROFILE)==PROFILE_SHA,'Fixed independently accepted native profile differs')
    incoming_profile=snapshot.read_json(ROOT/PROFILE)
    need(incoming_profile['build_id']==BUILD and incoming_profile['sdk']['sha256']==PINS['sdk_sha256'] and incoming_profile['imagebuilder']['sha256']==PINS['imagebuilder_sha256'] and incoming_profile['package_only']==['tailscale'] and 'tailscale' not in incoming_profile['image_packages'],'Fixed native generation/default-ROM policy differs')
    work=snapshot.fresh(work);output=snapshot.fresh(output);work.mkdir(parents=True)
    previous=snapshot.fetch_live(site,REPOSITORY,public_key,usign,work/'live')
    require_live_predecessor(previous,ticket,predecessor)
    old_pointer=previous['channels']['recommended'];latest=previous['channels']['latest']
    restored=snapshot.restore_live_channels(previous,profiles,REPOSITORY,public_key,usign,work,apk=apk)
    old_tree,_=restored['recommended'];old,_=snapshot.restored_identity(old_tree,old_pointer,'recommended',REPOSITORY,public_key,usign,apk=apk)
    incoming=work/'incoming-recommended'
    snapshot.restore_online(pointer,incoming_profile,REPOSITORY,public_key,usign,incoming,apk=apk)
    snapshot.restored_identity(incoming,pointer,'recommended',REPOSITORY,public_key,usign,apk=apk)
    need((incoming/'channel/profile.json').read_bytes()==(ROOT/PROFILE).read_bytes(),'Incoming complete signed profile differs')
    feed=incoming/'channel/feeds'/incoming_profile['id']/incoming_profile['firmware']['kernel_version']
    tails=list(feed.glob('tailscale-*.apk'));need(len(tails)==1 and tails[0].name=='tailscale-1.104.2-r3.apk' and tails[0].stat().st_size==11921395 and snapshot.sha256_file(tails[0])==PINS['tail_sha256'],'Authenticated compact supplement was downgraded/replaced')
    authorize_transition(snapshot,old,incoming_profile,Path(old_tree)/'channel',incoming/'channel',old_pointer,proof_path,proof_sha)
    replacement={'recommended':((old_tree,old_pointer),old['build_id'])}
    restored['recommended']=(incoming,pointer)
    state=snapshot.compose_site(work/'live/site-state.json',work/'live/site-state.sig',restored,REPOSITORY,key,public_key,usign,output,replacements=replacement,allow_native_apk_replacement=True,native_replacement_proof=proof_path,native_replacement_proof_sha256=proof_sha,apk=apk)
    need(state['channels']['recommended']==pointer and state['channels']['latest']==latest,'Composition changed incoming or retained latest pointer')
    require_live_unchanged(snapshot,previous,site,public_key,usign,work)
    snapshot.deployment_record(work,output,site,False)
    return state

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('pointer-base64','expected-predecessor','native-proof-base64','native-proof-sha256','authorization-base64','authorization-sha256','site-url'):p.add_argument('--'+name)
    for name in ('profiles','work-root','output','key','public-key','usign','apk'):p.add_argument('--'+name,type=Path)
    p.add_argument('--repository',default=REPOSITORY)
    p.add_argument('--execute',action='store_true');a=p.parse_args()
    if not a.execute:
        print(json.dumps({'execute':False,'pages_deployed':False}));return
    need(all(value is not None for name,value in vars(a).items() if name!='execute'),'All reviewed activation arguments required')
    need(os.environ.get('GITHUB_REPOSITORY',REPOSITORY)==a.repository==REPOSITORY and a.site_url==SITE,'Wrong activation repository/site')
    spec=importlib.util.spec_from_file_location('native_activation_snapshot',ROOT/'scripts/channel-snapshot.py');snapshot=importlib.util.module_from_spec(spec);spec.loader.exec_module(snapshot)
    decoder_spec=importlib.util.spec_from_file_location('native_activation_pointer',ROOT/'scripts/activate-snapshot.py');decoder=importlib.util.module_from_spec(decoder_spec);decoder_spec.loader.exec_module(decoder)
    pointer=decoder.decode_pointer(a.pointer_base64,'recommended')
    proof=decode_json(a.native_proof_base64,65536);validate_proof_transport(proof)
    raw=base64.b64decode(a.native_proof_base64,validate=True);need(hashlib.sha256(raw).hexdigest()==a.native_proof_sha256,'Reviewed portable proof SHA differs')
    ticket=decode_json(a.authorization_base64,16384)
    auth_raw=base64.b64decode(a.authorization_base64,validate=True);need(hashlib.sha256(auth_raw).hexdigest()==a.authorization_sha256,'Reviewed activation authorization SHA differs')
    validate_ticket(ticket,pointer,a.expected_predecessor,a.native_proof_sha256)
    proof_path=Path(os.environ['RUNNER_TEMP'])/'rec-native-proof.json'
    descriptor=os.open(proof_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as stream:stream.write(raw)
    activate(snapshot,pointer,ticket,a.expected_predecessor,proof_path,a.native_proof_sha256,a.site_url,a.profiles,a.work_root,a.key,a.public_key,a.usign,a.apk,a.output)

if __name__=='__main__':main()
