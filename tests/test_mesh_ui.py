"""Execute the LuCI view against a small DOM/RPC harness, without a router."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'files/mediatek-mesh/packages/luci-app-ax6000-mesh'
VIEW = PACKAGE / 'htdocs/luci-static/resources/view/network/ax6000-mesh.js'


@unittest.skipUnless(shutil.which('node'), 'Node.js required for LuCI behavioral tests')
class MeshUI(unittest.TestCase):
    def test_status_actions_and_untrusted_text(self):
        self.assertTrue(VIEW.is_file(), 'MediaTek Mesh view is absent')
        harness = r'''
const fs = require('fs'), assert = require('assert');
const calls = [], notifications = [], polls = [];
let fail = false, enabled = false, pending = false;
const rpc = {declare(spec) {return async function(...args) {
  calls.push([spec.method, args]);
  if (spec.method === 'status') return {ok:true, enabled, running:enabled,
    role:'controller',backhaul:'wireless',state:pending?'applying':enabled?'running':'disabled',detail:'<img src=x onerror=alert(1)>'};
  if (fail) return {ok:false,error:'preflight rejected'};
  if (spec.method === 'apply') {pending=true;return {ok:true,state:'applying'};}
  if (spec.method === 'disable') enabled=false;
  return {ok:true};
};}};
function E(tag, attrs, children) {
  if (Array.isArray(attrs)) {children=attrs;attrs={};}
  return {tag,attrs:attrs||{},children:children||[],value:attrs?.value||'',disabled:false,style:{},
    getAttribute(key){return this.attrs[key];},
    replaceChildren(...nodes){this.children=nodes;},appendChild(node){this.children.push(node);}};
}
const ui = {addNotification(a,b){notifications.push(b);}};
const dom = {content(n,c){n.children=Array.isArray(c)?c:[c];}};
const view = {extend(o){return o;}};
const page = new Function('view','rpc','ui','poll','dom','E','_','L',fs.readFileSync(process.argv[1],'utf8'))(
  view,rpc,ui,{add(fn){polls.push(fn);}},dom,E,x=>x,{url(...parts){return '/cgi-bin/luci/'+parts.join('/');}});
function all(n){return !n || typeof n!=='object'?[]:[n,...(n.children||[]).flatMap(all)];}
(async()=>{
  const tree = page.render(await page.load());
  const nodes = all(tree), buttons = nodes.filter(n=>n.tag==='button');
  const text = JSON.stringify(tree);
  assert(text.includes('<img src=x onerror=alert(1)>'), 'server detail rendered as text');
  assert(!nodes.some(n=>n.tag==='img'), 'RPC text must not become DOM markup');
  assert(!nodes.some(n=>n.attrs.innerHTML), 'no innerHTML');
  const apply = buttons.find(n=>n.attrs['data-action']==='apply');
  const backhaulRow = nodes.find(n=>n.children && n.children.some(c=>c && c.tag==='label' && c.attrs.for==='mesh-backhaul'));
  assert.equal(backhaulRow.style.display, 'none', 'controller hides agent connection selector in Argon');
  const pair = buttons.find(n=>n.attrs['data-action']==='pair');
  const disable = buttons.find(n=>n.attrs['data-action']==='disable');
  assert(apply&&pair&&disable);
  assert.equal(nodes.find(n=>n.attrs.id==='mesh-security').value,'sae','new setup defaults WPA3');
  assert(text.includes('WPA3-SAE (recommended)') && text.includes('WPA2-PSK (compatibility)'));
  const bandRow=nodes.find(n=>n.children?.some(c=>c?.tag==='label'&&c.attrs.for==='mesh-band'));
  assert.equal(bandRow.style.display,'none','controller band selector hidden');
  const actions = nodes.find(n=>n.attrs.class==='cbi-page-actions');
  assert((actions.attrs.style || '').includes('flex-wrap: wrap'), 'action row wraps on narrow screens');
  assert(buttons.every(n=>(n.attrs.style || '').includes('white-space: normal')), 'long labels can wrap');
  await apply.attrs.click();
  assert.deepEqual(calls.filter(x=>['configure','apply'].includes(x[0])).map(x=>x[0]),['configure','apply']);
  assert(apply.disabled && pair.disabled && disable.disabled, 'pending operation locks actions');
  pending=false; enabled=true; await polls[0]();
  assert(apply.disabled && !pair.disabled && !disable.disabled, 'running node supports pairing and restore');
  assert(nodes.find(n=>n.attrs.id==='mesh-security').disabled && nodes.find(n=>n.attrs.id==='mesh-band').disabled,'enabled policy is locked');
  await pair.attrs.click(); assert(calls.some(x=>x[0]==='pair'));
  await disable.attrs.click(); assert(calls.some(x=>x[0]==='disable'));
  fail=true; const before=calls.filter(x=>x[0]==='apply').length;
  await apply.attrs.click();
  assert.equal(calls.filter(x=>x[0]==='apply').length,before,'failed configure cannot activate');
  assert(notifications.length>0, 'show backend error');
  assert(!apply.disabled,'failed action unlocks buttons');
  assert(polls.length===1);
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', harness, str(VIEW)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_agent_setup_and_peer_status(self):
        harness = r'''
const fs = require('fs'), assert = require('assert');
let status = {ok:true,available:true,enabled:false,running:false,role:'agent',backhaul:'wired',state:'disabled'};
const calls=[], polls=[];
const rpc={declare(s){return async (...args)=>{calls.push([s.method,args]);return s.method==='status'?status:{ok:true};};}};
function E(tag,attrs,children){if(Array.isArray(attrs)){children=attrs;attrs={};}return {tag,attrs:attrs||{},children:children||[],value:attrs?.value||'',disabled:false,style:{},getAttribute(k){return this.attrs[k];}};}
const dom={content(n,c){n.children=Array.isArray(c)?c:[c];}};
const page=new Function('view','rpc','ui','poll','dom','E','_','L',fs.readFileSync(process.argv[1],'utf8'))(
 {extend:o=>o},rpc,{addNotification(){}},{add:f=>polls.push(f)},dom,E,x=>x,{url:()=>''});
function all(n){return !n||typeof n!=='object'?[]:[n,...(n.children||[]).flatMap(all)];}
(async()=>{
 const tree=page.render(await page.load());
 const nodes=all(tree), apply=nodes.find(n=>n.attrs['data-action']==='apply');
 assert(JSON.stringify(tree).includes('WAN port'), 'wired setup identifies the agent WAN port');
 assert(JSON.stringify(apply.children).includes('Join Mesh'), 'agent action identifies joining');
 const backhaulRow=nodes.find(n=>n.children && n.children.some(c=>c && c.tag==='label' && c.attrs.for==='mesh-backhaul'));
 assert.equal(backhaulRow.style.display, '', 'agent shows connection selector');
 assert(!JSON.stringify(tree).includes('disable its LAN DHCP server'), 'no manual DHCP setup');
 const bandRow=nodes.find(n=>n.children?.some(c=>c?.tag==='label'&&c.attrs.for==='mesh-band'));
 const securityRow=nodes.find(n=>n.children?.some(c=>c?.tag==='label'&&c.attrs.for==='mesh-security'));
 assert.equal(bandRow.style.display,'none','wired agent has no wireless band choice');
 assert.equal(securityRow.style.display,'none','wired agent has no wireless security choice');
 const connection=nodes.find(n=>n.attrs.id==='mesh-backhaul');
 connection.value='wireless';connection.onchange();
 assert.equal(bandRow.style.display,'','wireless agent band selector visible');
 assert.equal(securityRow.style.display,'','wireless agent security selector visible');
 connection.value='wired';connection.onchange();
 assert(JSON.stringify(tree).includes('enroll the node again'),'policy change explains re-enrollment');
 const legacy=page.render({...status,enabled:true});
 assert.equal(all(legacy).find(n=>n.attrs.id==='mesh-security').value,'psk2','enabled legacy setup stays WPA2');
 await apply.attrs.click();
 assert.deepEqual(calls.find(x=>x[0]==='configure')[1], ['agent','wired','sae','auto']);
 status={...status,enabled:true,running:true,phase:'connected',enrollment:{topology_valid:true,connected:true,peers:[{alid:'aa:bb:cc:dd:ee:ff'}]}};
 await polls[0]();
 let rendered=JSON.stringify(tree);
 assert(rendered.includes('aa:bb:cc:dd:ee:ff'), 'known peer identity shown');
 assert(rendered.includes('Address unknown'), 'missing address is not guessed');
 status={...status,state:'disabling',phase:'ready',enabled:true,running:true}; await polls[0]();
 assert(apply.disabled && nodes.find(n=>n.attrs['data-action']==='disable').disabled, 'operation state locks actions even when phase is stale');
 status={...status,enabled:false,running:false,state:'disabled',phase:'disabled',recovery_pending:true}; await polls[0]();
 const disable=nodes.find(n=>n.attrs['data-action']==='disable');
 const role=nodes.find(n=>n.attrs.id==='mesh-role');
 assert(apply.disabled && role.disabled, 'pending recovery blocks setup');
 assert(!disable.disabled && JSON.stringify(disable.children).includes('Restore previous settings'), 'pending recovery offers retry');
 status={...status,phase:'restored',error:'lease timed out'}; await polls[0]();
 assert(JSON.stringify(tree).includes('lease timed out'), 'show actual error');
 status={...status,enabled:true,running:true,recovery_pending:false,role:'agent',backhaul:'wireless',backhaul_security:'sae',backhaul_security_verified:false};
 await polls[0]();assert(JSON.stringify(tree).includes('Waiting for verified WPA3-SAE'),'unverified security visible');
 status={...status,backhaul_security_verified:true};await polls[0]();
 assert(JSON.stringify(tree).includes('Wireless backhaul verified: WPA3-SAE'),'verified security visible');
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', harness, str(VIEW)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_controller_connection_hint_uses_verified_enrollment(self):
        harness = r'''
const fs=require('fs'),assert=require('assert'),polls=[];
let status={ok:true,enabled:true,running:true,role:'controller',phase:'connected',
 backhaul_security:'sae',backhaul_security_verified:false,
 enrollment:{topology_valid:true,connected:true,peers:[
 {alid:'02:00:00:00:00:02',role:'agent',connected:true}]}};
const rpc={declare(s){return async()=>s.method==='status'?status:{ok:false};}};
function E(tag,attrs,children){if(Array.isArray(attrs)){children=attrs;attrs={};}return{tag,attrs:attrs||{},children:children||[],value:'',style:{},getAttribute(k){return this.attrs[k];}};}
const dom={content(n,c){n.children=Array.isArray(c)?c:[c];}};
const page=new Function('view','rpc','ui','poll','dom','E','_','L',fs.readFileSync(process.argv[1],'utf8'))(
 {extend:o=>o},rpc,{addNotification(){}},{add:f=>polls.push(f)},dom,E,x=>x,{});
(async()=>{
 const tree=page.render(await page.load());
 const text=()=>JSON.stringify(tree);
 const caution='A running service does not mean a node has joined.';
 assert(!text().includes(caution),'confirmed controller peer replaces caution');
 assert(text().includes('Connected Mesh nodes: 1'),'count comes from verified peer records');
 assert(!text().includes('Wireless backhaul verified: WPA3-SAE'),'controller has no verified upstream SAE link');
 status.enrollment.peers.push({role:'agent',connected:true},{role:'agent',connected:false},{role:'controller',connected:true});
 await polls[0]();assert(text().includes('Connected Mesh nodes: 2'),'count only connected agents');
 for(const enrollment of [
  {...status.enrollment,topology_valid:false},
  {...status.enrollment,connected:false},
  {...status.enrollment,peers:[]},
  {...status.enrollment,peers:[{role:'agent'}]},
  {}
 ]){
  status={...status,enrollment};await polls[0]();
  assert(text().includes(caution),'unverified or absent peer keeps caution');
  assert(!text().includes('Connected Mesh nodes:'),'no stale verified count');
  assert(!text().includes('Mesh node connected'),'stale phase does not claim verified controller peer');
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', harness, str(VIEW)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_managed_sync_states_never_claim_remote_guest_application(self):
        harness = r'''
const fs=require('fs'),assert=require('assert'),polls=[];
let status={ok:true,enabled:true,running:true,role:'controller',phase:'connected',
 enrollment:{topology_valid:true,connected:true,peers:[{role:'agent',connected:true}]}};
const rpc={declare(s){return async()=>s.method==='status'?status:{ok:false};}};
function E(tag,attrs,children){if(Array.isArray(attrs)){children=attrs;attrs={};}return{tag,attrs:attrs||{},children:children||[],value:'',style:{},getAttribute(k){return this.attrs[k];}};}
const dom={content(n,c){n.children=Array.isArray(c)?c:[c];}};
const page=new Function('view','rpc','ui','poll','dom','E','_','L',fs.readFileSync(process.argv[1],'utf8'))(
 {extend:o=>o},rpc,{addNotification(){}},{add:f=>polls.push(f)},dom,E,x=>x,{});
(async()=>{
 const tree=page.render(await page.load());
 assert(JSON.stringify(tree).includes('Guest network synchronization status is unknown.'));
 for(const [phase,message] of [
  ['unsupported','Guest network synchronization is unavailable for this configuration.'],
  ['pending','Guest network synchronization is pending.'],
  ['error','Guest network synchronization needs attention.'],
  ['managed','Local guest network management is ready. Synchronization on other Mesh nodes is not yet verified.'],
  ['<img src=x onerror=alert(1)>','Guest network synchronization status is unknown.']
 ]){
  status={...status,managed_sync_phase:phase};await polls[0]();const text=JSON.stringify(tree);
  assert(text.includes(message));assert(text.includes('Connected Mesh nodes: 1'),'enrollment status preserved');
  assert(!text.includes('onerror'),'arbitrary phase never rendered');
  assert(!text.includes('Wireless backhaul verified: WPA3-SAE'),'controller security not inferred');
 }
 status={...status,enabled:false};await polls[0]();
 assert(!JSON.stringify(tree).includes('Guest network synchronization status is unknown.'),'disabled Mesh has no stale sync status');
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', harness, str(VIEW)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_acl_limits_mutation_to_mesh_rpc(self):
        acl = json.loads((PACKAGE / 'root/usr/share/rpcd/acl.d/luci-app-ax6000-mesh.json').read_text())
        entry = acl['luci-app-ax6000-mesh']
        self.assertEqual(entry['read'], {'ubus': {'ax6000.mesh': ['status', 'clients']}})
        self.assertEqual(set(entry['write']['ubus']['ax6000.mesh']), {'configure', 'apply', 'pair', 'disable'})
        self.assertEqual(set(entry['write']), {'ubus'})

    def test_mesh_clients_nodes_links_and_unknown_measurements(self):
        harness = r'''
const fs=require('fs'),assert=require('assert');
const polls=[];
const snapshot={ok:true,nodes:[
 {alid:'02:00:00:00:00:01',local:true,role:1},
 {alid:'02:00:00:00:00:09',local:false,role:2,address:'10.10.1.175',hostname:'<img src=x onerror=alert(1)>'}],
 clients:[
 {mac:'04:00:00:00:00:01',node:'02:00:00:00:00:01',bssid:'02:00:00:00:00:02',local:true,band:'5g',address:'10.10.1.218',rssi_dbm:-61,tx_kbps:600000,tx_nss:2,tx_mcs:7,tx_bytes:1048576},
 {mac:'04:00:00:00:00:02',node:'02:00:00:00:00:09',bssid:'02:00:00:00:00:08',local:false,band:'2g',downlink_mbps:144,rx_bytes:null,rssi_dbm:null,rx_nss:99,rx_mcs:99,rx_kbps:999999}]};
let failed=false;
const rpc={declare(s){return async()=>s.method==='status'?{ok:true,enabled:true,running:true,role:'controller',state:'running'}:failed?{ok:false}:snapshot;}};
function E(tag,attrs,children){if(Array.isArray(attrs)){children=attrs;attrs={};}return{tag,attrs:attrs||{},children:children||[],value:'',style:{},getAttribute(k){return this.attrs[k];}};}
const dom={content(n,c){n.children=Array.isArray(c)?c:[c];}};
const page=new Function('view','rpc','ui','poll','dom','E','_','L',fs.readFileSync(process.argv[1],'utf8'))(
 {extend:o=>o},rpc,{addNotification(){}},{add:f=>polls.push(f)},dom,E,x=>x,{});
function all(n){return !n||typeof n!=='object'?[]:[n,...(n.children||[]).flatMap(all)];}
(async()=>{
 const tree=page.render(await page.load());let nodes=all(tree),serialized=JSON.stringify(tree);
 assert(nodes.some(n=>n.tag==='a'&&n.attrs.href==='http://10.10.1.175/cgi-bin/luci/'),'exact node address is clickable');
 assert(serialized.includes('04:00:00:00:00:01')&&serialized.includes('04:00:00:00:00:02'),'local and remote clients both shown');
 assert(serialized.includes('600.0 Mbit/s')&&serialized.includes('144 Mbit/s (estimated)'),'PHY and estimated rates labeled');
 assert(serialized.includes('2 / 7')&&!serialized.includes('99 / 99'),'remote NSS/MCS cannot be fabricated');
 assert(!nodes.some(n=>n.tag==='img'||n.attrs.innerHTML),'hostnames remain text');
 assert(serialized.includes('Unknown'),'missing measurements are not zero');
 snapshot.nodes[1].address='javascript:alert(1)';await polls[0]();
 assert(!all(tree).some(n=>n.tag==='a'&&n.attrs.href.startsWith('javascript:')),'address cannot become arbitrary URL');
 failed=true;await polls[0]();serialized=JSON.stringify(tree);
 assert(serialized.includes('Client information is unavailable'),'failed snapshot clears stale rows');
 assert(!serialized.includes('04:00:00:00:00:02'),'stale client data removed on failure');
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', harness, str(VIEW)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
