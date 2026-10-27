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
  await apply.attrs.click();
  assert.deepEqual(calls.filter(x=>['configure','apply'].includes(x[0])).map(x=>x[0]),['configure','apply']);
  assert(apply.disabled && pair.disabled && disable.disabled, 'pending operation locks actions');
  pending=false; enabled=true; await polls[0]();
  assert(apply.disabled && !pair.disabled && !disable.disabled, 'running node supports pairing and restore');
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
 await apply.attrs.click();
 assert.deepEqual(calls.find(x=>x[0]==='configure')[1], ['agent','wired']);
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
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', harness, str(VIEW)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_acl_limits_mutation_to_mesh_rpc(self):
        acl = json.loads((PACKAGE / 'root/usr/share/rpcd/acl.d/luci-app-ax6000-mesh.json').read_text())
        entry = acl['luci-app-ax6000-mesh']
        self.assertEqual(entry['read'], {'ubus': {'ax6000.mesh': ['status']}})
        self.assertEqual(set(entry['write']['ubus']['ax6000.mesh']), {'configure', 'apply', 'pair', 'disable'})
        self.assertEqual(set(entry['write']), {'ubus'})
