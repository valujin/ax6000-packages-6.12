const fs=require('fs'),assert=require('assert');
String.prototype.format=function(...args){let i=0;return this.replace(/%[hsd]/g,()=>String(args[i++]));};
const calls=[],tables=[];let failMesh=false;
let snapshot={ok:true,fresh_ms:30000,nodes:[{alid:'02:00:00:00:00:09',local:false,address:'10.10.1.175',hostname:'<img src=x onerror=alert(1)>'}],clients:[
 {node:'02:00:00:00:00:09',mac:'04:00:00:00:00:01',bssid:'02:00:00:00:00:02',local:false,band:'5g',address:'10.10.1.218',hostname:'client',rssi_dbm:-61,link_age_ms:10,uplink_mbps:144,downlink_mbps:866,traffic_age_ms:10,rx_bytes:1048576,tx_bytes:2097152}
]};
function E(tag,attrs,children){if(Array.isArray(attrs)||typeof attrs==='string'){children=attrs;attrs={};}return{tag,attrs:attrs||{},children:children||[]};}
const table={firstElementChild:{childNodes:Array(6),appendChild(){}}};
const document={querySelector:s=>s==='#wifi_assoclist_table'?table:null};
const rpc={declare:s=>async()=>{calls.push(s);if(failMesh)throw Error('unavailable');return snapshot;}};
const form={Value:{extend:o=>o},ListValue:{extend:o=>o}};
const network={flushCache:()=>Promise.resolve(),getHostHints:async()=>hosts,getWifiDevices:async()=>[local.radio]};
const L={isObject:v=>v!==null&&typeof v==='object',hasViewPermission:()=>true,resource:p=>p,itemlist:(node,rows)=>rows,bind:(fn,obj,...args)=>fn.bind(obj,...args)};
const config={};
const uci={get:(pkg,id,key)=>config[pkg+'.'+id+'.'+key]};
const source=fs.readFileSync(process.argv[2],'utf8');
const exposed=new Function('view','dom','poll','fs','ui','rpc','uci','form','network','firewall','widgets','uqr','L','E','_','document','cbi_update_table',source.replace('return view.extend({','const actualPage = view.extend({')+'\nreturn {page:actualPage,callMeshClients,mesh_agent_primary,mesh_agent_status,mesh_agent_protect_form,render_network_status};')(
 {extend:o=>o},{},{},{},{changes:{changes:{}}},rpc,uci,form,network,{},{},{},L,E,x=>x,document,(table,rows)=>tables.push(rows));
const page=exposed.page;
// Native WSC may update driver values while enrolled UCI keeps joining credentials.
config['ax6000_mesh.main.enabled']='1';config['ax6000_mesh.main.role']='agent';
config['wireless.primary.map_bss_type']='32';
let live={ssid:'Actual controller SSID',bssid:'02:00:00:00:00:02'};
const primary={getName:()=> 'primary',ubus:(...path)=>path.join('.')==='net.iwinfo'?live:undefined,
 isUp:()=>true,getActiveEncryption:()=> 'WPA3 SAE',getActiveMode:()=> 'Access Point',
 getActiveBSSID:()=>live.bssid,getChannel:()=>36,get:()=>null,getWifiDeviceName:()=> 'radio0',
 getMode:()=> 'ap',getSSID:()=> 'Original distinct SSID'};
assert(exposed.mesh_agent_primary(primary));
assert.equal(exposed.mesh_agent_status(primary).ssid,'Actual controller SSID');
assert.equal(exposed.mesh_agent_status(primary).security,'WPA3 SAE');
let rendered=JSON.stringify(exposed.render_network_status(primary));
assert(rendered.includes('Actual controller SSID')&&rendered.includes('Mesh controller'));
assert(!rendered.includes('Original distinct SSID'));
const options=[{option:'ssid',tab:'general'},{option:'_qrops',tab:'encryption'},{option:'_wpa_key',tab:'encryption'},{option:'encryption',tab:'encryption'},{option:'channel',tab:'general'}];
let section={children:options.slice()};exposed.mesh_agent_protect_form(section,primary);
assert.deepEqual(section.children.map(o=>o.option),['channel'],'managed credentials and QR removed');
live={};assert.equal(exposed.mesh_agent_status(primary).ssid,'Unavailable','missing runtime never falls back to joining UCI');
rendered=JSON.stringify(exposed.render_network_status(primary));assert(rendered.includes('Unavailable')&&!rendered.includes('Original distinct SSID'));
config['ax6000_mesh.main.role']='controller';assert(!exposed.mesh_agent_primary(primary));
assert(JSON.stringify(exposed.render_network_status(primary)).includes('Original distinct SSID'),'controller retains configured distinct SSID');
section={children:options.slice()};exposed.mesh_agent_protect_form(section,primary);assert.deepEqual(section.children,options);
config['ax6000_mesh.main.role']='agent';config['ax6000_mesh.main.enabled']='0';assert(!exposed.mesh_agent_primary(primary),'unenrolled original SSIDs preserved');
config['ax6000_mesh.main.enabled']='1';config['wireless.primary.map_bss_type']='64';assert(!exposed.mesh_agent_primary(primary),'backhaul row excluded');
config['wireless.primary.map_bss_type']='32';live={ssid:'AX6000-joining',bssid:'02:00:00:00:00:02'};
assert.equal(exposed.mesh_agent_status(primary).ssid,'AX6000-joining','pending enrollment reports actual joining runtime');
config['ax6000_mesh.main.enabled']='0';

const originalSnapshot=structuredClone(snapshot);
const local={mac:'04:00:00:00:00:03',signal:-55,noise:-95,rx:{rate:600000,mhz:80},tx:{rate:433000,mhz:80},
 network:{getWifiDeviceName:()=> 'radio0',getAssocList:async()=>[local],getIfname:()=> 'ra0',getMode:()=> 'ap',getSSID:()=> 'Local',isUp:()=>true,getShortName:()=> 'Local AP',isClientDisconnectSupported:()=>true,disconnectClient:()=>calls.push('disconnect-local')},radio:{getName:()=> 'radio0',getWifiNetworks:async()=>[local.network],getI18n:()=> '5 GHz'}};
const hosts={getHostnameByMACAddr:()=> 'local-host',getIPAddrByMACAddr:()=> '10.10.1.5',getIP6AddrByMACAddr:()=>null};
const map={querySelectorAll:()=>[]};
const data=()=>[hosts,[],[],[local],snapshot];
const flat=n=>Array.isArray(n)?n.flatMap(flat):!n||typeof n!=='object'?[]:[n,...flat(n.children)];
(async()=>{
 await page.poll_status(map,data());
 let rows=tables.at(-1);assert.equal(rows.length,2,'local and remote stations both appear');
 assert.equal(rows[1].length,7,'vendor uptime and action columns remain aligned');
 assert(flat(rows[0]).some(n=>n.tag==='button'),'local disconnect retained');
 assert(!flat(rows[1]).some(n=>n.tag==='button'),'remote row has no local action');
 assert(flat(rows[1]).some(n=>n.tag==='a'&&n.attrs.href==='http://10.10.1.175/cgi-bin/luci/'),'authoritative node link');
 assert(!flat(rows[1]).some(n=>n.tag==='img'||n.attrs.innerHTML),'untrusted hostname is text');
 assert(JSON.stringify(rows[1]).includes('144 Mbit/s (estimated)'));
 assert(JSON.stringify(rows[1]).includes('1.00 MiB')&&JSON.stringify(rows[1]).includes('2.00 MiB'));
 const duplicate=JSON.parse(JSON.stringify(snapshot.clients[0]));snapshot.clients.push(duplicate);
 await page.poll_status(map,data());assert.equal(tables.at(-1).length,2,'duplicate node/MAC/BSSID removed');
 snapshot.clients[1].bssid='02:00:00:00:00:04';
 await page.poll_status(map,data());assert.equal(tables.at(-1).length,3,'distinct BSSID is distinct association');
 snapshot.clients[1].mac=local.mac;
 await page.poll_status(map,data());assert.equal(tables.at(-1).length,2,'local driver association wins over old remote report');
 snapshot.clients[0].link_age_ms=30001;snapshot.clients[0].traffic_age_ms=30001;
 snapshot.nodes[0].address='javascript:alert(1)';
 await page.poll_status(map,data());rows=tables.at(-1);
 assert(!JSON.stringify(rows[1]).includes('144 Mbit/s'),'old rate hidden');
 assert(!JSON.stringify(rows[1]).includes('1.00 MiB'),'old counters hidden');
 assert(!flat(rows[1]).some(n=>n.tag==='a'),'invalid address has no link');
 snapshot=null;await page.poll_status(map,data());assert.equal(tables.at(-1).length,1,'unavailable Mesh never drops local station');
 // Execute the real polling chain too, so the remote RPC must reach vendor data[4].
 const start=source.match(/poll\.add\(L\.bind\(function\(\)\s*\{/).index;
 const closing=source.slice(start).match(/\},\s*this\),\s*5\);/),end=start+closing.index+closing[0].length;
 const scheduled=[];
 const schedule=new Function('poll','L','m','nodes','network','zones','callMeshClients','fs','ui','E',source.slice(start,end));
 schedule.call(page,{add:fn=>scheduled.push(fn)},L,{children:[{cfgsections:()=>[]}]},map,network,[],exposed.callMeshClients,{},{},E);
 snapshot=originalSnapshot;await scheduled[0]();
 assert(calls.some(call=>call.object==='ax6000.mesh'&&call.method==='clients'),'poll queries the real declared Mesh provider');
 assert.equal(tables.at(-1).length,2,'polled remote snapshot reaches the station table');
 failMesh=true;await scheduled[0]();assert.equal(tables.at(-1).length,1,'failed RPC preserves local rows');

})().catch(e=>{console.error(e);process.exitCode=1;});
