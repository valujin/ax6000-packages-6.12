"""Actual ucode bridge transition with persistent network-command fault model."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_mesh_ts_reconcile import UCODE
from test_mesh_slot_allocation import LIB
from mesh_openwrt_layout import install_commands, sandbox_commands

MODEL = r'''#!/usr/bin/python3
import json,os,sys,pathlib
p=pathlib.Path(os.environ['BOOTSTRAP_MODEL']); d=json.loads(p.read_text()); a=sys.argv[1:]; n=pathlib.Path(sys.argv[0]).name
c=[n,*a];d['calls'].append(c)
def done(rc=0,value=None):
 p.write_text(json.dumps(d))
 if value is not None: print(json.dumps(value))
 sys.exit(rc)
if d.get('fail')==c and not d.get('failed'):
 d['failed']=True;done(1)
if n=='ip' and a==['-j','-d','link','show']:done(value=list(d['links'].values()))
if n=='bridge' and a==['-j','vlan','show']:done(value=[{'ifname':k,'vlans':v} for k,v in d['vlans'].items()])
if n=='ip' and a[:6]==['link','set','dev','br-lan','type','bridge']:
 data=d['links']['br-lan']['linkinfo']['info_data']
 if a[6]=='vlan_default_pvid':
  data['vlan_default_pvid']=int(a[7])
  for rows in d['vlans'].values():
   rows[:]=[v for v in rows if v['vlan']!=1]
   if int(a[7])==1:rows.append({'vlan':1,'flags':['PVID','Egress Untagged']})
 elif a[6]=='vlan_filtering':
  if int(a[7])==1:
   # Enabling filtering without every management membership would cut LAN.
   assert data['vlan_default_pvid']==0
   assert all(any(v['vlan']==1 and set(v['flags'])=={'PVID','Egress Untagged'} for v in d['vlans'][k]) for k in ['br-lan','lan1','ra0','ra1'] if k in d['links'])
  if not d.get('ignore_filter'):data['vlan_filtering']=int(a[7])
 else:done(2)
 done()
if n=='bridge' and a[:1]==['vlan'] and a[1] in ('add','del'):
 rows=d['vlans'].setdefault(a[3],[]);rows[:]=[v for v in rows if v['vlan']!=int(a[5])]
 if a[1]=='add':rows.append({'vlan':int(a[5]),'flags':['PVID','Egress Untagged']})
 done()
done(2)
'''

@unittest.skipUnless(Path(UCODE).exists(),'Real ucode runtime required')
class BootstrapBridge(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.model=self.root/'model';self.transport=self.root/'transport';self.plan=self.root/'plan'
  self.data={'calls':[],'links':{},'vlans':{}}
  for i,n in enumerate(['br-lan','lan1','ra0','ra1']):
   self.data['links'][n]={'ifname':n,'ifindex':10+i,'address':'02:00:00:00:00:%02x'%i,'flags':['UP']}
   self.data['vlans'][n]=[{'vlan':1,'flags':['PVID','Egress Untagged']}]
   if n!='br-lan':self.data['links'][n]['master']='br-lan'
  self.data['links']['br-lan']['linkinfo']={'info_kind':'bridge','info_data':{'vlan_filtering':0,'vlan_default_pvid':1}}
  self.authority={'schema':2,'bridge':'br-lan','management_vid':1,'quarantine_vid':4090,'controller_alid':'02:00:00:00:00:10','management_ifnames':['lan1','ra0','ra1'],'trunk_ifnames':['ra1'],'guest_ports':[],'cpu_guest_links':[]}
  b=self.root/'bin';b.mkdir();stub=b/'stub';stub.write_text(MODEL);stub.chmod(0o700)
  target=install_commands(self.root,dict.fromkeys(['ip','bridge'],stub))
  self.assertFalse((target/'sbin/bridge').exists())
  source=sandbox_commands((LIB/'ax6000-mesh-bootstrap-bridge').read_text(),target)
  source=source.replace('s.uid == 0','s.uid == '+str(os.getuid()))
  self.helper=self.root/'helper';self.helper.write_text(source)
  self.env={**os.environ,'BOOTSTRAP_MODEL':str(self.model)}
 def run_op(self,op,ok=True):
  self.model.write_text(json.dumps(self.data));self.transport.write_text(json.dumps(self.authority));self.transport.chmod(0o600)
  p=subprocess.run([UCODE,'-L','/tmp/mesh-ucode-build/*.so',str(self.helper),op,str(self.transport if op in ('plan','plan-recover','health') else self.plan),*([str(self.plan)] if op in ('plan','plan-recover') else [])],env=self.env,capture_output=True,text=True,timeout=20)
  self.assertEqual(p.returncode==0,ok,p.stderr);self.assertEqual(p.stdout,'');self.data=json.loads(self.model.read_text());return p
 def test_stages_management_before_enabling_and_preserves_other_tagged_vlan(self):
  self.data['vlans']['br-lan'].append({'vlan':20,'flags':[]});self.run_op('plan');self.run_op('apply')
  mode=self.data['links']['br-lan']['linkinfo']['info_data'];self.assertEqual(mode,{'vlan_filtering':1,'vlan_default_pvid':0})
  self.assertIn({'vlan':20,'flags':[]},self.data['vlans']['br-lan']);self.assertEqual(self.plan.stat().st_mode&0o777,0o600)
  self.run_op('verify')
 def test_failed_enable_restores_original_bridge_and_vlans(self):
  original=copy.deepcopy(self.data);self.run_op('plan');self.data['fail']=['ip','link','set','dev','br-lan','type','bridge','vlan_filtering','1'];self.run_op('apply',False)
  self.assertEqual(self.data['links'],original['links']);self.assertEqual(self.data['vlans'],original['vlans'])
 def test_silent_command_failure_is_detected_and_rolled_back(self):
  self.run_op('plan');self.data['ignore_filter']=True;self.run_op('apply',False)
  self.assertEqual(self.data['links']['br-lan']['linkinfo']['info_data']['vlan_default_pvid'],1)
 def test_unknown_bridge_member_refused_without_mutations(self):
  self.data['links']['alien']={'ifname':'alien','ifindex':99,'master':'br-lan','flags':['UP']};self.run_op('plan',False)
  self.assertFalse(any(c[1:3]==['link','set'] for c in self.data['calls']))
 def test_live_or_attached_guest_refused(self):
  for flags,master in [(['UP'],None),([], 'br-lan')]:
   with self.subTest(flags=flags,master=master):
    self.data['links']['ra2']={'ifname':'ra2','ifindex':20,'flags':flags}
    if master:self.data['links']['ra2']['master']=master
    self.run_op('plan',False)
 def test_quarantine_membership_or_ranged_vlan_refused(self):
  self.data['vlans']['br-lan'].append({'vlan':4090,'flags':[]});self.run_op('plan',False)
  self.data['vlans']['br-lan']=[{'vlan':1,'vlanEnd':20,'flags':[]}];self.run_op('plan',False)
 def test_identity_drift_refused_before_mutations(self):
  self.run_op('plan');self.data['links']['lan1']['ifindex']=100;self.data['calls']=[];self.run_op('apply',False)
  self.assertFalse(any(c[1:3]==['link','set'] for c in self.data['calls']))
 def test_rollback_after_success_restores_original_management(self):
  before=copy.deepcopy(self.data);self.run_op('plan');self.run_op('apply');self.run_op('rollback')
  self.assertEqual(self.data['links'],before['links']);self.assertEqual(self.data['vlans'],before['vlans'])

 def test_reboot_plan_accepts_absent_wireless_but_retains_physical_management(self):
  for n in ['ra0','ra1']:self.data['links'].pop(n);self.data['vlans'].pop(n)
  self.data['links']['br-lan']['linkinfo']['info_data']['vlan_filtering']=1
  self.run_op('plan-recover');self.run_op('apply');self.run_op('verify')
 def test_recovery_does_not_treat_missing_physical_management_as_wireless(self):
  self.data['links'].pop('lan1');self.data['vlans'].pop('lan1');self.run_op('plan-recover',False)

 def test_recovers_netifd_tagged_only_cpu_membership(self):
  self.data['links']['br-lan']['linkinfo']['info_data'].update(vlan_filtering=1,vlan_default_pvid=0)
  self.data['vlans']['br-lan']=[{'vlan':1,'flags':[]}]
  self.run_op('health',False);self.run_op('plan-recover');self.run_op('apply');self.run_op('health')
 def test_health_allows_active_owned_guest_without_mutating_it(self):
  self.data['links']['br-lan']['linkinfo']['info_data'].update(vlan_filtering=1,vlan_default_pvid=0)
  self.data['links']['ra2']={'ifname':'ra2','ifindex':30,'master':'br-lan','flags':['UP']}
  self.run_op('health');self.assertFalse(any(c[1:3]==['link','set'] for c in self.data['calls']))

 def test_health_rejects_foreign_or_absent_management_port(self):
  self.data['links']['br-lan']['linkinfo']['info_data'].update(vlan_filtering=1,vlan_default_pvid=0)
  self.data['links']['lan1']['master']='br-other';self.run_op('health',False)
  self.data['links'].pop('lan1');self.run_op('health',False)

 def test_reenrollment_after_disable_preserves_unfiltered_empty_vlan_baseline(self):
  self.data['links']['br-lan']['linkinfo']['info_data']['vlan_default_pvid']=0
  for n in self.data['vlans']:self.data['vlans'][n]=[]
  before=copy.deepcopy(self.data);self.run_op('plan');self.run_op('apply');self.run_op('rollback')
  self.assertEqual(self.data['links'],before['links']);self.assertEqual(self.data['vlans'],before['vlans'])
