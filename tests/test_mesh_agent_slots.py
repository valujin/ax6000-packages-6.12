"""Offline agent bootstrap integration through native UCI, jshn and allocator."""
import json
import os
import re
import subprocess
import unittest
import test_mesh_network_materialize as materialize
from test_mesh_slot_allocation import LIB, NATIVE

class AgentSlots(unittest.TestCase):
    def setUp(self):
        materialize.Materialize.setUp(self)
        self.config=self.root/'config'; self.config.mkdir()
        self.state=self.root/'state'; self.state.mkdir()
        source=re.sub(r"config wifi-iface 'guest'\n.*?(?=config )",'',self.source.read_text(),flags=re.S)
        source+="config wifi-iface 'ax6000_mesh_bh1'\n option mode 'sta'\n option device 'radio24'\n option key 'private-station'\n"
        (self.config/'wireless').write_text(source)
        (self.config/'ax6000_mesh').write_text("config mesh 'main'\n option enabled '1'\n option role 'agent'\n option linux_ts '1'\n")
        (self.state/'phase').write_text('committed\n')
        (self.state/'original-wireless').write_text(source)
        self.capacity=dict(schema=1,confirmed=True,capacity24=4,capacity5=4)
        self.bindir=self.root/'helpers'; self.bindir.mkdir()
        for name in ['ax6000-mesh-agent-slots','ax6000-mesh-allocate-slots','ax6000-mesh-plan-networks','ax6000-mesh-materialize-networks']:
            text=(LIB/name).read_text().replace('#!/bin/sh','#!/usr/bin/busybox ash',1)
            text=text.replace('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh')).replace('/usr/share/ax6000-mesh/vendor.sh',str(LIB.parent/'share/ax6000-mesh/vendor.sh'))
            text=text.replace('/usr/libexec',str(self.bindir)).replace('state=/etc/ax6000-mesh','state='+str(self.state)).replace('config=/etc/config','config='+str(self.config))
            text=text.replace('[ "$(id -u)" = 0 ]','[ "$(id -u)" = '+str(os.getuid())+' ]').replace('[ "$(stat -c %u "$1")" = 0 ]','[ "$(stat -c %u "$1")" = '+str(os.getuid())+' ]')
            helper=self.bindir/name; helper.write_text(text); helper.chmod(0o700)
    def run_agent(self,ok=True,out='out'):
        cap=self.root/'capacity'; cap.write_text(json.dumps(self.capacity)); cap.chmod(0o600)
        before={p:p.read_bytes() for folder in [self.config,self.state] for p in folder.iterdir()}
        result=subprocess.run([str(self.bindir/'ax6000-mesh-agent-slots'),str(cap),str(self.root/out)],env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode==0,ok,result.stderr); self.assertEqual(result.stdout,''); self.assertNotIn('private-',result.stderr)
        self.assertEqual(before,{p:p.read_bytes() for folder in [self.config,self.state] for p in folder.iterdir()})
        if not ok: self.assertFalse((self.root/out).exists())
        return self.root/out
    def test_materializes_and_repeats_canonically(self):
        out=self.run_agent(); shown=materialize.Materialize.show(self,out)
        self.assertEqual(shown.count('=wifi-iface\n'),9)
        self.assertIn("wireless.ax6000_mesh_bh1.key='private-station'",shown)
        self.assertNotIn('wireless.ax6000_mesh_slot24_2.network=',shown)
        plan=json.loads((out/'plan').read_text()); self.assertEqual([x['slot'] for x in plan['bsses']],[0,0])
        self.assertEqual(plan['primary_vid'],1)
        (self.config/'wireless').write_bytes((out/'wireless').read_bytes())
        second=self.run_agent(out='second')
        self.assertEqual((out/'wireless').read_bytes(),(second/'wireless').read_bytes())
        self.assertEqual((out/'quarantine-key').read_bytes(),(second/'quarantine-key').read_bytes())
        self.assertNotIn('ax6000_mesh_',materialize.Materialize.show(self,second,True))
        for file in out.iterdir(): self.assertEqual(file.stat().st_mode&0o777,0o600)
    def test_unconfirmed_capacity(self):
        self.capacity['confirmed']=False; self.run_agent(False)
    def test_wrong_role(self):
        p=self.config/'ax6000_mesh'; p.write_text(p.read_text().replace("'agent'","'controller'")); self.run_agent(False)
    def test_uncommitted(self):
        (self.state/'phase').write_text('pending\n'); self.run_agent(False)
    def test_invalid_credentials(self):
        p=self.config/'wireless'; p.write_text(p.read_text().replace('private-main','short')); self.run_agent(False)
    def test_guest_rejected(self):
        p=self.config/'wireless'; p.write_text(p.read_text().replace("option network 'lan'","option network 'guest'",1)); self.run_agent(False)
    def test_private_seed_reused(self):
        p=self.state/'ts-quarantine-key'; p.write_text('private-stable-quarantine\n'); p.chmod(0o600)
        out=self.run_agent(); self.assertEqual((out/'quarantine-key').read_text(),'private-stable-quarantine\n')
