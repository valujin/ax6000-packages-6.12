"""Exercise the real supervisor with real worker death and fake local links."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from test_mesh_slot_allocation import LIB, NATIVE


@unittest.skipUnless(shutil.which('setsid') and shutil.which('busybox'), 'setsid and busybox ash required')
class TSSupervisor(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mesh-ts-supervisor-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root/'state';self.state.mkdir(mode=0o700)
        self.run = self.root/'run';self.run.mkdir()
        self.net = self.root/'net';self.net.mkdir()
        self.log = self.root/'commands'
        self.gen = 'a'*32
        owner={'schema':2,'generation':self.gen,'guest_ports':[{'ifname':'ra2','actual_bssid':'02:00:00:00:00:02','vid':10,'enabled':False}]}
        (self.state/'ts-ownership.json').write_text(json.dumps(owner));(self.state/'ts-ownership.json').chmod(0o600)
        (self.state/'ts-dataplane-approved').write_text(self.gen);(self.state/'ts-dataplane-approved').chmod(0o600)
        for n,mac in [('ra2','02:00:00:00:00:02'),('lan2','02:00:00:00:00:01')]:
            (self.net/n).mkdir();(self.net/n/'address').write_text(mac+'\n')
            (self.net/n/'flags').write_text('0');(self.net/n/'master').write_text('br-lan')
        ip=self.root/'ip';ip.write_text('''#!/usr/bin/python3
import os,sys
from pathlib import Path
p=Path(os.environ['TS_NET'])/sys.argv[4]
with open(os.environ['TS_LOG'],'a')as f:f.write(' '.join(sys.argv[1:])+'\\n')
if sys.argv[5]=='down':(p/'flags').write_text('0')
if sys.argv[5]=='nomaster':(p/'master').unlink(missing_ok=True)
''');ip.chmod(0o700)
        reconcile=self.root/'reconcile';reconcile.write_text('#!/bin/sh\necho "reconcile $*" >> "$TS_LOG"\nexit 0\n');reconcile.chmod(0o700)
        runtime=self.root/'runtime';runtime.write_text('''#!/usr/bin/python3
import os,time,signal,subprocess
from pathlib import Path
p=Path(os.environ['TS_NET'])/'ra2';(p/'flags').write_text('1');(p/'master').write_text('br-lan')
Path(os.environ['TS_ROOT']+'/worker-pid').write_text(str(os.getpid()))
if os.environ.get('TS_DESCENDANT'):
 q=subprocess.Popen(['sleep','120']);Path(os.environ['TS_ROOT']+'/descendant-pid').write_text(str(q.pid))
while True:time.sleep(.1)
''');runtime.chmod(0o700)
        source_path=LIB/'ax6000-mesh-ts-supervise'
        self.script=self.root/'supervise'
        if source_path.exists():
            source=source_path.read_text().replace('/usr/share/libubox/jshn.sh',str(NATIVE/'share/libubox/jshn.sh'))
            source=source.replace('/etc/ax6000-mesh',str(self.state)).replace('/var/run/',str(self.run)+'/').replace('/var/lock/',str(self.run)+'/')
            source=source.replace('/sys/class/net/',str(self.net)+'/').replace('/usr/libexec/ax6000-mesh-ts-runtime',str(runtime))
            source=source.replace('/usr/libexec/ax6000-mesh-ts-reconcile',str(reconcile)).replace('/sbin/ip',str(ip))
            source=source.replace('[ "$(id -u)" = 0 ]',f'[ "$(id -u)" = {os.getuid()} ]')
            source=source.replace('[ "$(stat -c %u "$1")" = 0 ]',f'[ "$(stat -c %u "$1")" = {os.getuid()} ]')
            source=source.replace('[ "$(stat -c %u "$dir")" = 0 ]',f'[ "$(stat -c %u "$dir")" = {os.getuid()} ]')
            self.script.write_text(source)
        self.env={**os.environ,'PATH':str(NATIVE/'bin')+':'+os.environ['PATH'],'LD_LIBRARY_PATH':str(NATIVE/'lib'),
                  'TS_ROOT':str(self.root),'TS_NET':str(self.net),'TS_LOG':str(self.log)}
        # Pinned routers use BusyBox setsid, whose API is only [-c] PROG ARGS.
        setsid=self.root/'setsid';setsid.write_text('#!/bin/sh\nexec busybox setsid "$@"\n');setsid.chmod(0o700)
        self.env['PATH']=str(self.root)+':'+self.env['PATH']
        self.procs=[]
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for proc in self.procs:
            if proc.poll() is None:proc.terminate()
        for proc in self.procs:
            try:proc.communicate(timeout=4)
            except subprocess.TimeoutExpired:proc.kill();proc.communicate(timeout=2)
        for name in ['worker-pid','descendant-pid']:
            p=self.root/name
            if p.exists():
                try:os.kill(int(p.read_text()),signal.SIGKILL)
                except ProcessLookupError:pass

    def wait_for(self,predicate):
        until=time.monotonic()+5
        while time.monotonic()<until:
            if predicate():return
            time.sleep(.02)
        self.fail('Timed out waiting for supervisor transition')

    def start(self):
        self.assertTrue(self.script.exists(),'TS supervisor implementation is absent')
        proc=subprocess.Popen(['busybox','ash',str(self.script),'run',self.gen],env=self.env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.procs.append(proc)
        self.wait_for(lambda:(self.root/'worker-pid').exists()or proc.poll()is not None)
        self.assertIsNone(proc.poll(),proc.communicate()if proc.poll()is not None else '')
        return proc

    def down(self):
        self.assertEqual((self.net/'ra2/flags').read_text(),'0')
        self.assertFalse((self.net/'ra2/master').exists())
        self.assertTrue((self.net/'lan2/master').exists())
        self.assertFalse((self.state/'ts-dataplane-approved').exists())

    def test_worker_sigkill_triggers_independent_quarantine(self):
        proc=self.start();worker=int((self.root/'worker-pid').read_text())
        self.assertEqual(os.getpgid(worker),worker,'BusyBox setsid must establish a separately killable worker group')
        os.kill(worker,signal.SIGKILL);proc.communicate(timeout=5)
        self.assertNotEqual(proc.returncode,0);self.down()

    def test_supervisor_sigterm_kills_worker_group_and_quarantines(self):
        self.env['TS_DESCENDANT']='1';proc=self.start()
        self.wait_for(lambda:(self.root/'descendant-pid').exists())
        proc.terminate();proc.communicate(timeout=5);self.down()
        descendant=int((self.root/'descendant-pid').read_text())
        self.wait_for(lambda:not Path('/proc/%s/stat'%descendant).exists()or Path('/proc/%s/stat'%descendant).read_text().rsplit(') ',1)[1].startswith('Z'))

    def test_procd_restart_after_supervisor_sigkill_quarantines_old_worker_first(self):
        proc=self.start();proc.kill();proc.communicate(timeout=2)
        restart=subprocess.run(['busybox','ash',str(self.script),'run',self.gen],env=self.env,text=True,capture_output=True,timeout=6)
        self.assertNotEqual(restart.returncode,0);self.down()

    def test_missing_approval_never_launches_worker(self):
        self.assertTrue(self.script.exists(),'TS supervisor implementation is absent')
        (self.state/'ts-dataplane-approved').unlink()
        proc=subprocess.run(['busybox','ash',str(self.script),'run',self.gen],env=self.env,capture_output=True,timeout=5)
        self.assertNotEqual(proc.returncode,0)
        self.assertFalse((self.root/'worker-pid').exists())

    def test_stop_without_prior_worker_still_quarantines_known_ownership(self):
        self.assertTrue(self.script.exists(),'TS supervisor implementation is absent')
        (self.net/'ra2/flags').write_text('1')
        proc=subprocess.run(['busybox','ash',str(self.script),'stop'],env=self.env,text=True,capture_output=True,timeout=5)
        self.assertEqual(proc.returncode,0,proc.stderr);self.down()

    def test_stop_command_terminates_active_worker_and_revokes_approval(self):
        proc=self.start()
        stopped=subprocess.run(['busybox','ash',str(self.script),'stop'],env=self.env,text=True,capture_output=True,timeout=5)
        self.assertEqual(stopped.returncode,0,stopped.stderr)
        proc.communicate(timeout=3);self.down()
