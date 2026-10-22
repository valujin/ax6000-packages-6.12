#!/usr/bin/env python3
"""Run the actual packed ARM64 multicall under explicit QEMU in an isolated container."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def need(value, message):
    if not value: raise ValueError(message)


def probe(binary, lock, output):
    # The workflow provides network-none/capability-free isolation, not binfmt.
    qemu=shutil.which('qemu-aarch64');need(qemu,'Explicit qemu-aarch64 is required')
    with tempfile.TemporaryDirectory(prefix='tailscale-qemu-') as temporary:
        root=Path(temporary);packed=root/'tailscale.multicall';shutil.copy2(binary,packed)
        for name in ('tailscale','tailscaled'):(root/name).symlink_to('tailscale.multicall')
        def run(alias,*args,check=True):
            result=subprocess.run([qemu,'-0',alias,str(root/alias),*args],capture_output=True,text=True,timeout=30)
            if check:need(result.returncode==0,result.stderr[-4096:])
            need(len(result.stdout.encode())<=1024**2,'Oversized CLI response')
            return result
        version=json.loads(run('tailscale','version','--json').stdout)
        need(version.get('short')==lock['version'] and version.get('gitCommit')==lock['commit'],'ARM64 source version/commit stamp differs')
        need(version.get('tailscaleGoGitHash')==lock['go']['commit'],'Actual ARM64 custom Go toolchain revision differs')
        daemon_version=run('tailscaled','--version').stdout
        need(daemon_version.startswith(lock['version']),'Daemon alias did not report the expected release')
        # These commands must remain present. No feature-reducing build is accepted.
        for command in ('serve','funnel','ssh','file'):run('tailscale',command,'--help')
        socket=root/'tailscaled.sock';log=root/'daemon.log'
        with log.open('wb') as stream:
            process=subprocess.Popen([qemu,'-0','tailscaled',str(root/'tailscaled'),'--tun=userspace-networking','--state=mem:','--socket='+str(socket),'--port=0'],stdout=stream,stderr=subprocess.STDOUT)
            try:
                deadline=time.monotonic()+30
                while not socket.exists() and time.monotonic()<deadline and process.poll() is None:time.sleep(.1)
                need(socket.exists() and process.poll() is None,'Emulated daemon did not open its private socket')
                result=run('tailscale','--socket='+str(socket),'status','--json',check=False)
                state=json.loads(result.stdout)
                need(state.get('BackendState') in ('NeedsLogin','NoState','Stopped'),'Unexpected unauthenticated private daemon state')
                client_daemon=json.loads(run('tailscale','--socket='+str(socket),'version','--daemon','--json').stdout)
                need(client_daemon.get('daemonLong')==version['long'],'CLI-to-daemon version IPC differs')
            finally:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        proof={'schema_version':1,'kind':'tailscale-packed-arm64-qemu-userspace-smoke','ok':True,'version':version,
               'daemon_version':daemon_version,'private_socket_ipc':True,'backend_state':state['BackendState'],
               'cli_features_present':['serve','funnel','ssh','file'],'tun':'userspace-networking','state':'memory-only',
               'actual_router_tested':False,'vpn_data_plane_tested':False,'apk_or_opkg_package_tested':False}
        Path(output).write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
        return proof


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','lock','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();probe(a.binary,json.loads(a.lock.read_text()),a.output)

if __name__=='__main__':main()
