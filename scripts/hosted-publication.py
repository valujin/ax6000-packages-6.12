#!/usr/bin/env python3
"""Run publication/build descendants in a verified disposable hosted cgroup."""
import argparse
import os
from pathlib import Path, PurePosixPath
import pwd
import subprocess
import sys

PRESERVE = ('GH_TOKEN', 'GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY', 'GITHUB_REPOSITORY',
            'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'RUNNER_TEMP', 'RUNNER_ENVIRONMENT',
            'AX6000_RECIPE_COMMIT')


def resource_budget(meminfo, affinity):
    records = {}
    for line in meminfo.splitlines():
        name, _, value = line.partition(':')
        records[name] = value.strip()
    fields = records.get('MemTotal', '').split()
    if len(fields) != 2 or fields[1] != 'kB' or not fields[0].isdigit():
        raise ValueError('Cannot determine host memory budget')
    page = os.sysconf('SC_PAGE_SIZE')
    memory = int(fields[0]) * 1024 // 2 // page * page
    cpus = max(1, len(affinity) // 2)
    if not affinity or memory < 64 * 1024 ** 2:
        raise ValueError('Insufficient hosted resource budget')
    return memory, cpus


def scope_command(memory, cpus, uid, payload):
    return ['sudo', '-n', '--preserve-env=' + ','.join(PRESERVE),
            'systemd-run', '--no-ask-password', '--scope', '--quiet', '--collect', '--same-dir', '--expand-environment=no',
            '--uid=' + str(uid), '--property=MemoryMax=' + str(memory),
            '--property=MemorySwapMax=0', '--property=CPUQuota=' + str(cpus * 100) + '%',
            '--property=CPUQuotaPeriodSec=100ms', '--description=AX6000 hosted publication',
            '/usr/bin/python3', str(Path(__file__).resolve()), '--inside',
            str(memory), str(cpus), '--', *payload]


def verify_scope(memory, cpus, membership, root=Path('/sys/fs/cgroup')):
    entries = [line[3:] for line in membership.splitlines() if line.startswith('0::')]
    if len(entries) != 1:
        raise ValueError('A unified cgroup is required')
    relative = PurePosixPath(entries[0])
    if not relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Invalid process cgroup path')
    group = root.joinpath(*relative.parts[1:])
    if int((group / 'memory.max').read_text()) != memory or (group / 'memory.swap.max').read_text().strip() != '0':
        raise ValueError('Hosted memory/swap limit is not enforced')
    quota, period = (group / 'cpu.max').read_text().split()
    if int(quota) != cpus * int(period) or int(period) != 100000:
        raise ValueError('Hosted CPU quota is not enforced')
    return group


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', nargs=2, type=int, metavar=('BYTES', 'CPUS'))
    parser.add_argument('payload', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    payload = args.payload[1:] if args.payload[:1] == ['--'] else args.payload
    try:
        if os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
            raise ValueError('This scope is allowed only on disposable GitHub hosted runners')
        if not payload:
            raise ValueError('A payload command is required')
        if args.inside:
            memory, cpus = args.inside
            verify_scope(memory, cpus, Path('/proc/self/cgroup').read_text())
            if os.getuid() == 0:
                raise ValueError('Publication must retain the unprivileged runner identity')
            print(f'Hosted scope verified: CPU quota={cpus}, memory={memory} bytes, swap=0', flush=True)
            os.execvp(payload[0], payload)
        memory, cpus = resource_budget(Path('/proc/meminfo').read_text(), os.sched_getaffinity(0))
        uid = os.getuid()
        pwd.getpwuid(uid)
        return subprocess.call(scope_command(memory, cpus, uid, payload))
    except (ValueError, OSError) as error:
        parser.exit(1, f'hosted-publication: {error}\n')


if __name__ == '__main__':
    sys.exit(main())
