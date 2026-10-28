"""Compile and execute the real pinned 1905 DSA FDB-clear callback.

The exact vendor preimage is kept here so the regression runs offline. Its
SHA256 is checked before the package patch is applied with zero fuzz. A fake
bridge executable models mixed local/static/learned entries; the production
callback forks and executes it normally. No host network state is touched.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'files/mediatek-mesh/packages/1905daemon/patches/101-preserve-local-fdb.patch'
VENDOR_PREIMAGE = r'''int clear_table()
{
#define CLEAR_BRIDGE_FDB_SCRIPT "/tmp/clear_bridge_fdb_script.sh"
	int ret = ETH_SUCCESS;
	int i = 0;
	char cmd[1024] = {0};
	int res = 0;
	FILE *f = NULL;

	for (i = 0; i < MAX_INF_NUM; i++) {
		if (!inf[i].valid)
			continue;

		debug(DEBUG_TRACE, "[%d], i = %d, inf[i].if_name = %s\n", __LINE__, i, inf[i].if_name);

		memset(cmd, 0, sizeof(cmd));
		res = snprintf(cmd, sizeof(cmd), "bridge fdb show dev %s"
			" | while read mac master br_name; do echo $mac; "
			"bridge fdb delete $mac dev %s master; done;", inf[i].if_name, inf[i].if_name);
		if (os_snprintf_error(sizeof(cmd), res))
			debug(DEBUG_ERROR, "[%d] snprintf fail!\n", __LINE__);

		/* mode: w, overwriting each time */
		f = fopen(CLEAR_BRIDGE_FDB_SCRIPT, "w");
		if (f == NULL) {
			debug(DEBUG_ERROR, "open file %s fail\n", CLEAR_BRIDGE_FDB_SCRIPT);
			return -1;
		}

		ret = fputs(cmd, f);
		if (ret == -1)
			debug(DEBUG_ERROR, "error fputs\n");
		ret = fflush(f);
		if (ret == -1)
			debug(DEBUG_ERROR, "error fflush\n");

		/* run shell by execl */
		ret = execl_sh(CLEAR_BRIDGE_FDB_SCRIPT);
		if (ret == -1)
			debug(DEBUG_ERROR, "error execl \"sh\" %s\n", CLEAR_BRIDGE_FDB_SCRIPT);
		ret = fclose(f);
		if (ret == -1)
			debug(DEBUG_ERROR, "error fclose %s\n", CLEAR_BRIDGE_FDB_SCRIPT);
		ret = remove(CLEAR_BRIDGE_FDB_SCRIPT);
		if (ret == -1)
			debug(DEBUG_ERROR, "error remove %s\n", CLEAR_BRIDGE_FDB_SCRIPT);
	}

	ret = ETH_SUCCESS;
	return ret;
}
'''
VENDOR_SHA256 = '2b8c497fcd2222177e392276d70ae3a6cf2cbcc351a5715d98d1a8907608829f'

BRIDGE = r'''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
state = Path(os.environ['FDB_STATE'])
a = sys.argv[1:]
with open(os.environ['FDB_CALLS'], 'a') as f:
    f.write(json.dumps(a) + '\n')
if os.environ.get('BRIDGE_FAIL') == '1':
    sys.exit(23)
rows = json.loads(state.read_text())
if a[:3] == ['fdb', 'show', 'dev']:
    for row in rows:
        if row['dev'] == a[3]:
            print(row['mac'], 'master br-lan', row['state'])
elif a[:2] == ['fdb', 'delete']:
    rows = [r for r in rows if not (r['mac'] == a[2] and r['dev'] == a[4])]
elif a[:3] == ['fdb', 'flush', 'dev']:
    if a[4:] != ['master', 'dynamic', 'noadded_by_user', 'noextern_learn']:
        sys.exit(24)
    rows = [r for r in rows if not (r['dev'] == a[3] and r['scope'] == 'master'
            and r['state'] == 'dynamic' and not r.get('user') and not r.get('extern'))]
else:
    sys.exit(25)
state.write_text(json.dumps(rows))
'''


class Mesh1905FDBTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mesh-1905-fdb-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assertEqual(hashlib.sha256(VENDOR_PREIMAGE.encode()).hexdigest(), VENDOR_SHA256)
        target = self.root / 'ethernet/mediatek_DSA/eth_ops_dsa.c'
        target.parent.mkdir(parents=True)
        target.write_text(VENDOR_PREIMAGE)
        if PATCH.exists():
            subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(PATCH)], cwd=self.root,
                           check=True, text=True, capture_output=True)
        function = target.read_text()
        harness = r'''
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#define MAX_INF_NUM 4
#define ETH_SUCCESS 0
#define ETH_ERROR_FAIL -1
#define debug(...) ((void)0)
#define os_snprintf_error(size, ret) ((ret) < 0 || (size_t)(ret) >= (size))
struct { int valid; char if_name[16]; } inf[MAX_INF_NUM] = {
    {1,"lan2"}, {0,"lan3"}, {1,"lan4"}, {0,"wan"}
};
static int __attribute__((unused)) execl_sh(char *file) {
    pid_t pid = fork(); int status = 0;
    if (pid < 0) return -1;
    if (!pid) { execl("/bin/sh", "sh", file, NULL); _exit(127); }
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -1;
    return status;
}
/* CALLBACK */
int main(void) { return clear_table() == ETH_SUCCESS ? 0 : 1; }
'''
        harness = harness.replace('/* CALLBACK */', function)
        # Original vendor callback writes a fixed /tmp script. Redirect that
        # path into this test's sandbox too, so the red test is isolated.
        harness = harness.replace('/tmp/clear_bridge_fdb_script.sh', str(self.root / 'clear.sh'))
        cfile = self.root / 'harness.c'
        cfile.write_text(harness)
        self.exe = self.root / 'clear'
        cc = os.environ.get('HOST_CC') or shutil.which('cc')
        if not cc:
            self.skipTest('host C compiler unavailable')
        compiled = subprocess.run([cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', str(cfile), '-o', str(self.exe)],
                                  capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        (self.root / 'bridge').write_text(BRIDGE)
        (self.root / 'bridge').chmod(0o755)
        self.state = self.root / 'state.json'
        self.calls = self.root / 'calls.jsonl'
        self.env = {**os.environ, 'PATH': str(self.root) + ':' + os.environ['PATH'],
                    'FDB_STATE': str(self.state), 'FDB_CALLS': str(self.calls)}

    def test_clear_preserves_local_static_and_unconfigured_entries(self):
        def row(mac, dev, state, scope='master', **flags):
            return dict(mac=mac, dev=dev, state=state, scope=scope, **flags)
        protected = [
            row('44:f7:70:c3:76:1b', 'lan2', 'permanent'),
            row('44:f7:70:c3:76:1b', 'lan2', 'permanent', vlan=1),
            row('02:00:00:00:00:01', 'lan2', 'static'),
            row('02:00:00:00:00:02', 'lan2', 'dynamic', user=True),
            row('02:00:00:00:00:03', 'lan2', 'dynamic', extern=True),
            row('02:00:00:00:00:04', 'lan2', 'dynamic', scope='self'),
            row('02:00:00:00:00:05', 'lan3', 'dynamic'),
            row('02:00:00:00:00:06', 'wan', 'dynamic'),
            row('46:f7:70:e3:76:1c', 'rax0', 'permanent'),
        ]
        learned = [row('02:00:00:00:01:01', 'lan2', 'dynamic'),
                   row('02:00:00:00:01:02', 'lan4', 'dynamic', vlan=3)]
        self.state.write_text(json.dumps(protected + learned))
        result = subprocess.run([str(self.exe)], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.state.read_text()), protected)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual([call[3] for call in calls], ['lan2', 'lan4'])

    def test_clear_propagates_bridge_failure(self):
        self.state.write_text('[]')
        result = subprocess.run([str(self.exe)], env={**self.env, 'BRIDGE_FAIL': '1'},
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
