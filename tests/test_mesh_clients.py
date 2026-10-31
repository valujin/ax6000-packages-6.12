"""Execute the bounded native exporter and the real ucode normalization module."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'files/mediatek-mesh/packages/mapd'
MODULE = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/share/ax6000-mesh/clients.uc'
HELPER = ROOT / 'files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-clients'
SOURCE_HASH = '39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18'

C_HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#define MAP_R2 1
#define MAP_6E_SUPPORT 1
#define CENT_STR 1
#define BAND_2G 0
#define BAND_5GL 1
#define BAND_5GH 2
#define BAND_6G 3
#define os_memcpy memcpy
#define os_memset memset
#define os_memcmp memcmp
#define SLIST_FOREACH_SAFE(v,h,f,t) for ((v)=(h)->first; (v) && (((t)=(v)->f),1); (v)=(t))
struct os_reltime { long sec,usec; };
static unsigned long long clock_ms=10000;
static int os_get_reltime(struct os_reltime *now) { now->sec=clock_ms/1000;now->usec=clock_ms%1000*1000;return 0; }
struct radio { int band; };
struct bss_info_db { unsigned char bssid[6]; struct radio *radio; char ssid[33],key[65]; };
struct associated_clients {
    unsigned char client_addr[6];struct bss_info_db *bss;int is_bh_link,is_APCLI;
    unsigned char rssi_uplink;unsigned int erate_downlink,erate_uplink;
    struct { unsigned int last_data_dl_rate,last_data_ul_rate; } sta_ext_info;
    struct { unsigned int bytes_sent,bytes_received,packets_sent,packets_received,tx_packets_errors,rx_packets_errors,retransmission_count; } stat_db;
    struct associated_clients *next_client;
};
struct iface_info { unsigned char iface_addr[6];struct iface_info *next_iface; };
struct _1905_map_device {
    struct { unsigned char al_mac_addr[6];struct {struct iface_info *first;} first_iface; } _1905_info;
    int in_network,device_role,byte_cnt_unit;
    struct {struct associated_clients *first;} assoc_clients;
    struct _1905_map_device *next;
};
struct own_1905_device { struct _1905_map_device *first; };
struct mapd_global { struct own_1905_device dev; };
static struct _1905_map_device *topo_srv_get_next_1905_device(struct own_1905_device *ctx,struct _1905_map_device *last) { return last?last->next:ctx->first; }
static struct _1905_map_device *topo_srv_get_1905_device_from_iface(struct own_1905_device *ctx,unsigned char *mac) {
    for(struct _1905_map_device *d=ctx->first;d;d=d->next)
        for(struct iface_info *i=d->_1905_info.first_iface.first;i;i=i->next_iface)
            if(!memcmp(i->iface_addr,mac,6)) return d;
    return NULL;
}
#include "mapd_interface/mesh_clients.inc"
int main(int argc,char **argv) {
    assert(argc==2);
    struct radio radio={.band=BAND_5GL};
    struct bss_info_db bss={.bssid={2,0,0,0,0,8},.radio=&radio,.ssid="DO_NOT_EXPORT_SSID",.key="DO_NOT_EXPORT_PASSWORD"};
    struct _1905_map_device nodes[17]={0};struct iface_info ifaces[17]={0};
    struct associated_clients clients[129]={0};
    for(int i=0;i<17;i++) {
        nodes[i]._1905_info.al_mac_addr[0]=2;nodes[i]._1905_info.al_mac_addr[5]=i+1;
        nodes[i].device_role=i?2:1;nodes[i].in_network=1;
        ifaces[i].iface_addr[0]=2;ifaces[i].iface_addr[5]=i+30;
    }
    nodes[0].next=&nodes[1];nodes[1].byte_cnt_unit=2;
    nodes[1]._1905_info.first_iface.first=&ifaces[0];
    for(int i=0;i<129;i++) {
        clients[i].client_addr[0]=4;clients[i].client_addr[5]=i+1;
        clients[i].bss=&bss;clients[i].rssi_uplink=(unsigned char)-61;
        clients[i].erate_downlink=866;clients[i].erate_uplink=433;
        clients[i].sta_ext_info.last_data_dl_rate=780;
        clients[i].stat_db.bytes_sent=0xffffffffU;clients[i].stat_db.bytes_received=42;
    }
    nodes[0].assoc_clients.first=&clients[0];nodes[1].assoc_clients.first=&clients[1];
    struct mapd_global global={.dev.first=&nodes[0]};
    if(strcmp(argv[1],"unobserved")) for(int i=0;i<2;i++) {
        mesh_client_observe(&clients[i],MESH_LINK);mesh_client_observe(&clients[i],MESH_EXTENDED);mesh_client_observe(&clients[i],MESH_TRAFFIC);
    }
    if(!strcmp(argv[1],"stale")) clock_ms+=30001;
    if(!strcmp(argv[1],"reset")) mesh_client_forget(&clients[0]);
    if(!strcmp(argv[1],"backhaul")) clients[1].is_bh_link=1;
    if(!strcmp(argv[1],"overflow")) {
        nodes[1].assoc_clients.first=NULL;
        for(int i=0;i<128;i++) clients[i].next_client=&clients[i+1];
    }
    if(!strcmp(argv[1],"nodes")) for(int i=0;i<16;i++) nodes[i].next=&nodes[i+1];
    if(!strcmp(argv[1],"interfaces")) for(int i=0;i<16;i++) ifaces[i].next_iface=&ifaces[i+1];
    if(!strcmp(argv[1],"offline")) nodes[1].in_network=0;
    char output[65536];
    int result=mesh_dump_clients(&global,output,!strcmp(argv[1],"small")?32:sizeof(output));
    if(!strcmp(argv[1],"small")) { assert(result==-1);return 0; }
    assert(result>0 && result<(int)sizeof(output));fwrite(output,1,result,stdout);return 0;
}
'''


class NativeMeshClients(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive = os.environ.get('MAPD_SOURCE_ARCHIVE')
        if not archive or not shutil.which('cc'):
            raise unittest.SkipTest('set MAPD_SOURCE_ARCHIVE; host C compiler required')
        if hashlib.sha256(Path(archive).read_bytes()).hexdigest() != SOURCE_HASH:
            raise AssertionError('Mapd archive differs from pinned source')
        cls.scratch = tempfile.TemporaryDirectory(prefix='mesh-clients-c-')
        with tarfile.open(archive) as vendor:
            vendor.extractall(cls.scratch.name, filter='data')
        cls.source = Path(cls.scratch.name) / 'mapd'
        for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
            result = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=cls.source, capture_output=True, text=True)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
        harness = cls.source / 'clients-test.c'
        harness.write_text(C_HARNESS)
        cls.binary = cls.source / 'clients-test'
        build = subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-I', str(cls.source), str(harness), '-o', str(cls.binary)], capture_output=True, text=True)
        if build.returncode:
            raise AssertionError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'scratch'):
            cls.scratch.cleanup()

    def snapshot(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True, check=True)
        self.assertNotIn('DO_NOT_EXPORT', result.stdout)
        return json.loads(result.stdout)

    def test_actual_exporter_converts_counters_and_emits_no_credentials(self):
        value = self.snapshot('fresh')
        self.assertFalse(value['truncated'])
        self.assertEqual(len(value['nodes']), 2)
        local, remote = value['clients']
        self.assertEqual(local['tx_bytes'], 0xffffffff)
        self.assertEqual(remote['tx_bytes'], 0xffffffff * 1048576)
        self.assertEqual(remote['rssi_dbm'], -61)
        self.assertEqual(remote['downlink_mbps'], 866)
        self.assertEqual(remote['link_age_ms'], 0)

    def test_missing_stale_and_reset_measurements_stay_unknown(self):
        for mode in ['unobserved', 'stale']:
            with self.subTest(mode=mode):
                for row in self.snapshot(mode)['clients']:
                    self.assertIsNone(row['rssi_dbm'])
                    self.assertIsNone(row['tx_bytes'])
                    self.assertIsNone(row['downlink_mbps'])
        self.assertIsNone(self.snapshot('reset')['clients'][0]['rssi_dbm'])

    def test_bounds_backhaul_and_offline_filtering(self):
        for mode in ['overflow', 'nodes', 'interfaces']:
            with self.subTest(mode=mode):
                self.assertTrue(self.snapshot(mode)['truncated'])
        self.assertEqual(len(self.snapshot('backhaul')['clients']), 1)
        self.assertEqual(len(self.snapshot('offline')['nodes']), 1)
        self.assertEqual(len(self.snapshot('offline')['clients']), 1)
        subprocess.run([str(self.binary), 'small'], check=True)


class MeshClientNormalization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = os.environ.get('UCODE') or shutil.which('ucode')
        if not cls.ucode:
            raise unittest.SkipTest('set UCODE to execute the real normalization module')

    def input(self):
        return {'snapshot': {'schema': 1, 'fresh_ms': 30000, 'truncated': False,
            'nodes': [{'alid': '02:00:00:00:00:09', 'local': False, 'role': 2,
                       'interfaces': ['02:00:00:00:00:08']}],
            'clients': [{'mac': '04:00:00:00:00:01', 'node': '02:00:00:00:00:09',
                         'bssid': '02:00:00:00:00:02', 'band': '5g', 'rssi_dbm': -60,
                         'link_age_ms': 10, 'downlink_mbps': 866, 'uplink_mbps': 433,
                         'traffic_age_ms': 10, 'tx_bytes': 123, 'rx_bytes': 456}]},
            'leases': {'dhcp_leases': [{'macaddr': '02:00:00:00:00:08', 'ipaddr': '10.10.1.175', 'expires': 60},
                                     {'macaddr': '04:00:00:00:00:01', 'ipaddr': '10.10.1.218', 'expires': 60,
                                      'hostname': '<img src=x onerror=alert(1)>'}]}, 'hints': {}, 'local': []}

    def run_normalizer(self, value, setup=""):
        with tempfile.TemporaryDirectory(prefix='mesh-clients-ucode-') as temp:
            data = Path(temp) / 'data.json'
            data.write_text(json.dumps(value))
            script = f'import {{ normalize }} from {json.dumps(str(MODULE))};\n'
            script += 'import { readfile } from "fs";\n'
            script += 'let d=json(readfile(ARGV[0])); ' + setup + ' try { print(sprintf("%J", normalize(d.snapshot,d.leases,d.hints,d.local))); } catch(e) { print("{\\"ok\\":false}"); }\n'
            result = subprocess.run([self.ucode, '-L', '/tmp/mesh-ucode-build/*.so', '-e', script, str(data)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

    def test_exact_interface_lease_join_never_guesses_alid_offset(self):
        data = self.input()
        result = self.run_normalizer(data)
        self.assertTrue(result['ok'])
        self.assertEqual(result['nodes'][0]['address'], '10.10.1.175')
        self.assertEqual(result['nodes'][0]['management_mac'], '02:00:00:00:00:08')
        self.assertEqual(result['clients'][0]['address'], '10.10.1.218')
        data['snapshot']['nodes'][0]['interfaces'] = []
        self.assertIsNone(self.run_normalizer(data)['nodes'][0]['address'])
        data['snapshot']['nodes'][0]['interfaces'] = ['02:00:00:00:00:09']
        self.assertIsNone(self.run_normalizer(data)['nodes'][0]['address'])

    def test_ambiguous_expired_and_invalid_leases_are_not_addresses(self):
        data = self.input()
        data['leases']['dhcp_leases'][0]['expires'] = 0
        self.assertIsNone(self.run_normalizer(data)['nodes'][0]['address'])
        data = self.input()
        data['leases']['dhcp_leases'].append({'macaddr': '02:00:00:00:00:08', 'ipaddr': '10.10.1.176', 'expires': 60})
        self.assertIsNone(self.run_normalizer(data)['nodes'][0]['address'])
        data['leases']['dhcp_leases'][0]['ipaddr'] = 'javascript:alert(1)'
        data['leases']['dhcp_leases'].pop()
        self.assertIsNone(self.run_normalizer(data)['nodes'][0]['address'])

    def test_missing_stale_nonfinite_malformed_and_caps(self):
        data = self.input()
        data['snapshot']['clients'][0]['link_age_ms'] = 30001
        data['snapshot']['clients'][0]['traffic_age_ms'] = 30001
        result = self.run_normalizer(data)['clients'][0]
        self.assertIsNone(result['rssi_dbm'])
        self.assertIsNone(result['tx_bytes'])
        for field, bad in [('rssi_dbm', 'NaN'), ('tx_bytes', 1e100), ('downlink_mbps', -1)]:
            value = self.input(); value['snapshot']['clients'][0][field] = bad
            self.assertFalse(self.run_normalizer(value)['ok'])
        for bad in [None, [], {}, {'schema': 1, 'fresh_ms': 30000, 'truncated': True}]:
            value = self.input(); value['snapshot'] = bad
            self.assertFalse(self.run_normalizer(value)['ok'])
        value = self.input();value['snapshot']['clients'] *= 129
        self.assertFalse(self.run_normalizer(value)['ok'])

    def test_actual_nonfinite_numbers_are_rejected(self):
        for expression in ['1e999', '-1e999', '0 / 0']:
            self.assertFalse(self.run_normalizer(self.input(),
                'd.snapshot.clients[0].tx_bytes = ' + expression + ';')['ok'])

    def test_local_phy_enrichment_cannot_invent_remote_nss_mcs(self):
        data = self.input()
        data['local'] = [{'mac': '04:00:00:00:00:01', 'rx': {'rate': 600000, 'nss': 2, 'mcs': 7}}]
        remote = self.run_normalizer(data)['clients'][0]
        self.assertNotIn('rx_nss', remote)
        data['snapshot']['nodes'][0]['local'] = True
        local = self.run_normalizer(data)['clients'][0]
        self.assertEqual(local['rx_nss'], 2)
        self.assertEqual(local['rx_kbps'], 600000)

    def test_actual_security_helper_requires_exact_successful_bounded_reply(self):
        security = HELPER.with_name('ax6000-mesh-security')
        with tempfile.TemporaryDirectory(prefix='mesh-security-helper-') as temp:
            root = Path(temp)
            fixture = root / 'fixture.json'
            mock = root / 'mock-fs.uc'
            mock.write_text('import { readfile } from "fs"; let d=json(readfile(ARGV[0]));\n'
                'export function popen(command,mode) {\n'
                ' if(command!="timeout 3 mapd_cli /tmp/mapd_ctrl get bh_security 2>/dev/null" || mode!="r") die("Unexpected command");\n'
                ' return {read: function(limit) {if(limit!=33) die("Unbounded read");return d.raw;}, close: function() {return d.status;}};\n};\n')
            script = root / 'security.uc'
            script.write_text(security.read_text().replace("from 'fs'", 'from ' + json.dumps(str(mock))))
            for raw, status, expected in [('sae=1\n', 0, 'sae=1\n'), ('sae=0\n', 0, 'sae=0\n'),
                    ('sae=1\n', 1, 'sae=0\n'), ('sae=1', 0, 'sae=0\n'),
                    ('sae=1\nDO_NOT_LEAK_KEY', 0, 'sae=0\n'), ('x' * 33, 0, 'sae=0\n')]:
                fixture.write_text(json.dumps({'raw': raw, 'status': status}))
                result = subprocess.run([self.ucode, '-L', '/tmp/mesh-ucode-build/*.so', str(script), str(fixture)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_actual_helper_uses_fixed_queries_and_hides_invalid_daemon_output(self):
        with tempfile.TemporaryDirectory(prefix='mesh-clients-helper-') as temp:
            root = Path(temp)
            fixture = root / 'fixture.json'
            fs = root / 'mock-fs.uc'
            fs.write_text('import { readfile } from "fs";\n'
                'let input=json(readfile(ARGV[0]));\n'
                'export function popen(command,mode) {\n'
                ' if(command!="timeout 3 mapd_cli /tmp/mapd_ctrl get mesh_clients 2>/dev/null" || mode!="r") die("Unexpected command");\n'
                ' return { read: function(limit) { if(limit!=65537) die("Unbounded read"); return input.raw; }, close: function() { return input.status; } };\n'
                '};\n')
            ubus = root / 'mock-ubus.uc'
            ubus.write_text('import { readfile } from "fs";\n'
                'let input=json(readfile(ARGV[0]));\n'
                'export function connect(path,timeout) { if(path!=null || timeout!=1) die("Unbounded ubus timeout"); return {\n'
                ' call: function(object,method,args) {\n'
                '  if(object=="luci-rpc" && method=="getDHCPLeases") return input.leases;\n'
                '  if(object=="luci-rpc" && method=="getHostHints") return {};\n'
                '  if(object=="iwinfo" && method=="assoclist") return {results:[]};\n'
                '  die("Unexpected ubus call");\n'
                ' }, disconnect: function() {} };\n};\n')
            script = root / 'helper.uc'
            source = HELPER.read_text().replace("from 'fs'", 'from ' + json.dumps(str(fs)))
            source = source.replace("from 'ubus'", 'from ' + json.dumps(str(ubus)))
            source = source.replace("from '/usr/share/ax6000-mesh/clients.uc'", 'from ' + json.dumps(str(MODULE)))
            script.write_text(source)
            data = self.input()
            fixture.write_text(json.dumps({'raw': json.dumps(data['snapshot']), 'status': 0, 'leases': data['leases']}))
            command = [self.ucode, '-L', '/tmp/mesh-ucode-build/*.so', str(script), str(fixture)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['ok'], result.stdout)
            for raw, status in [('DO_NOT_LEAK_PASSWORD', 0), ('x' * 65537, 0), ('{}', 1)]:
                fixture.write_text(json.dumps({'raw': raw, 'status': status, 'leases': data['leases']}))
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(json.loads(result.stdout)['ok'])
                self.assertNotIn('DO_NOT_LEAK', result.stdout)


if __name__ == '__main__':
    unittest.main()
