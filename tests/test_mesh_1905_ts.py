"""Run the patched vendor R2 SSID/VID policy builder as host C."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'files/mediatek-mesh/packages/1905daemon'
HASH = '82f7cc4ad5731e750f87c9a4ad19a39d2456bb8fec0cf79bf4b3f3ccb4f14795'
NATIVE = ROOT.parent / 'local-native-mesh-20261027/work/build/source/dl/1905daemon-35234223.tar.bz2'


def extract_function(source, signature):
    start = source.index(signature); pos = source.index('{', start); depth = 1; end = pos + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}'); end += 1
    return source[start:end]


class TrafficSeparationPolicy(unittest.TestCase):
    def test_real_builder_deduplicates_and_bounds_policies(self):
        archive = Path(os.environ.get('MESH_1905_SOURCE_ARCHIVE', str(NATIVE)))
        if not archive.exists(): self.skipTest('pinned vendor archive unavailable')
        cc = shutil.which('cc')
        if not cc: self.skipTest('host C compiler unavailable')
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), HASH)
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(archive) as tar: tar.extractall(tmp, filter='data')
            source = Path(tmp) / '1905daemon'
            for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
                r = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            vendor_source = (source / 'src/multi_ap.c').read_text()
            function = extract_function(vendor_source, 'int update_traffic_separation_policy(')
            parser = extract_function(vendor_source, 'int parse_traffic_separation_policy_tlv(')
            encoder = extract_function(vendor_source, 'int append_traffic_separation_tlv(')
            primary = extract_function(vendor_source, 'int parse_default_802_1q_setting_tlv(')
            harness = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#define DEBUG_ERROR 1
#define debug(...) ((void)0)
#define be_to_host16 ntohs
#define host_to_be16 htons
#define ETH_ALEN 6
#define TRAFFIC_SEPARATION_POLICY_TYPE 0xb6
#define os_memset memset
#define SLIST_INIT(h) ((h)->first=NULL)
#define SLIST_EMPTY(h) ((h)->first==NULL)
#define SLIST_FOREACH(p,h,f) for ((p)=(h)->first; (p); (p)=(p)->next)
#define INVALID_VLAN_ID 4095
#define VLAN_N_VID 4095
#define SSID_MAX_LEN 32
#define MAX_VLAN_NUM 48
#define os_memcmp memcmp
#define os_memcpy memcpy
#define os_zalloc(n) calloc(1,n)
#define os_free free
struct entry { struct entry *next; };
struct traffic_separation_db { unsigned short vid; unsigned char SSID_len; char *SSID; struct traffic_separation_db *next; };
struct head { struct traffic_separation_db *first; };
struct traffics_policy { struct head policy_head; int SSID_num, updated; };
struct p1905_managerd_ctx { int MAP_Cer; struct { struct traffics_policy tpolicy; } map_policy; };
struct __attribute__((packed)) def_8021q_setting { unsigned short primary_vid; struct { unsigned char Reserved:5, PCP:3; } dft; unsigned char updated; };
struct set_config_bss_info { unsigned short vid; unsigned char ssid_len, mac[6]; char ssid[33]; };
#define SLIST_INSERT_HEAD(h,p,f) do { (p)->next=(h)->first; (h)->first=(p); } while(0)
static void delete_exist_traffic_policy(struct p1905_managerd_ctx *ctx, struct traffics_policy *p) {
 (void)ctx; while(p->policy_head.first) {struct traffic_separation_db *n=p->policy_head.first; p->policy_head.first=n->next; free(n->SSID); free(n);} p->SSID_num=0;
}
/* REAL_FUNCTION */
/* REAL_PARSER */
/* REAL_ENCODER */
/* REAL_PRIMARY */
static void put(struct set_config_bss_info *b,const char *s,int vid) {strcpy(b->ssid,s);b->ssid_len=strlen(s);b->vid=vid;}
int main(void) {
 struct p1905_managerd_ctx c={0}; struct set_config_bss_info b[99]={0};
 put(&b[0],"Home",1);put(&b[1],"Guest",10);put(&b[2],"Home",1);put(&b[3],"Guest",10);
 assert(update_traffic_separation_policy(&c,b,4)==0);assert(c.map_policy.tpolicy.SSID_num==2);
 b[2].vid=11;assert(update_traffic_separation_policy(&c,b,4)<0);assert(c.map_policy.tpolicy.SSID_num==2);
 assert(update_traffic_separation_policy(&c,b,0)==0);assert(c.map_policy.tpolicy.SSID_num==0);assert(c.map_policy.tpolicy.updated==1);
 delete_exist_traffic_policy(&c,&c.map_policy.tpolicy);
 for(int i=0;i<49;i++){snprintf(b[i].ssid,sizeof(b[i].ssid),"N%d",i);b[i].ssid_len=strlen(b[i].ssid);b[i].vid=i+1;}
 assert(update_traffic_separation_policy(&c,b,49)<0);assert(c.map_policy.tpolicy.SSID_num==0);
 assert(update_traffic_separation_policy(&c,b,48)==0);assert(c.map_policy.tpolicy.SSID_num==48);
 delete_exist_traffic_policy(&c,&c.map_policy.tpolicy);
 b[0].vid=0;assert(update_traffic_separation_policy(&c,b,1)<0);
 b[0].vid=4095;assert(update_traffic_separation_policy(&c,b,1)==0);assert(c.map_policy.tpolicy.SSID_num==0);
 {
  unsigned char good[]={3,1,'A',0,10,1,'A',0,10,1,'B',0,20};
  unsigned char conflict[]={2,1,'A',0,10,1,'A',0,11};
  unsigned char invalid[]={1,1,'A',0,0};
  struct traffics_policy policy={0};
  assert(parse_traffic_separation_policy_tlv(&policy,sizeof(good),good)==0);assert(policy.SSID_num==2);
  assert(parse_traffic_separation_policy_tlv(&policy,sizeof(good),good)<0);assert(policy.SSID_num==2);
  delete_exist_traffic_policy(&c,&policy);
  assert(parse_traffic_separation_policy_tlv(&policy,sizeof(conflict),conflict)<0);
  delete_exist_traffic_policy(&c,&policy);
  assert(parse_traffic_separation_policy_tlv(&policy,sizeof(invalid),invalid)<0);
  delete_exist_traffic_policy(&c,&policy);
  good[0]=49; assert(parse_traffic_separation_policy_tlv(&policy,sizeof(good),good)<0);
 }
 {
  unsigned char out[2048], mac[6]={0}; struct def_8021q_setting primary={0};
  unsigned char good[]={0,1,0}; unsigned char bad[]={0,0,0}; unsigned char large[]={0xff,0xff,0};
  assert(parse_default_802_1q_setting_tlv(&primary,3,good)==0);assert(primary.primary_vid==1);
  assert(parse_default_802_1q_setting_tlv(&primary,2,good)<0);
  assert(parse_default_802_1q_setting_tlv(&primary,3,bad)<0);
  assert(parse_default_802_1q_setting_tlv(&primary,3,large)<0);
  memset(b,0,sizeof(b));put(&b[0],"Home",1);put(&b[1],"Guest",10);put(&b[2],"Home",1);
  assert(append_traffic_separation_tlv(&c,out,mac,3,b)>0);assert(out[3]==2);
  b[2].vid=11;memset(out,0xa5,sizeof(out));assert(append_traffic_separation_tlv(&c,out,mac,3,b)==0);assert(out[0]==0xa5);
  for(int i=0;i<49;i++){snprintf(b[i].ssid,sizeof(b[i].ssid),"N%d",i);b[i].ssid_len=strlen(b[i].ssid);b[i].vid=i+1;}
  assert(append_traffic_separation_tlv(&c,out,mac,49,b)==0);assert(out[0]==0xa5);
 }
 return 0;
}
'''.replace('/* REAL_FUNCTION */', function).replace('/* REAL_PARSER */', parser).replace('/* REAL_ENCODER */', encoder).replace('/* REAL_PRIMARY */', primary)
            c = Path(tmp) / 'test.c'; c.write_text(harness)
            binary = Path(tmp) / 'test'
            r = subprocess.run([cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            r = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_real_wts_reader_preserves_live_state_on_failure(self):
        archive = Path(os.environ.get('MESH_1905_SOURCE_ARCHIVE', str(NATIVE)))
        if not archive.exists(): self.skipTest('pinned vendor archive unavailable')
        cc = shutil.which('cc')
        if not cc: self.skipTest('host C compiler unavailable')
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), HASH)
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(archive) as tar: tar.extractall(tmp, filter='data')
            source = Path(tmp) / '1905daemon'
            for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
                r = subprocess.run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            reader = extract_function((source / 'src/file_io.c').read_text(), 'int _1905_read_set_config(')
            harness = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#define MAP_R2 1
#define INVALID_VLAN_ID 4095
#define MAX_SSID_LEN 33
#define BAND_2G_CAP 1
#define BAND_5GL_CAP 2
#define BAND_5GH_CAP 4
#define BAND_6G_CAP 8
#define BIT_BH_BSS 64
#define BIT_FH_BSS 32
#define os_zalloc(n) calloc(1,n)
#define os_free free
#define os_memset memset
#define os_memcpy memcpy
#define os_strlen strlen
#define os_snprintf_error(size, n) ((n) < 0 || (unsigned)(n) >= (size))
#define debug(...) ((void)0)
#define debugbyte(...) ((void)0)
struct setting { unsigned int primary_vid; struct { unsigned char PCP; } dft; };
struct p1905_managerd_ctx { int MAP_Cer; struct { struct setting setting; } map_policy; };
struct set_config_bss_info { unsigned int authmode, encryptype, band_support, wfa_vendor_extension, pvid, pcp, vid; unsigned char mac[6], key[65], oper_class[4], ssid_len, hidden_ssid; char ssid[33]; };
static int reject_policy;
static int find_band_by_opclass(const unsigned char *p) { (void)p; return 1; }
static int update_traffic_separation_policy(struct p1905_managerd_ctx *c, struct set_config_bss_info *b, unsigned char n) { (void)c;(void)b;(void)n;return reject_policy ? -1 : 0; }
/* READER */
int main(void) {
 char name[]="/tmp/mesh-reader-XXXXXX"; int fd=mkstemp(name); FILE *f;
 struct p1905_managerd_ctx ctx={0}; struct set_config_bss_info b[8]={0}, before[8]; unsigned char count=0;
 assert(fd>=0); f=fdopen(fd,"w"); assert(f);
 fputs("1,ff:ff:ff:ff:ff:ff 8x Home 0x0060 0x0008 password 0 1 hidden-N 4095 N/A N/A\n",f); assert(!fclose(f));
 assert(_1905_read_set_config(&ctx,name,b,8,&count)==0); assert(count==1); assert(!strcmp((char*)b[0].ssid,"Home"));
 memcpy(before,b,sizeof(b)); reject_policy=1;
 assert(_1905_read_set_config(&ctx,name,b,8,&count)<0); assert(count==1); assert(!memcmp(before,b,sizeof(b)));
 f=fopen(name,"w"); assert(f); fputs("invalid,not-a-mac\n",f); fclose(f); reject_policy=0;
 assert(_1905_read_set_config(&ctx,name,b,8,&count)<0); assert(count==1); assert(!memcmp(before,b,sizeof(b)));
 unlink(name);return 0;
}
'''.replace('/* READER */', reader)
            c = Path(tmp) / 'reader.c'; c.write_text(harness)
            binary = Path(tmp) / 'reader'
            r = subprocess.run([cc, '-std=gnu11', '-Wall', '-Wextra', '-Wno-unused-but-set-variable', '-Wno-sign-compare', '-Werror', str(c), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            r = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_managed_mode_blocks_real_mapfilter_ts_mutators(self):
        archive = Path(os.environ.get('MESH_1905_SOURCE_ARCHIVE', str(NATIVE)))
        if not archive.exists(): self.skipTest('pinned vendor archive unavailable')
        cc = shutil.which('cc')
        if not cc: self.skipTest('host C compiler unavailable')
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), HASH)
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(archive) as tar: tar.extractall(tmp, filter='data')
            source = Path(tmp) / '1905daemon'
            for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
                r = subprocess.run(['patch','-p1','--fuzz=0','-i',str(patch)], cwd=source, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            raw = (source / 'src/mapfilter_if.c').read_text()
            names = ('mapfilter_ts_onoff','mapfilter_set_ts_default_8021q','mapfilter_set_ts_policy',
                     'mapfilter_set_transparent_vid','mapfilter_update_client_vid')
            functions = '\n'.join(extract_function(raw, 'int '+name+'(') for name in names)
            harness = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "linux_ts_managed.h"
#define ETH_ALEN 6
#define os_memset memset
#define os_memcpy memcpy
#define TRAFFIC_SEPARATION_ONOFF 1
#define SET_TRAFFIC_SEPARATION_DEFAULT_8021Q 2
#define SET_TRAFFIC_SEPARATION_POLICY 3
#define SET_TRANSPARENT_VID 4
#define UPDATE_CLIENT_VID 5
struct map_netlink_message { int type,len; unsigned char event[4096]; };
struct ts_default_8021q { unsigned short primary_vid; unsigned char default_pcp; };
struct ssid_2_vid_mapping { unsigned short vid; char ssid[33]; };
struct ts_policy { unsigned char num; struct ssid_2_vid_mapping ssid_2_vid[48]; };
struct transparent_vids { unsigned char num; unsigned short vids[48]; };
struct client_vid { unsigned char client_mac[6]; unsigned short vid; unsigned char status,ssid_len; char ssid[33]; unsigned char al_mac[6]; };
static unsigned char cmd_buf[8192]; static int sends;
static int mapfilter_netlink_msg_send(void *p, unsigned int n, int f) {(void)p;(void)n;(void)f;sends++;return 0;}
/* FUNCTIONS */
int main(void) {
 unsigned char mac[6]={0};unsigned short vids[]={10};char ssid[]="Guest";
 setenv("AX6000_MESH_LINUX_TS","1",1);
 mapfilter_ts_onoff(1);mapfilter_set_ts_default_8021q(1,0);mapfilter_set_ts_policy(0,NULL);
 mapfilter_set_transparent_vid(vids,1);mapfilter_update_client_vid(mac,10,1,5,ssid,mac);assert(sends==0);
 mapfilter_ts_onoff(0);assert(sends==1);
 unsetenv("AX6000_MESH_LINUX_TS");mapfilter_ts_onoff(1);assert(sends==2);
 mapfilter_set_ts_default_8021q(1,0);assert(sends==3);return 0;
}
'''.replace('/* FUNCTIONS */',functions)
            c = Path(tmp) / 'managed.c'; c.write_text(harness)
            binary = Path(tmp) / 'managed'
            r = subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror','-I',str(source/'inc'),str(c),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            r = subprocess.run([str(binary)],capture_output=True,text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_managed_notifier_exports_without_vendor_dataplane(self):
        archive = Path(os.environ.get('MESH_1905_SOURCE_ARCHIVE', str(NATIVE)))
        if not archive.exists(): self.skipTest('pinned vendor archive unavailable')
        cc = shutil.which('cc')
        if not cc: self.skipTest('host C compiler unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(archive) as tar: tar.extractall(tmp, filter='data')
            source = Path(tmp) / '1905daemon'
            for patch in sorted((PACKAGE / 'patches').glob('*.patch')):
                r = subprocess.run(['patch','-p1','--fuzz=0','-i',str(patch)],cwd=source,capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            raw=(source/'src/multi_ap.c').read_text()
            fn=extract_function(raw,'void map_r2_notify_ts_config(')
            republish=extract_function(raw,'void mesh_ts_republish_after_attach(')
            harness=r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "linux_ts_managed.h"
#define MAX_VLAN_NUM 48
#define os_zalloc(n) calloc(1,n)
#define os_free free
#define os_memcpy memcpy
#define debug(...) ((void)0)
#define SLIST_FOREACH(p,h,f) for ((p)=(h)->first;(p);(p)=(p)->next)
struct traffic_separation_db {unsigned short vid;unsigned char SSID_len;char *SSID;struct traffic_separation_db *next;};
struct head {struct traffic_separation_db *first;};
struct traffics_policy {struct head policy_head;unsigned int SSID_num;int updated;};
struct ssid_2_vid_mapping {unsigned short vlan_id;char ssid[33];};
struct p1905_managerd_ctx {struct {struct {unsigned short primary_vid;struct {unsigned char PCP;} dft;int updated;} setting;struct traffics_policy tpolicy;} map_policy; int bss_head;};
static int mutations, events;
static void mapfilter_set_ts_default_8021q(unsigned short v,unsigned char p){(void)v;(void)p;mutations++;}
static void mapfilter_set_ts_policy(unsigned char n,struct ssid_2_vid_mapping *m){(void)n;(void)m;mutations++;}
static void _1905_notify_ts_setting(struct p1905_managerd_ctx *c,unsigned char n,struct ssid_2_vid_mapping *m){(void)c;(void)n;(void)m;events++;}
static void eth_layer_set_traffic_separation_vlan(unsigned short *v,unsigned char n){(void)v;(void)n;mutations++;}
static void map_rm_hnat_session(void){mutations++;}
static void update_operation_bss_vlan(struct p1905_managerd_ctx *c,void *b,struct traffics_policy *p,void *a){(void)c;(void)b;(void)p;(void)a;}
static void maintain_all_assoc_clients(struct p1905_managerd_ctx *c){(void)c;}
/* FUNCTION */
/* REPUBLISH */
int main(void){struct p1905_managerd_ctx c={0};struct traffic_separation_db e={10,5,"Guest",NULL};
 c.map_policy.tpolicy.policy_head.first=&e;c.map_policy.tpolicy.SSID_num=1;c.map_policy.tpolicy.updated=1;
 setenv("AX6000_MESH_LINUX_TS","1",1);map_r2_notify_ts_config(&c,NULL);assert(events==1&&mutations==0);
 c.map_policy.tpolicy.updated=1;c.map_policy.tpolicy.SSID_num=0;map_r2_notify_ts_config(&c,NULL);assert(events==2&&mutations==0);
 c.map_policy.tpolicy.SSID_num=1;mesh_ts_republish_after_attach(&c,NULL);assert(events==3&&mutations==0);
 unsetenv("AX6000_MESH_LINUX_TS");mesh_ts_republish_after_attach(&c,NULL);assert(events==3&&mutations==0);
 c.map_policy.tpolicy.updated=1;map_r2_notify_ts_config(&c,NULL);assert(events==4&&mutations==5);return 0;}
'''.replace('/* FUNCTION */',fn).replace('/* REPUBLISH */',republish)
            c=Path(tmp)/'notify.c';c.write_text(harness);binary=Path(tmp)/'notify'
            r=subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Wno-unused-parameter','-Werror','-I',str(source/'inc'),str(c),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            r=subprocess.run([str(binary)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)

    def test_production_policy_request_encodes_managed_clear(self):
        archive = Path(os.environ.get('MESH_1905_SOURCE_ARCHIVE', str(NATIVE)))
        if not archive.exists(): self.skipTest('pinned vendor archive unavailable')
        cc=shutil.which('cc')
        if not cc: self.skipTest('host C compiler unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(archive) as tar: tar.extractall(tmp,filter='data')
            source=Path(tmp)/'1905daemon'
            for patch in sorted((PACKAGE/'patches').glob('*.patch')):
                r=subprocess.run(['patch','-p1','--fuzz=0','-i',str(patch)],cwd=source,capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            fn=extract_function((source/'src/multi_ap.c').read_text(),'unsigned short map_policy_config_request_message(')
            harness=r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "linux_ts_managed.h"
#define MAP_R2 1
#define VLAN_N_VID 4095
#define DEFAULT_8021Q_SETTING_TYPE 0xb5
#define TRAFFIC_SEPARATION_POLICY_TYPE 0xb6
#define MIN_TLVS_LENGTH 1
#define MAP_POLICY_CONFIG_REQUEST 0x8003
#define host_to_be16 htons
typedef struct {unsigned char message_version,reserved_field_0;unsigned short message_type;unsigned char relay_indicator,reserve_field_1;} cmdu_message_header;
struct p1905_managerd_ctx {struct {unsigned char *buf;} tlv_buf;int MAP_Cer,bss_config_num;void *bss_config;struct {struct {unsigned short primary_vid;} setting;struct {int SSID_num;} tpolicy;} map_policy;};
static int append_send_tlv(unsigned char *b,void *c){(void)b;(void)c;return 0;}
static int append_default_8021Q_tlv(void *c,void *b,void *a,int n,void *p){(void)c;(void)b;(void)a;(void)n;(void)p;return 0;}
static int append_traffic_separation_tlv(void *c,void *b,void *a,int n,void *p){(void)c;(void)b;(void)a;(void)n;(void)p;return 0;}
static int append_end_of_tlv(unsigned char *b){b[0]=0;b[1]=0;b[2]=0;return 3;}
/* FUNCTION */
int main(void){unsigned char packet[100]={0},tlvs[100]={0},mac[6]={0};struct p1905_managerd_ctx c={0};
 c.tlv_buf.buf=tlvs;c.map_policy.setting.primary_vid=4095;setenv("AX6000_MESH_LINUX_TS","1",1);
 assert(map_policy_config_request_message(packet,&c,mac)==13);assert(tlvs[0]==0xb5&&tlvs[3]==15&&tlvs[4]==255);
 assert(tlvs[6]==0xb6&&tlvs[8]==1&&tlvs[9]==0);unsetenv("AX6000_MESH_LINUX_TS");
 assert(map_policy_config_request_message(packet,&c,mac)==3);return 0;}
'''.replace('/* FUNCTION */',fn)
            c=Path(tmp)/'request.c';c.write_text(harness);binary=Path(tmp)/'request'
            r=subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror','-I',str(source/'inc'),str(c),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            r=subprocess.run([str(binary)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)

    def test_controller_native_fh_mapping_is_emitted_to_subscribers(self):
        archive=Path(os.environ.get('MESH_1905_SOURCE_ARCHIVE',str(NATIVE)))
        if not archive.exists(): self.skipTest('pinned vendor archive unavailable')
        cc=shutil.which('cc')
        if not cc: self.skipTest('host C compiler unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(archive) as tar: tar.extractall(tmp,filter='data')
            source=Path(tmp)/'1905daemon'
            for patch in sorted((PACKAGE/'patches').glob('*.patch')):
                r=subprocess.run(['patch','-p1','--fuzz=0','-i',str(patch)],cwd=source,capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            text=(source/'src/_1905_lib_io.c').read_text()
            funcs=extract_function(text,'unsigned short get_vid_from_ssid(')+'\n'+extract_function(text,'void _1905_notify_ts_setting(')
            harness=r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#define MAX_VLAN_NUM 48
#define VLAN_N_VID 4095
#define ETH_ALEN 6
#define BIT_FH_BSS 32
#define _1905_SET_TRAFFIC_SEPARATION_SETTING_EVENT 8
#define os_memset memset
#define os_memcpy memcpy
#define os_strncmp strncmp
#define debug(...) ((void)0)
struct __attribute__((packed)) msg {unsigned short type,mid,length;unsigned char buffer[0];};
struct __attribute__((packed)) ts_fh_config {unsigned char itf_mac[6];unsigned short vid;};
struct __attribute__((packed)) ts_setting {struct {unsigned short primary_vid;unsigned char primary_pcp,policy_vid_num;unsigned short policy_vids[48];} common_setting;struct {unsigned char itf_num;struct ts_fh_config fh_configs[0];} fh_bss_setting;};
struct ssid_2_vid_mapping {unsigned short vlan_id;char ssid[33];};
struct config_bss_info {int config_status;char ifname[16];unsigned char mac[6];struct {char Ssid[33];unsigned char map_vendor_extension;} config;};
struct p1905_managerd_ctx {struct {struct {unsigned short primary_vid;struct {unsigned char PCP;} dft;} setting;} map_policy;int radio_number;struct {int bss_number;struct config_bss_info bss[4];} rinfo[2];};
static unsigned char buf_io[4096], saved[4096];static int sent;
static void _1905_interface_send(void *c,void *p,int len,void *a){(void)c;(void)a;memcpy(saved,p,len);sent=len;}
/* FUNCTIONS */
int main(void){struct p1905_managerd_ctx ctx={0};struct ssid_2_vid_mapping m[2]={{1,"Home"},{10,"Guest"}};struct msg *event=(struct msg *)saved;struct ts_setting *ts=(struct ts_setting *)event->buffer;
 ctx.map_policy.setting.primary_vid=1;ctx.radio_number=1;ctx.rinfo[0].bss_number=3;
 for(int i=0;i<3;i++){ctx.rinfo[0].bss[i].config_status=1;ctx.rinfo[0].bss[i].mac[0]=2;ctx.rinfo[0].bss[i].mac[5]=i+1;}
 strcpy(ctx.rinfo[0].bss[0].config.Ssid,"Home");ctx.rinfo[0].bss[0].config.map_vendor_extension=BIT_FH_BSS;
 strcpy(ctx.rinfo[0].bss[1].config.Ssid,"Guest");ctx.rinfo[0].bss[1].config.map_vendor_extension=BIT_FH_BSS;
 strcpy(ctx.rinfo[0].bss[2].config.Ssid,"BH");ctx.rinfo[0].bss[2].config.map_vendor_extension=64;
 _1905_notify_ts_setting(&ctx,2,m);assert(sent==(int)(sizeof(*event)+sizeof(*ts)+2*sizeof(struct ts_fh_config)));
 assert(ts->common_setting.primary_vid==1&&ts->common_setting.policy_vid_num==2&&ts->fh_bss_setting.itf_num==2);
 assert(ts->fh_bss_setting.fh_configs[0].vid==1&&ts->fh_bss_setting.fh_configs[1].vid==10);
 assert(ts->fh_bss_setting.fh_configs[0].itf_mac[5]==1&&ts->fh_bss_setting.fh_configs[1].itf_mac[5]==2);
 _1905_notify_ts_setting(&ctx,49,NULL);assert(sent==(int)sizeof(*event)&&event->length==0);return 0;}
'''.replace('/* FUNCTIONS */',funcs)
            c=Path(tmp)/'local.c';c.write_text(harness);binary=Path(tmp)/'local'
            r=subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Wno-sign-compare','-Werror',str(c),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            r=subprocess.run([str(binary)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
