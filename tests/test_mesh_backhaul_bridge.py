"""Execute the pinned netifd UCI-to-bridge path for hidden Mesh backhaul APs.

Set NETIFD_SOURCE_DIR to the prepared netifd cbb83a1857407a28a63dc09412a1f209195914ef
source and UCODE to a host ucode binary. Real option parsing, handle_link(),
uc_netifd_device_set(), and system_bridge_set_wireless() execute. Real libucode
values retain their types; only device lookup/sysfs writes are recorded.
No kernel, driver, firmware tree, or live network state is modified.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HASHES = {
    'examples/utils.uc': '9601c500d498103eb3b22010fd6fba0885840f10f32d8c8db7f05911e4aedeb9',
    'examples/wireless.uc': 'c64fb9f64f82f710fad7051ea8c7d510734860945c77121cf1967ee7c5cdefe8',
    'examples/wireless-device.uc': '8570cf9a8cfd9aecd8cf149a5009551980fe16744100f8a9c469caffddedea5e',
    'ucode.c': 'ff60cc267390b91362f708b2e4000a9487da5518b9fc981462882195e8a563fe',
    'system-linux.c': 'a3d94025b4ce24cf317bcccfbe0b47f2753e521f1ac807fae186818ef30c55fb',
}


def definition(text, marker):
    start = text.index(marker)
    opening = text.index('{', start)
    end, depth = opening + 1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


class MeshBackhaulBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = os.environ.get('NETIFD_SOURCE_DIR')
        cls.ucode = os.environ.get('UCODE') or shutil.which('ucode')
        compiler = os.environ.get('HOST_CC') or shutil.which('cc')
        if not source or not cls.ucode or not compiler:
            raise unittest.SkipTest('set NETIFD_SOURCE_DIR and UCODE; host C compiler also required')
        cls.source = Path(source)
        for name, expected in HASHES.items():
            actual = hashlib.sha256((cls.source / name).read_bytes()).hexdigest()
            if actual != expected:
                raise AssertionError('Pinned netifd source differs: ' + name)
        cls.temp = tempfile.TemporaryDirectory(prefix='mesh-backhaul-bridge-')
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        utils = (cls.source / 'examples/utils.uc').read_text()
        wireless = (cls.source / 'examples/wireless.uc').read_text()
        device = (cls.source / 'examples/wireless-device.uc').read_text()
        cls.uc = '\n'.join([
            '\n'.join(line.removeprefix('export ') for line in utils.splitlines()
                      if line.startswith('export const TYPE_')),
            *(definition(utils, 'function ' + name + '(') for name in
              ('parse_bool', 'parse_array', '__type_parsers')),
            'const type_parser = __type_parsers();',
            *(definition(utils, 'function ' + name + '(') for name in
              ('handler_attributes', 'parse_attribute_list')),
            definition(wireless, 'const network_config_attr =') + ';',
            definition(wireless, 'const default_config_attr =') + ';',
            'let captured = null; let netifd = { device_set: (dev, data) => { captured = data; }, '
            'interface_handle_link: () => {} };',
            definition(device, 'function handle_link('),
        ])
        kernel_setter = definition((cls.source / 'system-linux.c').read_text(),
                                   'system_bridge_set_wireless(')
        ucode_c = (cls.source / 'ucode.c').read_text()
        value_helpers = '\n'.join([
            'static uc_value_t *' + definition(ucode_c, 'prop_get('),
            'static bool ' + definition(ucode_c, 'prop_get_bool('),
            'static bool ' + definition(ucode_c, 'prop_get_int('),
            'static uc_value_t *' + definition(ucode_c, 'uc_netifd_device_set('),
        ])
        library = Path(cls.ucode).resolve().parent
        cache = library / 'CMakeCache.txt'
        if not cache.exists():
            raise unittest.SkipTest('host ucode build CMakeCache.txt required for matching libucode headers')
        cache_lines = cache.read_text().splitlines()
        source_line = next(line for line in cache_lines
                           if line.startswith('CMAKE_HOME_DIRECTORY:INTERNAL='))
        includes = Path(source_line.split('=', 1)[1]) / 'include'
        json_include = next(line.split('=', 1)[1] for line in cache_lines
                            if line.startswith('JSONC_INCLUDEDIR:'))
        json_library = next(line.split('=', 1)[1] for line in cache_lines
                            if line.startswith('pkgcfg_lib_JSONC_json-c:'))
        c = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucode/types.h>
#define DEV_OPT_MULTICAST_TO_UNICAST 1
#define DEV_OPT_ISOLATE 2
struct device { struct { int flags; bool multicast_to_unicast, isolate; } settings;
    bool wireless_ap, wireless_proxyarp, wireless_isolate, wireless; int bpdu_filter; };
static struct device target;
static uc_value_t *args[2];
#define uc_fn_arg(n) (args[n])
static struct device *__device_get(const char *n,int e,bool v) { (void)n;(void)e;(void)v;return &target; }
static int mcast, hairpin, proxy;
static void system_bridge_set_multicast_to_unicast(struct device *d,const char *v) { (void)d;mcast=atoi(v); }
static void system_bridge_set_hairpin_mode(struct device *d,const char *v) { (void)d;hairpin=atoi(v); }
static void system_bridge_set_proxyarp_wifi(struct device *d,const char *v) { (void)d;proxy=atoi(v); }
/* REAL_VALUE_HELPERS */
static void /* REAL_SETTER */
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    struct device bridge={0};
    struct json_object *json=json_tokener_parse(argv[1]);
    if(!json) return 3;
    args[0]=ucv_string_new("radio"); args[1]=ucv_from_json(NULL,json);
    uc_value_t *result=uc_netifd_device_set(NULL,2);
    if(!result) return 4;
    system_bridge_set_wireless(&bridge,&target);
    printf("{\"multicast_to_unicast\":%d,\"hairpin\":%d,\"proxyarp\":%d,\"explicit_mcast\":%d}\n",
        mcast,hairpin,proxy,!!(target.settings.flags&DEV_OPT_MULTICAST_TO_UNICAST));
    ucv_put(result);ucv_put(args[0]);ucv_put(args[1]);json_object_put(json);
    return 0;
}
'''.replace('/* REAL_SETTER */', kernel_setter).replace('/* REAL_VALUE_HELPERS */', value_helpers)
        (root / 'bridge.c').write_text(c)
        cls.bridge = root / 'bridge'
        built = subprocess.run([compiler, '-std=c99', '-D_GNU_SOURCE', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                                '-I' + str(includes), '-I' + json_include,
                                str(root / 'bridge.c'), '-L' + str(library),
                                '-Wl,-rpath,' + str(library), '-lucode', json_library, '-o', str(cls.bridge)],
                               capture_output=True, text=True)
        if built.returncode:
            raise AssertionError(built.stderr)

    def bridge_state(self, config, ifname):
        # Core defaults supply multicast_to_unicast even when the vendor
        # driver's dump/schema omits it. Parse the UCI string "0" as false.
        script = self.uc + '\nlet spec = handler_attributes([], default_config_attr.iface, {});\n'
        script += 'let config = parse_attribute_list(' + json.dumps(config) + ', spec);\n'
        script += 'handle_link(' + json.dumps(ifname) + ', { type: "vif", ifname: '
        script += json.dumps(ifname) + ', config }, true); printf("%J", captured);'
        parsed = subprocess.run([self.ucode, '-e', script], capture_output=True, text=True)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        data = json.loads(parsed.stdout)
        state = subprocess.check_output([str(self.bridge), json.dumps(data)], text=True)
        return data, json.loads(state)

    def test_wireless_boolean_zero_is_ignored_by_pinned_native_type_boundary(self):
        # A declarative wifi-iface-only fix would silently leave hairpin on.
        # This regression records why the owned runtime bridge helper is needed.
        for ifname in ('ra1', 'rax1'):
            data, state = self.bridge_state({'mode': 'ap', 'network': 'lan',
                                             'multicast_to_unicast': '0'}, ifname)
            self.assertIs(data['multicast_to_unicast'], False)
            self.assertEqual(state, {'multicast_to_unicast': 1, 'hairpin': 1,
                                     'proxyarp': 0, 'explicit_mcast': 0})

    def test_ordinary_fronthaul_default_keeps_existing_bridge_behavior(self):
        for ifname in ('ra0', 'rax0'):
            data, state = self.bridge_state({'mode': 'ap', 'network': 'lan'}, ifname)
            self.assertNotIn('multicast_to_unicast', data)
            self.assertEqual(state, {'multicast_to_unicast': 1, 'hairpin': 1,
                                     'proxyarp': 0, 'explicit_mcast': 0})

    def test_station_uplink_keeps_existing_bridge_behavior(self):
        data, state = self.bridge_state({'mode': 'sta', 'network': 'lan'}, 'apclix0')
        self.assertFalse(data['wireless_ap'])
        self.assertEqual(state, {'multicast_to_unicast': 0, 'hairpin': 0,
                                 'proxyarp': 0, 'explicit_mcast': 0})


if __name__ == '__main__':
    unittest.main()
