"""Compile every pinned MP ioctl self-append branch and check formatting independently."""
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from test_source_layouts_612 import ROOT, firmware


DRIVER_SHA = '46831640d2365a5fe0ddf4403aee3abf3063c1bd24b90a649c35ff3d40e47495'
TARGET = 'package/kernel/rtl8812au-ct/patches/120-fix-mp-ioctl-sprintf-self-append.patch'
OVERLAP = re.compile(r'sprintf\(\s*extra\s*,\s*"%s((?:[^"\\]|\\.)*)"\s*,\s*extra\s*(,.*?)?\);')
FORMATS = {' ', ' %02X', ' %d', ' %d ', ' 0x%02X ', ' 0x%x ', ' \\t', '%02X', '%02X ',
           ',', '0x%02X', '0x%02X ', '0x%02x\\t', '0x%03x\\t', ':', '\\n', '\\t'}


class Rtl8812au612Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.original = gzip.decompress((ROOT/'tests/fixtures/rtl8812au-9b2b203a-ioctl-linux.gz').read_bytes())
        self.assertEqual(hashlib.sha256(self.original).hexdigest(), DRIVER_SHA)
        self.calls = list(OVERLAP.finditer(self.original.decode()))
        self.assertEqual(len(self.calls), 54)
        self.assertEqual({m[1] for m in self.calls}, FORMATS)

    def patched(self, channel):
        directory = ROOT/'patches/firmware-6.12'/channel
        manifest = json.loads((directory/'manifest.json').read_text())
        spec = next((p for p in manifest['patches'] if p['path']==TARGET), None)
        self.assertIsNotNone(spec, 'both pinned sources require the new driver package patch')
        self.assertEqual(spec['operation'], 'add'); self.assertIsNone(spec['before_sha256'])
        firmware.apply_source_patch(self.work, spec, directory/spec['patch'])
        firmware.apply_source_patch(self.work, spec, directory/spec['patch'], check_only=True)
        driver = self.work/'os_dep/linux/ioctl_linux.c'; driver.parent.mkdir(parents=True, exist_ok=True)
        driver.write_bytes(self.original)
        subprocess.run(['git','apply','--check',str(self.work/TARGET)],cwd=self.work,check=True,capture_output=True)
        subprocess.run(['git','apply',str(self.work/TARGET)],cwd=self.work,check=True,capture_output=True)
        return driver.read_text(), spec, directory

    def test_both_pins_only_true_overlap_calls_change_and_hash_guards(self):
        for channel in ('recommended','latest'):
            with self.subTest(channel=channel):
                updated, spec, directory = self.patched(channel)
                expected = OVERLAP.sub(lambda m: 'sprintf(extra + strlen(extra), "'+m[1]+'"'+(m[2] or '')+');',self.original.decode())
                self.assertEqual(updated, expected)
                self.assertFalse(OVERLAP.search(updated))
                driver = self.work/'os_dep/linux/ioctl_linux.c'
                drift = self.original.decode().replace(self.calls[0][0], 'sprintf(extra, "upstream drift");', 1)
                driver.write_text(drift)
                rejected = subprocess.run(['git','apply','--check',str(self.work/TARGET)],cwd=self.work,
                                          capture_output=True,timeout=5)
                self.assertNotEqual(rejected.returncode,0)
                self.assertEqual(driver.read_text(),drift)
                target = self.work/TARGET; target.write_bytes(target.read_bytes()+b'# drift\n')
                before = target.read_bytes()
                with self.assertRaises(ValueError):
                    firmware.apply_source_patch(self.work, spec, directory/spec['patch'])
                self.assertEqual(target.read_bytes(), before)
                target.unlink()
                bad = self.work/'corrupt-outer.patch'; bad.write_bytes((directory/spec['patch']).read_bytes()+b'# drift\n')
                with self.assertRaises(ValueError):
                    firmware.apply_source_patch(self.work, spec, bad)
                self.assertFalse(target.exists())

    @unittest.skipUnless(shutil.which('cc'), 'C compiler required')
    def test_all_54_calls_compile_with_restrict_errors_and_preserve_formatted_outputs(self):
        updated, _, _ = self.patched('recommended')
        statements = re.findall(r'sprintf\(extra \+ strlen\(extra\), "(?:[^"\\]|\\.)*".*?\);', updated)
        self.assertEqual(len(statements), 54)
        declarations = '''
#include <stdio.h>
#include <string.h>
static unsigned char PROMContent[600], data[600], rawdata[600];
static struct { unsigned char BTEfuseInitMap[600], fakeBTEfuseModifiedMap[600],
 fakeEfuseInitMap[600], fakeEfuseModifiedMap[600]; } hal, *pEfuseHal=&hal;
static struct { unsigned char mptOutBuf[600]; } ctx, *pMptCtx=&ctx;
static int i, j=2, addr=3, strtout, strtou;
'''
        def harness(calls):
            functions = ''.join('static void call_'+str(n)+'(char *extra) { '+s+' }\n' for n,s in enumerate(calls))
            body = '''int main(void) {
 for (int k=0; k<600; k++) {
  unsigned char byte=(k*17+11)&255;
  PROMContent[k]=data[k]=rawdata[k]=hal.BTEfuseInitMap[k]=hal.fakeBTEfuseModifiedMap[k]=
   hal.fakeEfuseInitMap[k]=hal.fakeEfuseModifiedMap[k]=ctx.mptOutBuf[k]=byte;
 }
 const int seeds[]={0,15,127,255};
 for (unsigned int seed=0; seed<4; seed++) {
  i=seeds[seed]; strtout=strtou=i;
  for (int prefix=0; prefix<2; prefix++) {
'''
            body += ''.join('{ char extra[128]; strcpy(extra,prefix ? "header:" : ""); call_'+str(n)+'(extra); printf("%zu:",strlen(extra)); for (size_t k=0; k<strlen(extra); k++) printf("%02x",(unsigned char)extra[k]); puts(""); }\n' for n in range(len(calls)))
            return declarations+functions+body+'} } return 0; }\n'
        def compile_text(text, name):
            source = self.work/(name+'.c'); source.write_text(text)
            return subprocess.run(['cc','-O2','-Wrestrict','-Werror=restrict',str(source),'-o',str(self.work/name)],
                                  capture_output=True,text=True,timeout=15)
        old = compile_text(harness([m[0] for m in self.calls]),'old')
        self.assertNotEqual(old.returncode,0); self.assertIn('restrict',old.stderr)
        new = compile_text(harness(statements),'new')
        self.assertEqual(new.returncode,0,new.stderr)
        actual = subprocess.check_output([str(self.work/'new')],text=True,timeout=5).splitlines()
        expected = []
        for seed in (0,15,127,255):
            # Independent reference: concatenate prefix with a separately formatted
            # suffix; never run or depend on the original undefined-overlap behavior.
            byte = lambda index: (index*17+11)&255
            values = {'i':seed,'i+1':seed+1,'strtout':seed,'strtou':seed,
                      'PROMContent[i+j]':byte(seed+2),'data[i]':byte(seed),'rawdata[i]':byte(seed),
                      'pMptCtx->mptOutBuf[i]':byte(seed),
                      '(pMptCtx->mptOutBuf[i]& 0x3f)':byte(seed)&0x3f,
                      '(pMptCtx->mptOutBuf[i]& 0x1f)':byte(seed)&0x1f}
            for field in ('BTEfuseInitMap','fakeBTEfuseModifiedMap','fakeEfuseInitMap','fakeEfuseModifiedMap'):
                values['pEfuseHal->'+field+'[i+j]'] = byte(seed+2)
                values['pEfuseHal->'+field+'[addr+i]'] = byte(seed+3)
            for prefix in ('','header:'):
                for call in self.calls:
                    fmt = json.loads('"'+call[1]+'"')
                    argument = (call[2] or '').lstrip(', ').strip()
                    result = (prefix+(fmt % values[argument] if argument else fmt)).encode()
                    expected.append(str(len(result))+':'+result.hex())
        self.assertEqual(actual,expected)


if __name__ == '__main__': unittest.main()
