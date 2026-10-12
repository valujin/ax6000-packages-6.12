"""Pinned stock ARTIFACT limit, native check-size boundaries and cached JSON semantics."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from test_source_layouts_612 import ROOT, firmware


TARGET = 'target/linux/mediatek/image/filogic.mk'
DEVICE = 'xiaomi_redmi-router-ax6000-stock'
LIMIT = 30*1024*1024


def fixture(name):
    return gzip.decompress((ROOT/'tests/fixtures'/('ax6000-612-'+name+'.gz')).read_bytes()).decode()


class StockFactory612Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def test_both_pins_change_only_stock_artifact_and_refuse_source_drift(self):
        for channel in ('recommended','latest'):
            directory=ROOT/'patches/firmware-6.12'/channel
            manifest=json.loads((directory/'manifest.json').read_text())
            spec=next((p for p in manifest['patches'] if p['path']==TARGET),None)
            self.assertIsNotNone(spec)
            original=fixture(channel+'-filogic.mk')
            self.assertEqual(hashlib.sha256(original.encode()).hexdigest(),spec['before_sha256'])
            target=self.root/TARGET;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(original)
            firmware.apply_source_patch(self.root,spec,directory/spec['patch'])
            start=original.index('define Device/'+DEVICE+'\n');end=original.index('\nendef',start)
            stock=original[start:end]
            expected_stock=stock.replace('| ubinize-kernel\n','| ubinize-kernel | check-size 30720k\n')
            self.assertNotEqual(stock,expected_stock)
            self.assertEqual(target.read_text(),original[:start]+expected_stock+original[end:])
            firmware.apply_source_patch(self.root,spec,directory/spec['patch'],check_only=True)
            firmware.apply_source_patch(self.root,spec,directory/spec['patch'])
            target.write_text(target.read_text()+'# drift\n')
            with self.assertRaises(ValueError): firmware.apply_source_patch(self.root,spec,directory/spec['patch'])

    def test_native_check_size_boundary_and_missing_artifact_skips_json(self):
        commands=fixture('include-image-commands.mk');image=fixture('include-image.mk')
        check=re.search(r'^define Build/check-size\n.*?^endef$',commands,re.M|re.S)[0]
        exp=next(line for line in image.splitlines() if line.startswith('exp_units ='))
        makefile=self.root/'limit.mk';artifact=self.root/'factory.ubi'
        makefile.write_text(exp+'\nERROR_MESSAGE = echo "$(1)" >&2\n'+check+'\n'+str(artifact)+': FORCE\n\t$(call Build/check-size,30720k)\nFORCE:\n')
        for size in (LIMIT-1,LIMIT,LIMIT+1):
            with artifact.open('wb') as output: output.truncate(size)
            subprocess.run(['make','--no-print-directory','-f',str(makefile)],cwd=self.root,
                           check=True,capture_output=True,timeout=5)
            self.assertEqual(artifact.exists(),size<=LIMIT)
        script=self.root/'add-info.py';script.write_text(fixture('scripts-json_add_image_info.py'))
        output=self.root/'factory.json'
        subprocess.run(['python3',str(script),str(output)],env={**os.environ,'FILE_DIR':str(self.root),'FILE_NAME':artifact.name},
                       check=True,capture_output=True,timeout=5)
        self.assertFalse(output.exists())

    def test_cached_bin_and_profiles_require_explicit_reset_before_safe_resume(self):
        # Native ignored cp leaves an earlier BIN file after check-size deletes
        # its tmp input. This proves why the controlled migration must remove it.
        stale=self.root/'stale-factory.ubi';stale.write_bytes(b'old unsafe artifact')
        missing=self.root/'removed-tmp-factory.ubi';makefile=self.root/'copy.mk'
        makefile.write_text('.IGNORE: '+str(stale)+'\n'+str(stale)+': FORCE\n\tcp '+str(missing)+' $@\nFORCE:\n')
        subprocess.run(['make','--no-print-directory','-f',str(makefile)],check=True,capture_output=True,timeout=5)
        self.assertEqual(stale.read_bytes(),b'old unsafe artifact')
        stale.unlink()
        work=self.root/'json';work.mkdir();tools=self.root/'tools';tools.mkdir()
        native_make=tools/'make';native_make.write_text('#!/bin/sh\nprintf "opkg\\naarch64_cortex-a53\\n6.12.108\\n1\\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n"\n');native_make.chmod(0o755)
        script=self.root/'overview.py';script.write_text(fixture('scripts-json_overview_image_info.py'))
        output=self.root/'profiles.json'
        record={'version_code':'r1-ae65e1de69','profiles':{DEVICE:{'images':[{'name':'stock-sysupgrade.bin'}]}}}
        previous=json.loads(json.dumps(record));previous['profiles'][DEVICE]['images'].append({'name':'old-unsafe-factory.ubi'})
        output.write_text(json.dumps(previous));(work/'sysupgrade.json').write_text(json.dumps(record))
        env={**os.environ,'WORK_DIR':str(work),'PATH':str(tools)+os.pathsep+os.environ['PATH']}
        subprocess.run(['python3',str(script),str(output)],env=env,check=True,capture_output=True,timeout=5)
        self.assertIn('old-unsafe-factory.ubi',{r['name'] for r in json.loads(output.read_text())['profiles'][DEVICE]['images']})
        output.unlink()
        subprocess.run(['python3',str(script),str(output)],env=env,check=True,capture_output=True,timeout=5)
        self.assertEqual(json.loads(output.read_text())['profiles'][DEVICE]['images'],[{'name':'stock-sysupgrade.bin'}])


if __name__=='__main__':unittest.main()
