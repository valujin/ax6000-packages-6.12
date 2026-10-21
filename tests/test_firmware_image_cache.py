"""A resume must remove stale stock factory/catalog files before rebuilding."""
import importlib.util
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
from unittest import mock
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('image_cache_prepare', ROOT / 'scripts/prepare-firmware.py')
firmware = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(firmware)


class ImageCacheReset(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.profile = json.loads((ROOT / 'tests/fixtures/legacy612-recommended-source-profile.json').read_text())
        self.receipt = self.root / 'cleanup.json'
        self.git_patch = mock.patch.object(firmware.subprocess, 'check_output', return_value=self.profile['firmware']['commit']+'\n')
        self.git = self.git_patch.start(); self.addCleanup(self.git_patch.stop)
        name = 'immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-stock-initramfs-factory.ubi'
        build = Path('build_dir/target-aarch64_cortex-a53_musl')
        self.paths = [Path('bin/targets/mediatek/filogic') / name,
                      build / 'linux-mediatek_filogic/tmp' / name,
                      build / 'json_info_files' / (name + '.json'),
                      Path('bin/targets/mediatek/filogic/profiles.json')]
        for path in self.paths:
            target = self.source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'stale')
        (self.source / '.config').write_bytes(b'CONFIG_FIXED=y\n')
        self.other = self.source / 'bin/targets/mediatek/filogic/other-factory.ubi'
        self.other.write_bytes(b'other')

    def test_only_exact_stock_cache_removed_and_receipt_is_idempotent(self):
        firmware.reset_cached_images(self.profile, self.source, self.receipt)
        self.assertTrue(all(not (self.source / p).exists() for p in self.paths))
        self.assertEqual(self.other.read_bytes(), b'other')
        self.assertEqual((self.source / '.config').read_bytes(), b'CONFIG_FIXED=y\n')
        report = json.loads(self.receipt.read_text())
        self.assertEqual(set(report['files']), {p.as_posix() for p in self.paths})
        self.assertTrue(all(record['size'] == 5 for record in report['files'].values()))
        first = self.receipt.read_bytes()
        firmware.reset_cached_images(self.profile, self.source, self.receipt)
        self.assertEqual(self.receipt.read_bytes(), first)

    def test_real_cli_phase_accepts_external_receipt_and_removes_only_stock_cache(self):
        lock=self.root/'lock.json';lock.write_text('{}')
        tools=self.root/'tools';tools.mkdir()
        git=tools/'git';git.write_text('#!/bin/sh\nprintf "%s\\n" "'+self.profile['firmware']['commit']+'"\n');git.chmod(0o755)
        subprocess.run([sys.executable, str(ROOT / 'scripts/prepare-firmware.py'),
                        '--profile', str(ROOT / 'tests/fixtures/legacy612-recommended-source-profile.json'),
                        '--lock', str(lock),
                        '--source-dir', str(self.source), '--phase', 'reset-cached-images',
                        '--cleanup-receipt', str(self.receipt)], check=True, capture_output=True,
                        env={**os.environ,'PATH':str(tools)+os.pathsep+os.environ['PATH']})
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(all(not (self.source / p).exists() for p in self.paths))
        self.assertEqual(self.other.read_bytes(), b'other')

    def test_symlink_target_or_parent_refused_before_any_deletion(self):
        target = self.source / self.paths[2]
        target.unlink()
        target.symlink_to(self.other)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            firmware.reset_cached_images(self.profile, self.source, self.receipt)
        self.assertTrue((self.source / self.paths[0]).exists())
        self.assertFalse(self.receipt.exists())
        target.unlink()
        target.parent.rename(target.parent.with_name('actual-json'))
        target.parent.symlink_to(target.parent.with_name('actual-json'), target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            firmware.reset_cached_images(self.profile, self.source, self.receipt)
        self.assertTrue((self.source / self.paths[0]).exists())

    def test_foreign_receipt_or_receipt_inside_source_refused_before_deletion(self):
        self.receipt.write_text('{"foreign":true}')
        with self.assertRaisesRegex(ValueError, 'receipt'):
            firmware.reset_cached_images(self.profile, self.source, self.receipt)
        with self.assertRaisesRegex(ValueError, 'outside'):
            firmware.reset_cached_images(self.profile, self.source, self.source / 'receipt.json')
        self.assertTrue(all((self.source / p).exists() for p in self.paths))

    def test_latest_channel_and_other_layout_kernel_files_are_preserved(self):
        self.profile=json.loads((ROOT/'tests/fixtures/legacy612-latest-source-profile.json').read_text())
        self.git.return_value=self.profile['firmware']['commit']+'\n'
        untouched=[self.other,self.source/'.config',
                   self.source/'bin/targets/mediatek/filogic/immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-mtkuboot-squashfs-factory.bin',
                   self.source/'build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/linux-6.12.112/.vermagic']
        for p in untouched[2:]: p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'fixed other layout/kernel')
        before={p:p.read_bytes() for p in untouched}
        report=firmware.reset_cached_images(self.profile,self.source,self.receipt)
        self.assertEqual(report['channel'],'latest');self.assertEqual(report['devices'],self.profile['firmware']['devices'])
        self.assertEqual(before,{p:p.read_bytes() for p in untouched})

    def test_wrong_profile_or_native_source_pin_refuses_before_deletion(self):
        for field,value in [('channel','foreign'),('enabled',False),('commit','a'*40),('architecture','wrong')]:
            changed=json.loads(json.dumps(self.profile))
            (changed if field in ('channel','enabled') else changed['firmware'])[field]=value
            with self.assertRaises(ValueError):firmware.reset_cached_images(changed,self.source,self.receipt)
        changed=json.loads(json.dumps(self.profile));changed['firmware']['devices'].pop()
        with self.assertRaises(ValueError):firmware.reset_cached_images(changed,self.source,self.receipt)
        self.git.return_value='f'*40+'\n'
        with self.assertRaisesRegex(ValueError,'HEAD'):firmware.reset_cached_images(self.profile,self.source,self.receipt)
        self.assertTrue(all((self.source/p).exists() for p in self.paths));self.assertFalse(self.receipt.exists())

    def test_size_receipt_reservation_and_existing_receipt_refuse_before_delete(self):
        last=self.source/self.paths[-1]
        with last.open('wb') as stream:stream.truncate(128*1024**2+1)
        with self.assertRaisesRegex(ValueError,'unexpected image'):firmware.reset_cached_images(self.profile,self.source,self.receipt)
        last.write_bytes(b'stale')
        original_open=Path.open
        def denied(path,*args,**kwargs):
            if path==self.receipt:raise PermissionError('fixture denied receipt write')
            return original_open(path,*args,**kwargs)
        with mock.patch.object(Path,'open',denied),self.assertRaises(PermissionError):
            firmware.reset_cached_images(self.profile,self.source,self.receipt)
        self.assertTrue(all((self.source/p).exists() for p in self.paths));self.assertFalse(self.receipt.exists())
        firmware.reset_cached_images(self.profile,self.source,self.receipt)
        restored=self.source/self.paths[0];restored.write_bytes(b'new artifact')
        with self.assertRaisesRegex(ValueError,'fresh receipt'):firmware.reset_cached_images(self.profile,self.source,self.receipt)
        self.assertEqual(restored.read_bytes(),b'new artifact')

    def test_actual_resume_shell_checks_verify_then_resets_before_world(self):
        runner=self.root/'runner';runner.mkdir()
        shutil.copyfile(ROOT/'scripts/build-firmware.sh',runner/'build-firmware.sh')
        log=self.root/'order.log'
        # Stub preparation/build operations; delegate cleanup to the actual CLI.
        # This executes production shell ordering without preparing or compiling.
        stub=runner/'prepare-firmware.py'
        stub.write_text('import os,sys,subprocess\nfrom pathlib import Path\n'
                        'phase=sys.argv[sys.argv.index("--phase")+1]\n'
                        'with Path(os.environ["FIXTURE_LOG"]).open("a") as f:f.write(phase+"\\n")\n'
                        'if phase=="reset-cached-images":\n'
                        ' subprocess.run([sys.executable,'+repr(str(ROOT/'scripts/prepare-firmware.py'))+']+sys.argv[1:],check=True)\n')
        profile=self.root/'profile.json';profile.write_text(json.dumps(self.profile))
        lock=self.root/'inputs.json';lock.write_text('{}')
        marker={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in
                [('profile_sha256',profile),('lock_sha256',lock)]}
        (self.root/'prepared-inputs.json').write_text(json.dumps(marker))
        tools=self.root/'tools';tools.mkdir()
        git=tools/'git';git.write_text('#!/bin/sh\nprintf "%s\\n" "'+self.profile['firmware']['commit']+'"\n');git.chmod(0o755)
        make=tools/'make';make.write_text('#!/bin/sh\nprintf "make:%s\\n" "$*" >> "$FIXTURE_LOG"\nif [ "$2" = world ]; then test ! -e "$FACTORY_PATH" || exit 9; fi\n');make.chmod(0o755)
        result=subprocess.run(['bash',str(runner/'build-firmware.sh'),'--profile',str(profile),'--lock',str(lock),
                               '--work-dir',str(self.root),'--output-dir',str(self.root/'output'),'--min-free-gib','1','--resume'],
                              env={**os.environ,'PATH':str(tools)+os.pathsep+os.environ['PATH'],
                                   'AX6000_LIMITED_FIRMWARE_BUILD':'1','BUILD_JOBS':'1',
                                   'AX6000_BUILD_LOCK':str(self.root/'global-lock'),
                                   'FIXTURE_LOG':str(log),'FACTORY_PATH':str(self.source/self.paths[0])},
                              capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        phases=log.read_text().splitlines()
        self.assertEqual(phases[-4:],['verify','reset-cached-images','make:-j1 world V=s','export'])
        receipts=list(self.root.glob('image-cache-reset.*/receipt.json'))
        self.assertEqual(len(receipts),1);self.assertFalse(receipts[0].is_relative_to(self.source))
        self.assertTrue(all(not (self.source/p).exists() for p in self.paths))


if __name__ == '__main__':
    unittest.main()
