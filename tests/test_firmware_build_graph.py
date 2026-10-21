"""Run the real shell entry against a small native Make dependency graph.

The foreign kernel prerequisite models include/image.mk's CONFIG_IB branch:
an unselected device has no per-device rootfs, but CONFIG_IB=y still requests
its rootfs-dependent FIT kernel. No firmware, downloads or SDK compilation run.
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
LAYOUTS = ('stock', 'mtkuboot', 'ubootmod')

MAKEFILE = r'''include .config
OUT := bin/targets/mediatek/filogic
LAYOUTS := stock mtkuboot ubootmod
.PHONY: defconfig world install target/imagebuilder/compile
defconfig:
	@:
world:
	@$(MAKE) install
	@printf 'SDK\n' > $(OUT)/fixture-sdk.tar.zst
install: $(addprefix $(OUT)/,$(addsuffix -sysupgrade.bin,$(LAYOUTS))) $(OUT)/stock-initramfs-factory.ubi
ifdef CONFIG_IB
install: foreign-kernel
endif
foreign-kernel:
	@echo 'unselected netgear_eax17 requires missing root.squashfs+pkg=' >&2
	@test -f root.squashfs+pkg=
$(OUT)/%-sysupgrade.bin:
	@mkdir -p $(OUT); printf '%s\n' '$*' > $@
$(OUT)/stock-initramfs-factory.ubi:
	@mkdir -p $(OUT); printf 'factory\n' > $@
target/imagebuilder/compile:
	@mkdir -p $(OUT)
	@case "$$IB_ARTIFACT_KIND" in \
	  missing) rm -f $(OUT)/*imagebuilder* ;; \
	  ambiguous) printf 'IB\n' > $(OUT)/fixture-imagebuilder.tar.zst; printf 'other\n' > $(OUT)/other-imagebuilder.tar.zst ;; \
	  symlink) rm -f $(OUT)/fixture-imagebuilder.tar.zst; ln -s fixture-sdk.tar.zst $(OUT)/fixture-imagebuilder.tar.zst ;; \
	  directory) rm -f $(OUT)/fixture-imagebuilder.tar.zst; mkdir $(OUT)/fixture-imagebuilder.tar.zst ;; \
	  *) printf 'fresh IB\n' > $(OUT)/fixture-imagebuilder.tar.zst ;; \
	esac
'''

# Replace only the preparation boundary: source selection, real Git operations,
# Make recursion, shell failure propagation and archive checks remain real.
PREPARE = r'''import os, pathlib, shutil, sys
phase = sys.argv[sys.argv.index('--phase') + 1]
if phase == 'export':
    source = pathlib.Path(sys.argv[sys.argv.index('--source-dir') + 1])
    output = pathlib.Path(sys.argv[sys.argv.index('--output-dir') + 1])
    shutil.copytree(source / 'bin', output / 'bin')
'''


class NativeBuildGraphTest(unittest.TestCase):
    def fixture(self, resume=False, ib=True, stale=False, kind='regular'):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        seed = root / 'seed'
        seed.mkdir()
        (seed / 'Makefile').write_text(MAKEFILE)
        (seed / '.config').write_text('CONFIG_IB=y\n' if ib else '# CONFIG_IB is not set\n')
        (seed / 'target/imagebuilder').mkdir(parents=True)
        (seed / 'target/imagebuilder/Makefile').write_text('# packaging target fixture\n')
        (seed / 'scripts').mkdir()
        feeds = seed / 'scripts/feeds'
        feeds.write_text('#!/bin/sh\nexit 0\n')
        feeds.chmod(0o755)
        if stale:
            target = seed / 'bin/targets/mediatek/filogic'
            target.mkdir(parents=True)
            (target / 'fixture-imagebuilder.tar.zst').write_bytes(b'stale IB\n')
        for args in [('init', '-q', str(seed)), ('-C', str(seed), 'add', '.'),
                     ('-C', str(seed), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'local native graph fixture')]:
            subprocess.run(['git', *args], check=True, capture_output=True)
        commit = subprocess.check_output(['git', '-C', str(seed), 'rev-parse', 'HEAD'], text=True).strip()
        profile = root / 'profile.json'
        profile.write_text(json.dumps({'firmware': {'repository': str(seed), 'commit': commit}}))
        lock = root / 'lock.json'
        lock.write_text('{}')
        work = root / 'work'
        work.mkdir()
        if resume:
            subprocess.run(['git', 'clone', '-q', str(seed), str(work / 'source')], check=True,
                           capture_output=True)
            (work / 'prepared-inputs.json').write_text(json.dumps({
                'profile_sha256': hashlib.sha256(profile.read_bytes()).hexdigest(),
                'lock_sha256': hashlib.sha256(lock.read_bytes()).hexdigest()}))
        runner = root / 'runner'
        runner.mkdir()
        shutil.copyfile(ROOT / 'scripts/build-firmware.sh', runner / 'build-firmware.sh')
        (runner / 'prepare-firmware.py').write_text(PREPARE)
        env = {**os.environ, 'AX6000_LIMITED_FIRMWARE_BUILD': '1', 'BUILD_JOBS': '1',
               'AX6000_BUILD_LOCK': str(root / 'fixture.lock'), 'IB_ARTIFACT_KIND': kind}
        args = ['bash', str(runner / 'build-firmware.sh'), '--profile', str(profile), '--lock', str(lock),
                '--work-dir', str(work), '--output-dir', str(root / 'output'), '--min-free-gib', '1']
        args += ['--resume'] if resume else ['--source-tree', str(seed)]
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)
        return result, root

    def assert_exports(self, result, root, ib=True):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = root / 'output/bin/targets/mediatek/filogic'
        for layout in LAYOUTS:
            self.assertEqual((output / (layout + '-sysupgrade.bin')).read_text(), layout + '\n')
        self.assertEqual((output / 'stock-initramfs-factory.ubi').read_text(), 'factory\n')
        self.assertEqual((output / 'fixture-sdk.tar.zst').read_text(), 'SDK\n')
        if ib:
            self.assertEqual((output / 'fixture-imagebuilder.tar.zst').read_text(), 'fresh IB\n')
        else:
            self.assertFalse(list(output.glob('*imagebuilder*')))
        expected_config = 'CONFIG_IB=y\n' if ib else '# CONFIG_IB is not set\n'
        self.assertEqual((root / 'work/source/.config').read_text(), expected_config)
        self.assertFalse((root / 'work/source/foreign-kernel').exists())

    def test_fresh_build_skips_foreign_kernel_and_exports_three_layouts_sdk_and_ib(self):
        self.assert_exports(*self.fixture())

    def test_resume_skips_foreign_kernel_and_exports_three_layouts_sdk_and_ib(self):
        self.assert_exports(*self.fixture(resume=True))

    def test_existing_imagebuilder_is_rebuilt_in_fresh_and_resume_paths(self):
        for resume in (False, True):
            with self.subTest(resume=resume):
                self.assert_exports(*self.fixture(resume=resume, stale=True))

    def test_disabled_imagebuilder_stays_disabled(self):
        self.assert_exports(*self.fixture(ib=False), ib=False)

    def test_missing_ambiguous_symlink_and_directory_archives_refuse_export(self):
        for kind in ('missing', 'ambiguous', 'symlink', 'directory'):
            with self.subTest(kind=kind):
                result, root = self.fixture(kind=kind)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('ImageBuilder archive', result.stderr)
                self.assertFalse((root / 'output').exists())


if __name__ == '__main__':
    unittest.main()
