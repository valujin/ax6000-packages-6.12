"""Real pinned OpenWrt bundler fixtures; imported contexts are checked statically."""
import copy
import gzip
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('host_apk_bundle_test_helper', ROOT / 'scripts/host_apk_bundle.py')
bundle = importlib.util.module_from_spec(spec); spec.loader.exec_module(bundle)


class RealPortableApkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        apk = os.environ.get('APK')
        if not apk or not shutil.which('strip') or not shutil.which('cc'):
            raise unittest.SkipTest('Trusted host APK, GNU strip and host compiler are required')
        cls.tmp = tempfile.TemporaryDirectory(prefix='actual-apk-bundle-'); cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name); cls.native = Path(apk).resolve()
        cls.bundler = cls.root / 'bundle-libraries.sh'
        cls.bundler.write_bytes(gzip.decompress((ROOT / 'tests/fixtures/sdk-bundle-libraries.sh.gz').read_bytes()))
        cls.sdk = cls.root / 'sdk'; cls.entry = cls.sdk / bundle.ENTRY
        cls.entry.parent.mkdir(parents=True); shutil.copy2(cls.native, cls.entry)
        subprocess.run(['bash', str(cls.bundler), str(cls.sdk / 'staging_dir/host'), str(cls.entry)],
                       check=True, capture_output=True)
        strip_files = [cls.sdk / bundle.HIDDEN] + [path for path in (cls.sdk / bundle.LIBRARY_ROOT).rglob('*')
            if path.is_file() and not path.is_symlink() and bundle.is_bundle_path(path.relative_to(cls.sdk).as_posix())]
        subprocess.run(['strip', *map(str, strip_files)], check=True, capture_output=True)
        cls.proof = bundle.describe(cls.sdk, cls.native, cls.bundler)
        cls.records = bundle.records_from_tree(cls.sdk); cls.wrapper = cls.entry.read_bytes()

    def test_real_sdk_bundle_and_streaming_context_verify(self):
        self.assertEqual(self.proof['kind'], 'openwrt-bundle-v1')
        self.assertEqual(bundle.verify(self.sdk, self.proof), self.entry)
        self.assertEqual(bundle.verify_records(self.proof, self.records, self.wrapper), bundle.ENTRY)
        self.assertEqual(self.proof['native_source']['sha256'], hashlib.sha256(self.native.read_bytes()).hexdigest())
        self.assertEqual(self.proof['source_transform']['result_sha256'], self.records[bundle.HIDDEN]['sha256'])

    def test_real_direct_host_elf_remains_a_separate_supported_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); entry = root / bundle.ENTRY; entry.parent.mkdir(parents=True)
            shutil.copy2(self.native, entry)
            proof = bundle.describe(root, self.native, self.bundler)
            self.assertEqual(proof['kind'], 'native-elf-v1')
            self.assertEqual(bundle.verify(root, proof), entry)

    def test_script_with_updated_self_consistent_hash_is_never_accepted(self):
        proof = copy.deepcopy(self.proof); records = copy.deepcopy(self.records)
        malicious = self.wrapper + b'touch /tmp/SHOULD-NEVER-RUN\n'
        entry = records[bundle.ENTRY]
        entry.update(size=len(malicious), sha256=hashlib.sha256(malicious).hexdigest(), header=malicious[:64].hex())
        proof.update(size=entry['size'], sha256=entry['sha256'])
        proof['files'] = [dict(path=name, **value) for name, value in sorted(records.items())]
        with self.assertRaisesRegex(ValueError, 'exact reviewed bundler template'):
            bundle.verify_records(proof, records, malicious)

    def test_modified_library_or_new_loader_candidate_is_rejected(self):
        records = copy.deepcopy(self.records)
        records[bundle.LIBRARY_ROOT + '/runas.so']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'hash'): bundle.verify_records(self.proof, records, self.wrapper)
        records = copy.deepcopy(self.records)
        records[bundle.LIBRARY_ROOT + '/new.so'] = copy.deepcopy(records[bundle.LIBRARY_ROOT + '/runas.so'])
        with self.assertRaisesRegex(ValueError, 'member set'): bundle.verify_records(self.proof, records, self.wrapper)

    def test_absolute_or_cyclic_links_cannot_hide_in_a_bound_inventory(self):
        for aliases in ({bundle.USR_LIB: '/outside'},
                        {bundle.LIBRARY_ROOT + '/a.so': 'b.so', bundle.LIBRARY_ROOT + '/b.so': 'a.so'}):
            records = copy.deepcopy(self.records); proof = copy.deepcopy(self.proof)
            for name, target in aliases.items(): records[name] = {'type': 'symlink', 'mode': 0o777, 'target': target}
            proof['files'] = [dict(path=name, **value) for name, value in sorted(records.items())]
            with self.subTest(aliases=aliases), self.assertRaises(ValueError):
                bundle.verify_records(proof, records, self.wrapper)

    def test_target_architecture_and_unreviewed_bundler_are_rejected(self):
        records = copy.deepcopy(self.records); proof = copy.deepcopy(self.proof)
        header = bytearray.fromhex(records[bundle.HIDDEN]['header'])
        header[18:20] = (183 if self.proof['native_source']['machine'] == 62 else 62).to_bytes(2, 'little')
        records[bundle.HIDDEN]['header'] = header.hex()
        proof['files'] = [dict(path=name, **value) for name, value in sorted(records.items())]
        with self.assertRaisesRegex(ValueError, 'architecture'): bundle.verify_records(proof, records, self.wrapper)
        proof = copy.deepcopy(self.proof); proof['bundler_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'reviewed format'): bundle.verify_records(proof, self.records, self.wrapper)


if __name__ == '__main__': unittest.main()
