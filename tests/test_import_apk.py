"""Package-manager and signing-key identity survive immutable RAW import."""
import json
import unittest

import test_import_612 as fixtures

release=fixtures.release


class APKImportIdentity(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.CohortImportTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.profile.update(package_manager='apk',apk_key_sha256='a'*64)
        expected=json.loads(self.fixture.expected.read_text())
        expected.update(package_manager='apk',apk_key_sha256='a'*64)
        self.fixture.expected.write_text(json.dumps(expected))
        self.fixture.manifest.update(package_manager='apk',apk_key_sha256='a'*64)
        self.write()

    def write(self):
        self.fixture.write_metadata()
        path=self.fixture.raw/'lock.json'
        lock=json.loads(path.read_text())
        lock.update(package_manager='apk',apk_key_sha256='a'*64)
        path.write_text(json.dumps(lock))

    def test_apk_profile_lock_manifest_and_expected_identity_agree(self):
        validated=release.validate_metadata(self.fixture.raw,self.fixture.expected)
        self.assertEqual(validated['profile']['package_manager'],'apk')

    def test_old_opkg_profile_cannot_authorize_new_apk_import(self):
        expected=json.loads(self.fixture.expected.read_text());expected.pop('package_manager')
        self.fixture.expected.write_text(json.dumps(expected))
        with self.assertRaisesRegex(ValueError,'package manager'):
            release.validate_metadata(self.fixture.raw,self.fixture.expected)

    def test_lock_or_manifest_cannot_drop_apk_identity_or_change_key(self):
        for name,field,value in [('lock.json','package_manager','opkg'),
                                 ('lock.json','apk_key_sha256','b'*64),
                                 ('firmware-manifest.json','package_manager','opkg'),
                                 ('firmware-manifest.json','apk_key_sha256','b'*64)]:
            with self.subTest(name=name,field=field):
                self.write();path=self.fixture.raw/name;metadata=json.loads(path.read_text())
                metadata[field]=value;path.write_text(json.dumps(metadata))
                with self.assertRaisesRegex(ValueError,'APK|package manager'):
                    release.validate_metadata(self.fixture.raw,self.fixture.expected)

    def test_apk_inventory_cannot_contain_even_self_consistent_ipk_archive(self):
        (self.fixture.target/'foreign.ipk').write_bytes(b'foreign package')
        self.write()
        with self.assertRaisesRegex(ValueError,'foreign IPK'):
            release.validate_metadata(self.fixture.raw,self.fixture.expected)


if __name__=='__main__':unittest.main()
