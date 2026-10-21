"""Explicit new-firmware authorization, independently of actual build acceptance."""
import copy
import hashlib
from pathlib import Path
import unittest

import test_channel_snapshot as fixtures

snapshot = fixtures.snapshot


class APKMigrationAuthorization(unittest.TestCase):
    def setUp(self):
        commit='a'*40
        self.old={'schema_version':1,'id':'redmi-ax6000-612-recommended','channel':'recommended',
                  'build_id':'old-build','sdk':{'url':'https://fixture.invalid/old.tar.zst','sha256':'1'*64},
                  'firmware':{'commit':commit,'kernel_version':'6.12.108~'+'a'*32+'-r1',
                              'architecture':'aarch64_cortex-a53','devices':['stock','mtkuboot','ubootmod']},
                  'publication':{'repository':'valujin/ax6000-packages-6.12'},
                  'packages':['tailscale','pbr','luci-app-pbr'],
                  'image_packages':['pbr','luci-app-pbr'],'package_only':['tailscale']}
        self.new=copy.deepcopy(self.old)
        self.new.update(build_id='new-build',sdk={'url':'https://fixture.invalid/new.tar.zst','sha256':'2'*64},
                        package_manager='apk',apk_key_sha256=snapshot.sha256_file(snapshot.ROOT/'keys/repository-apk.pem'),
                        pbr_source='mossdef-stable',vendor_country_db=True,
                        asu={'enabled':True,'cohort':'612-recommended','server_url':'https://asu.ezon.by/612/recommended','seed':'3'*64},
                        imagebuilder={'url':'https://github.com/valujin/ax6000-packages-6.12/releases/download/firmware-new-build/imagebuilder.tar.zst',
                                      'size':123,'sha256':'4'*64})
        for field in ('packages','image_packages'):
            self.new[field]+=list(snapshot.module('asu_client').REQUIRED_PACKAGES)
        self.proof={'schema_version':1,'kind':'asu-apk-native-migration','predecessor_build_id':'old-build',
                    'successor_build_id':'new-build','source_commit':commit,
                    'kernel_version':self.old['firmware']['kernel_version'],
                    'kernel_context':{name:{'before':{'size':10,'sha256':'5'*64},'after':{'size':10,'sha256':'5'*64}}
                                      for name in ('.config','Module.symvers','arch/arm64/boot/Image')},
                    'source_patches':{'before':[],'after':[]}}

    def validate(self,old=None,new=None,proof=None):
        snapshot.validate_generation_replacement(old or self.old,new or self.new,'old-build',
                                                allow_asu_apk_migration=True,migration_proof=proof or self.proof)

    def test_exact_additive_transition_requires_both_manual_flag_and_comparison(self):
        self.validate()
        with self.assertRaises(ValueError):
            snapshot.validate_generation_replacement(self.old,self.new,'old-build')
        with self.assertRaisesRegex(ValueError,'native migration proof'):
            snapshot.validate_generation_replacement(self.old,self.new,'old-build',allow_asu_apk_migration=True)

    def test_source_kernel_layout_or_unreviewed_package_changes_stay_forbidden(self):
        for mutate in (lambda p:p['firmware'].update(commit='b'*40),
                       lambda p:p['firmware'].update(kernel_version='foreign'),
                       lambda p:p['firmware'].update(architecture='foreign'),
                       lambda p:p['firmware']['devices'].pop(),
                       lambda p:p['packages'].append('extra-package'),
                       lambda p:p['image_packages'].append('tailscale'),
                       lambda p:p.update(pbr_source='unreviewed'),
                       lambda p:p.update(vendor_country_db=False),
                       lambda p:p['asu'].update(server_url='https://foreign.invalid')):
            candidate=copy.deepcopy(self.new);mutate(candidate)
            with self.assertRaises(ValueError):self.validate(new=candidate)

    def test_missing_different_or_foreign_native_byte_receipt_stays_forbidden(self):
        for mutate in (lambda p:p.update(predecessor_build_id='foreign'),
                       lambda p:p.update(successor_build_id='foreign'),
                       lambda p:p.update(source_commit='b'*40),
                       lambda p:p['kernel_context'].pop('Module.symvers'),
                       lambda p:p['kernel_context']['arch/arm64/boot/Image']['after'].update(sha256='6'*64),
                       lambda p:p['source_patches']['after'].append({'patch':'new'})):
            candidate=copy.deepcopy(self.proof);mutate(candidate)
            with self.assertRaises(ValueError):self.validate(proof=candidate)


if __name__=='__main__':unittest.main()
