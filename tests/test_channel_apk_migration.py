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
        snapshot.validate_generation_replacement(old or self.old,new or self.new,self.old['build_id'],
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

    def reviewed_v2(self):
        self.old['build_id']='redmi-ax6000-612-recommended-ae65e1de6997-6ef19743b104'
        self.old['firmware'].update(commit='ae65e1de69971b5a2e3cf7e39390ee93f274d488',
                                    kernel_version='6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1')
        self.new['firmware']=copy.deepcopy(self.old['firmware'])
        proof=copy.deepcopy(self.proof)
        proof.update(schema_version=2,cohort='612-recommended',predecessor_build_id=self.old['build_id'],
                     source_commit=self.old['firmware']['commit'],kernel_version=self.old['firmware']['kernel_version'],
                     functional_image={'before':{'size':14661640,'sha256':'ac19e2c554e40219aed043a0760aef2a609743ec0437d295c4f7f15f51886d8f'},
                                       'after':{'size':14661640,'sha256':'5a0eedece2116a8dd046bd8337b487bdfc6913eaf1465d3dc6b711d0851ad611'}},
                     reviewed_transition={'kind':'rec-gnu-build-id-notes-v1',
                         'original_context_sha256':'cddaaf6593c873326894003a3695b1083435447ba49556c744b0b0fd995fd87c',
                         'accepted_context_sha256':'2d7dbf000444728dedd334a432445cf8aece08b2944e6d28e172d823490f8d15',
                         'enrollment_sha256':'c0b5ac9ba485f617662221dec2e9829772c4602f9091e0cda4297071d493cdea',
                         'transition_proof_sha256':'5f958f7cb6569f34ef3f02602c86e00c918ed8b53db1f80800d8e4d17b68a01a'},
                     firmware_manifest_sha256={'before':'ddadceae113c0e353c53272c188c2888c34d4127e987434be1a938518989f38e','after':'6'*64})
        identities={'.config':(216405,'f245fc96a9db54159662d86f32e57e86a07106bd029719ad5bdb7af6581e552e'),
                    'Module.symvers':(889880,'405d5e270cb79b7e3acd8d8a0ec8b2c593f86d0a37342e3311a0e0f7ed8dcd41'),
                    '.vermagic':(33,'555c28901ca8ca4023945b27b62b924fdbb3a2fc951bb234cca9b8ab8b61ec0b'),
                    'include/config/kernel.release':(9,'70ab81f7d2e0021fb2fca26461be33b18a0dc73828a383953ef5693f222b36ed')}
        proof['kernel_context']={name:{phase:{'size':size,'sha256':sha} for phase in ('before','after')}
                                 for name,(size,sha) in identities.items()}
        return proof

    def test_reviewed_v2_accepts_only_the_specific_enrolled_rec_image_pair(self):
        self.validate(proof=self.reviewed_v2())

    def test_v2_rejects_unknown_images_context_enrollment_source_and_cohort(self):
        proof=self.reviewed_v2()
        for mutate in (lambda p:p['functional_image']['after'].update(sha256='f'*64),
                       lambda p:p['functional_image']['before'].update(size=1),
                       lambda p:p['kernel_context'].pop('.vermagic'),
                       lambda p:p['kernel_context']['.config']['after'].update(sha256='f'*64),
                       lambda p:p['reviewed_transition'].update(enrollment_sha256='f'*64),
                       lambda p:p['reviewed_transition'].update(masked_ranges=[]),
                       lambda p:p.update(cohort='612-latest'),
                       lambda p:p.update(source_commit='f'*40),
                       lambda p:p['firmware_manifest_sha256'].update(before='not-a-sha256'),
                       lambda p:p.update(schema_version=2.0)):
            candidate=copy.deepcopy(proof);mutate(candidate)
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):self.validate(proof=candidate)


if __name__=='__main__':unittest.main()
