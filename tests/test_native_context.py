"""Synthetic guard fixtures only; no actual context/native acceptance is issued."""
import copy,hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
import test_native_generation as legacy

class NewContext(unittest.TestCase):
    helper=legacy.NativeProfiles.helper
    file=legacy.ActualFiles.file
    portable_fixture=legacy.ActualFiles.portable_fixture
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.n=self.helper()
    def typed_fixture(self):
        self.assertTrue(hasattr(self.n,'NEW_CONTEXT_KIND'),'Explicit new REC full-Image context route is missing')
        old,new,proof,pointer,trees=self.portable_fixture();s=proof['summary']
        proof.update(schema_version=2,kind=self.n.NEW_KIND)
        s.update(prior_image_equal=False,functional_image=copy.deepcopy(self.n.NEW_IMAGES),native_context=copy.deepcopy(self.n.NEW_CONTEXT7))
        s['context_transition']={'kind':self.n.NEW_CONTEXT_KIND,'cohort':self.n.COHORT,'source_commit':self.n.SOURCE,'kernel_abi':self.n.ABI,'producer_commit':self.n.NEW_PRODUCER,'diagnosis_sha256':self.n.DIAGNOSIS_SHA,'prior_image_equal':False,'functional_image':copy.deepcopy(self.n.NEW_IMAGES),'context7':copy.deepcopy(self.n.NEW_CONTEXT7),'native_acceptance_sha256':s['local_proof_sha256']['after']['native_status'],'candidate_context_sha256':self.n.CANDIDATE_SHA,'world_success_custody_sha256':self.n.WORLD_CUSTODY_SHA,'production_receipt_sha256':s['production_receipt_sha256'],'prior_world_producer_completed':False,'prior_world_process_wait_status':None,'prior_world_exit_code':1,'world_command_exit_zero_inferred':True,'app_metadata_relation':copy.deepcopy(self.n.APP_METADATA_RELATION)}
        self.install_reviewed_bank_fixture((old,new,proof,pointer,trees))
        return old,new,proof,pointer,trees
    def install_reviewed_bank_fixture(self,fixture):
        old,new,proof,_,trees=fixture;s=proof['summary'];policy=copy.deepcopy(self.n.REBUILT_BANK_POLICY)
        policy.update(build_id=new['build_id'],seed=new['asu']['seed'])
        policy['proofs']['new_native_acceptance']['sha256']=s['local_proof_sha256']['after']['native_status']
        policy['proofs']['new_native_evidence']['sha256']=s['local_proof_sha256']['after']['native_evidence']
        policy['proofs']['new_IB_approval']['sha256']=s['local_proof_sha256']['after']['ib_approval']
        for phase in ('before','after'):
            path=trees[phase]/'firmware-manifest.json';m=json.loads(path.read_text())
            rows=[{'path':'bin/packages/fixture-'+str(i)+'.apk','sha256':'a'*64,'size':6} for i in range(1395)]
            rows += [{'path':v['archive']['path'],**v['archive'][phase]} for v in policy['exact_rebuilt_archives']]
            rows += [policy['app_transition'][phase]];m['files']=rows;path.write_text(json.dumps(m))
            s[phase+'_metadata']['firmware-manifest.json']={k:self.n.identity(path)[k] for k in ('sha256','size')}
            policy['proofs'][phase+'_manifest']=copy.deepcopy(s[phase+'_metadata']['firmware-manifest.json'])
            bank=self.n.manifest_bank(m);s['native_archive_inventory_sha256'][phase]=self.n.json_sha(bank)
            paths={v['path']:{k:v[k] for k in ('sha256','size')} for v in rows}
            policy[phase+'_bank_inventory_sha256']=hashlib.sha256(json.dumps(paths,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.n.REBUILT_BANK_POLICY=policy;s['bank_transition']=copy.deepcopy(policy);s['unchanged_native_archives']=1395
    def check(self,fixture):
        old,new,proof,pointer,trees=fixture;ref=self.file('typed.json',json.dumps(proof).encode())
        return self.n.validate_receipt(old,new,ref['path'],ref['sha256'],predecessor_pointer=pointer,old_tree=trees['before'],new_tree=trees['after'])
    def test_reviewed_rebuilt_bank_requires_literal_authority(self):
        fixture=self.typed_fixture();s=fixture[2]['summary'];manifests={phase:json.loads((fixture[-1][phase]/'firmware-manifest.json').read_text()) for phase in ('before','after')}
        banks={phase:self.n.manifest_bank(m) for phase,m in manifests.items()};relation=s['bank_transition']
        self.n.compare_reviewed_banks(banks['before'],banks['after'],manifests,relation)
        # The old API still refuses these genuine byte changes.
        with self.assertRaisesRegex(ValueError,'Unreviewed native archive'):self.n.compare_banks(banks['before'],banks['after'])
        for mutate in (lambda x:x.update(decision_sha256='0'*64),lambda x:x['exact_rebuilt_archives'].pop(),lambda x:x.update(unchanged_whole_archive_count=1405),lambda x:x['exact_rebuilt_archives'][0]['archive']['after'].update(size=1),lambda x:x['exact_rebuilt_archives'][0].update(classification='arbitrary-control-change')):
            bad=copy.deepcopy(relation);mutate(bad)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.n.compare_reviewed_banks(banks['before'],banks['after'],manifests,bad)
        for mutate in (lambda rows:rows.pop(),lambda rows:rows.append({'path':'bin/packages/foreign.apk','sha256':'f'*64,'size':1}),lambda rows:rows[0].update(sha256='0'*64),lambda rows:rows[0].update(size=1)):
            bad=copy.deepcopy(manifests);mutate(bad['after']['files']);badbank=self.n.manifest_bank(bad['after'])
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.n.compare_reviewed_banks(banks['before'],badbank,bad,relation)
    def test_portable_bank_binds_decision_native_IB_manifest_and_control_identity(self):
        fixture=self.typed_fixture();self.check(fixture)
        for mutate in (lambda s:s['bank_transition'].update(decision_sha256='0'*64),lambda s:s['local_proof_sha256']['after'].update(native_status='0'*64),lambda s:s['local_proof_sha256']['after'].update(ib_approval='0'*64),lambda s:s['before_metadata']['firmware-manifest.json'].update(sha256='0'*64),lambda s:s.update(unchanged_native_archives=1405),lambda s:s['bank_transition']['exact_rebuilt_archives'][0].update(control={'Depends':'foreign'})):
            bad=copy.deepcopy(fixture);mutate(bad[2]['summary'])
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.check(bad)
    def test_local_decision_refuses_unpinned_authority_before_opening(self):
        for ref in (None,{'path':'/not/read','sha256':'0'*64,'size':1}):
            with self.assertRaisesRegex(ValueError,'decision SHA'):self.n.local_bank_decision(ref,{}, {}, {})

    def test_typed_portable_route_pins_distinct_full_images_without_claiming_equality(self):
        fixture=self.typed_fixture();s=self.check(fixture)
        self.assertFalse(s['prior_image_equal']);self.assertNotEqual(s['functional_image']['before'],s['functional_image']['after']);self.assertNotIn(str(self.root),json.dumps(fixture[2]));self.assertNotIn('/home/',json.dumps(fixture[2]))
    def test_v2_publication_still_requires_existing_explicit_native_authorization(self):
        old,new,proof,_,_=self.typed_fixture();r=self.file('authorized-proof.json',json.dumps(proof).encode());snapshot=self.n.module('channel-snapshot')
        kwargs={'native_replacement_proof':r['path'],'native_replacement_proof_sha256':r['sha256']}
        snapshot.validate_generation_replacement(old,new,old['build_id'],allow_native_apk_replacement=True,**kwargs)
        with self.assertRaisesRegex(ValueError,'explicit native flag'):snapshot.validate_generation_replacement(old,new,old['build_id'],**kwargs)
        with self.assertRaisesRegex(ValueError,'mutually exclusive'):snapshot.validate_generation_replacement(old,new,old['build_id'],allow_native_apk_replacement=True,allow_asu_apk_migration=True,**kwargs)
    def test_unknown_images_missing_status_latest_changed_abi_or_genuine_world_lies_refused(self):
        fixture=self.typed_fixture()
        mutations=[lambda s:s.update(prior_image_equal=True),lambda s:s['functional_image']['after'].update(sha256='0'*64),lambda s:s['native_context'].pop('.config.set'),lambda s:s['native_context']['Module.symvers'].update(sha256='0'*64),lambda s:s['context_transition'].update(cohort='612-latest'),lambda s:s['context_transition'].update(source_commit='0'*40),lambda s:s['context_transition'].update(producer_commit='0'*40),lambda s:s['context_transition'].update(native_acceptance_sha256=None),lambda s:s['context_transition'].update(world_success_custody_sha256=None),lambda s:s['context_transition'].update(prior_world_producer_completed=True),lambda s:s['context_transition'].update(prior_world_process_wait_status=0),lambda s:s['context_transition'].update(prior_world_exit_code=0),lambda s:s['context_transition'].update(world_command_exit_zero_inferred=False)]
        for mutate in mutations:
            bad=copy.deepcopy(fixture);mutate(bad[2]['summary'])
            with self.subTest(mutate=mutate),self.assertRaises((ValueError,KeyError)):self.check(bad)
    def test_v1_strict_image_route_remains_and_cannot_take_v2_image_map(self):
        fixture=self.portable_fixture();self.check(fixture)
        bad=copy.deepcopy(fixture);bad[2]['summary']['functional_image']={'before':bad[2]['summary']['functional_image'],'after':{'sha256':'0'*64,'size':14661640}}
        with self.assertRaises(ValueError):self.check(bad)
    def test_new_context_still_rejects_non_app_native_archive_change(self):
        fixture=self.typed_fixture();manifest=fixture[-1]['after']/'firmware-manifest.json';v=json.loads(manifest.read_text());v['files'][0]['sha256']='0'*64;manifest.write_text(json.dumps(v))
        with self.assertRaises(ValueError):self.check(fixture)
    def candidate_fixture(self):
        self.assertTrue(hasattr(self.n,'validate_candidate'),'Candidate validation is missing')
        roles={k:{'path':('kernel/'+k if k!='KDIR/Image' else 'Image'),**copy.deepcopy(v)} for k,v in self.n.NEW_CONTEXT7.items() if k in ('.config','.vermagic','Module.symvers','include/config/kernel.release')}
        roles['KDIR/Image']={'path':'Image',**copy.deepcopy(self.n.NEW_IMAGES['before'])}
        original={'kind':'ax6000-accepted-native-kernel-context-v2','source_commit':self.n.SOURCE,'cohort':self.n.COHORT,'recipe_commit':self.n.OLD_PRODUCER,'kernel_abi':self.n.ABI,'required_files':roles}
        owned={'kind':'rec-native-candidate-owned-context-p5-v1','kernel_abi':self.n.ABI,'required_files':copy.deepcopy(roles),'native_acceptance':None,'independently_verified':False};owned['required_files']['KDIR/Image'].update(self.n.NEW_IMAGES['after'])
        return {'schema_version':1,'kind':'rec-native-candidate-context-p5-v1','original_context':original,'owned_context':owned,'sdk_context_expected':copy.deepcopy(self.n.NEW_CONTEXT7),'prior_image_equal':False,'prior_abi_context_equal':True,'native_acceptance':None,'independently_verified':False,'diagnosis':{'sha256':self.n.DIAGNOSIS_SHA}}
    def test_candidate_context_is_only_exact_measured_pair_and_never_acceptance(self):
        candidate=self.candidate_fixture();self.n.validate_candidate(candidate)
        for mutate in (lambda x:x.update(native_acceptance=True),lambda x:x.update(independently_verified=True),lambda x:x['owned_context']['required_files']['KDIR/Image'].update(sha256='0'*64),lambda x:x['sdk_context_expected'].pop('.config.set'),lambda x:x['owned_context']['required_files']['Module.symvers'].update(sha256='0'*64)):
            bad=copy.deepcopy(candidate);mutate(bad)
            with self.assertRaises(ValueError):self.n.validate_candidate(bad)
    def test_schema3_requires_truthful_prior_false_new_true_and_exact_contexts(self):
        self.assertTrue(hasattr(self.n,'new_context_status'),'Explicit new independent native status validation is missing')
        prior={k:v for k,v in self.n.NEW_CONTEXT7.items() if k in ('.config','.vermagic','Module.symvers','include/config/kernel.release')};prior=copy.deepcopy(prior);prior['KDIR/Image']=copy.deepcopy(self.n.NEW_IMAGES['before']);current=copy.deepcopy(prior);current['KDIR/Image']=copy.deepcopy(self.n.NEW_IMAGES['after'])
        refs={k:self.file(k+'.json',json.dumps({'fixture':k}).encode()) for k in ('candidate_context','world_success_custody','producer_completion','native_evidence')};self.n.CANDIDATE_SHA=refs['candidate_context']['sha256'];self.n.WORLD_CUSTODY_SHA=refs['world_success_custody']['sha256']
        status={'schema_version':3,'kind':'ax6000-native-new-context-acceptance-v1','prior_image_equal':False,'prior_abi_context_equal':True,'strict_accepted_context_unchanged':False,'strict_new_context_unchanged':True,'original_source_readonly_guards_passed':True,'prior_kernel_image':self.n.NEW_IMAGES['before'],'accepted_kernel_image':self.n.NEW_IMAGES['after'],'prior_context':prior,'strict_context_before':current,'strict_context_after':current,'source_context7':self.n.NEW_CONTEXT7,'original_source_context_before':prior,'original_source_context_after':prior,'original_source':str(self.root/'original'),'container_exit_code':0,'oom_killed':False,'full_native_verifier_unchanged':True,**refs}
        self.n.new_context_status(status)
        for key,value in (('schema_version',2),('prior_image_equal',True),('strict_accepted_context_unchanged',True),('strict_new_context_unchanged',False),('native_evidence',None),('candidate_context',None),('world_success_custody',None),('producer_completion',None),('source_context7',{}),('container_exit_code',1)):
            bad=copy.deepcopy(status);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.n.new_context_status(bad)
    def world_fixture(self):
        code={name:self.file('P4/'+name,data) for name,data in (('build.sh',b'set -e; checked-world; after-world'),('world.py',b'subprocess.run(check=True)'),('world-argv.json',b'["world"]'))}
        manifest=self.file('P4/manifest.json',json.dumps({'code':{k:{f:v[f] for f in ('sha256','size')} for k,v in code.items()}}).encode());self.n.P4_MANIFEST_SHA=manifest['sha256']
        inspected={'Id':'002de6aea85d64daa3e6098ad19019b7e7d12a37822c9f5963cefcffa6ad4fa0','State':{'Status':'exited','Running':False,'OOMKilled':False,'ExitCode':1}}
        completion={'completed':False,'native_evidence':None,'producer_commit':self.n.NEW_PRODUCER,'source_commit':self.n.SOURCE,'stages':[{'steps':[]}]}
        refs={k:self.file('P4/'+k+'.json',json.dumps(v).encode()) for k,v in (('producer_inspect',inspected),('result',{'exit_code':1,'child_exit_code':1,'termination_reason':None}),('producer_completion',completion))};refs['build_log']=self.file('P4/log',b'world finished; following strict guard failed')
        inputs={name:refs[k] for k,name in (('producer_completion','producer-completion.json'),('producer_inspect','output/terminal-inspect.json'),('result','output/result.json'),('build_log','output/build.log'))}
        diagnosis={'world_shell_succeeded_before_strict_guard':True,'producer_completed':False,'full_Image_equal':False,'byte_normalization_performed':False,'inputs':inputs,'SDK7':{k:{'current':v,'original':v} for k,v in self.n.NEW_CONTEXT7.items()}}
        d=self.file('P4/diagnosis.json',json.dumps(diagnosis).encode());self.n.DIAGNOSIS_SHA=d['sha256']
        world={'schema_version':1,'kind':'rec-native-world-success-custody-v1','producer_commit':self.n.NEW_PRODUCER,'source_commit':self.n.SOURCE,'world_command_exit_zero_inferred':True,'raw_process_wait_status':None,'producer_completed':False,'producer_exit_code':1,'native_acceptance':None,'diagnosis':d,'runner_manifest':manifest,'producer_code':code,'build_script':code['build.sh'],'world_executor':code['world.py'],'world_argv':code['world-argv.json'],'guard_failure':{'role':'KDIR/Image','after_phase':'after-world','expected':self.n.NEW_IMAGES['before'],'observed':self.n.NEW_IMAGES['after']},**refs}
        return world
    def test_world_custody_checks_actual_failed_history_not_just_success_boolean(self):
        self.assertTrue(hasattr(self.n,'world_custody'),'P4 checked-world custody validation is missing')
        world=self.world_fixture()
        def call(v):
            r=self.file('world.json',json.dumps(v).encode());self.n.WORLD_CUSTODY_SHA=r['sha256'];return self.n.world_custody(r)
        self.assertFalse(call(world)['producer_completed'])
        for key,value in (('producer_completed',True),('producer_exit_code',0),('raw_process_wait_status',0),('native_acceptance',True),('world_command_exit_zero_inferred',False)):
            bad=copy.deepcopy(world);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):call(bad)
        bad=copy.deepcopy(world);bad['producer_code'].pop('world.py')
        with self.assertRaises(ValueError):call(bad)
        Path(world['build_log']['path']).write_bytes(b'changed')
        with self.assertRaises(ValueError):call(world)
    def test_packaging_completion_needs_real_p5_success_and_all_three_phases(self):
        self.assertTrue(hasattr(self.n,'packaging_completion'),'Genuine P5 IB/export completion validator is missing')
        world=self.world_fixture();w=self.file('world.json',json.dumps(world).encode());candidate=self.candidate_fixture();candidate['diagnosis']=world['diagnosis'];c=self.file('candidate.json',json.dumps(candidate).encode());self.n.CANDIDATE_SHA=c['sha256'];self.n.WORLD_CUSTODY_SHA=w['sha256']
        before={'source_context':{role:self.file('old/'+role,b'old'+role.encode()) for role in (*self.n.SDK_ROLES,'KDIR/Image')}}
        after={'source_context':{role:self.file('new/'+role,b'new'+role.encode()) for role in (*self.n.SDK_ROLES,'KDIR/Image')}}
        after['sdk_context']={k:self.file('sdk/'+k,k.encode()) for k in self.n.SDK_ROLES}
        metadata={k:self.file('raw/'+k,b'{}') for k in ('profile.json','lock.json','firmware-manifest.json','build.config')};staging=self.file('staging.json',b'{}')
        profile={'sdk':{'sha256':'c'*64},'imagebuilder':{'sha256':'d'*64,'size':10,'url':'https://example.invalid/ib.tar.zst'}}
        native={'bin/a.apk':{'sha256':'e'*64,'size':9},'bin/targets/mediatek/filogic/ib.tar.zst':{'sha256':'d'*64,'size':10}}
        # Native make imagebuilder produces a pristine archive; export augments it.
        pristine={'sha256':'a26d92292d340e10024d71a1837f20adb2cf5576baedaecde9c34f4f2d746c29','size':208825639}
        intermediate=copy.deepcopy(native);intermediate['bin/targets/mediatek/filogic/ib.tar.zst']=pristine
        right={'metadata':metadata,'profile':profile,'manifest':{'files':[{'path':k,**v} for k,v in native.items()]},'status':{'candidate_context':c,'world_success_custody':w}}
        phases={}
        for phase in ('before-packaging','after-imagebuilder','after-export'):
            v={'phase':phase,'native_context':{k:after['source_context'][k] for k in self.n.five_context('after')},'original_native_context':{k:before['source_context'][k] for k in self.n.five_context('before')},'source_context7':{k:after['source_context'][k] for k in self.n.SDK_ROLES},'source_config_sha256':metadata['build.config']['sha256'],'original_source_readonly_guards_passed':True,'prior_owned_Image_byte_identity':False,'candidate_context':True,'native_acceptance':None}
            if phase!='after-export':v['source_bin']=intermediate
            if phase=='after-imagebuilder':v['pristine_imagebuilder']={'archive':pristine,'archive_extracted':False,'pristine_native_makefile_sha256':'f'*64}
            if phase=='after-export':v['export']={'source_equals_raw_current_final_archives':True,'source_bin':native,'sdk_context':after['sdk_context'],'sdk':{'sha256':'c'*64},'imagebuilder':{'sha256':'d'*64,'size':10}}
            phases[phase]=self.file(phase+'.json',json.dumps(v).encode())
        inspected={'Id':'a'*64,'State':{'Status':'exited','Running':False,'OOMKilled':False,'ExitCode':0}};inspection=self.file('P5-inspect.json',json.dumps(inspected).encode())
        completion={'schema_version':1,'kind':'rec-native-packaging-completion-v1','producer_commit':self.n.NEW_PRODUCER,'source_commit':self.n.SOURCE,'completed':True,'native_evidence':None,'staging_receipt':staging,'candidate_context':c,'world_success_custody':w,'raw_metadata4':metadata,'stages':[{'steps':['imagebuilder','export'],'inspect':inspection}],'phase_receipts':phases}
        self.n.packaging_completion(completion,before,after,right,staging)
        # Neither intermediate proof nor final exported identity may substitute for the other.
        for phase,mutate in (
            ('after-imagebuilder',lambda v:v.pop('pristine_imagebuilder')),
            ('after-imagebuilder',lambda v:v['pristine_imagebuilder'].update(archive=native['bin/targets/mediatek/filogic/ib.tar.zst'])),
            ('after-export',lambda v:v['export']['source_bin'].update({'bin/targets/mediatek/filogic/ib.tar.zst':pristine})),
        ):
            bad=copy.deepcopy(completion);v=json.loads(Path(phases[phase]['path']).read_text());mutate(v)
            bad['phase_receipts'][phase]=self.file('bad-'+phase+'.json',json.dumps(v).encode())
            with self.subTest(phase=phase,mutate=mutate),self.assertRaises(ValueError):self.n.packaging_completion(bad,before,after,right,staging)
        # Export legitimately generates this RAW-only checksum file.
        right['manifest']['files'].append({'path':'bin/targets/mediatek/filogic/SHA256SUMS','sha256':'f'*64,'size':2})
        self.n.packaging_completion(completion,before,after,right,staging)
        right['manifest']['files'].append({'path':'bin/targets/mediatek/filogic/foreign.bin','sha256':'f'*64,'size':2})
        with self.assertRaises(ValueError):self.n.packaging_completion(completion,before,after,right,staging)
        right['manifest']['files'].pop()
        for mutate in (lambda x:x.update(completed=False),lambda x:x['stages'][0].update(steps=['world','imagebuilder','export']),lambda x:x['phase_receipts'].pop('before-packaging'),lambda x:x.update(native_evidence=True),lambda x:x.update(world_success_custody=None)):
            bad=copy.deepcopy(completion);mutate(bad)
            with self.assertRaises((ValueError,TypeError)):self.n.packaging_completion(bad,before,after,right,staging)
        bad=copy.deepcopy(inspected);bad['State']['ExitCode']=1;completion['stages'][0]['inspect']=self.file('P5-inspect.json',json.dumps(bad).encode())
        with self.assertRaises(ValueError):self.n.packaging_completion(completion,before,after,right,staging)
    def test_new_status_complete_bank_file_matches_actual_archive_inventory(self):
        self.assertTrue(hasattr(self.n,'new_status_bank'),'Schema3 complete native bank proof is missing')
        rows=[];bank={}
        for i in range(1406):
            package='kmod-fixture-'+str(i) if i<1079 else 'user-'+str(i);name=package+'.apk';row={'path':'bin/packages/'+name,'package':package,'version':'1','sha256':'a'*64,'size':1};rows.append(row);bank[name]={'sha256':'a'*64,'size':1}
        proof={'all_packages_verified':True,'packages':rows,'count':1406,'kmods':1079,'kernel_abi':self.n.ABI};r=self.file('native/native-bank.json',json.dumps(proof).encode());status={'native_bank_sha256':r['sha256']};side={'native_status':self.file('native/status.json',b'{}')}
        self.n.new_status_bank(status,side,bank)
        bad=copy.deepcopy(bank);bad[next(iter(bad))]['sha256']='0'*64
        with self.assertRaises(ValueError):self.n.new_status_bank(status,side,bad)
        with self.assertRaises(ValueError):self.n.new_status_bank({'native_bank_sha256':'0'*64},side,bank)
    def test_new_evaluator_keeps_shared_gates_and_never_relabels_old_completion(self):
        from unittest.mock import patch
        self.assertTrue(hasattr(self.n,'NEW_KIND'),'Typed new evaluation route missing')
        old,new,portable,pointer,trees=self.portable_fixture();metadata={}
        for phase in ('before','after'):
            metadata[phase]={name:self.n.full_ref(trees[phase]/name) for name in ('profile.json','lock.json','firmware-manifest.json','build.config')}
        banks={'before':{'core.apk':{'sha256':'a'*64,'size':6},self.n.APP+'2.apk':{'sha256':'b'*64,'size':7}},'after':{'core.apk':{'sha256':'a'*64,'size':6},self.n.APP+'3.apk':{'sha256':'c'*64,'size':8}}}
        profile_ref=self.file('source-profile.json',b'{}');staging=self.file('staging.json',b'{}');production=self.file('production.json',b'{}')
        sides={phase:{'producer_commit':self.n.OLD_PRODUCER if phase=='before' else self.n.NEW_PRODUCER,'source':'/synthetic/'+phase,'source_context':{**{k:{'path':'/synthetic/'+phase+'/'+k,**v} for k,v in self.n.NEW_CONTEXT7.items()},'KDIR/Image':{'path':'/synthetic/'+phase+'/Image',**self.n.NEW_IMAGES[phase]}},'source_profile':profile_ref,**{k:self.file(phase+'/'+k+'.json',b'{}') for k in ('native_status','native_evidence','sdk_baseline','ib_approval')}} for phase in ('before','after')}
        records={phase:{'profile':old if phase=='before' else new,'manifest':{'source_patches':[]},'metadata':metadata[phase],'bank':banks[phase],'baseline':{k:['kernel'] for k in ('protected_packages','frozen_packages','frozen_kmods')},'context':self.n.NEW_CONTEXT7,'image':self.n.NEW_IMAGES[phase],'evidence':{},'status':{'original_source':sides['before']['source'],'producer_completion':production,'native_evidence':sides[phase]['native_evidence'],'sdk_baseline':sides[phase]['sdk_baseline']}} for phase in ('before','after')}
        inputs={'schema_version':2,'kind':'rec-native-apk-replacement-inputs-v2','before':sides['before'],'after':sides['after'],'staging_receipt':staging,'production_receipt':production,'trusted_apk':None,'trusted_usign':None,'bank_transition_decision':{'path':'/synthetic/decision','sha256':'0'*64,'size':1},'predecessor_root':'/synthetic','predecessor_site_state':None,'predecessor_snapshot':None}
        observations=[]
        def side(value,**kw):observations.append(kw);return records['before' if value is sides['before'] else 'after']
        with patch.object(self.n,'side_records',side),patch.object(self.n,'local_bank_decision',return_value=copy.deepcopy(self.n.REBUILT_BANK_POLICY)),patch.object(self.n,'validate_bank_bindings'),patch.object(self.n,'staged_source',return_value=portable['summary']['source_postimages']) as stage,patch.object(self.n,'packaging_completion',return_value={'candidate_context_sha256':self.n.CANDIDATE_SHA,'world_success_custody_sha256':self.n.WORLD_CUSTODY_SHA}) as pack,patch.object(self.n,'production_completion',side_effect=AssertionError('Old completed-world path must not run')),patch.object(self.n,'root_delta') as root,patch.object(self.n,'app_payload_new_context') as app,patch.object(self.n,'predecessor',return_value=pointer) as pred:
            _,_,summary=self.n.evaluate(inputs)
            self.assertFalse(summary['prior_image_equal']);self.assertEqual(summary['functional_image'],self.n.NEW_IMAGES)
            self.assertEqual(observations,[{}, {'context_transition':self.n.NEW_CONTEXT_KIND}]);pack.assert_called_once();root.assert_called_once();app.assert_called_once();pred.assert_called_once()
            self.assertEqual(stage.call_args.args[2]['source_context']['KDIR/Image']['sha256'],self.n.NEW_IMAGES['before']['sha256'])
            self.assertEqual(sides['after']['source_context']['KDIR/Image']['sha256'],self.n.NEW_IMAGES['after']['sha256'])
            root.side_effect=ValueError('mandatory real native root gate')
            with self.assertRaisesRegex(ValueError,'mandatory real native root gate'):self.n.evaluate(inputs)
    def test_payload_adapter_decodes_all_six_phase_specific_images_and_refuses_wrong_phase(self):
        self.assertTrue(hasattr(self.n,'NEW_CONTEXT_KIND'),'Explicit new REC full-Image context route is missing')
        from test_kernel_migration import sysupgrade,image
        images={phase:image(phase.encode()) for phase in ('before','after')}
        summary={'predecessor_build_id':'old','successor_build_id':'new','prior_image_equal':False,'functional_image':{phase:{'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)} for phase,data in images.items()}}
        for phase in ('before','after'):
            files=[]
            for layout in ('stock','mtkuboot','ubootmod'):
                name='immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-'+layout+'-squashfs-sysupgrade'+('.itb' if layout=='ubootmod' else '.bin')
                relative='bin/targets/mediatek/filogic/'+name;r=self.file(phase+'/'+relative,sysupgrade(layout,images[phase]));files.append({'path':relative,**{k:r[k] for k in ('sha256','size')}})
            r=self.file(phase+'/firmware-manifest.json',json.dumps({'files':files}).encode());summary[phase+'_metadata']={'firmware-manifest.json':{'sha256':r['sha256']}}
        cache={};self.n.validate_payloads(self.root/'before',self.root/'after',summary,self.n.read_json,None,cache,{'used':0});self.assertEqual(len(cache),6)
        summary['functional_image']['after']=summary['functional_image']['before']
        with self.assertRaisesRegex(ValueError,'full functional Image'):self.n.validate_payloads(self.root/'before',self.root/'after',summary,self.n.read_json,None,cache,{'used':0})

if __name__=='__main__':unittest.main()
