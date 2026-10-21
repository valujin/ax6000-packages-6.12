"""Synthetic offline guard fixtures; never real native acceptance."""
import copy
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


def profiles():
    old = {'id': 'redmi-ax6000-612-recommended', 'channel': 'recommended',
           'build_id': 'old-native', 'package_manager': 'apk', 'apk_key_sha256': 'a' * 64,
           'firmware': {'commit': 'ae65e1de69971b5a2e3cf7e39390ee93f274d488',
                        'kernel_version': '6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1',
                        'architecture': 'aarch64_cortex-a53',
                        'devices': [{'layout': x} for x in ('stock', 'mtkuboot', 'ubootmod')]},
           'sdk': {'url': 'old', 'sha256': '1' * 64},
           'imagebuilder': {'url': 'old-ib', 'sha256': '2' * 64, 'size': 100},
           'asu': {'enabled': True, 'cohort': '612-recommended',
                   'server_url': 'https://asu.ezon.by/612/recommended', 'seed': '3' * 64},
           'packages': ['tailscale', 'luci-app-attendedsysupgrade', 'attendedsysupgrade-common'],
           'image_packages': ['luci-app-attendedsysupgrade', 'attendedsysupgrade-common'],
           'package_only': ['tailscale'], 'feeds': [{'commit': 'b' * 40}],
           'publication': {'repository': 'valujin/ax6000-packages-6.12'},
           'pbr_source': 'mossdef-stable', 'vendor_country_db': True}
    new = copy.deepcopy(old)
    new.update(build_id='new-native', sdk={'url': 'new', 'sha256': '4' * 64},
               imagebuilder={'url': 'new-ib', 'sha256': '5' * 64, 'size': 101})
    new['asu']['seed'] = '6' * 64
    return old, new


class NativeProfiles(unittest.TestCase):
    def helper(self):
        path = ROOT / 'scripts/native_generation.py'
        if not path.exists():
            self.fail('Finite native APK replacement guard is missing')
        spec = importlib.util.spec_from_file_location('native_generation_test', path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        return helper

    def test_exact_apk_native_profile_replacement_accepts_only_identity_and_seed_changes(self):
        self.helper().validate_profiles(*profiles())

    def test_policy_keys_source_layout_or_other_cohort_cannot_use_native_replacement(self):
        helper = self.helper()
        changes = [lambda x: x.update(package_manager='opkg'),
                   lambda x: x.update(channel='latest'),
                   lambda x: x['firmware'].update(commit='f' * 40),
                   lambda x: x['firmware'].update(kernel_version='foreign'),
                   lambda x: x['firmware']['devices'].pop(),
                   lambda x: x['packages'].append('unreviewed'),
                   lambda x: x.update(package_only=[]),
                   lambda x: x.update(apk_key_sha256='e' * 64),
                   lambda x: x['asu'].update(server_url='https://foreign.invalid'),
                   lambda x: x.update(pbr_source='moving'),
                   lambda x: x.update(unknown_policy=True)]
        for change in changes:
            old, new = profiles(); change(new)
            with self.subTest(change=change), self.assertRaises(ValueError):
                helper.validate_profiles(old, new)

    def test_old_opkg_and_unchanged_or_incomplete_new_identities_are_refused(self):
        helper = self.helper()
        for field in ('build_id', 'sdk', 'imagebuilder', 'asu'):
            old, new = profiles(); new[field] = old[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                helper.validate_profiles(old, new)
        old, new = profiles(); old['package_manager'] = 'opkg'
        with self.assertRaises(ValueError): helper.validate_profiles(old, new)

    def test_manual_native_flags_require_separate_reviewed_proof_and_refuse_bootstrap_or_opkg_flag(self):
        spec = importlib.util.spec_from_file_location('snapshot_native_test', ROOT / 'scripts/channel-snapshot.py')
        snapshot = importlib.util.module_from_spec(spec); spec.loader.exec_module(snapshot)
        old, new = profiles()
        with self.assertRaisesRegex(ValueError, 'native.*proof|proof.*native'):
            snapshot.validate_generation_replacement(old, new, old['build_id'], allow_native_apk_replacement=True)
        with self.assertRaisesRegex(ValueError, 'exclusive'):
            snapshot.validate_generation_replacement(old, new, old['build_id'],
                allow_native_apk_replacement=True, allow_asu_apk_migration=True)

    def test_native_publish_rejects_missing_authorization_before_any_files_or_external_writes(self):
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('snapshot_native_early_test', ROOT / 'scripts/channel-snapshot.py')
        snapshot = importlib.util.module_from_spec(spec); spec.loader.exec_module(snapshot)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = [root / 'absent'] * 4 + ['https://invalid', 'valujin/ax6000-packages-6.12', root / 'profiles',
                                           root / 'work', root / 'private', root / 'public', '/absent/usign', root / 'output']
            for options in ({'allow_native_apk_replacement': True},
                            {'allow_native_apk_replacement': True, 'replace_build_id': 'old', 'bootstrap': True},
                            {'allow_native_apk_replacement': True, 'replace_build_id': 'old', 'allow_asu_apk_migration': True},
                            {'native_replacement_proof': root / 'proof', 'native_replacement_proof_sha256': 'a' * 64}):
                with self.subTest(options=options), patch.object(snapshot, 'module') as external:
                    with self.assertRaises(ValueError): snapshot.publish_channel(*args, **options)
                    external.assert_not_called()
                    self.assertEqual(list(root.iterdir()), [])
            for replacements in (None, {'latest': ('irrelevant', 'old')}, {'recommended': ('x', 'old'), 'latest': ('y', 'old')}):
                with self.subTest(replacements=replacements), self.assertRaises(ValueError):
                    snapshot.compose_site(None, None, {}, 'repo', root / 'private', root / 'public', '/absent/usign',
                                          root / 'output', allow_native_apk_replacement=True, replacements=replacements)
            self.assertEqual(list(root.iterdir()), [])


class ActualFiles(unittest.TestCase):
    helper = NativeProfiles.helper
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.n = self.helper()

    def file(self, name, value):
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return {'path': str(path), 'sha256': hashlib.sha256(value).hexdigest(), 'size': len(value)}

    def test_refs_require_actual_bytes_and_canonical_paths_not_null_or_booleans(self):
        ref = self.file('actual', b'proof')
        self.assertEqual(self.n.checked_ref(ref), Path(ref['path']))
        for bad in (None, True, {**ref, 'size': True}, {**ref, 'sha256': '0' * 64},
                    {**ref, 'path': str(self.root) + '/x/../actual'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError): self.n.checked_ref(bad)
        (self.root / 'alias').symlink_to(self.root / 'actual')
        with self.assertRaises(ValueError): self.n.checked_ref({**ref, 'path': str(self.root / 'alias')})
        (self.root / 'actual').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.n.checked_ref(ref)

    def bank(self, prefix='raw'):
        raw = self.root / prefix
        entries = []
        for name, data in [('kernel-abi.apk', b'kernel'), ('kmod-vendor-1.apk', b'protected'),
                           ('attendedsysupgrade-common-10-r2.apk', b'common'),
                           ('luci-i18n-attendedsysupgrade-ru-1.apk', b'old translation'),
                           ('luci-app-attendedsysupgrade-20261021.2-r2.apk', b'app')]:
            ref = self.file(prefix + '/bin/packages/' + name, data)
            entries.append({'path': 'bin/packages/' + name, 'sha256': ref['sha256'], 'size': ref['size']})
        return raw, {'files': entries}

    def test_native_inventory_hashes_every_actual_archive_and_rejects_omissions_aliases(self):
        raw, manifest = self.bank()
        actual = self.n.native_bank(raw, manifest)
        self.assertEqual(set(actual), {Path(x['path']).name for x in manifest['files']})
        (raw / 'bin/packages/kernel-abi.apk').write_bytes(b'corrupt')
        with self.assertRaises(ValueError): self.n.native_bank(raw, manifest)
        raw, manifest = self.bank('second')
        with self.assertRaises(ValueError): self.n.native_bank(raw, {'files': manifest['files'][1:]})
        target = raw / 'bin/packages/kernel-abi.apk'; target.unlink(); target.symlink_to('/etc/hosts')
        with self.assertRaises(ValueError): self.n.native_bank(raw, manifest)

    def test_native_bank_permits_only_one_real_app_revision_and_retains_translation_and_common(self):
        raw, manifest = self.bank(); old = self.n.native_bank(raw, manifest)
        new = copy.deepcopy(old)
        app = new.pop('luci-app-attendedsysupgrade-20261021.2-r2.apk')
        new['luci-app-attendedsysupgrade-20261021.2-r3.apk'] = {**app, 'sha256': '1' * 64}
        self.n.compare_banks(old, new)
        for name in ('kernel-abi.apk', 'kmod-vendor-1.apk', 'attendedsysupgrade-common-10-r2.apk',
                     'luci-i18n-attendedsysupgrade-ru-1.apk'):
            bad = copy.deepcopy(new); bad[name]['sha256'] = '2' * 64
            with self.subTest(name=name), self.assertRaises(ValueError): self.n.compare_banks(old, bad)
        bad = copy.deepcopy(new); bad['unknown.apk'] = app
        with self.assertRaises(ValueError): self.n.compare_banks(old, bad)

    def test_production_completion_requires_real_exited_successful_stages_and_exact_bindings(self):
        metadata = {x: self.file(x, b'{}') for x in ('profile.json', 'lock.json', 'firmware-manifest.json', 'build.config')}
        evidence = self.file('evidence.json', b'{}'); staging = self.file('staging.json', b'{}')
        inspected = {'Id': 'a' * 64, 'State': {'Status': 'exited', 'Running': False, 'OOMKilled': False, 'ExitCode': 0}}
        inspect = self.file('inspect.json', json.dumps(inspected).encode())
        receipt = {'schema_version': 1, 'kind': 'rec-native-producer-completion-v1',
                   'producer_commit': 'b' * 40, 'source_commit': self.n.SOURCE,
                   'staging_receipt': staging, 'native_evidence': None, 'raw_metadata4': metadata,
                   'stages': [{'steps': ['world', 'imagebuilder', 'export'], 'inspect': inspect}],
                   'completed': True, 'phase_receipts': {}}
        contexts = {name: self.file('source/' + name, name.encode()) for name in (*self.n.SDK_ROLES, 'KDIR/Image')}
        sdk_context = {name: contexts[name] for name in self.n.SDK_ROLES}
        profile = {'sdk': {'sha256': 'c' * 64}, 'imagebuilder': {'sha256': 'd' * 64, 'size': 10}}
        manifest = {'files': [{'path': 'bin/a.apk', 'sha256': 'e' * 64, 'size': 9}]}
        for phase in ('after-prepare', 'after-world', 'after-imagebuilder', 'after-export'):
            actual = {'phase': phase, 'native_context': {k: contexts[k] for k in ('.config', '.vermagic', 'Module.symvers', 'include/config/kernel.release', 'KDIR/Image')},
                      'source_context7': sdk_context, 'source_config_sha256': metadata['build.config']['sha256'],
                      'original_source_readonly_guards_passed': True}
            if phase == 'after-export': actual['export'] = {'source_equals_raw_current_final_archives': True,
                'sdk_context': sdk_context, 'sdk': {'sha256': 'c' * 64, 'size': 12}, 'imagebuilder': profile['imagebuilder'],
                'source_bin': {'bin/a.apk': {'sha256': 'e' * 64, 'size': 9}}}
            receipt['phase_receipts'][phase] = self.file(phase + '.json', json.dumps(actual).encode())
        args = ('b' * 40, metadata, evidence, staging, contexts, sdk_context, profile, manifest)
        self.n.production_completion(receipt, *args)
        for mutate in (lambda x: x.update(stages=[]),
                       lambda x: x['stages'][0].update(steps=['export']),
                       lambda x: x.update(native_evidence=True),
                       lambda x: x.update(producer_commit='c' * 40),
                       lambda x: x.update(completed=False), lambda x: x['phase_receipts'].pop('after-world')):
            bad = copy.deepcopy(receipt); mutate(bad)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.n.production_completion(bad, *args)
        for field, value in [('ExitCode', 1), ('ExitCode', False), ('Running', True), ('OOMKilled', True)]:
            bad = copy.deepcopy(inspected); bad['State'][field] = value
            receipt['stages'][0]['inspect'] = self.file('inspect.json', json.dumps(bad).encode())
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.n.production_completion(receipt, *args)

    def test_seed_uses_declared_producer_git_blobs_not_later_publisher_or_worktree(self):
        recipe = self.root / 'recipe'; recipe.mkdir()
        subprocess.run(['git', 'init', '-q', str(recipe)], check=True)
        files = {'scripts/a.py': b'approved code', '.github/workflows/a.yml': b'approved workflow',
                 'files/asu-client/a.js': b'approved module', 'docs/notes.md': b'not recipe input'}
        for name, data in files.items(): self.file('recipe/' + name, data)
        subprocess.run(['git', '-C', str(recipe), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(recipe), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid',
                        'commit', '-qm', 'synthetic producer'], check=True)
        commit = subprocess.check_output(['git', '-C', str(recipe), 'rev-parse', 'HEAD'], text=True).strip()
        profile = {'asu': {'seed': '0' * 64}, 'sdk': None, 'firmware': {'kernel_version': None}}
        digest = hashlib.sha256()
        for name in sorted(files):
            if name.startswith('docs/'): continue
            digest.update(name.encode() + b'\0' + files[name] + b'\0')
        body = {'recipe_contract': 'ax6000-native-asu-v1', 'source_profile': {**profile, 'asu': {}},
                'recipe_sha256': digest.hexdigest()}
        expected = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        self.assertEqual(self.n.producer_seed(recipe, commit, profile), expected)
        (recipe / 'scripts/a.py').write_bytes(b'later publisher code')
        self.assertEqual(self.n.producer_seed(recipe, commit, profile), expected)
        with self.assertRaises(ValueError): self.n.producer_seed(recipe, 'f' * 40, profile)

    def test_abi_context_comparison_requires_all_seven_actual_roles(self):
        refs = {name: self.file('ctx/' + name, name.encode()) for name in self.n.SDK_ROLES}
        expected = {name: {k: value[k] for k in ('sha256', 'size')} for name, value in refs.items()}
        self.assertEqual(self.n.context_records(refs, expected), expected)
        with self.assertRaises(ValueError): self.n.context_records({k:v for k,v in refs.items() if k!='Module.symvers'}, expected)
        (self.root / 'ctx/.config').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.n.context_records(refs, expected)

    def test_exact_source_profile_export_transformation_rejects_unrelated_generated_policy(self):
        source, actual = profiles()
        source['firmware'].update(repository='https://source.invalid/repo', kernel_version=None)
        source['all_kmods'] = True
        actual = copy.deepcopy(source); actual['firmware']['kernel_version'] = self.n.ABI
        actual['all_kmods'] = False
        actual['feeds'].insert(0, {'name': 'base', 'url': source['firmware']['repository'],
                                   'commit': self.n.SOURCE, 'root': 'package'})
        actual['build_id'] = actual['id'] + '-' + self.n.SOURCE[:12] + '-' + actual['sdk']['sha256'][:12]
        self.n.generated_profile(source, actual)
        for mutate in (lambda x: x['packages'].append('unreviewed'),
                       lambda x: x['asu'].update(seed='f' * 64),
                       lambda x: x['feeds'][0].update(root='other'),
                       lambda x: x.update(build_id='invented')):
            bad = copy.deepcopy(actual); mutate(bad)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.n.generated_profile(source, bad)

    def test_sdk_baseline_is_bound_to_native_verifier_and_actual_archive_inventory(self):
        raw, manifest = self.bank(); bank = self.n.native_bank(raw, manifest)
        baseline = {'schema_version': 1, 'package_manager': 'apk', 'source_commit': self.n.SOURCE,
                    'kernel_version': self.n.ABI, 'architecture': 'aarch64_cortex-a53',
                    'protected_packages': ['kernel', 'kmod-vendor'],
                    'frozen_packages': ['kernel', 'kmod-vendor'], 'frozen_kmods': ['kmod-vendor'],
                    'files': [{'package': name, 'version': '1', 'path': 'packages/' + filename, 'sha256': bank[filename]['sha256']}
                              for name, filename in [('kernel', 'kernel-abi.apk'), ('kmod-vendor', 'kmod-vendor-1.apk')]]}
        ref = self.file('baseline.json', json.dumps(baseline).encode())
        proof = {'manifest_sha256': ref['sha256'], 'packages': 2, 'frozen_kmods': 1,
                 'whole_native_archive_bytes_matched': True}
        self.assertEqual(self.n.check_baseline(ref, proof, bank)['protected_packages'], ['kernel', 'kmod-vendor'])
        for mutate in (lambda x: x.update(manifest_sha256='f' * 64),
                       lambda x: x.update(whole_native_archive_bytes_matched=False),
                       lambda x: x.update(packages=1)):
            bad = copy.deepcopy(proof); mutate(bad)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.n.check_baseline(ref, bad, bank)
        (raw / 'bin/packages/kernel-abi.apk').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.n.native_bank(raw, manifest)

    def test_missing_actual_proof_is_refused_even_if_staging_claims_success(self):
        old, new = profiles()
        for value in (None, {'stage_complete': True}, {'kind': 'rec-native-apk-generation-transition-v1', 'inputs': None}):
            ref = self.file('unaccepted-proof.json', json.dumps(value).encode())
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.n.validate_receipt(old, new, ref['path'], ref['sha256'])

    def test_actual_v2_staging_measures_both_sides_at_copy_and_exact_four_postimages(self):
        from unittest.mock import patch
        from test_asu_client import client
        makefile = client._app_makefile(client._originals('612')['Makefile'], 'apk')
        sides, images, producers = {}, {}, {'before': self.n.OLD_PRODUCER, 'after': 'b' * 40}
        for phase, seed in [('before', '1' * 64), ('after', '2' * 64)]:
            source = self.root / phase; source.mkdir()
            profile = self.file(phase + '-profile.json', json.dumps({'asu': {'seed': seed}}).encode())
            contexts = {name: self.file(phase + '/ctx/' + name, name.encode()) for name in (*self.n.SDK_ROLES, 'KDIR/Image')}
            sides[phase] = {'source': str(source), 'source_profile': profile, 'recipe': str(self.root),
                            'producer_commit': producers[phase], 'source_context': contexts}
            self.file(phase + '/.config', b'fixed config')
            content = {name: b'unchanged public fixture' for name in self.n.POSTIMAGES}
            content.update({self.n.CLIENT + 'Makefile': makefile if phase == 'after' else makefile.replace(b'PKG_RELEASE:=3\n', b'PKG_RELEASE:=2\n'),
                            self.n.CLIENT + 'htdocs/luci-static/resources/ax6000_asu.js': (ROOT / 'files/asu-client/ax6000_asu.js').read_bytes() if phase == 'after' else b'old module',
                            'files/' + self.n.INSTALLER: (phase + ' installer').encode(),
                            'files/etc/asu-cohort.json': (json.dumps({'schema_version': 1, 'cohort': self.n.COHORT,
                                'seed': seed, 'package_manager': 'apk'}, sort_keys=True) + '\n').encode()})
            images[phase] = {}
            for name, payload in content.items():
                ref = self.file(phase + '/' + name, payload); path = Path(ref['path'])
                mode = 0o755 if name == 'files/' + self.n.INSTALLER else 0o644; path.chmod(mode)
                images[phase][name] = {'content_base64': base64.b64encode(payload).decode(),
                                      **{k: ref[k] for k in ('sha256', 'size')}, 'mode': mode}
        image_ref = self.file('postimages.json', json.dumps(images).encode())
        binding = {'postimages': image_ref, 'source': sides['before']['source'], 'destination': sides['after']['source'],
                   'source_commit': self.n.SOURCE, 'old_recipe_commit': self.n.OLD_PRODUCER,
                   'new_recipe_commit': producers['after'], 'changed_paths': sorted(self.n.CHANGED)}
        stage = {'kind': 'ax6000-rec-genuine-warm-fork-preparation-v2', 'execute': True, 'stage_complete': True,
                 'source': sides['before']['source'], 'destination': sides['after']['source'], 'source_commit': self.n.SOURCE,
                 'old_recipe_commit': self.n.OLD_PRODUCER, 'producer_commit': producers['after'],
                 'source_profile': sides['after']['source_profile'], 'postimages': image_ref,
                 'input_binding': self.file('binding.json', json.dumps(binding).encode()),
                 'copy': {'inventory_sha256': 'a' * 64, 'regular_files': 14, 'regular_file_bytes': 100,
                          'all_bytes_and_modes_compared': True, 'cross_tree_regular_hardlinks': False},
                 'changed_files': {name: {p: images[p][name] for p in ('before', 'after')} for name in self.n.CHANGED},
                 'native_build': None, 'native_verification': None, 'router_execution': None}
        five = ('.config', '.vermagic', 'Module.symvers', 'include/config/kernel.release', 'KDIR/Image')
        for phase in ('before', 'after'):
            stage['native_context_' + phase] = {name: sides['after']['source_context'][name] for name in five}
            stage['source_context7_' + phase] = {name: sides['after']['source_context'][name] for name in self.n.SDK_ROLES}
            stage['source_config_' + phase + '_sha256'] = hashlib.sha256(b'fixed config').hexdigest()
        def blob(recipe, commit, name):
            phase = 'before' if commit == producers['before'] else 'after'
            source = self.n.CLIENT + 'htdocs/luci-static/resources/ax6000_asu.js' if name.startswith('files/asu-client/') else 'files/' + self.n.INSTALLER
            return base64.b64decode(images[phase][source]['content_base64'])
        with patch.object(self.n, 'git_blob', side_effect=blob):
            self.assertEqual(self.n.staged_source(stage, sides['before'], sides['after']), images)
            for mutate in (lambda x: x.update(kind='ax6000-rec-genuine-warm-fork-preparation-v1'),
                           lambda x: x.update(native_build=True),
                           lambda x: x['native_context_before'].update({'.config': sides['before']['source_context']['.config']}),
                           lambda x: x['source_context7_after'].pop('.config.set')):
                bad = copy.deepcopy(stage); mutate(bad)
                with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.n.staged_source(bad, sides['before'], sides['after'])

    def test_inert_emitter_default_never_opens_inputs_or_native_state(self):
        process = subprocess.run(['/usr/bin/python3', '-B', str(ROOT / 'scripts/native_generation.py')],
                                 text=True, capture_output=True, check=True)
        self.assertEqual(json.loads(process.stdout)['execute'], False)

    def portable_fixture(self):
        old, new = profiles(); migration = self.n.module('kernel_migration')
        bank = {'core.apk': {'sha256': 'a' * 64, 'size': 6},
                self.n.APP + '2.apk': {'sha256': 'b' * 64, 'size': 7}}
        successor = copy.deepcopy(bank); successor.pop(self.n.APP + '2.apk')
        successor[self.n.APP + '3.apk'] = {'sha256': 'c' * 64, 'size': 8}
        producer = 'b122c35046ab1c3cd03828aabd168bb35466e2c8'
        metadata, trees = {}, {}
        for phase, profile, inventory, commit in [('before', old, bank, self.n.OLD_PRODUCER),
                                                  ('after', new, successor, producer)]:
            manifest = {'source_commit': self.n.SOURCE, 'kernel_version': self.n.ABI,
                        'build_id': profile['build_id'], 'recipe_commit': commit, 'source_patches': [],
                        'files': [{'path': 'bin/packages/' + name, **row} for name, row in inventory.items()]}
            metadata[phase] = {}
            for name, value in [('profile.json', json.dumps(profile).encode()), ('lock.json', b'{}'),
                                ('firmware-manifest.json', json.dumps(manifest).encode()), ('build.config', b'fixed config')]:
                ref = self.file(phase + '/' + name, value)
                metadata[phase][name] = {k: ref[k] for k in ('sha256', 'size')}
            trees[phase] = self.root / phase
        images = {phase: {name: {'sha256': 'd' * 64, 'size': 10, 'mode': 0o644}
                          for name in self.n.POSTIMAGES} for phase in ('before', 'after')}
        for phase, profile, sha in [('before', old, '6c3e1489551d35c218ba363d4727a0e52e69a98a30a1546722d91e131d48f54f'),
                                    ('after', new, '12c62440fbe9b5ee6b568fbe9253d90bc40d29edf3959375c7cbc8a21ecb6674')]:
            images[phase][self.n.CLIENT + 'Makefile']['sha256'] = sha
            cohort = (json.dumps({'schema_version': 1, 'cohort': self.n.COHORT, 'seed': profile['asu']['seed'],
                                 'package_manager': 'apk'}, sort_keys=True) + '\n').encode()
            images[phase]['files/etc/asu-cohort.json'] = {'sha256': hashlib.sha256(cohort).hexdigest(), 'size': len(cohort), 'mode': 0o644}
            images[phase]['files/' + self.n.INSTALLER] = {'sha256': ('e' if phase == 'before' else 'f') * 64, 'size': 10, 'mode': 0o755}
        images['after'][self.n.CLIENT + 'htdocs/luci-static/resources/ax6000_asu.js']['sha256'] = self.n.MODULE_SHA
        context = {**migration.CONTEXT, **{name: {'sha256': '1' * 64, 'size': 10}
                                         for name in self.n.SDK_ROLES if name not in migration.CONTEXT}}
        pointer = {'build_id': old['build_id'], 'manifest_sha256': '2' * 64}
        summary = {'predecessor_build_id': old['build_id'], 'successor_build_id': new['build_id'],
                   'predecessor_pointer': pointer, 'source_commit': self.n.SOURCE, 'kernel_abi': self.n.ABI,
                   'producer_commit': producer, 'native_context': context, 'functional_image': migration.IMAGES['after'],
                   'unchanged_native_archives': 1, 'protected_baseline_packages': 1,
                   'changed_source_paths': sorted(self.n.CHANGED), 'new_app_version': '20261021.2-r3',
                   'before_metadata': metadata['before'], 'after_metadata': metadata['after'],
                   'native_archive_inventory_sha256': {'before': self.n.json_sha(bank), 'after': self.n.json_sha(successor)},
                   'source_patch_ledger': [], 'source_postimages': images,
                   'source_profile': {phase: {'sha256': '3' * 64, 'size': 10} for phase in ('before', 'after')},
                   'seeds': {'before': old['asu']['seed'], 'after': new['asu']['seed']},
                   'local_proof_sha256': {phase: {name: '4' * 64 for name in ('native_status', 'native_evidence', 'sdk_baseline', 'ib_approval')}
                                          for phase in ('before', 'after')},
                   'staging_receipt_sha256': '5' * 64, 'production_receipt_sha256': '6' * 64}
        return old, new, {'schema_version': 1, 'kind': self.n.KIND, 'summary': summary}, pointer, trees

    def test_portable_receipt_needs_no_local_source_and_binds_real_metadata_inventory_and_live_predecessor(self):
        old, new, proof, pointer, trees = self.portable_fixture()
        def check(value, expected_pointer=pointer):
            ref = self.file('portable.json', json.dumps(value).encode())
            return self.n.validate_receipt(old, new, ref['path'], ref['sha256'], predecessor_pointer=expected_pointer,
                                           old_tree=trees['before'], new_tree=trees['after'])
        self.assertEqual(check(proof), proof['summary'])
        self.assertNotIn('"path":', json.dumps(proof))
        with self.assertRaises(ValueError): check(proof, {'build_id': 'raced'})
        for mutate in (lambda x: x.update(functional_image={'sha256': '0' * 64, 'size': 14661640}),
                       lambda x: x['native_context'].pop('.config.set'),
                       lambda x: x['native_context']['Module.symvers'].update(sha256='0' * 64),
                       lambda x: x.update(unchanged_native_archives=2),
                       lambda x: x.update(protected_baseline_packages=True),
                       lambda x: x['before_metadata']['profile.json'].update(sha256='0' * 64),
                       lambda x: x['after_metadata']['build.config'].update(size=1),
                       lambda x: x['source_postimages']['after']['files/etc/asu-cohort.json'].update(sha256='0' * 64),
                       lambda x: x['source_postimages']['after'][self.n.CLIENT + 'Makefile'].update(sha256='0' * 64),
                       lambda x: x['source_postimages']['after']['files/etc/ax6000/repository.pub'].update(sha256='0' * 64),
                       lambda x: x['local_proof_sha256']['after'].update(ib_approval=None),
                       lambda x: x['native_archive_inventory_sha256'].update(after='0' * 64),
                       lambda x: x.update(producer_commit='0' * 40)):
            bad = copy.deepcopy(proof); mutate(bad['summary'])
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, KeyError)): check(bad)
        manifest_path = trees['after'] / 'firmware-manifest.json'
        manifest = json.loads(manifest_path.read_bytes()); manifest['files'][0]['sha256'] = '0' * 64
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError): check(proof)

    def test_native_payload_adapter_decodes_all_six_real_tiny_images_and_rejects_whole_image_drift(self):
        from test_kernel_migration import sysupgrade, image
        expected = image(b'same-native-image')
        summary = {'predecessor_build_id': 'old', 'successor_build_id': 'new',
                   'functional_image': {'sha256': hashlib.sha256(expected).hexdigest(), 'size': len(expected)}}
        for phase in ('before', 'after'):
            files = []
            for layout in ('stock', 'mtkuboot', 'ubootmod'):
                name = 'immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-' + layout + '-squashfs-sysupgrade' + ('.itb' if layout == 'ubootmod' else '.bin')
                relative = 'bin/targets/mediatek/filogic/' + name
                ref = self.file(phase + '/' + relative, sysupgrade(layout, expected))
                files.append({'path': relative, **{k: ref[k] for k in ('sha256', 'size')}})
            ref = self.file(phase + '/firmware-manifest.json', json.dumps({'files': files}).encode())
            summary[phase + '_metadata'] = {'firmware-manifest.json': {'sha256': ref['sha256']}}
        cache = {}
        self.n.validate_payloads(self.root / 'before', self.root / 'after', summary, self.n.read_json, None, cache, {'used': 0})
        self.assertEqual(len(cache), 3)  # Identical full assets safely share a process cache key.
        summary['functional_image']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'full functional Image'):
            self.n.validate_payloads(self.root / 'before', self.root / 'after', summary, self.n.read_json, None, cache, {'used': 0})

    def test_actual_sdk_ib_approval_requires_persisted_result_source_and_scan_files(self):
        old, _ = profiles(); old['firmware'].update(target='mediatek', subtarget='filogic')
        side = {'producer_commit': 'c' * 40, 'metadata': {'profile.json': {'sha256': 'd' * 64}},
                'native_status': {'sha256': 'e' * 64}, 'native_evidence': {'sha256': 'f' * 64}}
        result = {'identity': {'build_id': old['build_id'], 'source_commit': self.n.SOURCE, 'kernel_version': self.n.ABI,
                   'architecture': old['firmware']['architecture'], 'target': 'mediatek/filogic', 'package_manager': 'apk'},
                  'packages': 2, 'apk_public_key_sha256': old['apk_key_sha256']}
        transform = {'producer_commit': side['producer_commit'], 'source_commit': self.n.SOURCE,
                     'native_status_sha256': side['native_status']['sha256'], 'full_source_checks_retained': True,
                     'imported_raw_tool_execution': False, 'vendor_elf_execution': False}
        refs = {name: self.file('ib/' + name, json.dumps(value).encode()) for name, value in [
            ('verification-result.json', result), ('source-transform.json', transform),
            ('layout-context.json', {}), ('private-key-context-scan.json', {}), ('apk-semantic.json', {})]}
        proof = {'kind': 'ax6000-imagebuilder-approval', 'approved': True, 'recipe_commit': side['producer_commit'],
                 'source_commit': self.n.SOURCE, 'cohort': self.n.COHORT, 'package_manager': 'apk',
                 'build_id': old['build_id'], 'kernel_version': self.n.ABI, 'archive_sha256': old['imagebuilder']['sha256'],
                 'archive_size': old['imagebuilder']['size'], 'profile_sha256': side['metadata']['profile.json']['sha256'],
                 'full_native_status_sha256': side['native_status']['sha256'], 'full_native_evidence_sha256': side['native_evidence']['sha256'],
                 'source_context_verified': True, 'native_bank_verified': True, 'signatures_verified': True, 'private_keys_absent': True}
        for name, field in [('verification-result.json', 'verification_result_sha256'), ('source-transform.json', 'source_transform_sha256'),
                            ('layout-context.json', 'layout_context_sha256'), ('private-key-context-scan.json', 'private_key_scan_sha256'),
                            ('apk-semantic.json', 'apk_semantic_verification_sha256')]: proof[field] = refs[name]['sha256']
        side['ib_approval'] = self.file('ib/approval.json', json.dumps(proof).encode())
        self.n.check_ib(side, old, {'one': {}, 'two': {}})
        (self.root / 'ib/source-transform.json').write_bytes(b'{}')
        with self.assertRaises(ValueError): self.n.check_ib(side, old, {'one': {}, 'two': {}})
        side['ib_approval'] = self.file('ib/approval.json', json.dumps({**proof, 'archive_sha256': '0' * 64}).encode())
        with self.assertRaises(ValueError): self.n.check_ib(side, old, {'one': {}, 'two': {}})

    def test_root_payload_policy_allows_only_constructor_seed_installer_and_app_revision(self):
        images = {phase: {self.n.CLIENT + 'htdocs/luci-static/resources/ax6000_asu.js': {'sha256': phase[0] * 64, 'size': 5},
                          'files/etc/asu-cohort.json': {'sha256': phase[0] * 64, 'size': 6},
                          'files/' + self.n.INSTALLER: {'sha256': phase[0] * 64}} for phase in ('before', 'after')}
        base = {name: [] for name in ('installed_packages', 'vendor_packages', 'ucode_packages', 'modules', 'firmware')}
        base.update(installed_kernel={'Version': self.n.ABI}, trusted_key_fingerprint='key', active_feeds=5,
                    apk_executable_present=True, package_manager='apk', apk_policy={'protected': 'fixed'}, package_only_absent=['tailscale'])
        evidence = {}
        for phase, release in [('before', '2'), ('after', '3')]:
            root = copy.deepcopy(base)
            root['optional_features'] = {'packages': {'luci-app-attendedsysupgrade': '20261021.2-r' + release,
                       'attendedsysupgrade-common': '10-r2', 'pbr': 'fixed'}, 'files': {'unchanged': {'sha256': '0' * 64}}}
            for name, source in [(self.n.MODULE, self.n.CLIENT + 'htdocs/luci-static/resources/ax6000_asu.js'),
                                 ('etc/asu-cohort.json', 'files/etc/asu-cohort.json')]:
                root['optional_features']['files'][name] = {**images[phase][source], 'mode': '0644'}
            root['repository_files'] = {self.n.INSTALLER: {**images[phase]['files/' + self.n.INSTALLER], 'mode': '0755'},
                                        'etc/asu-cohort.json': {'sha256': images[phase]['files/etc/asu-cohort.json']['sha256'], 'mode': '0644'},
                                        'repository.pub': {'sha256': '1' * 64}}
            evidence[phase] = {'layouts': {name: {'root': copy.deepcopy(root)} for name in ('stock', 'mtkuboot', 'ubootmod')}}
        self.n.root_delta(evidence['before'], evidence['after'], images)
        for mutate in (lambda x: x['optional_features']['packages'].update(pbr='changed'),
                       lambda x: x['optional_features']['packages'].update(**{'attendedsysupgrade-common': '10-r3'}),
                       lambda x: x['optional_features']['files']['unchanged'].update(sha256='2' * 64),
                       lambda x: x['repository_files']['repository.pub'].update(sha256='3' * 64),
                       lambda x: x['repository_files']['etc/asu-cohort.json'].update(sha256='3' * 64),
                       lambda x: x.update(modules=['different vendor']),
                       lambda x: x['apk_policy'].update(protected='changed')):
            changed = copy.deepcopy(evidence['after']); mutate(changed['layouts']['stock']['root'])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.n.root_delta(evidence['before'], changed, images)

    @unittest.skipUnless(os.environ.get('APK'), 'Set APK to the trusted EC6 host tool')
    def test_real_tiny_app_archives_prove_constructor_payload_and_modes_without_scripts(self):
        from test_package_format import make_apk
        apk = Path(os.environ['APK']); apk_ref = self.n.full_ref(apk)
        sides = {}
        module_data = (ROOT / 'files/asu-client/ax6000_asu.js').read_bytes()
        for phase, release, helper in [('before', '2', b'old module'), ('after', '3', module_data)]:
            raw = self.root / phase; (raw / 'bin').mkdir(parents=True)
            make_apk(apk, raw / 'bin', 'luci-app-attendedsysupgrade', version='20261021.2-r' + release,
                     arch='noarch', depends=['attendedsysupgrade-common'],
                     payload={self.n.MODULE: helper, 'usr/share/unchanged': b'fixed'})
            source = raw / 'source'; source.mkdir(); sides[phase] = {'raw': str(raw), 'source': str(source)}
        self.n.app_payload(sides['before'], sides['after'], apk_ref)
        changed = self.root / 'after/bin/files-luci-app-attendedsysupgrade/usr/share/unchanged'
        changed.chmod(0o755)
        command = [str(apk), '--no-network', 'mkpkg', '--info', 'name:luci-app-attendedsysupgrade',
                   '--info', 'version:20261021.2-r3', '--info', 'arch:noarch', '--info', 'depends:attendedsysupgrade-common',
                   '--files', str(changed.parents[2]), '--output', str(self.root / 'after/bin' / (self.n.APP + '3.apk'))]
        subprocess.run(command, check=True, capture_output=True)
        with self.assertRaises(ValueError): self.n.app_payload(sides['before'], sides['after'], apk_ref)


if __name__ == '__main__':
    unittest.main()
