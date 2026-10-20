"""Real signatures bind explicit same-ABI generation replacement to its live predecessor."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

import test_channel_snapshot as fixtures

snapshot = fixtures.snapshot
USIGN = os.environ.get('USIGN')


@unittest.skipUnless(USIGN, 'Set USIGN to the official host tool')
class GenerationMigration(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ChannelSnapshots()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        tree, profile = self.fixture.channel('recommended')
        profile.update(packages=['kmod-wireguard', 'tailscale'], image_packages=['tailscale', 'kmod-wireguard'])
        self.rewrite(tree, profile)
        self.old = self.pack(tree, profile, 'old', 20)
        self.other = self.fixture.pack_restore('latest')
        self.before = self.root/'before'
        snapshot.compose_site(None, None, {'recommended': self.old, 'latest': (self.other[5], self.other[3])},
                              self.fixture.repository, self.fixture.key, self.fixture.public, USIGN, self.before, bootstrap=True)
        self.profile = copy.deepcopy(profile)
        self.profile.update(package_only=['tailscale'], image_packages=['kmod-wireguard'])
        self.profile['sdk']['sha256'] = '9'*64
        self.profile['build_id'] = profile['build_id'][:-12]+'9'*12
        self.profile['sdk']['url'] = profile['sdk']['url'].replace(profile['build_id'], self.profile['build_id'])
        self.tree = self.root/'new-channel'
        shutil.copytree(tree, self.tree)

    def rewrite(self, tree, profile):
        (tree/'profile.json').write_text(json.dumps(profile))
        lock = json.loads((tree/'state/lock.json').read_text())
        lock.update(profile_sha256=snapshot.sha256_file(tree/'profile.json'), firmware=profile['firmware'], sdk=profile['sdk'])
        (tree/'state/lock.json').write_text(json.dumps(lock))
        catalog = json.loads((tree/'downloads.json').read_text())
        old_build = catalog['build_id']
        catalog.update(build_id=profile['build_id'], firmware=profile['firmware'], sdk=profile['sdk'])
        catalog['release']['tag'] = 'firmware-'+profile['build_id']
        for asset in catalog['assets']:
            asset['url'] = asset['url'].replace(old_build, profile['build_id'])
            if asset['kind'] == 'sdk': asset['sha256'] = profile['sdk']['sha256']
        (tree/'downloads.json').write_text(json.dumps(catalog))
        self.fixture.sign(tree/'downloads.json', tree/'downloads.sig')

    def pack(self, tree, profile, label, release_id):
        packed = self.root/('packed-'+label)
        plan = snapshot.pack_snapshot(tree, profile['channel'], self.fixture.repository, self.fixture.recipe,
                                      self.fixture.key, self.fixture.public, USIGN, packed)
        archive = packed/'channel.tar.zst'
        pointer = dict(channel=profile['channel'], profile_id=profile['id'], build_id=profile['build_id'],
                       kernel_version=profile['firmware']['kernel_version'], release_id=release_id, tag=plan['tag'],
                       asset_id=release_id+1, archive_sha256=snapshot.sha256_file(archive),
                       archive_size=archive.stat().st_size, manifest_sha256=plan['manifest_sha256'])
        metadata = dict(id=release_id, tag_name=plan['tag'], draft=False, immutable=True, assets=[
            dict(id=release_id+1+i, name=name, size=(packed/name).stat().st_size, state='uploaded', updated_at='now',
                 digest='sha256:'+snapshot.sha256_file(packed/name)) for i, name in enumerate(('channel.tar.zst','channel.tar.zst.sha256'))])
        restored = self.root/('restored-'+label)
        snapshot.restore_snapshot(archive, pointer, metadata, metadata, profile, self.fixture.public, USIGN, restored)
        return restored, pointer

    def replacement(self):
        self.rewrite(self.tree, self.profile)
        return self.pack(self.tree, self.profile, 'new', 40)

    def compose(self, replacement, expected=None, predecessor=None, before=None, output=None):
        before = before or self.before
        return snapshot.compose_site(before/'site-state.json', before/'site-state.sig',
            {'recommended': replacement, 'latest': (self.other[5], self.other[3])}, self.fixture.repository,
            self.fixture.key, self.fixture.public, USIGN, output or self.root/'after',
            replacements={'recommended': (predecessor or self.old, expected or self.old[1]['build_id'])})

    def test_explicit_signed_replacement_preserves_other_channel_bytes(self):
        self.compose(self.replacement())
        original = self.before/'channels/latest'; retained = self.root/'after/channels/latest'
        self.assertEqual({p.relative_to(original).as_posix():p.read_bytes() for p in original.rglob('*') if p.is_file()},
                         {p.relative_to(retained).as_posix():p.read_bytes() for p in retained.rglob('*') if p.is_file()})
        state = snapshot.read_state(self.root/'after/site-state.json', self.root/'after/site-state.sig',
                                    self.fixture.repository, self.fixture.public, USIGN)
        self.assertEqual(state['channels']['recommended']['build_id'], self.profile['build_id'])
        self.assertEqual(state['channels']['latest'], self.other[3])

    def test_daily_composition_still_refuses_generation_change(self):
        with self.assertRaisesRegex(ValueError, 'Daily publication cannot switch'):
            snapshot.compose_site(self.before/'site-state.json', self.before/'site-state.sig',
                {'recommended':self.replacement(),'latest':(self.other[5],self.other[3])}, self.fixture.repository,
                self.fixture.key,self.fixture.public,USIGN,self.root/'after')
        self.assertFalse((self.root/'after').exists())

    def test_wrong_exact_old_id_refuses_before_output(self):
        with self.assertRaisesRegex(ValueError, 'predecessor build'):
            self.compose(self.replacement(), expected='wrong-old-build')
        self.assertFalse((self.root/'after').exists())

    def test_source_abi_architecture_layout_or_other_profile_changes_refused(self):
        old = json.loads((self.old[0]/'channel/profile.json').read_text())
        for name, mutate in (
            ('source', lambda p:p['firmware'].update(commit='1'*40)),
            ('ABI', lambda p:p['firmware'].update(kernel_version='6.12.108~'+'b'*32+'-r1')),
            ('architecture', lambda p:p['firmware'].update(architecture='foreign')),
            ('layouts', lambda p:p['firmware']['devices'].pop()),
            ('requested packages', lambda p:p['packages'].append('extra-package')),
            ('unrelated image removal', lambda p:p.update(image_packages=[])),
        ):
            with self.subTest(name=name):
                changed=copy.deepcopy(self.profile);mutate(changed)
                with self.assertRaises(ValueError):snapshot.validate_generation_replacement(old,changed,old['build_id'])

    def test_replay_or_forged_predecessor_fails_before_output(self):
        new=self.replacement();self.compose(new)
        with self.assertRaisesRegex(ValueError, 'predecessor'):
            self.compose(new, before=self.root/'after', output=self.root/'replay')
        self.assertFalse((self.root/'replay').exists())
        (self.old[0]/'channel/profile.json').write_text('{}')
        with self.assertRaises(ValueError):self.compose(new, output=self.root/'forged')
        self.assertFalse((self.root/'forged').exists())

    def test_manual_authorization_checked_before_publisher_or_release_write(self):
        raw=self.root/'raw';raw.mkdir();(raw/'profile.json').write_text(json.dumps(self.profile))
        state=json.loads((self.before/'site-state.json').read_text())
        with patch.object(snapshot,'fetch_live',return_value=state), patch.object(snapshot,'restore_live_channels',return_value={'recommended':self.old}), \
             patch.object(snapshot.subprocess,'run', wraps=subprocess.run) as command, patch.object(snapshot,'publish_snapshot') as publish:
            with self.assertRaisesRegex(ValueError,'predecessor build'):
                snapshot.publish_channel(raw,None,None,None,'https://fixture.github.io',self.fixture.repository,None,
                    self.root/'manual-work',self.fixture.key,self.fixture.public,USIGN,self.root/'manual-output',replace_build_id='wrong')
            self.assertTrue(all(call.args[0][0] == USIGN for call in command.call_args_list))
            publish.assert_not_called()

    def test_manual_publication_passes_guard_to_composition(self):
        new=self.replacement()
        state=json.loads((self.before/'site-state.json').read_text())
        raw=self.root/'raw';raw.mkdir();(raw/'profile.json').write_bytes((self.tree/'profile.json').read_bytes())
        work=self.root/'manual-success-work'
        original_run=subprocess.run
        def run(command, **kwargs):
            if command[0]=='python3' and command[1].endswith('/scripts/publish.py'):
                shutil.copytree(self.tree,work/'staged')
                return subprocess.CompletedProcess(command,0)
            return original_run(command,**kwargs)
        def fetch(site,repository,public,usign,output,**kwargs):
            output.mkdir()
            for name in ('site-state.json','site-state.sig'):
                (output/name).write_bytes((self.before/name).read_bytes())
            return state
        def restore(pointer,profile,repository,public,usign,output):
            shutil.copytree(new[0],output)
        with patch.dict(os.environ,{'AX6000_RECIPE_COMMIT':self.fixture.recipe}), \
             patch.object(snapshot,'fetch_live',side_effect=fetch), \
             patch.object(snapshot,'restore_live_channels',return_value={'recommended':self.old,'latest':(self.other[5],self.other[3])}), \
             patch.object(snapshot.subprocess,'run',side_effect=run), \
             patch.object(snapshot,'publish_snapshot',return_value=new[1]), \
             patch.object(snapshot,'restore_online',side_effect=restore):
            snapshot.publish_channel(raw,None,None,None,'https://fixture.github.io',self.fixture.repository,None,
                work,self.fixture.key,self.fixture.public,USIGN,self.root/'manual-site',replace_build_id=self.old[1]['build_id'])
        self.assertEqual(json.loads((self.root/'manual-site/site-state.json').read_text())['channels']['recommended'],new[1])
        self.assertTrue((work/'deployment-check.json').is_file())
