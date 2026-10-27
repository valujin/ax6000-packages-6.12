"""The manual publisher may add only the reviewed Mesh feature to this ABI."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import mediatek_mesh
import no_asu

spec = importlib.util.spec_from_file_location('mesh_snapshot', ROOT / 'scripts/channel-snapshot.py')
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class MeshReplacement(unittest.TestCase):
    def generations(self):
        old = json.loads((ROOT / 'tests/fixtures/rec-r5-apk-profile.json').read_text())
        new = copy.deepcopy(old)
        new.pop('asu', None)
        new.pop('imagebuilder', None)
        new.update(exclude_asu=True, mediatek_mesh=True, build_id='mesh-native-generation',
                   sdk={'url': 'https://example.org/mesh-sdk.tar.xz', 'sha256': 'a' * 64})
        for field in ('packages', 'image_packages'):
            new[field] = [name for name in old[field] if not no_asu.package(name)]
            new[field] += sorted(mediatek_mesh.PACKAGES - set(new[field]))
        return old, new

    def test_exact_manual_mesh_transition(self):
        old, new = self.generations()
        snapshot.validate_generation_replacement(old, new, old['build_id'])
        with self.assertRaises(ValueError):
            snapshot.validate_generation_replacement(old, new, None)

    def test_reviewed_argon_addition_matches_final_native_profile_delta(self):
        old, new = self.generations()
        for field in ('packages', 'image_packages'):
            new[field].append('luci-theme-argon')
        snapshot.validate_generation_replacement(old, new, old['build_id'])
        with self.assertRaises(ValueError):
            snapshot.validate_generation_replacement(old, new, 'wrong-predecessor')

    def test_argon_does_not_allow_extra_dependencies_themes_removals_or_reordering(self):
        old, new = self.generations()
        for field in ('packages', 'image_packages'):
            new[field].append('luci-theme-argon')
        for field in ('packages', 'image_packages'):
            for extra in ('coreutils-stat', 'luci-theme-material', 'unreviewed'):
                changed = copy.deepcopy(new)
                changed[field].append(extra)
                with self.subTest(field=field, extra=extra), self.assertRaises(ValueError):
                    snapshot.validate_generation_replacement(old, changed, old['build_id'])
            changed = copy.deepcopy(new)
            changed[field].remove('pbr')
            with self.subTest(field=field, change='removal'), self.assertRaises(ValueError):
                snapshot.validate_generation_replacement(old, changed, old['build_id'])
            changed = copy.deepcopy(new)
            changed[field][0], changed[field][1] = changed[field][1], changed[field][0]
            with self.subTest(field=field, change='order'), self.assertRaises(ValueError):
                snapshot.validate_generation_replacement(old, changed, old['build_id'])

    def test_preexisting_argon_must_remain_and_keep_its_original_order(self):
        old, new = self.generations()
        for field in ('packages', 'image_packages'):
            old[field].insert(1, 'luci-theme-argon')
            new[field].insert(1, 'luci-theme-argon')
        snapshot.validate_generation_replacement(old, new, old['build_id'])
        for field in ('packages', 'image_packages'):
            for remove in (False, True):
                changed = copy.deepcopy(new)
                changed[field].remove('luci-theme-argon')
                if not remove: changed[field].append('luci-theme-argon')
                with self.subTest(field=field, remove=remove), self.assertRaises(ValueError):
                    snapshot.validate_generation_replacement(old, changed, old['build_id'])

    def test_mesh_cannot_mask_unrelated_policy_or_package_changes(self):
        old, new = self.generations()
        for field, value in (
            ('firmware', {**new['firmware'], 'kernel_version': '6.12.108~' + 'f' * 32 + '-r1'}),
            ('firmware', {**new['firmware'], 'commit': 'f' * 40}),
            ('apk_key_sha256', 'f' * 64),
            ('packages', new['packages'] + ['unreviewed']),
            ('image_packages', new['image_packages'] + ['tailscale']),
            ('packages', [name for name in new['packages'] if name != 'pbr']),
            ('asu', old['asu']),
            ('channel', 'latest'),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                snapshot.validate_generation_replacement(old, {**new, field: value}, old['build_id'])

    def test_no_asu_predecessor_and_later_mesh_generation(self):
        old, new = self.generations()
        old.pop('asu', None)
        old.pop('imagebuilder', None)
        old['exclude_asu'] = True
        for field in ('packages', 'image_packages'):
            old[field] = [name for name in old[field] if not no_asu.package(name)]
        snapshot.validate_generation_replacement(old, new, old['build_id'])
        later = copy.deepcopy(new)
        later['build_id'] = 'mesh-later-generation'
        later['sdk']['sha256'] = 'b' * 64
        snapshot.validate_generation_replacement(new, later, new['build_id'])
