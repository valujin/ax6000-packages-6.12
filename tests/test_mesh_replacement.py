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
        old = json.loads((ROOT / 'profiles/redmi-ax6000-612-recommended.json').read_text())
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
