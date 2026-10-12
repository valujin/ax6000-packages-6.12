import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import firmware_layouts as layouts

ABI = '6.12.108~' + 'a' * 32 + '-r1'
DEVICES = [{'device': 'xiaomi_redmi-router-ax6000-' + x, 'layout': x}
           for x in ('stock', 'mtkuboot', 'ubootmod')]


def fixture(root):
    target = root / 'bin/targets/mediatek/filogic'
    target.mkdir(parents=True)
    profile = {'id': 'redmi-ax6000-612-recommended', 'channel': 'recommended',
               'build_id': 'redmi-ax6000-612-recommended-' + 'b' * 12 + '-' + 'c' * 12,
               'publication': {'repository': 'valujin/ax6000-packages-6.12',
                               'site_url': 'https://valujin.github.io/ax6000-packages-6.12',
                               'firmware_assets': 'github-release'},
               'firmware': {'commit': 'b' * 40, 'repository': 'https://github.com/chasey-dev/immortalwrt-mt798x-rebase.git',
                            'kernel_version': ABI, 'target': 'mediatek', 'subtarget': 'filogic',
                            'architecture': 'aarch64_cortex-a53', 'device': DEVICES[0]['device'],
                            'devices': copy.deepcopy(DEVICES)}}
    native = {'target': 'mediatek/filogic', 'arch_packages': 'aarch64_cortex-a53',
              'linux_kernel': {'version': '6.12.108', 'vermagic': 'a' * 32, 'release': '1'}, 'profiles': {}}
    for item in DEVICES:
        suffix = 'squashfs-sysupgrade.itb' if item['layout'] == 'ubootmod' else 'squashfs-sysupgrade.bin'
        name = 'immortalwrt-mediatek-filogic-' + item['device'] + '-' + suffix
        payload = ('independent-' + item['layout']).encode()
        (target / name).write_bytes(payload)
        native['profiles'][item['device']] = {'supported_devices': [item['device'].replace('xiaomi_', 'xiaomi,')],
            'images': [{'name': name, 'sha256': hashlib.sha256(payload).hexdigest(), 'type': 'sysupgrade', 'filesystem': 'squashfs'}]}
    (target / 'profiles.json').write_text(json.dumps(native))
    (target / 'mt7986-ram-ddr3-bl2.bin').write_bytes(b'generic BL2 must never be offered')
    sdk = target / 'immortalwrt-sdk-mediatek-filogic.tar.zst'
    sdk.write_bytes(b'fixture archive identity')
    profile['sdk'] = {'url': layouts.firmware_release_url(profile, sdk.name),
                      'sha256': hashlib.sha256(sdk.read_bytes()).hexdigest()}
    manifest = {'build_id': profile['build_id'], 'source_commit': profile['firmware']['commit'],
                'kernel_version': ABI, 'files': [{'path': p.relative_to(root).as_posix(),
                'size': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                for p in sorted(target.iterdir())]}
    return profile, native, manifest


class LayoutsTests(unittest.TestCase):
    def test_three_images_sdk_native_metadata_and_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile, _, manifest = fixture(root)
            assets = layouts.collect_firmware_assets(root, profile, manifest)
            self.assertEqual({x['layout'] for x in assets if x['kind'] == 'sysupgrade'}, {'stock', 'mtkuboot', 'ubootmod'})
            self.assertEqual(sum(x['kind'] == 'sdk' for x in assets), 1)
            self.assertFalse(any('bl2' in x['filename'] for x in assets))
            self.assertTrue(all(isinstance(x['path'], str) and not x['path'].startswith('/') for x in assets))
            catalog = {'schema_version': 1, 'channel': profile['channel'], 'profile_id': profile['id'],
                       'build_id': profile['build_id'], 'firmware': profile['firmware'], 'sdk': profile['sdk'],
                       'release': {'repository': profile['publication']['repository'], 'id': 12,
                                   'tag': 'firmware-' + profile['build_id'], 'recipe_commit': 'd' * 40},
                       'assets': [{**{k: v for k, v in x.items() if k != 'path'},
                                   'url': layouts.firmware_release_url(profile, x['filename']),
                                   'asset_id': i + 1, 'updated_at': '2026-10-12T10:00:00Z'} for i, x in enumerate(assets)]}
            self.assertEqual(layouts.validate_download_catalog(catalog, profile), catalog)
            for mutate in ('missing', 'foreign', 'sdk', 'abi', 'duplicate', 'url'):
                broken = copy.deepcopy(catalog)
                if mutate == 'missing':
                    broken['assets'] = [x for x in broken['assets'] if x['layout'] != 'mtkuboot']
                elif mutate == 'foreign':
                    broken['assets'][0]['device'] = 'xiaomi_other'
                elif mutate == 'sdk':
                    next(x for x in broken['assets'] if x['kind'] == 'sdk')['sha256'] = '0' * 64
                elif mutate == 'abi':
                    broken['firmware']['kernel_version'] = ABI.replace('108', '112')
                elif mutate == 'duplicate':
                    broken['assets'].append(copy.deepcopy(broken['assets'][0]))
                else:
                    broken['assets'][0]['url'] = 'https://evil.example/asset'
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    layouts.validate_download_catalog(broken, profile)

    def test_missing_layout_wrong_native_identity_and_tampered_bytes_reject(self):
        for problem in ('missing', 'device', 'kernel', 'bytes', 'unlisted', 'symlink'):
            with tempfile.TemporaryDirectory() as directory, self.subTest(problem=problem):
                root = Path(directory)
                profile, native, manifest = fixture(root)
                target = root / 'bin/targets/mediatek/filogic'
                image = next(target.glob('*stock-squashfs-sysupgrade.bin'))
                if problem == 'missing':
                    next(target.glob('*mtkuboot-squashfs-sysupgrade.bin')).unlink()
                elif problem == 'device':
                    native['profiles'][DEVICES[0]['device']]['supported_devices'] = ['xiaomi,other']
                    (target / 'profiles.json').write_text(json.dumps(native))
                elif problem == 'kernel':
                    native['linux_kernel']['vermagic'] = 'f' * 32
                    (target / 'profiles.json').write_text(json.dumps(native))
                elif problem == 'bytes':
                    image.write_bytes(b'tampered')
                elif problem == 'unlisted':
                    (target / 'immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-stock-squashfs-factory.bin').write_bytes(b'wrong stock kind')
                else:
                    image.unlink(); image.symlink_to('/etc/passwd')
                with self.assertRaises(ValueError):
                    layouts.collect_firmware_assets(root, profile, manifest)

    def test_devices_order_and_primary_are_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, _, _ = fixture(Path(directory))
            self.assertEqual(layouts.validate_devices(profile), {x['device']: x['layout'] for x in DEVICES})
            for change in ('order', 'primary', 'foreign'):
                broken = copy.deepcopy(profile)
                if change == 'order':
                    broken['firmware']['devices'].reverse()
                elif change == 'primary':
                    broken['firmware']['device'] = DEVICES[-1]['device']
                else:
                    broken['firmware']['devices'][1]['device'] = 'xiaomi_other'
                with self.subTest(change=change), self.assertRaises(ValueError):
                    layouts.validate_devices(broken)


if __name__ == '__main__':
    unittest.main()
