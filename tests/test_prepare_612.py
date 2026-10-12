"""Independent SDK contract fixtures for the two vendor 6.12 cohorts."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('prepare_612', ROOT / 'scripts/prepare.py')
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


def channel_profile():
    commit = 'ae65e1de69971b5a2e3cf7e39390ee93f274d488'
    identifier = 'redmi-ax6000-612-recommended'
    build_id = identifier + '-' + commit[:12] + '-' + 'b' * 12
    repository = 'https://github.com/chasey-dev/immortalwrt-mt798x-rebase.git'
    return {
        'schema_version': 1, 'enabled': True, 'id': identifier,
        'channel': 'recommended', 'build_id': build_id,
        'publication': {'repository': 'valujin/ax6000-packages-6.12',
                        'site_url': 'https://valujin.github.io/ax6000-packages-6.12',
                        'firmware_assets': 'github-release'},
        'firmware': {'repository': repository, 'commit': commit,
                     'device': 'xiaomi_redmi-router-ax6000-stock',
                     'devices': [{'device': 'xiaomi_redmi-router-ax6000-' + layout,
                                  'layout': layout}
                                 for layout in ('stock', 'mtkuboot', 'ubootmod')],
                     'kernel_version': '6.12.108~' + 'a' * 32 + '-r1',
                     'target': 'mediatek', 'subtarget': 'filogic',
                     'architecture': 'aarch64_cortex-a53'},
        'sdk': {'url': 'https://github.com/valujin/ax6000-packages-6.12/releases/download/'
                       'firmware-' + build_id + '/immortalwrt-sdk-filogic.tar.zst',
                'sha256': 'b' * 64},
        'feeds': [{'name': 'base', 'url': repository, 'commit': commit, 'root': 'package'},
                  {'name': 'packages', 'url': 'https://github.com/immortalwrt/packages.git',
                   'commit': 'c' * 40}],
        'packages': ['pbr'], 'all_kmods': False,
    }


class ChannelContractTests(unittest.TestCase):
    def setUp(self):
        self.profile = channel_profile()

    def test_exact_cohort_is_accepted(self):
        prepare.validate(self.profile, {})

    def test_channel_and_pinned_base_cannot_diverge(self):
        for field, value in [('channel', 'latest'), ('id', 'redmi-ax6000-612-latest')]:
            with self.subTest(field=field):
                profile = copy.deepcopy(self.profile)
                profile[field] = value
                with self.assertRaises(ValueError):
                    prepare.validate(profile, {})

    def test_foreign_or_moving_sdk_url_rejected(self):
        for url in ('https://example.com/sdk.tar.zst',
                    'https://github.com/valujin/ax6000-packages-6.12/releases/latest/download/sdk.tar.zst'):
            with self.subTest(url=url):
                self.profile['sdk']['url'] = url
                with self.assertRaises(ValueError):
                    prepare.validate(self.profile, {})

    def test_missing_or_duplicate_layout_rejected(self):
        original = copy.deepcopy(self.profile['firmware']['devices'])
        for devices in (original[:2], original + [original[0]]):
            with self.subTest(devices=devices):
                self.profile['firmware']['devices'] = devices
                with self.assertRaises(ValueError):
                    prepare.validate(self.profile, {})

    def test_wrong_publication_site_rejected(self):
        self.profile['publication']['site_url'] += '/channels/latest'
        with self.assertRaises(ValueError):
            prepare.validate(self.profile, {})

    def test_base_root_is_mandatory_and_cannot_move(self):
        mutations = ({'root': '../package'}, {'root': None}, {'commit': 'd' * 40},
                     {'monitor_ref': 'refs/heads/25.12'})
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                profile = copy.deepcopy(self.profile)
                profile['feeds'][0].update(mutation)
                with self.assertRaises(ValueError):
                    prepare.validate(profile, {})
        del self.profile['feeds'][0]['root']
        with self.assertRaises(ValueError):
            prepare.validate(self.profile, {})

    def test_root_flag_not_allowed_on_external_feed(self):
        self.profile['feeds'][1]['root'] = 'package'
        with self.assertRaises(ValueError):
            prepare.validate(self.profile, {})

    def test_root_base_emits_native_sdk_syntax(self):
        with tempfile.TemporaryDirectory() as temporary:
            sdk = Path(temporary)
            prepare.configure_feeds(self.profile, {}, sdk)
            lines = (sdk / 'feeds.conf').read_text().splitlines()
            base = self.profile['feeds'][0]
            self.assertEqual(lines[0], 'src-git --root=package base ' + base['url'] + '^' + base['commit'])
            self.assertEqual(lines[1], 'src-git packages https://github.com/immortalwrt/packages.git^' + 'c' * 40)

    def test_sdk_selection_explicitly_disables_apk_and_verify_rejects_reenabled_apk(self):
        with tempfile.TemporaryDirectory() as temporary:
            sdk = Path(temporary)
            (sdk / 'tmp').mkdir()
            (sdk / 'tmp/.packageinfo').write_text('Package: pbr\n')
            (sdk / 'tmp/.config-package.in').write_text('config PACKAGE_pbr\n')
            (sdk / '.config').write_text('CONFIG_USE_APK=y\n')
            prepare.select_packages(self.profile, sdk)
            text = (sdk / '.config').read_text()
            self.assertNotIn('CONFIG_USE_APK=y', text)
            self.assertIn('# CONFIG_USE_APK is not set\n', text)
            prepare.verify_selection(self.profile, sdk)
            (sdk / '.config').write_text(text.replace('# CONFIG_USE_APK is not set', 'CONFIG_USE_APK=y'))
            with self.assertRaisesRegex(ValueError, 'APK|opkg'):
                prepare.verify_selection(self.profile, sdk)


class FeedRootCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.sdk = Path(self.temporary.name)
        self.clone = self.sdk / 'feeds/base_root'
        (self.clone / 'package').mkdir(parents=True)
        subprocess.run(['git', 'init', '-q', str(self.clone)], check=True)
        subprocess.run(['git', '-C', str(self.clone), '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.invalid', 'commit', '-q', '--allow-empty', '-m', 'fixture'], check=True)
        pin = subprocess.check_output(['git', '-C', str(self.clone), 'rev-parse', 'HEAD'], text=True).strip()
        self.profile = {'feeds': [{'name': 'base', 'root': 'package', 'commit': pin}]}
        self.link = self.sdk / 'feeds/base'
        self.link.symlink_to('base_root/package')

    def test_real_root_clone_and_exact_link_accepted(self):
        prepare.verify_feeds(self.profile, {}, self.sdk)

    def test_wrong_root_link_rejected_even_when_git_head_resolves(self):
        self.link.unlink()
        self.link.symlink_to('base_root')
        with self.assertRaisesRegex(ValueError, 'root|link'):
            prepare.verify_feeds(self.profile, {}, self.sdk)

    def test_plain_directory_is_not_root_feed_link(self):
        self.link.unlink()
        self.link.mkdir()
        with self.assertRaises(ValueError):
            prepare.verify_feeds(self.profile, {}, self.sdk)

    def test_wrong_clone_commit_rejected(self):
        with self.assertRaisesRegex(ValueError, 'locked'):
            prepare.verify_feeds(self.profile, {'feeds': {'base': '0' * 40}}, self.sdk)


if __name__ == '__main__':
    unittest.main()
