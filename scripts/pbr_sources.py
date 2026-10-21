"""Opt-in, matched stable MOSSDeF PBR sources; no upstream installers execute.

Release tags point at README-only main commits. Resolve the matching version
branch's published Makefile bump instead, and bind every downloaded byte.
"""
import hashlib
import gzip
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

PACKAGES = ('pbr', 'luci-app-pbr')
POLICY = 'mossdef-stable'
LIMIT = 8 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fetch_bytes(url):
    headers = {'User-Agent': 'ax6000-packages/1'}
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if token and url.startswith('https://api.github.com/'):
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=40) as response:
        data = response.read(LIMIT + 1)
    require(len(data) <= LIMIT, 'PBR source response exceeds size limit')
    return data


def archive_url(name, commit):
    return f'https://codeload.github.com/mossdef-org/{name}/tar.gz/{commit}'


def cached_archive_path(sdk, name, source):
    require(name in PACKAGES and COMMIT.fullmatch(source['commit']), 'Invalid PBR source cache identity')
    sdk = sdk.resolve(); directory = sdk / 'dl'
    require(not directory.is_symlink() and (not directory.exists() or directory.is_dir()),
            'PBR source cache must remain inside its source tree')
    path = directory / f'ax6000-pbr-{name}-{source["commit"]}.tar.gz'
    require(not path.is_symlink() and (not path.exists() or path.is_file()), 'PBR cache archive must be a regular file')
    return path


def source_archive(sdk, name, source, fetch):
    path = cached_archive_path(sdk, name, source)
    if not path.exists():
        return fetch(source['url'])
    require(path.stat().st_size <= LIMIT, 'PBR cached source exceeds size limit')
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == source['sha256'], 'PBR cached source archive SHA256 mismatch')
    return data


def cache_archive(sdk, name, source, data):
    """Retain locked whole source bytes for independent firmware verification."""
    require(len(data) <= LIMIT and hashlib.sha256(data).hexdigest() == source['sha256'],
            'PBR cached source archive SHA256 mismatch')
    path = cached_archive_path(sdk, name, source)
    if path.exists():
        require(source_archive(sdk, name, source, fetch_bytes) == data, 'PBR cache content differs')
        return
    path.parent.mkdir(exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix='.ax6000-pbr-', dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name); stream.write(data)
        temporary.chmod(0o444)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists(): temporary.unlink()


def recipe_version(text, name):
    def value(key):
        matches = re.findall(r'^' + key + r'\s*:?=\s*([^\s#]+)\s*$', text, re.M)
        require(len(matches) == 1, f'PBR source requires one literal {key}')
        return matches[0]
    require(value('PKG_NAME') == name, 'PBR recipe name mismatch')
    version, release = value('PKG_VERSION'), value('PKG_RELEASE')
    require(VERSION.fullmatch(version) and re.fullmatch(r'0|[1-9][0-9]*', release),
            'PBR recipe requires numeric version and release')
    return version, int(release)


def stable_tag(tag):
    match = re.fullmatch(r'v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)', str(tag))
    if not match:
        return None
    version, release = match[1], int(match[2])
    # Author documentation explicitly marks odd releases as requested test builds.
    if int(version.split('.')[-1]) % 2 or release % 2:
        return None
    return version, release


def release_map(releases):
    require(isinstance(releases, list), 'PBR releases response must be a list')
    result = {}
    for item in releases:
        require(isinstance(item, dict), 'Invalid PBR release record')
        key = stable_tag(item.get('tag_name'))
        if key and item.get('draft') is False and item.get('prerelease') is False:
            require(key not in result, 'Duplicate PBR stable release')
            result[key] = item
    require(result, 'No published stable PBR release found')
    return result


def release_order(value):
    return tuple(map(int, value[0].split('.'))) + (value[1],)


def select_release(pbr_releases, luci_releases):
    first, second = release_map(pbr_releases), release_map(luci_releases)
    left, right = max(first, key=release_order), max(second, key=release_order)
    require(left == right, 'Latest stable PBR and LuCI releases must be matching; pair not yet published')
    return left


def translation_languages(profile):
    return sorted({name.removeprefix('luci-i18n-pbr-') for name in profile.get('packages', [])
                   if name.startswith('luci-i18n-pbr-')})


def translation_version(timestamp, version, release, package_manager='opkg'):
    require(isinstance(timestamp, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', timestamp),
            'PBR translation requires a pinned UTC commit timestamp')
    date = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
    require(package_manager in ('opkg', 'apk'), 'Unsupported PBR translation package manager')
    if package_manager == 'apk':
        # APK version grammar rejects '+pbr'; numeric components retain the
        # same feed timestamp, author version and release in sortable form.
        return date.strftime('%Y%m%d.%H%M%S') + f'.{version}-r{release}'
    return date.strftime('%Y%m%d.%H%M%S') + f'+pbr{version}-r{release}'


def local_feed_timestamp(directory, expected_commit):
    output = subprocess.check_output(['git', '-C', str(directory), 'show', '-s', '--format=%H%n%ct', 'HEAD'],
                                     text=True, timeout=30).strip().splitlines()
    require(len(output) == 2 and output[0] == expected_commit and output[1].isdigit(),
            'PBR translation feed checkout differs from the pinned commit')
    return datetime.fromtimestamp(int(output[1]), timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def validate(profile, lock):
    policy = profile.get('pbr_source')
    value = lock.get('pbr')
    if policy is None:
        require(value is None, 'PBR source lock requires explicit profile opt-in')
        return None
    require(policy == POLICY, 'Unsupported PBR source policy')
    require(set(PACKAGES) <= set(profile.get('packages', [])), 'PBR source policy requires both packages')
    require(isinstance(value, dict), 'PBR source policy requires a matched source lock')
    version, release = value.get('version'), value.get('release')
    require(isinstance(version, str) and VERSION.fullmatch(version) and type(release) is int
            and release >= 0 and stable_tag(f'v{version}-{release}') == (version, release),
            'PBR source requires a stable version and even release')
    packages = value.get('packages')
    require(isinstance(packages, dict) and set(packages) == set(PACKAGES), 'PBR source requires exactly the matching pair')
    require(not set(PACKAGES) & set(lock.get('packages', {})), 'Duplicate PBR package overrides')
    for name, source in packages.items():
        require(isinstance(source, dict), 'PBR source must be an object')
        commit = source.get('commit')
        require(isinstance(commit, str) and COMMIT.fullmatch(commit), 'PBR source requires full commit SHA')
        require(source.get('repository') == f'https://github.com/mossdef-org/{name}.git'
                and source.get('url') == archive_url(name, commit), 'PBR source must use the exact author commit archive')
        require(isinstance(source.get('sha256'), str) and SHA.fullmatch(source['sha256']), 'PBR archive needs SHA256')
    translations = value.get('translations')
    require(isinstance(translations, dict) and set(translations) == set(translation_languages(profile)),
            'PBR translation pins must cover the requested language packages')
    if translations:
        feeds = [item for item in profile.get('feeds', []) if item.get('name') == 'luci']
        require(len(feeds) == 1, 'PBR translations require one pinned LuCI feed')
        pin = lock.get('feeds', {}).get('luci', feeds[0]['commit'])
        manager = profile.get('package_manager', 'opkg')
        require(value.get('translation_package_manager', 'opkg') == manager,
                'PBR translation lock package manager differs from its profile')
        require(value.get('translation_version') == translation_version(
                value.get('translation_commit_timestamp'), version, release, manager),
                'PBR translation version differs from its pinned timestamp and author pair')
        for language, source in translations.items():
            require(re.fullmatch(r'[a-z]{2,3}(?:_[A-Za-z]{2,8})?', language), 'Invalid PBR translation language')
            require(isinstance(source, dict) and source.get('feed') == 'luci' and source.get('commit') == pin
                    and source.get('path') == f'applications/luci-app-pbr/po/{language}/pbr.po'
                    and isinstance(source.get('sha256'), str) and SHA.fullmatch(source['sha256']),
                    'PBR translation must match the pinned LuCI feed')
    return value


def read_archive(name, source, pair, data):
    require(len(data) <= LIMIT and hashlib.sha256(data).hexdigest() == source['sha256'], 'PBR archive SHA256 mismatch')
    prefix = f'{name}-{source["commit"]}'
    files = {}; total = 0
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        unpacked = compressed.read(LIMIT + 1)
    require(len(unpacked) <= LIMIT, 'PBR unpacked archive exceeds size limit')
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode='r:') as archive:
        members = archive.getmembers()
        require(len(members) <= 2000, 'PBR archive contains too many entries')
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts and path.parts
                    and path.parts[0] == prefix and path.as_posix() not in seen,
                    'PBR archive path escapes or duplicates its commit root')
            seen.add(path.as_posix())
            require(member.isdir() or member.isfile(), 'PBR archive links and special files are forbidden')
            if member.isdir(): continue
            total += member.size
            require(0 <= member.size <= LIMIT and total <= LIMIT, 'PBR unpacked archive exceeds size limit')
            require(len(path.parts) > 1, 'PBR archive file occupies its root')
            files[PurePosixPath(*path.parts[1:]).as_posix()] = archive.extractfile(member).read()
    require('Makefile' in files, 'PBR archive is README-only or missing its recipe')
    require(recipe_version(files['Makefile'].decode(), name) == (pair['version'], pair['release']),
            'PBR source recipe version differs from the published stable pair')
    required = (('files/etc/init.d/pbr', 'files/etc/config/pbr', 'files/lib/pbr/pbr.uc', 'files/lib/pbr/pkg.uc')
                if name == 'pbr' else ('root/usr/share/rpcd/ucode/luci.pbr', 'htdocs/luci-static/resources/pbr/status.js'))
    require(all(path in files for path in required), 'PBR source archive missing its implementation')
    return files


def verify_compatibility(sources):
    checks = [('pbr', 'files/etc/init.d/pbr', r"initCompat=['\"]([0-9]+)['\"]"),
              ('pbr', 'files/lib/pbr/pkg.uc', r"compat:\s*['\"]([0-9]+)['\"]"),
              ('luci-app-pbr', 'root/usr/share/rpcd/ucode/luci.pbr', r'rpcdCompat\s*=\s*([0-9]+)'),
              ('luci-app-pbr', 'htdocs/luci-static/resources/pbr/status.js', r'LuciCompat\(\)\s*\{\s*return\s+([0-9]+)')]
    versions = []
    for name, path, pattern in checks:
        values = re.findall(pattern, sources[name][path].decode())
        require(len(values) == 1, 'PBR compatibility stamp missing or ambiguous')
        versions.extend(values)
    require(len(set(versions)) == 1, 'PBR and LuCI compatibility stamps differ')


def resolve(profile, feed_pins, fetch=None):
    if profile.get('pbr_source') is None: return None
    require(profile['pbr_source'] == POLICY, 'Unsupported PBR source policy')
    fetch = fetch or fetch_bytes
    def api(name, endpoint):
        return json.loads(fetch(f'https://api.github.com/repos/mossdef-org/{name}/{endpoint}'))
    releases = {name: api(name, 'releases?per_page=100') for name in PACKAGES}
    version, release = select_release(*(releases[name] for name in PACKAGES))
    result = {'version': version, 'release': release, 'packages': {}, 'translations': {}}
    sources = {}
    for name in PACKAGES:
        published = release_map(releases[name])[(version, release)].get('published_at')
        require(isinstance(published, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', published),
                'PBR release requires a publication timestamp')
        commits = api(name, f'commits?sha={version}&path=Makefile&per_page=100')
        require(isinstance(commits, list), 'Invalid PBR version branch history')
        pin = None
        for item in commits:
            commit = item.get('sha')
            require(isinstance(commit, str) and COMMIT.fullmatch(commit), 'Invalid PBR history commit')
            date = item.get('commit', {}).get('committer', {}).get('date', '')
            if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', date) or date > published:
                continue
            text = fetch(f'https://raw.githubusercontent.com/mossdef-org/{name}/{commit}/Makefile').decode()
            if recipe_version(text, name) == (version, release):
                pin = commit; break
        require(pin is not None, 'Published PBR source version not found in its version branch')
        url = archive_url(name, pin); data = fetch(url)
        source = {'repository': f'https://github.com/mossdef-org/{name}.git', 'commit': pin,
                  'url': url, 'sha256': hashlib.sha256(data).hexdigest()}
        sources[name] = read_archive(name, source, result, data)
        result['packages'][name] = source
    verify_compatibility(sources)
    feeds = [feed for feed in profile.get('feeds', []) if feed.get('name') == 'luci']
    for language in translation_languages(profile):
        require(len(feeds) == 1 and re.fullmatch(r'[a-z]{2,3}(?:_[A-Za-z]{2,8})?', language),
                'PBR translation requires one LuCI feed and valid language')
        repository = feeds[0]['url'].removesuffix('.git')
        require(re.fullmatch(r'https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository),
                'PBR translation requires a pinned GitHub LuCI feed')
        pin = feed_pins.get('luci', feeds[0]['commit'])
        require(COMMIT.fullmatch(pin), 'PBR translation requires a full commit')
        path = f'applications/luci-app-pbr/po/{language}/pbr.po'
        url = repository.replace('https://github.com/', 'https://raw.githubusercontent.com/') + f'/{pin}/{path}'
        result['translations'][language] = {'feed': 'luci', 'commit': pin, 'path': path,
                                          'sha256': hashlib.sha256(fetch(url)).hexdigest()}
    if result['translations']:
        owner_repo = feeds[0]['url'].removeprefix('https://github.com/').removesuffix('.git')
        commit = json.loads(fetch(f'https://api.github.com/repos/{owner_repo}/commits/{pin}'))
        require(commit.get('sha') == pin, 'PBR translation commit response differs from the pin')
        timestamp = commit.get('commit', {}).get('committer', {}).get('date')
        manager = profile.get('package_manager', 'opkg')
        result['translation_version'] = translation_version(timestamp, version, release, manager)
        result['translation_package_manager'] = manager
        result['translation_commit_timestamp'] = timestamp
    validate(profile, {'pbr': result, 'feeds': feed_pins})
    return result


def apply(profile, lock, sdk, fetch=None):
    value = validate(profile, lock)
    if value is None: return
    sdk = sdk.resolve(); fetch = fetch or fetch_bytes
    archives = {name: source_archive(sdk, name, meta, fetch) for name, meta in value['packages'].items()}
    sources = {name: read_archive(name, meta, value, archives[name])
               for name, meta in value['packages'].items()}
    verify_compatibility(sources)
    recipes = {}; links = []; translations = {}
    for name in PACKAGES:
        candidates = sorted({path.resolve() for path in (sdk / 'feeds').glob(f'*/**/{name}/Makefile')})
        require(len(candidates) == 1 and candidates[0].is_relative_to(sdk),
                f'PBR override {name} needs one unambiguous local feed recipe')
        recipes[name] = candidates[0].parent
        require(not (sdk / 'package/ax6000-overrides' / name).exists(), 'PBR override already exists')
        for link in (sdk / 'package/feeds').glob(f'*/{name}'):
            require(link.is_symlink(), 'Refusing to replace a non-symlink PBR feed package')
            links.append(link)
    for language, meta in value['translations'].items():
        path = recipes['luci-app-pbr'] / 'po' / language / 'pbr.po'
        require(path.resolve().is_relative_to(sdk) and path.is_file() and not path.is_symlink(),
                'Pinned PBR translation is missing from the local LuCI recipe')
        data = path.read_bytes()
        require(hashlib.sha256(data).hexdigest() == meta['sha256'], 'Pinned PBR translation SHA256 mismatch')
        translations[language] = data
    if translations:
        pin = next(iter(value['translations'].values()))['commit']
        require(local_feed_timestamp(sdk / 'feeds/luci', pin) == value['translation_commit_timestamp'],
                'PBR translation commit timestamp differs from the actual pinned feed')
    require((sdk / 'feeds/luci/luci.mk').is_file(), 'PBR LuCI override requires pinned luci.mk')
    for name, meta in value['packages'].items():
        cache_archive(sdk, name, meta, archives[name])
    # Prepare both complete overlays before changing any package-selection links.
    with tempfile.TemporaryDirectory(prefix='.pbr-source-', dir=sdk) as temporary:
        staging = Path(temporary)
        for name, files in sources.items():
            target = staging / name; target.mkdir()
            for path, data in files.items():
                if path != 'Makefile' and path.split('/')[0] not in ('files', 'htdocs', 'root', 'po'): continue
                destination = target / path; destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                destination.chmod(0o644)
            if name == 'luci-app-pbr':
                recipe = target / 'Makefile'; text = recipe.read_text()
                text, count = re.subn(r'^include\s+\.\./\.\./luci\.mk\s*$',
                                      'include $(TOPDIR)/feeds/luci/luci.mk', text, flags=re.M)
                require(count == 1, 'PBR LuCI source requires exactly one relocatable luci.mk include')
                if translations:
                    text = 'PKG_PO_VERSION:=' + value['translation_version'] + '\n' + text
                recipe.write_text(text)
                for language, data in translations.items():
                    path = target / 'po' / language / 'pbr.po'; path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                    path.chmod(0o644)
        overlay = sdk / 'package/ax6000-overrides'; overlay.mkdir(parents=True, exist_ok=True)
        for name in PACKAGES: shutil.move(str(staging / name), str(overlay / name))
        for link in links: link.unlink()
