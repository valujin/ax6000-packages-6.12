#!/usr/bin/env bash
# Bootstrap the publication decoder independently from every imported SDK/RAW.
# Installs nothing on the host; all outputs belong to a new explicit work dir.
set -euo pipefail
exec python3 - "$@" <<'PY'
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

APK_COMMIT = 'b5a31c0d865342ad80be10d68f1bb3d3ad9b0866'
APK_TOP = 'apk-tools-' + APK_COMMIT
INPUTS = {
    'apk': {
        'filename': 'apk-tools-b5a31c0.tar.gz',
        'url': 'https://codeload.github.com/alpinelinux/apk-tools/tar.gz/' + APK_COMMIT,
        'sha256': '598056e338fa96af030b0f6f2127cc7df151e6f078b0e44a5cae95cc4bba1f79',
        'size': 384352,
    },
    'meson': {
        'filename': 'meson-1.6.1-py3-none-any.whl',
        'url': 'https://files.pythonhosted.org/packages/d2/f3/9d53c24a7113e08879b14117f83e7105251e6ecf7e03bb7c04926888db9c/meson-1.6.1-py3-none-any.whl',
        'sha256': '3f41f6b03df56bb76836cc33c94e1a404c3584d48b3259540794a60a21fad1f9',
        'size': 974359,
    },
}
OPTIONS = ['-Ddocs=disabled', '-Dhelp=disabled', '-Dlua=disabled', '-Dpython=disabled',
           '-Dtests=disabled', '-Dzstd=enabled', '-Durl_backend=wget',
           '-Dcrypto_backend=openssl', '-Dminimal=false', '-Ddefault_library=static']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and '..' not in path.parts and '\\' not in name,
            'unsafe archive path')
    return path


def source_members(archive):
    members = archive.getmembers()
    require(0 < len(members) <= 5000, 'unexpected APK source archive member count')
    names = set()
    total = 0
    for member in members:
        path = safe_name(member.name)
        require(path.parts[0] == APK_TOP and str(path) not in names, 'unexpected APK source topdir or duplicate')
        names.add(str(path))
        require(member.isdir() or member.isfile() or
                (member.issym() and str(path) == APK_TOP + '/src/apk-static.c' and member.linkname == 'apk.c'),
                'unsupported APK source archive entry')
        total += member.size
        require(0 <= member.size <= 8 * 1024**2 and total <= 32 * 1024**2, 'APK source archive is too large')
    require(APK_TOP + '/meson.build' in names and APK_TOP + '/src/apk.c' in names,
            'APK source archive lacks required files')
    return members


def extract_source(path, destination):
    with tarfile.open(path, 'r:gz') as archive:
        members = source_members(archive)  # Complete validation precedes extraction.
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(member.mode & 0o777)
        for member in members:
            if member.issym():
                target = destination / member.name
                require((target.parent / member.linkname).is_file(), 'APK source symlink target missing')
                target.symlink_to(member.linkname)


def verify_wheel(path):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= 2000, 'unexpected Meson wheel member count')
        names = set()
        total = 0
        for entry in entries:
            safe_name(entry.filename)
            require(entry.filename not in names, 'duplicate Meson wheel entry')
            names.add(entry.filename)
            total += entry.file_size
            require(entry.file_size <= 8 * 1024**2 and total <= 32 * 1024**2, 'Meson wheel is too large')
        require('mesonbuild/mesonmain.py' in names, 'Meson wheel lacks its module')


def obtain(spec, downloads, cache):
    target = downloads / spec['filename']
    if cache is not None:
        source = cache / spec['filename']
        require(source.is_file() and not source.is_symlink(), 'cached APK host bootstrap input missing or symlink')
        require(source.stat().st_size == spec['size'] and sha256(source) == spec['sha256'],
                'cached APK host bootstrap input SHA256/size mismatch')
        shutil.copyfile(source, target)
    else:
        with urllib.request.urlopen(spec['url'], timeout=30) as source, target.open('xb') as output:
            size = 0
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                require(size <= spec['size'], 'APK host bootstrap download exceeds pinned size')
                output.write(chunk)
    require(target.stat().st_size == spec['size'] and sha256(target) == spec['sha256'],
            'APK host bootstrap input SHA256/size mismatch')
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description='Build pinned host APK without installing host packages')
    parser.add_argument('--work-dir', type=Path, required=True, help='Required new, non-existing output directory')
    parser.add_argument('--source-cache', type=Path, help='Optional offline directory containing both exact pinned inputs')
    args = parser.parse_args(argv)
    work = args.work_dir.absolute()
    require(not work.exists() and not work.is_symlink(), 'APK host work directory must be fresh')
    for executable in ('cc', 'ninja', 'pkg-config'):
        require(shutil.which(executable), 'APK host prerequisite missing: ' + executable)
    work.mkdir(parents=True, exist_ok=False)
    downloads = work / 'downloads'
    downloads.mkdir()
    source = obtain(INPUTS['apk'], downloads, args.source_cache)
    wheel = obtain(INPUTS['meson'], downloads, args.source_cache)
    verify_wheel(wheel)
    extract_source(source, work)
    allowed = os.sched_getaffinity(0)
    require(allowed, 'APK host build needs a CPU affinity')
    os.sched_setaffinity(0, {min(allowed)})
    os.nice(max(0, 19 - os.nice(0)))
    memory = 2 * 1024**3
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    limit = memory if hard == resource.RLIM_INFINITY else min(memory, hard)
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    environment = os.environ.copy()
    for name in ('PYTHONHOME', 'CC', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'AR', 'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR'):
        environment.pop(name, None)
    environment.update(PYTHONPATH=str(wheel), PYTHONNOUSERSITE='1', CC='cc', AR='ar')
    with (work / 'build.log').open('w') as log:
        for command in ([sys.executable, '-m', 'mesonbuild.mesonmain', 'setup', 'build', APK_TOP, *OPTIONS],
                        ['ninja', '-C', 'build', '-j1']):
            subprocess.run(command, cwd=work, env=environment, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    binary = work / 'build/src/apk'
    version = subprocess.check_output([str(binary), '--version'], text=True, timeout=10).strip()
    require(version.startswith('apk-tools 3.0.5, compiled for '), 'unexpected trusted host APK version')
    proof = {'schema_version': 1, 'source': INPUTS, 'source_commit': APK_COMMIT, 'meson_options': OPTIONS,
             'limits': {'cpus': sorted(os.sched_getaffinity(0)), 'jobs': 1, 'address_space_bytes': limit},
             'binary': {'path': str(binary), 'size': binary.stat().st_size, 'sha256': sha256(binary), 'version': version},
             'build_log_sha256': sha256(work / 'build.log')}
    (work / 'tool-proof.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'apk': str(binary), 'proof': str(work / 'tool-proof.json'), 'version': version}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise SystemExit('build-apk-host: ' + str(error))
PY
