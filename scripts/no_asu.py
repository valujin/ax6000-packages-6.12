"""Recommended-only images without attended sysupgrade; historical artifacts stay readable."""
from pathlib import Path
import re

PACKAGES={'auc','owut','attendedsysupgrade-common','luci-app-attendedsysupgrade'}
PATHS={'etc/asu-cohort.json','etc/uci-defaults/99-ax6000-asu',
       'www/luci-static/resources/ax6000_asu.js',
       'www/luci-static/resources/view/status/include/11_upgrades.js',
       'usr/bin/auc','usr/sbin/auc'}


def require(ok,message):
    if not ok:raise ValueError(message)


def package(name):
    return name in PACKAGES or name.startswith('luci-i18n-attendedsysupgrade-')


def path(name):
    return name in PATHS or any('attendedsysupgrade' in part or part in {'ax6000_asu.js','auc','owut'}
                               for part in Path(name).parts)


def validate(profile):
    if 'exclude_asu' in profile:require(type(profile['exclude_asu']) is bool,'exclude_asu must be boolean')
    if profile.get('exclude_asu') is not True:return
    require(profile.get('channel')=='recommended' and profile.get('package_manager')=='apk',
            'ASU-free builds require recommended APK')
    require('asu' not in profile and not any(package(n) for key in ('packages','image_packages')
            for n in profile.get(key,[])), 'ASU policy/packages are excluded')


def symbols(config,available=()):
    names=PACKAGES|{n for n in available if package(n)}
    names|={n for n in re.findall(r'^(?:# )?CONFIG_PACKAGE_([^=\s]+)',config,re.M) if package(n)}
    return {'IB':'n','IB_STANDALONE':'n',**{'PACKAGE_'+n:'n' for n in names}}


def verify_config(config):
    selected=re.findall(r'^CONFIG_PACKAGE_([^=\n]+)=[my]$',config,re.M)
    require(not any(package(n) for n in selected),'ASU package remains selected')
    require(not re.search(r'^CONFIG_IB(?:_STANDALONE)?=[my]$',config,re.M),'ASU ImageBuilder remains selected')


def configure(profile,source,check_only=False):
    validate(profile)
    if profile.get('exclude_asu') is not True:return
    source=Path(source);root=source/'files'
    require(not root.is_symlink(),'Linked source overlay refused')
    if not root.exists():return
    for item in sorted(root.rglob('*'),key=lambda p:len(p.parts),reverse=True):
        relative=item.relative_to(root).as_posix()
        if not path(relative):continue
        require(not item.is_symlink() and not any(p.is_symlink() for p in item.parents), 'Linked ASU overlay refused')
        require(not check_only,'ASU overlay remains: '+relative)
        if item.is_dir():item.rmdir()
        else:
            require(item.is_file(),'Special ASU overlay refused');item.unlink()


def assert_absent(installed,paths,symlinks=None):
    require(not any(package(n) for n in installed),'ASU package remains in actual image')
    require(not any(path(n) for n in paths),'ASU payload remains in actual image')
    require(not any(path(v.decode('utf-8') if isinstance(v,bytes) else v)
                    for v in (symlinks or {}).values()),'ASU symlink target remains in actual image')


def build_profile(profile):
    # Non-channel legacy helpers stay usable for historical fixture validation;
    # their checked-in source profile is disabled and has no workflow.
    if profile.get("channel") is None:return
    require(profile.get('exclude_asu') is True,'Build requires the new recommended ASU-free generation')
    validate(profile)
