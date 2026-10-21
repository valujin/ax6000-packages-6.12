"""Apply the reviewed MediaTek-only DB country UI change to native or SDK source.

DB is already mapped by vendor Lua/ucode to regions [5, 13]. This changes only
its explicit LuCI choice and package release; defaults and backend stay exact.
"""
from pathlib import Path
import hashlib
import os
import tempfile

PACKAGE = 'luci-app-mtwifi-cfg'
NATIVE = Path('package/mtk/applications') / PACKAGE
JAVASCRIPT = Path('root/usr/share') / PACKAGE / 'wireless-mtk.js'
# APK requires a numeric -r revision; OPKG keeps the existing custom revision.
RELEASES = {'66': '2.ax6000db1', '612': '2'}
# Reviewed upstream files at ec9ef10 (6.6), ae65e1d and a99b088 (6.12).
PREIMAGES = {
    '66': ('8042a4d59f860be53a9af8f8ded10d1c84170541144c59ce08d4e283602ee78b',
           '05ac6b5bb37b89b46972f57cc7aaf257010a47cdafa2a5210682f7ab50b73be0'),
    '612': ('08daedef19f06474ec8b196581ac617cd1157cdca2fc1120943f0ac6ab388cdf',
            '1dc93acd6bf75f9f6c20b302ec171af59b64254c3689cea5d2acbb685f2d697a'),
}
# Filled from the reviewed deterministic transform; foreign or mixed states fail.
POSTIMAGES = {
    '66': ('dc1afc0beee7590fb92cffd6ccdf721688cc9cfaa74c423af70850069f6029d8',
           'ecd900b25762b2b155e250cf36a60e3eaeaf056719dd647dcc11d0c7c42b3500'),
    '612': ('b2088523d857e6a7e6229ddc3debdcdf9c5a9c52e51d1af776605695d755a20e',
            '5a7376f526a8f8d80f63bb194a61c9d5e9075d6c94ec2f019dc504aed81e2a12'),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _replace_once(text, before, after):
    _require(text.count(before) == 1, 'reviewed vendor country patch anchor differs')
    return text.replace(before, after, 1)


def _patched_js(data):
    text = data.decode('utf-8')
    start = text.index('var CBIWifiCountryValue = form.Value.extend({')
    end = text.index('\nreturn view.extend({', start)
    country = text[start:end]
    anchor = '\n\t\t\treturn form.Value.prototype.load.apply(this, [section_id]);'
    addition = '''
			if (this.mtwifiCountry) {
				if (!this.keylist || this.keylist.length == 0)
					this.value('', _('driver default'));
				if (this.keylist.indexOf('DB') < 0)
					this.value('DB', _('DB - MediaTek debug domain'));
			}
'''
    country = _replace_once(country, anchor, addition + anchor)
    anchor = ("\t\t\t\tfor (var i = 0; i < countrylist.length; i++)\n"
              "\t\t\t\t\tthis.value(countrylist[i].iso3166, '%s - %s'.format(countrylist[i].iso3166, countrylist[i].country));")
    replacement = ("\t\t\t\tfor (var i = 0; i < countrylist.length; i++) {\n"
                   "\t\t\t\t\tif (this.mtwifiCountry && countrylist[i].iso3166 == 'DB')\n"
                   "\t\t\t\t\t\tcontinue;\n"
                   "\t\t\t\t\tthis.value(countrylist[i].iso3166, '%s - %s'.format(countrylist[i].iso3166, countrylist[i].country));\n"
                   "\t\t\t\t}")
    country = _replace_once(country, anchor, replacement)
    anchor = "\t\tvar typeClass = (this.keylist && this.keylist.length) ? form.ListValue : form.Value;"
    replacement = ("\t\tvar knownValue = !this.mtwifiCountry || cfgvalue == null || cfgvalue == '' ||\n"
                   "\t\t\t(this.keylist && this.keylist.indexOf(cfgvalue) >= 0);\n"
                   "\t\tvar typeClass = (this.keylist && this.keylist.length && knownValue) ? form.ListValue : form.Value;")
    country = _replace_once(country, anchor, replacement)
    text = text[:start] + country + text[end:]
    anchor = """else if (hwtype == 'mtwifi') {
					o = ss.taboption('advanced', CBIWifiCountryValue, 'country', _('Country Code'));
					o.wifiNetwork = radioNet;"""
    text = _replace_once(text, anchor, anchor + '\n\t\t\t\t\to.mtwifiCountry = true;')
    return text.encode('utf-8')


def _patched_makefile(data, release):
    return _replace_once(data.decode('utf-8'), 'PKG_VERSION:=1\n',
                         f'PKG_VERSION:=1\nPKG_RELEASE:={release}\n').encode('utf-8')


def _locate(root):
    candidates = [root / NATIVE]
    for pattern in (f'*/{NATIVE}', f'*/mtk/applications/{PACKAGE}'):
        candidates.extend((root / 'feeds').glob(pattern))
    candidates.extend((root / 'package/feeds').glob(f'*/{PACKAGE}'))
    actual = set()
    for path in candidates:
        if not path.exists():
            continue
        resolved = path.resolve()
        _require(resolved.is_relative_to(root), 'vendor country recipe escapes source root')
        actual.add(resolved)
    _require(len(actual) == 1, 'vendor country patch requires one unambiguous native recipe')
    package = actual.pop()
    for path in (package / JAVASCRIPT, package / 'Makefile'):
        _require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root),
                 'vendor country patch target is absent or escapes source root')
    return package


def _write_atomic(path, data):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            os.fchmod(output.fileno(), path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def apply_vendor_country_patch(source_root):
    """Patch one pinned vendor recipe, accepting only complete before/after pairs.

    Full builds use package/mtk/applications; exported SDKs retain the same recipe
    below feeds/base_root/package. Resolved aliases are counted once. Call after
    extracting/installing native feed recipes, before make defconfig or compile.
    """
    root = Path(source_root).resolve(strict=True)
    package = _locate(root)
    js = package / JAVASCRIPT
    makefile = package / 'Makefile'
    before = (js.read_bytes(), makefile.read_bytes())
    hashes = tuple(map(digest, before))
    matched = [(series, False) for series, pair in PREIMAGES.items() if hashes == pair]
    matched += [(series, True) for series, pair in POSTIMAGES.items() if hashes == pair]
    _require(len(matched) == 1, 'vendor country files differ from reviewed preimage/postimage pair (or partial patch)')
    series, applied = matched[0]
    release = RELEASES[series]
    if not applied:
        after = (_patched_js(before[0]), _patched_makefile(before[1], release))
        _require(tuple(map(digest, after)) == POSTIMAGES[series], 'vendor country patch produced unreviewed bytes')
        _write_atomic(js, after[0])
        _write_atomic(makefile, after[1])
    return {'series': series, 'changed': not applied, 'release': release,
            'package': str(package.relative_to(root)),
            'javascript_sha256': POSTIMAGES[series][0],
            'makefile_sha256': POSTIMAGES[series][1]}
