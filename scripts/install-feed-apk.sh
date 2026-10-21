#!/bin/sh
# Enable a matching APK feed after flashing the matching native firmware.
set -eu
base=${PACKAGE_REPOSITORY_URL:-https://valujin.github.io/ax6000-packages-6.12/channels/recommended}
expected_fingerprint=eaad5e29fcc9ed69
expected_apk_sha256=279ea19b627e16d0807e099de8bd6cf8b69830281defa9bdb9e4ae96f5beb751
fail() { printf '%s\n' "$*" >&2; exit 1; }
case "$base" in
    https://valujin.github.io/ax6000-packages-6.12/channels/recommended|https://valujin.github.io/ax6000-packages-6.12/channels/latest) ;;
    *) fail 'Unexpected APK channel URL' ;;
esac
for tool in wget jsonfilter apk usign sha256sum awk cat cp mv mkdir chmod mktemp id rm wc; do
    command -v "$tool" >/dev/null || fail "Missing tool: $tool"
done
[ "$(id -u)" = 0 ] || fail 'Run on router as root'
for directory in /etc/apk /etc/apk/keys /etc/apk/repositories.d; do
    [ ! -L "$directory" ] && [ -d "$directory" ] && [ -w "$directory" ] || fail "Unsafe APK directory: $directory"
done
metadata_key=/etc/ax6000/repository.pub
[ ! -L /etc/ax6000 ] && [ -d /etc/ax6000 ] && [ ! -L "$metadata_key" ] && [ -f "$metadata_key" ] || fail 'Missing image-pinned metadata key'
[ "$(usign -F -p "$metadata_key")" = "$expected_fingerprint" ] || fail 'Unexpected image metadata signing key'
key=/etc/apk/keys/repository-apk.pem
[ ! -L "$key" ] && [ -f "$key" ] || fail 'Missing image-pinned APK public key'
[ "$(sha256sum "$key" | awk '{print $1}')" = "$expected_apk_sha256" ] || fail 'Unexpected image APK signing key'
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fetch() {
    wget -q -T 30 -O "$tmp/$1" "$2"
    [ "$(wc -c < "$tmp/$1")" -le "$3" ] || fail "Oversized download: $1"
}
# Authenticate profile bytes before they can select a feed, architecture or ABI.
fetch profile.json "$base/profile.json" 1048576
fetch profile.sig "$base/profile.sig" 4096
usign -V -m "$tmp/profile.json" -p "$metadata_key" -x "$tmp/profile.sig"
manager=$(jsonfilter -i "$tmp/profile.json" -e '@.package_manager')
[ "$manager" = apk ] || fail 'Repository is not an APK firmware generation'
[ "$(jsonfilter -i "$tmp/profile.json" -e '@.apk_key_sha256')" = "$expected_apk_sha256" ] || fail 'Signed profile APK key differs'
arch=$(jsonfilter -i "$tmp/profile.json" -e '@.firmware.architecture')
kernel=$(jsonfilter -i "$tmp/profile.json" -e '@.firmware.kernel_version')
profile=$(jsonfilter -i "$tmp/profile.json" -e '@.id')
channel=$(jsonfilter -i "$tmp/profile.json" -e '@.channel')
case "$channel" in recommended|latest) ;; *) fail 'Invalid channel' ;; esac
[ "$base" = "https://valujin.github.io/ax6000-packages-6.12/channels/$channel" ] || fail 'Signed profile belongs to another channel'
[ "$profile" = "redmi-ax6000-612-$channel" ] || fail 'Invalid profile identity'
[ "$arch" = aarch64_cortex-a53 ] && [ "$(apk --print-arch)" = "$arch" ] || fail 'Architecture mismatch'
case "$kernel" in ''|*[!a-zA-Z0-9.~_+-]*) fail 'Invalid kernel ABI' ;; esac
installed_version() {
    apk --no-network --repositories-file /dev/null query --installed --format json --fields name,version "$1" > "$tmp/installed.json"
    [ "$(wc -c < "$tmp/installed.json")" -le 65536 ] || fail 'Oversized installed package query'
    [ "$(jsonfilter -i "$tmp/installed.json" -e '@[0].name')" = "$1" ] || fail 'Installed package identity differs'
    jsonfilter -i "$tmp/installed.json" -e '@[0].version'
}
installed=$(installed_version kernel)
[ "$installed" = "$kernel" ] || fail "Kernel ABI mismatch: router=$installed repository=$kernel"
# Source-built rootfs records its protected core/vendor/module closure and pins.
for path in /etc/apk/world /etc/apk/ax6000-protected.list; do
    [ ! -L "$path" ] && [ -f "$path" ] && [ -r "$path" ] || fail "Missing protected APK policy: $path"
    [ "$(wc -c < "$path")" -le 1048576 ] || fail 'Oversized protected APK policy'
done
awk '
    !/^[a-zA-Z0-9_.+-]+=[a-zA-Z0-9.~_+-]+$/ {exit 1}
    {split($0,p,"="); if (seen[p[1]]++) exit 1}
    END {if (!NR) exit 1}
' /etc/apk/ax6000-protected.list || fail 'Malformed protected APK policy'
for name in kernel libc base-files busybox; do
    awk -F= -v name="$name" '$1==name {found=1} END {exit !found}' /etc/apk/ax6000-protected.list || fail "Unprotected core package: $name"
done
awk -F= '$1=="apk-openssl" || $1=="apk-mbedtls" {found=1} END {exit !found}' /etc/apk/ax6000-protected.list || fail 'Unprotected APK provider'
while IFS='=' read -r name version; do
    awk -v pin="$name=$version" '$0==pin {found=1} END {exit !found}' /etc/apk/world || fail "Missing exact world pin: $name"
    [ "$(installed_version "$name")" = "$version" ] || fail "Protected package version differs: $name"
done < /etc/apk/ax6000-protected.list
feed_url="$base/feeds/$profile/$kernel/packages.adb"
fetch repository-apk.pem "$base/repository-apk.pem" 4096
[ "$(sha256sum "$tmp/repository-apk.pem" | awk '{print $1}')" = "$expected_apk_sha256" ] || fail 'Unexpected repository APK signing key'
fetch packages.adb "$feed_url" 8388608
mkdir "$tmp/keys"
cp "$key" "$tmp/keys/repository-apk.pem"
apk --keys-dir "$tmp/keys" --no-network --repositories-file /dev/null verify "$tmp/packages.adb"
# APK has no source-priority firewall. Accept only our exact source feed and
# explicitly tagged, same-branch public userspace feeds; preserve those bytes.
feeds=/etc/apk/repositories.d/ax6000.list
: > "$tmp/seen-files"
for directory in /etc/apk /etc/apk/repositories.d /lib/apk/repositories.d; do
    [ ! -L "$directory" ] || fail "Symlink APK configuration directory: $directory"
done
for path in /etc/apk/repositories /etc/apk/repositories.d/*.list /lib/apk/repositories.d/*.list; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    [ ! -L "$path" ] && [ -f "$path" ] && [ -r "$path" ] || fail "Unsafe APK configuration: $path"
    [ "$(wc -c < "$path")" -le 1048576 ] || fail 'Oversized APK configuration'
    # /etc definitions shadow an identically named /lib definition.
    case "$path" in /lib/apk/repositories.d/*)
        [ ! -e "/etc/apk/repositories.d/${path##*/}" ] || continue ;;
    esac
    awk -v own="$feed_url" '
        /^[ \t]*(#|$)/ {next}
        NF==1 && $1==own {next}
        NF==2 && $1 ~ /^@[a-zA-Z0-9_-]+$/ && $2 ~ /^https:\/\/downloads\.(immortalwrt|openwrt)\.org\/releases\/25\.12(\.0|-SNAPSHOT)\/packages\/aarch64_cortex-a53\/(base|luci|packages|routing|telephony|video)\/packages\.adb$/ {next}
        {exit 1}
    ' "$path" || fail "Unsafe or foreign APK repository: $path"
    if [ "$path" != "$feeds" ]; then
        awk -v own="$feed_url" '$1==own {found=1} END {exit !found}' "$path" && fail 'Own feed must be in ax6000.list only'
    fi
done
backup=$(mktemp -d /etc/apk/ax6000-feed-backup.XXXXXX)
printf 'Backup: %s\n' "$backup"
had_feed=false
if [ -f "$feeds" ]; then
    cp -p "$feeds" "$backup/ax6000.list"
    had_feed=true
fi
printf '%s\n' "$feed_url" > "$backup/staged.list"
chmod 644 "$backup/staged.list"
mv "$backup/staged.list" "$feeds"
if ! apk update; then
    if [ "$had_feed" = true ]; then
        cp -p "$backup/ax6000.list" "$backup/rollback.list"
        mv "$backup/rollback.list" "$feeds"
    else
        rm -f "$feeds"
    fi
    fail 'APK update failed; own feed configuration restored'
fi
printf 'Verified matching APK feed enabled. Kernel ABI: %s\n' "$kernel"
