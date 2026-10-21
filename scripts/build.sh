#!/usr/bin/env bash
# Build packages with the exact firmware SDK; never invoke a firmware image target.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { printf 'build: %s\n' "$*" >&2; exit 1; }
usage() {
    printf 'Usage: build.sh --profile FILE --lock FILE --work-dir DIR --output-dir DIR [--jobs N] [--memory-max SIZE]\n'
}
profile=""
lock=""
work=""
output=""
jobs=""
memory=""
while (($#)); do
    case "$1" in
        --profile|--lock|--work-dir|--output-dir|--jobs|--memory-max)
            (($# >= 2)) || fail "missing value for $1"
            case "$1" in
                --profile) profile=$2 ;; --lock) lock=$2 ;; --work-dir) work=$2 ;;
                --output-dir) output=$2 ;; --jobs) jobs=$2 ;; --memory-max) memory=$2 ;;
            esac
            shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done
[[ -n $profile && -n $lock && -n $work && -n $output ]] || { usage >&2; exit 1; }
# These checks happen before downloads or work directory creation.
python3 "$script_dir/prepare.py" --profile "$profile" --lock "$lock" --phase validate
profile=$(realpath -- "$profile")
lock=$(realpath -- "$lock")
work=$(realpath -m -- "$work")
output=$(realpath -m -- "$output")
for executable in curl sha256sum flock make git tar; do
    command -v "$executable" >/dev/null || fail "required command unavailable: $executable"
done
mkdir -p -- "$work"
exec 9>"${AX6000_BUILD_LOCK:-$script_dir/../.build.lock}"
flock -n 9 || fail 'another package or firmware build holds the repository build lock'
[[ ! -e $output ]] || fail "output directory exists; choose a new output directory: $output"
[[ ! -e $work/extracted ]] || fail 'SDK already extracted; use a fresh work directory'
# Relaunch the complete build inside the inherited affinity/cgroup limits.
if [[ ${AX6000_LIMITED_BUILD:-} != 1 ]]; then
    export AX6000_LIMITED_BUILD=1
    limits=()
    [[ -z $jobs ]] || limits+=(--jobs "$jobs")
    [[ -z $memory ]] || limits+=(--memory-max "$memory")
    # Release and reacquire in the child, which retains the same work lock.
    flock -u 9
    exec "$script_dir/resource-limit.sh" "${limits[@]}" -- "$script_dir/build.sh" \
        --profile "$profile" --lock "$lock" --work-dir "$work" --output-dir "$output"
fi
[[ ${BUILD_JOBS:-} =~ ^[1-9][0-9]*$ ]] || fail 'resource limiter did not set BUILD_JOBS'
prepare=(python3 "$script_dir/prepare.py" --profile "$profile" --lock "$lock")
sdk_url=$("${prepare[@]}" --inspect-sdk url)
sdk_sha=$("${prepare[@]}" --inspect-sdk sha256)
archive="$work/sdk.archive"
if [[ ! -f $archive ]]; then
    curl --fail --location --proto '=https' --proto-redir '=https' --retry 3 \
        --output "$archive.partial" -- "$sdk_url"
    printf '%s  %s\n' "$sdk_sha" "$archive.partial" | sha256sum -c -
    mv -- "$archive.partial" "$archive"
fi
printf '%s  %s\n' "$sdk_sha" "$archive" | sha256sum -c -
extract_archive=$archive
# tarfile handles gzip/xz directly. Zstandard SDKs need the host zstd tool.
if [[ $sdk_url == *.tar.zst || $sdk_url == *.tar.zst\?* ]]; then
    command -v zstd >/dev/null || fail 'this SDK archive requires the host zstd command'
    zstd -d -c -- "$archive" > "$work/sdk.tar.partial"
    mv -- "$work/sdk.tar.partial" "$work/sdk.tar"
    extract_archive="$work/sdk.tar"
fi
sdk_dir=$(python3 "$script_dir/prepare.py" --extract "$extract_archive" --extract-dir "$work/extracted")
prepare+=(--sdk-dir "$sdk_dir")
"${prepare[@]}" --phase feeds
cd -- "$sdk_dir"
./scripts/feeds update -a
"${prepare[@]}" --phase check-feeds
./scripts/feeds install -a
"${prepare[@]}" --phase overrides
make -j"$BUILD_JOBS" defconfig
"${prepare[@]}" --phase check-sdk
"${prepare[@]}" --phase check-kernel
"${prepare[@]}" --phase select
make -j"$BUILD_JOBS" defconfig
# Hidden native module dependency edges are absent from SDK menus. Restore
# their verified baseline closure and normalize until no selection changes.
native_closed=false
for native_pass in {1..8}; do
    native_changed=$("${prepare[@]}" --phase close-native)
    case "$native_changed" in
        false) native_closed=true; break ;;
        true) make -j"$BUILD_JOBS" defconfig ;;
        *) fail 'unexpected native dependency closure result' ;;
    esac
done
[[ $native_closed == true ]] || fail 'native dependency closure did not converge'
"${prepare[@]}" --phase verify
# Explicit targets exclude target/install and image generation.
make -j"$BUILD_JOBS" package/compile V=s
# Repacking userspace must not change the native package manager, host decoder
# or prepared kernel inputs. Verify before invoking the SDK's index tool.
"${prepare[@]}" --phase check-sdk
"${prepare[@]}" --phase check-kernel
make -j"$BUILD_JOBS" package/index V=s
"${prepare[@]}" --phase export --output-dir "$output" --sdk-archive "$archive"
printf 'Package build exported to %s\n' "$output"
