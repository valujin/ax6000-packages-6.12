#!/usr/bin/env bash
# Build the pinned vendor firmware, matching SDK and packages in an isolated tree.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { printf 'build-firmware: %s\n' "$*" >&2; exit 1; }
usage() {
    printf 'Usage: build-firmware.sh --profile FILE --lock FILE --work-dir DIR --output-dir DIR [--source-tree DIR] [--jobs N] [--memory-max SIZE] [--min-free-gib N] [--resume]\n'
}
profile=""
lock=""
work=""
output=""
source_tree=""
jobs=""
memory=""
min_free_gib=60
resume=0
while (($#)); do
    case "$1" in
        --profile|--lock|--work-dir|--output-dir|--source-tree|--jobs|--memory-max|--min-free-gib)
            (($# >= 2)) || fail "missing value for $1"
            case "$1" in
                --profile) profile=$2 ;; --lock) lock=$2 ;; --work-dir) work=$2 ;;
                --output-dir) output=$2 ;; --source-tree) source_tree=$2 ;; --jobs) jobs=$2 ;;
                --memory-max) memory=$2 ;; --min-free-gib) min_free_gib=$2 ;;
            esac
            shift 2 ;;
        --help|-h) usage; exit 0 ;;
        --resume) resume=1; shift ;;
        *) fail "unknown option: $1" ;;
    esac
done
[[ -n $profile && -n $lock && -n $work && -n $output ]] || { usage >&2; exit 1; }
[[ $min_free_gib =~ ^[1-9][0-9]*$ ]] || fail '--min-free-gib must be a positive integer'
python3 "$script_dir/prepare-firmware.py" --profile "$profile" --lock "$lock" --phase validate
profile=$(realpath -- "$profile")
lock=$(realpath -- "$lock")
work=$(realpath -m -- "$work")
output=$(realpath -m -- "$output")
[[ -z $source_tree ]] || source_tree=$(realpath -- "$source_tree")
for executable in git make flock; do
    command -v "$executable" >/dev/null || fail "required command unavailable: $executable"
done
mkdir -p -- "$work"
exec 9>"${AX6000_BUILD_LOCK:-$script_dir/../.build.lock}"
flock -n 9 || fail 'another package or firmware build holds the repository build lock'
[[ ! -e $output ]] || fail "output directory exists: $output"
[[ ! -e $work/source || $resume == 1 ]] || fail 'source build tree already exists; use --resume after preparation or a fresh work directory'
free_gib=$(python3 - "$work" <<'PY'
import shutil, sys
print(shutil.disk_usage(sys.argv[1]).free // (1024**3))
PY
)
((free_gib >= min_free_gib)) || fail "need at least ${min_free_gib} GiB free for firmware + all modules; have ${free_gib} GiB"
if [[ ${AX6000_LIMITED_FIRMWARE_BUILD:-} != 1 ]]; then
    export AX6000_LIMITED_FIRMWARE_BUILD=1
    limits=()
    extras=()
    [[ -z $jobs ]] || limits+=(--jobs "$jobs")
    [[ -z $memory ]] || limits+=(--memory-max "$memory")
    [[ -z $source_tree ]] || extras+=(--source-tree "$source_tree")
    [[ $resume == 0 ]] || extras+=(--resume)
    flock -u 9
    exec "$script_dir/resource-limit.sh" "${limits[@]}" -- "$script_dir/build-firmware.sh" \
        --profile "$profile" --lock "$lock" --work-dir "$work" --output-dir "$output" \
        --min-free-gib "$min_free_gib" "${extras[@]}"
fi
[[ ${BUILD_JOBS:-} =~ ^[1-9][0-9]*$ ]] || fail 'resource limiter did not set BUILD_JOBS'
read -r repository commit < <(python3 - "$profile" <<'PY'
import json, sys
firmware = json.load(open(sys.argv[1]))['firmware']
print(firmware['repository'], firmware['commit'])
PY
)
source_dir="$work/source"
prepare=(python3 "$script_dir/prepare-firmware.py" --profile "$profile" --lock "$lock" --source-dir "$source_dir")
# CONFIG_IB makes native image installation build kernels for unselected devices,
# including FIT pipelines requiring their absent per-device rootfs. Disable that
# graph expansion during world; package IB explicitly from the selected images.
ensure_imagebuilder() {
    grep -q '^CONFIG_IB=y$' "$source_dir/.config" || return 0
    [[ -f $source_dir/target/imagebuilder/Makefile && ! -L $source_dir/target/imagebuilder/Makefile ]] || fail 'native ImageBuilder target is unavailable'
    make -j"$BUILD_JOBS" target/imagebuilder/compile CONFIG_IB= V=s
    local archives=("$source_dir"/bin/targets/mediatek/filogic/*imagebuilder*.tar.*)
    [[ -e ${archives[0]} || -L ${archives[0]} ]] || archives=()
    ((${#archives[@]} == 1)) || fail 'native build must produce exactly one ImageBuilder archive'
    [[ -f ${archives[0]} && ! -L ${archives[0]} ]] || fail 'native ImageBuilder archive is not a regular file'
}
if [[ $resume == 1 ]]; then
    [[ -f $work/prepared-inputs.json ]] || fail '--resume requires a previously completed preparation stage'
    python3 - "$profile" "$lock" "$work/prepared-inputs.json" <<'PY'
import hashlib, json, pathlib, sys
actual = {name: hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
          for name, path in zip(('profile_sha256', 'lock_sha256'), sys.argv[1:3])}
expected = json.loads(pathlib.Path(sys.argv[3]).read_text())
if actual != expected:
    raise SystemExit('build-firmware: resume profile/lock differ from prepared build inputs')
PY
    [[ $(git -C "$source_dir" rev-parse HEAD) == "$commit" ]] || fail 'resume source HEAD differs from pinned firmware commit'
    "${prepare[@]}" --phase repository-files
    "${prepare[@]}" --phase check-feeds
    "${prepare[@]}" --phase ssl-selection
    "${prepare[@]}" --phase package-only-selection
    cd -- "$source_dir"
    make -j"$BUILD_JOBS" defconfig
    "${prepare[@]}" --phase verify
    # Native ignored copy/catalog merging can retain an obsolete stock factory.
    image_cache_receipts=$(mktemp -d "$work/image-cache-reset.XXXXXX")
    "${prepare[@]}" --phase reset-cached-images --cleanup-receipt "$image_cache_receipts/receipt.json"
    make -j"$BUILD_JOBS" world CONFIG_IB= V=s
    ensure_imagebuilder
    "${prepare[@]}" --phase export --output-dir "$output"
    exit 0
fi
if [[ -n $source_tree ]]; then
    # Read the existing git object store without changing its checkout or config.
    git clone --shared --no-hardlinks --no-checkout -- "$source_tree" "$source_dir"
    git -C "$source_dir" remote set-url origin "$repository"
else
    git clone --filter=blob:none --no-checkout -- "$repository" "$source_dir"
fi
if ! git -C "$source_dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$source_dir" fetch --depth 1 origin "$commit"
fi
git -C "$source_dir" checkout --detach "$commit"
[[ $(git -C "$source_dir" rev-parse HEAD) == "$commit" ]] || fail 'source checkout does not match pinned firmware commit'
"${prepare[@]}" --phase configure
cd -- "$source_dir"
./scripts/feeds update -a
"${prepare[@]}" --phase check-feeds
./scripts/feeds install -a
"${prepare[@]}" --phase overrides
make -j"$BUILD_JOBS" defconfig
"${prepare[@]}" --phase select
make -j"$BUILD_JOBS" defconfig
"${prepare[@]}" --phase verify
python3 - "$profile" "$lock" "$work/prepared-inputs.json" <<'PY'
import hashlib, json, pathlib, sys
fingerprints = {name: hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
                for name, path in zip(('profile_sha256', 'lock_sha256'), sys.argv[1:3])}
pathlib.Path(sys.argv[3]).write_text(json.dumps(fingerprints, sort_keys=True) + '\n')
PY
make -j"$BUILD_JOBS" world CONFIG_IB= V=s
ensure_imagebuilder
"${prepare[@]}" --phase export --output-dir "$output"
