#!/usr/bin/env bash
# Run only inside the isolated task container; never apt-install on the host.
set -euo pipefail
[[ -f /.dockerenv ]] || { echo 'This entrypoint requires a Docker container.' >&2; exit 1; }
(($#)) || { echo 'Pass explicit build-firmware.sh profile, lock and output arguments.' >&2; exit 1; }
[[ -d /global ]] || { echo 'Mount a shared /global directory for the cross-repository build lock.' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends build-essential clang flex bison gawk gettext \
  git libncurses-dev libssl-dev python3 python3-setuptools python3-pyelftools rsync \
  unzip zlib1g-dev file wget curl zstd xz-utils ca-certificates cmake ninja-build \
  time util-linux libelf-dev libzstd-dev swig device-tree-compiler cpio \
  libpython3-dev python3-dev perl pkgconf bzip2 patch tar gzip sudo xxd
export AX6000_BUILD_LOCK=/global/.build.lock
builder_uid=$(stat -c %u /workspace)
builder_user=$(getent passwd "$builder_uid" | cut -d: -f1)
if [[ -z "$builder_user" ]]; then
  useradd --uid "$builder_uid" --create-home builder
  builder_user=builder
fi
mkdir -p /build /output
chown "$builder_uid" /build /output
exec runuser -u "$builder_user" -- nice -n 19 ionice -c 3 \
  bash /workspace/scripts/build-firmware.sh "$@"
