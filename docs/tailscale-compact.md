# Full-feature compact Tailscale

The new monitored package builds upstream Tailscale source as one ARM64 executable,
with `ts_include_cli` as the only user build tag. It installs
`/usr/sbin/tailscale.multicall` and relative `tailscale`/`tailscaled` symlinks.
The pinned feed's init script, configuration, procd integration and state paths
are copied unchanged. The package remains optional; ordinary firmware images do
not contain Tailscale, and ASU adds it only when it was installed already.

The first reviewed lock is 1.104.2, source commit
`e26db7a5797683ec99ad1516c40b628c7f2dfd71`, SHA256
`c3f179baa72216fff022ac2d816a8272d9847a29f5e159c4b9433f1b64c6a75a`.
It requires the source-declared Tailscale Go revision
`7ef7b403648ac3a9481a6e88e8b894eff50b0167` (Go 1.27.3) and UPX 5.2.1.
All three download archives are SHA256-bound in the lock. The monitor follows the
stable Tailscale version, resolves its exact Git commit and required Go revision,
and records the corresponding official Go release asset digest. An unavailable,
incorrect or insufficient toolchain fails resolution. UPX stays at its reviewed
pin until a separate recipe update. Existing explicit `artifact: static` locks
keep the previous r2 recipe for historical reproducibility; new monitored locks
use `source-multicall-upx` and package release r3.

Host tools are isolated under the package's own build directory. The recipe never
updates the SDK Go compiler. The host must be Linux AMD64 with Python supporting
tarfile's `data` extraction filter (the Ubuntu 24.04 build environment does).
Configure explicitly prefetches Go modules into a cache named for the source
commit under `DL_DIR`; compile reuses that cache with `GOPROXY=off`.
`GOTOOLCHAIN=local`, `GOWORK=off`, `GOSUMDB=sum.golang.org` and the pinned `go.sum`
remain enforced. Missing module-cache data fails the offline build rather than
silently downloading a compiler or skipping checksum verification.

Compilation uses CGO=0, trimpath and linker `-s -w`, plus exact version/commit
stamps. It does not use `ts_omit_*`, `--min`, `--extra-small` or force-UPX flags.
UPX runs at `-7 --no-lzma`; inherited UPX options are cleared. A build is accepted
only after `upx -t` and a byte-exact decompression roundtrip. `RSTRIP:=:` protects
the packed executable from native strip/sstrip processing. The package provides
`tailscaled`; native provider generation continues to supply `tailscale-any`.

## Manual hosted verification

`tailscale-compact.yml` is manual and does not publish or use signing secrets.
It invokes the same shared build helper as the generated SDK recipe, with online
module prefetch followed by `GOPROXY=off` compilation in a disposable container capped
at 4 CPUs, 10 GiB RAM and no swap. That compile container still has network access;
`GOSUMDB` remains enabled. This phase exercises the prefetched module-cache path,
not a kernel-enforced compile network sandbox. Its runtime phase uses an unprivileged,
capability-free, network-disabled container with explicit `qemu-aarch64`.
It checks both aliases, full source and Go revision JSON, retained CLI commands,
and CLI-to-daemon IPC over a private socket with userspace networking and
memory-only state. It neither runs the router's init script nor changes host
routes or TUN devices.

The uploaded artifact contains the packed binary and measured hashes/sizes,
UPX integrity/roundtrip proof, build metadata, container limits and QEMU result.
The unpacked comparison binary and tool/module caches stay in temporary storage.

The [hosted verification on 2026-10-22](https://github.com/valujin/ax6000-packages-6.12/actions/runs/39699280195)
passed on recipe commit `0120e0932682dc45c361520a415615caa28edc92`.
The single executable measured 41,681,056 bytes before UPX and 12,223,164 bytes
after UPX (11.66 MiB, a 70.67% reduction). Its packed SHA256 is
`cbc98a1f7c0c142829bfbb660923fc4afa4ab2afd8588852f59b9ca34149ae8f`.
UPX integrity and exact decompression checks, ARM64 QEMU commands and private
CLI-to-daemon IPC all passed. This tests the shared build helper and emulated
binary; it does **not** verify a completed APK/IPK package, actual SDK host-tool
compatibility, real router performance or VPN data-plane operation.

The [real SDK APK/IPK workflow](https://github.com/valujin/ax6000-packages-6.12/actions/runs/39702777128)
subsequently passed. The APK producer is `bd433580538c5cb611e32881ad0bbe9ac5ba5a7e`;
the separate 6.6 IPK recipe is `3ce41f233b6f91bf04a7570b9703088caf27cdd7`.
Both matching SDKs performed normal configure, compile, install and export.
Accepted packages retain the one-ELF/two-relative-link layout, native init/config,
KEEP bytes, conffiles, dependencies and providers. The packaged ELF passed
isolated ARM64 QEMU command and private CLI-to-daemon IPC checks. No native
firmware, SDK or kernel rebuild was needed for this userland supplement.

The [published REC snapshot](https://github.com/valujin/ax6000-packages-6.12/releases/tag/packages-recommended-bcdea0807dc03fbd6639e63b19f161e01404d391499740174faf26bf21f3b4ed)
contains `tailscale-1.104.2-r3.apk`, **11,921,395 bytes (11.37 MiB)**,
SHA256 `4600a0a499dd8484247c8217adf5f6a43cb86b44528c1afeec954ae188287a00`.
It is 67.63% smaller than the historical r2 APK; Installed-Size is
**12,225,198 bytes (11.66 MiB)**. Stock UBI root remains 80 MiB: available overlay
space must still account for dependencies and persistent state.

[Activation 39711729943](https://github.com/valujin/ax6000-packages-6.12/actions/runs/39711729943)
passed. Fresh HTTPS verification checked 18 recommended files plus signed state
before/after (22 records), actual APK bytes and the signed ADB identity. The other
1,393 APKs, including ASU r3, and 19 catalog assets are unchanged and inherit the
earlier complete checks; they were not downloaded again. Receipt SHA256:
`3120cfcef01fbe7179b15cc6ee648dda6ff55583107689cabebab639e420ecaf`.
Native firmware, SDK, ImageBuilder, profile/seed and the latest OPKG pointer remain
unchanged. Latest APK has not been published. These checks do not establish
real-router performance or VPN data-plane operation; no Tailscale hardware test
or new personalized ASU image is claimed. [Acceptance details](tailscale-sdk-acceptance.md).

Primary implementation references:

- [CLI inclusion](https://github.com/tailscale/tailscale/blob/e26db7a5797683ec99ad1516c40b628c7f2dfd71/cmd/tailscaled/with_cli.go)
- [Upstream distribution flags](https://github.com/tailscale/tailscale/blob/e26db7a5797683ec99ad1516c40b628c7f2dfd71/build_dist.sh)
- [Required compiler revision](https://github.com/tailscale/tailscale/blob/e26db7a5797683ec99ad1516c40b628c7f2dfd71/go.toolchain.rev)
- [Automatic Tailscale Go build tag](https://github.com/tailscale/go/blob/7ef7b403648ac3a9481a6e88e8b894eff50b0167/src/cmd/go/internal/cfg/tailscale.go)
- [Runtime compiler revision](https://github.com/tailscale/go/blob/7ef7b403648ac3a9481a6e88e8b894eff50b0167/src/runtime/debug/mod.go)
