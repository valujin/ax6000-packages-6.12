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

The next package acceptance step uses the matching real SDK and generated
override: configure/prefetch with access to pinned downloads, then
`make package/ax6000-overrides/tailscale/compile V=s`, inspect the emitted actual
APK/IPK control/payload, and verify the one-file/two-relative-symlink layout,
unchanged wrappers, providers and actual version. It needs no firmware/kernel
rebuild. Full native Make install expansion is covered by the lightweight tests;
real package creation and router testing remain required before feed promotion.

Primary implementation references:

- [CLI inclusion](https://github.com/tailscale/tailscale/blob/e26db7a5797683ec99ad1516c40b628c7f2dfd71/cmd/tailscaled/with_cli.go)
- [Upstream distribution flags](https://github.com/tailscale/tailscale/blob/e26db7a5797683ec99ad1516c40b628c7f2dfd71/build_dist.sh)
- [Required compiler revision](https://github.com/tailscale/tailscale/blob/e26db7a5797683ec99ad1516c40b628c7f2dfd71/go.toolchain.rev)
- [Automatic Tailscale Go build tag](https://github.com/tailscale/go/blob/7ef7b403648ac3a9481a6e88e8b894eff50b0167/src/cmd/go/internal/cfg/tailscale.go)
- [Runtime compiler revision](https://github.com/tailscale/go/blob/7ef7b403648ac3a9481a6e88e8b894eff50b0167/src/runtime/debug/mod.go)
