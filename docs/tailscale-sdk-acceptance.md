# Manual acceptance of real compact Tailscale packages

`tailscale-sdk.yml` is a manual, default-branch-only workflow. It produces an
actual `tailscale` APK for the issued recommended 6.12 firmware and an IPK for
the issued 6.6 firmware. It does not sign a feed, install packages, publish,
change a firmware image or use repository signing secrets.

Supply `opkg_ref` as the full reviewed 40-character commit in
`valujin/ax6000-packages` containing the compact source override. The APK job
uses the triggering 6.12 repository commit. The helper bytes must match in both
checkouts. Both complete active profiles must retain their pinned whole-file
hashes; future firmware profiles are not used.

The reviewed initial OPKG input is
`3ce41f233b6f91bf04a7570b9703088caf27cdd7`; it includes the same source helper
as the 6.12 `0120e0932682dc45c361520a415615caa28edc92` commit, including its
private writable Go temporary directory. Both actual SDK jobs still have to run.

| Package | Native SDK SHA256 | Active profile SHA256 |
| --- | --- | --- |
| 6.12 recommended APK | `5a57052ba4722e7731b57104966034f9c813d94ee84077d667318a8c9afa3019` | `94dfcdca38c122a2ea0f8cac3a780d6cf6c6f91e12464a99caf0ffd9698ca9a9` |
| 6.6 OPKG | `940de134c620a168e5cb71be59cdbaef32e4fb5e9a1946ec6af10445b8067624` | `42092ea80f9d1131f19807c0810732fcd0a96773c108c816f1448dafae92b6bf` |

The OPKG profile is the one retained by the deployed 66 catalog
`90f17c130bd35acda7e2c16dc53e300e7560e8a66ef78fffb0ad22059bd4f595`,
snapshot `145f6926552a1deed5589a9df4a884e03000f94c5149d3cd18102cc74d157d6b`.
The APK profile binds the successful R5 native generation
`redmi-ax6000-612-recommended-ae65e1de6997-5a57052ba472`.
The SDK is downloaded on the hosted runner, at up to 8 MiB/s, and its complete
SHA256 must match before the normal safe SDK extraction API runs.

The existing monitor resolves immutable feed and paired PBR source locks using
`--pinned-feeds`. The resulting Tailscale lock must equal the reviewed 1.104.2
source/Go/UPX fixture. If stable upstream has moved, this acceptance attempt
stops; review a new compact source lock before using it.

The driver preserves the exact original profile and lock as evidence, validates
them, and derives an acceptance-only package profile selecting only Tailscale,
with `package_only=['tailscale']`, `all_kmods=false`, no LuCI language selection
and no unrelated ASU/PBR/vendor source hooks. The native firmware, SDK, cohort,
feed pins and image package recipe stay unchanged. The derivative is retained
as `probe-profile.json`/`probe-lock.json`; it is never published as a firmware
profile. SDK baselines deliberately exclude refreshed user packages, so a
Tailscale-only build cannot claim a full-profile refreshed export.

The driver calls the normal `prepare.py` SDK/feed/override/configuration,
native dependency closure and package selection APIs with that explicit
subset. SDK and kernel guards always use the complete original profile so
the narrowed selection cannot skip the native ABI checks. It then runs
`make -j4 package/ax6000-overrides/tailscale/compile V=s`. That target performs
the real generated recipe's Configure, Compile and package install steps,
including online checksum-verified module prefetch followed by compilation
with `GOPROXY=off` and the same module cache. It does not inject the earlier
standalone binary or skip compilation. Each SDK independently recompiles it.
The normal `package/index` and `prepare.export_packages` APIs produce the
package export, with the complete native bank available as unchanged fallback.
Only the separate probe's package selection is narrowed; original inputs are
never modified.

The isolated build container uses the hosted runner's actual non-root UID/GID,
four CPUs, 10 GiB including swap, no additional capabilities and a read-only
root filesystem. Jobs run serially. All native package archive bytes and the
prepared kernel configuration, symbols, vermagic, release, autoconf and any
functional Image bytes are checked before/after. No firmware target runs.

The separately issued native Tailscale r2 package is fetched for comparison,
because refreshed packages are excluded from the SDK's frozen baseline. Its
full SHA256 and size are pinned from authenticated deployment evidence:

| Format | Existing package SHA256 | Evidence |
| --- | --- | --- |
| APK | `021bfd0cc9e453004d7d359c1690d01d871c1fa5047f1fe14a229923c61e3898` | Verified REC HTTPS readback, retained by APP3 snapshot `abe8541e34b2d302497ec38bbc39e040d96fe0f10c67684c6094c5f80cb25212` |
| IPK | `66fec5f0e2cf4eab5d45bb73f94b1f067ec555ea8ab1aece9bb14c984b80c224` | Deployed signed immutable snapshot `145f6926552a1deed5589a9df4a884e03000f94c5149d3cd18102cc74d157d6b` |

Comparison downloads fail if the exact expected bytes are unavailable. Both
URLs are moving GitHub Pages feed locations; accepted payload bytes are fixed.
The OPKG URL received HTTP 200 and the expected size in a bounded HEAD probe;
its full hash still must be checked by the future hosted download.
No signature check is replaced: these comparison files are public,
operator-approved exact hashes, never installed or used as build input.

Acceptance inspects the actual exported package. It requires one packed
`/usr/sbin/tailscale.multicall`, exactly two relative aliases, unchanged native
init/config bytes and conffiles, modes, dependencies and providers, including
any native `tailscale-any` provider. APK's normal generated package metadata
files are retained. APK retains both declared conffile paths; the native
`ipkg-build` resolves the directory declaration to existing regular files,
so IPK retains `/etc/config/tailscale`. Each actual r2 comparison archive must
have the corresponding unchanged conffiles. The packaged ELF SHA256 must equal the normal Make
source-helper proof, including successful UPX test and exact unpack roundtrip.

A second container has no network, capabilities or host TUN. The existing
explicit QEMU probe executes that exact packaged ELF, verifies full Tailscale
and custom Go revisions, CLI commands, and CLI/private userspace-daemon IPC.
No packaged init script, `tailscale up` or host route command runs. Artifact
`acceptance.json` joins the actual package and runtime checks. Package scripts
are inspected as data and are never installed or executed on the runner.

Only the actual package, packed ELF and public JSON/checksum evidence are
uploaded. SDK, firmware, native bank, private tool/module caches and plain ELF
are excluded. Passing this workflow demonstrates package construction and the
limited QEMU smoke; actual router/VPN data-plane testing and authenticated feed
promotion remain separate steps.
