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
private writable Go temporary directory. Both actual SDK jobs subsequently passed in
[workflow 39702777128](https://github.com/valujin/ax6000-packages-6.12/actions/runs/39702777128)
on workflow commit `bd433580538c5cb611e32881ad0bbe9ac5ba5a7e`; that same commit is
the APK recipe, while the IPK recipe remains the separate 3ce41f commit above.

Accepted 1.104.2-r3 packages:

| Format | Archive bytes | Installed-Size bytes | Archive SHA256 |
| --- | --- | --- | --- |
| REC APK | 11,921,395 (11.37 MiB) | 12,225,198 (11.66 MiB) | `4600a0a499dd8484247c8217adf5f6a43cb86b44528c1afeec954ae188287a00` |
| 6.6 IPK | 11,911,941 | 12,236,800 | `8b423aade0647b2147533f5811a425f26e47d521f6330f87b116b928710dafb2` |

REC's [signed snapshot bcdea080…3b4ed](https://github.com/valujin/ax6000-packages-6.12/releases/tag/packages-recommended-bcdea0807dc03fbd6639e63b19f161e01404d391499740174faf26bf21f3b4ed)
(Release 420243400) was activated by
[39711729943](https://github.com/valujin/ax6000-packages-6.12/actions/runs/39711729943).
Fresh HTTPS checks verified 18 channel files and signed state before/after:
22 records, 13,944,633 bytes, including actual r3 APK bytes and signed index
identity. Receipt SHA256 is
`3120cfcef01fbe7179b15cc6ee648dda6ff55583107689cabebab639e420ecaf`.
The other 1,393 APKs, including ASU r3, and 19 catalog assets inherit the earlier
complete verification, without a fresh full-bank download. Original native
firmware/SDK/IB, profile/seed and latest OPKG snapshot `074e68e5…19ea3` remain
unchanged. No latest APK feed or new native/personalized ASU image is implied.
Ordinary ROMs omit Tailscale; ASU retains it only if already installed. Native
client simulations from the actual stage are separate from this light HTTPS
readback. No real-router Tailscale/VPN test was performed.

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
`make -j4 package/ax6000-overrides/tailscale/compile CONFIG_AUTOREMOVE= V=s`.
The empty command-line override retains the real compiler/helper proof for
inspection; it changes no source, SDK `.config`, native bank or package code.
The compile target performs
the real generated recipe's Configure, Compile and package install steps,
including online checksum-verified module prefetch followed by compilation
with `GOPROXY=off` and the same module cache. It does not inject the earlier
standalone binary or skip compilation. Each SDK independently recompiles it.
The normal `package/index` and `prepare.export_packages` APIs produce the
package export, with the complete native bank available as unchanged fallback.
The index target indexes existing packages and has no package compile prerequisite.
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
The accepted hosted run downloaded and verified both complete r2 archives.
These moving URLs now serve newer feed generations; a repeat cannot substitute
r3 bytes for the pinned r2 comparison. The original hashes remain historical
acceptance inputs, even when an old moving filename is no longer available.
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
Both native packers also generate `/lib/upgrade/keep.d/tailscale` to preserve
the state-directory conffile declaration. Its exact bytes and mode must match
the separately authenticated r2 comparison package; extra paths remain errors.

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
