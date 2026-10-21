# Explicit OPKG to APK generation publication

The manual publisher requires `--replace-build-id`, `--allow-asu-apk-migration`
and `--migration-proof`. The predecessor must be the authenticated live channel.
The daily publisher never supplies this authorization. Existing source, ABI,
architecture, layout, application and source-patch checks still apply.

Schema 1 (`kind: asu-apk-native-migration`) retains its original complete byte
equality requirements, including the uncompressed functional kernel Image.
It remains the only migration proof format available to `latest`.

Schema 2 is restricted to the independently reviewed `612-recommended`
transition at source `ae65e1de69971b5a2e3cf7e39390ee93f274d488`, ABI
`6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1`. Its two functional Images
are **different**, both 14,661,640 bytes:

| Phase | Complete functional Image SHA256 |
| --- | --- |
| before | `ac19e2c554e40219aed043a0760aef2a609743ec0437d295c4f7f15f51886d8f` |
| after | `5a0eedece2116a8dd046bd8337b487bdfc6913eaf1465d3dc6b711d0851ad611` |

The independent root review identified changes only in two 20-byte GNU build-ID
note descriptors. The publication code accepts only the exact full hashes above.
It performs no note masking, normalization or arbitrary changed-range comparison.
Every future successor check still requires the complete accepted `5a0e...` Image.
An unknown latest Image difference requires its own future review and code change.

The schema-2 receipt has exactly these fields:

- `schema_version: 2`, `kind: asu-apk-native-migration`,
  `cohort: 612-recommended`.
- `predecessor_build_id`, `successor_build_id`, `source_commit`, `kernel_version`:
  actual generation identities; the predecessor comes from the live signed pointer.
- `kernel_context`: exactly `.config`, `Module.symvers`, `.vermagic`, and
  `include/config/kernel.release`; each contains equal `before`/`after`
  `{sha256, size}` identities matching the four reviewed full-byte context pins.
- `functional_image`: the exact `before`/`after` `{sha256, size}` pair above.
- `reviewed_transition`: the exact typed `rec-gnu-build-id-notes-v1` root review
  pins in `scripts/kernel_migration.py`: original context `cddaaf65...`, accepted
  context `2d7dbf00...`, enrollment `c0b5ac9b...`, and relation proof `5f958f7c...`.
- `firmware_manifest_sha256`: exact `before`/`after` SHA256 of the actual native
  firmware manifests. Historical source-world manifests are not substitutes for
  the currently authenticated predecessor's manifest.
- `source_patches`: the unchanged actual `before`/`after` patch lists.

The operator reviews this receipt; the bounded workflow transports its exact JSON
as base64. The receipt does not assert native export acceptance or hardware boot.
Actual source/profile/lock/SDK/native manifests and the existing native acceptance
remain separate mandatory gates.

The publisher independently extracts the functional Image from all three actual
sysupgrades on both sides, using the existing FIT parser and bounded Python TAR,
gzip and LZMA readers. Local RAW files must match the full native manifest asset
size/SHA before and after inspection. Restored snapshots contain external download
catalogs, so missing firmware is fetched through the existing immutable Release
transport, with signed catalog identity, GitHub asset ID/digest/size/update time,
recipe tag and before/after immutable-release checks. No imported tool is executed.
Limits are 128 MiB per sysupgrade and 512 MiB aggregate/download bytes per process.

Successful full-image checks are memoized by actual outer SHA/size, layout and
expected complete Image SHA. Repeated composition rechecks release metadata and
avoids downloading the same immutable files twice. Every existing local file is
rehashed even if its parsed identity is cached; changed local bytes always fail.

Recipe changes refresh only future source-profile ASU seeds. Publication of an
already accepted frozen producer must use that producer's actual source profile;
regenerating its seed or rewriting native/export metadata is forbidden.
