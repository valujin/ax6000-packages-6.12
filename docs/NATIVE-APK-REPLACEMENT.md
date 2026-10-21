# REC native APK generation replacement

This manual path replaces the genuine REC native firmware generation with a
new generation embedding APP `20261021.2-r3`, its constructor fix, the corrected
installer, and its producer-bound ASU seed. It does not authorize a supplemental
package update or the OPKG-to-APK migration. LATEST is excluded.

The source remains AE `ae65e1de69971b5a2e3cf7e39390ee93f274d488`, ABI
`6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1`, and the complete functional
Image remains `5a0eedece2116a8dd046bd8337b487bdfc6913eaf1465d3dc6b711d0851ad611`
(14,661,640 bytes). Four enrolled ABI records and all seven measured source/SDK
records must match. All three layouts and the stock factory images need actual
full native verification; both actual ImageBuilders need independent approval.

Only the APP2 archive may be replaced by APP3. Every other native APK, including
core, kmods, vendor, common and translations, must retain its complete archive
SHA and size. A newly rebuilt translation with the same name fails this check.
Counts come from the actual SDK baseline and native manifests. There is no
restoration or normalization exception.

## Local acceptance input

`scripts/native_generation.py` prints an inert plan by default. Root runs its
explicit acceptance command only after actual native completion and independent
verification, in a bounded, trusted host environment serialized with the existing
build lease. The helper does not schedule, build, acquire the host lease, sign,
download, execute target code, or change native artifacts.

```sh
python3 -B scripts/native_generation.py --execute \
  --inputs /absolute/actual-inputs.json --inputs-sha256 REVIEWED_INPUT_SHA \
  --output /absolute/fresh-native-replacement.json
```

The exact input object contains `schema_version: 1`,
`kind: "rec-native-apk-replacement-inputs-v1"`, `before`, `after`,
`staging_receipt`, `production_receipt`, `trusted_apk`, `trusted_usign`,
`predecessor_root`, `predecessor_site_state`, and `predecessor_snapshot`.
Every file reference has exactly `path`, `sha256`, and integer `size`; the path
must be an absolute canonical regular file without symlink ancestors. Directory
paths have the same canonical/no-symlink requirement. Null/pending refs refuse.

Each side contains exactly:

| Field | Actual input |
| --- | --- |
| `raw` | Complete original native RAW directory |
| `source` | Genuine original/copy AE native source directory |
| `recipe` | Trusted Git store retaining the declared producer objects |
| `producer_commit` | Exact reviewed native producer (old EA; new explicitly reviewed commit) |
| `source_profile` | Source `profiles/redmi-ax6000-612-recommended-new.json` from that producer |
| `native_status`, `native_evidence` | Independent successful full native acceptance and evidence refs |
| `sdk_baseline` | Actual SDK baseline JSON, authenticated by native evidence |
| `source_context` | Eight refs: the seven roles below plus `KDIR/Image` |
| `sdk_context` | Seven actual retained final SDK refs |
| `ib_approval` | Independent actual IB approval, with its five hash-bound sibling evidence files |

The seven roles are `.config`, `.config.set`, `.vermagic`, `Module.symvers`,
`modules.builtin.modinfo`, `include/config/kernel.release`, and
`include/generated/autoconf.h`. The source paths must resolve to the measured
native kernel directory. The complete Image is measured separately.

The exact `ax6000-rec-genuine-warm-fork-preparation-v2` staging receipt binds the physical independent copy, reviewed binding and
all fourteen source postimages. Exactly four change: the APP Makefile, the APP
helper module, `/etc/asu-cohort.json`, and `/usr/sbin/ax6000-install-feed`.
The module/installer bytes come from the declared producer Git blobs; seed
calculation uses that exact producer tree, never the publisher HEAD. All other
postimages and source top-level config must remain unchanged. Both measured
staging context maps describe the copy paths before and after the four-file
adapter; their byte identities must also equal the separately measured original
source context. The receipt does not claim its before measurement ran at the
original source paths.

Staging is not native completion. The separate
`rec-native-producer-completion-v1` receipt must have actual exited-zero/no-OOM
container inspections and ordered `world`, `imagebuilder`, `export` steps,
four actual phase receipts, and exact RAW metadata/source/SDK context bindings.
Its `native_evidence` remains null because independent verification runs later.
The separate `before`/`after` acceptance refs above must be non-null and bind the
same actual metadata. No source staging boolean can substitute for those proofs.

Trusted host tools are the pinned EC6 APK and known usign binary. Imported RAW
and native source executables are never run. The signed predecessor state and
snapshot are verified with the old native recipe key, and bind the old actual
profile, firmware manifest, build config, build ID and live pointer.

## Portable publication authorization

Successful local acceptance emits
`{schema_version: 1, kind: "rec-native-apk-generation-transition-v1", summary: ...}`.
The summary contains measured identities, fourteen postimage identities, proof
digests, exact producer/seeds and the authenticated predecessor pointer. It
contains no required local host paths. The operator reviews and SHA-pins that
receipt; this is explicit operator authorization, not remote attestation.

`channel-snapshot.py publish-channel` accepts these additional options:

```text
--replace-build-id EXACT_AUTHENTICATED_LIVE_BUILD
--allow-native-apk-replacement
--native-replacement-proof REVIEWED_PORTABLE_JSON
--native-replacement-proof-sha256 REVIEWED_PORTABLE_SHA
```

Bootstrap and the old migration flag/proof are incompatible. The publisher
checks the actual signed predecessor pointer and metadata, new RAW metadata,
complete native APK inventories, all fixed policy, source/ABI/producer bindings
and all six actual functional Images. Firmware decoding reuses the bounded
TAR/FIT reader (128 MiB per asset, 512 MiB aggregate) and immutable Release API
identity checks. The same checks run again during signed site composition;
daily publication still cannot silently switch generations.

The local proof emitter has not been run for a new native generation during
implementation. No new native acceptance or publication is claimed here.

## Manual workflow producer binding

`publish-existing.yml` imports using the source profile from the exact producer
authenticated by the existing signed generation catalog, immutable Release API
identity and tag target. With `fetch-generation --channel`, the publisher reads
that Git commit's bounded source profile blob as data. If the object is absent,
it fetches only the exact commit from the fixed generation repository URL; the
producer tree is never checked out or executed. Seed replay uses that commit's
recipe blobs. A later publisher's profile or recipe digest cannot relabel an
older generation.

The selected profile and a small producer selection record live under
`release-download/producer/`. Import uses that selected file and
`--expected-producer-commit`; the RAW firmware manifest producer and ASU policy
must match. The option is additive: other import callers keep their previous
semantics. Manual OPKG and ordinary publication retain their existing flags,
keys and signed site composition.

The additional manual dispatch inputs are `allow_native_apk_replacement`,
`native_replacement_proof_base64`, and `native_replacement_proof_sha256`.
Supply the exact locally accepted portable receipt bytes, encoded as one base64
line, and their separately reviewed SHA. The workflow enforces a 64 KiB decoded
limit, strict JSON, exact SHA, exclusive REC authorization, no bootstrap and an
exact `replace_build_id`. It writes a fresh mode-0600 file and forwards the same
bytes/SHA to the full publisher checks. The workflow does not create acceptance
facts. Daily automation never enables this replacement path.

Adding publisher scripts changes future recipe fingerprints. Refresh only
future source profile seeds during integration; retain actual old producer
commits, source profiles and seeds for already built generations.
