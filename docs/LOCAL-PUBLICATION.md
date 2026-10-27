# Publish a genuinely verified local Mesh generation

Firmware and SDK compilation run on the owned server. The current authorization
allows up to 8 CPUs and 24 GiB for the task while preserving existing services.
This path requires successful source-backed native verification and a fresh,
successful build with the exact exported SDK. It does not reuse a failed GitHub
run as a successful producer or invent workflow IDs.

The existing independent `channel-snapshot.py publish-generation` CLI remains the
publisher. If the legitimate production key is available locally, it can be used
directly after the checks below. Otherwise, the signing-only
`publish-local-generation.yml` workflow uses `OPKG_SIGNING_KEY`. That workflow
builds only the small pinned host usign utility; it never compiles firmware or
SDK packages and never executes an SDK binary. Pages activation is separate.

## Preserve the actual producer and local results

Use a clean recipe checkout at the full committed producer SHA. A publisher
workflow may be committed later without changing that native producer. Keep the
completed native source, raw export, actual build logs and terminal statuses.
Run the original native verifier against the genuine completed source:

```sh
python3 "$PRODUCER/scripts/verify-firmware.py" \
  --repo "$PRODUCER" --source "$NATIVE_SOURCE" --raw "$RAW" \
  --apk "$TRUSTED_HOST_APK" --output "$TASK/native-verification.json"
```

Stop on failure. Do not reconstruct independent native references from the SDK
or alter the generated raw profile. Next, complete `build.sh` in a fresh local
SDK workspace, preseeding its `sdk.archive` with the exact SDK from raw. Use the
reviewed server launcher/resource scope. Preserve its exit status and logs;
the following command is run only after the complete SDK build exits zero:

```sh
python3 scripts/local_publication.py accept-sdk \
  --raw "$RAW" --producer "$PRODUCER" --producer-commit "$PRODUCER_COMMIT" \
  --native "$TASK/native-verification.json" --sdk "$BUILT_SDK" \
  --sdk-raw "$SDK_RAW" --sdk-archive "$SDK_WORK/sdk.archive" --apk "$TRUSTED_HOST_APK" \
  --output "$TASK/sdk-acceptance.json"
```

The acceptance command checks native image/SDK identity, actual SDK identity and
Mesh provenance, every one of the seven kernel-context hashes, requested fresh
package closure including Tailscale and AmneziaWG, exported package hashes and
unchanged generated profile bytes. Frozen native modules remain in their native
bank. The receipt explicitly names `execution: local-server`; it is a record of
a trusted local build, not remote attestation or a hardware boot test.

## Stage and authenticate the publication input

Create the ordinary raw transport, excluding its unnecessary host executable:

```sh
tar --exclude='./usign' -C "$RAW" -cf - . | zstd -T8 -3 -o "$TASK/raw.tar.zst"
(cd "$TASK" && sha256sum raw.tar.zst > raw.tar.zst.sha256)
python3 scripts/local_publication.py stage \
  --raw "$RAW" --producer "$PRODUCER" --producer-commit "$PRODUCER_COMMIT" \
  --native "$TASK/native-verification.json" --sdk-proof "$TASK/sdk-acceptance.json" \
  --archive "$TASK/raw.tar.zst" --checksum "$TASK/raw.tar.zst.sha256" \
  --output "$TASK/local-candidate"
```

Staging reimports the entire transport and validates the two actual receipts.
`local-publication.json` binds the producer commit, build ID, SDK hash and exact
archive/native/SDK receipt bytes. The SDK receipt also binds profile, lock,
manifest and native verification hashes. Preserve the emitted manifest SHA256.

Upload these five files to a private draft transport in this repository. Use a
new `local-build-...` tag and explicitly target the exact producer commit:

```sh
gh release create "$CANDIDATE_TAG" --repo valujin/ax6000-packages-6.12 \
  --draft --target "$PRODUCER_COMMIT" --title "$CANDIDATE_TAG" \
  --notes 'Verified local publication transport; retain draft for provenance.'
gh release upload "$CANDIDATE_TAG" --repo valujin/ax6000-packages-6.12 \
  "$TASK/local-candidate/raw.tar.zst" "$TASK/local-candidate/raw.tar.zst.sha256" \
  "$TASK/local-candidate/native-verification.json" "$TASK/local-candidate/sdk-acceptance.json" \
  "$TASK/local-candidate/local-publication.json"
```

After readback, dispatch the signing-only workflow with the exact release ID,
producer SHA and locally computed manifest SHA256. These explicit inputs are the
maintainer's authorization of the trusted local result, independent of mutable
draft transport metadata:

```sh
gh workflow run publish-local-generation.yml --repo valujin/ax6000-packages-6.12 \
  --ref main -f candidate_release_id="$CANDIDATE_RELEASE_ID" \
  -f producer_commit="$PRODUCER_COMMIT" -f local_manifest_sha256="$LOCAL_MANIFEST_SHA256"
```

The signer checks the exact draft/producer/asset inventory, the explicit manifest
hash, all transported file hashes and both receipts, and safely reimports the
full raw inventory. No SDK program runs in that job. The established publisher
then reimports again, uploads a new draft generation, signs the catalog with
actual asset IDs, and requires published `immutable: true` readback. It preserves
publication metadata and the truthful local receipts in the workflow artifact.
Do not delete or overwrite a partial publication after failure; inspect its
exact draft and use only the existing validated resume path.

After immutable publication, preserve its exact profile bytes, signed catalog,
signature, API metadata and checksums locally. Pages/feed activation and daily
profile adoption remain separate reviewed operations.
