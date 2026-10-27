# Publish a verified recommended Mesh generation

For the current owned-server build, use [the local publication path](LOCAL-PUBLICATION.md).
The workflow described below is the separate hosted-build path.

`publish-firmware-generation.yml` fills the manual step between `firmware.yml`
and `publish-existing.yml`. It uses the existing repository secret
`OPKG_SIGNING_KEY`; a local production private key is unnecessary. It publishes
the immutable firmware/SDK Release and leaves Pages activation to the existing
manual publisher. APK feed signing uses `APK_SIGNING_KEY` in that later workflow.

First wait for the exact `firmware.yml` run to finish successfully. Its raw and
diagnostics artifacts must still exist. Run:

```sh
gh workflow run publish-firmware-generation.yml \
  --repo valujin/ax6000-packages-6.12 --ref main \
  -f firmware_run_id=EXACT_SUCCESSFUL_FIRMWARE_RUN_ID
```

The workflow checks the run's repository, default branch, workflow path, head
commit, conclusion and exact artifact IDs. It verifies the downloaded ZIP
digests supplied by GitHub, then checks the complete raw inventory against the
source profile checked out at that producer commit. The producer's genuine
native verification report must describe the same three image hashes, SDK,
kernel ABI and verified stock factory payload. The completed native source tree
is not retained by the build artifact, so this step consumes that successful
producer report; it does not claim to repeat source-based native verification.

Before signing, it compiles the requested packages and AmneziaWG through the
actual exported SDK using `build.sh`. It preseeds `sdk-work/sdk.archive` from the
verified raw artifact, allowing acceptance before its future Release URL exists.
All seven prepared kernel-context files must still match the native evidence
after compilation. Missing SDK inputs, a failed compile or a changed context
stop publication. The job uses the existing hosted resource limiter and may
take several hours. No firmware compilation or router connection occurs here.

SDK acceptance runs in a job with read-only repository permissions and no
signing secret. A separate fresh hosted signing job downloads the original
producer artifacts again and repeats the run, ZIP, metadata and native-evidence
checks. It verifies a hash-bound acceptance handoff naming that exact producer
commit, artifact digests, profile, lock, manifest, SDK and kernel contexts.
SDK executables and SDK compilation stay out of the signing job.

The final step uses `channel-snapshot.py publish-generation`, a temporary
mode-0600 signing key and the pinned independently built host usign. The existing
publisher independently reimports the raw transport before any Release write,
uploads a draft, signs the catalog containing actual asset IDs, then requires
immutable Release readback. It refuses foreign tags, mismatched immutable
assets and incomplete drafts. The resulting tag and verification evidence are
saved in the workflow summary and `generation-publication-RUN_ID` artifact.

After successful generation publication, read and verify the live signed
`site-state.json`/`site-state.sig` with the pinned public key. Use its exact
recommended `build_id` as the replacement predecessor:

```sh
gh workflow run publish-existing.yml \
  --repo valujin/ax6000-packages-6.12 --ref main \
  -f channel=recommended -f release_tag=firmware-EXACT_NEW_BUILD_ID \
  -f bootstrap=false -f replace_build_id=EXACT_AUTHENTICATED_LIVE_BUILD_ID
```

This signs the APK feed, publishes its immutable snapshot, retains the other
live channel and performs the existing Pages deployment checks. An old run's
successful upload is not the live predecessor. After deployment and independent
live checks, copy the new generation's exact `profile.json` bytes into
`profiles/redmi-ax6000-612-recommended.json` to enable its daily SDK refreshes.
The two AX6000 routers are flashed manually with the image matching each
router's existing layout. Build and publication checks do not establish physical
Mesh onboarding, roaming or boot success.
