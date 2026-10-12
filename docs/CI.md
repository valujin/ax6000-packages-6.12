# GitHub Actions and signed channel publication

This repository publishes two fixed generations: `recommended` (Linux 6.12.108)
and `latest` (Linux 6.12.112). Each generation has stock, mtkuboot and ubootmod
images, one matching SDK and one exact kernel ABI. Daily package refreshes keep
that generation fixed. The inherited 6.6 profiles are never workflow defaults.

`test.yml` runs the Python suite and shell syntax checks on pushes and pull
requests. It builds official OpenWrt host usign at commit
`f1f65026a94137c91b5466b149ef3ea3f20091e9`, with one compiler job, for real signing
fixtures. A cheap scope probe verifies the actual hosted cgroup, UID, environment
and descendant inheritance before compiling usign. Locally, set `USIGN` to that trusted host executable.

`firmware.yml` is manual and requires a channel. It builds the corresponding
`profiles/redmi-ax6000-612-CHANNEL-new.json`, all three layouts, modules and SDK
together, and retains the complete raw artifact for fourteen days. It does not
publish unverified output. The disposable hosted runner reclaims only the fixed
unused toolchain directories listed in the workflow, then requires 60 GiB free.
`FIRMWARE_RUNNER` may name a larger GitHub hosted Ubuntu runner; a runtime guard
rejects self-hosted runners.

Hosted build and publication commands run inside `hosted-publication.py`. A
transient systemd scope limits the entire descendant tree to half of available
CPUs and half of MemTotal, with swap disabled. The helper returns to the runner's
unprivileged UID and reads the actual cgroup limits before executing the command;
unavailable or incorrect enforcement fails visibly. Secret values stay in the
environment or a temporary mode-0600 key file, never command arguments. The
existing build affinity and job limits also remain in effect.

`packages.yml` monitors both source profiles daily at 03:17 UTC, including before
bootstrap. A channel can build only after its generated
`profiles/redmi-ax6000-612-CHANNEL.json` exists and is enabled. Absent profiles
produce an actionable monitoring summary. The manual `force` option refreshes
unchanged inputs. Builds run serially: after successful staging, immutable
snapshot publication and authenticated round-trip restore, only that channel's
owned SDK/work/raw files are removed before starting the next SDK.

The signed live `site-state.json` and `site-state.sig` are the sole successful
publication baseline. Every non-null channel pointer names an exact immutable
snapshot release and asset, inventory hash and archive hash. Its restored lock
is passed to monitoring. Actions artifacts and newer undeployed releases are
never selected as the successful baseline. An unchanged lock skips compilation.

`publish-existing.yml` imports an exact immutable `firmware-BUILD_ID` release
from this repository, validates the full raw inventory and three layouts, then
uses the same snapshot and composition commands as local publication. It runs
no firmware compilation and executes no release-provided binaries. `bootstrap`
is permitted only when both live state files are absent; subsequent publication
restores the other channel from its signed live pointer.

All publication workflows share `package-repository` concurrency with
`cancel-in-progress: false`. A complete two-channel Pages payload is assembled
before upload. The other channel is retained byte for byte; channel removal and
implicit source/SDK/ABI migration are refused. The deploy job checks the live
predecessor again immediately before deployment and checks the intended state
afterward. A failed build or pre-deployment check preserves the previous site;
a published but undeployed snapshot can exist safely. A lost deployment response
is resolved by reading authenticated live state on the next run.

SDKs and firmware images live in immutable generation Releases. The Pages site
contains signed feeds, profiles, locks, keys, download catalogs and metadata. The
combined site is limited to 1,000,000,000 bytes, below the documented
[Pages 1 GB limit](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits).
Each Release asset must be
[under 2 GiB](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
There is no automatic replacement of a firmware generation: a future migration
must explicitly retain the previous ABI before changing its channel pointer.

Before first publication, configure Pages to use GitHub Actions, enable
[release immutability](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes),
and store the private key matching `keys/repository.pub` in `OPKG_SIGNING_KEY`.
The key payload is checked before staging or release writes. The publisher uses
the locally built pinned host usign; exported SDK usign relocation wrappers are
not standalone signers. No public-key secret is needed. Publication jobs receive
`contents: write`; only deployment receives `pages: write` and `id-token: write`.
The default Pages base is `https://valujin.github.io/ax6000-packages-6.12`;
`PACKAGE_REPOSITORY_URL` may supply a different HTTPS serving base.

For an independently verified initial raw build, use these same local/cloud
publication interfaces. Set `raw` to its output directory, `channel` to the exact
channel, `key` to a private mode-0600 key and `trusted_usign` to the pinned host
executable. Provide `GH_TOKEN` through your authenticated environment with access
to this repository. Commit the build's recipe first so its recorded recipe SHA
exists remotely. Outputs below must be fresh directories.

```sh
set -euo pipefail
repository=valujin/ax6000-packages-6.12
channel=recommended
raw=/absolute/path/to/recommended/raw
transport=/absolute/path/to/fresh/recommended-transport
mkdir -m 700 "$transport"
# All raw files are transported as data; the exported SDK signer is excluded.
tar --exclude='./usign' -C "$raw" -cf - . | \
  zstd -T1 -3 -o "$transport/raw.tar.zst"
(cd "$transport" && sha256sum raw.tar.zst > raw.tar.zst.sha256)
python3 scripts/channel-snapshot.py publish-generation \
  --raw "$raw" --expected-profile "profiles/redmi-ax6000-612-$channel-new.json" \
  --raw-archive "$transport/raw.tar.zst" --checksum "$transport/raw.tar.zst.sha256" \
  --repository "$repository" --output "$transport/generation" \
  --key "$key" --public-key keys/repository.pub --usign "$trusted_usign"
```

`publish-generation` validates the raw directory and independently imports the
bundle before any remote write. It uploads all SDK/image/build metadata and raw
assets while the Release is a draft; only after draft asset IDs are known does
it create, sign and upload `downloads.json` and `downloads.sig`. Then it publishes
and requires immutable API readback, exact asset inventory/digests and a tag
pointing to the recorded recipe commit. Existing matching immutable releases are
reused; an existing draft or foreign tag is refused. Large uploads are streamed.
See GitHub's
[immutable release model](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).

For initial hosted publication, use the resulting generation tag:

```sh
build_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["build_id"])' "$raw/profile.json")
gh workflow run publish-existing.yml --repo "$repository" \
  -f channel="$channel" -f release_tag="firmware-$build_id" -f bootstrap=true
```

Only the first recommended publication uses `bootstrap=true`. After the workflow
and independent live SDK checksum/feed signature checks pass, copy its exact
`raw/profile.json` to `profiles/redmi-ax6000-612-recommended.json` and activate that
generated daily profile. Keep its profile bytes unchanged so the initial lock's
fingerprint still matches. Repeat generation publication for `latest`, then run
`publish-existing.yml` with `channel=latest` and `bootstrap=false`; the already
activated recommended profile allows authenticated restoration of that channel.
Activate the exact latest generated profile only after the same live checks.

For local staging of the same first channel transaction, instead of hosted
`publish-existing.yml`, run:

```sh
python3 scripts/channel-snapshot.py publish-channel --raw "$raw" \
  --external-assets "$transport/generation/downloads.json" \
  --external-assets-signature "$transport/generation/downloads.sig" \
  --generation-release-metadata "$transport/generation/release.json" \
  --site-url https://valujin.github.io/ax6000-packages-6.12 --repository "$repository" \
  --profiles profiles --work-root "$transport/channel-work" --output "$transport/public" \
  --key "$key" --public-key keys/repository.pub --usign "$trusted_usign" --bootstrap
python3 scripts/channel-snapshot.py verify-deployment \
  --check "$transport/channel-work/deployment-check.json" --phase before
```

This creates the durable immutable snapshot, round-trip verifies it and produces
the complete Pages directory plus the authenticated deployment expectation; it
does not itself deploy Pages. Deployment must upload that entire directory and
then run the same `verify-deployment --phase after` check. Later local channel
transactions omit `--bootstrap`. Use the hosted workflow when a complete managed
Pages deployment is required.

GitHub public repository schedules
[disable after 60 days without repository activity](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/disable-and-enable-workflows).
The independent heartbeat job has narrowly scoped `contents: write` and commits
only `.github/monitor-heartbeat.json` after 30 idle days. It obeys branch protection,
fails visibly if denied and never force-pushes. Its content is outside recipe and
profile digests, so it does not cause package rebuilds. Pushes made with the
workflow token do not trigger additional push workflows. An already disabled
schedule must be re-enabled, for example:

```sh
gh workflow enable packages.yml --repo valujin/ax6000-packages-6.12
USIGN=/absolute/path/to/trusted/usign python3 -m unittest discover -s tests -v
for script in scripts/*.sh; do bash -n "$script"; done
```
