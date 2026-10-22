# Finite LATEST OPKG to APK migration

`latest_kernel_migration.py` permits only the reviewed existing-context LATEST
transition from build `a99b0888b88f-0b1249707848` to
`a99b0888b88f-31599e148e45`. Both use kernel
`6.12.112~d405163bfdb42254c245797a894994c0-r1` and the identical complete
14,661,640-byte Image (`a1db81320a822eab661310185948456cef216faa7fac0a11d689ce61233a8681`).
The original v1 equality and REC v2 transition validators remain in place.

Schema3 requires all ten exact existing native-context identities, the reviewed
native acceptance `ef3920c9…`, root decision `4ba65dc1…`, hosted context
`428ef4d3…`, exact source patch ledger, and exact authenticated predecessor
snapshot `074e68e5…` including its immutable Release/asset/archive identity.
The hosted context is native evidence; it is **not** an ImageBuilder approval.
The receipt projects already accepted native facts and makes no fresh SDK
compilation, hardware boot or ImageBuilder smoke claim.

The genuine predecessor generation Release is `419152056`, recipe commit
`6359d43b321f6049824a880a82081f93add13b98`. Its manifest asset `661318733`
is 327,805 bytes with SHA256
`459a7e06661b22e3b21a66ecb2e67d4416c3e0b1aef8c279305c97e0a1f49567`.
The successor manifest is
`0f8095952e7e4444dc464865d4b9608f507b56035f67e8df01e90fc6bd7a3ff2`.
If the signed predecessor channel lacks its original manifest, the normal bounded
immutable-Release metadata resolver retrieves that exact manifest into temporary
storage. It never adds files to the signed predecessor tree. A present corrupt
or linked manifest is rejected. The unchanged native payload decoder then
extracts and hashes the complete Image from **all six** actual sysupgrade
payloads (three layouts before and after), using normal immutable transport,
catalog/checksum, process byte-budget and cache checks.

The metadata projection CLI is inert by default. An operator may explicitly run
`python3 scripts/latest_kernel_migration.py --execute` with all eight genuine
metadata paths (`--accepted-status`, `--root-decision`, `--hosted-context`,
`--old-profile`, `--new-profile`, `--old-manifest`, `--new-manifest`,
`--old-snapshot`) and a fresh separate `--output`. Every input is bounded,
canonical and SHA-pinned. This creates only portable authorization JSON; it does
not validate firmware payloads or publish anything. Normal publication performs
the full payload verification again.

Use the existing publisher with `allow_asu_apk_migration=true`, the exact old
`replace_build_id`, this schema3 `migration_proof_base64`, and `bootstrap=false`.
`allow_native_apk_replacement` remains false: that separate REC policy does not
apply. The workflow already bounds and strictly decodes this JSON; no alternate
transport is introduced. Normal profile, immutable generation, package signing,
predecessor restoration, deployment and retained-channel controls remain active.
Do not activate before genuine new ImageBuilder approval/build/load, fresh signed
client verification and all three signed ImageBuilder smokes have passed for the
exact staged snapshot. Existing immutable staging can precede those signed
checks while the live pointer stays unchanged. Optional SDK recompilation is a
separate verification activity, never fabricated as a publication prerequisite.

After gated LATEST activation and fresh readback, update the active LATEST
profile to the exact generated successor profile
`6923e6be2fbfd2f4c880afc62b1b97053d71448c2686dd41e87829a773bd23b7`;
otherwise daily refresh would still select the old generation. Keep the active
profile unchanged until that cutover. Preserve the concurrently active REC
pointer/profile. Native Tailr2 archives and all original RAW inputs remain
unchanged; retaining any compact Tail supplement requires its own genuine
provenance and fresh solver/client checks for this LATEST native database.

The tests use public genuine metadata plus tiny synthetic TAR/FIT payloads.
They exercise real guard and decoder bodies; fixture identities never grant
native acceptance or publication authority.
