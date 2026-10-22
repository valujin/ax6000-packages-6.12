Public metadata for the finite LATEST same-Image policy tests.

`before-manifest.json.gz` is the exact 327805-byte manifest downloaded read-only
from immutable firmware Release419152056, asset661318733, SHA256
459a7e06661b22e3b21a66ecb2e67d4416c3e0b1aef8c279305c97e0a1f49567.
The Release/tag/manifest metadata was rechecked after the download.
`catalog.json.gz` and `catalog.sig` are the genuine public predecessor download
catalog and its verified public-key signature from signed snapshot074e68e5….
`after-manifest.json.gz` is the exact genuine successor manifest, SHA256
0f8095952e7e4444dc464865d4b9608f507b56035f67e8df01e90fc6bd7a3ff2.

`metadata.json` contains public profile, patch-ledger, predecessor-pointer and
native identity policy metadata. No private key, token, firmware, SDK or actual
kernel payload is included. These files supply test data, never acceptance.
The legacy transport fixture substitutes only Release API I/O; the normal
resolver and payload verification run and reject absent actual firmware.
Tiny generated TAR/FIT files exercise the real six-payload decoder separately.
