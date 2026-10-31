# Offline controller network materialization

`ax6000-mesh-materialize-networks PLAN_JSON CREDENTIALS_JSON SOURCE_WIRELESS NEW_OUTPUT_DIR [ORIGINAL_WIRELESS]`

The helper consumes the allocator's schema-1 proposed plan, the normalizer's
private schema-1 credentials, and a private wireless UCI snapshot. It creates a
new private directory containing `wireless` (staged managed configuration) and
`user-wireless` (user configuration for restoration). It does not publish either
file, reload wireless, change the live UCI configuration, or activate traffic
separation. The caller must bind both files to the same transaction generation.

Both bands require an active primary BSS in retained slot 0 and an existing
backhaul AP (`ax6000_mesh_ap1` for 2g, `ax6000_mesh_ap2` for 5g) in slot 1.
Backhaul settings and credentials remain unchanged. Named user sections retain
SSIDs, credentials, arbitrary extra options and list options. They are ordered
by allocator slot, with vacancies and tombstones represented by hidden APs
named `ax6000_mesh_slot24_2`, `ax6000_mesh_slot24_3`,
`ax6000_mesh_slot5_2`, and `ax6000_mesh_slot5_3`. Placeholders use the private
`quarantine_key`, `mesh_placeholder=1` and `map_bss_type=32`.

Every guest loses its UCI `network` attachment and retains its logical network
as `mesh_network`; placeholders have neither attachment. Primary-network user
BSSs retain their network attachment. Consumers must read `network`, falling
back to `mesh_network`. Primary radio/device ordering is retained. All APs move
to the end of the package in per-band slot order; other sections retain their
relative ordering and content.

The helper rejects unplanned wireless interfaces, including disabled APs and
unowned STA interfaces, reserved-name collisions, duplicate slots, missing backhaul
APs, multiple devices for one band, or normalized source fields/credentials
that changed before staging. Exact owned STA overlays `ax6000_mesh_bh1` and `ax6000_mesh_bh2`
are accepted only in STA mode, preserved, and ordered after the complete AP
bank. Restoration removes these owned STA overlays as well.

Restoration removes managed backhaul and placeholder sections, restores guest
network attachments, and removes mesh ownership options. When an original
pre-enrollment wireless snapshot is supplied, original `map_bss_type`,
`mesh_network`, `map_mode` and `map_agent` values are restored while current
user SSIDs, keys and other settings are retained. Without that snapshot,
those ownership options are removed. Prior ordering is not reconstructed from
the original snapshot; current user section ordering is preserved.

All writes use private clones with a unique UCI package name, explicit `-c`,
`-C` and `-t` paths, and batch commands on stdin. The unique name prevents
pending live `wireless` deltas from being read through UCI's default delta
search path. UCI `-P` must not be substituted: it disables commit. Credentials
are never passed as external command arguments. A successful output is mode
0700 with mode-0600 files; failures leave no published output directory.

Tests use actual host UCI and jshn, with `MESH_TEST_UCI` selecting the host UCI
binary. Run `python3 -m unittest discover -s tests -p test_mesh_network_materialize.py -v`.


## Offline agent bootstrap

`ax6000-mesh-agent-slots CAPACITY_MANIFEST NEW_OUTPUT_DIR` requires committed
managed agent enrollment and a private root-owned confirmed four-slot manifest.
It snapshots current wireless and mesh UCI into unique private packages, accepts
one active LAN primary AP per band plus exact owned overlays, and invokes the
allocator and materializer. Outputs are `wireless`, `user-wireless`, `plan`,
and private `quarantine-key`. The quarantine credential comes from existing
owned placeholders, the private persisted seed, or fresh random bytes in that
order. Repeated staging from materialized wireless preserves the credential.
The helper never writes persistent state or publishes UCI; its caller owns
quiescing, publication, restart, and accepted-overlay adoption. It does not
read or replace native controller-provisioned DAT credentials.
