# Controller UCI normalization

`ax6000-mesh-normalize-networks CAPACITY_MANIFEST PRIVATE_SEED NEW_OUTPUT_DIR`
reads the controller's existing wireless, network, firewall and DHCP UCI. It
requires root and private root-owned regular manifest and seed files. It writes
only a private sibling staging directory, then renames that directory to the
previously absent output path. It does not modify UCI or start services. Caller
must serialize creation and reject candidates if the UCI generation changes
during normalization/publication.

The capacity manifest is JSON with integer `schema: 1`, boolean `confirmed:
true`, integers `capacity24: 4`, `capacity5: 4`, and `enrolled_agents`, an array
of unique lowercase unicast AL MAC addresses. This is an explicit operator
confirmation; the helper does not infer peer capabilities from runtime state.
The lifecycle owner must bind that confirmation to the actual enrolled cohort.

The seed contains integer `schema: 1`, integer `quarantine_vid`, and strings
`backhaul_ssid`, `backhaul_key`, `backhaul_security`, `quarantine_key`. Backhaul
security accepts `psk2` or `sae`. Secrets are read by filename, never passed in
external command arguments, and never printed to stdout or error diagnostics.

Outputs (directory mode 0700, files mode 0600):

- `policy.json`: existing schema-1 normalized network policy for the allocator.
- `credentials.json`: existing schema-1 credentials for the WTS stage helper.
- `quarantine_vid`: decimal quarantine VID and newline.
- `enrolled_agents.json`: object with an `agents` array.
- `cpu_guest_links.json`: object with `links`, each containing `ifname`,
  `network`, and integer `vid`. These are existing controller CPU links only.

Primary network is explicitly `lan` on static `br-lan`, VID 1, PCP 0, with
only one primary client BSS per band. Additional LAN SSIDs are unsupported. Guests
must already have static L3 interfaces using exact `br-lan.VID`, address and
netmask, an active DHCP pool, and unambiguous firewall zone membership whose
input and forwarding policies are REJECT or DROP and output is ACCEPT. Guest
wireless client isolation must already be enabled. The helper does not create
firewall rules, DHCP pools, bridges or VLAN interfaces. It rejects unsupported
security, multiple networks per BSS, unsupported radio bands and active modes.

Stable identities are UCI section names. `network` wins when present;
`mesh_network` restores the logical network when the materializer deliberately
removes a direct wireless attachment. Exact owned backhaul identities
`ax6000_mesh_ap1` and `ax6000_mesh_ap2` are excluded only when mode is AP and
`map_bss_type=64`. Exact owned slot placeholders ending in 24_2, 24_3, 5_2 or
5_3 are excluded only with `mesh_placeholder=1`. An arbitrary backhaul flag
cannot hide an unsupported user interface.

Cross-band SSIDs must agree on network, VID, security, key, isolation and hidden
state. Quarantine cannot collide with existing network device references,
bridge VLAN identifiers, the primary network or an active guest. Allocation,
retained tombstones, dense WTS staging and activation remain separate gates.

Controller bootstrap may call `ax6000-mesh-controller-sync preflight VID` before
enabling Linux traffic separation or changing bridge filtering. This runs the
same normalization, allocation, WTS and wireless materialization chain as normal
synchronization in a temporary private directory. It requires a committed,
enabled controller and the private capability manifest. Its quarantine key is
ephemeral; it publishes no credentials, allocation ledger or lifecycle journal,
and removes the stage on success or failure.

Generation staging snapshots network, DHCP, firewall, mesh configuration and
capabilities in addition to wireless. Changes during validation or before
publication/resumption invalidate the candidate. Even when WTS is unchanged,
changed non-wireless UCI snapshots require a new generation so transaction
adoption can preserve the latest accepted configuration.
