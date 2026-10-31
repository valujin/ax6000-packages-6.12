# Managed native EasyMesh rollout contract

The default remains the existing two-slot native enrollment. A validated release capability permits the post-commit bootstrap service to bind that enrollment and transition automatically to the measured four-slot topology. No capability is shipped by this change, and software tests are not wireless packet-isolation evidence.

## User flow and supported scope

The user enables Mesh once using the existing enrollment flow. After native enrollment commits and genuine topology confirms a connected controller/agent (the controller waits for its first native peer), `ax6000-mesh-managed` validates the installed release capability, derives private per-enrollment transport/capacity contracts, checks the network policy without changing it, and journals a management-preserving bridge transition. It then invokes the controller or agent slot coordinator and starts `ax6000-mesh-sync`. There is no user UCI toggle, per-boot nonce approval or per-device packet-test assertion.

The initial release profile is `wireless-tagged-br-lan-v1` on Redmi AX6000, management VID1, four AP slots per radio (FH0/BH1/FH2/FH3), and a reserved quarantine VID. Wired backhaul and custom bridge topologies are unsupported by this automatic binding profile. Without valid release evidence, enrollment continues in its existing two-slot mode and managed synchronization reports unsupported/pending rather than enabling guests.

Controller guests must already have a static `br-lan.VID` network, DHCP and an exclusively owned restrictive firewall zone. The normalizer refuses custom forwarding, aliases, extra LAN SSIDs, inconsistent crossband credentials/security/isolation and unowned active interfaces. Guest AP isolation is mandatory. Each guest zone must contain only its own guest network; only conventional guest-to-WAN forwarding and narrow DHCP/DNS input exceptions are accepted. Guest-to-LAN/other-guest overrides, wildcard selector bypasses and active custom firewall includes are rejected, while unrelated WAN-to-LAN port forwards remain supported. CPU tagged membership and the actual controller 802.1Q device must exist before guest activation; the reconciler never authors L3/firewall/DHCP. Creating such network services remains the normal OpenWrt network/firewall configuration workflow.

## Bounded hardware acceptance before a release proof exists

A private two-device guest experiment is being prepared for independent review. Its scenario and harness are not yet approved for execution; this section describes their required properties, not a release or test authorization. Four AP slots per radio have been measured on the node. Controller capacity and native row mapping still require their own measurement. Neither capacity evidence nor successful configuration checks prove packet isolation.

The experiment must persist and verify the exact management bridge UCI candidate before publishing slots. A runtime-only bridge change is insufficient: Wi-Fi setup reloads netifd and can recreate the bridge from UCI. Production transaction adoption requires valid release evidence and must not be bypassed silently. The proposed one-shot adapter is a private, hash-bound copy of the exact transaction helper, restricted to `adopt-managed-bootstrap`, with only its release guard replaced by a narrowly scoped experiment guard. It retains the installed candidate reconstruction, committed-phase and journal checks, unchanged-unrelated-files checks, original snapshot and expected-seal verification. It does not modify the installed transaction helper, create a release capability, or permit an uncertain adoption to be retried forward.

Each router needs its own complete, verified baseline and independent persistent boot and timeout recovery before any mutation. Recovery must stop and quarantine guest forwarding, unload the currently configured radio driver before restoring DAT, restore the original UCI, native files, Mesh state, firewall, DHCP and service state, and verify management and native recovery. Failed or interrupted restoration must remain recoverable and must not be reported as successful. The existing capacity recovery helper alone does not cover this complete guest rollback.

Any future experiment must use genuine current native policy and BSSID/VID observations, stage guests disabled, and explicitly authorize only the bounded test generation. Actual client traffic and isolation, including hardware/offload behavior, must be measured; bridge tables, a staged nonce, and native renewal acceptance are not packet proof or a remote acknowledgment. The offline scenario and one-shot adoption/recovery harness remain subject to independent review and do not establish publication or automatic bootstrap readiness. A release capability can be considered only after the required real packet, failure and recovery acceptance succeeds for the exact frozen payload, followed by a separate test of the normal automatic path.

## Release acceptance and deployment

Install the complete `files/mediatek-mesh/packages/ax6000-mesh/files` tree from one frozen build, including main, managed and sync init scripts, and the managed bridge hotplug hook. Required tools are UCI, jshn, jsonfilter, ucode/fs, ip/bridge JSON VLAN support, flock, timeout and setsid. Install the matching native mapd/1905 schema-2 TS patches and mtwifi netifd pre-attachment gate. Preserve WAPP/mapd/1905 and the existing SAE environment.

Before issuing an attestation, the release owner must verify actual four-VIF capacity and native WTS row→interface mapping on each supported radio, dense placeholders without credential shifting, and real packets through the hardware/offload path. Acceptance includes guest-to-management denial, intended guest isolation, guest DHCP, tag preservation over wireless backhaul, management DHCP, new valid guest VID, slot deletion/reordering, reconnect, reboot, daemon/worker/supervisor termination and rollback preserving user configuration. Source support for indices up to15 and successful isolated kernel tests are not this evidence.

After those tests, distribute a root-owned regular `/etc/ax6000-mesh-dataplane-capability.json`, not group/other writable. Its schema is:

```json
{
  "schema": 2,
  "packet_tested": true,
  "platform": "xiaomi,redmi-router-ax6000",
  "topology": "wireless-tagged-br-lan-v1",
  "capacity24": 4,
  "capacity5": 4,
  "management_vid": 1,
  "quarantine_vid": 4093,
  "abi_sha256": "actual digest",
  "driver_sha256": "actual digest",
  "implementation_sha256": "actual digest",
  "native_sha256": "actual digest"
}
```

4093 is an illustrative reserved VID; the release must explicitly choose its reservation, which provisioning rejects if already allocated. The artifact contains release-test evidence, not secrets. No runtime helper creates `packet_tested` or changes an invalid capability into a valid one.

`abi_sha256` hashes `/etc/ax6000-mesh-abi.json`; `driver_sha256` hashes the actual `/lib/modules/$(uname -r)/mt_wifi.ko`. `native_sha256` hashes the concatenation of SHA256 digests, each followed by newline, of `/usr/bin/wapp`, `/usr/bin/mapd`, `/usr/bin/p1905_managerd`, in that order.

`implementation_sha256` uses the same newline-delimited digest construction over `/usr/libexec/ax6000-mesh-` helpers, in this order: ts-capability, ts-provision, ts-declare, ts-own, ts-gate, ts-runtime, ts-reconcile, ts-supervise, ts-observe, managed-bootstrap, bootstrap-bridge, controller-sync, agent-sync, normalize-networks, allocate-slots, stage-wts, materialize-networks, agent-slots, control, transaction, vendor. Append the digests of `/etc/init.d/ax6000-mesh`, `/etc/init.d/ax6000-mesh-sync`, `/etc/init.d/ax6000-mesh-managed`, `/lib/netifd/wireless/mtwifi.sh`, `/etc/hotplug.d/net/95-ax6000-mesh-managed`, `/usr/bin/wifi_config_save`, `/usr/share/ax6000-mesh/vendor.sh`, in that order. The installed verifier is the authoritative format.

A changed implementation, native executable, driver, ABI or unsupported platform invalidates the artifact. A release pipeline may distribute a separately accepted new artifact; it must not label untested code as tested. MAC addresses and otherwise valid guest VIDs are not hardcoded in the release proof.

## Local binding, recovery and authority

`ax6000-mesh-ts-provision bootstrap` first verifies release evidence, committed role/backhaul and genuine native topology. It binds the actual controller/local ALIDs and allowlisted existing bridge members into private `ts-transport.json`, a four-slot capacity manifest and `ts-provision-binding.json`. The binding includes exact release/transport/capacity hashes. It neither changes the bridge nor asserts cryptographic peer authentication; this uses the existing native trusted LAN control domain.

The persistent binding permits management-only bridge recovery before radio/native topology is available after reboot. The bootstrap journal allows only its reconstructed network/mesh UCI candidates, preserves immutable enrollment originals and never adopts unrelated wireless/vendor changes. Once a slot publication begins, its own journal owns recovery; reverting only bridge configuration is not a claimed restoration of the two-slot radio state. A netifd bridge recreation restores default PVID zero and management CPU PVID/untagged semantics before managed radio attachment.

Every guest activation still needs fresh native schema-2 policy, matching controller ALID, current boot/PIDs/start times/connection epoch, actual BSSID, exact VID and reconciled bridge inventory. A root-derived generation nonce is issued only after disabled staging and release-proof validation; it is not another packet-test claim. The independent supervisor owns worker death/restart cleanup. Unknown and placeholder ports remain down/unbridged.

## Synchronization and honest status

Controller configuration is normalized on the next policy pass (up to30 seconds), with wireless/network/DHCP/firewall/Mesh reload triggers. The controller publishes private dense WTS and stable ledger, regenerates the measured slots and invokes native1905 renewal through mapd_cli. Native WSC supplies agent credentials. No SSH replacement control plane is used. Journals refuse to overwrite newer user configuration. The observer validates the currently accepted UCI snapshots on each pass and before activation; a changed or rejected policy stops the old supervised guest generation. Accepted user network/DHCP/wireless edits have a separate rollback overlay while enrollment originals remain immutable. That overlay removes only the exact bootstrap-owned management bridge section and restores the original filtering option, retaining later user guest/WAN edits; conflicting edits to owned settings are refused.

Remote `applied_generation` remains null and `pending_unverified` until a genuine remote dataplane acknowledgment exists. Successful renewal means only that the native command was accepted. Local verification and generic release acceptance do not manufacture a remote ACK. Automatic synchronization has software and isolated-kernel coverage; live guest/offload packet acceptance remains required before a release capability can be issued.

## MU-MIMO reload regression (2026-10-29)

A controller Wi-Fi apply exposed an ownership-check ordering bug: the radio-ready callback stopped the native daemons before validating changes to the sealed wireless configuration. Enabling the original client APs' `mumimo_dl`/`mumimo_ul` flags therefore left the controller stopped and its wireless agent disconnected, even though the radios were up.

Runtime `ax6000-mesh 1-r10` validates these bounded boolean changes before restarting daemons. A separate authenticated radio preimage and journal track accepted tuning without rewriting immutable enrollment snapshots. Existing enrollments capture an unchanged baseline automatically; already changed legacy enrollments require an independently retained preimage matching the old seal. Disable restores the original user topology while preserving accepted MU flags. Unrelated edits remain rejected; the callback reports a fixed LuCI error and does not stop native daemons on validation failure.

Focused checks passed: 33 radio-tuning tests, 3 callback tests, 5 restart tests, 30 transaction tests and 9 RPC tests. Independent review also exercised the actual captured controller configuration and canonical agent WTS behavior. On the two real AX6000 devices, the controller retained all four enabled MU flags and the agent rejoined without re-enrollment. Subsequent MU off/on Wi-Fi reload cycles recovered the wireless native EasyMesh link in approximately 37 and 38 seconds respectively. These timings are observations from this setup, not a universal reconnect deadline. The local r10 APK was built and verified separately; this does not constitute full firmware, guest isolation or SDK acceptance.
