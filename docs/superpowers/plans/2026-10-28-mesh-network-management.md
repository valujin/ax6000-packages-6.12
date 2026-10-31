# Mesh network management implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development. Root alone changes live routers. Independent workers own disjoint source files and tests.

**Goal:** Implement the user’s nine requested Mesh capabilities, preserving the migrated production gateway and guest isolation.

**Architecture:** Retain the pinned MediaTek MAP R2 stack and native adaptive PHY. Add strict SAE backhaul, persistent band policy, bounded read-only telemetry, conservative AP service ownership, and explicit multi-network/VLAN provisioning. Vendor success messages are not evidence of Linux bridge configuration or packet isolation.

**Tech Stack:** MediaTek mt_wifi 7.6.7.3, mapd/WAPP/1905, OpenWrt UCI/netifd/firewall4, shell/Python/C, rpcd and LuCI JavaScript.

**Spec:** User requirements of 2026-10-28, including explicit guest isolation/VLAN confirmation; guest design in ../specs/2026-10-28-mesh-networks-design.md.

## Global constraints
- Only recommended 25.12/6.12 maintained; no ASU, no hosted target builds.
- Main LAN 192.168.10.1, PPPoE, existing Wi-Fi credentials, firewall/forwards and DHCP reservations remain intact.
- Root controls device state; N95 independent Wi-Fi remains available.
- Existing WPA2 Mesh remains valid until an explicit transactional re-enrollment. New strict SAE must not silently downgrade.
- Preserve automatic NSS/MCS negotiation; four-stream capability is not a forced per-peer rate.
- Guests must never fall into the management LAN, including startup, failed provisioning and rollback.
- Preserve truthful build/SDK provenance. The running e1c474c native build is an immutable baseline; defer another full SDK build until scope stabilizes.

## Review focus
- Offline/rebooting node receives the current policy without exposing guest traffic.
- Mixed 2x2/4x4 and unsupported bands/security fail or adapt accurately without falsely reporting 4803 Mbps.
- Missing, stale or malformed remote metrics remain unknown; topology credentials never reach the browser.
- Other services/interfaces survive AP mode and exact prior enable/running states return on disable.
- Protected management reachability and prior configurations survive any failed Mesh operation.

### 1. Baseline and real throughput (root)
- [ ] Confirm isolated wireless path with physical wired uplink disabled.
- [ ] Record negotiated width/NSS/MCS/rate and band from actual driver state.
- [ ] Run bounded TCP forward/reverse tests between router CPUs; record CPU/path limitations and raw JSON.

### 2. Strict WPA3 and band policy (WPA3 worker, then root integration)
Files: mapd patch150+, vendor.sh, ax6000-mesh-profile/control, dedicated tests; root integrates UCI/rpc/LuCI fields after telemetry worker.
- [ ] Test both mapd SAE downgrade branches, pure/mixed/legacy profiles and malformed profiles.
- [ ] Implement backhaul_security=sae|psk2, missing legacy value=psk2; new setup default=sae.
- [ ] Add backhaul_band=auto|5g|2g mapping native priorities 3/1/1, 0/1/1, 1/0/0.
- [ ] Verify pure SAE+PMF, PBC, persistence, band selection and reboot on hardware; patch driver WSC mapping only if necessary and validated.

### 3. Lean AP lifecycle (runtime worker)
Files: ax6000-mesh-transaction, dedicated service lifecycle tests.
- [ ] Preserve enabled/running state and old snapshot compatibility.
- [ ] Stop unneeded DHCP/DNS processes only for a conservatively proven pure AP; retain other interface needs and firewall filtering.
- [ ] Test transition failure, reboot persistence and disable restoration without DHCP leakage onto uplink.

### 4. Network-wide client and node visibility (telemetry worker)
Files: mapd bounded JSON exporter patch140, new clients helper, rpcd mesh method, LuCI Mesh table; later main wireless station table integration.
- [ ] Test bounded output, metric units/validity, malformed records and credential exclusion.
- [ ] Join authoritative leases to advertised node/client MACs without guessed MAC offsets.
- [ ] Show serving AP/band, IP management links, signal/rates/counters when known; disable unsupported remote disconnect actions.
- [ ] Compare UI rows against live local and remote associations.

### 5. Multiple networks and guest VLANs (network worker + root)
Files: dedicated network policy planner/helper/tests, then reviewed driver persister/WTS/bridge integration.
- [ ] Specify stable BSS slots/VID mapping, capacity negotiation, guest security semantics and exact policy delivery.
- [ ] Test policy conflicts, capacity, duplicate SSIDs, VID collisions and unsupported authentication.
- [ ] Validate actual driver tagging and DSA bridge packet path before enabling traffic separation.
- [ ] Implement atomic provisioning, last-known-good rollback and offline-node synchronization, without flattening guest traffic.
- [ ] Test create/change/delete of LAN and guest networks, wired/wireless delivery, guest-to-LAN denial, client isolation and reboot.

### 6. Client steering (root + source research)
- [ ] Confirm vendor client steering/802.11k/v knobs separately from backhaul preference.
- [ ] Prefer 5 GHz subject to signal/load/client capability; preserve client-controlled association and avoid forced poor links.
- [ ] Verify emitted capabilities and compatible client transitions; explicitly distinguish unavailable physical roaming tests from passing tests.

### 7. Integrated build/publication and cleanup
- [ ] Review all changes, run meaningful regression/source/native/SDK checks once final scope is stable.
- [ ] Publish signed coherent images/packages and validate protected ABI/version pins on migrated routers.
- [ ] Restore test networking, remove temporary access, save final private backups and report actual results/limitations.
