# Mesh transaction helper implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this assigned component. Parent owns the controller, vendor helper, and UI integrations; do not change their files.

**Goal:** Make automatic AX6000 agent network setup recoverable across interruption, watchdog expiration, and reboot.

**Architecture:** A shell helper stores a complete atomic, persistent snapshot and a pending/committed state. Early boot recovery and an independent procd watchdog restore pending setup only after detaching its backhaul. Existing committed enrollment is retained.

**Tech stack:** BusyBox ash, UCI, procd, Linux bridge interfaces, existing flock and timeout commands.

**Spec:** `docs/2026-10-27-mediatek-mesh-onboarding-design.md`, plus parent's explicit dedicated WAN-to-controller-LAN wiring decision, which supersedes its older LAN-to-LAN sentence.

## Global constraints

- Only supported AX6000 topology; wired agents use the physical WAN port for backhaul.
- Snapshot network, DHCP, wireless, Mesh settings, both DAT profiles, and changed map files, preserving absent paths and modes.
- Stop old DHCP/RA before attaching backhaul; detach backhaul before restoring original DHCP/IP.
- Pending boot recovery precedes network START20; watchdog expires after 360 monotonic seconds.
- Serialize with the existing Mesh lock; retain snapshots on partial restore failure.
- No device mutation by this implementer; only isolated tests.

## Review focus

- Process loss before atomic snapshot publication must leave original configuration unchanged.
- DHCP/RA stop failure must prevent bridge attachment.
- Backhaul detach failure must prevent original DHCP/IP restoration.
- User changes must be rejected, while expected vendor-learned credentials remain allowed.
- Committed transactions must survive reboot/link loss without watchdog rollback.

## Task 1: Durable snapshot and transaction API

Create `files/mediatek-mesh/packages/ax6000-mesh/files/usr/libexec/ax6000-mesh-transaction` and `tests/test_mesh_transaction.py`.

- [x] Write failing ash tests for complete snapshot, absent paths, interrupted publication, mode preservation, and pending-UCI rejection.
- [x] Implement begin/seal/check/commit/status with fixed paths and atomic state publication.
- [x] Verify snapshot corruption and real configuration conflicts fail closed.

## Task 2: Agent network transition and rollback

- [x] Write failing tests asserting DHCP/RA shutdown before WAN bridge attachment, and detach before original DHCP/IP restoration.
- [x] Implement prepare-agent/rollback with bounded service operations and retained snapshots on failure.
- [x] Verify rollback retry after partial restore and allowed vendor credential changes.

## Task 3: Independent watchdog and early boot recovery

Create recovery/watchdog init and worker helpers under the same package and extend isolated tests.

- [x] Write failing pending-reboot, timeout, stopped-job, and committed-reboot tests.
- [x] Implement START18 recovery and monotonic 360-second procd watchdog, using the shared Mesh lock.
- [x] Run focused transaction/recovery tests and ash syntax checks; hand exact API and validation evidence to parent without committing.

## Validation and handoff

- `python3 -m unittest discover -s tests -p test_mesh_transaction.py -v`: 29 passed under real BusyBox ash, including pinned rc.common dispatch.
- All four added shell scripts pass `busybox ash -n`; `git diff --check` passes.
- Snapshot publication failures and watchdog launch failures leave original configuration untouched. Interrupted snapshot writers never publish a valid state.
- Rollback verifies WAN detach or wireless APCLI down, restores original network first and DHCP last, retains the snapshot on any partial failure, and retries safely.
- Seal binds all four UCI packages before reload. Commit verifies those exact UCI bytes and records the generated vendor files/DAT after enrollment. Later checks allow only explicitly owned AP/BhProfile credential fields.
- Timeout recovery stops the worker. Every nonboot rollback marks restoration pending, drains stopped DHCP/RA processes for at most 20 polls, then invokes quiesce-radios before copying any original DAT/configuration. After restoring files, restore-radios loads modules before wifi up reloads network configuration. It waits for both radios before restarting DHCP, unloading an owned mapfilter module, or removing the snapshot. Boot recovery restores files without starting network services.
- Parent owns live router testing; this implementation made no live router changes and no commits.

## Cold driver rollback and upgrade validation

- Quiesce uses a 180-second callback bound; resume uses 270 seconds to include lock, module loads, wifi up and the 150-second radio-readiness budget.
- The immutable original snapshot remains intact while phase changes to pending before restoration, so an interrupted committed disable completes at early boot.
- The pinned sysupgrade selector and actual tar roundtrip retain all live UCI/DAT/vendor files plus every snapshot member. Boot recovery restores directory privacy and handles pending state before starting network services.
- Final combined command: `python3 -m unittest tests.test_mesh_transaction tests.test_mesh_sysupgrade -v`: 32 tests passed in 62.517 seconds. No device writes or commits by this implementer.
