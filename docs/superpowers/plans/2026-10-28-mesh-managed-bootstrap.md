# Managed Mesh bootstrap

Implement an automatic, post-commit transition from the working two-slot vendor enrollment to the existing managed synchronization workers. Missing or invalid measured capacity, transport authority, or hardware dataplane capability must leave enrollment untouched and report unsupported guest synchronization.

The new bootstrap service owns only this transition, its private journal, and management-preserving bridge preparation. It never creates capability or packet-test evidence. A separate kernel helper snapshots and validates all current bridge members, requires guest slots down/unbridged, stages explicit untagged management before filtering, verifies each command, and restores the original bridge mode on failure. The bounded initial topology retains management VID 1 and refuses unknown ports or conflicting bridge-VLAN ownership. Persistent UCI belongs to an exact private candidate journal validated by a coordinated transaction adoption API; immutable enrollment originals are preserved.

1. Add real-ucode kernel-model tests first: successful transition, command failure/readback failure, unknown port, quarantine collision, live guest refusal, capability/transport mismatch, recovery and identity drift.
2. Implement the bounded bridge helper and verify actual ucode behavior against the model.
3. Add the shell coordinator with real BusyBox shell tests: unsupported capability performs no writes, exact staged UCI and adoption order, failed transition rollback, restart/idempotence and interrupted journal recovery.
4. Add a separate procd bootstrap service and bridge hotplug trigger; serialize bootstrap against Mesh operations and recheck policy on bounded retry. Coordinate the existing sync worker and transaction API before wiring activation.
5. Run focused regression suites. Source tests are not hardware isolation evidence; retain pending/unverified remote acknowledgment semantics.
