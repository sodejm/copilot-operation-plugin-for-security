---
name: network-passive-discovery
description: Normalize passive asset telemetry, preserve multi-source evidence provenance, and reconcile scope quarantine.
---

# Network passive discovery

1. **Ingest and Normalize Telemetry**:
   - Collect and normalize multi-source DNS records, certificate transparency logs, IP allocations, endpoints, and cloud exports without active scanning.
   - Bind every record to an immutable `EvidenceProvenance` envelope containing SHA-256 digest and collection timestamp.

2. **Deduplicate Observations**:
   - Merge overlapping observations of identical network entities while retaining multi-source provenance lineages.
   - Detect conflicting ownership or tenant identities across merged evidence streams.

3. **Reconcile Scope Quarantine**:
   - Classify all assets against authorized engagement boundaries into `verified_in_scope`, `quarantined`, or `excluded`.
   - Quarantine assets with uncertain ownership, conflicting attributes, stale pointers, or missing provenance so discovery cannot expand engagement boundaries.

4. **CLI Invocation**:
   ```bash
   python3 -m cops discovery normalize <records.json> --type dns --output inventory.json
   python3 -m cops discovery reconcile inventory.json --scope scope.json --output reconciled.json
   python3 -m cops discovery merge inv1.json inv2.json --output merged.json
   python3 -m cops discovery inspect inventory.json
   ```
