---
name: network-passive-discovery
description: Normalize passive asset telemetry, preserve multi-source evidence provenance, and reconcile scope quarantine.
---

# Network Passive Discovery

Normalize DNS, certificate transparency, IP allocation, endpoint, and cloud export records, maintain strict evidence provenance with cryptographic checksums, deduplicate multi-source observations, and reconcile ownership against authorized engagement scope.

## Core Responsibilities

1. **Multi-Source Ingestion & Normalization**:
   - Ingest raw DNS records (A, AAAA, CNAME, TXT, MX, NS), TLS/CT certificates, IP ranges, endpoints, and cloud exports.
   - Produce canonical `DiscoveredAsset` records with deterministic 24-character asset identifiers.
2. **Evidence Provenance Preservation**:
   - Bind every normalized observation to an immutable `EvidenceProvenance` record with source identifier, SHA-256 hash, and extraction timestamp.
   - Retain full provenance lineage across multi-source merges.
3. **Multi-Source Deduplication**:
   - Merge overlapping or identical entity observations without inflating inventory counts.
   - Detect conflicting ownership or tenant identities across merged evidence streams.
4. **Scope Quarantine Reconciliation**:
   - Classify discovered assets into:
     - `verified_in_scope`: clearly belongs to authorized targets, within approved boundaries.
     - `quarantined`: uncertain ownership, conflicting attributes, stale pointer, or missing provenance.
     - `excluded`: matches explicit exclusion list or outside scope boundary.
   - Enforce quarantine so discovery cannot expand engagement boundaries without operator sign-off.

## CLI Usage

### Normalize Raw Records

```bash
python3 -m cops discovery normalize path/to/dns.json --type dns --output path/to/inventory.json
```

### Reconcile Against Scope

```bash
python3 -m cops discovery reconcile path/to/inventory.json --scope path/to/scope.json --output path/to/reconciled.json
```

### Merge Multiple Inventories

```bash
python3 -m cops discovery merge inv1.json inv2.json --output path/to/merged.json
```

### Inspect Inventory Summary

```bash
python3 -m cops discovery inspect path/to/inventory.json
```

## Python API

```python
from cops.discovery import (
    EvidenceProvenance,
    merge_inventories,
    normalize_dns_record,
    reconcile_asset,
)
```
