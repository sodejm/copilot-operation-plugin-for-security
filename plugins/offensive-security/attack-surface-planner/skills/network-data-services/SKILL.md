---
name: network-data-services
description: Assess databases (MySQL, Postgres, MSSQL, Oracle), NoSQL/document stores (MongoDB, CouchDB, Cassandra), caches (Redis, Memcached), and search/analytics engines (Elasticsearch, InfluxDB, Kibana, Splunk) with bounded query budgets, synthetic canary verification, cleanup receipts, and data privilege candidate routing.
---

# Databases, Caches, and Search Services

1. **Protocol-Specific Database, Cache, and Search Probes**:
   - Assess exposure of relational databases (MySQL, Postgres, MSSQL, Oracle), NoSQL/document stores (MongoDB, CouchDB, Cassandra), caches (Redis, Memcached), and search/analytics engines (Elasticsearch, InfluxDB, Kibana, Splunk) across approved targets.
   - Ground assessments in observed protocol responses, versions, and configurations.

2. **Bounded Query Budgets & Zero Bulk Extraction**:
   - Enforce bounded query budgets (default 5 rows/documents) to verify schema, table/collection presence, and access controls.
   - Prohibit and block bulk data dumps, full collection scans, and unconstrained production record retrieval.

3. **Authentication Prerequisites & Data Privilege Routing**:
   - Determine whether services require authentication (`none`, `anonymous`, `default_credentials`, `user_password`, `client_cert`, `token_or_api_key`, `kerberos`, `unknown`).
   - Extract `DataPrivilegeCandidate` entries for lateral movement and database takeover workflows.

4. **Canary Validation and Verifiable Cleanup Receipts**:
   - Validate access controls using benign canary identifiers (`canary_audit_table`, `canary_cache_key`) without modifying production data.
   - Emit verified `CleanupReceipt` records confirming rollback and artifact removal (`verified_removed`).

5. **Inaccessible != Secure Truth Boundary**:
   - Strictly mark unreachable, filtered, or connection-refused services as `inaccessible` (with `auth_prerequisite: unknown`). Never claim unverified services are protected or secure.

6. **CLI Invocation**:
   ```bash
   python3 -m cops data-services assess --targets db01.corp.internal --canary-id "canary_audit_table" --output data_report.json
   python3 -m cops data-services candidates data_report.json --output data_candidates.json
   python3 -m cops data-services cleanup data_report.json --output cleanup_receipts.json
   python3 -m cops data-services inspect data_report.json
   ```
