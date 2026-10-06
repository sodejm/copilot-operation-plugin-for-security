---
name: network-data-services
description: Assess databases (MySQL, Postgres, MSSQL, Oracle), NoSQL/document stores (MongoDB, CouchDB, Cassandra), caches (Redis, Memcached), and search/analytics engines (Elasticsearch, InfluxDB, Kibana, Splunk) with bounded query budgets, synthetic canary verification, cleanup receipts, and data privilege candidate routing.
---

# Database, Cache, and Search Services Assessment

Execute authorized, bounded exposure and configuration assessments across relational databases, NoSQL stores, in-memory caches, and search/analytics engines under strict Rules of Engagement and operational boundaries.

## Core Capabilities

1. **Protocol-Specific Coverage**:
   - **Relational Databases**:
     - **MySQL (3306)**: Assesses unauthenticated root/anonymous accounts, empty passwords, native password vs caching sha2 authentication, and bind-address exposure.
     - **PostgreSQL (5432)**: Detects `trust` authentication method, unauthenticated `postgres` superuser access, and client certificate enforcement.
     - **Microsoft SQL Server (1433)**: Probes blank `sa` password, SQL Server vs Windows Integrated Authentication, and `xp_cmdshell` configuration exposure.
     - **Oracle Database (1521)**: Evaluates TNS listener security, default SID/Service Name exposure (e.g. `ORCL`, `XE`), and default administrative accounts (`SYS`, `SYSTEM`).
   - **NoSQL & Document Stores**:
     - **MongoDB (27017)**: Detects missing authentication (`--auth` disabled), open cluster access, and unauthenticated database listing.
     - **CouchDB (5984)**: Detects Admin Party mode (unauthenticated admin role on `/_all_dbs`), basic auth vs cookie session enforcement.
     - **Cassandra (9042)**: Assesses default superuser credentials (`cassandra`/`cassandra`), `AllowAllAuthenticator` vs `PasswordAuthenticator`.
   - **In-Memory & Caches**:
     - **Redis (6379)**: Detects missing `requirepass`, dangerous command execution (`CONFIG`, `FLUSHALL`, `MODULE LOAD`), and unauthenticated data exfiltration/poisoning.
     - **Memcached (11211)**: Probes ASCII/binary protocol without SASL authentication, unauthenticated stats inspection, and item dumping.
   - **Search & Analytics Engines**:
     - **Elasticsearch (9200)**: Detects disabled security features (`xpack.security.enabled: false`), open cluster API access (`/_cluster/health`, `/_cat/indices`), and unauthenticated search index queries.
     - **InfluxDB (8086)**: Evaluates HTTP API ping and query endpoints without mandatory token or user/password authentication.
     - **Kibana (5601)**: Probes open web analytics dashboards exposing saved objects, visualizations, and index patterns without authentication.
     - **Splunk (8089)**: Detects management port exposure with default administrative credentials (`admin`/`changeme`) or unencrypted API management.

2. **Bounded Query Budgets & Zero Bulk Extraction**:
   - Technical probes strictly enforce a bounded query budget (default 5 rows/documents) to verify schema, table/collection presence, and access controls.
   - **Zero Bulk Extraction**: Bulk table dumps, full collection scans, and unconstrained production record retrieval are strictly prohibited and architecturally blocked.

3. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If a database, cache, or search service is timed out, connection-refused, filtered, or unreachable from the probe vantage, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes.
   - A service is **NEVER** reported as `protected` or `hardened` merely because it failed to respond. Only positive verification of authentication enforcement or access rejection warrants a `protected` status.

4. **Canary Validation and Verifiable Cleanup Receipts**:
   - Uses non-destructive canary identifiers (e.g. `canary_audit_table`, `canary_cache_key`) to verify write boundaries and probe containment.
   - Every assessment verifying canary artifacts generates a cryptographically hashed `CleanupReceipt` confirming that temporary artifacts were removed and the system state was restored (`verified_removed`).

5. **Data Privilege Candidate Routing**:
   - Discovered misconfigurations and weak boundaries are structured as `DataPrivilegeCandidate` records:
     - `redis_no_auth` / `redis_config_set`: Unauthenticated Redis allowing cache poisoning or remote code execution.
     - `elasticsearch_open_cluster`: Open cluster API allowing index data exfiltration.
     - `mongodb_no_auth`: Open MongoDB cluster enabling database takeover.
     - `memcached_no_auth`: Unauthenticated memory cache allowing key/value extraction.
     - `mysql_no_auth`: Unauthenticated root or anonymous MySQL user.
     - `postgres_trust_auth`: PostgreSQL `trust` authentication enabling database takeover.
     - `mssql_blank_sa`: Microsoft SQL Server blank `sa` password.
     - `couchdb_admin_party`: CouchDB Admin Party mode enabling administrative takeover.
     - `cassandra_default_superuser`: Cassandra default `cassandra`/`cassandra` superuser.
     - `influxdb_no_auth`: Open InfluxDB HTTP API enabling analytics tampering.
     - `kibana_no_auth`: Open Kibana analytics dashboard.
     - `splunk_default_creds`: Splunk management daemon with default credentials.
   - Binds cryptographic evidence hashes, auth prerequisites, and privilege impact ratings (`remote_code_execution`, `database_takeover`, `credential_harvesting`, `data_exfiltration`, `cache_poisoning`, `analytics_tampering`) for handoff to host and lateral movement specialists (`cops-pentest-specialist`, `cops-redteam-operator`).

## CLI Usage

### 1. Assess Database, Cache, and Search Services
```bash
python3 -m cops data-services assess \
  --targets "198.51.100.30,db01.corp.internal" \
  --vantage internal \
  --canary-id "canary_audit_probe" \
  --query-budget 5 \
  --output data_assessment.json
```

Or via the discovery namespace:
```bash
python3 -m cops discovery data assess \
  --targets "198.51.100.30,db01.corp.internal" \
  --vantage internal \
  --output data_assessment.json
```

### 2. Export Data Privilege Candidates for Lateral Movement Workflows
```bash
python3 -m cops data-services candidates data_assessment.json \
  --output data_candidates.json
```

### 3. Export Verified Cleanup Receipts
```bash
python3 -m cops data-services cleanup data_assessment.json \
  --output cleanup_receipts.json
```

### 4. Inspect Summary, Privilege Candidates, and Truth-in-Advertising Metrics
```bash
python3 -m cops data-services inspect data_assessment.json
```
