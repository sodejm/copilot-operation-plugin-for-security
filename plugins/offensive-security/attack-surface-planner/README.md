# COPS Attack Surface Planner

The **Attack Surface Planner** helps offensive security engineers and red teams plan strictly authorized, scope-compliant assessments against Microsoft/Azure environments.

In complex enterprise environments, cloud boundaries blur quickly: an organization often manages dozens of Azure subscriptions, partner tenants, shared IP ranges, and historical DNS records. Accidentally probing an out-of-scope asset or unapproved third-party service can lead to severe compliance violations, legal liability, or cloud provider service suspensions.

The Attack Surface Planner acts as an **ethical guardrail for offensive operations**. It takes your human-signed Rules of Engagement (RoE) alongside local asset inventory exports, cross-references them, and partitions discoveries into three strict buckets: `in_scope`, `excluded`, and `unresolved`. It then drafts a structured, non-intrusive observation plan that keeps your testing 100% compliant with approved boundaries.

The planner operates completely offline, making zero network requests, tenant API calls, or active scans.

---

## When to Use & Offensive Engineer Playbook

For step-by-step scoping workflows, authorization templates, and compliance tracking, see the complete [Offensive Engineer & Red Teamer Playbook](docs/PLAYBOOK.md).

Use this planner when:
- **Scoping authorized offensive engagements**: Translating human-signed rules-of-engagement contracts into actionable asset inventories.
- **Reconciling multi-tenant cloud boundaries**: Partitioning Azure, Entra ID, and public endpoint exports into verified in-scope vs. excluded targets.
- **Planning passive reconnaissance**: Designing non-intrusive observation steps without executing unauthorized network calls.
- **Documenting engagement compliance**: Establishing verifiable audit trails, emergency stop conditions, and cleanup steps before testing begins.

---

## The Foundation: Rules of Engagement

Every engagement begins with explicit human authorization. Before generating a plan, ensure the assessment owner has signed off on:
- Approved Tenant IDs and Azure Subscription IDs
- Explicit DNS domain names and IP ranges
- Designated testing windows (UTC) and allowed observation methods
- Explicitly excluded assets (e.g., mission-critical production clusters or third-party partner services)

Record this sign-off in your local scope manifest. Discovered assets never automatically expand scope—if an asset's ownership is unverified, the planner flags it as `unresolved` and blocks testing until an authorized human signs off.

### Planning versus execution authority

The planner's report and sign-off record document scope; they do not authorize a worker to execute operations. A separate execution phase must bind the complete approved Action Plan and expected worker identity to an authenticated authorization, validate it through verifier-owned trust and the active Engagement, compare signed requirements with an independently owner-provisioned worker capability inventory, and consume it once. COPS loads that inventory as a trusted measurement artifact; it does not discover installed executables at runtime. Never place signing secret bytes in the plan, authorization, scope manifest, worker request, or inventory. Follow the repository [Authenticated Execution Guide](docs/AUTHENTICATED_EXECUTION.md) for provisioning, setup, migration, rotation, and rejection handling.

---

## Quick Test Drive (Offline Demo)

You can explore how the planner reconciles assets using the included synthetic test fixtures:

```bash
# From the repository root:
python3 -m cops demo attack-surface-planner

# Or run the script directly from the package directory:
python3 scripts/plan.py fixtures/synthetic/scope.json
```

### What to look for
The planner outputs a structured JSON report to standard output:
1. **`surface_map`**: Categorizes every discovered asset into:
   - `in_scope`: Matches your approved subscriptions, domains, and environments.
   - `excluded`: Explicitly prohibited assets, out-of-scope partner tenants, or non-production testbeds.
   - `unresolved`: Discovered assets with missing or ambiguous ownership that require manual verification.
2. **`test_plan`**: For in-scope assets only, generates a passive review plan specifying allowed observation methods, expected telemetry, emergency stop conditions, and cleanup protocols.

---

## Input Limits & Safety Guardrails

To protect your system from malformed inputs or runaway memory consumption, the planner enforces strict local constraints:
- Scope manifest maximum size: 128 KiB.
- Individual export maximum size: 4 MiB (total input capped at 12 MiB).
- Maximum total records: 1,000 across all sources.
- Maximum JSON nesting depth: 24 levels.
- File path containment: All export sources must reside within the manifest directory; symlinks and directory climbing (`../`) are strictly rejected.

---

## Extended Passive Discovery & Scope Quarantine Reconciliation

The package extends its passive planning capabilities with multi-source telemetry normalization and scope quarantine reconciliation (`cops discovery`):

1. **Multi-Source Normalization**: Ingests raw DNS, TLS/CT certificates, IP allocations, endpoints, and cloud exports into canonical `DiscoveredAsset` records with cryptographic SHA-256 evidence provenance.
2. **Provenance Deduplication**: Consolidates multi-source observations of identical entities while retaining all source proofs.
3. **Scope Quarantine Reconciliation**:
   - `verified_in_scope`: Matches approved targets, subnets, and domains with verified ownership.
   - `quarantined`: Flags assets with conflicting ownership, stale/dangling DNS records, or missing provenance so discovery cannot expand the engagement.
   - `excluded`: Explicitly prohibited domains, IP ranges, or partner tenants.

```bash
# Normalize raw telemetry
python3 -m cops discovery normalize fixtures/recon/dns.json --type dns --output inventory.json

# Reconcile against approved engagement scope
python3 -m cops discovery reconcile inventory.json --scope scope.json --output reconciled.json

# Merge and deduplicate multiple inventories
python3 -m cops discovery merge inv1.json inv2.json --output merged.json

# Inspect inventory summary
python3 -m cops discovery inspect reconciled.json
```

---

## Bounded Active Discovery & Service Identification

The package extends reconnaissance foundations with bounded, rate-limited active port and TLS service assessment (`cops discovery active` or `cops active-discovery`):

1. **Approved Assessment Configuration**:
   - Explicit scan vantage (`external`, `internal`, `egress_point`, `cloud_tenant`).
   - Rate limiting (`--rate-limit <pps>`) with probe pacing to prevent perimeter disruption.
   - Resource and execution budgets (`--timeout <sec>`, `--max-total-seconds <sec>`).
2. **Resumable Execution**:
   - Saves checkpoint after every probe or upon budget exhaustion.
   - Resuming skips completed probes without repeating network side effects or exceeding approved targets.
3. **Grounded Service Identification with Visible Uncertainty**:
   - Distinguishes verbatim observed configurations (raw banners, HTTP status/headers, TLS ciphers/certs) from inferred fingerprints (product, version, OS).
   - Calibrates confidence (`high`, `medium`, `low`, `uncertain`, `provisional`) and flags reverse proxies, CDNs, and certificate mismatches.
4. **Scope Quarantine & DNS Rebind Defense**:
   - Enforces scope CIDR and domain checks before each probe; halts probes and flags `dns_rebind_detected` if target resolution shifts.
5. **Remediated Exposure Verification**:
   - Compares baseline vs. re-test scans to compute remediated, new, and persistent exposures with exact remediation rate percentage.

```bash
# Plan active assessment
python3 -m cops discovery active plan --targets "198.51.100.10,app.corp.internal" --ports 80,443,22 --output session.json

# Execute bounded scan
python3 -m cops discovery active scan session.json --scope scope.json --checkpoint checkpoint.json

# Resume interrupted scan
python3 -m cops discovery active resume checkpoint.json --output completed.json

# Compare scans for remediation delta
python3 -m cops discovery active diff baseline.json current.json --output delta.json

# Import Masscan or Nmap output
python3 -m cops discovery active import masscan.json --tool masscan --output masscan_session.json
```

---

## Infrastructure & Identity Services Assessment

The package evaluates protocol-specific exposure across core network infrastructure and identity-facing services (`cops discovery infrastructure` or `cops infrastructure-services`):

1. **Protocol-Specific Bounded Collectors**:
   - **DNS**: Evaluates open recursion and zone exposure using benign query probing.
   - **SNMP**: Detects default community strings (`public`, `private`) and system descriptor leakage.
   - **NTP**: Evaluates monlist/Mode 6 query amplification exposure.
   - **RPC Endpoint Mapper**: Enumerates registered RPC interfaces (e.g. MS-RPC port 135) to identify unauthenticated attack surface.
   - **LDAP**: Tests anonymous or unauthenticated `rootDSE` queries to disclose domain naming contexts, forest topology, and supported SASL mechanisms without querying directory objects.
   - **Kerberos**: Evaluates Kerberos realm visibility and AS-REP roasting vulnerability by checking pre-authentication requirements for designated accounts.
2. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If an infrastructure service is timed out, connection-refused, filtered, or unreachable from the current assessment vantage, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes.
   - A service is **NEVER** marked as `protected` or `hardened` merely because it failed to respond. Only positive verification of explicit authentication enforcement or authorization rejection warrants a `protected` status.
3. **Canary Records and Controlled Identities**:
   - Uses canary domain lookups (`canary.corp.internal`) and synthetic controlled identity accounts (`canary-user@CORP.INTERNAL`) to validate boundary conditions without interacting with real user credentials or directory records.
4. **Identity Attack-Path Candidates & AD Inventory Handoff**:
   - Extracts structured `IdentityAttackPathCandidate` records (with SHA-256 evidence hashes and remediation guidance) for lateral movement and Active Directory inventory handoffs (`cops-pentest-specialist`, `cops-redteam-operator`).

```bash
# Assess infrastructure and identity services
python3 -m cops discovery infrastructure assess --targets "198.51.100.10,dc01.corp.internal" --vantage internal --output infra_assessment.json

# Extract identity attack-path candidates for AD inventory
python3 -m cops discovery infrastructure candidates infra_assessment.json --output identity_candidates.json

# Inspect assessment summary and truth-in-advertising metrics
python3 -m cops discovery infrastructure inspect infra_assessment.json
```

---

## Remote Administration, File Sharing, and Printing Services Assessment

The package assesses protocol-specific exposure across remote administration (SSH, Telnet, RDP, VNC, WinRM, X11), file sharing (SMB, NFS, FTP/TFTP, rsync, AFP), and network printing services (LPD, IPP, Raw/JetDirect) (`cops remote-services` or `cops discovery remote`):

1. **Protocol-Specific Coverage**:
   - **Remote Admin**: Evaluates SSH authentication modes and versions, Telnet unencrypted credential leakage, RDP Network Level Authentication (NLA) enforcement, VNC RFB authentication barriers, WinRM HTTP unencrypted endpoints, and open X11 display servers.
   - **File Sharing**: Audits SMBv1 enablement, mandatory SMB message signing, null/guest share enumeration, NFS exports with `no_root_squash` privilege escalation, anonymous FTP access, unauthenticated rsync daemon modules, and Apple Filing Protocol (AFP) guest access.
   - **Printing**: Checks LPD, IPP, and Raw/JetDirect queues for unauthenticated job submissions.
2. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If a service is filtered, connection-refused, or timed out, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes. It is **never** reported as secure or hardened.
3. **Canary Validation and Verifiable Cleanup Receipts**:
   - Non-destructive probes validate access boundaries using canary files or synthetic print jobs.
   - Assessments emit cryptographically hashed `CleanupReceipt` records confirming test artifacts were removed and the system state was restored (`verified_removed`).
4. **Host Privilege Candidate Routing**:
   - Discovered misconfigurations (e.g. SMBv1, missing SMB signing, RDP without NLA, NFS `no_root_squash`, open VNC/X11) are structured as `HostPrivilegeCandidate` records with cryptographic evidence hashes and lateral movement impact ratings for handoff to offensive specialists (`cops-pentest-specialist`, `cops-redteam-operator`).

```bash
# Assess remote, file, and printing services
python3 -m cops remote-services assess --targets "198.51.100.20,fileserver01.corp.internal" --vantage internal --canary-id "canary_share/audit.tmp" --output remote_assessment.json

# Extract host privilege candidates for lateral movement specialists
python3 -m cops remote-services candidates remote_assessment.json --output host_candidates.json

# Export verified cleanup receipts
python3 -m cops remote-services cleanup remote_assessment.json --output cleanup_receipts.json

# Inspect remote assessment summary and truth-in-advertising metrics
python3 -m cops remote-services inspect remote_assessment.json
```

---

## Database, Cache, and Search Services Assessment

The package evaluates exposure, access control, and configuration security across relational databases, NoSQL stores, in-memory caches, and search/analytics engines (`cops data-services` or `cops discovery data`):

1. **Protocol-Specific Coverage**:
   - **Relational Databases**: Probes MySQL (3306), PostgreSQL (5432), Microsoft SQL Server (1433), and Oracle Database (1521) for blank/unauthenticated root accounts, `trust` authentication, blank `sa` accounts, default SIDs, and client certificate requirements.
   - **NoSQL & Document Stores**: Evaluates MongoDB (27017) unauthenticated clusters (`--auth` disabled), CouchDB (5984) Admin Party mode, and Apache Cassandra (9042) default `cassandra`/`cassandra` superuser credentials.
   - **In-Memory & Caches**: Audits Redis (6379) missing `requirepass` and dangerous `CONFIG` command availability, and Memcached (11211) unauthenticated slab dump access without SASL.
   - **Search & Analytics Engines**: Assesses Elasticsearch (9200) open cluster REST endpoints, InfluxDB (8086) unauthenticated HTTP API, Kibana (5601) open analytics dashboards, and Splunk (8089) management port default credentials.
2. **Bounded Query Budgets & Zero Bulk Extraction**:
   - Technical probes strictly enforce a bounded query budget (default 5 rows/documents) to verify schema, table/collection presence, and access controls.
   - Bulk table dumps, full collection scans, and unconstrained production record retrieval are strictly prohibited and architecturally blocked.
3. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If a database, cache, or search service is timed out, connection-refused, filtered, or unreachable from the probe vantage, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes. It is **never** reported as secure or hardened.
4. **Canary Validation and Verifiable Cleanup Receipts**:
   - Non-destructive probes validate access boundaries using canary table/key identifiers (`canary_audit_table`, `canary_cache_key`).
   - Assessments emit cryptographically hashed `CleanupReceipt` records confirming test artifacts were removed and the system state was restored (`verified_removed`).
5. **Data Privilege Candidate Routing**:
   - Discovered misconfigurations (e.g. `redis_no_auth`, `postgres_trust_auth`, `elasticsearch_open_cluster`, `mssql_blank_sa`, `mongodb_no_auth`, `couchdb_admin_party`, `cassandra_default_superuser`) are structured as `DataPrivilegeCandidate` records with cryptographic evidence hashes and privilege impact ratings (`database_takeover`, `remote_code_execution`, `data_exfiltration`, `cache_poisoning`, `analytics_tampering`) for handoff to offensive specialists (`cops-pentest-specialist`, `cops-redteam-operator`).

```bash
# Assess databases, caches, and search services
python3 -m cops data-services assess --targets "198.51.100.30,db01.corp.internal" --vantage internal --canary-id "canary_audit_table" --output data_assessment.json

# Extract data privilege candidates for lateral movement specialists
python3 -m cops data-services candidates data_assessment.json --output data_candidates.json

# Export verified cleanup receipts
python3 -m cops data-services cleanup data_assessment.json --output cleanup_receipts.json

# Inspect assessment summary, privilege candidates, and truth-in-advertising metrics
python3 -m cops data-services inspect data_assessment.json
```

---

## Mail, Messaging, and Message Broker Services Assessment

The package records exposure and configuration evidence for mail transfer/retrieval agents, real-time chat, and message queuing/streaming brokers (`cops messaging-services` or `cops discovery messaging`). The socket collector checks TCP reachability only. The synthetic collector evaluates supplied fixture data; neither sends protocol messages or establishes live relay, authentication, delivery, or cleanup behavior.

1. **Protocol-Specific Coverage**:
   - **Mail Transfer & Retrieval**: Covers SMTP (25, 587, 465), POP3 (110, 995), and IMAP (143, 993).
   - **Real-Time Chat**: Covers IRC (6667, 6697).
   - **Message Brokers & Streaming**: Covers RabbitMQ / AMQP (5672, 15672), NATS (4222, 8222), IBM MQ (1414), Apache Kafka (9092), and MQTT (1883).
2. **Bounded Message Budgets & Zero Mass Outbound Relaying**:
   - Synthetic canary evidence requires an allowlisted destination, an allowlisted recipient for mail, an active retention window of at most 86400 seconds, and a message budget of 1 through 5 (default 5).
   - The budget bounds accepted fixture evidence. Neither collector sends outbound messages.
3. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If a mail or message broker service is timed out, connection-refused, filtered, or unreachable from the probe vantage, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes. It is **never** reported as secure or hardened.
4. **Canary Validation and Verifiable Cleanup Receipts**:
   - A synthetic canary is validated only when fixture evidence matches its identifier, route, recipient, delivery time, and message budget.
   - `CleanupReceipt` records are emitted only for matching fixture evidence that confirms cleanup within retention. Their hashes bind the retention start and duration to the delivery and cleanup timestamps; report import checks those bounds and rejects older synthetic receipts that lack them. Hashes detect changes to report data; they do not authenticate the fixture or confirm a live purge.
5. **Messaging Privilege Candidate Routing**:
   - Discovered misconfigurations (e.g. `smtp_open_relay`, `smtp_user_enumeration`, `pop3_plaintext_auth`, `imap_anonymous_login`, `irc_unauthenticated_operator`, `rabbitmq_guest_default_creds`, `rabbitmq_open_management`, `nats_unauthenticated_cluster`, `ibmmq_blank_channel`, `kafka_unauthenticated_broker`, `mqtt_anonymous_read_write`) are structured as `MessagingPrivilegeCandidate` records with cryptographic evidence hashes and privilege impact ratings (`unauthorized_relay`, `broker_takeover`, `credential_harvesting`, `data_exfiltration`, `message_tampering`, `remote_code_execution`) for handoff to offensive specialists (`cops-pentest-specialist`, `cops-redteam-operator`).

```bash
# Assess mail, messaging, and message broker services
python3 -m cops messaging-services assess --targets "198.51.100.40,mail01.corp.internal" --vantage internal --output messaging_assessment.json

# Extract messaging privilege candidates for unauthorized relay or broker takeover
python3 -m cops messaging-services candidates messaging_assessment.json --output messaging_candidates.json

# Export synthetic fixture cleanup receipts, if present
python3 -m cops messaging-services cleanup messaging_assessment.json --output cleanup_receipts.json

# Inspect assessment summary, privilege candidates, and truth-in-advertising metrics
python3 -m cops messaging-services inspect messaging_assessment.json
```

---

## Developer and Runtime Interfaces Assessment

The package evaluates exposure, access control, and code execution risk across developer tooling, language debugging endpoints, distributed build systems, and application gateway interfaces (`cops developer-services` or `cops discovery developer`):

1. **Protocol-Specific Coverage**:
   - **Container & Orchestration Runtimes**: Probes Docker Engine API (2375, 2376) for unauthenticated TCP socket access permitting container breakouts and root host takeover; evaluates Docker Registry v2 (5000) for anonymous image catalog enumeration and private repository leakage.
   - **Language & Debugging Runtimes**: Probes Java RMI Registry (1099) for unauthenticated object bindings and remote codebase deserialization; detects Java Debug Wire Protocol (JDWP, 8000/5005) raw handshake responses allowing arbitrary bytecode execution; evaluates Erlang Port Mapper Daemon (EPMD, 4369) node discovery and cookie enforcement; and detects wireless Android Debug Bridge (ADB, 5555) unauthenticated root shells.
   - **Distributed Build & SCM**: Assesses distcc (3632) compilation daemons missing `--allow` CIDR IP restrictions enabling arbitrary shell execution; and probes Subversion (svnserve, 3690) anonymous repository checkout leaking source code.
   - **Application Server & Gateway Interfaces**: Probes Apache JServ Protocol (AJP13, 8009) for missing `secretRequired` configuration vulnerable to Ghostcat (CVE-2020-1938); and assesses FastCGI / PHP-FPM (9000) external socket exposure allowing arbitrary PHP code execution.
2. **Explicit Execution Effect Classification & Plan Binding**:
   - Explicitly classifies every assessment effect via `ExecutionEffect`: `read_only`, `non_destructive`, `state_change`, `code_execution`.
   - Operations that execute code (`can_execute_code`) or modify state (`can_change_state`) MUST be explicitly authorized via `--allow-code-execution` or `--allow-state-change` and bound to the active action plan.
3. **Application vs Infrastructure Specialist Routing**:
   - Application-layer findings route to web and application specialists (`cops-web-specialist`, `cops-appsec-engineer`).
   - Container cluster management and orchestrator interfaces route to cloud infrastructure specialists (`cops-cloud-specialist`).
   - Host breakout and remote code execution findings route to penetration testing specialists (`cops-pentest-specialist`, `cops-redteam-operator`).
4. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If a developer interface is timed out, connection-refused, filtered, or unreachable from the probe vantage, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes. It is **never** reported as secure or hardened.
5. **Canary Validation and Verifiable Cleanup Receipts**:
   - Non-destructive probes validate access boundaries using canary identifiers (`canary_docker_probe`, `canary_debug_probe`).
   - Assessments emit cryptographically hashed `CleanupReceipt` records confirming test containers or temporary artifacts were purged (`verified_removed`).
6. **Developer Privilege Candidate Routing**:
   - Discovered misconfigurations (e.g. `docker_socket_rce`, `docker_registry_leak`, `rmi_code_execution`, `jdwp_code_execution`, `erlang_epmd_rce`, `adb_shell_rce`, `distcc_rce`, `svn_anonymous_checkout`, `ajp_ghostcat_rce`, `fastcgi_rce`) are structured as `DeveloperPrivilegeCandidate` records with cryptographic evidence hashes, auth prerequisites, and privilege impact ratings for handoff to offensive specialists (`cops-pentest-specialist`, `cops-redteam-operator`).

```bash
# Assess developer and runtime interface services
python3 -m cops developer-services assess --targets "198.51.100.50,dev01.corp.internal" --vantage internal --canary-id "canary_docker_probe" --output developer_assessment.json

# Assess with authorized code execution verification
python3 -m cops developer-services assess --targets "198.51.100.50" --services "docker,jdwp,distcc" --allow-code-execution --output developer_assessment.json

# Extract developer privilege candidates for code execution or breakout workflows
python3 -m cops developer-services candidates developer_assessment.json --output developer_candidates.json

# Export verified cleanup receipts
python3 -m cops developer-services cleanup developer_assessment.json --output cleanup_receipts.json

# Inspect assessment summary, privilege candidates, and truth-in-advertising metrics
python3 -m cops developer-services inspect developer_assessment.json
```

---

## Legacy Enterprise, Management, and Proxy Services Assessment

The package evaluates exposure, access control, and proxy egress risk across legacy enterprise storage protocols, hardware out-of-band management interfaces, network device appliance management, legacy VPN tunneling protocols, and forward proxy egress services (`cops legacy-services` or `cops discovery legacy`):

1. **Protocol-Specific Coverage**:
   - **Enterprise Storage & Data Management**: Probes NDMP (10000) for unauthenticated backup stream traversal, directory browsing, and tape/disk storage takeover; evaluates iSCSI (3260) for unauthenticated SendTargets discovery and LUN volume attachment without mutual CHAP.
   - **Out-of-Band & Hardware Management**: Assesses IPMI 2.0 / RMCP+ (623/udp) Baseboard Management Controller (BMC) interfaces for Cipher Suite 0 authentication bypass and unauthenticated RAKP HMAC-SHA1 password hash dumping for offline dictionary cracking.
   - **Network Device & Appliance Management**: Detects active Cisco Smart Install client daemons (`vstack`, 4786) allowing unauthenticated configuration download/replacement and arbitrary code execution; and evaluates TACACS+ AAA (49) daemons exposed with weak/default shared secret keys and missing TLS encapsulation (RFC 8907).
   - **VPN & Tunneling Services**: Evaluates IPsec / IKEv1 (500/udp) Aggressive Mode responses exposing pre-shared key (PSK) negotiation hashes to offline cracking; and assesses legacy PPTP VPN endpoints (1723) utilizing vulnerable MS-CHAPv2 challenge-response authentication.
   - **Proxy & Egress Services**: Assesses SOCKS4/SOCKS5 proxies (1080) for open network relaying without RFC 1929 authentication; and evaluates Squid HTTP proxies (3128) for unrestricted client ACLs allowing internal/cloud metadata SSRF pivoting.
2. **Proxy Egress Restriction Testing**:
   - For all proxy and egress services (SOCKS, Squid), explicitly tests and records destination egress restriction policy (`proxy_egress_tested`, `proxy_egress_restricted`) to evaluate whether outbound access to internal loopback, cloud metadata (`169.254.169.254`), or arbitrary external subnets is denied.
3. **Explicit Execution Effect Classification & Plan Binding**:
   - Explicitly classifies every assessment effect via `ExecutionEffect`: `read_only`, `non_destructive`, `state_change`, `code_execution`.
   - Operations that execute code (`can_execute_code`) or modify state (`can_change_state`) MUST be explicitly authorized via `--allow-code-execution` or `--allow-state-change` and bound to the active action plan.
4. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If a legacy interface is timed out, connection-refused, filtered, or unreachable from the probe vantage, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes. It is **never** reported as secure or hardened.
5. **Canary Validation and Verifiable Cleanup Receipts**:
   - Non-destructive probes validate access boundaries using canary identifiers (`canary_legacy_artifact`, `canary_proxy_probe`).
   - Assessments emit cryptographically hashed `CleanupReceipt` records confirming test artifacts were removed and the system state was restored (`action_taken="verified_removed"`).
6. **Legacy Privilege Candidate Routing**:
   - Discovered misconfigurations (e.g. `ndmp_unauthenticated_access`, `iscsi_unauthenticated_target`, `ipmi_cipher_zero_bypass`, `ipmi_rakp_hash_dump`, `cisco_smart_install_rce`, `tacacs_unauthenticated_daemon`, `ike_aggressive_mode_psk`, `pptp_mschapv2_exposure`, `socks_open_proxy`, `squid_open_proxy`) are structured as `LegacyPrivilegeCandidate` records with cryptographic evidence hashes, auth prerequisites, and privilege impact ratings for handoff to offensive specialists (`cops-pentest-specialist`, `cops-redteam-operator`).

```bash
# Assess legacy enterprise, management, and proxy services
python3 -m cops legacy-services assess --targets "198.51.100.60,storage01.corp.internal" --vantage internal --canary-id "canary_legacy_probe" --output legacy_assessment.json

# Assess with authorized code execution verification
python3 -m cops legacy-services assess --targets "198.51.100.60" --services "ipmi,cisco_smart_install" --allow-code-execution --output legacy_assessment.json

# Extract legacy privilege candidates for takeover or proxy egress pivoting
python3 -m cops legacy-services candidates legacy_assessment.json --output legacy_candidates.json

# Export verified cleanup receipts
python3 -m cops legacy-services cleanup legacy_assessment.json --output cleanup_receipts.json

# Inspect assessment summary, privilege candidates, and truth-in-advertising metrics
python3 -m cops legacy-services inspect legacy_assessment.json
```

---

## Evidence & Ethical Boundaries

The Attack Surface Planner is a **planning and compliance tool**, not an active exploitation framework:
- It **never** authenticates to cloud tenants, crawls websites, queries live DNS/CT logs, or scans ports.
- It **never** runs active penetration tests, harvests credentials, or establishes persistence.
- Any finding, public endpoint, or permission name in an export is a hypothesis trigger for passive review, not proof of exploitability.

Always ensure you have written, executive authorization before undertaking any security assessment.
