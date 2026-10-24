---
layout: documentation
title: "When to Use Each COPS Plugin"
description: "A comprehensive guide to selecting, evaluating, and running each of the 25 security plugins across defensive and offensive cybersecurity disciplines."
---

# When to Use Each COPS Plugin

COPS packages **25 specialized cybersecurity plugins** across seven core disciplines. Each plugin is self-contained under `plugins/<category>/<plugin-id>/` and includes deterministic Python tools, reusable AI skills, and a practitioner playbook.

Use the [runnable workflow index](plugin-playbacks.md) for checked examples and
the [malicious-access walkthrough](investigate-malicious-access.md) for a complete
investigation from intake to disposition.

Use this guide to determine which plugin best matches your operational requirements.
Follow [plugin verification and maturity](plugin-verification.md) to run a complete
qualification workflow and record evidence before proposing a status change.

---

## Start from your goal

Describe the outcome in everyday words; you do not need to choose a workbench
first. Every workbench can begin with a discussion or draft that records unknowns.
Local evidence processing still requires permission and privacy controls. Contract
validation, laboratory runs, and live execution retain their own prerequisites;
a draft never grants permission to execute. See [Getting started](getting-started.md)
for the stage-by-stage requirements and a local example.

## Quick Decision Matrix

| What are you trying to accomplish? | Reach for this plugin | Category | Maturity | Operational Mode | Try it out |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **Audit code for logging gaps and credential leaks** | `security-logging-advisor` | Logging & Telemetry | <span class="badge badge-stable">Stable</span> | `import` | `python3 -m cops demo security-logging-advisor` |
| **Verify telemetry pipeline health (Cribl → SIEM)** | `telemetry-proof-pack` | Logging & Telemetry | <span class="badge badge-beta">Beta</span> | `laboratory` | `python3 -m cops check telemetry-proof-pack` |
| **Investigate complex alerts with rival hypotheses** | `soc-investigation-workbench` | Detection & Hunting | <span class="badge badge-beta">Beta</span> | `laboratory` | `python3 -m cops demo soc-investigation-workbench` |
| **Author, adapt, or stress-test Sentinel/Defender KQL** | `sentinel-hunt-workbench` | Detection & Hunting | <span class="badge badge-beta">Beta</span> | `laboratory` | `python3 -m cops demo sentinel-hunt-workbench` |
| **Trace multi-hop cloud lateral movement paths** | `attack-path-workbench` | Detection & Hunting | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo attack-path-workbench` |
| **Validate detection query syntax & regressions** | `detection-quality-workbench` | Detection & Hunting | <span class="badge badge-beta">Beta</span> | `laboratory` | `python3 -m cops check detection-quality-workbench` |
| **Enrich observables with threat intelligence feeds** | `threat-intelligence-enrichment` | Detection & Hunting | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops check threat-intelligence-enrichment` |
| **Audit Entra ID roles, apps, and credential hygiene** | `entra-identity-workbench` | Identity & Access | <span class="badge badge-beta">Beta</span> | `import` | `python3 -m cops check entra-identity-workbench` |
| **Map scoped Active Directory relationships and candidate paths** | `ad-assessment-workbench` | Identity & Access | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo ad-assessment-workbench` |
| **Prepare redacted secret revocation and rotation work** | `secrets-remediation-workbench` | Identity & Access | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo secrets-remediation-workbench` |
| **Prioritize vulnerability triage with SBOM reachability** | `exposure-triage-workbench` | Vulnerability Management | <span class="badge badge-beta">Beta</span> | `import` | `python3 -m cops check exposure-triage-workbench` |
| **Preflight an exact-version vulnerability reproduction plan** | `exploit-validation-workbench` | Vulnerability Management | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo exploit-validation-workbench` |
| **Review code diffs and pull requests for security flaws** | `patch-security-review` | Vulnerability Management | <span class="badge badge-beta">Beta</span> | `import` | `python3 -m cops check patch-security-review` |
| **Assess imported cloud and infrastructure configuration** | `cloud-posture-workbench` | Vulnerability Management | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo cloud-posture-workbench` |
| **Review software supply-chain and CI/CD evidence** | `supply-chain-cicd-workbench` | Vulnerability Management | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo supply-chain-cicd-workbench` |
| **Compare network evidence with segmentation intent** | `network-segmentation-workbench` | Vulnerability Management | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo network-segmentation-workbench` |
| **Review TLS, certificate, JWT, and JWKS evidence** | `tls-crypto-workbench` | Vulnerability Management | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo tls-crypto-workbench` |
| **Plan an authorized, passive attack surface review** | `attack-surface-planner` | Offensive Security | <span class="badge badge-experimental">Experimental</span> | `planned` | `python3 -m cops demo attack-surface-planner` |
| **Reconcile an approved Kubernetes context and namespace scope** | `kubernetes-assessment-workbench` | Offensive Security | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo kubernetes-assessment-workbench` |
| **Intake engagement scope and compile action plans** | `offensive-engagement-workbench` | Offensive Security | <span class="badge badge-experimental">Experimental</span> | `planned` | `python3 -m cops demo offensive-engagement-workbench` |
| **Review Linux and Windows privilege-boundary exports** | `host-assessment-workbench` | Offensive Security | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo host-assessment-workbench` |
| **Rehearse synthetic agent/MCP and provider response handling** | `foundry-agent-harness` | Offensive Security | <span class="badge badge-beta">Beta</span> | `laboratory` | `python3 -m cops check foundry-agent-harness` |
| **Inventory and assess imported web API records** | `web-api-assessment-workbench` | Offensive Security | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo web-api-assessment-workbench` |
| **Rehearse containment with cryptographic receipts** | `incident-response-sandbox` | Incident Response | <span class="badge badge-experimental">Experimental</span> | `laboratory` | `python3 -m cops check incident-response-sandbox` |
| **Map dated evidence to compliance controls** | `compliance-posture-workbench` | Governance & Compliance | <span class="badge badge-experimental">Experimental</span> | `import` | `python3 -m cops demo compliance-posture-workbench` |

---

## Detailed Plugin Guidance

### 1. Logging & Telemetry

#### Security Logging Advisor
- **Maturity**: <span class="badge badge-stable">Stable</span> | **Operational Mode**: `import`
- **When to use**: During code reviews, CI security checks, or application onboarding when you need to detect missing security audit logging, unmasked PII or credentials in log streams, and identify whether vulnerable dependencies (CVEs) are reachable from application entry points.
- **Key Capabilities**: Offline AST-based code analysis, regex credential detectors, CVE reachability correlation.
- **Boundaries**: Static code and configuration inspection only; does not ingest live SIEM streams or connect to runtime clusters.
- **Playbook**: `plugins/logging-telemetry/security-logging-advisor/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/logging-telemetry/security-logging-advisor/docs/VERIFICATION.md)

#### Telemetry Proof Pack
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When validating complex log pipelines between Cribl Stream, Splunk, and Microsoft Sentinel to detect ingestion bottlenecks, broken routing rules, or cross-tenant event collisions before pushing pipeline changes to production.
- **Key Capabilities**: Pipeline topology validation, synthetic health proofs, edge-case failure mode verification.
- **Boundaries**: Operates on simulated pipeline topologies; does not connect to live streaming buffers.
- **Playbook**: `plugins/logging-telemetry/telemetry-proof-pack/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/logging-telemetry/telemetry-proof-pack/docs/VERIFICATION.md)

---

### 2. Detection & Hunting

#### SOC Investigation Workbench
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When investigating an alert that has multiple plausible explanations (e.g. administrator maintenance vs. attacker living-off-the-land) and you need structured guidance to avoid confirmation bias.
- **Key Capabilities**: Analysis of Competing Hypotheses (ACH), inquiry question ranking, evidence dependency graphs.
- **Boundaries**: Decision-support framework; does not execute autonomous containment actions.
- **Playbook**: `plugins/detection-hunting/soc-investigation-workbench/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/detection-hunting/soc-investigation-workbench/docs/VERIFICATION.md)

#### Sentinel Hunt Workbench
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When authoring, adapting, or testing Microsoft Sentinel and Defender XDR KQL queries against synthetic event streams before deployment to live workspaces.
- **Key Capabilities**: 12 defensive threat hunts, multi-surface syntax adaptation (Sentinel vs Defender vs Data Lake), offline mutation stress-testing.
- **Boundaries**: Synthetic event evaluation; does not authenticate to customer cloud tenants.
- **Playbook**: `plugins/detection-hunting/sentinel-hunt-workbench/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/detection-hunting/sentinel-hunt-workbench/docs/VERIFICATION.md)

#### Attack Path Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When analyzing cloud IAM trust topologies and lateral movement pathways from offline asset exports to identify critical remediation choke points.
- **Key Capabilities**: Multi-hop directed graph traversal, blast radius calculation, choke-point identification.
- **Boundaries**: Operates strictly on offline JSON exports; does not perform active network scanning.
- **Playbook**: `plugins/detection-hunting/attack-path-workbench/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/detection-hunting/attack-path-workbench/docs/VERIFICATION.md)

#### Detection Quality Workbench
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When running detection-as-code CI/CD pipelines to catch syntax errors, deprecated operators, and performance regressions in Sentinel KQL and Splunk SPL queries.
- **Key Capabilities**: Offline syntax validation, query regression testing, normalization checks.
- **Boundaries**: Syntax and regression parser; does not query live search clusters.
- **Playbook**: `plugins/detection-hunting/detection-quality-workbench/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/detection-hunting/detection-quality-workbench/docs/VERIFICATION.md)

#### Threat Intelligence Enrichment
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When enriching indicators of compromise (IPs, hashes, domains) with threat intelligence metadata while preserving provenance and avoiding external data leaks.
- **Key Capabilities**: Offline feed correlation (MISP/TAXII cached formats), confidence weighting, tamper-evident provenance stamps.
- **Boundaries**: Operates against cached local feeds; external API lookups require explicit operator opt-in.
- **Playbook**: `plugins/detection-hunting/threat-intelligence-enrichment/skills/threat-intelligence-enrichment/SKILL.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/detection-hunting/threat-intelligence-enrichment/docs/VERIFICATION.md)

---

### 3. Identity & Access

#### Entra Identity Workbench
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `import`
- **When to use**: When conducting an identity governance review of Microsoft Entra ID (Azure AD) tenants to uncover over-privileged role assignments, stale service principals, high-risk OAuth consent grants, or expiring credentials.
- **Key Capabilities**: Offline tenant JSON parsing, privilege escalation graph analysis, credential hygiene scoring.
- **Boundaries**: Ingests offline JSON exports; makes zero Microsoft Graph mutations.
- **Playbook**: `plugins/identity-access/entra-identity-workbench/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/identity-access/entra-identity-workbench/docs/VERIFICATION.md)

#### AD Assessment Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When reviewing an approved, scoped Active Directory relationship export and the declared forest and host collection coverage.
- **Key Capabilities**: Bounded offline graph validation, provenance-linked candidate paths, and explicit complete, partial, or unknown coverage.
- **Boundaries**: Candidate paths require analyst validation. The package neither queries a domain controller nor verifies live privileges or missing relationships outside the collected graph.
- **Playbook**: `plugins/identity-access/ad-assessment-workbench/skills/ad-inventory-and-paths/SKILL.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/identity-access/ad-assessment-workbench/docs/VERIFICATION.md)

#### Secrets Remediation Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When imported evidence indicates a credential exposure and an analyst needs a redacted incident record plus an ordered revocation, rotation, and validation plan.
- **Key Capabilities**: Evidence redaction, secret-type classification, dependency-aware remediation sequencing, and fixture-based recovery checks.
- **Boundaries**: Never prints credential values. Imported records and local fixtures do not prove provider-side revocation, successful rotation, or production recovery.
- **Playbook**: `plugins/identity-access/secrets-remediation-workbench/`
- **Related Specialist**: `cops-secrets-remediation-specialist`

---

### 4. Vulnerability Management

#### Exposure Triage Workbench
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `import`
- **When to use**: When prioritizing thousands of open CVEs across container images or repositories by filtering for components that are actually reachable from code entry points or exposed to network boundaries.
- **Key Capabilities**: SBOM ingestion (CycloneDX / SPDX), advisory CVE matching, static call-graph reachability.
- **Boundaries**: Offline reachability analysis indicates exposure potential, not confirmed live exploitability.
- **Playbook**: `plugins/vulnerability-management/exposure-triage-workbench/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/vulnerability-management/exposure-triage-workbench/docs/VERIFICATION.md)

#### Exploit Validation Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: Before a separately authorized disposable-lab reproduction, check that a proposed CVE exercise declares exact affected and fixed versions, local source files, three control cases, and lab references.
- **Key Capabilities**: Offline JSON preflight, local SHA-256 verification, exact-version membership checks, and refusal of unrecognized fields or unsafe file paths.
- **Boundaries**: Advisory provenance, acquisition receipts, lab controls, observed effects, and cleanup remain unverified; the report never grants execution authority.
- **Playbook**: `plugins/vulnerability-management/exploit-validation-workbench/docs/PLAYBOOK.md`
- **Verification**: [Offline preflight playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/vulnerability-management/exploit-validation-workbench/docs/VERIFICATION.md)

#### Patch Security Review
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `import`
- **When to use**: During code reviews and pull request approvals to automatically detect whether a proposed change introduces security regressions, bypasses authorization, or weakens defensive controls.
- **Key Capabilities**: Static patch diff inspection, AST security pattern matching, regression risk classification.
- **Boundaries**: Static diff inspection; does not execute dynamic application security or runtime exploit payloads.
- **Playbook**: `plugins/vulnerability-management/patch-security-review/skills/patch-review/SKILL.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/vulnerability-management/patch-security-review/docs/VERIFICATION.md)

#### Cloud Posture Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When reviewing exported Terraform, cloud, Kubernetes, and IAM configuration evidence before deciding what needs live validation.
- **Key Capabilities**: Versioned evidence import, posture rule evaluation, coverage reporting, and provenance-preserving findings.
- **Boundaries**: Does not connect to a cloud tenant or establish deployed state, tenant identity, or effective production enforcement.
- **Playbook**: `plugins/vulnerability-management/cloud-posture-workbench/`
- **Related Specialist**: `cops-cloud-posture-specialist`

#### Supply Chain CI/CD Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When reviewing lockfiles, SBOMs, workflow definitions, and provenance records for dependency and pipeline risks.
- **Key Capabilities**: Offline artifact normalization, provenance checks, CI workflow inspection, and explicit missing-evidence reporting.
- **Boundaries**: Does not query a package registry, execute a build, or prove runtime exploit reachability or current deployment integrity.
- **Playbook**: `plugins/vulnerability-management/supply-chain-cicd-workbench/`
- **Related Specialist**: `cops-supply-chain-specialist`

#### Network Segmentation Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When comparing declared network boundaries with imported policies, flow logs, DNS records, packet summaries, and reachability matrices.
- **Key Capabilities**: Cross-source normalization, intended-versus-observed path analysis, provenance tracking, and fixture-based controls.
- **Boundaries**: Synthetic fixture playback does not prove deployed isolation or establish that a required isolated laboratory is provisioned and ready.
- **Playbook**: `plugins/vulnerability-management/network-segmentation-workbench/`
- **Related Specialist**: `cops-network-segmentation-specialist`

#### TLS and Crypto Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When evaluating imported certificate chains, TLS records, JWTs, JWKS documents, or OpenSSL output with known collection context.
- **Key Capabilities**: Certificate and algorithm inventory, policy comparison, signature-material provenance, and explicit coverage limits.
- **Boundaries**: Does not probe live endpoints or prove that production clients and servers negotiate or enforce the assessed configuration.
- **Playbook**: `plugins/vulnerability-management/tls-crypto-workbench/`
- **Related Specialist**: `cops-tls-crypto-specialist`

---

### 5. Offensive Security

#### Attack Surface Planner
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `planned`
- **When to use**: Prior to an authorized penetration test or red team engagement to reconcile rules of engagement, partition in-scope vs out-of-scope targets, normalize multi-source passive discovery telemetry, execute bounded active discovery and service identification, assess infrastructure and identity-facing services, evaluate remote administration, file sharing, and printing services, assess databases, caches, and search engines, evaluate mail, chat, and message brokers, assess developer and runtime interfaces, evaluate legacy enterprise, management, and proxy services, and generate bounded test plans.
- **Key Capabilities**: Scope boundary enforcement, rule-of-engagement parsing, passive review plan generation, multi-source telemetry normalization (DNS, certificate, IP, endpoint, cloud exports), evidence provenance preservation, scope quarantine reconciliation, bounded active service identification with resumable checkpoints and visible uncertainty, protocol-specific infrastructure assessment (DNS, SNMP, NTP, RPC, LDAP, Kerberos), remote administration, file sharing, and printing assessment (SSH, Telnet, RDP, VNC, WinRM, X11, SMB, NFS, FTP/TFTP, rsync, AFP, LPD, IPP, Raw/JetDirect), database, cache, and search assessment (MySQL, Postgres, MSSQL, Oracle, MongoDB, CouchDB, Cassandra, Redis, Memcached, Elasticsearch, InfluxDB, Kibana, Splunk) with bounded query budgets and zero bulk extraction, mail, messaging, and broker assessment (SMTP, POP3, IMAP, IRC, RabbitMQ, NATS, IBM MQ, Kafka, MQTT) with bounded message budgets and zero mass outbound relaying, developer and runtime interfaces assessment (Docker API, Docker Registry, Java RMI, JDWP, Erlang EPMD, ADB, distcc, SVN, AJP, FastCGI), nine legacy enterprise, management, VPN, and proxy offline fixture models (NDMP, iSCSI, IPMI 2.0, Cisco Smart Install, TACACS+, IKEv1, PPTP, SOCKS, Squid), with socket reachability reported as unconfirmed and no live proxy egress, canary, cleanup, or privilege validation.
- **Boundaries**: Strictly an authorized planning and scoping tool; operates offline or within bounded authorized parameters without executing uncoordinated exploits.
- **Service handoff**: The offline API can propose a specialist from an observed protocol response on an exact approved endpoint. A live reachability scan alone usually cannot establish the service or a vulnerability; the coordinator must separately authorize and account for validation.
- **Playbook**: `plugins/offensive-security/attack-surface-planner/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/offensive-security/attack-surface-planner/docs/VERIFICATION.md)

#### Kubernetes Assessment Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: Before planning a Kubernetes assessment, compare an explicitly approved context, namespaces, and surfaces with a sanitized local observation.
- **Key Capabilities**: Exact context tuple checks, local Namespace name and UID anchor comparison, namespace access and environment fact reporting.
- **Boundaries**: Reads a local JSON record only. Matching local assertions do not establish live cluster identity or readiness; missing or denied access stays visible, and the report never grants execution.
- **Playbook**: `plugins/offensive-security/kubernetes-assessment-workbench/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/offensive-security/kubernetes-assessment-workbench/docs/VERIFICATION.md)

#### Offensive Engagement Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `planned`
- **When to use**: When intaking authorized adversary engagements, enforcing target scope and boundary exclusions, compiling immutable action plans, orchestrating Triad specialist handoffs, and managing scenario laboratory environments.
- **Key Capabilities**: Scope intake validation, CIDR collision checks, immutable action plan generation, Triad specialist handoffs, capability verification, scenario laboratory environment verification, reproducible reset, and controlled case execution.
- **Boundaries**: Scoping, planning, and isolated laboratory execution only; refuses incomplete live requests and does not execute network payloads outside verified lab boundaries.
- **Playbook**: `plugins/offensive-security/offensive-engagement-workbench/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/offensive-security/offensive-engagement-workbench/docs/VERIFICATION.md)

#### Host Assessment Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When reviewing a bounded local export of Linux or Windows host configuration, prerequisite context, coverage, and canary outcomes.
- **Key Capabilities**: Strict versioned import, eight Linux or seven Windows privilege-boundary surfaces, prerequisite selection, explicit Windows bridge declarations, and distinct configuration versus reported-canary classifications.
- **Boundaries**: No host collection or execution; imported canary assertions are not independent proof of privilege crossing or cleanup.
- **Playbook**: `plugins/offensive-security/host-assessment-workbench/README.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/offensive-security/host-assessment-workbench/docs/VERIFICATION.md)

#### Foundry Agent Harness
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When rehearsing how an independent authorization gate handles synthetic agent tool proposals from untrusted content or how strict post-gate validation normalizes bundled provider-shaped response fixtures.
- **Key Capabilities**: Versioned local agent and MCP cases, observed gate denials and mock effects, paired permissive and strict controls, and offline OpenAI-, Azure-, AWS-, and GCP-shaped response cases with exact request binding and shared synthetic budget accounting.
- **Boundaries**: No provider client, credential lookup, network call, hosted model, deployed agent, or live MCP integration. Provider usage, billing, cancellation, and cleanup are not independently verified, and fixture subprocesses are not an operating-system network sandbox.
- **Playbook**: `plugins/offensive-security/foundry-agent-harness/docs/PLAYBOOK.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/offensive-security/foundry-agent-harness/docs/VERIFICATION.md)

#### Web API Assessment Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When inventorying and assessing imported HAR, OpenAPI, GraphQL, Postman, or API gateway records before any separately authorized live testing.
- **Key Capabilities**: Offline surface inventory, normalized request evidence, schema-aware observations, and deterministic replay fixtures.
- **Boundaries**: Imported traffic and fixture replay do not prove production authorization controls, deployed rate limiting, or live endpoint behavior.
- **Playbook**: `plugins/offensive-security/web-api-assessment-workbench/`
- **Related Specialist**: `cops-api-security-specialist`

---

### 6. Incident Response

#### Incident Response Sandbox
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `laboratory`
- **When to use**: When preparing an incident response containment plan and needing to rehearse actions, calculate blast radius (e.g. affected dependent services), and obtain interactive operator sign-off with cryptographic receipts.
- **Key Capabilities**: Blast radius calculation, approval-gated containment rehearsal, cryptographic execution receipts.
- **Boundaries**: Approval-gated rehearsal only; does not execute destructive actions on live infrastructure.
- **Playbook**: `plugins/incident-response/incident-response-sandbox/skills/incident-response-sandbox/SKILL.md`
- **Verification**: [End-to-end playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/incident-response/incident-response-sandbox/docs/VERIFICATION.md)

---

### 7. Governance & Compliance

#### Compliance Posture Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When mapping dated and versioned evidence to SOC 2, NIST, CIS, ISO, or PCI controls and separating gaps from stale or unknown evidence.
- **Key Capabilities**: Evidence-to-control mapping, freshness evaluation, coverage accounting, and supported, missing, stale, or unknown outcomes.
- **Boundaries**: Does not perform penetration testing, establish operating effectiveness, or convert incomplete evidence into a passing control result.
- **Playbook**: `plugins/governance-compliance/compliance-posture-workbench/`
- **Related Specialist**: `cops-compliance-auditor`

---

## Operational Readiness Modes & Truth-in-Advertising

To maintain absolute integrity and avoid capability over-claiming, COPS reconciles all capabilities into four explicit operational readiness modes:

- **`planned`**: Specification, routing persona, or scoping defined; no autonomous runtime execution.
- **`import`**: Offline static file, code AST, git diff, or export manifest ingestion only; zero live service mutation.
- **`laboratory`**: Controlled offline simulation, synthetic event replay, or sandbox rehearsal. A passing bundled fixture covers only that fixture path and does not establish that a separately required isolated laboratory is provisioned or ready.
- **`live-validated`**: Fully authorized, live-tested execution path against an authorized environment with cryptographic evidence receipt. Currently 0 capabilities claim live-validated, ensuring zero false claims.

To audit all 89 capabilities across 25 plugins, 27 specialist profiles, and 37 canonical scenarios:

```bash
python3 -m cops capabilities audit --check
python3 -m cops capabilities list
```
