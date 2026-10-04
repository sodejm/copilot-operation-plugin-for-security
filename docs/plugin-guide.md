---
layout: documentation
title: "When to Use Each COPS Plugin"
description: "A comprehensive guide to selecting, evaluating, and running each of the thirteen security plugins across defensive and offensive cybersecurity disciplines."
---

# When to Use Each COPS Plugin

COPS packages **thirteen specialized cybersecurity plugins** across six core disciplines. Each plugin is self-contained under `plugins/<category>/<plugin-id>/` and includes deterministic Python tools, reusable AI skills, and a practitioner playbook.

Use this guide to determine which plugin best matches your operational requirements.

---

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
| **Prioritize vulnerability triage with SBOM reachability** | `exposure-triage-workbench` | Vulnerability Management | <span class="badge badge-beta">Beta</span> | `import` | `python3 -m cops check exposure-triage-workbench` |
| **Review code diffs and pull requests for security flaws** | `patch-security-review` | Vulnerability Management | <span class="badge badge-beta">Beta</span> | `import` | `python3 -m cops check patch-security-review` |
| **Plan an authorized, passive attack surface review** | `attack-surface-planner` | Offensive Security | <span class="badge badge-experimental">Experimental</span> | `planned` | `python3 -m cops demo attack-surface-planner` |
| **Test AI agent prompt injection resistance** | `foundry-agent-harness` | Offensive Security | <span class="badge badge-beta">Beta</span> | `laboratory` | `python3 -m cops check foundry-agent-harness` |
| **Rehearse containment with cryptographic receipts** | `incident-response-sandbox` | Incident Response | <span class="badge badge-beta">Beta</span> | `laboratory` | `python3 -m cops check incident-response-sandbox` |

---

## Detailed Plugin Guidance

### 1. Logging & Telemetry

#### Security Logging Advisor
- **Maturity**: <span class="badge badge-stable">Stable</span> | **Operational Mode**: `import`
- **When to use**: During code reviews, CI security checks, or application onboarding when you need to detect missing security audit logging, unmasked PII or credentials in log streams, and identify whether vulnerable dependencies (CVEs) are reachable from application entry points.
- **Key Capabilities**: Offline AST-based code analysis, regex credential detectors, CVE reachability correlation.
- **Boundaries**: Static code and configuration inspection only; does not ingest live SIEM streams or connect to runtime clusters.
- **Playbook**: `plugins/logging-telemetry/security-logging-advisor/docs/PLAYBOOK.md`

#### Telemetry Proof Pack
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When validating complex log pipelines between Cribl Stream, Splunk, and Microsoft Sentinel to detect ingestion bottlenecks, broken routing rules, or cross-tenant event collisions before pushing pipeline changes to production.
- **Key Capabilities**: Pipeline topology validation, synthetic health proofs, edge-case failure mode verification.
- **Boundaries**: Operates on simulated pipeline topologies; does not connect to live streaming buffers.
- **Playbook**: `plugins/logging-telemetry/telemetry-proof-pack/docs/PLAYBOOK.md`

---

### 2. Detection & Hunting

#### SOC Investigation Workbench
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When investigating an alert that has multiple plausible explanations (e.g. administrator maintenance vs. attacker living-off-the-land) and you need structured guidance to avoid confirmation bias.
- **Key Capabilities**: Analysis of Competing Hypotheses (ACH), inquiry question ranking, evidence dependency graphs.
- **Boundaries**: Decision-support framework; does not execute autonomous containment actions.
- **Playbook**: `plugins/detection-hunting/soc-investigation-workbench/docs/PLAYBOOK.md`

#### Sentinel Hunt Workbench
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When authoring, adapting, or testing Microsoft Sentinel and Defender XDR KQL queries against synthetic event streams before deployment to live workspaces.
- **Key Capabilities**: 12 defensive threat hunts, multi-surface syntax adaptation (Sentinel vs Defender vs Data Lake), offline mutation stress-testing.
- **Boundaries**: Synthetic event evaluation; does not authenticate to customer cloud tenants.
- **Playbook**: `plugins/detection-hunting/sentinel-hunt-workbench/docs/PLAYBOOK.md`

#### Attack Path Workbench
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When analyzing cloud IAM trust topologies and lateral movement pathways from offline asset exports to identify critical remediation choke points.
- **Key Capabilities**: Multi-hop directed graph traversal, blast radius calculation, choke-point identification.
- **Boundaries**: Operates strictly on offline JSON exports; does not perform active network scanning.
- **Playbook**: `plugins/detection-hunting/attack-path-workbench/docs/PLAYBOOK.md`

#### Detection Quality Workbench
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When running detection-as-code CI/CD pipelines to catch syntax errors, deprecated operators, and performance regressions in Sentinel KQL and Splunk SPL queries.
- **Key Capabilities**: Offline syntax validation, query regression testing, normalization checks.
- **Boundaries**: Syntax and regression parser; does not query live search clusters.
- **Playbook**: `plugins/detection-hunting/detection-quality-workbench/docs/PLAYBOOK.md`

#### Threat Intelligence Enrichment
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `import`
- **When to use**: When enriching indicators of compromise (IPs, hashes, domains) with threat intelligence metadata while preserving provenance and avoiding external data leaks.
- **Key Capabilities**: Offline feed correlation (MISP/TAXII cached formats), confidence weighting, tamper-evident provenance stamps.
- **Boundaries**: Operates against cached local feeds; external API lookups require explicit operator opt-in.
- **Playbook**: `plugins/detection-hunting/threat-intelligence-enrichment/skills/threat-intelligence-enrichment/SKILL.md`

---

### 3. Identity & Access

#### Entra Identity Workbench
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `import`
- **When to use**: When conducting an identity governance review of Microsoft Entra ID (Azure AD) tenants to uncover over-privileged role assignments, stale service principals, high-risk OAuth consent grants, or expiring credentials.
- **Key Capabilities**: Offline tenant JSON parsing, privilege escalation graph analysis, credential hygiene scoring.
- **Boundaries**: Ingests offline JSON exports; makes zero Microsoft Graph mutations.
- **Playbook**: `plugins/identity-access/entra-identity-workbench/docs/PLAYBOOK.md`

---

### 4. Vulnerability Management

#### Exposure Triage Workbench
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `import`
- **When to use**: When prioritizing thousands of open CVEs across container images or repositories by filtering for components that are actually reachable from code entry points or exposed to network boundaries.
- **Key Capabilities**: SBOM ingestion (CycloneDX / SPDX), advisory CVE matching, static call-graph reachability.
- **Boundaries**: Offline reachability analysis indicates exposure potential, not confirmed live exploitability.
- **Playbook**: `plugins/vulnerability-management/exposure-triage-workbench/docs/PLAYBOOK.md`

#### Patch Security Review
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `import`
- **When to use**: During code reviews and pull request approvals to automatically detect whether a proposed change introduces security regressions, bypasses authorization, or weakens defensive controls.
- **Key Capabilities**: Static patch diff inspection, AST security pattern matching, regression risk classification.
- **Boundaries**: Static diff inspection; does not execute dynamic application security or runtime exploit payloads.
- **Playbook**: `plugins/vulnerability-management/patch-security-review/skills/patch-review/SKILL.md`

---

### 5. Offensive Security

#### Attack Surface Planner
- **Maturity**: <span class="badge badge-experimental">Experimental</span> | **Operational Mode**: `planned`
- **When to use**: Prior to an authorized penetration test or red team engagement to reconcile rules of engagement, partition in-scope vs out-of-scope targets, and generate bounded test plans.
- **Key Capabilities**: Scope boundary enforcement, rule-of-engagement parsing, passive review plan generation.
- **Boundaries**: Strictly a planning and scoping tool; makes zero network calls and executes zero exploits.
- **Playbook**: `plugins/offensive-security/attack-surface-planner/docs/PLAYBOOK.md`

#### Foundry Agent Harness
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When evaluating an autonomous AI agent's robustness against adversarial prompt injection, jailbreak attempts, and unauthorized tool invocation.
- **Key Capabilities**: Simulated agent sandbox, adversarial payload replay, safety boundary scoring.
- **Boundaries**: Mock runtime sandbox; isolates testing without sending data to third-party inference APIs.
- **Playbook**: `plugins/offensive-security/foundry-agent-harness/docs/PLAYBOOK.md`

---

### 6. Incident Response

#### Incident Response Sandbox
- **Maturity**: <span class="badge badge-beta">Beta</span> | **Operational Mode**: `laboratory`
- **When to use**: When preparing an incident response containment plan and needing to rehearse actions, calculate blast radius (e.g. affected dependent services), and obtain interactive operator sign-off with cryptographic receipts.
- **Key Capabilities**: Blast radius calculation, approval-gated containment rehearsal, cryptographic execution receipts.
- **Boundaries**: Approval-gated rehearsal only; does not execute destructive actions on live infrastructure.
- **Playbook**: `plugins/incident-response/incident-response-sandbox/skills/incident-response-sandbox/SKILL.md`

---

## Operational Readiness Modes & Truth-in-Advertising

To maintain absolute integrity and avoid capability over-claiming, COPS reconciles all capabilities into four explicit operational readiness modes:

- **`planned`**: Specification, routing persona, or scoping defined; no autonomous runtime execution.
- **`import`**: Offline static file, code AST, git diff, or export manifest ingestion only; zero live service mutation.
- **`laboratory`**: Controlled offline simulation, synthetic event replay, or sandbox rehearsal; zero external egress.
- **`live-validated`**: Fully authorized, live-tested execution path against an authorized environment with cryptographic evidence receipt. Currently 0 capabilities claim live-validated, ensuring zero false claims.

To audit all 63 capabilities across plugins, specialist profiles, and scenarios:

```bash
python3 -m cops capabilities audit --check
python3 -m cops capabilities list
```
