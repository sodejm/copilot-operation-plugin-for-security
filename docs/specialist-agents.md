---
layout: documentation
title: "27 Specialist Cybersecurity Agents & Dynamic Routing"
description: "Catalog of twenty-seven cybersecurity agent profiles, deterministic profile selection, proposed triad plans, and specialist handoff records."
---

# 27 Specialist Cybersecurity Agents & Dynamic Routing

COPS centralizes **27 specialist cybersecurity agent profiles** housed in `agents/`. Each profile defines a dedicated persona, tool allowlist, domain constraints, and evaluation criteria tailored to specific security disciplines.

The COPS router recommends a specialist profile for your host assistant to use. Starting an agent is a separate action in that host.

---

## Dynamic local routing (`cops route`)

The router selects a profile by an explicit profile ID or by deterministic matches
against the profile's symptom, artifact, anti-trigger, and example-prompt metadata.
It extracts only routing-safe feature categories, then combines exact trigger,
BM25, and conservative fuzzy scores. A result below 0.65 confidence, or with less
than 0.15 confidence between its leading candidates, asks for clarification. It
does not silently select a general-purpose profile. The clarification includes
candidate purposes and required permissions so the caller can make a bounded
choice.

These local rules use standard Python **without consuming LLM tokens** or calling
external APIs:

```bash
# Route any natural language task:
python3 -m cops route "Review this Microsoft Sentinel KQL query for high ingestion cost"

# Route an incident containment task:
python3 -m cops route "Rehearse containment of a compromised service principal with blast radius proof"

# Route an application security review:
python3 -m cops route "Audit this Python codebase for missing audit logs and credential leaks"
```

To list all 27 specialist profiles from your terminal:

```bash
python3 -m cops specialists
```

The versioned `cops.routing-decision/v2` result includes its status, ranked
candidates, reasons, confidence, and authorization requirements. Integrators can
optionally supply a classifier callback when deterministic routing remains
ambiguous. The callback contract requires an explicit model, deadline, and token
budget. It receives redacted feature categories and registered profile IDs rather
than the raw request. Missing limits, an exhausted budget, an unavailable or timed
out callback, an unknown profile, or a low-confidence answer leaves the result in
clarification status.

Repository integrations can use `collect_repository_context` from `cops.context`
to inventory supported local artifacts without returning file content. It detects
dependency manifests, CI workflows, rendered Kubernetes or Helm output, and
Terraform plan JSON while excluding credentials, raw state, history, symlinks,
special files, and unrelated directories. Network collection is a separate,
explicit input. `build_execution_preview` from `cops.preview` turns a routing
decision and declared actions into a pure preview of specialist order, reads,
writes, exact destinations, authorization, evidence, budget, noise, and unknowns.
The preview does not connect services, launch workers, consume approval, or write
state.

---

## Triad plans from routing

When the selected profile is marked critical, or you pass `--critical`, the router returns a proposed plan with a Primary Specialist, Domain Skeptic, Evidence Auditor, and handoff steps:

```bash
python3 -m cops route "cops-pentest-specialist" --json
```

The command returns routing data; it does not launch agents or execute the task. The `interactive_authorization_required` field comes from the selected profile. A prompt appears only when you pass `--authorize` and that field is true. A routing authorization receipt does not replace the separate [execution authorization requirements](AUTHENTICATED_EXECUTION.md).

## Model and effort suggestions

Specialist profiles define task roles. The optional model advisor evaluates the
model and reasoning effort used to carry out those roles:

```bash
python3 -m cops route "Review the authorization boundary" \
  --suggest-model --model-catalog model-catalog.json \
  --current-model <exact-host-model-id> --current-effort medium --json
```

Follow the [model routing guide](model-effort-routing.md) to supply fresh exact
host evidence, inspect task classification and exclusions, and verify the current
pair before implementation. Family names do not establish cybersecurity
capability or entitlement. Suggestions do not launch agents, switch models, or
replace execution authorization.

## Specialist Catalog by Discipline

### 1. Offensive Security

| Agent Profile ID | Role | Key Capabilities |
| :--- | :--- | :--- |
| `cops-pentest-specialist` | Penetration Testing Specialist | Scoping validation, non-destructive methodology planning, vulnerability assessment. |
| `cops-host-specialist` | Host Assessment Specialist | Offline Linux and Windows privilege-boundary export review with prerequisite and canary-report limits. |
| `cops-kubernetes-specialist` | Kubernetes Assessment Specialist | Offline approved-context, namespace, and surface comparison with live-evidence limits. |
| `cops-redteam-operator` | Red Team Operations Specialist | Threat actor emulation planning, ATT&CK TTP mapping, defensive evasion analysis. |
| `cops-attack-surface-planner` | Attack Surface Planner | Passive reconnaissance planning, domain mapping, in-scope vs. out-of-scope enforcement. |
| `cops-ai-adversary-specialist` | AI Adversary & Red Teamer | Bounded direct and indirect injection cases and recorded tool-boundary assessment; provider resistance requires separate live evidence. |
| `cops-api-security-specialist` | API Security Specialist | REST and GraphQL inventory, isolated role/object authorization playback, and bounded rate-limit cases. |

---

### 2. Defensive & Detection Engineering

| Agent Profile ID | Role | Key Capabilities |
| :--- | :--- | :--- |
| `cops-sentinel-kql-engineer` | Microsoft Sentinel KQL Engineer | High-performance KQL authoring, multi-table joins, ingestion cost optimization, Defender XDR adaptation. |
| `cops-threat-hunter` | Threat Hunter | Hypothesis generation, baseline anomaly detection, living-off-the-land (LotL) hunting. |
| `cops-soc-analyst` | SOC Alert Analyst | Tier 1-3 alert triage, Analysis of Competing Hypotheses (ACH), inquiry question ranking. |
| `cops-detection-engineer` | Detection Engineer | Detection-as-code, SPL and KQL syntax validation, regression testing against synthetic events. |

---

### 3. Incident Response & Forensics

| Agent Profile ID | Role | Key Capabilities |
| :--- | :--- | :--- |
| `cops-incident-responder` | Incident Responder | Containment playbooks, blast radius calculation, cryptographic execution receipts. |
| `cops-forensic-collector` | Forensic Evidence Collector | Tamper-evident evidence capture, hash generation, chain-of-custody verification. |
| `cops-malware-analyst` | Static Malware Analyst | Static binary triage, string extraction, PE header analysis, capability identification. |

---

### 4. Identity & Application Security

| Agent Profile ID | Role | Key Capabilities |
| :--- | :--- | :--- |
| `cops-identity-specialist` | Cloud Identity & Access Specialist | Microsoft Entra ID role analysis, service principal credential hygiene, OAuth consent audits. |
| `cops-ad-specialist` | Active Directory Assessment Specialist | Offline, scoped AD relationship inventory, evidence-linked candidate paths, and collection coverage review. |
| `cops-exposure-analyst` | Vulnerability Exposure Analyst | SBOM correlation (CycloneDX/SPDX), CVE reachability analysis, exploit exposure scoring. |
| `cops-appsec-engineer` | Application Security Engineer | Static code review, logging gap analysis, patch security review, CWE pattern detection. |
| `cops-threat-intel-analyst` | Threat Intelligence Analyst | IOC enrichment, MITRE ATT&CK actor attribution, offline feed correlation. |
| `cops-secrets-remediation-specialist` | Secrets Remediation Specialist | Bounded, read-only Git-history review, redacted exposure evidence, and rotation or revocation guidance. |
| `cops-supply-chain-specialist` | Supply Chain Security Specialist | Lockfile and SBOM review against pinned advisory evidence, workflow permissions, and registry-resolution risks. |

---

### 5. Governance, Efficacy & Architecture

| Agent Profile ID | Role | Key Capabilities |
| :--- | :--- | :--- |
| `cops-purple-team-coordinator` | Purple Team Coordinator | Joint offensive-defensive exercise design, detection gap analysis, remediation tracking. |
| `cops-logging-architect` | Enterprise Logging Architect | Telemetry pipeline design (Cribl Stream, Splunk, Sentinel), ingestion volume management. |
| `cops-compliance-auditor` | Security & Compliance Auditor | Versioned SOC 2, CIS, and NIST evidence mappings with supported, unsupported, and unknown outcomes. |
| `cops-cloud-posture-specialist` | Cloud Posture Specialist | Bounded Terraform plan, rendered Kubernetes, and cloud configuration export review with explicit coverage limits. |
| `cops-network-segmentation-specialist` | Network Segmentation Specialist | Expected versus recorded reachability, firewall and NetworkPolicy evidence, and bounded laboratory connectivity checks. |
| `cops-tls-crypto-specialist` | TLS & Cryptography Specialist | Certificate and JWT/JWKS configuration review and ephemeral TLS/mTLS service tests. |

---

## Triad Orchestration for High-Risk Operations

For sensitive operational domains, the specialist handoff contract records a bounded review by a planner, specialist, skeptic, and auditor. The planner selects a workflow skill and specialist capability. Acceptance verifies the skill is declared by the recipient, exists locally, and maps to a registered specialist capability. It records the resolved skill path, file digest, and a checksum of the target within the handoff record. Skeptic review and audit repeat the resolution and reject a missing or changed local target.

Records marked `accepted`, `in_review`, or `completed` must include the resolved skill path, digest, and target checksum. Older records without these fields fail current contract validation and need a new proposal and acceptance before continuing the handoff. The checksum detects partial edits to one record; an operator who can rewrite the entire JSON record can also replace its checksum. Treat the handoff file as operator-controlled input, not authenticated approval evidence.

The handoff API and CLI do not automatically activate on high-risk tasks or execute the selected skill. A `completed` handoff records successful metadata and evidence review; it is not an execution receipt.

```mermaid
flowchart LR
    PLAN["Approved action plan"] --> PROPOSAL["Proposed handoff and workflow target"]
    PROPOSAL --> ACCEPT["Specialist accepts resolved skill and capability"]
    ACCEPT --> REVIEW["Skeptic reviews candidate evidence"]
    REVIEW --> AUDIT["Auditor checks plan bounds and skill digest"]
    AUDIT --> COMPLETE["Completed handoff record"]
```

The approved `ActionPlan` supplies the bounds checked by this workflow. Tool execution and its authorization use separate execution contracts and controls.

---

## Using Specialist Profiles in AI Assistants

Profiles and skills are packaged for these hosts. Installation and actual host execution require separate validation:

- **GitHub Copilot**: Configured in `.github/copilot-instructions.md` and repository skills.
- **Claude Code**: Packaged under `.claude/` and callable via subagents.
- **Codex / ChatGPT**: Packaged under `.agents/` and registered with the Agent Skills specification.
