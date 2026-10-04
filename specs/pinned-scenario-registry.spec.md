# Pinned Scenario and Provenance Registry Specification

## Purpose

Define the canonical scenario catalog and pinned external research provenance registry for COPS operational cybersecurity workflows. This specification guarantees:
1. **Verifiable External Provenance**: Every operational scenario is grounded in pinned, licensed external research, cheatsheets, threat articles, or open-source security tools (S01–S13) with immutable revision commits and explicit licenses.
2. **Deterministic Mapping Integrity**: Every item across all 13 pinned sources has an explicit resolution (`scenario`, `supporting_guidance`, or `applicability_decision`) with zero orphaned targets.
3. **Structured Scenario Definitions**: Canonical scenarios declare precise MITRE ATT&CK tactics and techniques, execution environments, required tools, isolation requirements, prerequisites, and safety profiles.
4. **Offline and Script-First Validation**: Integrity checks and queries run completely offline using Python 3.11+ standard library without external network dependencies.

---

## Registry Schemas

### 1. Provenance Registry (`cops.provenance/v1`)
Location: `catalog/provenance.json`
Schema: `catalog/schemas/provenance-registry.schema.json`

Captures 13 pinned reference sources:
- **S01**: `command-cheatsheet` (gunyakit, MIT, commit `4c118399602212f205c91e8f01e418e226fa320c`) — 135 topics
- **S02**: `Cheatsheet-God` (OlivierLaflamme, MIT, commit `2f4a43b2f8eac546a364be16a5dbbe5e2195f469`) — 51 items
- **S03**: Dynatrace: Container Misconfigurations (Technical Article, fair use citation) — 5 items
- **S04**: Palo Alto Unit 42: Modern Kubernetes Threats (Threat Research, fair use citation) — 5 items
- **S05**: SentinelOne: Kubernetes Privilege Escalation (Technical Analysis, fair use citation) — 4 items
- **S06**: Kubernetes RBAC Privilege Escalation & Mitigation (Technical Guide, fair use citation) — 6 items
- **S07**: Bishop Fox: Kubernetes Bad Pods (Apache 2.0 / Technical Research) — 8 items
- **S08**: Kubescape (ARMO, Apache 2.0, tag `v3.0.0`) — 5 items
- **S09**: kube-bench (Aqua Security, Apache 2.0, tag `v0.8.0`) — 4 items
- **S10**: kube-hunter (Aqua Security, Apache 2.0, tag `v0.6.8`) — 5 items
- **S11**: Trivy Kubernetes Documentation (Aqua Security, Apache 2.0, tag `v0.58.0`) — 4 items
- **S12**: Kubernetes RBAC Good Practices (Kubernetes Docs, CC BY 4.0) — 3 items
- **S13**: Kubernetes Pod Security Standards (Kubernetes Docs, CC BY 4.0) — 3 items

Total inventoried items: 238 items.

#### Item Resolutions
- `scenario`: Directly resolves to a canonical scenario in `catalog/scenarios.json`.
- `supporting_guidance`: Pinned as foundational security context, hardening advice, or mitigation principles.
- `applicability_decision`: Explicit engineering rationale for why an item is out-of-scope, unmaintained, or superseded.

### 2. Scenario Registry (`cops.scenario-registry/v1`)
Location: `catalog/scenarios.json`
Schema: `catalog/schemas/scenario-registry.schema.json`

Captures 32 canonical security assessment scenarios spanning:
- **Reconnaissance & Boundary Discovery**: `COPS-E01.01-S01`, `COPS-E04.01-S01`, `COPS-E04.02-S01`, `COPS-E12.02-S01`
- **Infrastructure & RPC Evaluation**: `COPS-E04.03-S01`, `COPS-E04.04-S01`, `COPS-E04.06-S01`
- **Web & API Assessment**: `COPS-E05.01-S01` to `COPS-E05.06-S01`
- **Host & System Privilege Boundaries**: `COPS-E06.01-S01` to `COPS-E06.03-S01`
- **Identity & Active Directory**: `COPS-E07.01-S01` to `COPS-E07.04-S01`
- **Cloud-Native & Kubernetes**: `COPS-E10.01-S01` to `COPS-E10.10-S01`
- **Adversary Simulation & Post-Exploitation**: `COPS-E15.01-S01` to `COPS-E15.03-S01`

---

## Integrity Constraints

1. **Schema Adherence**: Both documents must validate against draft-2020-12 JSON schemas.
2. **Provenance Validity**: Every scenario's `provenance.source_id` must match a registered source ID in `provenance.json`.
3. **No Orphan References**: Every item in `provenance.json` with resolution `scenario` must reference a valid `scenario_id` present in `scenarios.json`.
4. **Identifier Uniqueness**:
   - `scenario_id` must be globally unique across all scenarios.
   - `source_id` must be unique across all sources.
   - `item_id` must be unique across all inventoried items.
5. **Safety Constraints**: Every scenario must specify an explicit safety profile (`impact`, `safe_for_production`, and `reversible`).
