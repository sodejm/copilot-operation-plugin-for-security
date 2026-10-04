# Capability Reconciliation and Truth-in-Advertising Specification

## Purpose

Define the specification for reconciling advertised and implemented capabilities in COPS. Following the integration of 13 distributed plugins, 18 specialist agent profiles, and 32 canonical security scenarios, this contract guarantees:
1. **Strict Operational Readiness Modes**: Every capability is explicitly classified into one of four verified operational modes:
   - `planned`: Specification, routing persona, or passive scoping defined; no autonomous runtime execution.
   - `import`: Offline static file, code AST, git diff, or export manifest ingestion only; zero live service mutation.
   - `laboratory`: Controlled offline simulation, synthetic event replay, or rehearsal sandbox; zero external egress.
   - `live-validated`: Fully authorized, live-tested execution path against an authorized environment.
2. **Truth in Advertising**:
   - Specialist agent routing profiles are explicitly recognized as advisory/planning personas that cannot autonomously execute without human-signed ActionPlan contracts.
   - Offline plugins that parse static files or replay synthetic telemetry cannot claim live cloud or live network execution.
3. **No Unverified Live Claims**:
   - Automated audit fails closed if any capability claims `live-validated` or `live_integration: "validated"` without cryptographically verifiable `cops.evidence/v1` receipt envelopes.
4. **Zero Catalog Drift**:
   - Reconciles counts across `docs/CAPABILITIES.md`, `catalog/plugins.json`, `agents/registry.json`, and `catalog/scenarios.json`.

---

## Capability Schema Contract

Location: `catalog/schemas/capability-registry.schema.json`
Schema Version: `cops.capabilities/v1`
Registry File: `catalog/capabilities.json`

### Required Fields for Each Capability Entry
- `id`: Unique identifier of the plugin, specialist profile, or scenario.
- `name`: Human-readable display name.
- `kind`: `plugin`, `specialist`, or `scenario`.
- `mode`: `planned`, `import`, `laboratory`, or `live-validated`.
- `domain`: Functional cybersecurity domain or family.
- `validation_status`: `validated` or `unverified`.
- `truth_boundaries`: Mandatory non-empty statement of what the capability can and cannot do.
- `evidence_requirements`: List of verifiable artifacts required for the claimed mode.
- `live_evidence_verified`: Boolean flag indicating whether live execution proof has been verified.

---

## Truth-in-Advertising Invariants

1. **Unverified Live Execution**: If `mode == "live-validated"` and `live_evidence_verified == False`, validation fails with `unverified_live_claim`.
2. **Unverified Live Integration in Packages**: If any plugin's `package.json` specifies `support.live_integration == "validated"` without registered live receipts, audit fails with `unverified_live_integration`.
3. **Mandatory Truth Boundaries**: Any capability with empty, whitespace-only, or missing `truth_boundaries` fails with `missing_truth_boundary`.
4. **Descriptive Drift Prevention**: Any deviation from the canonical counts (13 plugins, 18 specialists, 32 scenarios) fails with `catalog_descriptive_drift`.
