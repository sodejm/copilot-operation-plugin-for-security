# Capability Reconciliation and Truth-in-Advertising Specification

## Purpose

Define the specification for reconciling advertised and implemented capabilities in COPS. Following the integration of 25 distributed plugins, 27 specialist agent profiles, and 37 canonical security scenarios, this contract guarantees:
1. **Strict Operational Readiness Modes**: Every capability is explicitly classified into one of four verified operational modes:
   - `planned`: Specification, routing persona, or passive scoping defined; no autonomous runtime execution.
   - `import`: Offline static file, code AST, git diff, or export manifest ingestion only; zero live service mutation.
   - `laboratory`: Isolated local execution with observed activity and telemetry, verified isolation, and complete restoration.
   - `live-validated`: Live execution whose evidence has been accepted by a registered live-evidence verifier.
2. **Truth in Advertising**:
   - Specialist agent routing profiles are explicitly recognized as advisory/planning personas that cannot autonomously execute without human-signed ActionPlan contracts.
   - Offline plugins that parse static files or replay synthetic telemetry cannot claim live cloud or live network execution.
3. **No Unverified Live Claims**:
   - No live-evidence verifier is currently registered. The audit therefore rejects every `live-validated` mode, true `live_evidence_verified` flag, and `live_integration: "validated"` package claim.
   - Filenames, flags, manifests, and supplied receipt labels are claims rather than proof and cannot establish live validation.
4. **Zero Catalog Drift**:
   - Reconciles the exact capability identity sets, rejects duplicates, and verifies summary counts across `catalog/plugins.json`, `agents/registry.json`, `catalog/scenarios.json`, and `catalog/capabilities.json`.

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

1. **Unverified Live Execution**: Until a live-evidence verifier is registered, any `mode == "live-validated"` or `live_evidence_verified == True` claim fails with `unverified_live_claim`.
2. **Unverified Live Integration in Packages**: Until a live-evidence verifier is registered, any plugin whose package manifest specifies `support.live_integration == "validated"` fails with `unverified_live_integration`.
3. **Mandatory Truth Boundaries**: Any capability with empty, whitespace-only, or missing `truth_boundaries` fails with `missing_truth_boundary`.
4. **Descriptive Drift Prevention**: Duplicate or mismatched capability identifiers, inconsistent summaries, or deviation from the canonical counts (25 plugins, 27 specialists, 37 scenarios; 89 total) fails with `catalog_descriptive_drift`.

## Laboratory and Portable Evidence

Offline fixtures, generated playbooks, and generated walkthroughs validate deterministic package logic. They do not establish laboratory readiness. A laboratory claim also requires recorded local activity, telemetry and alerts where applicable, verified isolation, and successful restoration. These conditions are enforced by the mandatory laboratory gate:

```bash
make check-laboratory
```

The portable baseline remains:

```bash
make check
```

Package playbooks and walkthroughs are generated and checked with:

```bash
python3 scripts/generate_plugin_playbooks.py
python3 scripts/generate_plugin_playbooks.py --check
```

Portable exports include approved, Git-tracked package assets under `examples/`, `playbooks/`, `walkthroughs/`, `datasets/`, `provenance/`, and `signatures/`. Their presence proves packaging completeness only; it does not prove execution, isolation, restoration, or live integration.
