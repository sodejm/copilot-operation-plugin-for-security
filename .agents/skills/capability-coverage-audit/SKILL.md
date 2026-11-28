---
name: capability-coverage-audit
description: Audit capability truth-in-advertising, reconcile operational readiness modes, and detect over-claiming across plugins, specialists, and scenarios.
---

# Capability coverage and truth-in-advertising audit

Audit, reconcile, and enforce strict truthfulness regarding the operational readiness of all COPS capabilities across three domains:
- **25 Distributed Plugins** (`plugins/*/*/package.json`)
- **27 Specialist Agent Profiles** (`agents/registry.json`)
- **37 Canonical Security Scenarios** (`catalog/scenarios.json`)

## Operational Readiness Modes

COPS strictly differentiates four operational readiness modes:

1. **`planned`**:
   - Specification, routing persona, or scoping defined.
   - No autonomous or live execution path.
   - Example: Scoping planner plugins, specialist agent advisory personas, upcoming attack scenarios.
2. **`import`**:
   - Offline static file, code AST, git diff, or export manifest ingestion only.
   - Zero live service mutation; zero external network egress.
   - Example: `security-logging-advisor`, `entra-identity-workbench`, `patch-security-review`.
3. **`laboratory`**:
   - Isolated local execution with recorded activity and telemetry, verified isolation, and complete restoration.
   - Offline fixtures and synthetic replay can exercise logic, but do not independently establish laboratory readiness.
   - Example: `sentinel-hunt-workbench`, `foundry-agent-harness`, `incident-response-sandbox`.
4. **`live-validated`**:
   - Requires evidence accepted by a registered live-evidence verifier.
   - No such verifier is currently registered, so every `live-validated` mode, true `live_evidence_verified` flag, or package `live_integration: "validated"` claim fails audit.
   - Filenames, flags, manifests, and supplied receipt labels cannot establish live validation.

## CLI Usage

### Audit All Capabilities Against Truth-in-Advertising Rules

Verify that no capability makes a live claim while no live-evidence verifier is registered, and confirm exact identifier and summary reconciliation:

```bash
python3 -m cops capabilities audit --check
```

### List Reconciled Capabilities

List all capabilities with their verified operational modes and truth boundaries:

```bash
# List all 89 capabilities
python3 -m cops capabilities list

# Filter by operational mode
python3 -m cops capabilities list --mode laboratory
python3 -m cops capabilities list --mode import
python3 -m cops capabilities list --mode planned

# Filter by kind (plugin, specialist, scenario)
python3 -m cops capabilities list --kind plugin
python3 -m cops capabilities list --kind specialist

# Output structured JSON
python3 -m cops capabilities list --json
```

### Render Capability Mode Matrix

Generate or export the Markdown capability matrix:

```bash
python3 -m cops capabilities matrix
python3 -m cops capabilities matrix --output docs/CAPABILITIES_MATRIX.md
```

## Python API

```python
from cops.capabilities import (
    build_capability_registry,
    audit_capabilities,
    generate_capability_matrix_markdown,
    CapabilityTruthError,
)

# Build reconciled catalog
registry = build_capability_registry()

# Audit truth-in-advertising invariants
summary = audit_capabilities(registry_data=registry)
print(f"Audited {summary['total_capabilities']} capabilities successfully.")

# Generate markdown table
md = generate_capability_matrix_markdown(registry)
```

## Truth Invariant Error Codes

- `unverified_live_claim`: A capability claimed `live-validated` mode or set `live_evidence_verified` while no live-evidence verifier is registered.
- `unverified_live_integration`: A plugin package claimed `live_integration: "validated"` while no live-evidence verifier is registered.
- `missing_truth_boundary`: A capability has empty or undefined truth boundaries.
- `catalog_descriptive_drift`: Capability identifiers, duplicate detection, summaries, or audited counts diverged from the canonical sources (expected 25 plugins, 27 specialists, 37 scenarios; 89 total).

## Readiness and Generated Assets

Run the portable repository baseline for every change:

```bash
make check
```

Changes affecting laboratory behavior or readiness claims must also pass the dedicated gate:

```bash
make check-laboratory
```

That gate requires observed local activity and telemetry, verified isolation, and restoration. Passing offline fixtures alone is insufficient.

Generate and verify package-owned offline playbooks and walkthroughs with:

```bash
python3 scripts/generate_plugin_playbooks.py
python3 scripts/generate_plugin_playbooks.py --check
```

The portable exporter can carry approved, Git-tracked package assets from `examples/`, `playbooks/`, `walkthroughs/`, `datasets/`, `provenance/`, and `signatures/`. Generated assets document and package a workflow; they are not laboratory execution evidence or live-integration proof.
