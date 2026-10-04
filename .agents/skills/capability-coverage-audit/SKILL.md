---
name: capability-coverage-audit
description: Audit capability truth-in-advertising, reconcile operational readiness modes, and detect over-claiming across plugins, specialists, and scenarios.
---

# Capability coverage and truth-in-advertising audit

Audit, reconcile, and enforce strict truthfulness regarding the operational readiness of all COPS capabilities across three domains:
- **13 Distributed Plugins** (`plugins/*/*/package.json`)
- **18 Specialist Agent Profiles** (`agents/registry.json`)
- **32 Canonical Security Scenarios** (`catalog/scenarios.json`)

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
   - Controlled offline simulation, synthetic event replay, or sandbox rehearsal.
   - Zero production infrastructure impact; zero external egress.
   - Example: `sentinel-hunt-workbench`, `foundry-agent-harness`, `incident-response-sandbox`.
4. **`live-validated`**:
   - Fully authorized, live-tested execution path against an authorized environment.
   - Requires cryptographic operator authorization receipt and immutable `cops.evidence/v1` receipt bundle.
   - Currently 0 capabilities claim `live-validated`, preserving absolute honesty.

## CLI Usage

### Audit All Capabilities Against Truth-in-Advertising Rules

Verify that no capability claims `live-validated` or `live_integration: validated` without verified evidence, and confirm zero catalog drift:

```bash
python3 -m cops capabilities audit --check
```

### List Reconciled Capabilities

List all capabilities with their verified operational modes and truth boundaries:

```bash
# List all 63 capabilities
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

- `unverified_live_claim`: A capability or scenario claimed `live-validated` mode without verified live execution evidence.
- `unverified_live_integration`: A plugin package claimed `live_integration: "validated"` without registered live evidence receipts.
- `missing_truth_boundary`: A capability has empty or undefined truth boundaries.
- `catalog_descriptive_drift`: Total audited count diverged from the canonical registry (expected 13 plugins, 18 specialists, 32 scenarios).
