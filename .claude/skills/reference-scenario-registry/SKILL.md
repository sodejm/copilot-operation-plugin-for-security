---
name: reference-scenario-registry
description: Inspect, filter, and validate the canonical scenario catalog and pinned external provenance registry.
---

# Reference scenario and provenance registry

Inspect, cross-validate, and query canonical operational security scenarios and their pinned external research provenance:

- **Scenario Registry** (`catalog/scenarios.json`): Canonical scenario definitions mapped to MITRE ATT&CK techniques, environment prerequisites, safety profiles, and provenance citations.
- **Provenance Registry** (`catalog/provenance.json`): Pinned external research sources (S01–S13: cheatsheets, threat research articles, Kubernetes tools, primary documentation) with license bounds, revision pins, and complete item-level inventory mappings.

## CLI Usage

### Validate Registry Integrity

Verify that both registries strictly adhere to their JSON schemas and cross-validate that every scenario references a known source and every inventory item resolves without orphans:

```bash
python3 -m cops scenario validate
```

### List Scenarios

List registered canonical scenarios, with optional filtering:

```bash
python3 -m cops scenario list
python3 -m cops scenario list --family COPS-E10.01
python3 -m cops scenario list --tactic discovery
python3 -m cops scenario list --mode planned
python3 -m cops scenario list --json
```

### Inspect a Scenario

View detailed execution metadata, MITRE ATT&CK mappings, safety constraints, and provenance for a specific scenario:

```bash
python3 -m cops scenario info COPS-E01.01-S01
python3 -m cops scenario info COPS-E01.01-S01 --json
```

### Inspect Provenance Sources

View all pinned research sources or drill into the complete item inventory of a specific source:

```bash
# List all 13 pinned sources
python3 -m cops scenario provenance

# Inspect items for a specific source (e.g. S01 command-cheatsheet, S07 Bad Pods)
python3 -m cops scenario provenance --source S01
python3 -m cops scenario provenance --source S07 --json
```

## Python API

```python
from cops.scenarios import (
    load_scenario_registry,
    load_provenance_registry,
    validate_scenario_and_provenance_integrity,
    list_scenarios,
    get_scenario,
    list_provenance_sources,
    get_provenance_source,
    RegistryError,
)

# Cross-validate integrity
summary = validate_scenario_and_provenance_integrity()
print(f"Validated {summary['scenarios_count']} scenarios across {summary['sources_count']} sources")

# Query scenarios
k8s_scenarios = list_scenarios(family_id="COPS-E10.01")
for s in k8s_scenarios:
    print(s["scenario_id"], s["title"])

# Retrieve single scenario
scen = get_scenario("COPS-E01.01-S01")
print(f"Safety profile: {scen['safety_profile']}")

# Query provenance
source = get_provenance_source("S07")
print(f"Source: {source['name']} ({source['url']})")
```

## Error Codes

- `missing_registry`: Required registry file missing from `catalog/`.
- `invalid_json`: Registry file contains malformed JSON syntax.
- `duplicate_scenario_id`: A scenario identifier was defined more than once.
- `duplicate_source_id`: A source identifier was defined more than once in provenance.
- `duplicate_item_id`: An inventory item identifier was defined more than once across sources.
- `orphan_scenario_provenance`: A scenario references a `source_id` that is not registered in provenance.
- `orphan_inventory_mapping`: An inventory item resolves to a scenario that does not exist in the scenario registry.
- `scenario_not_found`: Requested scenario ID does not exist in registry.
- `source_not_found`: Requested provenance source ID does not exist in registry.
