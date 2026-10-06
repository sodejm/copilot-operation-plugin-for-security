---
name: workflow-capability-diagnostics
description: Inspect host platforms, tool prerequisites, package structures, and capability truth-in-advertising diagnostics.
---

# Workflow Capability Diagnostics

Run comprehensive system platform checks, host tool prerequisite inspections against tested matrices, package manifest/skills/playbook/validator structure verification, and capability truth-in-advertising audits across all registered packages.

## Core Responsibilities

1. **System Platform Verification**:
   - Detect host operating system, architecture, and Python runtime version.
   - Verify compatibility against the tested OS baseline (`linux`, `darwin`).
2. **Tool Prerequisite Diagnostics**:
   - Query presence and versions of standard and domain security tools (e.g., `python3`, `cops`, `git`, `nmap`, `trivy`, `curl`, `jq`, `docker`).
   - Distinguish missing tools explicitly without treating them as silent failures in offline planning mode.
3. **Package Structure Diagnostics**:
   - Verify package manifest (`package.json`, `plugin.json`), documentation (`README.md`, `PLAYBOOK.md`), validation scripts (`validate-package.py`), and skills directories.
   - Report status as `ready`, `degraded`, or `unready`.
4. **Capability Truth Audit**:
   - Ensure zero unverified claims of `live-validated` mode.
   - Reconcile plugins, specialist profiles, and scenarios against catalog definitions.

## CLI Usage

### Run All Diagnostics

```bash
python3 -m cops diagnostics
```

### Inspect Host Tools Only

```bash
python3 -m cops diagnostics --tools
```

### Scope to a Specific Package

```bash
python3 -m cops diagnostics --package offensive-engagement-workbench
```

### Strict Mode Gate

Fails (exit code 1) if any package is degraded/unready or any tool is missing:

```bash
python3 -m cops diagnostics --strict
```

### JSON Output for Automation

```bash
python3 -m cops diagnostics --json
```

## Python API

```python
from pathlib import Path
from cops.diagnostics import run_diagnostics

report = run_diagnostics(root=Path("."), strict=False)
assert report.system.is_supported
assert report.capability_truth_passed
for pkg in report.packages:
    print(pkg.package_id, pkg.status)
```
