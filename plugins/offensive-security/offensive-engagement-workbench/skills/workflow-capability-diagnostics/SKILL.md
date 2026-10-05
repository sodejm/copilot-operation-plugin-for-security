---
name: workflow-capability-diagnostics
description: Inspect host platforms, tool prerequisites, package structures, and capability truth-in-advertising diagnostics.
---

# Workflow capability diagnostics

1. **System Platform Verification**:
   - Detect host operating system, architecture, and Python runtime version.
   - Verify compatibility against the tested OS baseline (`linux`, `darwin`).

2. **Tool Prerequisite Diagnostics**:
   - Query presence and versions of standard and domain security tools (e.g., `python3`, `cops`, `nmap`, `kubectl`, `kube-bench`, `kube-hunter`, `kubescape`).
   - Distinguish missing tools explicitly without treating them as silent failures in offline planning mode.

3. **Package Structure Diagnostics**:
   - Verify package manifests (`package.json`, `plugin.json`), documentation (`README.md`, `PLAYBOOK.md`), validation scripts (`validate-package.py`), and skills directories.
   - Report status as `ready`, `degraded`, or `unready`.

4. **Capability Truth Audit**:
   - Ensure zero unverified claims of `live-validated` mode.
   - Reconcile plugins, specialist profiles, and scenarios against catalog definitions.

5. **CLI Invocation**:
   ```bash
   python3 -m cops diagnostics
   python3 -m cops diagnostics --tools
   python3 -m cops diagnostics --package offensive-engagement-workbench
   python3 -m cops diagnostics --strict
   python3 -m cops diagnostics --json
   ```
