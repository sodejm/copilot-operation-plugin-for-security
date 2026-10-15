# Reconcile Kubernetes evidence

Use this playback when you have a selected context and want to establish whether
a sanitized observation belongs to the approved scope. See the
[README](../README.md) for the schema and design rationale.

## 1. Run the checked example

From the repository root with Python 3.11 or newer:

```bash
python3 -m cops demo kubernetes-assessment-workbench
```

The playback invokes `scripts/assess.py` for each case in a temporary private
directory. It deletes its generated inputs on exit and prints a JSON summary.
`status: passed` requires all of these assertions:

| Case | Change from the checked-in fixture | Expected result |
| --- | --- | --- |
| Matching context | None | `matched_sanitized_export`, accessible `payments` namespace, no blockers |
| Limited evidence | Remove the observed UID anchor, deny namespace access, omit surface observations, mark control-plane access managed-unavailable | Unresolved identity, all three incomplete-evidence blockers, explicit control-plane and node limitations |
| Context switch | Change the observed cluster | Exit 2 with `context_mismatch`; no success report |

The matching record is imported twice and must produce identical reports. All
successful imports assert zero network requests and no live-execution readiness.

## 2. Inspect one report

```bash
python3 plugins/offensive-security/kubernetes-assessment-workbench/scripts/assess.py plugins/offensive-security/kubernetes-assessment-workbench/fixtures/synthetic/context.json
```

Read `selected_context` first, then `cluster_identity`. Check each namespace and
surface independently before reviewing `cluster_facts`, `blockers`, and
`limitations`. The fixture contains synthetic assertions for a local lab; its
version strings are input data, not recommendations for a production cluster.

## 3. Apply the workflow to an export

Create a local record using the fixture's exact structure. Replace assertions with
a sanitized export obtained within your approved scope. Run the same importer
with your record path. Preserve unresolved values when evidence is unavailable.
Store reports privately: even a credential-free report can reveal context names
and scope. The command writes JSON to stdout; redirect it only to a location you
control.

If the importer rejects a context switch or conflicting UID, correct or recollect
the export before continuing. An access denial calls for an explicit collection
limitation or a separately authorized change in access. The playback supplies no
such authorization.

## 4. Verify and close

```bash
python3 -m cops check kubernetes-assessment-workbench
```

The package check covers import constraints and repeats this playback. No cluster
resources are created. Remove any operator-created report copies according to
your evidence retention policy. Record results with the
[verification procedure](VERIFICATION.md); keep offline and live evidence separate.

<!-- BEGIN COPS GENERATED OFFLINE ASSESSMENT LINKS -->
## Generated offline assessment

- [Machine-readable playbook](../playbooks/offline-assessment.json)
- [Runnable offline walkthrough](../walkthroughs/offline-assessment.md)
<!-- END COPS GENERATED OFFLINE ASSESSMENT LINKS -->
