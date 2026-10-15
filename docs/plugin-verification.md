---
layout: documentation
title: Verify a Plugin and Qualify It for Stable
description: Run end-to-end plugin playbooks, record evidence, and review maturity changes.
---

# Verify a plugin and qualify it for stable

Every catalog package has an end-to-end verification playbook. Use it to exercise
the documented user workflow, inspect its results, test rejection and failure
paths, and verify installation in the host you intend to use. A successful run
produces evidence for a maturity review; it does not change a status automatically.

## Choose a playbook

The package manifest (`package.json`) is the source of truth for `maturity`.
Use `python3 -m cops info <plugin-id>` to read its current status and support
limits. The index deliberately does not repeat status labels.

| Plugin | End-to-end verification playbook |
| :--- | :--- |
| COPS Security Logging Advisor | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/logging-telemetry/security-logging-advisor/docs/VERIFICATION.md) |
| COPS SOC Investigation Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/detection-hunting/soc-investigation-workbench/docs/VERIFICATION.md) |
| COPS Sentinel Hunt Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/detection-hunting/sentinel-hunt-workbench/docs/VERIFICATION.md) |
| COPS Attack Path Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/detection-hunting/attack-path-workbench/docs/VERIFICATION.md) |
| COPS Attack Surface Planner | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/offensive-security/attack-surface-planner/docs/VERIFICATION.md) |
| COPS Kubernetes Assessment Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/offensive-security/kubernetes-assessment-workbench/docs/VERIFICATION.md) |
| COPS AD Assessment Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/identity-access/ad-assessment-workbench/docs/VERIFICATION.md) |
| COPS Entra Identity Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/identity-access/entra-identity-workbench/docs/VERIFICATION.md) |
| COPS Exposure Triage Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/vulnerability-management/exposure-triage-workbench/docs/VERIFICATION.md) |
| COPS Exploit Validation Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/vulnerability-management/exploit-validation-workbench/docs/VERIFICATION.md) |
| COPS Microsoft Foundry Adversarial Agent Review Harness | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/offensive-security/foundry-agent-harness/docs/VERIFICATION.md) |
| COPS Detection Quality & Regression Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/detection-hunting/detection-quality-workbench/docs/VERIFICATION.md) |
| COPS Patch Security Review | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/vulnerability-management/patch-security-review/docs/VERIFICATION.md) |
| COPS Threat Intelligence Enrichment | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/detection-hunting/threat-intelligence-enrichment/docs/VERIFICATION.md) |
| COPS Telemetry-to-Detection Proof Pack | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/logging-telemetry/telemetry-proof-pack/docs/VERIFICATION.md) |
| COPS Incident Response Sandbox | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/incident-response/incident-response-sandbox/docs/VERIFICATION.md) |
| COPS Host Assessment Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/offensive-security/host-assessment-workbench/docs/VERIFICATION.md) |
| COPS Offensive Engagement Workbench | [Run the playbook](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/plugins/offensive-security/offensive-engagement-workbench/docs/VERIFICATION.md) |

## Prepare the run

Use a trusted checkout of the revision being qualified and Python 3.11 or newer.
Run commands below from the repository root in Bash or Git Bash. Select the plugin
ID from the index;
this example selects Attack Path Workbench:

```bash
PLUGIN_ID=attack-path-workbench
python3 --version
git rev-parse HEAD
git status --short --branch
python3 -m cops doctor
python3 -m cops info "$PLUGIN_ID"
```

Record the commit, package version, working-tree changes, Python version, OS,
host name/version, and input digests. Qualify a clean revision; results from local
changes must identify the exact patch and be repeated on the review revision.
Use synthetic inputs first, then a sanitized, representative input you are
authorized to inspect. Keep raw logs and customer data in an access-controlled
location outside the checkout. Commit only the sanitized record described below.

Read the package's prerequisites and limitations before running it. Some workflows
use the repository SDK and cannot be qualified by copying the package alone.
An unavailable dependency is `blocked`, not a passing or skipped result. Set up
contributor dependencies using [Contributing](../CONTRIBUTING.md) when required;
`python3 -m cops doctor --contributor` checks the test environment.

The playbooks grant no permission to scan targets, call a provider, send data to a
hosted model, or perform containment. Their runnable examples use local fixtures.
For a host exercise, use a host permitted to handle the selected synthetic input.
Live integrations require separate authorization and an implemented evidence
contract; see [Security model](SECURITY_MODEL.md).

## Run the complete workflow

1. Run the package's verification page in order. Start with discovery, the demo,
   and its complete package gate:

   ```bash
   python3 -m cops info "$PLUGIN_ID"
   python3 -m cops demo "$PLUGIN_ID"
   python3 -m cops check "$PLUGIN_ID"
   ```

2. Run the additional end-to-end exercise on that page. Compare the actual output
   with every acceptance criterion, including evidence references, uncertainty,
   and expected refusals. A zero exit code alone is insufficient. Repeat using a
   representative input and compare the result with an independently prepared
   expected answer. Do not treat an AI-generated answer as its own oracle.
3. Run the package's negative and recovery cases. Confirm invalid or out-of-scope
   input fails with a useful error, partial evidence remains partial, and failures
   leave no unexpected side effects. Record missing cases as gaps to implement.
4. Perform the host exercise below for each host and OS advertised in the proposed
   stable scope. Repeat the complete workflow in a fresh environment and have a
   second operator follow the published instructions without undocumented fixes.
   Preserve both run records. Compare semantic results and digests of deterministic
   outputs; timestamps and operator metadata may differ.
5. Complete cleanup and inspect the resulting Git state. Record each step as
   `pass`, `fail`, `blocked`, or `not_applicable`, with its observed result and
   evidence reference. Explain every `not_applicable`; it cannot exempt a claimed
   feature or required host. Resolve failures and repeat affected steps and their
   downstream workflow on the changed revision.

### Host installation and agent exercise

The CLI suite verifies deterministic behavior. To qualify the user experience,
follow [Portability](PORTABILITY.md) and the package README to install its native
adapter or supported portable export into a clean host profile. Record the exact
installation method, exported artifact digest, host version, OS, and any required
repository SDK. Do not assume generated marketplace files prove host installation.

Confirm the package appears in discovery, its documented command/skill/agent can
be invoked, and referenced files and scripts resolve from the installed location.
Give the host the package-specific task in the playbook, using the same synthetic
input and a private output directory. Compare its report with the CLI result and
the expected answer. Check that it identifies unsupported operations and missing
evidence instead of fabricating provider results or approvals. Remove the test
installation and confirm no test process, fixture mutation, or credential remains.

| Host exercise | Evidence to retain |
| :--- | :--- |
| Native or portable installation | Format, artifact digest, discovery result, dependency resolution |
| Command/skill/agent invocation | Invocation used, selected input digest, report, expected versus observed behavior |
| Boundary and failure case | Rejected request or incomplete input, error/uncertainty shown, side-effect check |
| Cleanup and fresh rerun | Removal result, second installation/run, reviewer comparison |

If a host cannot load a declared adapter, record a failure. If it is unavailable,
record a blocker and keep that host unqualified. Do not expand a passing result
to another host, OS, plugin, version, or service.

## Maturity gates

Maturity describes confidence in the package's **declared scope**. It is separate
from `support.structural_validation`, `support.offline_workflow`,
`support.host_installation`, `support.live_integration`, and capability operational
modes. A stable offline importer can remain an `import` capability. An offline
pass cannot establish live-service behavior. See [Capabilities](CAPABILITIES.md).

| Proposed status | Evidence required |
| :--- | :--- |
| `experimental` | A discoverable package, bounded demo, documented limitations, and an executable verification playbook. Known gaps stay visible. |
| `beta` | Complete declared offline workflow passes on synthetic and representative inputs; malformed, partial, and out-of-scope cases have expected results; dependencies, installation instructions, output contracts, and cleanup are documented. Remaining qualification gaps are explicitly recorded. |
| `stable` | All beta criteria plus successful host exercises for the advertised stable scope, a fresh repeat run, an independent operator/reviewer, passing repository checks on the candidate revision, and no unresolved correctness, security, installation, or recovery defect affecting that scope. Evidence and limitations are linked from the docs. |

Apply every intervening gate when proposing experimental-to-stable promotion.
One demo or a green CI run is insufficient. A limited supported scope must be
explicit in the package README and qualification record before review; narrowing
scope must not hide a broken advertised feature. Existing stable packages use the
same process for requalification; their current label is not historical run evidence.

If a proposed feature needs live validation, qualification remains blocked until
the authorized integration and its evidence contract exist and pass. The current
package schema does not accept stronger host/live support claims without that
contract. A run record can document observations without changing those fields.

## Record the run

Copy [the verification record template](templates/PLUGIN_VERIFICATION_RECORD.md)
to `docs/verification/<plugin-id>/<date>-<short-commit>.md`. Do this on a fresh,
dedicated branch based on the fetched remote default branch; use an isolated
worktree when the current checkout serves another task. For example, in a clean
checkout:

```bash
git fetch origin
git switch -c codex/qualify-attack-path-workbench origin/HEAD
mkdir -p "docs/verification/$PLUGIN_ID"
COPS_RECORD="docs/verification/$PLUGIN_ID/$(date -u +%Y-%m-%d)-$(git rev-parse --short HEAD).md"
cp docs/templates/PLUGIN_VERIFICATION_RECORD.md "$COPS_RECORD"
```

Fill every field. Record command exit codes, expected and observed results,
fixture or representative-input digests, host matrix, negative cases, cleanup,
repeat runs, and reviewer decision. Keep access-controlled evidence references
opaque and sanitized: no credentials, customer identifiers, internal URLs, or
absolute machine paths. Mark unperformed work `blocked`; leave the overall decision
pending until review. A template is not evidence of a completed run.

## Update status after review

After the reviewer accepts the evidence for the proposed scope, prepare these
changes together on the qualification branch:

1. Change only the justified `maturity` value (`experimental`, `beta`, or `stable`)
   in the package's `package.json`. Preserve package IDs and separately assessed
   support fields and capability modes. Do not mark host/live support `validated`
   or set `live-validated` merely because this playbook passed.
2. Link the accepted record from the package README and verification page. State
   the tested package version, revision, host scope, and remaining limitations.
3. Synchronize maturity labels in `README.md`, `docs/index.md`,
   `docs/plugin-guide.md` (both its matrix and detailed section), and
   `docs/CAPABILITIES.md`, plus any package-local status statement. The catalog
   indexes reference packages; they do not hold a separate maturity field.
4. Run the focused checks and the complete contributor gate:

   ```bash
   python3 -m cops info "$PLUGIN_ID"
   python3 -m cops check "$PLUGIN_ID"
   python3 -m cops validate
   python3 -m cops generate --check
   python3 -m cops capabilities audit --check
   python3 scripts/agent/validate_docs.py
   make check
   git diff --check
   ```

5. Review the diff and record exact validation results. Follow the project's
   authorized pull-request and release workflow. Publication or merge is a
   separate decision; writing a status proposal does not publish it.

Evidence binds to the tested revision. If runtime, dependencies, adapters, or
workflow instructions change during review, repeat affected qualification steps
and update the record. A subsequent documentation-only status commit should cite
the tested parent revision and its own check results. Requalify after a material
change or a newly discovered defect; record the reason and lower maturity when
the previously accepted scope no longer meets its gate.
