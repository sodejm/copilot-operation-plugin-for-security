---
layout: documentation
title: Runnable Plugin Workflows
description: Run each COPS plugin from sample input to checked output and understand what the result proves.
---

# Runnable plugin workflows

Start with the [possible malicious access walkthrough](investigate-malicious-access.md)
if you have an alert or a suspicious sign-in. It follows one investigation from
intake through evidence review and export, with malicious, benign, and
insufficient-evidence examples.

Use the table below to exercise a particular plugin. Each playback starts with
local sample input, invokes the package's tools, and checks the resulting artifacts
and decisions. A failed expectation makes the command exit with a nonzero status.
The examples use synthetic data or local fixtures; passing them establishes the
documented local behavior, not the state of a production system or readiness of
an isolated laboratory.

## Run a playback

From the repository root, use Python 3.11 or later. Complete the
[contributor setup](contributing.md#environment-setup) for the full test suite. The
optional `laboratory` dependency is needed for signed laboratory receipts.

```bash
python3 -m cops list
python3 -m cops info soc-investigation-workbench
python3 -m cops demo soc-investigation-workbench
python3 -m cops check soc-investigation-workbench
```

`demo` runs the playback declared in the package manifest. `check` runs its
validation suite. The package playbook explains the individual commands, how to
retain output when supported, and how to supply your own sanitized evidence.
Commands that use temporary workspaces remove them when the run finishes.

## Choose a workflow

| Plugin | What the playback exercises | Step-by-step instructions |
| --- | --- | --- |
| `security-logging-advisor` | Collect repository evidence, disclose partial coverage, and validate an analyst-authored recommendation. | [Logging review](../plugins/logging-telemetry/security-logging-advisor/docs/PLAYBOOK.md) |
| `telemetry-proof-pack` | Validate telemetry mappings and compare supported, degraded, and missing evidence. | [Telemetry proof](../plugins/logging-telemetry/telemetry-proof-pack/docs/PLAYBOOK.md) |
| `soc-investigation-workbench` | Intake, handoff, hunt evidence, revise hypotheses, and export all three investigation outcomes. | [SOC investigation](../plugins/detection-hunting/soc-investigation-workbench/docs/PLAYBOOK.md) |
| `sentinel-hunt-workbench` | Render the hunt library and evaluate malicious, benign, and invalid-input fixtures. | [Sentinel hunting](../plugins/detection-hunting/sentinel-hunt-workbench/docs/PLAYBOOK.md) |
| `attack-path-workbench` | Import a graph, evaluate supported and candidate paths, quarantine invalid evidence, and verify report integrity. | [Attack paths](../plugins/detection-hunting/attack-path-workbench/docs/PLAYBOOK.md) |
| `detection-quality-workbench` | Evaluate detection fixtures, benign controls, and mapping drift against expected results. | [Detection regression](../plugins/detection-hunting/detection-quality-workbench/docs/PLAYBOOK.md) |
| `threat-intelligence-enrichment` | Enrich observables with local provider responses and assess conflicts, stale data, and provider failures. | [Intelligence enrichment](../plugins/detection-hunting/threat-intelligence-enrichment/docs/PLAYBOOK.md) |
| `entra-identity-workbench` | Build an identity graph, evaluate privilege hypotheses, and generate reports from local exports. | [Entra identity](../plugins/identity-access/entra-identity-workbench/docs/PLAYBOOK.md) |
| `ad-assessment-workbench` | Plan bounded directory queries, import observations, evaluate a candidate path, and report evidence gaps. | [Active Directory](../plugins/identity-access/ad-assessment-workbench/docs/PLAYBOOK.md) |
| `exposure-triage-workbench` | Join vulnerability and asset evidence, prioritize supported exposure, and preserve unresolved cases. | [Exposure triage](../plugins/vulnerability-management/exposure-triage-workbench/docs/PLAYBOOK.md) |
| `exploit-validation-workbench` | Preflight exact-version reproduction metadata and local hashes, then refuse a mismatched version without execution. | [Versioned reproduction preflight](../plugins/vulnerability-management/exploit-validation-workbench/docs/PLAYBOOK.md) |
| `patch-security-review` | Review malicious and benign changes, validate findings, and produce an evidence-backed report. | [Patch review](../plugins/vulnerability-management/patch-security-review/docs/PLAYBOOK.md) |
| `attack-surface-planner` | Normalize passive exports, apply scope, quarantine exclusions, and propose bounded assessments. | [Attack-surface planning](../plugins/offensive-security/attack-surface-planner/docs/PLAYBOOK.md) |
| `foundry-agent-harness` | Evaluate local mock attacks, classify outcomes, and test authorization denials. | [Foundry agent review](../plugins/offensive-security/foundry-agent-harness/docs/PLAYBOOK.md) |
| `offensive-engagement-workbench` | Validate engagement scope, build a plan and specialist handoffs, and record an inert local subprocess observation. | [Engagement planning](../plugins/offensive-security/offensive-engagement-workbench/docs/PLAYBOOK.md) |
| `kubernetes-assessment-workbench` | Reconcile context identity, namespace access, incomplete coverage, and a rejected cluster change. | [Kubernetes assessment](../plugins/offensive-security/kubernetes-assessment-workbench/docs/PLAYBOOK.md) |
| `host-assessment-workbench` | Import canary observations, distinguish crossings from blocked cases, and reject missing cleanup evidence. | [Host assessment](../plugins/offensive-security/host-assessment-workbench/docs/PLAYBOOK.md) |
| `incident-response-sandbox` | Plan and rehearse response actions, check authorization, and verify rollback and expiry behavior. | [Response rehearsal](../plugins/incident-response/incident-response-sandbox/docs/PLAYBOOK.md) |
| `compliance-posture-workbench` | Map dated fixture evidence to controls while preserving supported, missing, stale, and unknown states. | [Compliance posture](../plugins/governance-compliance/compliance-posture-workbench/docs/PLAYBOOK.md) |
| `cloud-posture-workbench` | Assess imported Terraform, cloud, Kubernetes, and IAM fixtures without claiming live tenant state. | [Cloud posture](../plugins/vulnerability-management/cloud-posture-workbench/docs/PLAYBOOK.md) |
| `supply-chain-cicd-workbench` | Assess imported lockfiles, SBOMs, CI workflows, and provenance fixtures without claiming registry or deployment reachability. | [Supply chain and CI/CD](../plugins/vulnerability-management/supply-chain-cicd-workbench/docs/PLAYBOOK.md) |
| `secrets-remediation-workbench` | Build a revocation and rotation plan from redacted evidence without storing a secret or claiming provider-side completion. | [Secrets remediation](../plugins/identity-access/secrets-remediation-workbench/docs/PLAYBOOK.md) |
| `network-segmentation-workbench` | Assess imported policy, flow, DNS, packet-capture, and reachability fixtures without claiming deployed isolation. | [Network segmentation](../plugins/vulnerability-management/network-segmentation-workbench/docs/PLAYBOOK.md) |
| `tls-crypto-workbench` | Assess imported certificate, TLS, JWT, JWKS, and OpenSSL fixtures without probing an endpoint or proving enforcement. | [TLS and cryptography](../plugins/vulnerability-management/tls-crypto-workbench/docs/PLAYBOOK.md) |
| `web-api-assessment-workbench` | Import redacted HAR, OpenAPI, GraphQL, Postman, and gateway fixtures; preview requests without dispatching them. | [Web and API assessment](../plugins/offensive-security/web-api-assessment-workbench/docs/PLAYBOOK.md) |

## Understand the playback structure

Each package owns its workflow. Its README explains the purpose, design choices,
data contracts, and limits; `docs/PLAYBOOK.md` gives the runnable procedure;
`docs/VERIFICATION.md`, when present, explains qualification and maturity
evidence. The seven experimental import workflows exercise checked-in fixtures;
they do not establish live provider state, deployed enforcement, completed
remediation, production authorization behavior, or isolated-laboratory readiness.

The executable flow follows the same broad sequence:

1. **Prepare input.** Load checked-in synthetic fixtures or create a private
   temporary fixture. Validate required fields and the allowed scope.
2. **Run the tools.** Invoke public commands to build intermediate artifacts,
   such as a graph, query plan, normalized evidence, or a response plan.
3. **Evaluate evidence.** Check expected findings and explicit gaps. Missing
   evidence must remain unresolved; it must not become a benign verdict.
4. **Inspect output.** Check the report, decision records, and integrity or
   provenance fields supported by that package.
5. **Rerun and recover.** Confirm the documented repeat behavior, reject invalid
   inputs, and remove temporary artifacts. Packages that refuse an existing
   workspace explain how to use a fresh one.

Local schemas describe different contracts: an imported observation, an analyst
decision, and an execution receipt are not interchangeable. Use each README's
schema table to identify the producer, consumer, validation command, and example.

## Run the catalog acceptance test

With contributor dependencies installed, this test discovers every catalog
entry and invokes its public `cops demo` command twice. It then exports and runs
each playback twice with an isolated COPS runtime, without source package files or
contributor scripts. Adding a plugin to the catalog automatically adds it to the
test. Exports use the Git index as their file inventory, so stage new package
files before testing an uncommitted change. See the
[export inventory rules](PORTABILITY.md#universal-agent-plugins-v100-export).

```bash
python3 -m pytest -q tests/step_defs/test_portable_operator_workflow.py
python3 scripts/agent/validate_docs.py
make check
```

Package tests check domain behavior in detail; the catalog test checks expected
results through the complete public entry point. Documentation validation also
requires a linked playbook, its demo command, and a schema contract table for each
catalog entry. None of
these checks substitutes for the environment-specific evidence required by
[plugin qualification](plugin-verification.md).
