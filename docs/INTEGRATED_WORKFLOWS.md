# Integrated workflows

The integrated workflow catalog contains six versioned, executable examples that
connect COPS assessment results without weakening the existing ActionPlan
authorization boundary. Catalog fixture profiles pin their inputs by digest;
ad hoc inputs must satisfy the selected definition's declared types. Offline
playback uses exact `fixture://<workflow-id>` targets, denies egress, and permits no side
effects. Every stage still compiles to `cops.action-plan/v1`, including its bound
target, action, arguments, limits, and expected evidence.

| Workflow ID | Typed stage chain | Fixture profiles |
| --- | --- | --- |
| `leaked-credential-blast-radius` | Git history findings → identity and SOC evidence → exposure assessment → rotation/revocation checklist → evidence bundle | `vulnerable`, `corrected` |
| `cve-reachability-triage` | advisory and dependency evidence → call graph/runtime reachability → compensating controls → prioritized remediation | `vulnerable`, `limited` |
| `kubernetes-compromise-containment` | evidence snapshot → RBAC/service account review → proposed containment → modeled lab expectations → required authorized lab validation | `vulnerable`, `corrected` |
| `illicit-consent-remediation` | Entra grants and sign-ins → suspicious-consent assessment → remediation proposal → modeled identity/hunt validation expectations | `vulnerable`, `corrected` |
| `detection-rule-ci-validation` | telemetry replay → Sigma/KQL execution → attack and benign counts → evidence-backed detection report | `verified`, `detection_gap` |
| `pre-release-exposure-audit` | scoped DNS/service inventory → port and route checks → authentication checks → remediation report | `vulnerable`, `corrected` |

## Catalog and playback API

The catalog is `catalog/workflows/catalog.json`. Each entry pins the canonical
digest of its workflow definition and every fixture. Validation rejects unsafe
paths, changed definitions or fixtures, invalid workflow graphs, missing or
mistyped inputs, undeclared output references, unsafe fixture targets, egress,
side effects, unregistered playback actions, unregistered specialist ownership,
and unregistered scenario IDs.

Use the public functions from `cops.workflows.playback`:

```python
from cops.workflows.playback import (
    EvidenceBundleSigner,
    load_integrated_workflows,
    run_fixture_profile,
    run_offline_playback,
    validate_integrated_workflow_catalog,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

catalog = validate_integrated_workflow_catalog()
definitions = load_integrated_workflows()
report = run_fixture_profile("cve-reachability-triage", "limited")

# A caller that controls an Ed25519 key can sign the leaked-credential bundle.
# The report verifies integrity immediately but does not claim that the caller's
# public key is anchored to an external trust system.
signed = run_fixture_profile(
    "leaked-credential-blast-radius",
    "vulnerable",
    evidence_signer=EvidenceBundleSigner(
        key_id="evidence-key-2026",
        private_key=Ed25519PrivateKey.generate(),
    ),
)

# Ad hoc fixture inputs are also allowed when they satisfy the selected
# definition's declared input types.
report = run_offline_playback(
    "detection-rule-ci-validation",
    {
        "source_result": {
            "kind": "simulation", "ref": "simulation://credential-revocation"
        },
        "expected_telemetry": [{"field": "event", "value": "credential_revoked"}],
        "correlation_ids": ["corr-001"],
        "evidence_refs": ["evidence://simulation/001"],
        "time_window": {
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-01T00:10:00Z",
        },
        "telemetry": [{
            "correlation_id": "corr-001", "event": "credential_revoked",
            "timestamp": "2026-01-01T00:05:00Z",
        }],
        "alerts": [{
            "alert": True, "correlation_id": "corr-001",
            "timestamp": "2026-01-01T00:06:00Z",
        }],
        "attack_fixture": [{
            "correlation_id": "corr-001", "event": "credential_revoked"
        }],
        "benign_fixture": [{
            "correlation_id": "corr-benign", "event": "interactive_login"
        }],
    },
)
```

`run_offline_playback` returns `cops.integrated-workflow-playback/v1`. Its stage
records include the compiled ActionPlan snapshot, typed outputs, and a deterministic
evidence reference. This report is suitable for tests and demonstrations; it is
not an authorization record and does not execute a worker.

## Authorization and evidence boundaries

The catalog fixture definitions are limited to offline evidence transformation.
A live target, a different action, or an action with side effects requires a new
workflow definition and a newly authorized ActionPlan through the existing worker
authorization flow. The workflow layer does not create another approval system
and does not expand targets from discovered data.

Fixture reports state their evidence limits directly:

- Missing call graph or runtime evidence produces `insufficient_evidence` and
  never establishes non-exploitability.
- The leaked-credential fixture bundle always carries a SHA-256 payload digest.
  Without a signer it reports `unsigned` and `live_signing_required: true`. With
  a caller-owned Ed25519 signer, it records and verifies the signature while
  reporting `caller_configured_unanchored` and
  `authenticity_established: false`; key trust remains external evidence.
- Kubernetes containment playback only models proposed changes and expected lab
  checks. It reports `activity_performed: false`, never claims connectivity or
  cleanup verification, and returns `insufficient_lab_validation` when changes
  require an authorized laboratory run.
- Illicit-consent playback models the expected identity and hunt package checks.
  It never reports either package as exercised and returns
  `insufficient_lab_validation` when a remediation proposal requires laboratory
  validation.
- Detection validation reports `verified_detection` only when actual telemetry
  and an alert share the expected correlation and time window. Missing logs are
  an `instrumentation_gap`; captured telemetry without the expected alert is a
  `detection_gap` with Sigma and KQL proposals. Missing evidence is
  `indeterminate`.
- Exposure inventory and route checks discard hosts outside the declared scope.
  A clean fixture result supports only `no_exposure_observed` for the supplied
  evidence.

The laboratory report integration maps the `telemetry_events` and
`alert_events` arrays returned by `ServiceLaboratoryReport.to_dict()` to the
workflow inputs `telemetry` and `alerts`, respectively. Events must
carry RFC 3339 `timestamp` and `correlation_id` values; alerts also carry
`alert: true`. Passing those arrays into the detection workflow evaluates the
same purple-team handoff rules used by offline playback.

## Active service chains

`cops.laboratory.integrated_lab.run_integrated_service_laboratory` executes five
additional chains against disposable services: leaked-credential blast radius,
CVE reachability, illicit consent, detection CI, and pre-release exposure. Pass
the workflow ID and a new private state directory. Set `require_isolation=True`
for acceptance; the strict Docker gate runs all five chains automatically.

Each stage receives typed configuration and the preceding stage's observations.
The laboratory approval adapter reconstructs the expected ActionPlan from those
exact inputs, the next stage, run identity, worker, and service URLs before issuing
and consuming a one-use execution authorization. Changed destinations, actions,
prior outputs, workers, or authorization IDs fail before consumption. Persisted
results retain plan and output digests. The service-issued credential remains in
memory and is excluded from results and state.

The credential chain creates a disposable Git repository, commits and then deletes
a synthetic credential, and scans reachable history through the pinned Git
adapter. It verifies unchanged repository bytes and identifies the same credential
used by the service. The credential and consent chains prove authenticated access,
revocation, and subsequent HTTP 401. The credential chain signs its redacted evidence bundle with
an ephemeral Ed25519 key and verifies the signature. Detection CI measures actual
captured attack and benign events. Exposure checks make authenticated and anonymous
requests to the scoped graph. CVE triage sends the injection fixture to vulnerable
and corrected servers and preserves missing reachability as unknown. Every chain
collects correlated telemetry and verifies baseline restoration and stopped services.

These cases have explicit coverage limits. Git scanning recognizes the documented
synthetic patterns only and requires a reviewed executable pin; CVE triage uses a pinned synthetic injection advisory rather than a
dependency build; consent uses an application-grant emulator rather than Entra;
active detection uses registered laboratory event rules rather than a production
Sigma/KQL engine; the exposure inventory uses numeric loopback addresses rather
than DNS discovery. Kubernetes policy enforcement remains unvalidated. An ephemeral
signing key proves bundle integrity, not external source authenticity. These
laboratory cases do not establish the production worker's distinct-user boundary.

Run the focused validation with the repository environment:

```console
python -m pytest -q tests/test_integrated_workflows.py
python -m pytest -q tests/test_integrated_service_laboratory.py
```
