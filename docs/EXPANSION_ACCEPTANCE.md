# Expansion acceptance record

This record distinguishes implementation, offline correction evidence, and
active laboratory evidence. No production/provider integration is promoted by
this expansion. A required check that is blocked or unavailable leaves that
capability incomplete.

## Revision and reproducibility

The integration branch is based on
`6c2a1b5f9659429dfd0c260c3929ff0f251e3e7`. Acceptance is in progress against the
integration changes; that base commit alone does not identify the changed
implementation. Final handoff must record a clean implementation revision,
fixture digests, runtime image digest, and exact check results. Evidence from an
earlier source snapshot must be rerun after behavioral changes.

An earlier strict laboratory run passed all eleven cases using immutable image
`sha256:cf7d32ac327f8eb584f8d917f43c48ff5bf460019af889da93b33583bde62fd9`
and source snapshot
`4e60b8c5d7a44299c33031e798034ef613484acb4b5ff0bb46dbea2c8df97195`.
It exercised offline playback, vulnerable and corrected services, workflow
success, partial failure, cancellation, and five integrated service chains.
These digests identify that run, not subsequent changes. The focused laboratory
test selection passed 70 tests on the same implementation.

## Check ledger

| Check | Observed result | Remaining requirement |
| --- | --- | --- |
| Package and portable checks | `make check` passed; 25 package gates passed | Repeat after behavioral changes |
| Root test suite | Passed as part of `make check`; platform-specific skips remain | Record final totals and platform limits |
| Documentation | `make check-docs` passed for 56 pages | Repeat after documentation changes |
| Strict isolated laboratory | Eleven cases passed on the snapshot above | Repeat after service coverage changes |
| Hosted and native CI | Not run by this local record | Obtain distinct platform and worker evidence |
| Production integrations | Not run | Separately authorized live validation |

The strict gate proved a Docker `none` network, loopback-only interfaces and
routes, definitive IPv4/IPv6 egress rejection, actual TCP activity, captured
telemetry, baseline restoration, stopped listeners, and owned-container removal.
It did not certify a production worker running under a distinct OS identity.

## Capability evidence

All offline families use vulnerable, corrected, benign, and insufficient-evidence
cases in `tests/fixtures/artifact_assessment_cases_v1.json`, with API cases in the
API package. Each result preserves source identity and provenance. The table
records active coverage separately so fixture results cannot silently promote
readiness.

| Capability | Implemented correction path | Active evidence and outstanding work |
| --- | --- | --- |
| Application security | Python AST, JavaScript/TypeScript, diff and scanner evidence | Real SQLite-backed HTTP mini-app demonstrates vulnerable and corrected injection; broader language/runtime coverage remains partial |
| AI adversary testing | Direct/indirect injection and bounded tool-access observations | Seven real tool-gateway requests per profile demonstrate four scope denials after correction; provider resistance unvalidated |
| Compliance posture | Versioned SOC 2/CIS/NIST subset and stale/missing evidence handling | Evidence assessment only; no operating-effectiveness claim |
| Forensic collection | Hash, source identity, timestamps, custody and permissions | Disposable acquisition verifies hashes, identity, permissions and original preservation; native disk/memory tools require registered adapters |
| Malware triage | Bounded static binary and PowerShell decoding | Harmless synthetic byte analysis; submitted content never executed |
| Purple-team validation | Shared handoff and four result states; bounded Sigma/KQL execution | Actual service telemetry and alert counts; broader query engines require adapters |
| Adversary emulation | Allowlisted lateral laboratory paths | Permitted/denied paths, telemetry, failure/cancellation and restoration exercised |
| Cloud infrastructure | Terraform plan, rendered Kubernetes and provider configuration imports | Seeded configuration corrections; actual K3s NetworkPolicy enforcement now has a registered laboratory path; provider enforcement remains unvalidated |
| Supply chain and CI/CD | Lockfiles, SBOMs, Actions and pinned advisories | Seeded dependency/workflow corrections; actual build/runtime coverage pending |
| Secrets remediation | Redacted bounded Git history, identity correlation, exposure guidance | Actual ephemeral credential revocation returns 401 and a signed bundle verifies; service chain enumerates a real synthetic Git history; provider rotation remains unvalidated |
| REST/GraphQL security | Inventory/replay, owner/other/anonymous and rate-limit cases | Ten real HTTP checks per profile verify authorization and rate-limit corrections inside the strict isolated gate |
| Network segmentation | Policy, flow, DNS and expected/observed paths | Actual allowed/denied lateral path; K3s NetworkPolicy enforcement has a required laboratory path; native firewalls remain unvalidated |
| TLS, mTLS and JWT | Imported policy checks and ephemeral mTLS acceptance | Certificate trust/client failures and nine JWT requests with eight rejection cases exercised using ephemeral credentials; production services unvalidated |

## Integrated workflows

All six catalog definitions validate and execute offline. Leaked-credential
bundles support caller-owned Ed25519 signing and explicitly report unanchored key
trust. Missing reachability evidence cannot establish non-exploitability. The
IOC → hunt → containment laboratory performs real HTTP operations through the
existing ActionPlan authorization boundary and verifies resume/failure/cancel
cleanup. Five additional typed service chains bind resolved inputs and exact
loopback destinations to one-use ActionPlan approvals. They exercise credential
and consent revocation (200 before, 401 afterward), injection correction,
attack/benign telemetry measurement, and authentication checks. Their limits are
explicit: consent uses an application emulator, CVE reachability uses a pinned
synthetic advisory, detection uses registered lab-event rules, exposure uses
numeric loopback endpoints. The leaked-credential chain scans real synthetic Git
history. Kubernetes uses the isolated K3s adapter with real required/forbidden
pod connectivity, correlated audit and HTTP telemetry, and success/failure/cancel
restoration. Production Entra, Kubernetes,
SIEM, DNS, and provider integrations remain unvalidated.

## Evidence limits and completion rule

Synthetic Entra, Kubernetes audit, normalized Sysmon JSONL and binary EVTX datasets
have provenance, checksums, expected outcomes, and reset instructions. The pinned
EVTX adapter imports vulnerable, corrected and insufficient binary counterparts
in the strict gate. Native Windows acquisition remains unvalidated. Report exporters preserve
inconclusive statuses, redaction, and revision-bound anchors. Offline report
validation does not establish hosted posting or ingestion.

Complete this record only after focused checks, `make check`, `make check-docs`,
and `make check-laboratory` pass on the recorded implementation revision. Attach
explicit blockers for required native/platform, provider, acquisition, and
capability-specific laboratory checks; do not turn skipped checks into success.

## Raw forensic import correction scope

The raw import gate now consumes actual disposable acquisition output for both
disk and memory kinds. It requires digest and byte-count binding, denied-permission
and missing-custody rejection, tamper rejection, and successful restored-copy
verification. Native acquisition and filesystem/memory analysis remain incomplete.
The final integrated acceptance record must identify the tested revision and
commands; this scope entry alone is not execution evidence.

## Kubernetes containment correction scope

The strict composite gate now requires thirteen named cases: twelve in the
unprivileged service container and one isolated Kubernetes case. The latter must
exercise success, failure after policy application, and cancellation after
application. Required traffic stays available, forbidden traffic is blocked, and
cleanup restores both. Node inspection, definitive pod egress failures, correlated
HTTP logs and successful NetworkPolicy create/delete audit records are mandatory.
Missing images or incomplete cleanup fail the gate. See the
[Kubernetes runbook](KUBERNETES_LABORATORY.md) for the privileged host boundary.
The final check ledger must bind this scope to a clean tested revision.
