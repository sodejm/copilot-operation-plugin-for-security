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

The previous strict laboratory run passed all six cases using immutable image
`sha256:cf7d32ac327f8eb584f8d917f43c48ff5bf460019af889da93b33583bde62fd9`
and source snapshot
`cc6f418d7b248643ab2d002cb7cebdd7dc3427c29ae7d13ca26b036ff0c9eacd`.
It exercised offline playback, vulnerable and corrected services, workflow
success, partial failure, and cancellation. These digests identify that run,
not subsequent changes.

## Check ledger

| Check | Observed result | Remaining requirement |
| --- | --- | --- |
| Package and portable checks | 25 package gates passed during integration | Repeat on final revision |
| Root test suite | Passed during integration; platform-specific skips remain | Record final totals and platform limits |
| Documentation | Missing migration/acceptance links identified and corrected | Rerun `make check-docs` and full gate |
| Strict isolated laboratory | Six cases passed on the snapshot above | Repeat after service coverage changes |
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
| Application security | Python AST, JavaScript/TypeScript, diff and scanner evidence | Seeded source corrections; dynamic application lab coverage pending |
| AI adversary testing | Direct/indirect injection and bounded tool-access observations | Offline boundary cases; active tool gateway coverage pending; providers unvalidated |
| Compliance posture | Versioned SOC 2/CIS/NIST subset and stale/missing evidence handling | Evidence assessment only; no operating-effectiveness claim |
| Forensic collection | Hash, source identity, timestamps, custody and permissions | Offline import; disposable acquisition adapter coverage pending |
| Malware triage | Bounded static binary and PowerShell decoding | Harmless synthetic byte analysis; submitted content never executed |
| Purple-team validation | Shared handoff and four result states; bounded Sigma/KQL execution | Actual service telemetry and alert counts; broader query engines require adapters |
| Adversary emulation | Allowlisted lateral laboratory paths | Permitted/denied paths, telemetry, failure/cancellation and restoration exercised |
| Cloud infrastructure | Terraform plan, rendered Kubernetes and provider configuration imports | Seeded configuration corrections; actual cluster/provider enforcement pending |
| Supply chain and CI/CD | Lockfiles, SBOMs, Actions and pinned advisories | Seeded dependency/workflow corrections; actual build/runtime coverage pending |
| Secrets remediation | Redacted bounded Git history, identity correlation, exposure guidance | Actual ephemeral credential revocation returns 401; provider rotation unvalidated |
| REST/GraphQL security | Inventory/replay, owner/other/anonymous and rate-limit cases | Actual mini-app tests; strict isolated API gate integration pending |
| Network segmentation | Policy, flow, DNS and expected/observed paths | Actual allowed/denied lateral path; native firewall and Kubernetes enforcement pending |
| TLS, mTLS and JWT | Imported policy checks and ephemeral mTLS acceptance | Valid/missing/untrusted clients exercised; JWT signature and wrong-server trust cases pending |

## Integrated workflows

All six catalog definitions validate and execute offline. Leaked-credential
bundles support caller-owned Ed25519 signing and explicitly report unanchored key
trust. Missing reachability evidence cannot establish non-exploitability. The
IOC → hunt → containment laboratory performs real HTTP operations through the
existing ActionPlan authorization boundary and verifies resume/failure/cancel
cleanup. Kubernetes and illicit-consent fixture profiles currently model their
required active validation; they do not claim remediation occurred. Production
Entra, Kubernetes, SIEM, DNS, and provider integrations remain unvalidated.

## Evidence limits and completion rule

Synthetic Entra, Kubernetes audit, and normalized Sysmon JSONL datasets have
provenance, checksums, expected outcomes, and reset instructions. Normalized
Sysmon JSON is not raw EVTX; native EVTX acquisition remains unsupported until
the registered adapter is available and exercised. Report exporters preserve
inconclusive statuses, redaction, and revision-bound anchors. Offline report
validation does not establish hosted posting or ingestion.

Complete this record only after focused checks, `make check`, `make check-docs`,
and `make check-laboratory` pass on the recorded implementation revision. Attach
explicit blockers for required native/platform, provider, acquisition, and
capability-specific laboratory checks; do not turn skipped checks into success.
