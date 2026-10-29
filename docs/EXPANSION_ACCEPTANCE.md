# Expansion acceptance record

## Agent/MCP execution acceptance boundary

For the agent/MCP worker path, data-only inventory, evaluation, and package
validation are separate from execution evidence. Run `make check-ai-agent-acceptance`
and `make check` on the revision being qualified. Record the actual results,
including skips and blockers, instead of carrying a prior revision's pass forward.
Acceptance requires an approved exact plan and registered adapter, verified
worker isolation, independent effect observation, and verified cleanup. Preserve
distinct vulnerable-effect, negative-control, and remediated-case observations;
unsupported protocol features require explicit rejection evidence. Missing
observation or cleanup is inconclusive. Local disposable JSONL and MCP stdio
fixtures do not establish hosted, provider-backed, production, or independent
human-review coverage. Those gates require separate evidence.

The implemented offline and isolated-laboratory scopes passed the checks below.
Native worker/filesystem checks and production integrations have separate gaps;
they are not promoted by these results. An unavailable required check leaves its
capability incomplete.

## Tested revision and runtime

- Implementation revision: `04b01ed7240ceef29f343a026674c4d23d0d0b65`.
- Integration base: `50e6d96c144f9d81d52c99403e5ceae8815d3e16`.
- Acceptance date: 2026-10-23 UTC. This documentation-only refresh records the
  integrated provenance (`38e091b`), authorized transport (`cda3255`), bounded SQL
  fixture (`b55c68d`), TLS minimum policy (`19fa8df`) and review corrections.
  Additional review corrections cover artifact result completeness, consent
  evidence, workflow conditions and retries, bounded report anchors, cloud
  exclusions, TLS metadata, OpenAPI reconstruction, import/session provenance,
  replay allowlists and request budgets. All combined local gates passed on the
  implementation revision above; hosted checks separately validate the final PR
  revision containing this documentation-only refresh.
- Strict service image:
  `sha256:b8e6b1acd24b5803a2cc7ed8c911af40d518c2e9ef351ed915d6a4fdba317f3e`.
- Service source snapshot:
  `3b5c394cfbb7d5f4f256688dcf50779a857ed4b8de65b9a1c7df32655036c150`.
  The launcher verified this fresh snapshot against its source manifest.
- Portable host: macOS arm64, Python 3.14.8. Strict runtime: Linux arm64,
  Python 3.14.6, Git 2.47.3, pip 26.1.2, cryptography 50.0.2,
  python-evtx 0.8.1 and hexdump 3.3.

Changes are committed on dedicated, dependency-ordered branches and integrated
with the base above on `codex/expansion-delivery`. The linear delivery branch,
`codex/expansion-linear-delivery`, preserves all 52 bounded commits with origin
references and a separate integration-resolution commit. The initial implementation
tree at `77794c1` exactly matched reviewed integration revision `da8df21`; ten
subsequent bounded commits address PR #322 review and scanner regressions. The original branches
remain intact. The original API checkout
retains its branch and unfinished edits. PR #322 merged at `2ce127a58b9c7c544b3bb944992ca9dffe2d233d` after all
19 hosted checks passed on `f0bd977a433a2c8da3d9751236c7e471d16ee329`. The merged
tree matched the tested tree. Its automatic Pages deployment succeeded and the
published acceptance page returned HTTP 200 with the tested revision and fixture
markers. Postmerge repository CI subsequently exposed the startup race recorded
below; passing PR checks did not establish passing postmerge checks. Normal automatic documentation deployment after merge is
authorized. These results do not establish release or production validation.

## Commands and check ledger

Run these from the contributor environment described in
[CONTRIBUTING.md](../CONTRIBUTING.md). The Docker context used for this acceptance
was Colima; `TMPDIR` pointed to a disposable directory shared with its VM. Image
prerequisites must be provisioned before the strict gate, as described in the
[runtime instructions](../laboratories/service-runtime/README.md) and
[Kubernetes runbook](KUBERNETES_LABORATORY.md).

```sh
.venv/bin/python -m pytest -o addopts= -q -ra \
  tests/step_defs/test_portable_operator_workflow.py \
  tests/step_defs/test_web_api_inventory_replay.py \
  tests/test_artifact_assessments.py \
  tests/test_artifact_report_integrity.py \
  tests/test_boundary_query_safety.py \
  tests/test_cloud_corrections.py \
  tests/test_cloud_networkpolicy_exclusions.py \
  tests/test_consent_evidence.py \
  tests/test_cve_evidence_binding.py \
  tests/test_integrated_service_laboratory.py \
  tests/test_integrated_workflows.py \
  tests/test_network_policy_inputs.py \
  tests/test_openapi_operation_reconstruction.py \
  tests/test_purple_team_workflows.py \
  tests/test_report_anchor_bounds.py \
  tests/test_supply_chain_corrections.py \
  tests/test_tls_metadata_hostnames.py \
  tests/test_web_api_allowlist_validation.py \
  tests/test_web_api_import_limits.py \
  tests/test_web_api_import_safety.py \
  tests/test_web_api_import_session_bindings.py \
  tests/test_web_api_inventory_skill.py \
  tests/test_web_api_offline_budget.py \
  tests/test_web_api_preview_cli.py \
  tests/test_web_api_replay_transport.py \
  tests/test_workflow_idempotent_retries.py \
  tests/test_workflow_optional_signing.py \
  tests/test_workflow_resume_conditions.py \
  tests/test_workflow_runtime.py
make check PYTHON=.venv/bin/python
make check-docs PYTHON=.venv/bin/python
DOCKER_CONTEXT=colima make check-laboratory PYTHON=.venv/bin/python LABORATORY_ARGS='--runtime docker --image sha256:b8e6b1acd24b5803a2cc7ed8c911af40d518c2e9ef351ed915d6a4fdba317f3e --kubernetes-timeout 480'
```

| Check | Observed result | Scope or limitation |
| --- | --- | --- |
| Focused correction tests | 1037 passed, no skips; one expected TLS 1.1 deprecation warning | API transport/import/session/provenance, TLS, SQL/CVE evidence, report integrity, workflow guards/retries, cloud/network, signing and supply chain |
| `make check` | Passed, including all 25 package gates | Portable root suite includes 24 platform skips, detailed below |
| `make check-docs` | Passed; 58 pages verified | Documentation contract and local links |
| Strict `make check-laboratory` | Passed, 13/13 cases; no failures or blockers | Twelve service-container cases plus three Kubernetes lifecycle runs in one composite case |
| Held-out routing | 270/270 clear requests correct; 10/10 for each of 27 specialists | 100/100 ambiguous or negative requests clarified; published examples remain separate |
| Gitleaks 8.24.3 | Zero leaks across the 64-commit delivery history; ten positive/negative canaries passed | Narrow fixture exceptions retain detection of real private-key material |
| Hosted/native CI | PR #322: 19 checks passed on its exact head; postmerge repository CI failed twice | Startup observation race and bounded correction recorded below; correction requires its own exact-head hosted checks |
| Production/provider integrations | Not run | Separate live validation required before support claims |

The service image was rebuilt on October 19 from the current runtime Dockerfile
and pinned, hash-verified offline dependencies. The October 23 run reused that
immutable image with unchanged runtime sources. The launcher verified
the fresh source manifest and inspected the container configuration before use;
old evidence and marker files were not accepted as readiness evidence. The service
run nonce was `9a7bf86ad4f84c2588c3ce8dbd309616`; the Kubernetes run nonce was
`bd5eb876f6a86957b014e1e156d4916d`, with observed audit activity from
2026-10-23T14:07:19.752894Z through 2026-10-23T14:09:14.318687Z. The launcher verified removal
of the service container; Kubernetes cleanup verified namespace removal for all
three lifecycle cases, node removal and removal of both owned image tags.

Transport regressions exercise numeric-address DNS pinning, original-host TLS
verification (valid, wrong-host and untrusted certificates), TLS 1.2 minimum
without weakening stricter caller settings, rejection of a mutated TLS context
before DNS, redirect policy and credential removal, aggregate deadlines, HTTP
error responses and real signed,
persisted, single-use approvals. Request, session, destination and budget changes
cannot reuse an approval bound to the frozen transport plan.

Review regression coverage now includes complete artifact collections and unique
occurrence IDs, clean consent evidence, explicit workflow skips and optional-output
guards, persisted planned-attempt recovery, and default non-idempotent actions.
Report anchors enforce a byte limit before reading immutable Git blobs. Cloud
exclusions and unsupported TLS metadata stay indeterminate. Replay validates every
allowlist entry and rejects an oversized offline request batch before any send.
Imports enforce an 8 MiB budget before parsing, retain all merged source
provenance, namespace duplicate source/session identities and preserve the
authentication mechanism attached to each request. HAR, Postman and raw requests
preserve their source scheme. OpenAPI imports validate the declared version and
merge shared path parameters with operation overrides, rejecting unsupported
references. Opaque request/response payloads serialize as digests while approved
wire payloads remain intact. Conditional GCP bindings remain indeterminate, Actions
trigger detection respects the top-level event declaration, and compliance inputs
exceeding 1,000 controls fail before evaluation. Kubernetes regressions retain the
upstream default: omitted policy types include Egress only for nonempty egress
rules; an explicit Egress type isolates even with an empty rule list.

The portable suite also covers threshold boundaries and conflicting artifacts,
classifier redaction/timeouts/unavailability, preview side-effect exclusion,
workflow type/graph validation, plan-bound approvals, scope and budget rejection,
tampered outputs, restart/cancellation/retries, duplicate-write prevention and
cleanup. Report checks validate the bundled official SARIF 2.1.0 schema and
GitHub subset, JUnit escaping and inconclusive statuses, revision-bound Markdown
anchors, redaction, portable assets, host manifests and generated marketplaces.

## Postmerge sandbox correction

Implementation revision `97b691d9c7cc0e65d9bdca077a3165ba5d1c99c9` is based on
merged revision `2ce127a58b9c7c544b3bb944992ca9dffe2d233d`, on the separate branch
`codex/offline-sandbox-readiness`. Postmerge repository workflow run `39971066876`
failed twice with a transient setup socket observed after bubblewrap published
its child PID but before it reached its execution gate. The correction waits for
the child's one-byte read on the exact parent-owned gate pipe before taking one
isolation measurement. A socket remaining at that gate, a changed isolation
digest, unavailable procfs or an unsupported syscall ABI still fails closed.

The regression failed against the original implementation by observing the setup
socket. The corrected implementation passed these October 23 checks:

| Check | Observed result | Scope or limitation |
| --- | --- | --- |
| Focused macOS tests | 28 passed, four Linux procfs tests skipped | ABI/procfs rejection, sandbox and offline approval behavior |
| Focused Linux tests | 40 passed, no skips | Real bubblewrap plus delayed setup, persistent socket rejection, wrong pipe and wrong descriptor regressions |
| `make check` | Passed; all 25 package gates | Initial sandboxed attempt could not bind existing loopback fixtures; unchanged command passed with required host access |
| `make check-docs` | Passed; 58 pages verified | Rerun after this acceptance update |
| Strict `make check-laboratory` | 13/13 passed; no failures or blockers | Fresh source snapshot, actual activity, telemetry and verified cleanup |
| Correction hosted checks | Pending at this documentation commit | The correction PR records exact-head checks, merge and resulting deployment separately |

Linux ran all four files below. The macOS command omitted
`tests/integration/test_linux_bubblewrap_sandbox.py`; its four skips were the
Linux-only procfs cases:

```sh
.venv/bin/python -m pytest -q -p no:cacheprovider -o addopts= \
  tests/integration/test_linux_bubblewrap_sandbox.py \
  tests/integration/test_offline_sandbox_gate.py \
  tests/test_execution_sandbox.py tests/test_offline_research.py
make check PYTHON=.venv/bin/python
make check-docs PYTHON=.venv/bin/python
DOCKER_CONTEXT=colima make check-laboratory PYTHON=.venv/bin/python LABORATORY_ARGS='--runtime docker --image sha256:b8e6b1acd24b5803a2cc7ed8c911af40d518c2e9ef351ed915d6a4fdba317f3e --kubernetes-timeout 480'
```

The contributor Python 3.14.8 environment was reused from the linear delivery
worktree. Linux focused validation used a disposable Ubuntu 24.04 container with
bubblewrap and its official AppArmor user-namespace profile; both container and
temporary profile were removed afterward. No host-wide user-namespace restriction
was disabled. The isolated laboratory reused the unchanged immutable runtime image
with fresh verified source snapshot
`d1a36fd61fbbd747f91af53b8ea713dcc6a96eb6a568aa6de212206e025f7775`.
Service nonce `ec87f08931474e989422592624e7d693` and Kubernetes nonce
`bfffd6025251bb1a1b1e0e52b4beccea` identify this run. Kubernetes audit activity spans
2026-10-23T15:30:34.043936Z through 2026-10-23T15:32:27.547738Z. Docker configuration
inspection verified network isolation and the source manifest; IPv4/IPv6 egress
was rejected. All thirteen cases below retained their expected outcomes. Cleanup
verified service-container removal, all three namespaces, the owned node and both
owned image tags. This laboratory result does not replace native hosted checks.

## Issue #245: disposable Linux acceptance reconciliation

Recorded 2026-10-24 UTC against [issue #245](https://github.com/sodejm/copilot-operation-plugin-for-security/issues/245).
The fresh evidence meets the functional acceptance criteria for the issue's
**local Linux first increment**. Delivery of the dependent fixture correction and
this record still requires exact-revision hosted checks and a verified merge.
This does not establish production readiness or support for other worker paths.

The restricted worker used source `624993bef1aebad4eeaf47d36e14046346f850b3`.
The separate writable test runner used base
`9d4ffcd6fea95ed030611574b49abe5f5bdfdd4f` plus patch SHA-256
`cb70fe5b33195813ffab16ed521933d222a0de4e0392855ee38119dc5f3d774b`,
corresponding to correction commit `163fe2806e001e324946eee1a919b7b6229275b2`.
The VM applied that patch; it did not contain the correction commit object.
Comparison of the worker runtime, action-plan schema and relevant isolation and
approval tests between the worker source and correction commit found no changes.
The correction changes scanner synchronization and TLS test fixtures, plus
contributor instructions; it does not change production execution behavior.

| Issue criterion | Source and automated coverage | Fresh acceptance evidence |
| --- | --- | --- |
| Pinned local corpus, provenance-bound result, no external network | [Offline profile enforcement](../cops/execution/offline_research.py), [profile and corpus tests](../tests/test_offline_research.py), and [Linux integration tests](../tests/integration/test_linux_bubblewrap_sandbox.py) | Real approved corpus read; 53 output bytes matched SHA-256 `bc32961010d54e8dbe25ca71891561dbd3b09a15205564a186e55fcc40de85c1`. Observed tool namespaces contained only loopback interfaces/routes and no socket descriptors. |
| Reject remote URLs, DNS/proxies, inherited channels, out-of-profile actions, missing/stale observations and substituted receipts | [Linux integration tests](../tests/integration/test_linux_bubblewrap_sandbox.py), [execution-gate tests](../tests/integration/test_offline_sandbox_gate.py), [missing procfs tests](../tests/test_execution_sandbox.py), [profile tests](../tests/test_offline_research.py), [receipt substitution scenarios](../tests/step_defs/test_offline_research_execution_steps.py), and required attestation fields in the [action-plan schema](../catalog/schemas/action-plan.schema.json) | All 12 Linux integration tests passed without skips, including real network/inherited-socket rejection and gate/digest failures. All 45 approval/profile/BDD tests passed without skips on the separate authority-capable test account. |
| A configuration flag alone cannot establish isolation | [Observed-state validation](../cops/execution/offline_research.py) and configuration-only rejection in [profile tests](../tests/test_offline_research.py) | The signed immutable plan bound the profile, corpus, worker/inventory and fresh isolation digest. Root observation outside the worker captured 12 process/namespace snapshots and six executable witnesses; the runtime's `independent_observer_attestation=false` was retained because external acceptance evidence is not an installed runtime supervisor. |
| Document supported hosts, authorization, evidence, limitations and recovery, using inert local examples | [Operator and security contract](OFFLINE_RESEARCH_EXECUTION.md), [authenticated execution](AUTHENTICATED_EXECUTION.md), [security model](SECURITY_MODEL.md), and [contributor runtime](contributing.md) | Documentation validation passed for 58 pages. Linux-only scope, fail-closed behavior, independent observation, cleanup and inert examples are documented; no external assessment coverage is claimed. |

Run `offline-20261024-0138` executed from `2026-10-24T01:36:33.275756Z`
through `01:36:36.964601Z`, with acceptance complete at `01:36:39.367154Z`.
It used the actual signer, trusted key, protected approval store/server and control
client, with exactly one durable consumption binding the request, authorization,
immutable plan, engagement, worker and local destination. The plan digest was
`9ea90c3bff6d8572da38203846ff859442668e637a2adab090b780054b72f3af`;
the approved isolation digest was
`ee10ed7c0e2cd8c7525eb4af0e629026ba5a02414cefee880f855a98e30fd4d0`,
observed at `01:36:29.520504Z` and rechecked at execution boundaries. The action
had no credentials or egress, a 30-second/4096-byte budget and a pinned local cat
executable. Protected approval and observer state remained inaccessible to the
worker. Root captured actual output and step evidence before deletion, verified
all seven cleanup-ledger targets absent while the private mount namespace still
existed, then verified no descendants, authority socket or remaining processes.

The disposable Ubuntu 24.04.5 arm64 VM used kernel 6.8.0-146, Python 3.12.3,
bubblewrap 0.9.0-1ubuntu0.3 and strace 6.8. Worker, approval authority and test
runner used distinct locked accounts. The worker retained `ProtectSystem=strict`,
`ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`,
`RestrictSUIDSGID=yes`, private state and inaccessible host mounts/Docker socket.
AppArmor and user-namespace restrictions remained enabled.

The exact test arguments below ran with `python` resolving to that VM's prepared
interpreter, `PYTHONPATH` bound to the tested checkout and `RESULTS` bound to a
private results directory. The readiness assertion was an operational VM harness,
not an additional installed product command.

```sh
python -m pytest -o addopts= -q -ra tests/integration/test_linux_bubblewrap_sandbox.py tests/integration/test_offline_sandbox_gate.py --junitxml="$RESULTS/linux-integration.xml"
python -m pytest -o addopts= -o cache_dir="$RESULTS/cache" -q -ra tests/test_offline_research.py tests/test_approval_control_boundary.py tests/step_defs/test_offline_research_execution_steps.py --junitxml="$RESULTS/approval.xml"
ruff check .
make check-docs PYTHON="$PYTHON"
PYTEST_ADDOPTS="--junitxml=$RESULTS/make-check.xml -ra" make check PYTHON="$PYTHON"
```

| Gate | Result | Qualification |
| --- | --- | --- |
| Restricted-worker readiness assertion | Exit 0 | Local bubblewrap readiness; external observer evidence is recorded separately. |
| Restricted-worker Linux integration | 12 passed, zero skips | Real isolation and execution-gate checks. |
| Restricted-worker approval/profile tests | 44 passed, one failed, zero skips | The authority fixture's SGID directory creation is blocked by unchanged `RestrictSUIDSGID=yes`; this is not reported as a passing worker check. |
| Separate-account approval/profile tests | 45 passed, zero skips | The test account can create the authority fixture; worker restrictions were preserved. |
| Separate-account Linux integration | 12 passed, zero skips | Writable Git runner isolated from worker, authority and observer state. |
| Separate-account `ruff check .` / `make check-docs` | Passed / 58 pages | Correction patch applied. |
| Separate-account `make check` | 4537 passed, 11 skipped, zero failures/errors | Windows junction/device, PowerShell/Evtx and offline supply-chain-installer skips do not establish those capabilities. No required #245 Linux integration or approval test was skipped. |

The dependent delivery checkout at correction commit `163fe2806e001e324946eee1a919b7b6229275b2`
plus this acceptance record was also checked on macOS with Python 3.14.8. Here
`PYTHON` identifies the prepared repository interpreter; the laboratory used the
local disposable Linux Docker VM and a private, Docker-shared `TMPDIR`.

```sh
"$PYTHON" -m pytest -o addopts= -q -ra tests/test_repository_context_reader.py tests/test_web_api_replay_transport.py tests/test_offline_research.py tests/test_execution_sandbox.py tests/test_approval_control_boundary.py tests/step_defs/test_offline_research_execution_steps.py
uv tool run ruff check .
make check-docs check-issue-coverage PYTHON="$PYTHON"
make check PYTHON="$PYTHON"
DOCKER_CONTEXT=colima make check-laboratory PYTHON="$PYTHON" LABORATORY_ARGS='--runtime docker --image sha256:b8e6b1acd24b5803a2cc7ed8c911af40d518c2e9ef351ed915d6a4fdba317f3e --kubernetes-timeout 480'
```

Focused tests passed: 158 passed, two platform skips (Windows device and Linux
socket authority), with one expected deprecated-TLS negative-test warning. Ruff,
issue coverage, documentation validation (58 pages) and the full `make check`
passed. The macOS baseline retained platform skips; the zero-skip Linux evidence
above supplies the required Linux integration and approval coverage.

The fresh strict laboratory gate passed all 13 cases with no failures or
blockers, including vulnerable, corrected and insufficient-evidence outcomes.
Its verified source manifest was
`4eda89bdb684affac04ecb5c2d7af91024473dcf9727d30fffc61ca905cfd778`;
service nonce `ba176aac6d914076a398c916d8e089c6` and Kubernetes nonce
`7a750d2e2eedbe6924480e2ac17f7656` identify the run. Container configuration,
loopback-only interfaces/routes and failed IPv4/IPv6 egress established isolation.
Actual service activity and Kubernetes API/audit telemetry were observed for
success, failure and cancellation. Cleanup verified container removal, namespace
and node removal and both owned image tags. This laboratory gate remains
separate from the offline-worker acceptance and hosted checks.

The private evidence bundle contains 149 artifacts, including approval/result
bindings, independent snapshots, executable witnesses, actual output, observed
cleanup, journals, source/patch identities, commands and JUnit results. Its
manifest SHA-256 is
`7f447e5ca427cf39ab40d0a7da7f5592c0bba5343d1c34e737ded16642c9bded`;
the exported Ed25519 public-key SHA-256 is
`da29535d3be8e7fa963f100c3b7193dd4c0fcdbbec594198ee02bf8b6939ed14`.
Host verification repeated at `2026-10-24T02:12:04.948145Z` checked every artifact's
size/hash, the signature and a tamper-negative case, approval/result/cleanup
bindings, single consumption and actual activity. Raw private operational paths,
credentials, approval database and signing material are not committed here.

The seal authenticates a post-run manifest under the exported key. The observer
is root in the same VM and controls its signing key and worker administration;
it is independent of the restricted worker account, not a separate administrator
trust domain. Root strace delayed exec/removal calls to capture witnesses; the
observations are sampled and intrusive, not continuous production enforcement.
A configured pre-execution SSH supervisor was not installed or validated. SSH,
Windows/macOS, production operation and the skipped repository capabilities remain
outside this local Linux closure claim. The previous service-laboratory result
above is a separate run, not evidence of current offline-worker acceptance.

## Fixture identities

The service manifest pins the Entra, Kubernetes, Sysmon, advisory and service
profiles, with provenance, expected outcomes and reset instructions. The binary
EVTX counterparts additionally have the following digests.

| Fixture | SHA-256 |
| --- | --- |
| `cops/laboratory/service_fixtures/manifest.json` | `a2fb5f80ffe97409f91653f4574052665ed992da597e25cb472b1547ef3a7803` |
| Vulnerable Sysmon EVTX | `4dbd6c4f96c5adae0e2c1df9847ab03a76131ecc60136c227d35f0fde8c1c245` |
| Corrected Sysmon EVTX | `74e3ba983be16a897f515c12744f9f155876ed06f4eeb52fa790507cf339b8d2` |
| Insufficient Sysmon EVTX | `5023fa444889f6a5d54c524f6507dfffe3677f076fb0640132c69ec6f8bd5ff9` |
| `tests/fixtures/artifact_assessment_cases_v1.json` | `d54de2657404483aa15350390a8a25ee38f46d46263c91590a42479471a88284` |
| `tests/fixtures/routing-held-out-v1.json` | `2a235734f9eb8bd0fcb4d07a83e4a901fd9a335004629d0b9f67c07ee76271c0` |

The three pinned Kubernetes prerequisites were:

```text
rancher/k3s@sha256:c20f2c044a28cf217440464a810fb81715a48192716a5bc99eaf2c3113a9cfb4
rancher/mirrored-pause@sha256:a433214620b407678934ebd69690a9ed6066247231eacfba181fab20dbc3dbf1
python:3.14.6-slim@sha256:34bf30c914ac17d2a0f7ecf94866e54380669d618ae4673672445516603ad8d7
```

## Isolated execution evidence

The gate inspected Docker `none` networking, loopback-only interfaces/routes,
read-only service-container configuration and definitive IPv4/IPv6 egress
rejection. It observed actual activity, captured telemetry, verified restored
state and stopped listeners, and removed owned containers. The K3s node runs
privileged inside the disposable VM and shares its kernel; this is not evidence
of a production worker under a distinct OS identity.

| Strict case | Observed correction or lifecycle evidence |
| --- | --- |
| `offline-playback` | Four fixtures, eight telemetry records and four alerts |
| `binary-evtx` | Vulnerable: two normalized records and both expected indicators; corrected: two records and neither indicator; insufficient: zero normalized records and `partial` status |
| `service-vulnerable` | Ten API checks expose authorization/rate-limit failures; injection exposes another object; zero scope denials among seven gateway requests; lateral path returns 200 |
| `service-corrected` | Ten API checks pass; injection cannot expose the other object; four scope denials; forbidden lateral path returns 403 |
| `workflow-success` | Three consumed authorizations, five TCP requests, six telemetry records, four alerts; restored and stopped |
| `workflow-failure` | Two authorizations, three requests, three telemetry records, one alert; partial failure with restoration and stopped services |
| `workflow-cancellation` | One authorization, two requests, two telemetry records, no alert; cancelled with restoration and stopped services |
| `integrated-leaked-credential-blast-radius` | Six authorized stages, actual Git-history scan, three HTTP requests, four telemetry records, two alerts; revoked credential and verified signed bundle |
| `integrated-cve-reachability-triage` | Four authorized stages; actual component invocation and one bound telemetry record; no TCP request or alert claimed |
| `integrated-illicit-consent-remediation` | Five authorized stages and five requests; seven telemetry records and one alert; exact synthetic grant revoked while unrelated access remains available |
| `integrated-detection-rule-ci-validation` | Four authorized stages and five requests; six telemetry records and two alerts with attack/benign measurements |
| `integrated-pre-release-exposure-audit` | Four authorized stages, real scoped DNS and five HTTP requests; seven telemetry records and one alert |
| `integrated-kubernetes-compromise-containment` | Success, failure and cancellation after real policy application; required traffic preserved, forbidden traffic blocked, correlated audit/HTTP evidence and baseline restored |

Both service profiles also verified two actual raw acquisition imports,
permission/custody/tampering rejection, original preservation, post-revocation
HTTP 401, and nine JWT requests with eight rejection cases. Each installed a
hash-pinned synthetic wheel offline, made two runtime requests, rejected a
tampered wheel and verified cleanup. Advisory evidence changed from `matched`
to `clear` with the corrected installed component. An empty inventory remained
unknown. Both profiles restored their baseline.

The vulnerable SQL runtime accepts one exact, reviewed injection seed and executes
a constant query for that seed. All other submitted values use bound SQLite
parameters; the corrected profile always uses parameters. The separate scanner
fixture retains explicit vulnerable/corrected source for static AST inspection
only. Descriptor hashes bind that fixture to the observed HTTP/SQLite outcome;
missing or inconsistent evidence remains inconclusive. Focused tests cover
arbitrary submitted input, both runtime outcomes and this evidence boundary.

All six integrated workflows have offline and isolated execution paths. Their
stages use typed prior outputs and exact, single-use ActionPlan approvals. The
IOC → hunt → containment example additionally exercises success, failure and
cancellation. CVE evidence binds a pinned synthetic advisory to component version,
source digest and observed invocation; absent reachability evidence never proves
non-exploitability. Consent uses an Entra-shaped application emulator. Exposure
uses actual DNS inside the isolated scope. These do not validate provider APIs.

## Readiness by capability

Offline families have vulnerable, corrected, benign and insufficient-evidence
cases in the assessment fixture; the API package has its own role/rate-limit
cases. Source identity, provenance and verification status survive reporting.
“Validated” below applies only to the stated scope. Packages remain experimental.

| Capability | Validated scope | Incomplete or unsupported scope |
| --- | --- | --- |
| Application security | Python AST, JavaScript/TypeScript, diff/scanner evidence; actual SQLite-backed HTTP injection and authorization corrections | Other languages/runtimes and production applications |
| AI adversary testing | Direct/indirect injection fixtures and seven actual tool-gateway requests per profile; corrected tool/scope boundaries | Provider-specific model resistance requires live evidence |
| Compliance posture | Versioned SOC 2/CIS/NIST subsets; missing or stale evidence cannot pass | Full-framework coverage and operating effectiveness |
| Forensic collection | Raw disk/memory copies with source/hash/time/custody/permission binding; disposable acquisition and unchanged originals | Native acquisition, E01/AFF4 and filesystem/memory interpretation require separate adapters |
| Malware triage | Bounded static binary inspection and safe PowerShell decoding of harmless synthetic samples | Unsupported binary formats or deep analysis; submitted content is never executed |
| Purple-team validation | All four outcomes, correlated captured telemetry/alerts, and generated Sigma/KQL subset execution against attack/benign events | Broader query engines and production SIEM ingestion |
| Adversary emulation | Allowlisted real lateral paths and cleanup after success, failure and cancellation | Other techniques, targets and production engagement |
| Cloud infrastructure | Typed Terraform, Kubernetes and AWS/Azure/GCP exports; actual K3s NetworkPolicy application and restoration | Provider enforcement and incomplete configuration exports |
| Supply chain and CI/CD | Lockfiles, SBOMs, Actions and pinned advisories; actual offline wheel installation, runtime correction and hash rejection | Arbitrary package builds, registry behavior and hosted CI integration |
| Secrets remediation | Redacted bounded Git history, identity/exposure assessment and actual ephemeral revocation returning 401; caller-signed evidence bundle | Provider validity/rotation and external signing-key trust |
| REST/GraphQL security | Lossless import provenance and redacted reports; approved frozen transport with DNS/TLS/redirect/deadline checks; ten actual HTTP checks per profile across owner, other-user, anonymous and rate-limit cases | Production targets and unsupported API semantics |
| Network segmentation | Typed firewall/NetworkPolicy/flow/DNS evidence; real allowed/denied service and pod connectivity | Native firewall enforcement and unobserved networks |
| TLS, mTLS and JWT | Typed chain/RS256 verification, ephemeral certificate/client acceptance and nine actual JWT requests | Production trust, revocation services and unsupported algorithms |

## Platform gaps and completion rule

The original macOS portable run skipped 24 platform-dependent tests; the sandbox
correction adds four Linux-only procfs regressions, for 28 skips in its portable
run. Linux-specific
production approval sockets, `/proc` descriptor protections and bubblewrap worker
isolation require the retained native Linux jobs. Windows device/junction handling
and PowerShell assessment require the retained Windows jobs. Linux-only EVTX
parsing was exercised by the strict Linux gate; that does not validate native
Windows acquisition. No skipped check is counted as a pass.

The existing CI matrix retains Linux bubblewrap, Windows filesystem/PowerShell,
multi-version portable and isolated laboratory jobs. Results for the exact final
pushed revision must be verified on the pull request before merge. Until then,
the unavailable platform checks above remain incomplete. Production/provider and
native acquisition validation remain incomplete regardless of synthetic CI
results. Exported reports are review artifacts; hosted posting and production
integration remain separate transitions.

After a behavioral change, rerun the relevant corrections and all required gates
against its new revision and source snapshot. Documentation-only changes require
the documentation gate. Retain limitations and inconclusive states when reusing
this evidence; do not infer broader readiness from a passing synthetic fixture.


## Native Windows service DACL follow-up

Issue #107's first remaining collection gap is addressed by a local read-only
SCM DACL probe and a separate disposable-service correction fixture. The source
mapping now covers `s01-122` directly. The required Windows gate reads actual
vulnerable, corrected, denied and missing service descriptors, checks ambiguous
ACE handling, broad-owner implicit write-DACL rights and OWNER RIGHTS
suppression. It observes deletion after success, controlled failure, and injected
status-query failures while preserving the original and cleanup errors.

Acceptance requires the exact candidate revision's Windows CI result; a macOS
skip is not a pass. Run-key ACLs, Credential Manager, scheduled-task source mapping
and cross-identity privilege canaries remain incomplete. This change does not
promote the overall capability or native Windows forensic acquisition readiness.
The delivery record must retain the tested revision, focused checks, portable,
documentation and laboratory checks, and hosted Windows evidence separately.

## Restricted worker authority fixtures (#327)

The original worker failure is reproducible at revision
`6848fd97a7620fae74566c0afb3d50ff35fb911d`: the positive listener test tries to
create an SGID directory under `RestrictSUIDSGID=yes` and receives `EPERM`.
The disposable Linux worker ran as UID 996/GID 990 with `NoNewPrivileges=yes`,
`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, inaccessible host
mounts and Docker socket, and writes limited to its private home. The failed
service invocation was `2ef9ac8abfd4467396a12cc9626590c4`. This is a fixture
ownership failure; relaxing the worker is not the correction.

The positive SGID listener fixture now belongs to the authority test role.
Worker protocol and negative-boundary tests retain their assertions and share
the same signed, persisted approval setup. The
[fixture ownership guide](../tests/authority/README.md) defines the separate
provisioner, authority and worker commands. Its cross-account acceptance probe
creates a fresh random signing key and database under authority-only ownership,
then uses the restricted worker's actual UID/GID/PID for socket authentication.
It checks protected-state denial, rejected SGID creation, wrong PID/plan/identity,
single-use consumption, socket non-inheritance and cleanup. No production
authorization code, worker service configuration or laboratory image changed.

Revision `d978f874b0abb3f0ff76ecc7999cf36eedd4b450` passed the following
checks on disposable Ubuntu 24.04.5 aarch64, Linux `6.8.0-146-generic`, Python
3.12.3, bubblewrap 0.9.0 and Ruff 0.17.2. The source archive was read-only for
worker checks; the repository gates used a separate writable Git checkout owned
by the test account. `PYTHON` below identifies the prepared repository interpreter.

| Role and command | Result |
| --- | --- |
| Restricted worker: `"$PYTHON" -m pytest -o addopts= -p no:cacheprovider -q -ra tests/test_offline_research.py tests/test_approval_control_boundary.py tests/step_defs/test_offline_research_execution_steps.py tests/integration/test_linux_bubblewrap_sandbox.py tests/integration/test_offline_sandbox_gate.py` | 56 passed, 0 failures/errors/skips; includes all 12 Linux isolation/gate checks |
| Authority: `"$PYTHON" -m pytest -o addopts= -p no:cacheprovider -q -ra tests/authority/test_approval_listener.py` | 1 passed, 0 failures/errors/skips |
| Provisioner: `sudo env PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -m tests.authority.check_role_separation` | Exit 0; real cross-account consumption, all denials, non-inheritance and cleanup verified |
| Restricted worker: existing readiness assertion, bound to this source revision | Exit 0; actual bubblewrap execution, separate network namespace, loopback only, no routes or socket descriptors, workspace removed |
| Writable Git test runner: `make check PYTHON="$PYTHON"` with `PYTEST_ADDOPTS="--junitxml=$RESULTS/make-check.xml -ra"` | Exit 0; all COPS checks passed; pytest 4,546 passed, 12 skipped, 0 failures/errors (4,558 collected) |
| Writable Git test runner: `make check-docs PYTHON="$PYTHON"` | Exit 0; 58 documentation pages verified |
| Writable Git test runner: `ruff check .` | Exit 0 |

The restricted-worker service invocation was
`37d51ba73152474285b3bc93b3bed76b`. The cross-account probe invocation was
`976af6adbeb849afba73dc3401437c09`: worker UID 996/GID 990/PID 232145,
authority UID 994/GID 988, five requests and exactly one persisted consumption.
It rejected wrong PID, plan, identity and replay, denied signing-key/database
access and control-directory mutation, and removed the socket and temporary
fixtures. The persistent worker service configuration SHA-256 remained
`f3709bfca860dc882b505c27819b0b9c0117857df34e0d1f798d38714077d516`.
Its `RestrictSUIDSGID`, `NoNewPrivileges`, filesystem protections and narrow
write allowlist were unchanged. The readiness assertion also observed UID/GID
996/990, no supplementary groups, zero effective capabilities, and no host
home or Docker socket access. It did not assert a new independent-observer
attestation; that evidence belongs to the separate #245 increment.

The full-suite skips are outside #327's required Linux checks. They remain
incomplete capabilities, not passes:

- `test_soc_investigation`: two vendor-junction and two dangling-junction cases
  require native NTFS; `test_windows_device_input_is_rejected_without_blocking`
  requires Windows device handles.
- `test_supply_chain_laboratory_steps`: vulnerable and corrected installed-package
  cases require the registered offline installer/supported platform.
- `test_adapter_execution::test_prepare_executable_fails_closed_without_linux_proc`
  exercises the unsupported-platform boundary and skips on Linux.
- `test_evtx_import::test_binary_correction_and_provenance` requires optional
  `Evtx`, absent from this runner.
- `test_host_windows_assessment::test_native_path_validator_rejects_unc_before_probe_runtime`
  and `test_host_windows_service_acl::test_native_service_dacl_correction_and_cleanup`
  require PowerShell/native Windows.
- `test_repository_context_reader::test_windows_nul_is_rejected_before_read`
  requires Windows device handles.

These are local Linux validation results. Hosted checks and merge/deployment
results must be verified on the delivered revision separately. No laboratory
image rebuild is required for this test/documentation-only change. Production
supervision (#328), independent production observation and deployed-environment
validation (#331) remain separate follow-ups; #327 does not establish production
readiness or authorize a release.

## Issue 100 worker integration

The earlier expansion results in this document do not qualify the subsequent
Issue #100 isolated-worker integration. Its criterion-by-criterion evidence and
remaining closure gates are tracked in the [worker qualification contract](../specs/issue-100-worker-qualification.md).
Record results against the actual integrated revision before claiming completion.
