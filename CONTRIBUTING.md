# Contributing

Thank you for improving this project.

API import changes must preserve exact source hashes and keep report redaction
separate from lossless approval digests. Run
`python -m pytest tests/test_web_api_import_safety.py`, then synchronize and check
the package runtime with `scripts/sync_web_api_runtime.py` and `--check`.
Retain source identity, malformed-input, credential and origin regression cases.
Transport changes also require `tests/test_web_api_replay_transport.py` and the
package `tests/test_authorized_assessment.py`: use actual loopback services and
signed, persisted one-use approvals. Cover DNS and redirect scope changes,
credential/plan drift, caller-input mutation during approval, TLS trust and hostname
verification, cross-origin bodies, deadlines, header framing, and observed HTTP
error statuses.

Run `make check-web-api-acceptance` for the complete local-service authorization
suite; `make check` requires this gate too. Unlike the standard-library offline
package check, this development gate uses the declared pytest dependencies and
starts disposable loopback listeners. All required cases must execute without
skips. An unavailable listener or prerequisite is a failed gate, not acceptance.
Pass `PYTHON=.venv/bin/python` to select the prepared interpreter. A passing
result proves neither OS/network isolation nor production-provider readiness.
Response-model changes must preserve derived GraphQL access observations through
digest-only serialization without retaining raw payloads; old digest-only records
without those observations remain inconclusive.

WebSocket transport changes also require `tests/test_web_api_websocket.py` and
the package's `test_authorized_websocket.py`. Preserve the distinct version 1
WebSocket operation and existing HTTP version 2 budget digest. Cover malformed
upgrades and frames, both-direction frame/byte limits before allocation, actual
TLS trust/hostname rejection, control floods, cancellation during DNS/TLS/reads,
partial evidence, socket/thread cleanup and recovery with a fresh authorization.
The mandatory local-service gate requires both vulnerable/corrected role profiles.
Keep standard-library offline cases in the package's `test_workbench*.py` family;
its offline validator must not import pytest-only `test_authorized*.py` modules.
Those real-service cases remain mandatory in the separate development gate.

1. Read `AGENTS.md`, whether contributing manually or with an AI assistant.
2. Open or reference a focused issue when the project uses issue tracking.
3. Work on a short-lived branch; do not mix unrelated changes.
4. Set up local push protections with `make setup-hooks`.
5. Add behavior-first tests and update relevant documentation for the issue being worked.
6. Run `make check` and `make check-issue-coverage`.
7. Open a pull request using the supplied template and include exact evidence.

Never include secrets, personal data, proprietary prompts, or confidential logs.
AI assistance does not change contributor responsibility: review all generated
content and ensure licensing, correctness, security, and attribution are sound.

## Plugin verification and maturity

Every catalog package must include `docs/VERIFICATION.md`, linked from its README
and the [verification index](docs/plugin-verification.md). Keep its end-to-end
exercise, acceptance criteria, negative cases, cleanup, and host installation steps
current when changing behavior, dependencies, adapters, or workflow instructions.

Follow the shared maturity gates and [record template](docs/templates/PLUGIN_VERIFICATION_RECORD.md).
A demo pass is one step in qualification. After independent review, update the
manifest's maturity and all public labels together; retain the tested revision,
scope, limitations, and evidence links. Support flags and capability modes have
their own evidence requirements.

## Evidence connector contributions

Use the [Shared Evidence SDK guide](docs/EVIDENCE_SDK.md#add-a-connector) and
[specification](specs/shared-evidence-sdk.spec.md) when adding acquisition tooling.
Reuse the bounded runner and checkpoint contract, project only reviewed fields,
and test interruption/resume and failure behavior with synthetic fixtures. A new
adapter needs explicit permission and scope documentation; offline tests do not
establish live service support. Portable packages must declare and distribute a
compatible dependency before importing the root SDK.

## Prepare the test environment

Contributor checks require Python 3.11 or newer. From the repository root, create
a virtual environment and explicitly install the test dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
make check-prerequisites
make check
make setup-hooks
```

`make setup-hooks` installs a local Git pre-push hook (`.git/hooks/pre-push`) that
blocks accidental direct pushes to `main`, prevents secret exposure, and ensures
that documentation and test cases have been updated for the issue being worked.
You can run the issue coverage check on demand with `make check-issue-coverage`.
If an administrative or typo change requires an exemption, include
`[skip-docs: <rationale>]` or `[skip-tests: <rationale>]` in the commit message.


On Windows, activate `.venv\Scripts\Activate.ps1` in PowerShell. If Make is not
available, run `python scripts/agent/check_prerequisites.py` for verification alone
or `python scripts/agent/check.py` for the full gate.

Make defaults to `python3` on the active PATH. To select an interpreter explicitly,
use `make check PYTHON=.venv/bin/python` (or `make check-prerequisites` with the same
override). The preflight reports its executable and whether it is in a virtual
environment. A prepared interpreter outside a virtual environment is also
accepted, as in CI. Every Make target uses the selected interpreter.

Both full-gate entry points stop before repository checks when Python is too old,
a dependency is missing or cannot be imported, or an installed version is
incompatible. Verification is offline, never runs pip, and never installs or
upgrades packages. Installation is a separate command under your control.

Report conformance is mandatory in `make check`. The official SARIF 2.1.0 schema
is bundled unchanged and verified by SHA-256; the declared `jsonschema` dependency
validates exports offline. No external schema path is needed. See the
[report export guide](docs/REPORT_EXPORTS.md) for the focused check.

`requirements.txt` is the canonical declaration for local setup and all CI test
jobs. Each non-comment line contains a distribution name with an optional numeric
`>=` minimum version. The verifier checks stable numeric releases, including post
releases, and imports the name with hyphens replaced by underscores. Unsupported
declaration syntax, duplicate names, and prerelease or development versions fail
explicitly. Extend the verifier and its tests before introducing other requirement
formats or dependencies with different import names. This file sets minimum
versions; it is not a lockfile.

Native service DACL changes also require the real Windows SCM correction gate:

```powershell
python -m pytest tests/test_host_windows_service_acl.py -q
```

Run it with PowerShell 7 and service-creation permission on an authorized
disposable Windows runner. A non-Windows skip is not native acceptance. The test
creates only stopped, randomly named owned services and verifies cleanup after
success, controlled failure, and injected status-query failures. Semantic cases
cover broad owners, OWNER RIGHTS suppression, and missing owner evidence. Keep the broader Windows capability partial until
its remaining collection and privilege-boundary evidence exists.

## Offline setup

On a connected machine with the same operating system, architecture, and Python
version as the offline machine, prepare dependencies from the same declaration:

```bash
python -m pip download --dest wheelhouse -r requirements.txt
```

Transfer `wheelhouse` and the matching `requirements.txt` to the offline machine.
After creating and activating its virtual environment, install from local files:

```bash
python -m pip install --no-index --find-links wheelhouse -r requirements.txt
make check-prerequisites
make check
```

The download includes transitive dependencies. Prepare the artifacts before
disconnecting; the verification gate does not fetch missing dependencies.

## Troubleshooting prerequisites

- **Missing or incompatible dependency:** activate the intended environment and
  run `python -m pip install -r requirements.txt`, or use the offline command above.
- **Unexpected interpreter:** compare the executable printed by the preflight
  with your environment, then select it with Make's `PYTHON` override. The direct
  Python entry point uses the interpreter that launches it.
- **Unsupported Python:** recreate the environment with Python 3.11 or newer.
- **Import failure:** recreate the environment and reinstall from the declaration;
  installed metadata alone does not prove a usable dependency.
- **Invalid requirement declaration:** correct `requirements.txt` or extend the
  supported declaration format and regression tests together.

CI installs `requirements.txt` explicitly before verifying prerequisites and
running tests. A passing local gate does not establish hosted CI status.

## Plugin run economics

Use the [plugin-run-cost contributor skill](.agents/skills/plugin-run-cost/SKILL.md)
for local execution accounting and input-based forecasts. It reuses session audit
request normalization. Keep private ledgers outside Git, and keep development costs
separate from plugin executions. Synthetic examples are not production benchmarks.

### EVTX correction evidence

For shared laboratory HTTP changes, run
`python -m pytest tests/test_laboratory_http_client.py tests/test_service_laboratory.py tests/test_integrated_service_laboratory.py`.
Verify destination rejection, proxy and redirect refusal, bounded responses, and
actual service correction outcomes before the full repository and laboratory gates.

Run `python -m pytest tests/test_evtx_import.py tests/test_check_laboratory.py`
after importer changes. `python scripts/build_evtx_fixtures.py` regenerates the
three synthetic binary counterparts; update their manifest checksums only after
reviewing the intended fixture change. Portable tests cover framing and worker
boundaries. The required Linux laboratory gate parses every counterpart with the
pinned parser and cannot skip a missing prerequisite. See
[the runtime recipe](laboratories/service-runtime/README.md).

### Forensic import correction evidence

Run `python -m pytest tests/test_forensic_import.py tests/test_acquisition.py`
for raw import and acquisition changes. Include source replacement during reads,
symlink ancestors, special files, malformed custody, missing permission, bounded
streaming, and unchanged originals. Then run `make check`, `make check-docs`, and
`make check-laboratory` with the pinned isolated runtime. The gate imports the
actual acquired copy and checks rejection and restoration; fabricated receipt
records cannot replace this playback.

### Credential pattern correction evidence

Use only synthetic values when extending Git-history patterns. Run
`python -m pytest tests/test_git_history_scanner.py` for historical exposure,
corrected history, insufficient bounds, benign lookalikes, redaction and unchanged
source bytes. Retain existing synthetic fingerprints so the actual laboratory
revocation exercise correlates the same credential. Synchronize portable runtimes
and run the repository, documentation and laboratory gates.

### Hosted secret scanner exceptions

The hosted GitLeaks gate retains all built-in rules through `.gitleaks.toml`.
Exceptions require both the exact reviewed source match and its repository path:
the signer type annotation, the synthetic replay Basic credential, and the
historical Python PEM generator expression. The latter can make GitLeaks consume
source through the next public-key marker; the exception rejects intervening PEM
headers. These exceptions do not allowlist files or commits. A supplemental PEM-body rule
also detects actual keys independently: the built-in rule can overrun malformed
fixtures and miss a neighboring key before any repository exception is applied.

Before changing an exception, reproduce the finding with the hosted GitLeaks
version and scan the full delivery history. Verify that a newly generated disposable
private key in the same file, a key embedded in the overrun region, a different
credential in each affected file, and the same fixture in another file still fail
the gate. Never commit or print generated private key canaries.

### Kubernetes correction evidence

Run `python -m pytest tests/test_kubernetes_laboratory.py tests/test_check_laboratory.py`
after changes to the cluster adapter or composite gate. Keep malformed isolation,
missing telemetry, namespace replacement and incomplete case-list regressions.
Then run all three repository gates with the preprovisioned image pins in
[the Kubernetes runbook](docs/KUBERNETES_LABORATORY.md). Actual pod connectivity,
audit records and cleanup are required; mocked policy results are insufficient.

### CVE correction evidence

Run `python -m pytest tests/test_cve_evidence_binding.py tests/test_integrated_workflows.py tests/test_integrated_service_laboratory.py`.
Keep exact component and malformed inventory regressions, missing invocation
evidence, unbound controls, and vulnerable/corrected real HTTP cases. A source
change requires reviewing and repinning the synthetic advisory fixtures. Then
run the portable, documentation and strict laboratory gates.

### Consent correction evidence

Run `python -m pytest tests/test_consent_evidence.py tests/test_integrated_workflows.py tests/test_integrated_service_laboratory.py`.
Retain missing, stale, conflicting and cross-tenant cases, principal-specific
correlation, corrected risk assertions, and mismatched grant rejection. Actual
HTTP acceptance must show target access changing from 200 to 401 while unrelated
access stays 200. Run portable, documentation and strict laboratory gates.

### Exposure correction evidence

Run `python -m pytest tests/test_exposure_evidence.py tests/test_exposure_dns.py tests/test_integrated_workflows.py tests/test_integrated_service_laboratory.py`.
Retain wrong endpoint/address, stale, duplicate, incomplete and redirect cases.
DNS tests must reject malformed responses, timeouts and address changes while
proving early-failure cleanup. Actual laboratory evidence must show a DNS exchange
and anonymous HTTP 200 → 401 with authorized access preserved. Run `make check`,
`make check-docs` and `make check-laboratory` before claiming acceptance.

### Supply-chain installation correction evidence

Run `python -m pytest tests/test_supply_chain_laboratory.py tests/step_defs/test_supply_chain_laboratory_steps.py tests/test_service_laboratory.py`.
Retain deterministic wheel hashes, installed-source verification, real vulnerable
and corrected HTTP responses, hash-rejection and insufficient-evidence cases.
Timeout, output-limit and cancellation tests must reap actual workers and remove
partial installations. Run `make check`, `make check-docs` and the strict isolated
`make check-laboratory` gate with the registered installer version before claiming
laboratory acceptance.
