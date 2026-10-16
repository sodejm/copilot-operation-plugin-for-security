# Service validation playbook

Service entry-point validation starts from a discovery record whose probe,
endpoint, scope, and protocol evidence have already been reconciled. Preparing a
handoff remains offline. Execution occurs only after an operator selects one
exact action and supplies a fresh budget attempt and an approval receipt bound to
the exact plan, endpoint, and action.

The current executable provider is a disposable loopback laboratory fixture used
by the acceptance suite. COPS does not register a native provider for external
targets. If either a provider or an independent evidence verifier is absent, the
dispatcher returns `provider_unavailable` before reserving a budget, requesting
approval, or opening a connection.

## Routed service families

The discovery boundary conservatively routes independently observed protocols to
the following specialist skills. A route identifies who can assess the service;
it does not prove a service, vulnerability, or successful use.

| Observed service | Specialist skill | Current executable evidence |
| --- | --- | --- |
| HTTP | `web-api-inventory-and-replay` | `GET /health` and an HTTP status line in the loopback acceptance lab |
| SSH | `network-remote-and-file-services` | SSH identification-string exchange in the loopback acceptance lab |
| Redis | `network-data-services` | Redis `PING`; separately authorized proof also uses `ECHO authorized-use` |
| SMTP | `network-messaging-services` | SMTP greeting plus `EHLO` response in the loopback acceptance lab |
| Docker API | `network-developer-interfaces` | Docker Engine `GET /version` and JSON API version in the loopback acceptance lab |
| DNS | `network-infrastructure-services` | Length-prefixed DNS-over-TCP query and response in the loopback acceptance lab |
| SOCKS | `network-legacy-and-proxy-services` | SOCKS5 method negotiation in the loopback acceptance lab |

These seven adapters are registered only by the disposable laboratory. They
exercise the public selection, authorization, dispatcher, verifier, budget,
reporting, and cleanup boundaries without claiming production coverage for an
external target. The provider opens one loopback connection, and the verifier
reads the fixture-owned passive audit after the server closes that connection.
Even discovery requests and server greetings require a fixture-issued one-use
audit reference before the fixture responds; an unaudited connection receives no
service response.
The verifier disregards provider-authored output. Here, "independent
evidence" means independent of provider-authored output only. The fixture and
verifier share one Python process, administrative authority, and parser, so this
laboratory does not establish independently administered observation or native
protocol support.

Unknown responses, port-only guesses, endpoints outside the validated scope, and
evidence without matching active-probe provenance produce no execution plan.

## Evidence and proof gates

Low-impact validation requires the verifier to read a fixture-owned passive audit
record that binds the approval receipt, plan, attempt, endpoint, selected action,
evidence digest, random dispatch correlation identifier, opaque one-use audit
reference, and observation time within the dispatch interval. The provider returns
only the opaque audit reference; provider-authored evidence claims do not satisfy
this gate. The verifier waits for the exact issued audit reference up to the bounded
transaction deadline; a missing closure audit still produces `dispatch_uncertain`.
The result records
protocol evidence plus all five assessment dimensions: exposure, authentication,
configuration, version, and trust. Complete evidence may establish an observed
exposure or a versioned candidate; it cannot establish a verified finding or
successful authorized use.

The owner-controlled ledger consumes the one-use approval receipt when dispatch is
durably recorded. A successful low-impact candidate produces a durable prerequisite
receipt. Controlled proof requires a fresh approval receipt and atomically consumes
the exact prerequisite receipt bound to the candidate plan, endpoint, source
action, evidence digest, trusted issue `#143` reproduction digest, affected
version, and candidate-verification state. A finding becomes verified only when
the fixture-owned audit records the reproduction's exact expected effect and
cleanup evidence.
Receipt uniqueness in the SQLite ledger is limited to that database. The injected
authorization authority must reject receipt reuse across every ledger database for
the engagement. The laboratory gate keeps this authority state only in the fixture
process, so restarting it resets that additional replay defense.
Successful authorized use is a separate state and requires distinct authorized
effect evidence; verified finding evidence alone never sets it.

Every action uses its own attempt identifier, budget reservation, and approval
receipt. A terminal or reused attempt fails before approval and provider dispatch.
The provider's retained-output byte count is an upper bound, not the charged
usage: the dispatcher charges the canonical serialized size of the retained
result and marks an over-bound result uncertain.
Authorization and dispatch-intent failures release an undispatched reservation.
Once dispatch is durably recorded, provider, verifier, or settlement ambiguity
becomes an uncertain attempt and is not retried automatically. Incomplete
correlated evidence may return `insufficient_evidence` only when the dispatcher
can establish that no uncertain effect remains. Either outcome blocks progression.
An invalid candidate claim retains that insufficient state instead of being
silently reported as a completed non-candidate.

Results retain bounded ATT&CK mappings and explicit coverage. `T1046` records
only that the approved service responded. `T1210` is recorded only for a
version-bound `#143` candidate and remains a candidate until controlled proof
records the exact effect and cleanup. Each assessment and finding field is marked
`tested`, `documented`, `untested`, or `unverified`.

## Run the disposable laboratory

Install the repository test dependencies, then run the public operator journey:

```bash
.venv/bin/python scripts/service_validation_loopback_example.py
```

The command creates eight services on random nonstandard ports bound to
`127.0.0.1`, discovers and routes all seven families, and runs the public
selection, authorization, provider, dispatcher, fixture-owned verifier, budget,
reporting, and cleanup path. Its JSON report includes benign SSH, a versioned
Redis `#143` candidate and separately authorized proof, remediated Redis, and an
HTTP insufficient-evidence outcome. It stops every service and confirms that all
fixture transport connections have closed. This does not prove rollback, effect
reversal, external process cleanup, or target-side reconciliation. To retain the
state artifacts for inspection, select a fresh path that does not yet exist:

```bash
.venv/bin/python scripts/service_validation_loopback_example.py \
  --state-dir /tmp/cops-service-validation-lab
```

Each journey uses fixed fixture attempt identifiers, so a retained state directory
cannot be reused. The command exclusively creates the final directory before
starting a fixture, rejects symbolic-link ancestors, and pins the directory identity
for later ledger opens. The identity checks reject persistent replacement before and
after each ledger open. Python's SQLite interface still opens the database by pathname,
so the checks do not eliminate a same-account pathname ABA during that internal open.
Run the lab where no untrusted process under the same account can rename or replace
the state path or SQLite entry, or alter the database contents, during the journey.
A cleanup failure exits unsuccessfully instead of reporting a completed journey.

Run the focused executable acceptance suite with:

```bash
.venv/bin/python -m pytest -q \
  tests/test_service_entry_validation.py \
  tests/test_service_validation_execution.py \
  tests/test_service_validation_lab.py \
  tests/step_defs/test_service_entry_validation_steps.py
```

The suite checks every loopback adapter through the public subprocess entry point
and separately exercises fabricated provider claims, ledger-reopen replay,
approval and prerequisite consumption, correlation/reference/time and
receipt/plan/attempt/endpoint/action/digest mismatches, exact
endpoint/version/effect binding, provider availability, budget release before
dispatch, post-dispatch uncertainty, fresh attempts, and cleanup reporting.

These commands authorize loopback fixtures only. They do not grant scope for an
external endpoint or register a production provider.
