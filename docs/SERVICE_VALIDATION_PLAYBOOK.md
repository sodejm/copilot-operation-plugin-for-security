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
exercise the public selection, authorization, dispatcher, independent verifier,
budget, reporting, and cleanup boundaries without claiming production coverage
for an external target. The provider and verifier collect evidence over separate
connections, and the verifier disregards provider-authored output. Both paths use
the same bounded lab protocol parser, so this laboratory does not establish
independent parser implementations.

Unknown responses, port-only guesses, endpoints outside the validated scope, and
evidence without matching active-probe provenance produce no execution plan.

## Evidence and proof gates

Low-impact validation requires an independent verifier to bind the approval
receipt, plan, attempt, endpoint, selected action, evidence digest, and a fresh
verification time, then record protocol evidence plus all five assessment
dimensions: exposure, authentication, configuration, version, and trust. The
result retains those identities as operator-visible provenance. Provider-supplied
strings do not satisfy this gate. Complete evidence may establish an observed
exposure or a versioned candidate; it cannot establish a verified finding or
successful authorized use.

Controlled proof requires a prior candidate for the same plan and endpoint. The
candidate must bind the observed version and exact endpoint to the immutable,
trusted issue `#143` reproduction digest. A finding becomes verified only when
the independent verifier records the reproduction's exact expected effect and
cleanup evidence.
Successful authorized use is a separate state and requires distinct authorized
effect evidence; verified finding evidence alone never sets it.

Every action uses its own attempt identifier, budget reservation, and approval
receipt. A terminal or reused attempt fails before approval and provider
dispatch. Authorization and dispatch-intent failures release an undispatched
reservation. Provider exceptions after dispatch intent become an uncertain
attempt for recovery; missing or mismatched independent evidence returns
`insufficient_evidence`. An invalid candidate claim retains that insufficient
state instead of being silently reported as a completed non-candidate.

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
selection, authorization, provider, dispatcher, independent verifier, budget,
reporting, and cleanup path. Its JSON report includes benign SSH, a versioned
Redis `#143` candidate and separately authorized proof, remediated Redis, and an
HTTP insufficient-evidence outcome. It stops every service and confirms that all
connections have closed. To retain the state artifacts for inspection, select a
directory explicitly:

```bash
.venv/bin/python scripts/service_validation_loopback_example.py \
  --state-dir /tmp/cops-service-validation-lab
```

Run the focused executable acceptance suite with:

```bash
.venv/bin/python -m pytest -q \
  tests/test_service_entry_validation.py \
  tests/test_service_validation_execution.py \
  tests/test_service_validation_lab.py \
  tests/step_defs/test_service_entry_validation_steps.py
```

The suite checks every loopback adapter through the public subprocess entry
point and separately exercises fabricated evidence, receipt/plan/attempt/digest
and time mismatches, exact endpoint/version/effect binding, provider availability,
budget release before dispatch, uncertain recovery after dispatch intent, fresh
retries, and replay rejection.

These commands authorize loopback fixtures only. They do not grant scope for an
external endpoint or register a production provider.
