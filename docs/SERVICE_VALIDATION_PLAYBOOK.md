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
| HTTP | `web-api-inventory-and-replay` | Conservative identification and routing only |
| SSH | `network-remote-and-file-services` | Native loopback banner probe in the acceptance lab |
| Redis | `network-data-services` | Native loopback banner and bounded `PING` proof in the acceptance lab |
| SMTP | `network-messaging-services` | Conservative identification and routing only |
| Docker API | `network-developer-interfaces` | Conservative identification and routing only |
| DNS | `network-infrastructure-services` | Conservative identification and routing only |
| SOCKS | `network-legacy-and-proxy-services` | Conservative identification and routing only |

Unknown responses, port-only guesses, endpoints outside the validated scope, and
evidence without matching active-probe provenance produce no execution plan.

## Evidence and proof gates

Low-impact validation requires an independent verifier to bind the approval
receipt, endpoint, and selected action, then record protocol evidence plus all
five assessment dimensions: exposure, authentication, configuration, version,
and trust. The result retains the action, approval receipt identifier, attempt
identifier, and endpoint as operator-visible provenance. Provider-supplied strings do not satisfy this gate. Complete evidence
may establish an observed exposure or a versioned candidate; it cannot establish
a verified finding or successful authorized use.

Controlled proof requires a prior candidate for the same plan and endpoint. The
candidate must bind the observed version and exact endpoint to the versioned
issue `#143` reproduction. A finding becomes verified only when the independent
verifier records the reproduction's exact expected effect and cleanup evidence.
Successful authorized use is a separate state and requires distinct authorized
effect evidence; verified finding evidence alone never sets it.

Every action uses its own attempt identifier, budget reservation, and approval
receipt. A terminal or reused attempt fails before approval and provider
dispatch. Provider exceptions become an uncertain dispatch receipt for recovery;
missing or mismatched independent evidence returns `insufficient_evidence`.

Results retain bounded ATT&CK mappings and explicit coverage. `T1046` records
only that the approved service responded. `T1210` is recorded only for a
version-bound `#143` candidate and remains a candidate until controlled proof
records the exact effect and cleanup. Each assessment and finding field is marked
`tested`, `documented`, `untested`, or `unverified`.

## Run the disposable laboratory

Install the repository test dependencies, then run the complete service
validation acceptance path:

```bash
.venv/bin/python -m pytest -q \
  tests/test_service_entry_validation.py \
  tests/test_service_validation_execution.py \
  tests/step_defs/test_service_entry_validation_steps.py
```

The suite creates random-port services bound to `127.0.0.1`, runs the real
provider/dispatcher boundary, verifies evidence through a separate fixture audit,
and closes every server and connection. It covers benign SSH, affected Redis,
protected Redis, verified finding without successful use, distinct authorized
use, fabricated provider evidence, endpoint/version/effect mismatch, incomplete
evidence, missing providers, fresh retries, and replay rejection.

Run individual operator outcomes with these commands:

```bash
# Benign, protected, and insufficient-evidence outcomes
.venv/bin/python -m pytest -q tests/step_defs/test_service_entry_validation_steps.py \
  -k "benign or protected or missing_independent"

# Versioned issue #143 controlled proof and cleanup
.venv/bin/python -m pytest -q tests/step_defs/test_service_entry_validation_steps.py \
  -k "controlled_proof"

# Provider-availability and retry gates
.venv/bin/python -m pytest -q tests/step_defs/test_service_entry_validation_steps.py \
  -k "availability or retry"
```

These examples authorize loopback fixtures only. They do not grant scope for an
external endpoint or provide a production provider registration.
