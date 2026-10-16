# Workflow service laboratory

The workflow service laboratory is a disposable local acceptance path for an authorized IOC-to-hunt-to-containment workflow. It starts four disposable HTTP services on ephemeral `127.0.0.1` ports, issues a synthetic credential in memory, ingests and hunts a harmless documentation-range IOC, applies containment, revokes the credential, and proves that a later authenticated request receives HTTP 401.

The stable Python entry point is:

```python
from cops.laboratory.workflow_lab import run_workflow_service_laboratory

report = run_workflow_service_laboratory(
    "/tmp/cops-workflow-lab",
    mode="success",
    require_isolation=False,
)
```

The command wrapper emits the same `cops.workflow-service-laboratory-report/v1` document:

```console
python scripts/run_workflow_laboratory.py \
  --state-directory /tmp/cops-workflow-lab \
  --mode success
```

`success`, `failure`, and `cancellation` exercise normal completion, an injected hunt-stage failure, and cancellation after IOC ingestion. The failure path invokes the workflow cleanup callback. Every path also verifies baseline restoration while the service graph closes and verifies that all service threads stop. Remove the supplied state directory after retaining any report or telemetry needed for review; the services require no manual reset.

Each stage is compiled into the shared `ActionPlan` type before execution. The laboratory creates a signed execution authorization bound to that exact plan, verifies it against an active laboratory engagement and the expected worker, and consumes it atomically from the shared one-use approval store. This in-process adapter exercises the shared authorization primitives. It does not claim the distinct-UID and Linux `SO_PEERCRED` boundary required by the production approval authority.

The report records each real TCP request and response status, stage results, authorization consumption, telemetry, detection-rule counts, alerts, fixture-manifest digest, reset status, and isolation evidence. `telemetry_events` and `alert_events` use RFC 3339 timestamps and the run ID as `correlation_id`, so they can be passed directly to `evaluate_purple_team_handoff`. Alerts contain `alert: true` and are derived by executing the bundled detection rules against the captured attack events.

Loopback binding limits reachability but does not establish process, container, or network-namespace isolation. `--require-isolation` fails with exit code 2 before creating the state directory unless `probe_isolated_runtime()` can verify an isolation boundary. A normal macOS run therefore reports the limitation and must not be represented as isolated execution.

Fixture provenance, SHA-256 checksums, expected outcomes, and pinned optional-tool prerequisites are maintained in `cops/laboratory/service_fixtures/manifest.json` and verified before a report is returned. The normalized Entra sign-in/grant, Kubernetes audit, and Sysmon JSON fixtures are offline playback inputs. Separate synthetic binary EVTX fixtures exercise the registered pinned parser. Native Windows/Sysmon acquisition remains unvalidated; the laboratory does not relabel JSON as EVTX.

Run the required laboratory gate from the root `Makefile`:

```console
make check-laboratory
```

The default process runtime returns exit code 2 when isolation is unverified,
even if every functional case passes. For verified execution, use the immutable,
preinstalled Docker image path described in [service laboratories](SERVICE_LABORATORY.md).
The gate includes success, partial failure, cancellation, authorization consumption,
actual service activity, correlated telemetry, and baseline restoration checks.

The laboratory never targets external systems. Its only allowed destination is its own disposable loopback service graph.
