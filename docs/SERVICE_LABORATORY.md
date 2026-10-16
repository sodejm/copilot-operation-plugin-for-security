# Disposable service laboratory

The COPS service laboratory has two complementary acceptance paths. Offline playback evaluates deterministic synthetic Entra grant, Entra sign-in, Kubernetes audit, and normalized Sysmon-shaped JSON events. Process acceptance starts four disposable loopback HTTP services and performs actual requests through identity, protected-resource, IOC hunt/containment, and lateral-target paths. Additional disposable servers exercise REST/GraphQL object authorization, rate limits, a SQLite-backed injection fixture, and a proposed-tool-call gateway. Ephemeral TLS and JWT credentials test actual trust and signature decisions.

Neither path creates an authorization mechanism. Authorized active operations continue to use the existing `ActionPlan`, approval, worker scope, and signed `LaboratoryHarness` observation gates. The disposable services use reserved example addresses and synthetic identities and never contact an external target.

## Run the paths

Use the repository environment:

```console
python scripts/run_service_laboratory.py --mode offline
python scripts/run_service_laboratory.py --mode process --profile vulnerable
python scripts/run_service_laboratory.py --mode process --profile corrected
python scripts/run_service_laboratory.py --mode isolation-readiness
```

`--output PATH` writes the JSON report. `--require-isolation` exits with status 2 unless isolation is verified. On macOS without an available Docker daemon, that failure is expected. A loopback bind and actual TCP requests prove service activity, but they do not prove network namespace isolation.

The callable API is `ServiceLaboratory.run_offline_playback()` or `ServiceLaboratory.run_process_acceptance("vulnerable" | "corrected")`. A report uses `cops.service-laboratory-report/v1`. Capability assessment can preserve it as artifact kind `service_laboratory_report`, including `fixture_manifest_digest`. `telemetry_events` and `alert_events` are direct inputs to the workflow purple-team evaluator: each contains a correlation ID and RFC3339 timestamp, and alert records contain `alert: true`.

## Expected service outcomes

| Case | Vulnerable | Corrected |
| --- | ---: | ---: |
| Credential issue | 201 | 201 |
| Authenticated request | 200 | 200 |
| Lateral request | 200, target reached | 403, target not reached |
| IOC ingest, hunt, containment | 201, 200 hit, 200 | 201, 200 hit, 200 |
| Authenticated request after revocation | 401 | 401 |
| Trusted client mTLS | 204 | 204 |
| Missing or untrusted client certificate | TLS rejected | TLS rejected |
| SQL injection | Other synthetic object exposed | No object returned |
| Permitted tool and resource | 200 | 200 |
| Direct/indirect unauthorized tool or resource | Allowed, boundary finding | 403, no tool call |
| Other-user or anonymous API object request | Object exposed | 403 or 401 |
| Repeated API request over budget | Accepted | 429 |

The API cases preserve owner access while rejecting other-user and anonymous
access after correction. TLS cases also reject an untrusted server chain. JWT
cases verify an ephemeral RSA signature and reject tampered, unsigned,
wrong-key, and expired credentials. The tool gateway verifies enforcement of a
registered synthetic tool/resource allowlist; it does not test a provider model's
prompt-injection resistance. A separate acquisition case copies a pinned
synthetic file, rejects missing permission and modified evidence, and verifies
exclusive output and unchanged original bytes.

The process runner writes every service event to a JSONL telemetry file while the run is active and executes detection rules against those captured events. It reports rule counts and alert objects for the lateral path, credential revocation, post-revocation rejection, IOC hit, and containment. It restores the in-memory baseline after normal completion, injected failure, cancellation, and graph shutdown.

## Fixtures and provenance

`cops/laboratory/service_fixtures/manifest.json` is the fixture registry. It contains SHA256 checksums, provenance, expected vulnerable/corrected outcomes, reset instructions, and pinned prerequisites for Docker Engine, kubectl, Zeek, Suricata, Sysmon, and python-evtx. Those heavyweight tools are not bundled. Their platform and runtime limits are explicit in the registry.

The registry includes normalized synthetic JSON and three separate binary EVTX
fixtures. `scripts/build_evtx_fixtures.py` generates vulnerable, corrected, and
insufficient-evidence EVTX 3.1 containers; the manifest pins their bytes and expected
record/indicator counts. They are synthetic containers, not native Windows captures.
The registered `sysmon-evtx/v1` importer requires `python-evtx==0.8.1` and
`hexdump==3.3` on Linux. It checks the supplied SHA-256, framing and CRCs, parses a
private read-only snapshot with resource limits, and omits raw commands, users, and
paths. Native Windows/Sysmon acquisition remains unvalidated.

Run `cops telemetry import-evtx --input FILE --sha256 EXPECTED_SHA256` for an
import. Input, record and deadline budgets can be lowered with `--max-bytes`,
`--max-records` and `--deadline`. A partial result is indeterminate for detection
coverage. See [the import contract](../specs/evtx-import.spec.md).

No persistent state is required. Stop an interrupted runner to close its listeners. Temporary mTLS keys and certificates are removed automatically. A caller-provided telemetry directory can be deleted after evidence has been retained under the engagement's evidence policy.

## Required repository gate

`scripts/check_laboratory.py` is the strict acceptance entry point. Its twelve service-container cases
run fixture playback; binary EVTX correction and integrity checks; vulnerable and corrected process acceptance; authorized IOC
workflow success, injected failure, and cancellation; and five integrated service
chains. The process cases assert actual TCP request results, mTLS acceptance and
rejection, telemetry persistence, detection counts, post-revocation denial, stopped
services, and restored baselines. The integrated cases verify typed stage outputs,
exact plan and service-URL binding, and single-use authorization consumption. See
[integrated workflows](INTEGRATED_WORKFLOWS.md#active-service-chains) for their
synthetic-service limits and remaining production validation.

A thirteenth case runs the separate, registered
[Kubernetes containment laboratory](KUBERNETES_LABORATORY.md). Provision its three
architecture-specific image pins before running the Docker gate. It verifies real
NetworkPolicy enforcement, HTTP and audit evidence, restoration after success,
failure and cancellation, and owned-resource removal. All thirteen cases are
required; process-only acceptance cannot satisfy the Kubernetes isolation gate.

The gate prints one compact JSON object. `status` is `passed`, `blocked`, or `failed`; `blockers` contains the exact isolation blocker; `failures` contains behavioral mismatches; and each item in `cases` contains bounded metrics for service, API, gateway, acquisition, TLS, and JWT checks. Exit status 0 requires verified network isolation and every functional assertion. Exit status 2 means the functional evidence passed but the isolation prerequisite is blocked. Exit status 1 means functional evidence or strict preflight failed.

Run it directly, optionally retaining disposable evidence below a caller-selected directory:

```console
python scripts/check_laboratory.py
python scripts/check_laboratory.py --state-dir "$TMPDIR/cops-laboratory-evidence"
```

On a host without a verified container or network namespace boundary, the gate still exercises the local services so failures remain observable, then exits 2 only if all functional prerequisites and checks pass. A missing Linux EVTX parser fails its required case with exit 1. It marks nonisolated results as `functional_evidence_only: true`. Its strict preflight also calls the workflow runner with `require_isolation=True` and verifies rejection happens before a state directory is created.

The root `Makefile` exposes the strict gate. The default process runtime records functional evidence and cannot verify network isolation. For isolated acceptance, provision an image locally containing Python 3.11 or later, `cryptography==50.0.2`, `python-evtx==0.8.1`, and `hexdump==3.3`, then supply its immutable image ID:

```console
make check-laboratory
make check-laboratory LABORATORY_ARGS='--runtime docker --image sha256:<64-hex-image-id>'
```

The Docker adapter never pulls an image or installs dependencies. It copies an allowlisted, size-bounded source snapshot, excluding credentials, repository metadata, and unrelated files, and binds its digest and a fresh nonce to the child report. Before starting the container, the host independently inspects its immutable image, read-only source mount and root filesystem, unprivileged identity, dropped capabilities, resource limits, private namespaces, and `none` network mode. The child verifies the snapshot, checks that Linux exposes only loopback interfaces and routes, and requires actual IPv4 and IPv6 egress attempts to fail with a definitive unreachable or denied result. A timeout is insufficient evidence.

The [runtime recipe](../laboratories/service-runtime/README.md) pins the wheel
versions and hashes for Linux amd64 and arm64. Its Docker build has network
access disabled and accepts only a caller-selected immutable base image. The
`isolated-service-laboratory` repository CI job builds the recipe and runs the
strict gate; a local run does not establish that hosted CI passed.

The adapter verifies removal of its owned container after success, failure, cancellation, or deadline expiry. This acceptance adapter does not certify the production worker's distinct-user boundary. Production operations still require the existing signed `LaboratoryHarness` observations and execution authorization. An available Docker CLI or daemon, a loopback listener, and marker files alone cannot establish laboratory readiness.

## Forensic copy correction cases

The acquisition case imports the real acquired regular file as `disk_image` and
`memory_image`, binds import digests and byte counts to its collection receipt,
and verifies unchanged original bytes. It rejects denied permission, absent
custody, and a deliberately modified copy. Restoring the copy must restore
integrity verification. Temporary files are removed on exit. These checks cover
raw-file integrity only; they do not establish native disk or memory collection.
