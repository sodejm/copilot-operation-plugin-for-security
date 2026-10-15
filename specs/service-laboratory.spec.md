# Specification: Disposable Service Laboratory

## Purpose

Provide two deterministic acceptance paths for COPS service scenarios: offline fixture playback and actual disposable local services. The service path proves network requests, credential revocation, lateral movement behavior, mTLS handshakes, telemetry collection, detection execution, IOC hunting, containment, and state restoration. It reports isolation separately and never treats a loopback bind as proof of a network namespace.

## Invariants

1. Every process acceptance run starts four ephemeral loopback services, performs real HTTP requests, and shuts the listeners down.
2. The vulnerable profile reaches the lateral target and the corrected profile blocks that path. Both outcomes come from checksum-verified configuration fixtures.
3. Issued credentials authenticate before revocation and receive HTTP 401 after containment revokes them.
4. Valid client mTLS succeeds; missing and untrusted client certificates fail a real TLS handshake. All keys and certificates are deleted with the temporary directory.
5. Telemetry and alert events contain a correlation ID and RFC3339 timestamp so the workflow purple-team handoff evaluator can consume them directly.
6. Detection counts include attack and benign classes during offline playback and rule matches during process acceptance.
7. IOC ingestion, hunting, and containment use the actual hunt and identity services.
8. Normal completion, injected failure, and cancellation restore the service baseline. Final graph shutdown verifies the clean baseline again.
9. The fixture manifest records provenance, SHA256 checksums, expected outcomes, reset instructions, and pinned prerequisites for unbundled heavyweight adapters.
10. The Sysmon fixture is labeled normalized synthetic JSON. Authentic EVTX acquisition remains unsupported until a harmless authentic artifact is supplied.
11. Offline playback performs no network activity. Default process acceptance proves local TCP activity and reports network isolation unverified.
12. Isolated Docker acceptance uses an already installed immutable image. Independent host inspection verifies the container configuration before dispatch; Linux interface, route, and actual IPv4/IPv6 egress checks verify the running boundary. Missing evidence or an inconclusive egress timeout blocks completion.
13. The container receives only a bounded allowlisted source snapshot. Both host and child bind the exact snapshot digest and a fresh nonce; missing, modified, extra, symbolic-link, and traversal paths fail verification.
14. Container cleanup checks ownership before removal and verifies that the container is absent. Cleanup failure fails the gate, including after a deadline or failed dispatch.
15. Laboratory acceptance does not certify the distinct-user production worker boundary or replace the signed `LaboratoryHarness` authorization and observation contracts.
