# Specification: Disposable Service Laboratory

## Purpose

Provide two deterministic acceptance paths for COPS service scenarios: offline fixture playback and actual disposable local services. The service path proves network requests, credential revocation, lateral movement behavior, mTLS handshakes, telemetry collection, detection execution, IOC hunting, containment, and state restoration. It reports isolation separately and never treats a loopback bind as proof of a network namespace.

## Invariants

1. Every process acceptance run starts four ephemeral loopback services, performs real HTTP requests, and shuts the listeners down.
2. The vulnerable profile reaches the lateral target and the corrected profile blocks that path. Both outcomes come from checksum-verified configuration fixtures.
3. Issued credentials authenticate before revocation and receive HTTP 401 after containment revokes them.
4. Valid client mTLS succeeds; missing and untrusted client certificates fail a real TLS handshake. All keys and certificates are deleted with the temporary directory.
5. Telemetry and alert events contain a correlation ID and RFC3339 timestamp so the workflow purple-team handoff evaluator can consume them directly. Each expected telemetry field occurs exactly once; equal-value and conflicting-value duplicates fail with `duplicate_expected_telemetry_field` before a handoff, rule proposal, or evaluation result is produced. Telemetry and alerts must satisfy every unique expected predicate before detection can be verified; an unrelated correlated alert does not qualify.
6. Detection counts include attack and benign classes during offline playback and rule matches during process acceptance.
7. IOC ingestion, hunting, and containment use the actual hunt and identity services.
8. Normal completion, injected failure, and cancellation restore the service baseline. Final graph shutdown verifies the clean baseline again.
9. The fixture manifest records provenance, SHA256 checksums, expected outcomes, reset instructions, and pinned prerequisites for unbundled heavyweight adapters.
10. Sysmon JSON and binary EVTX fixtures are independently labeled synthetic. The registered, pinned Linux EVTX adapter must parse vulnerable, corrected, and incomplete binary fixtures, reject modified evidence, and preserve originals. Native Windows acquisition remains unvalidated.
11. Offline playback performs no network activity. Default process acceptance proves local TCP activity and reports network isolation unverified.
12. Isolated Docker acceptance uses an already installed immutable image. Independent host inspection verifies the container configuration before dispatch; Linux interface, route, and actual IPv4/IPv6 egress checks verify the running boundary. Missing evidence or an inconclusive egress timeout blocks completion.
13. The container receives only a bounded allowlisted source snapshot. Both host and child bind the exact snapshot digest and a fresh nonce; missing, modified, extra, symbolic-link, and traversal paths fail verification.
14. Container cleanup checks ownership before removal and verifies that the container is absent. Cleanup failure fails the gate, including after a deadline or failed dispatch.
15. Laboratory acceptance does not certify the distinct-user production worker boundary or replace the signed `LaboratoryHarness` authorization and observation contracts.
16. Five integrated service chains bind each stage's typed configuration and prior observations to a freshly compiled ActionPlan. The approval adapter rejects changed actions, destinations, inputs, workers, authorization IDs, and replay before dispatch.
17. Integrated reports preserve actual request statuses, consumed approvals, plan digests, persisted telemetry, baseline restoration, and stopped listeners. Synthetic consent, advisory, event-rule, and fixed-name DNS fixtures do not establish production Entra, dependency, Sigma/KQL, or DNS support.
18. Credential evidence bundles use an ephemeral Ed25519 signature and verify it before reporting integrity. Reports state that the key is unanchored and do not claim source authenticity; plaintext credentials remain absent from reports and persisted workflow state.
19. The detection chain evaluates complete evidence and explicitly labeled withheld-log, withheld-alert, and unavailable-alert views of actual captured service activity. Source and handoff digests bind these views. Generated Sigma and KQL subsets execute against captured attack and benign events; all four result states and measured counts are required by the laboratory gate.
20. Kubernetes acceptance uses only registered, preinstalled publisher image digests in a fixed privileged node on a disposable Docker host. It never consumes ambient kubeconfig, publishes ports, or mounts host paths. This node shares the host kernel and is not a production worker sandbox.
21. Kubernetes stages bind namespace UID, pod IP, pinned images, policy digest and prior output to existing ActionPlan approvals. Actual required and forbidden pod requests establish baseline, containment and restoration. Correlated HTTP logs and successful policy create/delete audit records are mandatory.
22. Kubernetes success, injected failure and cancellation restore connectivity and remove their namespaces. Final cleanup removes the owned node, volumes and nonce-scoped tags. Missing cleanup or inconclusive IPv4/IPv6 egress evidence fails acceptance.
23. The strict composite gate requires the exact twelve service cases plus the Kubernetes case. Missing, duplicate, failed or blocked cases cannot produce completion.

24. Consent correlation requires complete, unique, in-window tenant-bound records
    joining grant client object IDs through service principals to sign-in app IDs.
    Missing or conflicting evidence yields no target. The emulator revokes only an
    exact tenant/grant/client/app tuple; acceptance proves target 200 → 401 and
    unrelated grant 200 → 200. Session revocation and hunt steps remain proposals.

25. Exposure acceptance requires a real fixed-name DNS exchange and exact endpoint,
    address, timestamp and evidence-reference correlation. Anonymous access changes
    from 200 to 401 while authorized access stays 200; a withheld DNS view remains
    insufficient. Malformed DNS, timeout and address changes fail the inventory
    stage, prevent later authentication requests and still restore baseline state.
    The resolver never forwards requests or accepts external discovery targets.

26. Supply-chain acceptance builds only the registered synthetic pure-Python
    wheels, installs them with a pinned offline hash-enforcing installer, and
    observes the installed module over loopback HTTP. The vulnerable version
    exposes the seeded injection; its corrected counterpart preserves the owner
    query and rejects injection. Modified wheels must fail installation, missing
    dependency evidence remains unknown, and temporary installations and services
    are removed after success, failure, timeout, or cancellation.
