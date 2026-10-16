# Isolated Kubernetes containment laboratory

The registered `isolated-k3s-containment/v1` acceptance adapter runs a fixed,
synthetic Kubernetes fixture. It proves NetworkPolicy enforcement through real
pod requests, server logs, and Kubernetes API audit records. It never reads an
ambient kubeconfig or connects to an existing cluster.

## Provision and run

Use a disposable Docker Linux VM with at least 6 GiB of memory. The Kubernetes
node is privileged and shares the Docker host kernel. It is suitable for these
fixed fixtures on a dedicated lab host; it is not a sandbox for hostile images or
a production execution worker. The node has no published ports, host path mounts,
host PID namespace, or external network. It is limited to 2 CPUs, 3 GiB of memory,
and 768 processes. The unprivileged service laboratory remains a separate container.

Provision the service runtime described in [service laboratories](SERVICE_LABORATORY.md).
Before starting acceptance, explicitly pull the three publisher manifests listed
for the Docker daemon's architecture in `IMAGE_PINS` in
`cops/laboratory/kubernetes_lab.py`. Those digest pins identify K3s
`v1.34.12-k3s1`, pause `3.10.2`, and Python `3.14.6-slim`; Linux arm64 and amd64
are registered. Pulling is a provisioning action with network access. The adapter
itself never pulls, installs dependencies, or uses a floating tag.

```console
make check-laboratory LABORATORY_ARGS='--runtime docker --image sha256:<service-runtime-id> --kubernetes-timeout 480'
```

The Kubernetes deadline accepts 180–600 seconds. Cleanup has a separate 90-second
budget. Missing images, unsupported platforms, unavailable Docker, or incomplete
isolation evidence leave acceptance incomplete. The strict composite gate requires
all twelve service-container cases and the Kubernetes case; a partial case list
cannot pass.

## Hardening walkthrough

1. Start a fresh node with Docker network mode `none`. Import only the pinned
   pause and Python images into its private container runtime.
2. Create a namespace, a service account without token automount, one HTTP server,
   and required and forbidden client pods. Snapshot the namespace UID and pod IP.
3. Confirm that both clients can reach the server before containment. Capture the
   pod configuration and review the service account.
4. Propose an ingress NetworkPolicy allowing only the required client on TCP 8080.
   Compile each typed stage into the existing ActionPlan contract and consume a
   signed, single-use approval bound to the namespace UID, pod IP, images, policy,
   prior evidence and exact action. Changed inputs or namespace identity fail.
5. Apply the policy, prove that required traffic still returns 200 and forbidden
   traffic is blocked, then remove it and prove both paths return 200 again.

## Incident-response walkthrough

The same snapshot → review → proposal → authorized application → verification
sequence tests containment of the synthetic compromised client. The lab repeats
the sequence with an injected failure after application and cancellation after
application. Both paths must run cleanup and restore connectivity. A failed or
cancelled workflow remains `partial_failure` or `cancelled`; successful cleanup
does not convert it into a successful workflow.

Each request path includes the run nonce, namespace, role and phase. Every
successful probe must have matching timestamped server telemetry. Metadata-only
Kubernetes audit records must show successful creation and deletion of the
containment policy. Reports retain record digests and omit request bodies,
credentials and user identities. Missing logs or audit records fail acceptance.

## Isolation, provenance and reset

Host inspection verifies the immutable node image, resources, owned volumes,
entrypoint and network configuration before execution. The running node must have
no default IPv4 or IPv6 route. Actual pod egress probes for both families must
fail with a definitive unreachable or denied error; a timeout or refusal is
insufficient evidence. Internal pod networking is expected and remains confined
to the disposable node.

The fixture definitions and image manifests are versioned with the adapter. Each
run reports its nonce, resolved image identities, stage plan digests, audit
digests, observed paths and lifecycle results. Normal completion, failure and
cancellation require removal of their namespace. Final cleanup verifies removal
of the owned node, its four anonymous volumes and two nonce-scoped image tags.
The preinstalled publisher images and service-runtime image are retained.

For an interrupted host, inspect resources carrying the reported nonce before
removing them. Never reset unrelated Docker resources or a user cluster. A cleanup
failure fails the gate. The report does not establish native firewall coverage,
other CNI behavior, production Kubernetes authorization, provider support, or the
production worker's distinct-user boundary.
