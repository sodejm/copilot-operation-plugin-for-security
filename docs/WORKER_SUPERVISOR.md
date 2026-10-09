# Worker supervisor deployment boundary

The production execution path uses three distinct, unprivileged Linux accounts:
an SSH relay account, a worker supervisor account, and an approval authority
account. The relay accepts one host-key-authenticated SSH request and forwards it
to the supervisor Unix socket. The supervisor validates the request and runs the
isolated worker. The approval authority independently verifies and atomically
consumes the signed authorization through its consume-only control socket.

The relay account must not read the engagement, worker inventory, executable
pins, verifier trust store, signing secret, or approval database. The supervisor
account must not read the authority's trust store, signing secret, or database.
Provision each account and artifact through the host's trusted deployment
workflow; this repository does not create accounts or establish an SSH host key.

## Provision the accounts and sockets

Use separate UIDs for all three accounts. Give the relay account supplemental
membership in the supervisor's primary group, while keeping its primary GID
distinct. Provision the supervisor socket directory as a real, supervisor-owned
directory with the supervisor group and mode `2710`. The supervisor binds its
socket with mode `0660`; group members can connect but cannot list, unlink, or
replace the socket. Provision the authority socket directory as a real,
authority-owned directory with the supervisor group and mode `2710`. The
authority's socket must be authority-owned, in the supervisor group, and mode
`0660`. Neither socket path may already exist when its service starts. Keep all
ancestor directories free of symbolic links and writable only by trusted
administrators.

The supervisor reads an owner-only JSON configuration file and owner-only
inventory and engagement files. Use absolute paths and mode `0600`; the loader
rejects symbolic links, other owners, and group or other read access. The
configuration has this shape, with site-specific identities and paths:

```json
{
  "schema_version": "cops.worker-supervisor-config/v2",
  "expected_host": "worker.example.test",
  "worker_identity": "worker-lab-01",
  "socket_path": "/var/lib/cops-supervisor/relay.sock",
  "relay_uid": 2101,
  "relay_gid": 2101,
  "supervisor_uid": 2102,
  "supervisor_gid": 2202,
  "authority_uid": 2103,
  "approval_socket_path": "/var/lib/cops-authority/control.sock",
  "cleanup_journal_path": "/var/lib/cops-supervisor/cleanup.sqlite3",
  "inventory_path": "/etc/cops-supervisor/worker-inventory.json",
  "engagement_path": "/etc/cops-supervisor/engagement.json",
  "attestation_key_id": "worker-lab-01-2026-01",
  "attestation_key_path": "/etc/cops-supervisor/response-attestation.key",
  "executable_sha256_pins": {},
  "egress_trust_domain": "services.example.test",
  "credential_manifest_path": "/etc/cops-supervisor/credential-manifest.json"
}
```

The v2 supervisor configuration requires `cleanup_journal_path`. Provision its
parent as a real, supervisor-owned directory with mode `0700`. Keep the SQLite
journal outside execution workspaces on durable storage, owned by the supervisor
with mode `0600`, and retain it across process restarts. The worker records
cleanup transitions before acting and recovers pending work before accepting
another relay request. An invalid journal path,
unsafe ownership or permissions, or unreadable recovery state stops supervisor
startup. Review unresolved cleanup receipts and unknown effects before repeating
an operation; recovery does not prove an interrupted external effect rolled back.

The worker records cleanup intent before exclusively creating each default
workspace or credential scratch directory. It records the resource identity from
the still-open creation descriptor before cleanup is permitted. Recovery verifies
that identity without following symbolic links, quarantines a matching object in
its verified parent, and verifies the moved object again before deletion. Missing,
unverified, replaced, and legacy journal effects without a creation identity remain
unresolved and are preserved. A replacement detected after quarantine remains in
an owner-only `.cops-cleanup-*` directory for operator reconciliation. A caller-
supplied worker workspace must already exist and remains caller-owned. Recursive
cleanup preserves a worker-owned directory whenever any effect beneath it lacks a
durable `cleaned` state, including an unresolved plan declaration.

`egress_trust_domain` and `credential_manifest_path` are optional. Omit the
manifest path when no operation uses a credential. For credentialed operations,
provision the manifest as a supervisor-owned regular JSON file with mode `0600`:

```json
{
  "schema_version": "cops.worker-credential-manifest/v1",
  "provider_socket_path": "/var/lib/cops-credentials/provider.sock",
  "provider_uid": 2104,
  "provider_gid": 2204,
  "provider_timeout_seconds": 5,
  "grants": [
    {
      "reference": "opaque-credential-reference",
      "environment_variable": "COPS_CREDENTIAL_API_TOKEN",
      "plan_id": "approved-plan-id",
      "plan_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "engagement_id": "engagement-id",
      "worker_identity": "worker-lab-01",
      "target": "approved-target",
      "operation_index": 0,
      "operation_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "step_id": "approved-step-id",
      "tool": "approved-tool",
      "tool_version": "approved-version",
      "action": "approved-action"
    }
  ]
}
```

Replace the example digests with the canonical digests of the approved plan and
the operation at the stated index; the operation digest covers its arguments and
egress policy. Every other grant field must match that same approved operation.
The manifest contains only opaque references, never credential values. The
provider runs under a fourth, distinct non-root UID. Its socket directory must
be owned by root or the provider and must not be group- or other-writable; the
socket must have the configured provider UID/GID and no access for other users.
The supervisor checks the provider's kernel peer credentials before sending a
reference. Provision and operate the provider through the trusted host workflow:
this repository implements the bounded client transport, not the provider
service. The provider accepts one newline-terminated JSON request containing
`{"protocol":"cops.credential-provider/v1","reference":"..."}` and returns
one newline-terminated JSON object with the same protocol and reference plus a
non-empty `value` string. The response is limited to 1 MiB and the configured
timeout is at most 30 seconds. Keep credential values out of provider logs and
configuration; the worker injects each resolved value only into its isolated
operation and clears its receipt-scoped redactor afterward.

When configured, `egress_trust_domain` allows network access only for an
operation whose signed Action Plan explicitly sets `limits.egress_allowed` to
`true` and supplies a closed `egress_policy` object. The engagement scope must
also permit the endpoint. A policy names one HTTPS host and port, one exact
provider/service/account/tenant/cluster/namespace/resource identity, and the
allowed HTTP request targets:

```json
{
  "egress_policy": {
    "https_endpoint": {
      "host": "api.example.test",
      "port": 443,
      "identity": {
        "provider": "example",
        "service": "inventory",
        "account": "account-a",
        "tenant": "tenant-a",
        "cluster": "cluster-a",
        "namespace": "namespace-a",
        "resource": "resource-a"
      },
      "request_targets": ["/v1/accounts/account-a/resources/resource-a"]
    }
  }
}
```

The mediator resolves and connects on the worker side, verifies the TLS peer
hostname and a single COPS resource-identity URI SAN in the configured trust
domain, and allows only the named identity and exact `GET`/`HEAD` request
targets. Each adapter receives a per-operation Unix-socket broker capability
inside the Linux network namespace; it cannot make direct IPv4 or IPv6
connections. Redirects and DNS changes are rechecked at the boundary, and
metadata, proxy, tunnel, and out-of-scope destinations fail closed. Provision
service certificates and the trust domain through the trusted deployment
workflow. A normal hostname-only certificate does not authenticate the account
or resource identity required by this policy.

The response-attestation key file contains exactly 64 lowercase hexadecimal
characters (32 bytes), is owned by the supervisor, and has mode `0600`. Its path
and all ancestors must resist writes and symbolic-link substitution by the relay
identity. Provision the same key and key ID in the trusted operator endpoint
inventory. The supervisor authenticates the exact request scope, fresh exchange
nonce, approval receipt, and result before the relay receives the response. The
relay never reads the key. Because the operator verifier uses the same symmetric
key, protect that copy as a signing credential and rotate both copies together.

For each external adapter that will execute, map its logical tool name (for
example, `nmap`) to the exact lowercase SHA-256 digest measured by trusted
provisioning. The worker also checks tool versions and
the independently provisioned capability inventory. Review the
[authenticated execution guide](AUTHENTICATED_EXECUTION.md) for those inputs.

Run the long-lived supervisor under its configured UID and primary GID:

```bash
python3 -m cops.worker_supervisor --config /etc/cops-supervisor/supervisor.json
```

The supervisor refuses a non-Linux host, identity or file-permission mismatch,
unsafe socket directory, or pre-existing socket. Each accepted connection must
have the configured relay's kernel peer UID and GID, send exactly one bounded
newline-terminated request, and close its writing half before the worker sees
any request bytes. It returns one bounded newline-terminated response. The
worker checks approval authority readiness, platform support, sandbox readiness,
scope, adapter pins, and evidence constraints at the execution boundary. A
missing or mismatched control socket fails closed.

The worker binds each request to the locally provisioned engagement ID before
it consumes approval. The supervisor allows 30 seconds to receive the complete
request and 30 seconds to deliver the completed response; the separately
approved worker execution timeout bounds the intervening run.

The authority service must pin the supervisor worker process identity, including
its PID, before accepting a consume request. A restarted supervisor requires a
new authority binding. Starting the supervisor before the authority is ready is
safe because request execution fails closed until the authority socket and
identity checks pass; it is not evidence of execution readiness.

Configure the SSH account's forced command to run the separate
`cops.remote_worker` relay with an owner-only relay configuration and the
operator's endpoint inventory as described in
[Remote Worker SSH Transport](REMOTE_WORKER_SSH_TRANSPORT.md). Pin the server
host key through a trusted channel and keep the SSH private key and known-hosts
file outside request payloads. Do not run the supervisor as the SSH login user.

Provision `/etc/cops/remote-worker.json` as a regular file owned by the relay
account with mode `0600`. The forced command uses this path by default, or an
explicit `--config` path. Its host and worker identity must match the operator
inventory and supervisor configuration; its UID and GID must identify the
supervisor process, not the relay account:

```json
{
  "schema_version": "cops.remote-worker-relay-config/v1",
  "expected_host": "worker.example.test",
  "worker_identity": "worker-lab-01",
  "supervisor_socket_path": "/var/lib/cops-supervisor/relay.sock",
  "supervisor_uid": 2102,
  "supervisor_gid": 2202
}
```

The relay rejects a missing socket, unexpected ownership or mode, or wrong
kernel peer identity before forwarding a request. It preserves the supervisor's
signed response for verification by the operator; it has no attestation key.

Validate account ownership, socket modes, pinned process identity, installed
`bubblewrap`, and a real end-to-end request on the intended Linux host before
claiming deployment readiness. Repository tests cover boundary behavior but do
not prove that a particular host has been provisioned correctly.
