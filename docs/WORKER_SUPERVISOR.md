# Worker supervisor deployment boundary

The production execution path uses three distinct, unprivileged Linux accounts:
an SSH relay account, a worker supervisor account, and an approval authority
account. The relay accepts one host-key-authenticated SSH request and forwards it
to the supervisor Unix socket. The supervisor validates the request and runs the
isolated worker. For offline research, the approval authority verifies the
signed authorization through a read-only preflight. The same control socket
checks the pinned supervisor peer for each request, including the later atomic
consumption of the authorization.

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
`0660`. Both services apply a restrictive umask at bind and verify the socket
type, ownership, and mode before listening. Neither socket path may already
exist when its service starts. Keep all ancestor directories free of symbolic
links and writable only by trusted administrators.

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
cleanup transitions before acting and recovers pending work before opening the
relay listener. An invalid journal path, unsafe ownership or permissions,
unreadable recovery state, or incomplete recovery receipt stops supervisor
startup. Review unresolved receipts and unknown effects during host recovery
before returning the supervisor to service.

### Select an offline-only supervisor

The optional v2 configuration field `execution_profile` defaults to `"standard"`,
which preserves the existing scoped worker, credential and egress behavior.
To dedicate a supervisor to local offline research, set it to
`"offline-research/v1"` and omit `egress_trust_domain` and
`credential_manifest_path` (or set them to `null`). Unknown profile values and
offline configurations with either external capability fail startup.

The offline supervisor constructs no network scope guard, credential resolver or
egress mediator. Instead, the worker requires the signed `offline_research`
profile and applies its local-target, inventory, corpus, adapter, freshness and
isolation checks. A relay cannot remove the profile to fall back to standard
execution; that request fails before approval consumption. The configured
engagement, one-use authority, budgets, sandbox and durable cleanup journal
remain required. See [Offline research execution](OFFLINE_RESEARCH_EXECUTION.md)
for plan preparation and the supported GNU cat version and executable pin.

Profile selection is an owner-provisioned service decision, not a request field
or automatic dispatch rule. Use separate service configuration, identities and
state when operating separate standard and offline supervisors. To change a
profile, stop admission, reconcile pending cleanup, provision the new reviewed
configuration and inventory, restart the supervisor, and rebind the authority
to its new PID. Never relax worker restrictions to make a profile start. Older
v2 implementations reject the new field; remove it only when intentionally
restoring standard scoped behavior, not to bypass failed offline qualification.

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

### Qualify a dedicated Ubuntu VM with the host observer

Use a dedicated Ubuntu 24.04 LTS guest with AppArmor enabled and Ubuntu's
packaged Bubblewrap profile loaded in enforcing mode. Install `bubblewrap`,
`apparmor-profiles`, `openssh-server`, and the Python environment required by
this repository. The Lima VM used for qualification has host filesystem mounts
and its container runtime disabled. Verify `uname -m`, `uname -r` and the
package versions in the guest. Record the kernel's AppArmor user-namespace
restriction and Yama settings and leave those restrictions in force. Confirm
that the packaged `/usr/bin/bwrap` starts as the unprivileged worker. Pin the
packaged GNU `cat` executable by hash and version in the worker inventory.

The single-maintainer qualification uses a fourth, unprivileged account for the
observer. Guest administrators can change every service and its trust roots,
including the observer's policy and key. Record that shared authority in the
qualification evidence. Keep the observer key and policy inaccessible to the
worker, relay and approval authority. The templates under
[scripts/qualification/ubuntu-observer](../scripts/qualification/ubuntu-observer)
assume the names `cops328-observer` and `cops328-worker`, worker UID `997`,
worker primary GID `987`, a root-managed checkout at `/opt/cops-qual` and a
root-managed virtual environment at `/opt/cops-m0-venv314`. The AppArmor
template pins the executable and library paths of the Python 3.14.10 ARM64
build at `/opt/hostedtoolcache/Python/3.14.10/arm64`. Verify the publisher's
SHA-256 before installation. If the guest uses a different interpreter path,
architecture or account IDs, update the templates and service configurations
together.
Keep the relay out of the observer group. The supervisor socket can use the
worker group for relay access. The observer also checks the connecting peer's
primary UID and GID before accepting a request.

Use the guest administrator account to install the private key directory and
generate a dedicated Ed25519 key without copying the private bytes off the VM.

```sh
install -d -o cops328-observer -g cops328-observer -m 0700 /var/lib/cops328-observer
runuser -u cops328-observer -- /opt/cops-m0-venv314/bin/python - <<'PY'
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()
os.umask(0o077)
with open("/var/lib/cops328-observer/signing-key", "xb") as private_key:
    private_key.write(key.private_bytes_raw())
print(key.public_key().public_bytes_raw().hex())
PY
```

The printed 64-character public key goes in the trusted configuration of the
supervisor and authority. Install the templates from the checkout as root.

```sh
templates=/opt/cops-qual/scripts/qualification/ubuntu-observer
install -m 0644 "$templates/cops328-observer.apparmor" /etc/apparmor.d/cops328-observer
install -m 0644 "$templates/cops328-observer.service" /etc/systemd/system/cops328-observer.service
install -m 0644 "$templates/cops328-observer.tmpfiles" /etc/tmpfiles.d/cops328-observer.conf
apparmor_parser -r /etc/apparmor.d/cops328-observer
systemd-tmpfiles --create /etc/tmpfiles.d/cops328-observer.conf
systemctl daemon-reload
systemctl start cops328-observer.service
```

The observer socket directory uses mode `2710` and the socket uses mode
`0660`, both owned by the observer and the worker group. The observer supplies
read-only evidence from the paused Bubblewrap child's process, namespace and
descriptor metadata. AppArmor denies access to process memory, maps, environment
and auxiliary vectors. The systemd unit denies process-inspection syscalls,
namespace creation and network families other than Unix sockets. The supervisor
and authority do not get these host-observation privileges.

Set the supervisor's `offline_observer` to an object with `socket_path`
(`/run/cops328-observer/observer.sock` in the template), the observer's
numeric `uid`, and the hex `public_key`. In the approval authority service,
pass `offline_observer=ObserverVerifier(bytes.fromhex(public_key))` when
constructing `ApprovalAuthority`, keeping its configured worker PID bound to the
actual supervisor process. The client verifies the socket peer UID, the pinned
signature, the request nonce and the blocked gate. The authority requires the
approval-phase signature for a new consumption and binds it to the signed
plan, authorization, isolation digest and the authenticated supervisor PID.
Each invocation requests a fresh release-phase signature while its gate is
still blocked. If the observer loses connectivity or supplies invalid evidence,
the required approval or release stops.

Capture the guest package and kernel versions, enforcing profiles, socket and
key permissions, pinned SSH host key, signed approval and release evidence, and
negative checks for a missing, stale or substituted observer. Correlate the
observer journal's phase, plan digest and isolation digest with the authority
consumption and the worker cleanup receipt. The in-process receiver regression
test covers its local Linux path. Use the installed services across the distinct
accounts and pinned SSH route to qualify #328. Start #331 only after the complete
#328 acceptance checklist passes with zero required skips.

For the installed inert-corpus qualification, append
`--live-cat-sha256=<approved SHA-256 of /usr/bin/cat>` to the observer service's
`ExecStart` in a root-owned systemd override. The observer verifies the root-owned
executable at startup. After a release attestation it hashes the running child's
loaded executable through `/proc/<pid>/exe`, which resolves to the read-only
staged copy at `/cops/tool`. A qualifying sample requires the approved digest,
unchanged process and executable identities, the same worker lineage and
network namespace as the release gate, the enforcing Ubuntu Bubblewrap profile
stack, loopback-only interfaces and routes, and zero socket descriptors. The
observer signs the sample and records it in its service journal with the digest
of the signed release attestation.

For #331, verify the journal signature with the configured observer public key,
then match the release digest to `observer_release_sha256` on the corpus
invocation in the authenticated SSH result. Verify the approval consumption,
output, telemetry and cleanup receipt for that same run. A missing live sample
leaves qualification incomplete. The sample
records process isolation at a point in time. The enforcement configuration and
channel-denial checks establish the rest of the network boundary. The dedicated
VM administrator controls the observer, its journal, and the enforcement policy.

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

An opt-in v2 provider gateway `POST` broker and signed dispatch emulator are
documented in [Operator Provider Gateway Boundary](PROVIDER_GATEWAY.md). They
do not change the deployed supervisor's v1 `GET`/`HEAD` operation contract or
establish a production provider route.

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

For an SSH request sent with the operator's opt-in `cops worker execute
--cancel-on-interrupt`, the relay uses cancellable framing rather than closing
its supervisor write side after the request. Once it has received the complete
frame, the supervisor treats EOF or surplus input on that authenticated relay
connection as a cancellation signal. It passes that signal only to an
offline-research worker request; a cancellable request for any other profile
fails closed. The worker completes mandatory cleanup before the supervisor
attests and returns the response. The relay and operator must verify that signed
response before treating cleanup as evidenced; an SSH disconnect or either
deadline expiring can leave the result unknown rather than proving cancellation
or cleanup. See [Remote Worker SSH Transport](REMOTE_WORKER_SSH_TRANSPORT.md)
for the operator behavior and no-retry rule.

The authority service must pin the supervisor worker process identity, including
its PID, before accepting a consume request. A restarted supervisor requires a
new authority binding. Starting the supervisor before the authority is ready is
safe because request execution fails closed until the authority socket and
identity checks pass; it is not evidence of execution readiness.

The supervisor CLI handles `SIGTERM` by completing its bounded active request,
closing its listener and removing the socket it bound. The authority's service
entry point can do the same by passing an event to
`ApprovalAuthorityServer.serve_forever(stop_requested=event)` and setting it
on `SIGTERM`. Give both services time to drain before escalation. After a forced
stop, a service manager may clear its dedicated runtime directory once all
processes from that service are gone. Keep the persistent worker cleanup
journal outside that directory. The supervisor recovers that journal before
opening its relay socket.

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
