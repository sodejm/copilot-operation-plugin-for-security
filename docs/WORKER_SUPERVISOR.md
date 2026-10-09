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
  "schema_version": "cops.worker-supervisor-config/v1",
  "expected_host": "worker.example.test",
  "worker_identity": "worker-lab-01",
  "socket_path": "/var/lib/cops-supervisor/relay.sock",
  "relay_uid": 2101,
  "relay_gid": 2101,
  "supervisor_uid": 2102,
  "supervisor_gid": 2202,
  "authority_uid": 2103,
  "approval_socket_path": "/var/lib/cops-authority/control.sock",
  "inventory_path": "/etc/cops-supervisor/worker-inventory.json",
  "engagement_path": "/etc/cops-supervisor/engagement.json",
  "executable_sha256_pins": {}
}
```

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

Validate account ownership, socket modes, pinned process identity, installed
`bubblewrap`, and a real end-to-end request on the intended Linux host before
claiming deployment readiness. Repository tests cover boundary behavior but do
not prove that a particular host has been provisioned correctly.
