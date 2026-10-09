# Remote Worker SSH Transport

`cops.execution.ssh_transport` provides the bounded application transport for a
remote isolated worker. Configure an absolute OpenSSH client path, one canonical
host, one expected worker identity, one remote command, and a dedicated
known-hosts file containing exactly one pinned host key.

The transport sends a single `cops.remote-worker/v1` JSON request on standard
input. The response must echo the request identifier, exact configured host, and
exact expected worker identity. The request and response payloads are otherwise
opaque to the transport; worker-side code remains responsible for verifying the
Action Plan authorization and consuming approval before execution.

The dispatcher must resolve `SSHRemoteEndpoint` from trusted worker inventory
using the worker identity bound into the approved plan. The host, port, username,
worker ID, known-hosts path, and remote command must not come from the dispatch
request. A missing inventory entry or identity mismatch fails before SSH starts.

The known-hosts file must be an owner-only regular file on POSIX systems. Use a
literal host entry from a trusted provisioning channel; wildcard, hashed, marker,
multi-host, and multi-entry files are rejected. Do not obtain or replace the pin
with `ssh-keyscan` inside the connection workflow, because an unauthenticated scan
does not establish the intended server identity.

OpenSSH is invoked in batch mode with strict host-key verification. User and
global SSH configuration, DNS host-key lookup, proxies, local commands,
forwarding, and TTY allocation are disabled. Request bytes, response bytes,
diagnostic bytes, and the total exchange duration are bounded. Timeout or output
overflow kills the SSH process group and discards retained output so a truncated
credential cannot reach an error or evidence record.

This control authenticates the configured SSH endpoint and the worker identity in
the application response. It does not prove that the remote worker consumed an
approval, entered its Linux sandbox, or mediated network egress; those checks stay
inside the worker. Run the client and worker under dedicated operating-system
identities and provision the SSH key, known-host pin, and worker identity outside
the request payload.
