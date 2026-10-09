# Remote Worker SSH Transport

`cops.execution.ssh_transport` provides the bounded application transport for a
remote isolated worker. Configure an absolute OpenSSH client path, one canonical
host, one expected worker identity, one remote command, and a dedicated
known-hosts file containing exactly one pinned host key.

The transport sends a single `cops.remote-worker/v1` JSON request on standard
input. The response must echo the request identifier, exact configured host, and
exact expected worker identity. `SSHExecutionDispatcher` also generates a fresh
exchange nonce for every invocation and verifies the supervisor's response
attestation before reconstructing the result. Worker-side code remains
responsible for verifying the Action Plan authorization and consuming approval
before execution.

Load the endpoint mapping with `SSHRemoteEndpointInventory.from_file`, then give
that verified object to `SSHExecutionDispatcher`. The inventory path, every
known-hosts path, and every response-attestation key path must be absolute. The
inventory must be an owner-only regular file and use this exact shape:

```json
{
  "schema_version": "cops.ssh-remote-endpoint-inventory/v1",
  "workers": [
    {
      "host": "worker.example.test",
      "known_hosts_path": "/etc/cops/ssh/worker.example.test.known_hosts",
      "attestation_key_id": "worker-lab-01-2026-01",
      "attestation_key_path": "/etc/cops/ssh/worker-lab-01.attestation.key",
      "port": 22,
      "remote_command": ["python3", "-m", "cops.remote_worker"],
      "username": "cops-worker",
      "worker_id": "worker-lab-01"
    }
  ]
}
```

The attestation key file contains exactly 64 lowercase hexadecimal characters
(32 bytes), is a regular file owned by the dispatcher process, and has no group
or other permissions. All path ancestors must resist replacement by the SSH
relay identity. Provision the same bytes only to the supervisor and the trusted
operator endpoint inventory; never put the key in a request, log, or diagnostic.
Rotate the key ID and key together.

Call `SSHRemoteDispatcher.request` with only the worker identity bound into the
approved plan, the opaque request payload, and the request identifier. The host,
port, username, worker ID, known-hosts path, and remote command cannot come from
the dispatch request. A missing inventory entry, unverified inventory lookalike,
duplicate identity, or malformed entry fails before SSH starts.

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

The supervisor attestation binds the fresh exchange nonce, endpoint host, worker
identity, authorization and plan digests, engagement and target, execution
limits, and exact result and approval receipt. A missing, stale, incorrectly
keyed, or altered response fails closed before the dispatcher accepts the result,
so the untrusted relay cannot forge successful SSH output. The symmetric verifier
key lets its holder create attestations, so protect the operator copy with the
same care as the supervisor copy. This control does not by itself prove sandbox
or egress configuration on a deployed host. Run the client and worker under
dedicated operating-system identities and provision the SSH key, known-host pin,
worker identity, and attestation key outside the request payload.
