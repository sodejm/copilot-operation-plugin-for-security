# Remote Worker SSH Transport Specification

## Title
COPS Remote Worker SSH Transport (`[E02.03]`)

## Overview

Defines the application transport boundary for sending one authorized worker
request to a remote execution worker. The transport is deliberately narrower
than SSH configuration in general: it sends one bounded, versioned JSON request
and accepts one bounded, versioned JSON response.

## Requirements

1. **Pinned SSH peer**
   - The caller supplies one dedicated OpenSSH known-hosts file containing one
     exact host and public-key pin.
   - The transport stages that pin in a private directory and invokes an
     absolute SSH executable with strict host-key checking, batch mode, DNS
     host-key lookup disabled, forwarding disabled, and proxy mechanisms
     disabled.
   - Wildcard, hashed, marker, multi-host, and non-matching known-host entries
     fail before SSH starts.

2. **Exact request binding**
   - Requests use the protocol identifier `cops.remote-worker/v1` and bind the
     request identifier, exact configured host, and exact expected worker
     identity.
   - The dispatcher resolves the endpoint from trusted worker inventory by the
     approved worker ID. Callers cannot select the host, username, known-hosts
     file, remote command, or response worker identity.
   - Responses must contain only the protocol identifier, request identifier,
     host, worker identity, and response payload. Every binding must match the
     request exactly before the response is returned to the caller.
   - The inventory is loaded only through `SSHRemoteEndpointInventory.from_file`
     from an absolute, owner-only regular file reached without following
     symbolic links. It uses the exact
     `cops.ssh-remote-endpoint-inventory/v1` schema, unique worker identities,
     and absolute known-hosts paths.
   - Directly constructed inventory objects, missing worker identities,
     duplicate identities, unknown fields, and malformed entries fail before
     the SSH process starts.

3. **Bounded exchange**
   - Request bytes, response bytes, diagnostic bytes, and total elapsed time are
     bounded before dispatch.
   - Timeout or output overflow terminates the SSH process group and suppresses
     retained output. Errors never include remote output, local paths, request
     payloads, or credentials.
   - Malformed JSON, a non-zero SSH exit, or a protocol or identity mismatch
     fails closed without returning a response payload.

4. **Restricted service sockets**
   - The supervisor and approval authority bind their Unix sockets with mode
     `0660` from creation using a restrictive bind umask.
   - Before listening, each service verifies that the new path is a Unix socket
     with mode `0660` and the configured owner and dedicated group. A mismatch
     stops startup.

## Security boundary

This module authenticates the configured SSH host key and application worker
identity. It does not replace worker-side authorization verification, approval
consumption, sandboxing, or egress mediation. The process must run under a
dedicated operating-system identity because a hostile same-UID process can alter
process memory or other files owned by that identity.

## In-flight cancellation

For an offline research plan, the operator may opt into cancellation by sending an ASCII `!` before the existing
newline-delimited request. This mode accepts one bounded JSON frame and holds the
SSH input channel open while the worker runs. The relay forwards the frame on its
authenticated supervisor socket and half-closes its write side on SSH input EOF
or further input. Further bytes cannot request any action. Existing callers
continue to submit a frame followed by EOF.

The supervisor treats write-side closure or further input on a cancellable
connection as cancellation. It checks cancellation before releasing a child
through the execution gate and during bounded child collection. Once an
authorization has been consumed, cancellation follows the worker's normal
result and durable cleanup path. The client continues reading within the
existing transport limits and verifies the signed result and cleanup receipt.
An interrupted or missing response does not establish that cleanup completed.
