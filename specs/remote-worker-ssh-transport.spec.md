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

3. **Bounded exchange**
   - Request bytes, response bytes, diagnostic bytes, and total elapsed time are
     bounded before dispatch.
   - Timeout or output overflow terminates the SSH process group and suppresses
     retained output. Errors never include remote output, local paths, request
     payloads, or credentials.
   - Malformed JSON, a non-zero SSH exit, or a protocol or identity mismatch
     fails closed without returning a response payload.

## Security boundary

This module authenticates the configured SSH host key and application worker
identity. It does not replace worker-side authorization verification, approval
consumption, sandboxing, or egress mediation. The process must run under a
dedicated operating-system identity because a hostile same-UID process can alter
process memory or other files owned by that identity.
