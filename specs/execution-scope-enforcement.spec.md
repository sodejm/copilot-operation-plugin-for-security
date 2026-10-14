# Execution Scope & Network Egress Enforcement Specification

## Title
COPS Execution Scope & Egress Guard (`[E02.03]`)

## Overview
Enforces actual network destinations and resource identities at execution time against authorized `cops.engagement/v1` boundaries.

## Rules & Mitigations

1. **Destination Boundary Validation**:
   - The HTTPS mediator validates IPv4, IPv6, hostname, and URL destinations immediately before each mediated connection.
   - Destinations must fall strictly within `included_targets` and outside `excluded_targets`.

2. **Cloud Metadata Exfiltration Guard**:
   - Outbound requests to link-local cloud instance metadata addresses (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) are blocked unconditionally to prevent SSRF credential theft.

3. **Anti-DNS Rebinding & Egress Pinning**:
   - Hostnames are resolved to IP addresses at execution time.
   - All resolved IP endpoints must satisfy authorized CIDR boundaries; domains resolving to private/metadata IPs trigger immediate rejection.

4. **Resource Identity Binding**:
   - A verified TLS peer must present exactly one canonical URI identity whose provider, service, account, tenant, cluster, namespace, and resource match an allowlisted identity.
   - Each identity is bound to an exact canonical request-target allowlist, preventing a shared service endpoint from reaching another account, namespace, resource path, or query.

5. **Bounded Mediation Protocol**:
   - Only HTTPS `GET` and `HEAD` operations with strict request framing are supported.
   - Redirects, resolution changes, peer-address changes, proxy/tunnel headers, metadata endpoints, malformed responses, and request or response limit overruns fail closed and produce redacted observations.
   - The broker bounds request count, aggregate bytes, and total protocol time for one operation.

6. **Operator Gateway POST Protocol (`cops.operator-gateway-dispatch/v2`)**:
   - Provider dispatch is a separate, versioned broker capability. It does not widen the `GET`/`HEAD` mediation protocol.
   - The capability permits exactly one HTTPS `POST` to one configured gateway origin and one exact request target. The worker does not receive a provider origin, provider credential, redirect destination, or proxy/tunnel capability.
   - The request body has a configured maximum byte length. The worker verifies its SHA-256 digest and byte length against the signed dispatch descriptor before the first byte leaves the broker.
   - The configured gateway TLS peer must present the exact allowlisted SPIFFE URI identity. Hostname, resolved addresses, connected peer address, origin, and request target remain subject to the existing scope and identity checks.
   - Redirect status responses, a changed origin or target, a second request, and every retry are rejected. A timeout or transport failure after transmission is recorded as an unknown outcome and is never resent.
   - A pre-send callback runs after all transport checks and immediately before bytes leave the broker. It is the only point at which a caller may consume a one-use authorization for the dispatch.

7. **Gateway Dispatch Binding and Replay Prevention**:
   - The dispatch descriptor binds a unique `dispatch_id`, authorization identifier, action-plan identifier and digest, worker SPIFFE identity, account, project, region, model, gateway endpoint identifier, exact request target, body SHA-256 digest, body byte length, issuance and expiry, and signing key identifier.
   - A gateway verifies the descriptor with a pinned Ed25519 public-key trust store. The gateway must not receive a worker-held shared signing secret; existing HMAC execution authorization remains an input to issuance, rather than a gateway-verification credential.
   - Before any upstream provider attempt, the gateway atomically claims `dispatch_id` durably. A replay or descriptor mismatch is rejected without an upstream attempt.
   - The gateway maps the endpoint identifier to the provider route and obtains its own scoped credential. Neither the worker request nor execution evidence may contain a provider credential, raw request body, authorization header, or raw provider response.

8. **Synthetic Gateway Emulator Boundary**:
   - The laboratory emulator is loopback-only and validates the signed descriptor, mTLS identity, fixed target, digest, size, replay behavior, and redacted receipt shape.
   - By default it has no provider credential resolver or forwarding path. A separately installed gateway-local handler may resolve an opaque credential reference for the exact verified endpoint only after the one-use grant is consumed, with a caller-supplied synthetic transport. This does not implement a production gateway service or provider route.
   - Its evidence records only identifiers, hashes, byte counts, decision codes, and bounded status metadata. Credential resolver and provider transport exceptions must not be exposed in receipts or chained public errors.

## Deployment boundary

The mediator and broker are a capability for a contained worker. They do not remove an adapter's ambient network access by themselves. A deployment may claim mandatory egress mediation only after the worker derives the destination, identity, and exact request-target allowlists from verified trusted authorization and the dispatch descriptor before consuming authorization, passes only the broker capability into an operating-system network sandbox, and proves the child cannot open direct IPv4 or IPv6 sockets while broker traffic succeeds.
