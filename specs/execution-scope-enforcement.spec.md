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

## Deployment boundary

The mediator and broker are a capability for a contained worker. They do not remove an adapter's ambient network access by themselves. A deployment may claim mandatory egress mediation only after the worker derives the destination, identity, and exact request-target allowlists from consumed trusted authorization, passes only the broker capability into an operating-system network sandbox, and proves the child cannot open direct IPv4 or IPv6 sockets while broker traffic succeeds.
