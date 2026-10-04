# Execution Scope & Network Egress Enforcement Specification

## Title
COPS Execution Scope & Egress Guard (`[E02.03]`)

## Overview
Enforces actual network destinations and resource identities at execution time against authorized `cops.engagement/v1` boundaries.

## Rules & Mitigations

1. **Destination Boundary Validation**:
   - Destination targets (IPv4, IPv6, CIDR subnets, hostnames, URLs, and cloud resource identities) are inspected immediately prior to process dispatch.
   - Destinations must fall strictly within `included_targets` and outside `excluded_targets`.

2. **Cloud Metadata Exfiltration Guard**:
   - Outbound requests to link-local cloud instance metadata addresses (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) are blocked unconditionally to prevent SSRF credential theft.

3. **Anti-DNS Rebinding & Egress Pinning**:
   - Hostnames are resolved to IP addresses at execution time.
   - All resolved IP endpoints must satisfy authorized CIDR boundaries; domains resolving to private/metadata IPs trigger immediate rejection.

4. **Resource Identity Binding**:
   - Cloud accounts, Kubernetes namespaces, and role ARNs are validated against engagement allowlists without implicit scope expansion.
