---
name: execution-scope-enforcement
description: Enforce network destinations and resource identities at execution time to prevent scope expansion and egress violations.
---

# Execution scope enforcement

Enforce execution-time destination and resource scope boundaries against `cops.engagement/v1` rules.

## Core Responsibilities

1. **Pre-Execution Destination Validation**:
   - Intercept IP addresses, subnets, hostnames, and URLs prior to execution.
   - Assert inclusion in authorized engagement CIDRs and domain names.
2. **Egress & Cloud Metadata Protection**:
   - Strictly block attempts to query sensitive cloud instance metadata addresses (`169.254.169.254`, `fd00:ec2::254`).
   - Block loopback destinations unless explicitly included.
3. **Anti-DNS Rebinding**:
   - Resolve hostnames to IP addresses prior to dispatch and assert that all resolved endpoints reside within in-scope networks.
4. **Cloud Resource Scoping**:
   - Enforce prefix and exact match boundaries on cloud ARNs, Azure resource IDs, and Kubernetes namespaces.

## Python API

```python
from cops.execution import ScopeDefinition, ScopeGuard, ScopeViolationError

# 1. Create scope definition from engagement contract
scope_def = ScopeDefinition.from_engagement_scope(engagement.scope)

# 2. Initialize ScopeGuard
guard = ScopeGuard(scope_def)

# 3. Check destination before execution
guard.check_destination("10.0.0.5")  # Succeeds
guard.check_destination("169.254.169.254")  # Raises ScopeViolationError
```
