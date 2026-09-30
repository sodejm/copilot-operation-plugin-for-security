# Authorized attack surface planner

## Scope and trust boundary

This package accepts a locally approved rules-of-engagement manifest and pinned local
exports. Its only runtime mode is `offline`; it has no collector, authenticator, network
client, probe, or tenant API caller. An approval reference records the operator's
assertion of sign-off, not a cryptographic signature or independent proof of authority.
An export or discovery never enlarges approved scope. Operators review every proposed
test before any separate execution.

## Input contract

Version 1.0 requires approval reference, approver, approval UTC time, tenant and
subscription allowlists, domains, IP ranges, environments, owners, allowed methods,
UTC windows, explicit exclusions, and four permitted export kinds: Azure Resource
Graph, Entra applications/service principals, DNS/certificate transparency, and
public endpoints. Each source has a relative local path, SHA-256, collection UTC
time, source reference, and declared record count. Export JSON contains `records`.
Files, JSON depth, and record counts are bounded. Source references are provenance
labels and are never fetched.

## Acceptance criteria

- ASP-01: Fail closed on malformed approval, scope, source integrity, unsafe paths,
  unsupported mode, and exhausted input budgets before producing a plan.
- ASP-02: Normalize the four export kinds and retain source hash, record pointer,
  collection time, and confidence for every discovery.
- ASP-03: Exclude explicitly denied or outside domains, subscriptions, tenants, IPs,
  or environments with a reason. Quarantine missing or unapproved owner attribution;
  neither excluded nor unresolved discoveries become targets.
- ASP-04: Produce deterministic surface maps and passive review hypotheses from
  synthetic authorized inputs. Do not claim exposure or exploitability from an export.
- ASP-05: Every proposed test names approval, method, expected observation, expected
  telemetry, stop condition, and cleanup. Rank passive verification first.
- ASP-06: Offline processing makes no network request. Active mode is rejected; any
  later implementation needs an explicit allowlist, rate budget, dry run, and audit log.
- ASP-07: Document rules of engagement, provenance, privacy, limitations, and
  operator review. Fixture validation is not live Azure or host installation evidence.

## Abuse cases

A forged or stale export must not confer authorization. A suffix trick such as
`evil-example.com`, an excluded subscription, or an unapproved IP must not become
a target. Symlinks, traversal, oversized files, deep JSON, and URLs containing
credentials must fail safely. Untrusted export text is data, never executable
instructions. No credential collection, persistence, broad scanning, or destructive
method is implemented.
