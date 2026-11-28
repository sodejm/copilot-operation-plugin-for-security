# Kubernetes assessment context (E10.01 / issue #121)

## Scope

The workbench consumes one sanitized local JSON record containing an operator-approved
plan and an observed context inventory. It does not read kubeconfig, invoke kubectl,
contact a cluster, or grant execution authority. Approval references and observations
are operator assertions. The report is a deterministic offline reconciliation.

## Input and decision contract

- KAC-01: The plan names one context as an exact `(name, cluster, user)` tuple, one
  or more specific namespaces, one or more requested surfaces, and an approval
  reference. Missing context, wildcard namespaces, `all` namespaces, and unknown
  surfaces fail closed. No default or current context is selected implicitly.
- KAC-02: An observed current context must exactly match the approved tuple and
  appear once in the context inventory. Duplicate display names, even when their
  backing cluster or user differs, fail closed. A context switch fails closed.
- KAC-03: The plan and observation may provide an anchor Namespace name and UID.
  Matching pairs yield `matched_sanitized_export`; missing either pair yields
  `unresolved`. Conflicting pairs fail closed. A Namespace UID is an identity
  anchor for that object, not a Kubernetes-defined universal cluster UID.
- KAC-04: Each approved namespace is reported as accessible, denied, or unknown
  from the sanitized observation. A denied or absent observation is never treated
  as permission or proof of a secure namespace. Unapproved observed namespaces
  never expand assessment scope.
- KAC-05: Cluster version, distribution, runtime, node OS, network model, admission
  controls, control-plane access, node access, and surface access retain explicit
  `unknown` or `unavailable` values. Managed-control-plane and absent-node access
  do not imply hardened posture.
- KAC-06: Every report declares `live_execution_ready: false` and zero network
  requests. Stable-identity uncertainty is an explicit blocker. A separate,
  approved execution workflow must establish fresh identity and scope before any
  live operation.
- KAC-07: Input is bounded, parsed as JSON only, and never executed. Reject
  malformed, credential-bearing, or unsupported-mode records with stable errors.

## Threat and abuse cases

An operator could switch kubeconfig context between approval and observation,
reuse a display name for another cluster, omit namespace access, or mistake a
managed control plane for a hardened one. The importer rejects identity mismatch
and duplicate names and preserves denials and unknowns. Sanitized input must omit
tokens, certificates, raw kubeconfig, and server URLs; the importer rejects common
credential-bearing keys. An export cannot authorize execution or add namespaces.

## Evidence boundary

Synthetic fixtures demonstrate parser and reconciliation behavior only. They do
not establish cluster ownership, live access, host installation, node controls,
admission behavior, or Kubernetes security posture. The pinned E10.01 S01
scenario remains a planning reference; this change does not assert coverage for
S02-S13.
