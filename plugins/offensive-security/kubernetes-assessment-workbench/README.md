# COPS Kubernetes Assessment Workbench

This experimental package reconciles a **selected** Kubernetes context and
namespace scope against a sanitized local observation. It performs no network
requests, reads no kubeconfig, and never authorizes cluster execution.

## Local use

```bash
python3 -m cops demo kubernetes-assessment-workbench
python3 -m cops check kubernetes-assessment-workbench
python3 plugins/offensive-security/kubernetes-assessment-workbench/scripts/assess.py <sanitized-record.json>
```

The input has `schema_version: "1.0"`, `mode: "offline"`, a `plan`, and an
`observation`. The plan requires `approval_reference`, an exact `context` with
`name`, `cluster`, and `user`, explicit `namespaces`, and selected `surfaces`.
Supported surfaces are `api_server`, `namespaced_resources`, `control_plane`,
`nodes`, and `network`. An optional `identity_anchor` names a Namespace and its
UID. The observation requires `current_context` and a `contexts` inventory;
`namespace_access`, `surface_access`, `cluster_facts`, and an identity anchor
may be supplied. Access statuses are `accessible`, `denied`, or `unknown`;
surfaces may also be `unavailable`. Missing observations remain `unknown`.
Control-plane and node access facts accept `accessible`, `denied`, `unavailable`,
`managed_unavailable`, or `unknown`; every value other than `accessible` is
reported as a limitation.

See [`fixtures/synthetic/context.json`](fixtures/synthetic/context.json) for a
complete **synthetic** example. Gate semantics and misuse cases are documented
in the source repository at `specs/kubernetes-assessment-context.spec.md`.
Do not include credentials, kubeconfig,
server URLs, or real workload data in fixtures or published reports.

`matched_sanitized_export` means only that two local assertions agree on a
Namespace object UID. It is not proof of a universal cluster identity or fresh
live access. Unknown identity, namespace denials, managed control-plane limits,
and absent node access remain explicit. Every report sets
`live_execution_ready` to `false`. Host installation and live integration have
not been verified.
