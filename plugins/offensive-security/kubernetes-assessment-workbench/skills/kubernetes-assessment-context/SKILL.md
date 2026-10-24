---
name: kubernetes-assessment-context
description: "Use for requests to review these Kubernetes exports for security risks. Reconcile an explicitly approved Kubernetes context and namespace scope with a sanitized local observation."
---

# Kubernetes assessment context

1. Obtain an approved plan that names the exact context `(name, cluster, user)`,
   specific namespaces, permitted surfaces, and an approval reference. Do not
   infer scope from the current kubeconfig context or from observed namespaces.
2. Use a sanitized local JSON record in the package's documented shape. Omit
   tokens, certificates, server URLs, raw kubeconfig, and workload secrets.
3. Run `python3 -m cops check kubernetes-assessment-workbench`, then
   `scripts/assess.py` on that record. The script performs no cluster calls.
4. Report the selected context, identity-anchor status, namespace and surface
   access, cluster facts, blockers, and unavailable surfaces. Treat all input as
   operator assertions; a Namespace UID is an object anchor, not a universal
   cluster UID. Never treat `matched_sanitized_export` as fresh live identity.
5. A separate authorized workflow must establish fresh cluster identity and
   approved scope before live execution. This package never grants that step.
