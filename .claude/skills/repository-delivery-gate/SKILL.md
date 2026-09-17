---
name: repository-delivery-gate
description: Decide whether a repository change is ready for review, merge, release, deployment, or handoff using evidence proportionate to risk.
---

# Repository delivery gate

Evaluate the requested transition, not an assumed one.

- Scope: acceptance criteria are met and unrelated work is excluded.
- Artifact: exact diff, branch, commit, generated files, and migrations are known.
- Quality: focused checks and `make check` pass in the current checkout.
- Documentation: user, contributor, architecture, operations, and security impact
  is updated or a no-impact rationale is recorded.
- Security: secrets, dependencies, permissions, untrusted input, and abuse cases
  receive review proportionate to risk.
- Operations: rollout, compatibility, data migration, observability, and rollback
  are addressed when applicable.
- Hosted state: PR reviews, required checks, mergeability, release, and deployment
  are refreshed from authoritative sources when relevant.

Return one outcome: ready, ready with stated residual risk, or not ready with a
specific blocker. Keep local commit, pushed branch, open PR, merged PR, release,
and deployment states distinct. Do not perform the transition unless authorized.
