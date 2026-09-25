---
name: attack-path-review
description: Apply bounded specialist review to ambiguous path, impact, technique, action, and claim judgments without overriding deterministic gates.
---

# Specialist review

Select the narrow specialist in `agents/` and provide only this run's evidence packet, user context, and approved local reference bundles. Require a typed `attackpath.review/v1` response with prompt version, input hash, cited rationale, alternatives, and abstention when necessary. Save conflicting responses and human disposition separately.

Reviewers cannot create source facts, alter graph validity or impact ratings, or fill missing owner and deadline fields. A material unresolved claim-auditor objection blocks publication. See `agents/README.md` and `docs/gates.md`.
