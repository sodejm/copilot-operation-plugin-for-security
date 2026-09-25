# Deferred integration contracts

## Wiz

Input needed: representative redacted exports, field descriptions, relationship semantics and direction, export coverage rules, exact API/query operation, selectors, pagination, authentication, and approved documentation version. Until then, `query-intent` returns selectors, scope, requested fields/relations, and `[PENDING_WIZ_DOCS]` placeholders with `blocked_pending_docs`. No live adapter, credentials, renderer, or Wiz-specific parser is installed.

## Business impact

Input needed: user-defined crown jewels and priority, owner, service map, CIA objectives, the specific NIST publication and any other approved framework documents, organization impact criteria, thresholds, citations, and approval authority. `schemas/impact-profile-v1.schema.json` defines a future profile shape. The executable engine refuses a non-null impact-profile ID until implementation and review; it reports `unrated`. No illustrative scale is described as NIST compliant.

## MITRE

Input needed: approved locally available, version-pinned ATT&CK technique catalog and Attack Flow representation contract with usage terms. A mapping requires described adversary behavior, exact technique ID, matrix/version, and evidence. `technique_mapping/v1` is the interchange interface. The current engine emits no mappings and `pending_reference_bundle` for Attack Flow; it neither downloads a catalog nor guesses techniques from CVEs or asset names.

## Human review and remediation closure

The repository contains versioned specialist definitions and `attackpath.review/v1`. A future orchestrator must record prompt version, model settings, packet hash, cited opinion, disagreements, and human disposition. Publication is blocked by an unresolved material claim-auditor objection. Remediation closure needs the assigned owner and stated validation evidence from an authorized test or later observation; a recommendation or export date is insufficient.
