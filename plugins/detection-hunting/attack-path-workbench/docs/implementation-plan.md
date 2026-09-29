# Implementation state and required inputs

The repository specification and matching Gherkin feature preceded the code. The current package has a synthetic local intake profile, provenance records, graph/path engine, bounded blast radius, `unrated` impact, stable ranking, blocked query intent, JSON/Markdown reports, action ledger, specialist definitions, and positive/denial/recovery tests.

The following require supplied, approved inputs before implementation: real Wiz export mappings and query renderer; organization-approved NIST/business impact profile; pinned ATT&CK and Attack Flow reference bundle; agent execution/orchestration and human review workflow. The respective schemas and review contracts are extension points, not claims that these integrations run now.

## Open questions

1. Which redacted Wiz export versions, graph relationship definitions, and completeness guarantees will be approved?
2. Which crown-jewel identifiers, owners, service dependencies, priorities, and CIA objectives should an analysis use?
3. Which NIST publication and organization thresholds govern business-impact ratings, and who approves them?
4. Which ATT&CK matrix/version and Attack Flow bundle may be stored locally?
5. Which authorized validation tests and telemetry sources may substantiate closure?
6. Which person or process records and resolves specialist disagreements?

## Azure entitlement implementation (#26)

The additive Azure profile accepts SDK response pages and acquisition receipts,
normalizes tenant and scope relationships, evaluates bounded authorization paths,
exports evidence-linked reports and single-entitlement counterfactuals, and generates
read-only collection plans. Paired fixtures cover RBAC grants, application credentials,
VMs, Automation, Functions, Logic Apps, user-assigned identity attachment, federation,
and Lighthouse delegation. Acceptance scenarios also cover incomplete acquisition,
integrity failure, missing runtime context and alternate grants.

Live collection, Attack Flow serialization, and workflow automation remain separate
workstreams. This implementation authenticates to no service, sends no API requests,
retrieves no secrets, changes no entitlements, and executes no suggested remediation.
