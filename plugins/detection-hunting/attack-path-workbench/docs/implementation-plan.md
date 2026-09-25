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
