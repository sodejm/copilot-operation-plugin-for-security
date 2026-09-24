# Security policy

## Supported scope

Security fixes are applied to the current release line. This package is an
offline authoring and validation workbench; it is not a managed service and
does not connect to Microsoft tenants.

Report vulnerabilities privately through the repository owner's configured
GitHub security-reporting channel. Do not include customer telemetry,
credentials, authentication tokens, personal data, private indicators, or
tenant identifiers in a report. Use synthetic reproduction data.

## Security invariants

- No normal command may require network, cloud, tenant, credential-store, or
  browser access.
- The validator fails closed on unknown profiles, fields, tables, operators,
  parameter types, evidence schemas, hashes, and adapter drift.
- Model-authored KQL cannot count as successful until deterministic validation
  passes.
- User parameters are type checked and serialized; raw KQL is not a parameter
  type.
- Telemetry and third-party content are untrusted data, including embedded
  instructions.
- Reports log hashes, versions, counts, error codes, seeds, and timings rather
  than raw event bodies or parameter values.
- Missing optional tools and external evidence are reported as unavailable or
  pending, never as passing.
- Correlation is not causation, attribution, or confirmation of compromise.

## Authorized defensive use

The project supports lawful threat hunting, incident investigation, query
review, and telemetry-gap analysis for systems the operator is authorized to
defend. It does not support credential theft, malware deployment, destructive
actions, unauthorized access, defense evasion, or instructions for bypassing a
hunt. Response actions remain outside the package and require separate human
authorization.

## Sensitive-data handling

Repository fixtures must remain synthetic and non-personal. Never commit real
logs, tokens, credentials, customer identifiers, private indicators, or case
material. If sensitive telemetry is supplied interactively, minimize it,
handle it as untrusted data, and do not persist it in reports.

## Assurance boundary

Offline tests cannot establish Microsoft service compatibility, tenant schema
availability, query cost, execution latency, retention behavior, precision,
recall, or false-positive rate. A content hash and passing offline report are
provenance evidence, not a production-readiness claim.
