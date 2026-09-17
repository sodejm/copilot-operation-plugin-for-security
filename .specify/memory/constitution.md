# COPS project constitution

The [root contributor contract](../../AGENTS.md) owns instruction precedence and
authorization. This document records COPS product constraints.

## Specification-driven development

Update the relevant `specs/` before changing behavior. Keep behavior requirements
and executable Gherkin scenarios in `specs/features/` aligned. Documentation and
configuration changes use focused checks. Do not mark acceptance criteria complete
without a matching scenario and current passing evidence; the existing package
validator alone does not prove scenario coverage. Keep
[project context](../project-context.md) current after architectural changes.
Use Conventional Commits when a commit is authorized. An explicit implementation
request authorizes in-scope local changes; hosted transitions follow root policy.

## Licensing and quality

Preserve the project [LICENSE](../../LICENSE) and imported
[third-party notices](../../THIRD_PARTY_NOTICES.md). Do not infer additional rights
from internal or enterprise use. Scanner and plugin validation runtime code uses
Python's standard library; test dependencies are separate. Add regression tests
for behavioral changes and run `make check` before handoff.

## Security logging

Never commit or emit matched credentials, secret-bearing endpoints, or raw PII.
Recommendations should include redaction of authorization headers, cookies and
credentials. Security events should capture UTC timestamps, event category,
pseudonymous actor references, action, target, and outcome. Review privacy and
retention requirements before implementing recommendations. Keep local scanning
and provider-mediated agent processing explicit in documentation.
