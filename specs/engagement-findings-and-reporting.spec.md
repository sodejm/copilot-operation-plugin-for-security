# Engagement findings and reporting specification

## Scope

The offline `cops.assessment-input/v1` bundle is a local join of existing
Engagement, ActionPlan, RunResult, Finding and `cops.evidence/v1` records. Its
output is `cops.assessment-report/v1` JSON and an escaped Markdown rendering.
`COPS-E17.01` is a provisional family identifier for this workflow, not a
canonical scenario mapping or an execution claim. No collector, network action,
authorization grant, or report publication occurs in this workflow.

## Acceptance contract

1. Validate every embedded contract and evidence envelope, reject duplicate
   identifiers and conflicting joins, and keep all reported targets within the
   Engagement's included scope and outside its exclusions. A RunResult has one
   provenance mode; planning coverage cannot reference a RunResult. An ActionPlan
   has a RunResult or a planning coverage row.
2. Provide a coverage row for each RunResult and distinguish planned, imported,
   laboratory and live provenance. Missing access, evidence or result is
   `not_assessed`; partial or imported evidence cannot become a complete live
   validation claim. Live evidence has an observation time inside the RunResult
   window; scanner-only assertions cannot establish assessed coverage.
3. Distinguish configuration observations, scanner assertions, observed behavior
   and reproduced attack paths. A reproduced path needs scoped, repeatable
   laboratory or live evidence and unique, acyclic Finding dependencies.
4. Include scope, coverage, affected assets, reproducibility, evidence strength,
   dependencies, remediation, uncertainty and limitations in both output forms.
   Contradictory findings stay unresolved; references with missing validated
   evidence cannot be assessed. Every assessed affected asset has linked evidence.
   Validate a saved output report's semantic joins and claims as well as its schema.
5. Omit source payloads, credential references, source locators and artifact
   paths. Escape caller-supplied Markdown text and control characters. Create new owner-only files and
   never overwrite an existing output.

## Trust limits

Schema validity and hashes establish internal consistency and integrity, not
source authenticity, operator authorization, or live execution. The bundle is
caller supplied. Free-text fields and scope identifiers remain sensitive after
rendering; an operator reviews both outputs before sharing. A report describes
only supplied coverage rows and cannot establish exhaustive scenario coverage.

See the [operator guide](../docs/ENGAGEMENT_REPORTING.md) for input fields,
labels and command usage.
