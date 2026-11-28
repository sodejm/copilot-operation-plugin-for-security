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
   has a RunResult or a planning coverage row for its full, canonically equivalent
   target; a single-host row cannot represent a network-wide plan.
   Normalize single-address CIDRs
   to their host identity when detecting duplicate targets. A non-import
   RunResult cannot be reused across different scenarios in a saved report.
2. Provide a coverage row for each RunResult and distinguish planned, imported,
   laboratory and live provenance. Missing access, evidence or result is
   `not_assessed`; partial or imported evidence cannot become a complete live
   validation claim. Live evidence has an observation time inside the RunResult
   window; scanner-only assertions cannot establish assessed coverage. A
   non-scanner Finding can corroborate a scanner-associated row only when it is
   itself assessed, names that RunResult and scenario, covers each asset asserted
   by the scanner within the row, and shares validated evidence with the row.
   If corroboration fails, the row is partial and findings that depend on its
   assessed status cannot remain assessed.
3. Distinguish configuration observations, scanner assertions, observed behavior
   and reproduced attack paths. A reproduced path needs scoped, repeatable
   laboratory or live evidence and unique, acyclic Finding dependencies.
4. Include scope, coverage, affected assets, reproducibility, evidence strength,
   dependencies, remediation, uncertainty and limitations in both output forms.
   Contradictory findings stay unresolved; references with missing validated
   evidence cannot be assessed. Every assessed affected asset has linked evidence.
   Validate a saved output report's semantic joins and claims as well as its schema.
   A saved Finding's status, verification, and evidence-strength labels must agree:
   assessed/recorded, partial/limited, not_assessed/limited or missing, and
   contradicted verification with unresolved/contradicted or missing.
   `recorded`, `limited`, and `contradicted` strength require linked evidence.
   Saved scanner-associated coverage cannot become assessed without assessed
   non-scanner corroboration. Resultless coverage cannot carry evidence records.
   A partial Finding requires matching partial or assessed coverage; linked
   evidence on exclusively not_assessed coverage does not establish partiality.
   Each Finding retains an explicit limitation for affected assets lacking
   assessed coverage with linked evidence. A scanner assertion with partial
   coverage is the exception: partial records collection without independent
   corroboration, rather than absent collection for the named asset. The saved
   report retains the notice that record hashes do not prove source authenticity
   or authorization.
5. Omit source payloads, credential references, source locators and artifact
   paths. Escape caller-supplied Markdown text and control characters. Create new owner-only files and
   never overwrite an existing output.
6. Cross-format exports validate the saved assessment-report contract before
   rendering. Only an `assessed` / `verified` / `recorded` Finding is exported
   as verified. All other valid Findings stay inconclusive or contradicted:
   SARIF lowers them to notes, JUnit represents them as skipped rather than
   successful, and PR Markdown labels the conclusion explicitly. Exporters
   redact credential patterns and create local artifacts without posting or
   uploading them.
7. SARIF conforms to the official OASIS 2.1.0 schema and the fields documented
   by GitHub's supported subset. The portable gate must validate vulnerable,
   corrected and inconclusive exports offline against the bundled, hash-pinned
   official schema; missing schema bytes or validation dependencies fail the gate
   rather than skip it. Remote schema retrieval is forbidden. Optional source
   locations and every Markdown
   suggestion resolve against a full immutable Git commit, a repository-relative
   UTF-8 path and an existing line range. Before reading content, the exporter
   resolves each commit-and-path pair to one exact Git blob object with Git
   replacement objects disabled, verifies its type and declared size, and rejects
   non-blobs or blobs larger than 1 MiB without capturing their content. It reads
   content by that immutable object ID, also with replacement objects disabled,
   and keeps the read bounded to 1 MiB even if Git metadata disagrees with the
   returned body.
   The export records a digest of the committed lines and rejects unknown Findings,
   duplicate locations, traversal, invalid ranges and credential-bearing paths.

## Trust limits

Schema validity and hashes establish internal consistency and integrity, not
source authenticity, operator authorization, or live execution. The bundle is
caller supplied. Free-text fields and scope identifiers remain sensitive after
rendering; an operator reviews both outputs before sharing. A report describes
only supplied coverage rows and cannot establish exhaustive scenario coverage.

See the [operator guide](../docs/ENGAGEMENT_REPORTING.md) for input fields,
labels and command usage. See the [export guide](../docs/REPORT_EXPORTS.md) for
cross-format status mapping and revision-bound source anchors.
