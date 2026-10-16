# Assessment report exports

`cops.reports` converts a validated `cops.assessment-report/v1` object into
SARIF 2.1.0, JUnit XML, or local PR-ready Markdown. The exporters only create
artifacts. They do not post a review, upload SARIF, or contact a hosted service.

The common entry point is:

```python
from cops.reports import export_report

artifact = export_report(report, format="sarif")
```

`format` accepts `sarif`, `junit`, or `pr-markdown`. The return value is text;
the caller owns secure file creation and retention. The CLI writes a local
artifact from a saved assessment report:

```console
python -m cops report export --input assessment.json --format sarif --output findings.sarif
python -m cops report export --input assessment.json --format pr-markdown \
  --repository-root . --revision <full-commit-hash> --anchors anchors.json --output findings.md
```

The anchors file contains an object with an `anchors` array of source anchors.
`repository_root`, `revision`, and `source_anchors` are optional for SARIF and
unsupported for JUnit. PR Markdown requires the repository root and the full
40- or 64-character commit hash even when the report has no source anchors.

## Conclusion mapping

The exporters validate the saved assessment-report contract, including its
semantic status combinations, before rendering. They use this strict predicate
for a verified finding:

```text
assessment_status == assessed
and verification == verified
and evidence_strength == recorded
```

| Assessment conclusion | SARIF | JUnit | PR Markdown |
| --- | --- | --- | --- |
| Verified | Original severity and high precision | Failing test case | `Verified finding` |
| Unverified or partial | Note and low precision | Skipped test case | `Inconclusive finding` |
| Contradicted | Note and low precision | Skipped test case | `Contradicted finding` |

An inconclusive or contradicted finding therefore cannot become a SARIF error,
a successful JUnit test, or a verified Markdown heading. JUnit represents a
verified security finding as a failure because its presence is the failing
condition. It represents every other valid finding as skipped rather than
successful.

SARIF output uses the official OASIS SARIF 2.1.0 schema URL and the fields in
GitHub's documented supported subset. The emitted fields include `ruleId`,
`ruleIndex`, `level`, `message`, relative physical locations, and partial
fingerprints. COPS-specific properties retain the source assessment status,
verification, evidence strength, conclusion, and affected assets. See the
[OASIS schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json)
and [GitHub SARIF support reference](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

## Revision-bound source anchors

A source anchor has `finding_id`, repository-relative POSIX `path`, positive
`start_line`, optional `end_line`, and optional replacement text. The exporter
resolves the supplied revision as an exact commit, reads the file from that
commit with `git show`, verifies that the UTF-8 line range exists, and records a
SHA-256 digest of those committed lines. Paths containing traversal, absolute
locations, control characters, credential-shaped text, or platform-specific
separators are rejected. Duplicate and unknown-finding anchors are also
rejected.

PR Markdown emits a GitHub suggestion block only when an anchor has explicit
replacement text. The exporter validates the anchor and redacts known credential
patterns before rendering the replacement. The digest and immutable revision
make the artifact reviewable, but they do not prove that the source repository,
assessment evidence, or proposed remediation is trustworthy. Review the local
artifact before using it in a hosted workflow.

The option contracts are documented under
[`cops/reports/schemas`](../cops/reports/schemas/README.md). The portable
`make check` gate validates exports against the bundled, unmodified official
schema and GitHub subset. To run the focused check:

```bash
python -m pytest -q tests/test_report_exports.py
```

The tests pin the schema SHA-256, reject remote references, and use the declared
development `jsonschema` dependency. Missing prerequisites or modified schema
bytes fail rather than skip validation. Vulnerable, corrected and inconclusive
exports must conform; malformed versions, missing messages, invalid levels and
line numbers, and unregistered rule references must fail their respective checks.
No environment override or download is required. Runtime exporters retain their
standard-library implementation and supported-subset checks.
