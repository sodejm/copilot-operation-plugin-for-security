# Sentinel Hunt Workbench v2 task record

## Implemented offline scope

- Twelve canonical hunts share the same static and fixture contract.
- Typed rendering, strict surface profiles, and fail-closed parameter binding.
- Deterministic canonical skill adapters for Codex, GitHub Copilot, and Claude Code.
- Package validation, unit/CLI regressions, full synthetic stress test, and release tooling.
- A stable ZIP archive, CycloneDX file SBOM, source provenance manifest,
  bounded secret scan, reproducible-build result, and content-addressed report.

## Required local completion checks

Run `make check` and `make release` from this directory. Inspect the generated
release report and verify that all local gates pass. The fixture evaluator must
record 576 curated scenarios, 3,000 generated perturbations, and 144 semantic
mutations, with 100% of critical mutations caught and at least 95% overall.

## External evidence still required

- Genuine 2,160-run cross-platform model evaluation under the protocol.
- Two distinct qualified human reviewers covering security, hunt quality,
  uncertainty language, and residual risk.
- A human source, authorship, redistribution, and license review.
- Authorized tenant validation before operational use, kept separate from
  offline qualification.

Do not mark missing evidence passed. `qualification_withheld` is the correct
release status while any required external record is absent or invalid.
