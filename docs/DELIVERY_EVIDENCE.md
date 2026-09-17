# Delivery evidence

Use exact language for exact states.

| State | Minimum evidence |
| --- | --- |
| Modified locally | current worktree diff |
| Validated locally | command, checkout, result, and relevant coverage |
| Committed | commit ID in the intended branch |
| Pushed | remote branch contains the commit |
| Open for review | pull request URL and head commit |
| Ready to merge | current required checks, reviews, threads, and mergeability |
| Merged | merge state and resulting default-branch commit |
| Released | authoritative release/tag/package evidence |
| Deployed | target-environment deployment and health evidence |

One row never proves a later row. Record skipped checks and environment blockers.
Sanitize evidence; paths, tokens, internal URLs, personal data, and proprietary logs
do not belong in public issues or pull requests.

For behavior changes, prefer red/green/refactor evidence when practical. For docs,
metadata, or configuration-only changes, use focused validation without inventing a
failing test.
