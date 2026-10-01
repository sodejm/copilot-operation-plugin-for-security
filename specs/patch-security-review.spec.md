# Patch security review

## Scope

The workbench reviews a local Git repository without executing its code. It resolves
the selected base and head to full commit IDs before reading a patch and bounded
source blobs. Repository data is untrusted. No output may include credential values.

## Requirements

- Reject oversized patches, too many changed files, large source blobs, binary
  patches, and output beyond fixed budgets.
- Inventory changed entrypoints and trust boundaries, and identify candidate
  source-to-sink paths with language-aware Python and JavaScript rules.
- Keep observed facts, plausible scenarios, unknowns, and validated findings
  distinct. A rule hit cannot validate exploitability. Analyst evidence must
  identify preconditions and disconfirming evidence before validation.
- Emit pinned commits and SHA-256 of the patch so a later review can detect drift.
- Include synthetic vulnerable and benign cases. No reviewed code is executed.

## Limitations

Rule coverage is deliberately bounded and incomplete; absence of a candidate is
not evidence that a patch is safe. Concurrent mutation of the local repository is
outside the current deployment guarantee.
