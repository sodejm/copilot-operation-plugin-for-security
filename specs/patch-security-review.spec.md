# Patch security review

## Scope

The workbench reviews a local Git repository without executing its code. It resolves
the selected base and head to full commit IDs before reading a patch and bounded
source blobs. Repository data is untrusted. No output may include credential values.

## Requirements

- Reject oversized patches, too many changed files, large source blobs, binary
  patches, and output beyond fixed budgets.
- Inventory changed entrypoints and trust boundaries, and identify candidate
  source-to-sink paths with language-aware Python and JavaScript rules. A
  Python call affected by a changed line in its expression that posts a literal
  Microsoft Graph directory role assignment request is a privilege-change
  candidate, including calls at module level.
- Keep observed facts, plausible scenarios, unknowns, and validated findings
  distinct. A rule hit cannot validate exploitability. Analyst evidence must
  identify preconditions and disconfirming evidence before validation.
- Give each candidate and its recorded analyst assertion an explicit conditional
  impact and confidence. Impact describes what could happen if the stated
  preconditions hold; confidence describes only the static rule's evidence for
  the candidate pattern, not exploitability or likelihood.
- Reject validation of older or malformed candidate records missing a bounded
  impact string or the supported `limited` confidence value.
- Emit pinned commits and SHA-256 of the patch so a later review can detect drift.
- Include synthetic unsafe-input, privilege-change, and benign cases with
  reproducible changed-line records. No reviewed code is executed.

## Limitations

Rule coverage is deliberately bounded and incomplete; absence of a candidate is
not evidence that a patch is safe. Concurrent mutation of the local repository is
outside the current deployment guarantee.
