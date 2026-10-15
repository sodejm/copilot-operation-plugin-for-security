# Bounded Git History Scanner

`scripts/scan_git_history.py` inspects an explicitly supplied local Git work tree.
The root must be an absolute, canonical path to an ordinary checkout with a `.git`
directory. The scanner never searches parent directories, terminal history, sibling
repositories, or unrelated paths.

The scanner invokes the `git` executable with explicit argument arrays and a
restricted environment. It does not use a shell, execute repository scripts, or
access the network; lazy fetching of partial-clone objects is disabled. It rejects linked worktrees, configuration includes, alternate
object stores, symlinked roots, every symlink in Git metadata, and non-file metadata
entries. Git metadata validation stops at 250,000 entries. Symlink entries in commit
trees and paths containing control characters are skipped and recorded as coverage
limitations. Keep the repository unchanged for the duration of the read-only scan.

Use the default hard bounds or lower them for a smaller inspection:

```console
python3 scripts/scan_git_history.py \
  --root /absolute/path/to/synthetic-repository \
  --max-commits 100 \
  --max-files 5000 \
  --max-blob-bytes 1048576 \
  --max-total-bytes 16777216 \
  --max-matches 1000 \
  --timeout-seconds 30
```

The scanner recognizes only synthetic fixture values beginning with
`COPS_TEST_TOKEN_` or `COPS_SYNTHETIC_SECRET_`, followed by 16 to 128 safe test
characters. Output uses schema `cops.git-history-scan/v1`. Each observation contains
an opaque SHA-256 fingerprint, a safe path, a commit object ID, and Git blob source
provenance. A matched value is never returned. A path containing a matched synthetic
value is replaced by a path fingerprint.

Deleting a value from the current tree does not clear an older reachable commit.
The scanner reports that exposure and leaves containment unknown. It cannot establish
provider-side rotation or revocation; that needs
`registered-adapter:provider-revocation-check@1`. Empty repositories and scans that
reach a bound without finding a match return insufficient evidence. A complete
bounded scan with no recognized synthetic match is an observation about that bounded
local scope, not proof that credentials are absent elsewhere.
