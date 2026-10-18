# Bounded Git History Scanner

`scripts/scan_git_history.py` inspects an explicitly supplied local Git work tree.
The root must be an absolute, canonical path to an ordinary checkout with a `.git`
directory. The scanner never searches parent directories, terminal history, sibling
repositories, or unrelated paths.

The scanner uses the registered `git-object-enumerator@1` adapter and requires an
operator-reviewed SHA-256 of the installed Git executable. It copies that
executable into a private directory, verifies the pin, and checks its version
before enumerating objects. Only relocatable Git 2.x builds are supported. A
missing or changed prerequisite fails closed; input artifacts cannot supply it.
Commands use typed argument arrays and a restricted environment. They do not use
a shell, execute repository scripts, or
access the network; lazy fetching of partial-clone objects is disabled. It rejects linked worktrees, configuration includes, alternate
object stores, symlinked roots, every symlink in Git metadata, and non-file metadata
entries. Git metadata validation stops at 250,000 entries. Symlink entries in commit
trees and paths containing control characters are skipped and recorded as coverage
limitations. Keep the repository unchanged for the duration of the read-only scan.

Use the default hard bounds or lower them for a smaller inspection:

```console
python3 scripts/scan_git_history.py \
  --root /absolute/path/to/synthetic-repository \
  --git-sha256 <reviewed-lowercase-sha256> \
  --max-commits 100 \
  --max-files 5000 \
  --max-blob-bytes 1048576 \
  --max-total-bytes 16777216 \
  --max-matches 1000 \
  --timeout-seconds 30
```

The scanner recognizes these bounded potential credential shapes:

| Pattern | Accepted shape |
| --- | --- |
| COPS test tokens | `COPS_TEST_TOKEN_` or `COPS_SYNTHETIC_SECRET_` with 16–128 safe test characters |
| GitHub classic PAT | `ghp_` with exactly 36 alphanumeric characters |
| AWS access-key identifier | `AKIA` with exactly 16 uppercase alphanumeric characters |
| Bearer credential | `Bearer` followed by 16–2048 token characters |
| PEM private key | Matching private-key labels and at most 128 base64 lines of 128 characters |

These are potential exposures requiring review. A pattern match does not prove
validity, and an AWS identifier alone cannot authenticate. Unsupported encodings,
provider token formats and malformed or oversized shapes remain outside coverage.
Output uses schema `cops.git-history-scan/v1`. Each observation contains
an opaque SHA-256 fingerprint, a safe path, a commit object ID, and Git blob source
provenance and a versioned pattern ID. A matched value is never returned. A path
containing a recognized credential shape is replaced by a path fingerprint.

Deleting a value from the current tree does not clear an older reachable commit.
The scanner reports that exposure and leaves containment unknown. It cannot establish
provider-side rotation or revocation; that needs
`registered-adapter:provider-revocation-check@1`. Empty repositories and scans that
reach a bound without finding a match return insufficient evidence. A complete
bounded scan returns `no_supported_match_observed` when it finds none of the
supported patterns. This describes only that bounded local scope and does not
prove the absence of other credentials.

The isolated service gate commits a synthetic credential, deletes it in a second
commit, and scans the historical blob. It proves the repository is unchanged and
uses that same credential for authenticated access, revocation, and an HTTP 401
after revocation. The runtime supplies a root-owned prerequisite pin recorded
during its reviewed image build. These results cover the synthetic pattern and
disposable service, not arbitrary provider credentials or production revocation.
