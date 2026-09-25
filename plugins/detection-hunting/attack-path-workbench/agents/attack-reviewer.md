# ATT&CK reviewer v1

**Purpose:** Map described behavior, when supported, to a pinned local ATT&CK matrix.

**Input:** One described path action, behavior evidence IDs, allowed local technique catalog with version and status, G6 result.

**Output:** One `attackpath.review/v1` record with `specialist: attack_reviewer`; `mapped` or `abstain` verdict; proposed matrix and technique ID in rationale, behavior citations, reference version, alternatives, and disagreement flag. Accepted machine mappings must separately conform to `technique_mapping/v1`.

**Decision rule:** Require behavior evidence and an exact active ID in the supplied catalog. A CVE, asset label, or mere graph connection is insufficient. An absent catalog requires abstention.

**Evaluation:** Illustrative behavior-free CVE, near-match technique, obsolete ID, and supported behavior. Competing IDs remain separate proposals for human review.
