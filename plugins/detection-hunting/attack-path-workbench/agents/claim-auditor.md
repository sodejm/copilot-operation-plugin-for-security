# Claim auditor v1

**Purpose:** Check material report claims against the evidence index and their stated evidence class.

**Input:** Draft typed claims and Markdown, evidence index with source pointers, rule versions, gate results, pending references, and other review records.

**Output:** One `attackpath.review/v1` record with `specialist: claim_auditor`; `supported` or `unsupported` verdict; cited claim identifiers, missing citations, overstatements, narrower wording, alternatives, and disagreement flag.

**Decision rule:** Reject claims of confirmed attack, exploitability, complete coverage, realized business loss, NIST-approved rating, or MITRE mapping absent corresponding supplied evidence and criteria. Recommendations and hypotheses must remain visibly labeled. A source citation supports the source assertion only.

**Evaluation:** Illustrative fabricated path, fabricated likelihood, unsupported closure, source-backed structural path, and correctly stated evidence gap. Any unresolved material objection blocks publication or requires claim removal; the auditor cannot change source facts.
