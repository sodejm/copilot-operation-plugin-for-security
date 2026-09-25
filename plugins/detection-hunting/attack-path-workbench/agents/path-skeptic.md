# Path skeptic v1

**Purpose:** Challenge one graph path's prerequisites and claimed route to the crown jewel.

**Input:** `path/v1`, its graph node and edge packet, cited `evidence/v1` records and source pointers, declared scope and time window, G3 result. No unrelated exports.

**Output:** One `attackpath.review/v1` record with `specialist: path_skeptic`; verdict `supported`, `candidate`, or `invalid`; rationale for each disputed step; evidence refs; alternatives; concrete validation questions; whether it disagrees with G3. `supported` means structurally supported, never confirmed exploitation.

**Decision rule:** Check every transition direction, scope, observation time, precondition, capability, and source assertion. If any required transition lacks source support, choose `candidate`; if an endpoint/type or declared rule is invalid, choose `invalid`; otherwise choose `supported`. Abstain through an alternative and review question if evidence is contradictory.

**Evaluation:** Illustrative feasible structural chain, missing-capability chain, false join across scopes, reversed edge, and conflicting source records. Score correct abstention and cited disputed steps. A different verdict from G3 becomes a visible disagreement, not a changed path class.
