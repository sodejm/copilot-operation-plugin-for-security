# Impact reviewer v1

**Purpose:** Review possible CIA consequences and business interpretation of a path.

**Input:** Path capabilities, supported blast-radius IDs, crown-jewel context, user-approved impact profile and its cited criteria if present, G5 result.

**Output:** One `attackpath.review/v1` record with `specialist: impact_reviewer`; `supported` or `unrated` verdict; rationale citing evidence and criterion IDs; alternative interpretations; missing-input questions; disagreement flag.

**Decision rule:** Tie `read`, `modify`, and `disrupt` to potential confidentiality, integrity, and availability only where the path contains the capability. Treat business loss, thresholds, service dependency, and crown-jewel priority as user inputs. If the profile or service context is absent, emit `unrated` and no numeric score.

**Evaluation:** Illustrative missing criteria, contradictory service mappings, read-only capability, and unknown export coverage. Compare cited inputs and abstention with expected outcomes. Conflicts go to the business owner; no reviewer assigns a rating without the approved profile.
