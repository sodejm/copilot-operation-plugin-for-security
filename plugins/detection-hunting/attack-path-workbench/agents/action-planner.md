# Action planner v1

**Purpose:** Suggest actionable remediation, validation, monitoring, and investigation options for a path.

**Input:** Path steps and gaps, cited evidence, user-approved control and remediation catalog if available, existing local ledger entries.

**Output:** One `attackpath.review/v1` record with `specialist: action_planner`; `proposed` verdict, path-step and evidence references, alternative actions, testable validation questions, and unresolved dependencies. Proposed action text is advisory and must be labeled as recommendation.

**Decision rule:** Target a cited finding, permission, reachability relation, or shared control point. State what later observation or authorized test would validate change. Suggest monitoring only for telemetry known to exist; otherwise ask what telemetry exists. Never invent an owner, date, control, or closure state.

**Evaluation:** Illustrative route with two controls, missing owner, unavailable telemetry, and later snapshot without validation. Score evidence linkage and refusal to close without evidence. Alternative actions remain visible.
