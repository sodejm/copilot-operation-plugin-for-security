# Graph rules and deterministic gates

The executable graph has typed `asset`, `data`, `service`, and `identity` nodes, finding-on-asset records, and directed `reachable_from`, `permission_to_act`, `accesses_data`, and `service_depends_on` relationships. The last relation is retained for business context but is not an attacker transition. Each traversed edge declares required capabilities and one resulting capability. A supported structural path still assumes successful exploitation of the starting finding. The engine does not infer exploitability, lateral movement, or control from a network/dependency edge.

Each gate has a machine-readable result in `report.json`. Blocking errors return a nonzero CLI status and no output directory.

| Gate | Input and check | Failure or uncertainty behavior |
|---|---|---|
| G1 input/schema | Manifest, file hashes, strict keys, UTC times, IDs, profile and scope | Reject with field location; no analysis. |
| G2 provenance/completeness | Source hash, pointer, scope, transform, count reconciliation | Quarantine unusable rows and report declared coverage separately; never promote unknown coverage to complete. |
| G3 graph/path | Endpoint type and direction, declared prerequisites, scope and observation window | Exclude invalid graph rows; mark missing capability and hypothetical transitions candidate; keep dead ends and depth limits. |
| G4 dedup/rank | Canonical signature: finding, target, ordered relation and asset sequence, preconditions, postconditions, support, missing capabilities, and scope | Merge equivalent routes while preserving all supporting evidence refs; sort supported and candidate separately. |
| G5 impact | Distinct supported assets/services, `read`/`modify`/`disrupt`, approved profile and service map | Emit bounded counts and potential CIA; `unrated` with missing profile. |
| G6 MITRE | Pinned local catalog version, exact ID, behavior evidence | Pending with no mappings while bundle is absent; behavior-free IDs are invalid. |
| G7 claim support | Rebuild each source record, accepted fact, graph relation, path, impact, and generated action from cited source snapshots and rules | Block report when a generated material claim differs from its source or deterministic rule. Free-form specialist claims require separate claim audit. |
| G8 reproducibility | Canonical JSON, cross-references, version and input/source/rule/profile hash record | Fail invalid references or serialization; repeated deterministic runs must have identical bytes. |

Ranking uses a published tuple, with separate classes: supplied crown-jewel priority (null last), descending evidenced asset count, descending count of services with observed direct dependencies on those assets, descending fraction of supported steps, then stable path ID. Business rating is presently `unrated` and therefore adds no ordering. Path length is not an ease-of-attack proxy. There is no likelihood model or hidden weight.

The blast radius counts distinct assets on the supported prefix of each path and distinct services with observed direct dependencies on those assets. A dependency is a structural relationship, not evidence that the service will be disrupted. These counts are not an inventory-wide estimate; longer service dependency chains are not traversed by this release. `read`, `modify`, and `disrupt` label potential confidentiality, integrity, and availability consequences; whether those become business impacts is a user and profile decision.

Specialists in `agents/` may challenge ambiguous judgments with citations. Their opinions never mutate gate outputs. A disagreement stays in a typed review record for human disposition. The CLI currently does not invoke specialists.
