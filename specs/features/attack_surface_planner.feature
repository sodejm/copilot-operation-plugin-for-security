Feature: Authorized offline attack surface planning
  Scenario: ASP-01 rejects unsafe or unapproved input
    Given a synthetic signed-off scope and four pinned local exports
    When an active mode or mismatched source hash is supplied
    Then the planner fails before producing a test plan

  Scenario: ASP-02 retains provenance
    Given a synthetic signed-off scope and four pinned local exports
    When the offline surface plan is generated
    Then every discovery retains source hash pointer time and confidence

  Scenario: ASP-03 enforces scope and attribution
    Given a synthetic signed-off scope and four pinned local exports
    When the offline surface plan is generated
    Then outside discoveries are excluded and ambiguous discoveries are unresolved

  Scenario: ASP-04 and ASP-05 produce repeatable passive plans
    Given a synthetic signed-off scope and four pinned local exports
    When the offline surface plan is generated twice
    Then the plans match and every proposal has permission telemetry stop and cleanup

  Scenario: ASP-06 makes no network requests
    Given a synthetic signed-off scope and four pinned local exports
    When the offline surface plan is generated with network disabled
    Then the plan succeeds without network activity
