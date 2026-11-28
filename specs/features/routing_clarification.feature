Feature: Clarify a security request using its evidence category
  Scenario: A vague request includes a source diff
    When I ask for help with a pull request diff and no stated goal
    Then the router asks for the desired outcome and identifies the application security specialist and its tool

  Scenario: A declared input conflicts with a clear goal
    When I request a high-confidence Sentinel query review with a source diff as input
    Then the router asks which outcome to prioritize without selecting a specialist
