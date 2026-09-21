Feature: Honest CVE reachability evidence reporting
  The helper checks report structure and local evidence integrity, not semantic truth.

  Scenario: Initialize an unresolved investigation
    Given an empty repository and evidence workspace
    When I initialize a report through the CLI
    Then the report is unresolved and the repository is unchanged

  Scenario: Check a report with intact evidence
    Given an empty repository and evidence workspace
    And a structurally complete report with captured evidence
    When I check the report through the CLI
    Then only structure and integrity are reported as checked

  Scenario Outline: Reject invalid evidence or reports
    Given an empty repository and evidence workspace
    And a structurally complete report with captured evidence
    And the report or evidence has "<defect>"
    When I check the report through the CLI
    Then the check fails without a traceback
    Examples:
      | defect               |
      | changed bytes        |
      | missing file         |
      | absolute path        |
      | parent escape        |
      | symlink escape       |
      | directory            |
      | oversized file       |
      | out of range lines   |
      | malformed line range |
      | null line bounds     |
      | duplicate id         |
      | unknown reference    |
      | invalid status       |
      | non-object report    |
      | malformed json       |
      | missing limitations  |

  Scenario Outline: Reject unsupported conclusions
    Given an empty repository and evidence workspace
    And a structurally complete report with captured evidence
    And the report or evidence has "<defect>"
    When I check the report through the CLI
    Then the check fails without a traceback
    Examples:
      | defect                   |
      | no path                  |
      | disconnected path        |
      | wrong sink               |
      | unresolved dispatch      |
      | no parameters            |
      | missing guard analysis   |
      | no review                |
      | no scope evidence        |
      | negative without proof   |
      | parameter sink mismatch  |
      | trigger without evidence |
      | impact without review    |

  Scenario: Reject an unevidenced execution claim
    Given an empty repository and evidence workspace
    And a structurally complete report with captured evidence
    And the report or evidence has "unevidenced execution"
    When I check the report through the CLI
    Then the check fails without a traceback

  Scenario: Resolve packaged workflow assets
    Then the manifests and workflow assets resolve consistently
