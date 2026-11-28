Feature: Local push validation
  Contributors validate committed branch tips before updating a remote.

  Scenario Outline: Disposable remotes enforce the push contract
    Given the local push regression "<regression>"
    When the disposable push regression executes
    Then its remote-update assertions pass

    Examples:
      | regression                                             |
      | test_push_validates_selected_commit_when_head_differs   |
      | test_missing_tool_prevents_remote_update                |
      | test_checks_and_scanners_prevent_remote_update          |
      | test_branch_wide_requirement_survives_previous_push     |
