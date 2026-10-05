Feature: Issue Documentation and Test Case Coverage Gate

  Scenario: Change contains both documentation and tests for an issue branch
    Given an issue branch "codex/issue-104-secret-guard"
    And modified files "docs/security-audit.md, tests/test_secret_guard.py, cops/execution/redaction.py"
    When issue coverage gate is evaluated with commit message "feat(redaction): harden secret redaction"
    Then the issue coverage check passes with issue identifier "104"

  Scenario: Change addresses an issue but lacks documentation
    Given an issue branch "issue-88-cve-scanner"
    And modified files "cops/capabilities/cve.py, tests/test_cve.py"
    When issue coverage gate is evaluated with commit message "fix: improve cve scan speed"
    Then the issue coverage check fails with error "Missing documentation changes for issue 88"

  Scenario: Change addresses an issue but lacks test cases
    Given an issue branch "issue-88-cve-scanner"
    And modified files "cops/capabilities/cve.py, docs/cve-scanner.md"
    When issue coverage gate is evaluated with commit message "feat: add cve scan capability"
    Then the issue coverage check fails with error "Missing test case changes for issue 88"

  Scenario: Pure refactor with explicit documentation exemption
    Given an issue branch "codex/refactor-adapters"
    And modified files "cops/adapters/registry.py, tests/test_adapter_registry.py"
    When issue coverage gate is evaluated with commit message "refactor(adapters): internal cleanup [skip-docs: internal refactor no user impact]"
    Then the issue coverage check passes with documentation exemption

  Scenario: Documentation only update with explicit test exemption
    Given an issue branch "docs/update-guide"
    And modified files "docs/plugin-guide.md"
    When issue coverage gate is evaluated with commit message "docs: update guide steps [skip-tests: doc only]"
    Then the issue coverage check passes with test exemption
