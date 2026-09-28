Feature: Repository Scanning Edge Cases
  As a developer using the COPS Security Logging Advisor
  I want the scanner to gracefully handle massive files, large repos, and diverse languages
  So that it doesn't crash and provides a complete audit footprint.

  Scenario: Detect expanded language stack
    Given a workspace containing a Rust file "main.rs"
    And a C++ file "app.cpp"
    And a Ruby file "app.rb"
    And a PHP file "index.php"
    And a Java Spring Boot file "pom.xml"
    When the scanner script executes with target "."
    Then the JSON output "languages" must list "Rust"
    And the JSON output "languages" must list "C/C++"
    And the JSON output "languages" must list "Ruby"
    And the JSON output "languages" must list "PHP"
    And the JSON output "frameworks_and_libraries" must list "Java Framework: Spring Boot"

  Scenario: Prevent crash on massive files
    Given a workspace containing a massive 5MB file "massive.log"
    When the scanner script executes with target "."
    Then the scanner should complete successfully
    And the scanner must not throw a MemoryError

  Scenario: Limit maximum files scanned
    Given a workspace containing 15000 dummy files
    When the scanner script executes with target "."
    Then the scanner should complete successfully
    And the JSON output "scanned_files_count" should not exceed 10000

  Scenario: Skip a symbolic link without reading its target
    Given a workspace containing a symbolic link "package.json" to a file outside the workspace
    When the scanner script executes with target "."
    Then the scanner should complete successfully
    And the scanner reports "package.json" skipped with reason "symlink"
    And the scanner output must not contain the linked file content

  Scenario: Skip a FIFO without waiting for a writer
    Given a workspace containing a FIFO "config.env"
    When the scanner script executes with target "."
    Then the scanner should complete successfully
    And the scanner reports "config.env" skipped with reason "non_regular"

  Scenario: Skip file content that exceeds the byte limit
    Given a workspace containing an oversized config file "oversized.env"
    When the scanner script executes with target "."
    Then the scanner should complete successfully
    And the scanner reports "oversized.env" skipped with reason "too_large"
    And the JSON output "secrets_findings" must be empty

  Scenario: Preserve findings from bounded regular files
    Given a workspace containing a file "bounded.env"
    And "bounded.env" contains the line "db_password = 'FixturePassword123!'"
    When the scanner script executes with target "."
    Then the scanner should complete successfully
    And the JSON output "secrets_findings" must list a finding for "bounded.env"
    And the output JSON must NOT contain the string "FixturePassword123!"
