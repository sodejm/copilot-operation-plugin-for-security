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
