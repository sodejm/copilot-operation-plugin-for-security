Feature: Repository Security Scanning
  As a developer using the COPS Security Logging Advisor
  I want to run a local repository scan
  So that I can identify code languages, cloud platforms, and prevent credential leaks.

  Scenario: Detect technology stack and cloud platform from HCL configuration
    Given a workspace containing a Terraform file "main.tf"
    And "main.tf" references the provider "aws"
    When the scanner script executes with target "."
    Then the JSON output "iac_and_cloud" must list "AWS"
    And the JSON output "languages" must list "HashiCorp Configuration Language (HCL)"

  Scenario: Prevent credential leakage in scanner output
    Given a workspace containing a file "config.env"
    And "config.env" contains the line "db_password = 'SuperSecretPassword123!'"
    When the scanner script executes with target "."
    Then the JSON output "secrets_findings" must list a finding for "config.env"
    And the "remediation" key must advise moving credentials to a secure vault
    And the output JSON must NOT contain the string "SuperSecretPassword123!"

  Scenario: Detect multi-language and Cloud provider indicators
    Given a workspace containing a Bicep file "deploy.bicep"
    And a package.json file containing dependency "aws-sdk"
    When the scanner script executes with target "."
    Then the JSON output "languages" must list "Bicep"
    And the JSON output "iac_and_cloud" must list "Azure Bicep"
    And the JSON output "iac_and_cloud" must list "AWS"
