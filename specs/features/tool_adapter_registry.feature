Feature: Tool Adapter Registry and Parameter Validation

  Scenario: Assembling a valid command using a registered tool adapter
    Given the tool adapter registry is loaded
    When assembling command for tool "echo" and action "print_status" with parameter "message" as "safe test message"
    Then the assembled command line is:
      | echo | safe test message |

  Scenario: Rejecting command with shell injection characters
    Given the tool adapter registry is loaded
    When attempting to assemble tool "echo" and action "print_status" with parameter "message" as "hello; id"
    Then an adapter injection error is raised

  Scenario: Rejecting command with path traversal
    Given the tool adapter registry is loaded
    When attempting to assemble tool "echo" and action "print_status" with parameter "message" as "../../../sensitive"
    Then an adapter injection error is raised

  Scenario: Assembling nmap scan with typed parameters
    Given the tool adapter registry is loaded
    When assembling command for tool "nmap" and action "port_scan" with target "10.0.0.5" and ports "22,80,443"
    Then the assembled command includes target "10.0.0.5" and ports flag
