Feature: Network Active Discovery and Service Identification
  As an authorized penetration tester or attack surface specialist
  I want bounded active port, protocol, and TLS assessment with explicit vantages, rate limits, and resumable checkpoints
  So that service identification distinguishes observed configs from inferred fingerprints, exposes visible uncertainty, and strictly bounds execution side effects

  Scenario: Bounded active port and TLS assessment with explicit scan vantage and rate limits
    Given an approved target list and port range with external vantage
    And an explicit rate limit of 50 probes per second and 2 second timeout
    When the active scanner executes against the target inventory
    Then discrete assessment records are generated for each approved port
    And each assessment specifies vantage, reachability, latency, and observed configuration

  Scenario: Resuming active scan without repeating completed side effects
    Given an interrupted active scan session with pre-recorded completed probe keys
    When the active scanner resumes execution from the session checkpoint
    Then previously completed probes are skipped
    And zero redundant probe side effects are dispatched to already assessed ports

  Scenario: Distinguishing reachable services, inferred fingerprints, and observed configuration with visible uncertainty
    Given target endpoints with varying service configurations and reverse proxies
    When the service identification engine evaluates observed response banners and TLS handshakes
    Then SSH banners produce high-confidence product and OS inferences
    And HTTP server headers fronted by reverse proxies record explicit uncertainty reasons
    And mismatched TLS certificate subjects lower inference confidence

  Scenario: Quarantining targets upon dynamic DNS shift or rebind detection
    Given an approved target hostname configured in scope
    When the hostname resolves to an IP address outside authorized CIDR boundaries
    Then the active scanner halts outbound probes to that target
    And records a "dns_rebind_detected" quarantine entry

  Scenario: Handling unreachable hosts and timed-out probes gracefully
    Given a target host with unreachable network routes and filtered ports
    When active probes are dispatched
    Then unreachable hosts are classified as reachability "unreachable"
    And timed-out ports are classified as port state "filtered" without halting overall scan progress

  Scenario: Checkpointing partial results upon execution budget exhaustion
    Given an active scan session with a tight overall execution time budget
    When the allocated time budget expires during execution
    Then the session status is marked "budget_exhausted"
    And partial assessment results up to the cutoff are preserved in the checkpoint

  Scenario: Verifying remediated exposures against baseline active assessment
    Given a baseline active scan session observing open vulnerable ports
    And a subsequent re-test session after security remediation
    When the active scan delta comparison is evaluated
    Then closed or filtered ports are identified as remediated exposures
    And an exact remediation rate percentage is calculated
