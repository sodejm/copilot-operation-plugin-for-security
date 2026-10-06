Feature: Legacy Enterprise, Management, and Proxy Services Assessment
  As an authorized penetration tester or attack surface specialist
  I want protocol-specific assessment across enterprise storage, out-of-band hardware management, network appliance management, legacy VPN tunneling, and proxy egress services
  So that legacy privilege candidates are routed to takeover or egress pivoting workflows, proxy egress restrictions are verified, execution effects are plan-bound, canary artifacts generate verified cleanup receipts, and inaccessible services are never falsely reported as secure

  Scenario: Assessing legacy enterprise, management, and proxy services with protocol-specific collectors
    Given an approved target host exposing NDMP, iSCSI, IPMI, Cisco Smart Install, TACACS+, IKE, PPTP, SOCKS, and Squid
    When the legacy services assessment engine executes protocol-specific probes
    Then discrete assessments are recorded across enterprise storage, hardware out-of-band management, network device appliance, VPN tunneling, and proxy egress categories
    And observed configurations, authentication prerequisites, and versions are recorded for each legacy service

  Scenario: Testing proxy egress restrictions and evaluating internal network pivoting
    Given an evaluated proxy service on port 1080 or 3128
    When the proxy egress verification probe executes
    Then proxy egress testing is recorded as tested
    And open network relaying without destination restriction evaluates proxy egress restricted as False
    When a hardened proxy enforces client subnet allowlists and restricts loopback metadata egress
    Then proxy egress restricted evaluates as True

  Scenario: Enforcing truth-in-advertising boundary where inaccessible services are never reported as secure
    Given a legacy service that is filtered, connection-refused, or timed out
    When the legacy services assessment probe executes
    Then the service exposure status is strictly recorded as "inaccessible"
    And the service is never marked as "protected" or "hardened"
    And authentication prerequisite is recorded as "unknown" with explicit uncertainty notes

  Scenario: Classifying execution effects and enforcing action plan binding
    Given an assessment targeting exposed legacy services with code execution capabilities
    When the assessment executes without explicit code execution authorization
    Then code execution verification is skipped and recorded in uncertainty notes
    And the assessment can_execute_code flag is strictly False
    When explicit code execution authorization is granted in the plan
    Then code execution capability is verified and bound to the approved plan

  Scenario: Validating boundary controls using non-destructive canaries and generating verified cleanup receipts
    Given an assessment configured with canary identifier "canary_legacy_probe"
    When the legacy services assessment executes canary validation probes
    Then canary validation status is confirmed in the assessment record
    And a verified cleanup receipt with "verified_removed" status and receipt hash is emitted

  Scenario: Extracting legacy privilege candidates for storage takeover, BMC compromise, and proxy pivoting
    Given an evaluated target exhibiting exposed NDMP, open iSCSI, IPMI Cipher 0, Cisco Smart Install, open SOCKS, and open Squid
    When legacy privilege candidates are extracted
    Then actionable candidates for "ndmp_unauthenticated_access", "iscsi_unauthenticated_target", "ipmi_cipher_zero_bypass", "cisco_smart_install_rce", "socks_open_proxy", and "squid_open_proxy" are generated
    And each candidate contains service type, target host, port, execution effect, privilege impact, SHA-256 evidence hash, and remediation guidance

  Scenario: Reporting properly authenticated and hardened legacy services as protected or remediated
    Given a hardened server enforcing NDMP auth, iSCSI CHAP, disabled IPMI Cipher 0, disabled Cisco Smart Install, and restricted proxy ACLs
    When the legacy services assessment evaluates access controls
    Then the exposure status is reported as "protected"
    And authentication prerequisites reflect "chap", "rakp_hash", "user_password", or "acl_restricted"
    And zero unauthenticated legacy privilege candidates are generated
