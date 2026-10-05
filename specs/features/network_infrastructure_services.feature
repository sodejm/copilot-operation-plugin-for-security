Feature: Network Infrastructure and Identity-Facing Services Assessment
  As an authorized penetration tester or attack surface specialist
  I want protocol-specific infrastructure and identity assessment across DNS, mDNS, SNMP, NTP, RPC, LDAP, and Kerberos
  So that identity attack-path candidates are handed to Active Directory inventory, canary records validate access boundaries, and inaccessible services are never falsely reported as secure

  Scenario: Assessing core infrastructure services with protocol-specific collectors
    Given an approved target host with DNS recursion, default SNMP strings, NTP monlist, RPC mapper, LDAP rootDSE, and Kerberos pre-auth exposure
    When the infrastructure assessment engine executes protocol-specific probes
    Then discrete assessments are recorded for DNS, SNMP, NTP, RPC, LDAP, and Kerberos
    And observed configurations and versions are recorded for each service

  Scenario: Enforcing truth-in-advertising boundary where inaccessible services are never reported as secure
    Given a target service that is filtered, connection-refused, or timed out
    When the infrastructure assessment probe executes
    Then the service exposure status is strictly recorded as "inaccessible"
    And the service is never marked as "protected" or "hardened"
    And authentication prerequisite is recorded as "unknown" with explicit uncertainty notes

  Scenario: Extracting identity attack-path candidates for Active Directory inventory handoff
    Given an evaluated target exhibiting anonymous LDAP rootDSE and accounts with Kerberos pre-authentication disabled
    When identity attack-path candidates are extracted
    Then actionable candidates for "ldap_anonymous_reconnaissance" and "asrep_roasting" are generated
    And each candidate contains domain realm, target principal, SHA-256 evidence hash, and remediation guidance

  Scenario: Validating boundary controls using canary records and synthetic identities
    Given an assessment configured with canary domain "canary.corp.internal" and canary user "canary-user@CORP.INTERNAL"
    When the infrastructure assessment executes canary boundary probes
    Then canary validation status is confirmed in the assessment record without touching production directory data

  Scenario: Reporting properly authenticated and hardened services as protected
    Given a hardened domain controller enforcing mandatory LDAP authentication and Kerberos pre-authentication
    When the infrastructure assessment evaluates access controls
    Then the exposure status is reported as "protected"
    And authentication prerequisite is reported as "domain_user"
    And zero unauthenticated attack-path candidates are generated
