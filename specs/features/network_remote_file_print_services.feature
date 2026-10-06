Feature: Network Remote Administration, File Sharing, and Printing Services Assessment
  As an authorized penetration tester or attack surface specialist
  I want protocol-specific assessment across remote administration, file sharing, and printing services
  So that host privilege candidates are routed to lateral movement specialists, canary files generate verified cleanup receipts, and inaccessible services are never falsely reported as secure

  Scenario: Assessing remote administration, file sharing, and printing services with protocol-specific collectors
    Given an approved target host exposing SSH, Telnet, RDP, VNC, WinRM, X11, SMB, NFS, FTP, rsync, and IPP
    When the remote services assessment engine executes protocol-specific probes
    Then discrete assessments are recorded across remote administration, file sharing, and printing categories
    And observed configurations, authentication prerequisites, and legacy versions are recorded for each service

  Scenario: Enforcing truth-in-advertising boundary where inaccessible services are never reported as secure
    Given a remote service that is filtered, connection-refused, or timed out
    When the remote services assessment probe executes
    Then the service exposure status is strictly recorded as "inaccessible"
    And the service is never marked as "protected" or "hardened"
    And authentication prerequisite is recorded as "unknown" with explicit uncertainty notes

  Scenario: Extracting host privilege candidates for lateral movement workflows
    Given an evaluated target exhibiting SMBv1, missing SMB signing, RDP without NLA, and NFS with no root squash
    When host privilege candidates are extracted
    Then actionable candidates for "smb_v1_enabled", "smb_signing_disabled", "rdp_nla_disabled", and "nfs_no_root_squash" are generated
    And each candidate contains service type, target host, port, lateral movement impact, SHA-256 evidence hash, and remediation guidance

  Scenario: Validating boundary controls using canary files and generating verified cleanup receipts
    Given an assessment configured with canary file "canary_share/audit.tmp"
    When the remote services assessment executes canary file boundary probes
    Then canary validation status is confirmed in the assessment record
    And a verified cleanup receipt with "verified_removed" status and receipt hash is emitted

  Scenario: Reporting properly authenticated and hardened services as protected
    Given a hardened server enforcing SSH public key authentication, RDP NLA, and SMB message signing
    When the remote services assessment evaluates access controls
    Then the exposure status is reported as "protected"
    And authentication prerequisites reflect "public_key", "nla_required", and "kerberos"
    And zero unauthenticated host privilege candidates are generated
