Feature: Bounded binary Sysmon EVTX evidence import
  Scenario: Vulnerable and corrected binary counterparts
    Given hash-pinned synthetic EVTX files containing real binary event records
    When the registered pinned parser imports both files within its budgets
    Then the vulnerable file contains a PowerShell network indicator
    And the corrected file contains no matching indicator
    And both original files retain their hashes
    And exported evidence contains no command line or user path

  Scenario: Unsupported event evidence cannot pass
    Given an EVTX file containing only an unsupported Sysmon event
    When the file is imported
    Then its evidence is partial and its detection coverage is indeterminate

  Scenario: Corruption cannot be hidden by repinning the outer hash
    Given an EVTX file with modified event bytes and a newly computed SHA-256
    When the file is imported
    Then chunk integrity validation rejects it before starting the parser

  Scenario: Parser prerequisites and resource bounds fail closed
    Given an unavailable parser or a parsing deadline that expires
    When the file is imported
    Then the importer reports a stable limitation or failure code
    And the parser child is stopped and its private snapshot is removed
