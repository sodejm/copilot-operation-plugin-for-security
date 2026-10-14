Feature: Conservative service attack notice assessment
  Scenario: Advisory context merits a targeted investigation
    Given a Dell RecoverPoint for VMs 6.0.3 asset with reachable Tomcat Manager
    When its service context is assessed offline
    Then the Dell notice is a candidate for targeted investigation
    And the result does not claim exploitability

  Scenario: A service port alone is insufficient
    Given an asset with only a TCP service observation
    When its service context is assessed offline
    Then no notice is a candidate
    And missing product, version, and configuration evidence is reported

  Scenario: Named vendor version is a candidate and unlisted version is unknown
    Given a Dell RecoverPoint for VMs 6.0.3.1 asset with reachable Tomcat Manager
    When its service context is assessed offline
    Then the Dell notice is a candidate for targeted investigation
    And an unlisted 6.0.2 version remains unknown pending product-specific source review

  Scenario: Fixed, unrelated, and stale contexts are not candidates
    Given fixed or unrelated assets or a notice past its review due date
    When their service contexts are assessed offline
    Then each result states why no current candidate is established

  Scenario: A historical request cannot use a future source review
    Given a Dell RecoverPoint for VMs 6.0.3 asset with reachable Tomcat Manager
    When its service context is assessed before the registry review date
    Then the Dell notice is unknown pending a historical source snapshot
