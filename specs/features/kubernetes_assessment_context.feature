Feature: Explicit offline Kubernetes assessment context
  Scenario: KAC-01 and KAC-02 require the approved context and namespaces
    Given a synthetic approved Kubernetes assessment record
    When the observed context switches to another cluster
    Then the importer rejects the context switch

  Scenario: KAC-02 rejects duplicate context display names
    Given a synthetic approved Kubernetes assessment record
    When another context reuses the selected display name
    Then the importer rejects the duplicate name

  Scenario: KAC-03 blocks uncertain identity
    Given a synthetic approved Kubernetes assessment record
    When the observed identity anchor is absent
    Then the report records unresolved identity and blocks live execution

  Scenario: KAC-04 preserves namespace denials and scope
    Given a synthetic approved Kubernetes assessment record
    When an approved namespace is denied and another is unapproved
    Then only approved namespaces appear and denial is visible

  Scenario: KAC-05 preserves managed control-plane and node limits
    Given a synthetic approved Kubernetes assessment record
    When managed control-plane and node access are unavailable
    Then the report records access limits without security conclusions

  Scenario: KAC-06 makes no network calls
    Given a synthetic approved Kubernetes assessment record
    When the record is assessed with network disabled
    Then the offline report is produced with no network requests
