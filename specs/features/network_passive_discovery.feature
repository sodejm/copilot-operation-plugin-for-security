Feature: Network Passive Discovery and Scope Reconciliation
  As a perimeter security analyst
  I want multi-source passive asset telemetry normalized, deduplicated, and reconciled against engagement boundaries
  So that uncertain, stale, or conflicting ownership assets are quarantined and discovery cannot expand the engagement

  Scenario: Normalizing multi-source asset telemetry with cryptographic provenance
    Given raw DNS, certificate, IP allocation, endpoint, and cloud export records
    When the records are normalized into discovered assets
    Then each asset contains a canonical identifier and deterministic asset ID
    And each asset binds an immutable evidence provenance record with SHA-256 digest

  Scenario: Deduplicating multi-source assets preserves complete evidence lineage
    Given multiple telemetry records observing the same network asset
    When the discovery merger deduplicates the inventories
    Then a single consolidated asset is produced
    And all distinct evidence provenance envelopes are preserved

  Scenario: Quarantining assets with conflicting ownership
    Given two discovery records asserting contradictory ownership for the same domain
    When the assets are merged and reconciled against approved scope
    Then the asset is classified as "quarantined"
    And "conflicting_ownership" is recorded in quarantine reasons

  Scenario: Quarantining assets with stale or dangling pointers
    Given a DNS record with a dangling target pointer or expired certificate
    When the asset is reconciled against approved scope
    Then the asset is classified as "quarantined"
    And "stale_record" is recorded in quarantine reasons

  Scenario: Quarantining assets with absent provenance or uncertain ownership
    Given a discovered asset without valid evidence provenance or missing an owner
    When the asset is reconciled against approved scope
    Then the asset is classified as "quarantined"
    And the asset cannot expand engagement boundaries into verified status

  Scenario: Excluding assets matching explicit scope exclusions
    Given discovered assets matching explicit domain or CIDR exclusions
    When the assets are reconciled against approved scope
    Then the assets are classified as "excluded"
    And "explicitly_excluded" is recorded in quarantine reasons
