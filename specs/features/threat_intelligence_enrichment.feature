Feature: Read-only threat intelligence enrichment
  Scenario: Sensitive URL requires source-specific approval
    Given a URL with a path and query
    When the analyst has not approved a Microsoft lookup
    Then no request is sent and the lookup is privacy denied

  Scenario: Conflicting source claims remain separate
    Given MISP and TAXII claims for the same domain disagree
    When the claims are normalized
    Then each claim keeps its source and the result records a conflict

  Scenario: Cached intelligence exposes stale status
    Given a positive claim cached beyond its configured TTL
    When the analyst requests a cache-only lookup
    Then the result is labeled stale
