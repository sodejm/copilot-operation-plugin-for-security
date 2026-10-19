Feature: Web API inventory and approved request replay
  Scenario Outline: Preserve supported API inventory formats
    Given an API definition in <format>
    When the definition is imported
    Then the inventory preserves its endpoints and authentication metadata
    And credential values are redacted

    Examples:
      | format       |
      | HAR 1.2      |
      | OpenAPI 3    |
      | Swagger 2    |
      | Postman      |
      | raw HTTP     |

  Scenario: Preview is side effect free
    Given a replay request for an explicitly allowed destination
    When the operator previews the replay
    Then no request reaches the destination
    And the preview reports zero dispatched requests

  Scenario: Import input is bounded before parsing
    Given exact-limit and oversized API import sources
    When each supported format is imported offline
    Then the exact-limit source keeps its exact content digest
    And the oversized source fails without disclosing content or its path

  Scenario: Merged inventory provenance is lossless and stable
    Given repeated API sources with opaque provenance identities
    When the sources are imported in different orders
    Then every source provenance record is preserved including duplicates
    And the merged inventory identity is independent of order and timestamps

  Scenario: Provenance records are safe at every public boundary
    Given malformed path-bearing and digest provenance records
    When provenance deserialization and serialization are attempted
    Then every malformed provenance record is rejected without disclosure

  Scenario: Saved web API documents are bounded and validated before inspection
    Given exact-limit and oversized saved inventory documents
    When the saved inventories are loaded through the public document boundary
    Then the exact-limit saved inventory is accepted
    And the oversized saved inventory fails without disclosing content or its path

  Scenario: Public inventory labels cannot disclose source references
    Given inventory documents with unsafe public source labels
    When deserialization serialization and JSON inspection are attempted
    Then every unsafe public source label is rejected without disclosure

  Scenario: Authentication metadata is credential-free at every public boundary
    Given inventory documents and objects with unsafe authentication metadata
    When authentication deserialization serialization and JSON inspection are attempted
    Then every unsafe authentication mechanism is rejected without disclosure
    And declaration-only and digest authentication identities round trip

  Scenario: HAR standard authorization survives merge and preview
    Given separate HAR sources for one Bearer and one Basic route
    When the HAR inventories are merged and prepared for preview
    Then both mechanisms retain the Authorization header name
    And each authorization alternative has a distinct endpoint and matching session binding
    And preview uses scheme-prefixed redacted Authorization values
    And no plaintext credential enters inventory or preview evidence

  Scenario: Authenticated imports keep explicit session identity end to end
    Given authenticated HAR OpenAPI Postman and raw HTTP sources
    When the sources are imported serialized merged previewed and replayed offline
    Then every authenticated endpoint keeps its explicit matching session
    And Bearer Basic and API-key requests use only redacted placeholders
    And no plaintext credential enters persisted or replay evidence

  Scenario: Same-scheme sources remain distinct through merge
    Given duplicate and distinct sources using the same authentication scheme
    When the authenticated inventories are merged in different orders
    Then endpoint and session references remain valid and source scoped
    And the merged identity is stable without conflating credential contexts

  Scenario: Invalid endpoint session references fail closed
    Given inventories with missing malformed or conflicting endpoint session references
    When serialization request synthesis and deserialization are attempted
    Then each invalid association fails without disclosing source content

  Scenario: Live replay consumes exact approval
    Given an action plan bound to the exact request digests and destination
    And an approval authority receipt for that plan and worker identity
    And every request and redirect remains within engagement scope
    When the isolated worker executes the replay
    Then the approval is consumed once
    And the destination receives only the approved requests
    And the report redacts session credentials

  Scenario: Object authorization distinguishes owner, other user, and anonymous
    Given a vulnerable or corrected disposable API service
    When owner, other-user, and anonymous cases access the same object through REST and GraphQL
    Then owner access is allowed
    And anonymous access is denied
    And other-user access is a failure for the vulnerable service
    And other-user access is denied by the corrected service

  Scenario: Rate limit evidence is conclusive only after the configured threshold
    Given repeated requests from one bounded session
    When enough requests are observed
    Then missing throttling is a failure
    And an HTTP 429 response with retry guidance is a fix
    But too few observations are insufficient evidence
