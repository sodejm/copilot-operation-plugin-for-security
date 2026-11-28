Feature: Bounded forensic image import
  Scenario: Import a collected raw image without changing it
    Given a raw image with pinned identity and complete custody
    When the image is imported
    Then its integrity is verified with explicit analysis limitations

  Scenario: Reject modified evidence
    Given a raw image with pinned identity and complete custody
    When the image bytes are changed before import
    Then import rejects the modified evidence
