Feature: Supply-chain correction through an installed synthetic dependency
  The laboratory builds only reviewed synthetic wheels and installs them offline.

  Scenario Outline: Installed package behavior agrees with pinned advisory evidence
    Given the registered supply-chain laboratory has its pinned installer
    When the "<profile>" synthetic wheel is built and installed offline
    Then the installed package preserves the owner's permitted query
    And the installed injection exposes <rows> objects
    And the pinned advisory assessment is "<assessment>"
    And a modified wheel is rejected by the installer
    And missing dependency evidence remains unknown
    And the package service stops and its disposable installation is removed

    Examples:
      | profile    | rows | assessment |
      | vulnerable | 2    | matched    |
      | corrected  | 0    | clear      |
