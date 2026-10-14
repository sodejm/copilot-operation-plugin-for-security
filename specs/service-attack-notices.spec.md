# Service attack notices and conservative applicability

Issue #286 provides a versioned, offline registry of primary-source notices for
Windows, Linux-based appliances, and macOS services. The registry informs a
targeted investigation; it never asserts that a discovered port is vulnerable,
that a host was exploited, or that an action is authorized.

## Acceptance criteria

- The registry records each source's publication date, an exact observation
  date when supported or an explicit context when it is not, review dates,
  source type and URL, product/OS and version scope, service and transport, prerequisites,
  defensible ATT&CK mappings, detection and remediation advice, and limitations.
- Seed notices distinguish Storm-2570 post-compromise RDP/SMB behavior with
  unconfirmed initial access, Dell RecoverPoint for VMs CVE-2026-22769, and
  macOS Tahoe Screen Sharing CVE-2026-65400. Product-specific conclusions must
  remain product-specific.
- Offline assessment returns `candidate`, `fixed`, `not_applicable`, or
  `unknown` with reasons and a safe next action. A candidate means only that
  an investigator should verify the advisory against the asset. A port alone
  cannot produce a candidate. Missing evidence and unknown versions are
  `unknown`, not a presumed match.
- Withdrawn and superseded notices cannot generate candidates. Notices past
  their review due date require fresh source review before a candidate is emitted.
  Historical requests before the current source-review snapshot remain `unknown`.
- Registry validation rejects malformed/duplicate records and prerequisite keys,
  unsupported source URLs, invalid dates and version overlap. Inputs are bounded
  and parsed without network requests or code execution.
- The CLI provides machine-readable validation, listing, and assessment so a
  coordinator can consume the registry without a manual research step.
- Tests cover positive, fixed, wrong-product, insufficient, stale, withdrawn,
  and malformed cases using fixtures. No live host support is claimed.

## Scenarios

The [executable feature](features/service_attack_notices.feature) binds the
positive, port-only, version, non-candidate, and historical-request scenarios
to [pytest-bdd steps](../tests/step_defs/test_service_attack_notices_steps.py).
The source review dates are operational metadata; tests cannot prove that a
public advisory remains current. A maintainer must recheck cited primary
sources on the stated cadence and update the versioned registry.
