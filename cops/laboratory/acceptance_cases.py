"""Stable case identifiers shared by the isolated gate and its host verifier."""

INTEGRATED_WORKFLOW_IDS = (
    "leaked-credential-blast-radius",
    "cve-reachability-triage",
    "illicit-consent-remediation",
    "detection-rule-ci-validation",
    "pre-release-exposure-audit",
)

ACCEPTANCE_CASE_IDS = (
    "offline-playback", "binary-evtx", "service-vulnerable", "service-corrected",
    "workflow-success", "workflow-failure", "workflow-cancellation",
    *("integrated-" + workflow_id for workflow_id in INTEGRATED_WORKFLOW_IDS),
)
