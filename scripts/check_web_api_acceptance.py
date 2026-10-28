#!/usr/bin/env python3
"""Require complete local-service API acceptance, separate from offline package checks."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_FILE = ROOT / "plugins/offensive-security/web-api-assessment-workbench/tests/test_authorized_assessment.py"
WS_TEST_FILE = ROOT / "plugins/offensive-security/web-api-assessment-workbench/tests/test_authorized_websocket.py"
WORKER_TEST_FILES = tuple(
    ROOT / "tests" / name
    for name in (
        "test_web_api_replay_envelope.py",
        "test_web_api_worker_plan.py",
        "test_web_api_worker_integration.py",
        "test_web_api_worker_broker.py",
        "test_web_api_worker_qualification.py",
    )
)
TIMEOUT_SECONDS = 120
REQUIRED_CASES = frozenset(
    {
        "test_owner_other_and_anonymous_authorization_evidence[vulnerable-fail]",
        "test_owner_other_and_anonymous_authorization_evidence[corrected-pass]",
        "test_bounded_request_rate_evidence[vulnerable-fail]",
        "test_bounded_request_rate_evidence[corrected-pass]",
        "test_rate_limit_requires_enough_evidence",
        "test_plan_mismatch_is_rejected_before_approval_or_dispatch",
        "test_request_cannot_override_isolated_session_credentials",
        "test_approved_websocket_role_sessions_and_clean_close[vulnerable]",
        "test_approved_websocket_role_sessions_and_clean_close[corrected]",
        "test_operation_requires_new_envelope_and_matching_policy",
        "test_operation_requires_explicit_non_idempotent_execution",
        "test_session_credentials_bind_explicit_roles_and_references_without_values",
        "test_worker_keeps_credentials_and_body_on_trusted_broker_boundary",
        "test_fixed_registered_adapter_returns_only_broker_result",
        "test_completed_dispatch_with_adapter_exit_failure_is_uncertain",
        "test_worker_rejects_changed_context_before_provider_or_network[session_id]",
        "test_worker_rejects_changed_context_before_provider_or_network[role_id]",
        "test_receipt_digests_and_only_broker_capability_reach_worker_dispatch",
        "test_approval_retries_produce_exactly_one_web_api_exchange[concurrent-double-spend]",
        "test_approval_retries_produce_exactly_one_web_api_exchange[lost-response-retry]",
    }
)


def validate_report(path: Path) -> int:
    """Reject partial or inconclusive runs even if pytest returned success."""
    try:
        root = ET.parse(path).getroot()  # noqa: S314 - private report from this gate's trusted pytest child.
    except (OSError, ET.ParseError) as error:
        raise ValueError("acceptance report is missing or invalid") from error
    cases = list(root.iter("testcase"))
    names = [case.get("name") for case in cases]
    if (
        not REQUIRED_CASES.issubset(names)
        or len(names) != len(set(names))
        or any(not name for name in names)
        or root.find(".//skipped") is not None
        or root.find(".//failure") is not None
        or root.find(".//error") is not None
    ):
        raise ValueError("acceptance cases are incomplete, skipped or failed")
    return len(cases)


def main() -> int:
    try:
        with tempfile.TemporaryDirectory(prefix="cops-web-api-acceptance-") as directory:
            report = Path(directory) / "results.xml"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    str(TEST_FILE),
                    str(WS_TEST_FILE),
                    *(str(path) for path in WORKER_TEST_FILES),
                    "-q",
                    "--junitxml",
                    str(report),
                ],
                cwd=ROOT,
                check=False,
                timeout=TIMEOUT_SECONDS,
            )
            if result.returncode != 0:
                raise ValueError("acceptance subprocess failed or did not collect tests")
            count = validate_report(report)
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"FAIL: Web API {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {"status": "passed", "cases": count, "scope": "loopback-only", "isolation_qualified": False},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
