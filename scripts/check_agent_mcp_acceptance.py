#!/usr/bin/env python3
"""Require complete disposable agent/MCP worker acceptance."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_TEST_ROOT = ROOT / "plugins/offensive-security/foundry-agent-harness/tests"
TEST_FILES = (
    PLUGIN_TEST_ROOT / "test_laboratory.py",
    PLUGIN_TEST_ROOT / "test_executable_contracts.py",
    PLUGIN_TEST_ROOT / "test_disposable_laboratory.py",
    PLUGIN_TEST_ROOT / "test_worker_dispatch.py",
    ROOT / "tests/test_agent_mcp_worker.py",
    ROOT / "tests/test_agent_mcp_worker_integration.py",
    ROOT / "tests/step_defs/test_agent_mcp_laboratories.py",
)
TIMEOUT_SECONDS = 180
REQUIRED_CASES = frozenset(
    {
        "test_bundled_cases_observe_denial_effect_and_cleanup",
        "test_v2_contract_is_immutable_and_legacy_remains_readable_only",
        "test_trace_redacts_secrets_and_canary_values_before_serialization",
        "test_vulnerable_corrected_and_remediated_cases_are_distinct_and_repeatable",
        "test_cancellation_interrupts_a_pending_response_and_terminates_child",
        "test_fixed_case_snapshots_and_bindings_are_deterministic_and_detached",
        "test_only_digest_metadata_survives_dispatch_and_capability_is_single_use",
        "test_fixed_registered_adapter_receives_only_completion",
        "test_dispatcher_failure_is_redacted_and_classified_uncertain",
        "test_worker_dispatches_fixed_capability_and_returns_only_digest_receipt",
    }
)


def validate_report(path: Path) -> int:
    """Reject partial, duplicated, skipped, or failed acceptance evidence."""
    try:
        root = ET.parse(path).getroot()  # noqa: S314 - trusted report from this gate's pytest child.
    except (OSError, ET.ParseError) as error:
        raise ValueError("acceptance report is missing or invalid") from error
    cases = list(root.iter("testcase"))
    names = [case.get("name") for case in cases]
    if (
        not cases
        or any(not name for name in names)
        or any(names.count(required) != 1 for required in REQUIRED_CASES)
        or root.find(".//skipped") is not None
        or root.find(".//failure") is not None
        or root.find(".//error") is not None
    ):
        raise ValueError("acceptance cases are incomplete, duplicated, skipped or failed")
    return len(cases)


def main() -> int:
    try:
        missing = [str(path.relative_to(ROOT)) for path in TEST_FILES if not path.is_file()]
        if missing:
            raise ValueError(f"acceptance test inventory is incomplete: {', '.join(missing)}")
        with tempfile.TemporaryDirectory(prefix="cops-agent-mcp-acceptance-") as directory:
            report = Path(directory) / "results.xml"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    *(str(path) for path in TEST_FILES),
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
        print(f"FAIL: agent/MCP {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "cases": count,
                "hosted_provider_claims": False,
                "isolation_qualified": False,
                "network_requests": 0,
                "scope": "disposable-stdio-only",
                "status": "passed",
                "worker_path_exercised": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
