"""End-to-end evidence checks for the local synthetic agent and MCP laboratory."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

from foundryharness.laboratory import (  # noqa: E402
    LabError,
    _JsonLineProcess,
    _McpClient,
    load_lab_cases,
    run_lab_case,
)


def test_bundled_cases_observe_denial_effect_and_cleanup():
    case_schema = json.loads((PLUGIN_ROOT / "schemas" / "lab-case.schema.json").read_text())
    report_schema = json.loads((PLUGIN_ROOT / "schemas" / "lab-report.schema.json").read_text())
    for case_path in sorted((PLUGIN_ROOT / "lab_cases").glob("*.json")):
        jsonschema.validate(json.loads(case_path.read_text()), case_schema)

    cases = load_lab_cases(PLUGIN_ROOT / "lab_cases")
    expected_case_ids = {
        "authorized-canary-sink",
        "authorized-lookup",
        "authorized-state-change",
        "context-boundary",
        "cross-tenant",
        "data-exfiltration",
        "memory-boundary",
        "peer-agent-spoofing",
        "retrieval-poisoning",
        "state-change-baseline",
        "state-change-remediated",
        "tool-permission",
        "tool-response-poisoning",
    }
    assert len(cases) == len(expected_case_ids)
    assert {case.case_id for case in cases} == expected_case_ids
    results = {case.case_id: run_lab_case(case) for case in cases}

    assert all(result["environment_verified"] for result in results.values())
    assert all(result["cleanup_verified"] for result in results.values())
    assert all(result["expectation_met"] for result in results.values())
    assert all(result["mcp_protocol_version"] == "2025-11-25" for result in results.values())
    assert all(result["agent_origin"] == "deterministic-local-fixture" for result in results.values())
    jsonschema.validate(
        {
            "schema_version": "cops.agent-mcp-lab-run/v1",
            "environment": "local-synthetic-fixtures",
            "all_expectations_met": all(result["expectation_met"] for result in results.values()),
            "results": list(results.values()),
        },
        report_schema,
    )

    baseline = results["state-change-baseline"]
    remediated = results["state-change-remediated"]
    assert baseline["attempted_calls"] == remediated["attempted_calls"]
    assert baseline["executed_effects"]
    assert baseline["state_before"] != baseline["state_after"]
    assert remediated["denied_calls"]
    assert remediated["executed_effects"] == []
    assert remediated["state_before"] == remediated["state_after"]

    lookup = results["authorized-lookup"]
    assert lookup["executed_calls"]
    assert lookup["executed_effects"] == []
    assert lookup["state_before"] == lookup["state_after"]

    for result in results.values():
        if result["denied_calls"]:
            if result["case_id"] == "tool-response-poisoning":
                assert [call["name"] for call in result["executed_calls"]] == ["lookup_account"]
            else:
                assert result["executed_calls"] == []
            assert result["executed_effects"] == []
            assert result["state_before"] == result["state_after"]


def test_case_loader_rejects_untrusted_execution_configuration(tmp_path: Path):
    case = json.loads((PLUGIN_ROOT / "lab_cases" / "state_change_baseline.json").read_text())
    case["agent_command"] = ["sh", "-c", "echo unsafe"]
    (tmp_path / "case.json").write_text(json.dumps(case), encoding="utf-8")
    with pytest.raises(LabError, match="Unknown case fields"):
        load_lab_cases(tmp_path)


def test_mcp_reset_clears_injected_tool_response(tmp_path: Path):
    server = _JsonLineProcess("mcp_fixture_server.py", str(tmp_path))
    try:
        mcp = _McpClient(server)
        mcp.initialize()
        initial = mcp.call("lab/state", {})
        assert initial["tool_response"] == ""

        mcp.call("lab/configure", {"note": "synthetic untrusted note"})
        assert mcp.call("lab/state", {})["tool_response"] == "synthetic untrusted note"
        lookup = {"tenant_id": "tenant-contoso-01", "account_id": "acct-001"}
        assert mcp.call("lookup_account", lookup)["note"] == "synthetic untrusted note"

        mcp.call("lab/reset", {})
        assert mcp.call("lab/state", {}) == initial
        assert mcp.call("lookup_account", lookup)["note"] == ""
    finally:
        server.close()
