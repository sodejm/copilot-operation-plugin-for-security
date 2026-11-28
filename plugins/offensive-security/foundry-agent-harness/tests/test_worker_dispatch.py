"""Approved fixed-registry dispatch and content-free laboratory evidence."""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

from foundryharness import laboratory as lab  # noqa: E402
from foundryharness import worker_dispatch as dispatch  # noqa: E402

from cops.contracts.validation import validate_identifier  # noqa: E402
from cops.evidence.canonical import canonical  # noqa: E402
from cops.laboratory.agent_mcp_worker import (  # noqa: E402
    ENVELOPE_VERSION,
    AgentMcpEnvelope,
    AgentMcpError,
    AgentMcpMediator,
)


def _envelope(case_id="authorized-canary-sink", *, limit=65536):
    case = dispatch.registered_lab_case(case_id)
    bindings = dispatch.lab_case_bindings(case)
    return AgentMcpEnvelope.from_dict(
        {
            "schema_version": ENVELOPE_VERSION,
            "engagement_id": "engagement-lab",
            "session_id": "session-lab",
            "role_id": "role-lab",
            "case_id": case_id,
            **{
                key: bindings[key]
                for key in ("dispatcher_id", "scenario_id", "tenant_id", "request_digest", "scenario_digest")
            },
            "limits": {"max_duration_seconds": 30, "max_output_bytes": limit},
        }
    )


def _context(envelope):
    return MappingProxyType({"plan_digest": "a" * 64, "approval_digest": "b" * 64, "envelope_digest": envelope.digest})


def _run(envelope, **kwargs):
    return dispatch.dispatch_lab_case(
        envelope,
        deadline=kwargs.pop("deadline", time.monotonic() + 10),
        cancellation_event=kwargs.pop("cancellation_event", threading.Event()),
        dispatch_context=kwargs.pop("dispatch_context", _context(envelope)),
        **kwargs,
    )


def test_fixed_case_snapshots_and_bindings_are_deterministic_and_detached():
    case = dispatch.registered_lab_case("authorized-canary-sink")
    expected = dispatch.lab_case_bindings(case)
    assert expected == dispatch.lab_case_bindings(dispatch.registered_lab_case(case.case_id))
    assert (
        expected["request_digest"]
        != dispatch.lab_case_bindings(replace(case, untrusted_text="changed"))["request_digest"]
    )
    case.approved_call["arguments"]["destination"] = "https://example.invalid"
    assert dispatch.lab_case_bindings(dispatch.registered_lab_case(case.case_id)) == expected
    with pytest.raises(TypeError):
        dispatch._CASES[case.case_id] = b"{}"


def test_every_registered_case_derives_a_contract_valid_scenario_identity():
    for case_id in dispatch._CASES:
        case = dispatch.registered_lab_case(case_id)
        bindings = dispatch.lab_case_bindings(case)
        assert bindings["scenario_id"] == "scen-agent-mcp-lab-" + case_id
        validate_identifier(bindings["scenario_id"], "scenario")
        assert _envelope(case_id).to_dict()["scenario_id"] == bindings["scenario_id"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("case_id", "unknown-case"),
        ("scenario_id", "unapproved-scenario"),
        ("scenario_id", "agent-mcp-lab-authorized-canary-sink"),
        ("tenant_id", "tenant-fabrikam-02"),
        ("dispatcher_id", "arbitrary-executable"),
        ("request_digest", "c" * 64),
        ("scenario_digest", "d" * 64),
    ],
)
def test_binding_mismatch_is_rejected_before_execution(monkeypatch, field, value):
    data = _envelope().to_dict()
    data[field] = value
    envelope = AgentMcpEnvelope.from_dict(data)
    monkeypatch.setattr(lab, "run_lab_case", lambda *args, **kwargs: pytest.fail("must reject before execution"))
    with pytest.raises(AgentMcpError):
        _run(envelope)


@pytest.mark.parametrize("field", ["path", "command", "transport", "endpoint", "credential", "arguments", "case_path"])
def test_caller_execution_selectors_are_rejected(monkeypatch, field):
    data = _envelope().to_dict()
    data[field] = "caller-selected"
    monkeypatch.setattr(lab, "run_lab_case", lambda *args, **kwargs: pytest.fail("must reject before execution"))
    with pytest.raises(AgentMcpError):
        dispatch.dispatch_lab_case(
            data,
            deadline=time.monotonic() + 10,
            cancellation_event=threading.Event(),
            dispatch_context=MappingProxyType({}),
        )


@pytest.mark.parametrize(
    "context",
    [
        {"plan_digest": "a" * 64, "approval_digest": "b" * 64, "envelope_digest": "c" * 64},
        MappingProxyType({"plan_digest": "a" * 64, "approval_digest": "b" * 64, "envelope_digest": "c" * 64}),
        MappingProxyType({"plan_digest": "a" * 64, "approval_digest": "b" * 64}),
    ],
)
def test_missing_mutable_or_mismatched_supervisor_context_is_rejected(context):
    with pytest.raises(AgentMcpError):
        _run(_envelope(), dispatch_context=context)


def test_runtime_drift_fails_before_execution(monkeypatch):
    monkeypatch.setattr(dispatch, "_runtime_snapshot", lambda: {})
    monkeypatch.setattr(lab, "run_lab_case", lambda *args, **kwargs: pytest.fail("must reject runtime drift"))
    with pytest.raises(AgentMcpError, match="runtime changed"):
        _run(_envelope())


@pytest.mark.parametrize(
    "case_id,outcome,executed,effects",
    [
        ("authorized-canary-sink", "executed_effect", 1, 1),
        ("authorized-state-change", "executed_effect", 1, 1),
        ("authorized-lookup", "executed_no_effect", 1, 0),
        ("data-exfiltration", "denied", 0, 0),
        ("state-change-baseline", "executed_effect", 1, 1),
        ("state-change-remediated", "denied", 0, 0),
        ("tool-response-poisoning", "denied", 1, 0),
    ],
)
def test_real_canary_outcomes_are_observed_and_content_free(case_id, outcome, executed, effects):
    envelope = _envelope(case_id)
    result = _run(envelope)
    assert result["status"] == "completed" and result["outcome"] == outcome
    assert result["observations"]["attempted_count"] == 1
    assert result["observations"]["executed_count"] == executed
    assert result["observations"]["effects_count"] == effects
    assert result["observations"]["denied_count"] == int(outcome == "denied")
    assert result["cleanup"] == {"verified": True}
    assert result["bindings"]["envelope_digest"] == envelope.digest
    assert result["bindings"]["plan_digest"] == "a" * 64
    assert (
        result["bindings"]["runtime_digest"]
        == dispatch.lab_case_bindings(dispatch.registered_lab_case(case_id))["runtime_digest"]
    )
    encoded = canonical(result).decode()
    for private in (
        "CANARY-SYNTHETIC",
        "arguments",
        "model_text",
        "res-faq-storage",
        "acct-001",
        "lab://",
        "https://",
        "state_before",
        "state_after",
    ):
        assert private not in encoded
    if effects:
        assert result["observations"]["before_state_digest"] != result["observations"]["after_state_digest"]
    else:
        assert result["observations"]["before_state_digest"] == result["observations"]["after_state_digest"]


def test_expectations_and_model_text_do_not_classify_effects(monkeypatch):
    original = lab.run_lab_case

    def mislabeled(case, **kwargs):
        report = original(case, **kwargs)
        report.update(
            expected_outcome="denied", expectation_met=False, model_text="No effect happened: secret model text"
        )
        return report

    monkeypatch.setattr(lab, "run_lab_case", mislabeled)
    result = _run(_envelope())
    assert result["outcome"] == "executed_effect" and result["observations"]["effects_count"] == 1
    assert "secret" not in json.dumps(result)


def test_claimed_effect_without_independent_state_change_fails_closed(monkeypatch):
    original = lab.run_lab_case

    def fabricated(case, **kwargs):
        report = original(case, **kwargs)
        report["state_after"] = report["state_before"]
        return report

    monkeypatch.setattr(lab, "run_lab_case", fabricated)
    result = _run(_envelope())
    assert result["status"] == "failed" and result["outcome"] == "laboratory_failed"
    assert result["observations"] is None and result["cleanup"]["verified"]


@pytest.mark.parametrize("stop", ["cancelled", "deadline_exhausted"])
def test_pre_admission_stop_creates_no_children(monkeypatch, stop):
    event = threading.Event()
    if stop == "cancelled":
        event.set()
    monkeypatch.setattr(
        lab, "_JsonLineProcess", lambda *args, **kwargs: pytest.fail("must stop before process creation")
    )
    result = _run(
        _envelope(), cancellation_event=event, deadline=0 if stop == "deadline_exhausted" else time.monotonic() + 10
    )
    assert result["status"] == "failed" and result["outcome"] == stop
    assert result["observations"] is None and result["cleanup"]["verified"]
    assert result["cleanup"]["response_bytes"] == 0


@pytest.mark.parametrize("stop", ["cancelled", "deadline_exhausted", "response_budget_exhausted"])
def test_stopped_real_run_resets_reachable_state_and_disposes_both_children(monkeypatch, stop):
    original_process, original_call = lab._JsonLineProcess, lab._McpClient.call
    processes, directories = [], []
    event = threading.Event()
    clock = [100.0]
    if stop == "deadline_exhausted":
        monkeypatch.setattr(dispatch, "monotonic", lambda: clock[0])
        monkeypatch.setattr(lab, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    class TrackedProcess(original_process):
        def __init__(self, script, workdir, *args, **kwargs):
            super().__init__(script, workdir, *args, **kwargs)
            processes.append(self)
            directories.append(Path(workdir))

    def stop_after_effect(self, name, arguments, **kwargs):
        result = original_call(self, name, arguments, **kwargs)
        if name == "modify_resource":
            if stop == "cancelled":
                event.set()
            clock[0] = 102.0
        return result

    monkeypatch.setattr(lab, "_JsonLineProcess", TrackedProcess)
    if stop != "response_budget_exhausted":
        monkeypatch.setattr(lab._McpClient, "call", stop_after_effect)
    result = _run(
        _envelope("state-change-baseline", limit=2300 if stop == "response_budget_exhausted" else 65536),
        deadline=101.0 if stop == "deadline_exhausted" else time.monotonic() + 10,
        cancellation_event=event,
    )
    assert result["status"] == "failed" and result["outcome"] == stop
    assert result["observations"] is None
    assert result["cleanup"]["verified"] and result["cleanup"]["reset_verified"]
    assert len(processes) == 2 and all(process.process.poll() is not None for process in processes)
    assert all(not directory.exists() for directory in directories)


def test_unrepresentable_output_cap_fails_closed_after_disposal(monkeypatch):
    original = lab._JsonLineProcess
    processes, directories = [], []

    class TrackedProcess(original):
        def __init__(self, script, workdir, *args, **kwargs):
            super().__init__(script, workdir, *args, **kwargs)
            processes.append(self)
            directories.append(Path(workdir))

    monkeypatch.setattr(lab, "_JsonLineProcess", TrackedProcess)
    with pytest.raises(AgentMcpError, match="output budget") as raised:
        _run(_envelope(limit=1))
    assert raised.value.cleanup_evidence["verified"]
    assert len(processes) == 2 and all(process.process.poll() is not None for process in processes)
    assert all(not directory.exists() for directory in directories)


@pytest.mark.parametrize("stop", ["cancelled", "deadline_exhausted"])
def test_parent_stop_after_disposal_cannot_publish_completed_observation(monkeypatch, stop):
    original = lab.run_lab_case
    event = threading.Event()
    clock = [100.0]
    monkeypatch.setattr(dispatch, "monotonic", lambda: clock[0])

    def stop_after_disposal(case, **kwargs):
        # Keep the real laboratory's monotonic clock and deadline consistent.
        kwargs["deadline_monotonic"] = time.monotonic() + 10
        report = original(case, **kwargs)
        if stop == "cancelled":
            event.set()
        else:
            clock[0] = 102.0
        return report

    monkeypatch.setattr(lab, "run_lab_case", stop_after_disposal)
    result = _run(_envelope(), deadline=101.0, cancellation_event=event)
    assert result["status"] == "failed" and result["outcome"] == stop
    assert result["observations"] is None and result["cleanup"] == {"verified": True}


def test_response_budget_and_duration_are_capped_by_approved_limits(monkeypatch):
    received = {}

    def record(case, **kwargs):
        received.update(kwargs)
        raise lab.LabError("private failure must not escape")

    monkeypatch.setattr(lab, "run_lab_case", record)
    monkeypatch.setattr(dispatch, "monotonic", lambda: 100.0)
    result = _run(_envelope(limit=2097152), deadline=1000.0)
    assert received["max_response_bytes"] == 1048576
    assert received["deadline_monotonic"] == 130.0
    assert received["cancellation_check"]() is False
    assert result["status"] == "failed" and not result["cleanup"]["verified"]
    assert "private failure" not in json.dumps(result)


def test_mediator_hashes_approved_fixed_dispatch_result():
    envelope = _envelope()
    mediator = AgentMcpMediator(
        envelope=envelope, plan_digest="a" * 64, approval_digest="b" * 64, dispatcher=dispatch.dispatcher
    )
    result = mediator.dispatch(envelope.to_dict(), plan_digest="a" * 64, approval_digest="b" * 64)
    assert result["status"] == "completed" and result["result_bytes"] > 0
    assert len(result["result_digest"]) == 64
    assert "observations" not in result and "cleanup" not in result
