"""Strict contract acceptance; fixture digests are illustrative, never approval."""

import copy
import json
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_ROOT))

from foundryharness.models import (  # noqa: E402
    ExecutableScenario,
    ExecutionTrace,
    HarnessError,
    Scenario,
    TraceEvent,
    contract_digest,
)


def _scenario():
    return json.loads((PLUGIN_ROOT / "executable_scenarios/local_canary_read.json").read_text())


def _trace(terminal="tool_call_denied"):
    bindings = _scenario()["bindings"]
    common = {"bindings_digest": contract_digest(bindings), "summary": "Bounded fixture observation"}
    events = [
        {**common, "sequence": 0, "event_kind": "model_output", "output_digest": "1" * 64},
        {**common, "sequence": 1, "event_kind": "tool_call_attempted", "request_digest": "2" * 64},
    ]
    evidence = {"decision_digest": "3" * 64}
    if terminal == "tool_effect_executed":
        evidence = {
            "before_state_digest": "4" * 64,
            "after_state_digest": "5" * 64,
            "effect_count": 1,
            "observer_id": "fixture-observer",
        }
    events.append({**common, "sequence": 2, "event_kind": terminal, "request_digest": "2" * 64, **evidence})
    return {
        "schema_version": "foundry.execution-trace/v1",
        "trace_id": "trace-1",
        "bindings": bindings,
        "limits": {"max_trace_events": 16, "max_trace_bytes": 65_536},
        "events": events,
        "cleanup": {"verified": True, "before_state_digest": "4" * 64, "after_state_digest": "4" * 64},
    }


def test_v2_contract_is_immutable_and_legacy_remains_readable_only():
    source = _scenario()
    accepted = ExecutableScenario.from_dict(source)
    source["execution"]["request"]["profile_id"] = "changed"
    detached = accepted.to_dict()
    detached["bindings"]["tenant_id"] = "foreign"
    assert accepted.execution["request"]["profile_id"] == "fixture-read-canary"
    assert accepted.bindings["tenant_id"] == "fixture-tenant"
    with pytest.raises(FrozenInstanceError):
        accepted._json = "{}"
    legacy = json.loads(next((PLUGIN_ROOT / "scenarios").glob("*.json")).read_text())
    assert Scenario.from_dict(legacy).to_dict()["schema_version"] == "foundry.scenario/v1"
    with pytest.raises(HarnessError):
        ExecutableScenario.from_dict(legacy)
    with pytest.raises(HarnessError):
        Scenario.from_dict(_scenario())


@pytest.mark.parametrize(
    "path", [(), ("execution",), ("execution", "request"), ("bindings",), ("expected_outcome", "effect"), ("cleanup",)]
)
def test_executable_contract_rejects_unknown_fields_at_each_boundary(path):
    data = _scenario()
    target = data
    for key in path:
        target = target[key]
    target["unexpected"] = "unsupported"
    with pytest.raises(HarnessError):
        ExecutableScenario.from_dict(data)


@pytest.mark.parametrize(
    "mutation", ["legacy", "tenant", "envelope", "profile", "credential", "network", "command", "limits"]
)
def test_execution_rejects_stale_bindings_and_unsafe_request_data(mutation):
    data = _scenario()
    if mutation == "legacy":
        data["schema_version"] = "foundry.scenario/v1"
    elif mutation == "tenant":
        data["bindings"]["scenario_id"] = "another-scenario"
    elif mutation == "envelope":
        data["execution"]["request"]["request"]["nonce"] = "changed"
    elif mutation == "profile":
        data["execution"]["profile_id"] = "another-profile"
    elif mutation == "limits":
        data["execution"]["limits"]["max_duration_seconds"] = 301
    else:
        arguments = {
            "credential": {"api_key": "private"},
            "network": {"query": "https://example.invalid"},
            "command": {"shell": "echo private"},
        }[mutation]
        data["execution"]["request"]["request"]["arguments"] = arguments
        data["bindings"]["envelope_digest"] = contract_digest(data["execution"]["request"])
    with pytest.raises(HarnessError):
        ExecutableScenario.from_dict(data)


@pytest.mark.parametrize("field,value", [("network_egress", 0), ("required", 1), ("title", "Bearer privatecredential")])
def test_scenario_rejects_boolean_coercion_and_credentials_outside_arguments(field, value):
    data = _scenario()
    if field == "network_egress":
        data["execution"]["request"]["effect"][field] = value
        data["bindings"]["envelope_digest"] = contract_digest(data["execution"]["request"])
    elif field == "required":
        data["cleanup"][field] = value
    else:
        data[field] = value
    with pytest.raises(HarnessError):
        ExecutableScenario.from_dict(data)


@pytest.mark.parametrize("terminal", ["tool_call_denied", "tool_effect_executed"])
def test_trace_distinguishes_attempts_from_terminal_observations(terminal):
    data = _trace(terminal)
    trace = ExecutionTrace.from_dict(data)
    assert [item["event_kind"] for item in trace.to_dict()["events"]] == [
        "model_output",
        "tool_call_attempted",
        terminal,
    ]
    data["bindings"]["session_id"] = "changed"
    assert trace.to_dict()["bindings"]["session_id"] == "fixture-session"
    with pytest.raises(HarnessError):
        ExecutionTrace.from_dict(data)


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown",
        "raw_content",
        "sequence",
        "request",
        "observer",
        "cleanup",
        "events_budget",
        "bytes_budget",
        "after_terminal",
    ],
)
def test_trace_rejects_unbound_misclassified_or_unbounded_evidence(mutation):
    data = _trace("tool_effect_executed")
    if mutation == "unknown":
        data["unexpected"] = True
    elif mutation == "raw_content":
        data["events"][0]["raw_output"] = "private"
    elif mutation == "sequence":
        data["events"][1]["sequence"] = 5
    elif mutation == "request":
        data["events"][2]["request_digest"] = "9" * 64
    elif mutation == "observer":
        del data["events"][2]["observer_id"]
    elif mutation == "cleanup":
        data["cleanup"]["after_state_digest"] = "9" * 64
    elif mutation == "events_budget":
        data["limits"]["max_trace_events"] = 2
    elif mutation == "bytes_budget":
        data["limits"]["max_trace_bytes"] = 1
    else:
        data["events"].append(copy.deepcopy(data["events"][-1]))
        data["events"][-1]["sequence"] = 3
    with pytest.raises(HarnessError):
        ExecutionTrace.from_dict(data)


def test_trace_redacts_secrets_and_canary_values_before_serialization():
    data = _trace()
    data["events"][0]["summary"] = "Bearer sensitivecredential canary-private-value"
    result = ExecutionTrace.from_dict(data, redaction_values=("canary-private-value",)).to_dict()
    encoded = json.dumps(result)
    assert "sensitivecredential" not in encoded
    assert "canary-private-value" not in encoded
    event = result["events"][0]
    assert TraceEvent.from_dict(event).to_dict() == event


def test_trace_effect_count_is_an_integer_observation():
    data = _trace("tool_effect_executed")
    data["events"][2]["effect_count"] = True
    with pytest.raises(HarnessError):
        ExecutionTrace.from_dict(data)


def test_unsupported_feature_has_typed_content_free_evidence():
    data = _trace()
    data["events"] = [
        {
            "sequence": 0,
            "event_kind": "unsupported_feature",
            "bindings_digest": contract_digest(data["bindings"]),
            "summary": "Native hosted adapter unavailable",
            "reason_code": "unsupported-native-hosted-adapter",
            "decision_digest": "7" * 64,
        }
    ]
    assert ExecutionTrace.from_dict(data).to_dict()["events"][0]["event_kind"] == "unsupported_feature"
