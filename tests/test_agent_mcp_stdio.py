from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from cops.adapters import (
    ExecutableVerification,
    ToolActionDefinition,
    ToolAdapter,
    ToolAdapterRegistry,
    ToolParameter,
)
from cops.contracts.models import ActionPlan
from cops.laboratory.agent_mcp_stdio import (
    StdioProfileError,
    compile_stdio_action_plan,
    validate_stdio_action_plan,
)


def _registry(tmp_path: Path) -> ToolAdapterRegistry:
    registry = ToolAdapterRegistry(definitions_path=tmp_path / "no-definitions")
    registry.register_adapter(
        ToolAdapter(
            tool="fixture-agent",
            version="1.0.0",
            binary="fixture-agent",
            provenance={
                "source": "fixture-owned",
                "license": "MIT",
                "pinned_revision": "a" * 64,
            },
            supported_environments=["darwin", "linux"],
            actions={
                "invoke": ToolActionDefinition(
                    action="invoke",
                    description="Execute one bounded stdio request",
                    base_args=["--request-b64"],
                    parameters={
                        "request_b64": ToolParameter(
                            name="request_b64",
                            param_type="string",
                            required=True,
                            regex_pattern=r"[A-Za-z0-9_-]+",
                        )
                    },
                )
            },
            executable_verification=ExecutableVerification(
                sha256="b" * 64,
                version_args=("--version",),
                version_pattern=r"fixture-agent (?P<version>[0-9.]+)",
            ),
        )
    )
    return registry


def _profile() -> dict[str, object]:
    return {
        "schema_version": "cops.agent-mcp-stdio-profile/v1",
        "profile_id": "fixture-read-canary",
        "target": "local-stdio-fixture",
        "adapter": {
            "tool": "fixture-agent",
            "tool_version": "1.0.0",
            "action": "invoke",
            "protocol_version": "2025-11-25",
            "source_revision": "a" * 64,
            "executable_sha256": "b" * 64,
            "request_parameter": "request_b64",
        },
        "effect": {"classification": "read_only", "network_egress": False},
        "request_contract": {
            "method": "tools/call",
            "tool_name": "canary/read",
            "arguments": {"query": "status"},
        },
        "limits": {"max_duration_seconds": 30, "max_output_bytes": 65_536},
    }


def _request() -> dict[str, object]:
    return {
        "schema_version": "cops.agent-mcp-stdio-request/v1",
        "request_id": "request-1",
        "method": "tools/call",
        "tool_name": "canary/read",
        "arguments": {"query": "status"},
        "nonce": "fixture-nonce-1",
    }


def _decode_envelope(encoded: str) -> dict[str, object]:
    padding = "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded + padding))


def _compile(
    registry: ToolAdapterRegistry,
    *,
    profile: dict[str, object] | None = None,
    request: dict[str, object] | None = None,
) -> ActionPlan:
    return compile_stdio_action_plan(
        profile=_profile() if profile is None else profile,
        request=_request() if request is None else request,
        registry=registry,
        plan_id="plan-stdio-1",
        engagement_id="eng-stdio-1",
        scenario_id="scen-stdio-1",
        target="local-stdio-fixture",
        specialist_id="agent-mcp-laboratory",
        created_at="2026-10-16T12:00:00Z",
    )


def _rebuild_with_envelope(plan: ActionPlan, envelope: dict[str, object]) -> ActionPlan:
    data = plan.to_dict()
    encoded = (
        base64.urlsafe_b64encode(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    data["operations"][0]["arguments"]["request_b64"] = encoded
    return ActionPlan.create(
        plan_id=data["plan_id"],
        engagement_id=data["engagement_id"],
        scenario_id=data["scenario_id"],
        target=data["target"],
        specialist_id=data["specialist_id"],
        operations=data["operations"],
        limits=data["limits"],
        credential_references=data["credential_references"],
        created_at=data["created_at"],
    )


def test_compile_stdio_request_binds_trusted_profile_to_action_plan(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    plan = _compile(registry)

    data = plan.to_dict()
    operation = data["operations"][0]
    assert operation["tool"] == "fixture-agent"
    assert operation["tool_version"] == "1.0.0"
    assert operation["action"] == "invoke"
    assert data["limits"] == {
        "max_duration_seconds": 30,
        "max_output_bytes": 65_536,
        "egress_allowed": False,
    }

    envelope = _decode_envelope(operation["arguments"]["request_b64"])
    assert envelope["schema_version"] == "cops.agent-mcp-stdio-envelope/v1"
    assert envelope["request"] == _request()
    assert envelope["adapter_binding"] == {
        "protocol_version": "2025-11-25",
        "source_revision": "a" * 64,
        "executable_sha256": "b" * 64,
    }
    assert envelope["effect"] == {
        "classification": "read_only",
        "network_egress": False,
    }
    assert validate_stdio_action_plan(plan=plan, profile=_profile(), registry=registry) == envelope


def test_compile_rejects_request_owned_effect_classification(tmp_path: Path) -> None:
    request = _request()
    request["effect"] = {"classification": "state_changing"}

    with pytest.raises(StdioProfileError, match="unexpected=.*effect"):
        _compile(_registry(tmp_path), request=request)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("method", "resources/read"),
        ("tool_name", "canary/write"),
        ("arguments", {"query": "other"}),
        ("arguments", {"query": "status", "destination": "https://example.invalid"}),
    ],
)
def test_compile_rejects_request_outside_exact_contract(tmp_path: Path, field: str, value: object) -> None:
    request = _request()
    request[field] = value
    with pytest.raises(StdioProfileError, match="differ[s]? from trusted contract"):
        _compile(_registry(tmp_path), request=request)


def test_compile_rejects_json_boolean_integer_ambiguity(tmp_path: Path) -> None:
    profile = _profile()
    profile["request_contract"]["arguments"] = {"enabled": True}
    request = _request()
    request["arguments"] = {"enabled": 1}
    with pytest.raises(StdioProfileError, match="arguments differ"):
        _compile(_registry(tmp_path), profile=profile, request=request)

    profile = _profile()
    profile["effect"]["network_egress"] = 0
    with pytest.raises(StdioProfileError, match="read-only, no-egress"):
        _compile(_registry(tmp_path), profile=profile)


def test_compile_rejects_changed_adapter_pin_and_oversized_request(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    profile = _profile()
    profile["adapter"]["executable_sha256"] = "c" * 64
    with pytest.raises(StdioProfileError, match="digest differs"):
        _compile(registry, profile=profile)

    request = _request()
    request["arguments"] = {"query": "x" * 17_000}
    with pytest.raises(StdioProfileError, match="bounded canonical JSON: payload_limit"):
        _compile(registry, request=request)


def test_revalidate_rejects_plan_tamper_and_rebound_envelope(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    plan = _compile(registry)
    data = plan.to_dict()
    data["limits"]["egress_allowed"] = True
    with pytest.raises(StdioProfileError, match="action plan is invalid"):
        validate_stdio_action_plan(plan=data, profile=_profile(), registry=registry)

    envelope = _decode_envelope(plan.to_dict()["operations"][0]["arguments"]["request_b64"])
    changed = copy.deepcopy(envelope)
    changed["request"]["arguments"] = {"query": "other"}
    rebound = _rebuild_with_envelope(plan, changed)
    with pytest.raises(StdioProfileError, match="arguments differ"):
        validate_stdio_action_plan(plan=rebound, profile=_profile(), registry=registry)

    changed = copy.deepcopy(envelope)
    changed["effect"]["network_egress"] = True
    rebound = _rebuild_with_envelope(plan, changed)
    with pytest.raises(StdioProfileError, match="effect differs"):
        validate_stdio_action_plan(plan=rebound, profile=_profile(), registry=registry)
