"""Data-only compiler for bounded local agent/MCP stdio requests.

This module does not launch an adapter or grant execution authorization. Its
read-only and no-egress fields are plan assertions, not OS isolation evidence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace

from cops.adapters import AdapterError, ToolAdapterRegistry
from cops.contracts.models import ActionPlan
from cops.evidence.canonical import EvidenceError, canonical, decode_json
from cops.execution.redaction import DEFAULT_SENSITIVE_PATTERNS

STDIO_PROFILE_SCHEMA = "cops.agent-mcp-stdio-profile/v1"
STDIO_REQUEST_SCHEMA = "cops.agent-mcp-stdio-request/v1"
STDIO_ENVELOPE_SCHEMA = "cops.agent-mcp-stdio-envelope/v1"

_PROFILE_FIELDS = {
    "schema_version",
    "profile_id",
    "target",
    "adapter",
    "effect",
    "request_contract",
    "limits",
}
_ADAPTER_FIELDS = {
    "tool",
    "tool_version",
    "action",
    "protocol_version",
    "source_revision",
    "executable_sha256",
    "request_parameter",
}
_EFFECT_FIELDS = {"classification", "network_egress"}
_CONTRACT_FIELDS = {"method", "tool_name", "arguments"}
_LIMIT_FIELDS = {"max_duration_seconds", "max_output_bytes"}
_REQUEST_FIELDS = {
    "schema_version",
    "request_id",
    "method",
    "tool_name",
    "arguments",
    "nonce",
}
_ENVELOPE_FIELDS = {
    "schema_version",
    "profile_id",
    "adapter_binding",
    "effect",
    "request",
}
_BINDING_FIELDS = {"protocol_version", "source_revision", "executable_sha256", "command_template_sha256"}
_OPERATION_FIELDS = {
    "step_id",
    "tool",
    "tool_version",
    "action",
    "arguments",
    "timeout_seconds",
    "idempotent",
    "side_effects",
}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_TOOL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")
_CREDENTIAL_KEY = re.compile(
    r"(?i)(?:auth(?:orization|entication)?|credential|password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|cookie)"
)
_CREDENTIAL_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9+/_.~=-]+|\bsk-[A-Za-z0-9_-]{8,}\b")
_MAX_REQUEST_BYTES = 16_384
_MAX_ENVELOPE_BYTES = 32_768


class StdioProfileError(ValueError):
    """An untrusted request or trusted conformance contract is invalid."""


@dataclass(frozen=True)
class _TrustedProfile:
    profile_id: str
    target: str
    tool: str
    tool_version: str
    action: str
    protocol_version: str
    source_revision: str
    executable_sha256: str
    command_template_sha256: str
    request_parameter: str
    request_contract: dict[str, object]
    max_duration_seconds: int
    max_output_bytes: int

    @property
    def binding(self) -> dict[str, str]:
        return {
            "protocol_version": self.protocol_version,
            "source_revision": self.source_revision,
            "executable_sha256": self.executable_sha256,
            "command_template_sha256": self.command_template_sha256,
        }


def _object(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise StdioProfileError(f"{name} must be an object with string keys")
    return value


def _exact_fields(value: Mapping[str, object], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        raise StdioProfileError(
            f"{name} fields differ: missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
        )


def _string(value: object, name: str, pattern: re.Pattern[str] = _IDENTIFIER) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise StdioProfileError(f"{name} has an invalid identifier")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise StdioProfileError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _positive_int(value: object, name: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise StdioProfileError(f"{name} must be between 1 and {maximum}")
    return value


def _canonical_bytes(value: object, name: str, maximum: int) -> bytes:
    try:
        return canonical(value, max_bytes=maximum, max_depth=16)
    except EvidenceError as exc:
        raise StdioProfileError(f"{name} is not bounded canonical JSON: {exc.code}") from exc


def _reject_credentials(value: object) -> None:
    """Reject recognizable credential material without including it in diagnostics."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            if _CREDENTIAL_KEY.search(key):
                raise StdioProfileError("stdio request arguments cannot contain credentials")
            _reject_credentials(child)
    elif isinstance(value, list):
        for child in value:
            _reject_credentials(child)
    elif isinstance(value, str) and (
        _CREDENTIAL_VALUE.search(value) or any(pattern.search(value) for _, pattern in DEFAULT_SENSITIVE_PATTERNS)
    ):
        raise StdioProfileError("stdio request arguments cannot contain credentials")


def _trusted_profile(profile: Mapping[str, object], registry: ToolAdapterRegistry) -> _TrustedProfile:
    source = _object(profile, "profile")
    _exact_fields(source, _PROFILE_FIELDS, "profile")
    if source["schema_version"] != STDIO_PROFILE_SCHEMA:
        raise StdioProfileError("unsupported stdio profile schema")
    adapter_source = _object(source["adapter"], "profile.adapter")
    _exact_fields(adapter_source, _ADAPTER_FIELDS, "profile.adapter")
    effect = _object(source["effect"], "profile.effect")
    _exact_fields(effect, _EFFECT_FIELDS, "profile.effect")
    if effect["classification"] != "read_only" or effect["network_egress"] is not False:
        raise StdioProfileError("stdio profile must assert read-only, no-egress behavior")
    limits = _object(source["limits"], "profile.limits")
    _exact_fields(limits, _LIMIT_FIELDS, "profile.limits")
    request_contract = _object(source["request_contract"], "profile.request_contract")
    _exact_fields(request_contract, _CONTRACT_FIELDS, "profile.request_contract")
    if request_contract["method"] != "tools/call":
        raise StdioProfileError("only MCP tools/call is supported")
    _string(request_contract["tool_name"], "profile.request_contract.tool_name", _TOOL_NAME)
    contract_arguments = _object(request_contract["arguments"], "profile.request_contract.arguments")
    _canonical_bytes(contract_arguments, "profile.request_contract.arguments", _MAX_REQUEST_BYTES)
    _reject_credentials(contract_arguments)
    contract = dict(request_contract)
    _canonical_bytes(contract, "profile.request_contract", _MAX_REQUEST_BYTES)

    trusted = _TrustedProfile(
        profile_id=_string(source["profile_id"], "profile.profile_id"),
        target=_string(source["target"], "profile.target"),
        tool=_string(adapter_source["tool"], "profile.adapter.tool"),
        tool_version=_string(adapter_source["tool_version"], "profile.adapter.tool_version"),
        action=_string(adapter_source["action"], "profile.adapter.action"),
        protocol_version=_string(adapter_source["protocol_version"], "profile.adapter.protocol_version"),
        source_revision=_digest(adapter_source["source_revision"], "profile.adapter.source_revision"),
        executable_sha256=_digest(adapter_source["executable_sha256"], "profile.adapter.executable_sha256"),
        command_template_sha256="",
        request_parameter=_string(adapter_source["request_parameter"], "profile.adapter.request_parameter"),
        request_contract=contract,
        max_duration_seconds=_positive_int(limits["max_duration_seconds"], "profile.limits.max_duration_seconds", 300),
        max_output_bytes=_positive_int(limits["max_output_bytes"], "profile.limits.max_output_bytes", 4_194_304),
    )
    if trusted.protocol_version != "2025-11-25":
        raise StdioProfileError("unsupported MCP protocol version")
    if not isinstance(registry, ToolAdapterRegistry):
        raise StdioProfileError("trusted adapter registry is required")
    try:
        adapter = registry.get_adapter(trusted.tool)
    except AdapterError as exc:
        raise StdioProfileError("profile adapter is unavailable") from exc
    if adapter.version != trusted.tool_version:
        raise StdioProfileError("profile adapter version differs from registration")
    if adapter.provenance.get("pinned_revision") != trusted.source_revision:
        raise StdioProfileError("profile source revision differs from registration")
    verification = adapter.executable_verification
    if verification is None or verification.sha256 != trusted.executable_sha256:
        raise StdioProfileError("profile executable digest differs from registration")
    action = adapter.actions.get(trusted.action)
    if action is None or set(action.parameters) != {trusted.request_parameter}:
        raise StdioProfileError("profile action requires one bounded request parameter")
    parameter = action.parameters[trusted.request_parameter]
    if (
        parameter.param_type != "string"
        or not parameter.required
        or parameter.default is not None
        or parameter.flag is not None
        or parameter.regex_pattern is None
    ):
        raise StdioProfileError("profile request parameter must be a required constrained string")
    command_template = {
        "binary": adapter.binary,
        "supported_environments": list(adapter.supported_environments),
        "provenance": {
            "source": adapter.provenance.get("source"),
            "license": adapter.provenance.get("license"),
            "pinned_revision": adapter.provenance.get("pinned_revision"),
        },
        "executable_verification": {
            "sha256": verification.sha256,
            "version_args": list(verification.version_args),
            "version_pattern": verification.version_pattern,
            "max_size_bytes": verification.max_size_bytes,
        },
        "action": action.action,
        "base_args": action.base_args,
        "parameter": {
            "name": parameter.name,
            "param_type": parameter.param_type,
            "flag": parameter.flag,
            "required": parameter.required,
            "default": parameter.default,
            "allowed_values": parameter.allowed_values,
            "regex_pattern": parameter.regex_pattern,
        },
    }
    template_digest = hashlib.sha256(
        _canonical_bytes(command_template, "registered adapter command template", _MAX_REQUEST_BYTES)
    ).hexdigest()
    return replace(trusted, command_template_sha256=template_digest)


def _validated_request(request: Mapping[str, object], trusted: _TrustedProfile) -> dict[str, object]:
    source = _object(request, "request")
    _exact_fields(source, _REQUEST_FIELDS, "request")
    if source["schema_version"] != STDIO_REQUEST_SCHEMA:
        raise StdioProfileError("unsupported stdio request schema")
    _string(source["request_id"], "request.request_id")
    _string(source["nonce"], "request.nonce")
    if source["method"] != trusted.request_contract["method"]:
        raise StdioProfileError("request method differs from trusted contract")
    if source["tool_name"] != trusted.request_contract["tool_name"]:
        raise StdioProfileError("request tool differs from trusted contract")
    request_arguments = _object(source["arguments"], "request.arguments")
    _canonical_bytes(request_arguments, "request.arguments", _MAX_REQUEST_BYTES)
    _reject_credentials(request_arguments)
    normalized = dict(source)
    _canonical_bytes(normalized, "request", _MAX_REQUEST_BYTES)
    if _canonical_bytes(source["arguments"], "request.arguments", _MAX_REQUEST_BYTES) != _canonical_bytes(
        trusted.request_contract["arguments"], "profile.request_contract.arguments", _MAX_REQUEST_BYTES
    ):
        raise StdioProfileError("request arguments differ from trusted contract")
    return normalized


def _envelope(trusted: _TrustedProfile, request: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": STDIO_ENVELOPE_SCHEMA,
        "profile_id": trusted.profile_id,
        "adapter_binding": trusted.binding,
        "effect": {"classification": "read_only", "network_egress": False},
        "request": request,
    }


def _encode_envelope(envelope: Mapping[str, object]) -> str:
    raw = _canonical_bytes(dict(envelope), "envelope", _MAX_ENVELOPE_BYTES)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_envelope(value: object) -> dict[str, object]:
    if (
        not isinstance(value, str)
        or len(value) > (_MAX_ENVELOPE_BYTES * 4 + 2) // 3
        or _BASE64URL.fullmatch(value) is None
    ):
        raise StdioProfileError("compiled envelope is not bounded canonical base64url")
    try:
        raw = base64.b64decode((value + "=" * (-len(value) % 4)).encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise StdioProfileError("compiled envelope is invalid base64url") from exc
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise StdioProfileError("compiled envelope is not canonically encoded")
    try:
        decoded = decode_json(raw, max_bytes=_MAX_ENVELOPE_BYTES, max_depth=16)
    except EvidenceError as exc:
        raise StdioProfileError(f"compiled envelope is invalid: {exc.code}") from exc
    return dict(_object(decoded, "compiled envelope"))


def _coerce_plan(plan: ActionPlan | Mapping[str, object]) -> ActionPlan:
    try:
        if isinstance(plan, ActionPlan):
            return ActionPlan.from_dict(plan.to_dict())
        return ActionPlan.from_dict(dict(_object(plan, "action plan")))
    except (ValueError, TypeError, KeyError) as exc:
        raise StdioProfileError("compiled action plan is invalid") from exc


def _validate_plan(plan: ActionPlan, trusted: _TrustedProfile, registry: ToolAdapterRegistry) -> dict[str, object]:
    snapshot = plan.approved_snapshot()
    if snapshot["target"] != trusted.target:
        raise StdioProfileError("action plan target differs from trusted profile")
    if "offline_research" in snapshot or snapshot["credential_references"] or snapshot["platform_prerequisites"]:
        raise StdioProfileError("stdio plan cannot carry credentials, research, or prerequisites")
    if snapshot["batch"] != {"mode": "sequential", "max_operations": 1, "fail_fast": True}:
        raise StdioProfileError("stdio plan must contain one fail-fast operation")
    if snapshot["limits"] != {
        "max_duration_seconds": trusted.max_duration_seconds,
        "max_output_bytes": trusted.max_output_bytes,
        "egress_allowed": False,
    }:
        raise StdioProfileError("action plan limits differ from trusted profile")
    operations = snapshot["operations"]
    if len(operations) != 1:
        raise StdioProfileError("stdio plan must contain exactly one operation")
    operation = _object(operations[0], "action plan operation")
    _exact_fields(operation, _OPERATION_FIELDS, "action plan operation")
    expected = {
        "step_id": f"stdio-{trusted.profile_id}",
        "tool": trusted.tool,
        "tool_version": trusted.tool_version,
        "action": trusted.action,
        "timeout_seconds": trusted.max_duration_seconds,
        "idempotent": True,
        "side_effects": ["read_only"],
    }
    if any(operation[key] != value for key, value in expected.items()):
        raise StdioProfileError("action plan operation differs from trusted profile")
    arguments = _object(operation["arguments"], "action plan operation arguments")
    _exact_fields(arguments, {trusted.request_parameter}, "action plan operation arguments")
    encoded = arguments[trusted.request_parameter]
    envelope = _decode_envelope(encoded)
    _exact_fields(envelope, _ENVELOPE_FIELDS, "compiled envelope")
    if envelope["schema_version"] != STDIO_ENVELOPE_SCHEMA or envelope["profile_id"] != trusted.profile_id:
        raise StdioProfileError("compiled envelope identity differs from trusted profile")
    binding = _object(envelope["adapter_binding"], "compiled envelope adapter binding")
    _exact_fields(binding, _BINDING_FIELDS, "compiled envelope adapter binding")
    if dict(binding) != trusted.binding:
        raise StdioProfileError("compiled envelope adapter binding differs from trusted profile")
    envelope_effect = _object(envelope["effect"], "compiled envelope effect")
    _exact_fields(envelope_effect, _EFFECT_FIELDS, "compiled envelope effect")
    if envelope_effect["classification"] != "read_only" or envelope_effect["network_egress"] is not False:
        raise StdioProfileError("compiled envelope effect differs from trusted profile")
    request = _validated_request(_object(envelope["request"], "compiled envelope request"), trusted)
    if envelope != _envelope(trusted, request) or encoded != _encode_envelope(envelope):
        raise StdioProfileError("compiled envelope differs from canonical trusted binding")
    parameter = registry.get_adapter(trusted.tool).actions[trusted.action].parameters[trusted.request_parameter]
    try:
        if parameter.validate_and_format(encoded) != [encoded]:
            raise StdioProfileError("compiled envelope changes the adapter argument shape")
    except AdapterError as exc:
        raise StdioProfileError("compiled envelope violates the adapter parameter contract") from exc
    return envelope


def compile_stdio_action_plan(
    *,
    profile: Mapping[str, object],
    request: Mapping[str, object],
    registry: ToolAdapterRegistry,
    plan_id: str,
    engagement_id: str,
    scenario_id: str,
    target: str,
    specialist_id: str,
    created_at: str,
) -> ActionPlan:
    """Compile one trusted read-only profile and exact untrusted request as data."""

    trusted = _trusted_profile(profile, registry)
    if target != trusted.target:
        raise StdioProfileError("requested target differs from trusted profile")
    encoded = _encode_envelope(_envelope(trusted, _validated_request(request, trusted)))
    try:
        plan = ActionPlan.create(
            plan_id=plan_id,
            engagement_id=engagement_id,
            scenario_id=scenario_id,
            target=target,
            specialist_id=specialist_id,
            operations=[
                {
                    "step_id": f"stdio-{trusted.profile_id}",
                    "tool": trusted.tool,
                    "tool_version": trusted.tool_version,
                    "action": trusted.action,
                    "arguments": {trusted.request_parameter: encoded},
                    "timeout_seconds": trusted.max_duration_seconds,
                    "idempotent": True,
                    "side_effects": ["read_only"],
                }
            ],
            limits={
                "max_duration_seconds": trusted.max_duration_seconds,
                "max_output_bytes": trusted.max_output_bytes,
                "egress_allowed": False,
            },
            credential_references=[],
            created_at=created_at,
        )
    except (ValueError, TypeError) as exc:
        raise StdioProfileError("compiled action plan violates the action-plan contract") from exc
    _validate_plan(plan, trusted, registry)
    return plan


def validate_stdio_action_plan(
    *,
    plan: ActionPlan | Mapping[str, object],
    profile: Mapping[str, object],
    registry: ToolAdapterRegistry,
) -> dict[str, object]:
    """Revalidate plan data, profile pins, and the canonical request envelope."""

    return _validate_plan(_coerce_plan(plan), _trusted_profile(profile, registry), registry)
