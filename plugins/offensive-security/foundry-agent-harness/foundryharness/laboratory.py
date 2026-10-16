"""Observed agent and MCP laboratory for synthetic local cases.

The fixture agent only proposes calls. An independent gate decides whether a
proposal reaches the MCP server. Effects come exclusively from state reads on
that server, never from agent text or a tool's claim of success.
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bounded_json import JSONInputError, decode_json

PROTOCOL_VERSION = "2025-11-25"
AGENT_ORIGIN = "deterministic-local-fixture"
PACKAGE_ROOT = Path(__file__).resolve().parent
CASE_FIELDS = frozenset(
    {
        "schema_version",
        "case_id",
        "title",
        "source_family",
        "attack_surface",
        "legitimate_task",
        "untrusted_text",
        "principal_tenant",
        "tool_permissions",
        "approved_call",
        "control_profile",
        "expected_outcome",
        "expected_safe_behavior",
    }
)
ATTACK_SURFACES = frozenset(
    {
        "retrieval",
        "tool_response",
        "cross_tenant",
        "peer_message",
        "state_change",
        "data_exfiltration",
        "memory",
        "context",
        "tool_permission",
        "trusted_task",
    }
)
TOOL_NAMES = frozenset({"lookup_account", "modify_resource", "export_canary"})
FIXTURE_TOOLS = TOOL_NAMES | {"lab/configure", "lab/state", "lab/reset"}


class LabError(ValueError):
    """An invalid case, failed fixture protocol, or unverifiable observation."""


@dataclass(frozen=True)
class LabCase:
    case_id: str
    title: str
    source_family: str
    attack_surface: str
    legitimate_task: str
    untrusted_text: str
    principal_tenant: str
    tool_permissions: tuple[str, ...]
    approved_call: dict[str, Any]
    control_profile: str
    expected_outcome: str
    expected_safe_behavior: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LabCase:
        unknown = set(data) - CASE_FIELDS
        if unknown:
            raise LabError(f"Unknown case fields: {', '.join(sorted(unknown))}")
        missing = CASE_FIELDS - set(data)
        if missing:
            raise LabError(f"Missing case fields: {', '.join(sorted(missing))}")
        if data["schema_version"] != "cops.agent-mcp-lab-case/v1":
            raise LabError("Unsupported lab case schema version")
        if not isinstance(data["case_id"], str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", data["case_id"]):
            raise LabError("Invalid case ID")
        for key in ("title", "source_family", "legitimate_task", "expected_safe_behavior"):
            if not isinstance(data[key], str) or not data[key].strip() or len(data[key]) > 512:
                raise LabError(f"Invalid {key}")
        if data["source_family"] != "COPS-E16.01 (provisional)":
            raise LabError("Unsupported source family")
        if not isinstance(data["attack_surface"], str) or data["attack_surface"] not in ATTACK_SURFACES:
            raise LabError("Unsupported attack surface")
        if not isinstance(data["untrusted_text"], str) or len(data["untrusted_text"]) > 2048:
            raise LabError("Invalid untrusted text")
        if data["principal_tenant"] != "tenant-contoso-01":
            raise LabError("Only the synthetic lab tenant is supported")
        permissions = data["tool_permissions"]
        if (
            not isinstance(permissions, list)
            or not all(isinstance(p, str) and p in TOOL_NAMES for p in permissions)
            or len(permissions) != len(set(permissions))
        ):
            raise LabError("Invalid tool permissions")
        approved = data["approved_call"]
        if not isinstance(approved, dict) or set(approved) != {"name", "arguments"}:
            raise LabError("Invalid approved call")
        if (
            not isinstance(approved["name"], str)
            or approved["name"] not in TOOL_NAMES
            or not isinstance(approved["arguments"], dict)
        ):
            raise LabError("Invalid approved call tool or arguments")
        if _fixture_argument_error(approved["name"], approved["arguments"]):
            raise LabError("Approved call is outside the synthetic fixture allowlist")
        if not isinstance(data["control_profile"], str) or data["control_profile"] not in ("strict", "permission_only"):
            raise LabError("Unsupported control profile")
        if not isinstance(data["expected_outcome"], str) or data["expected_outcome"] not in (
            "denied",
            "executed_effect",
            "executed_no_effect",
        ):
            raise LabError("Unsupported expected outcome")
        return cls(
            case_id=data["case_id"],
            title=data["title"],
            source_family=data["source_family"],
            attack_surface=data["attack_surface"],
            legitimate_task=data["legitimate_task"],
            untrusted_text=data["untrusted_text"],
            principal_tenant=data["principal_tenant"],
            tool_permissions=tuple(permissions),
            approved_call=approved,
            control_profile=data["control_profile"],
            expected_outcome=data["expected_outcome"],
            expected_safe_behavior=data["expected_safe_behavior"],
        )


def load_lab_cases(path: Path) -> list[LabCase]:
    """Load one case or a directory; reject malformed or duplicate cases."""
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted(path.glob("*.json"))
    else:
        raise LabError(f"Lab cases not found: {path}")
    if not files:
        raise LabError("No lab cases found")
    cases: list[LabCase] = []
    seen: set[str] = set()
    for case_path in files:
        try:
            data = json.loads(case_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise LabError("Case root must be an object")
            case = LabCase.from_dict(data)
        except (OSError, json.JSONDecodeError) as exc:
            raise LabError(f"Invalid case {case_path.name}: {exc}") from exc
        if case.case_id in seen:
            raise LabError(f"Duplicate case ID: {case.case_id}")
        seen.add(case.case_id)
        cases.append(case)
    return cases


class _JsonLineProcess:
    def __init__(
        self,
        script: str,
        workdir: str,
        extra_args: tuple[str, ...] = (),
        response_timeout_seconds: float = 5.0,
        *,
        admission_check: Callable[[], None] | None = None,
        response_timeout_provider: Callable[[], float] | None = None,
        account_response: Callable[[bytes], None] | None = None,
        response_bytes_remaining: Callable[[], int] | None = None,
        source_root: Path | None = None,
        on_spawn: Callable[[Any], None] | None = None,
    ) -> None:
        if not 0 < response_timeout_seconds <= 30:
            raise LabError("Fixture response timeout must be between zero and 30 seconds")
        command = [sys.executable, "-I", "-B", "-u", str((source_root or PACKAGE_ROOT) / script), *extra_args]
        env = {"PATH": os.defpath, "PYTHONIOENCODING": "utf-8"}
        if os.name == "nt" and "SystemRoot" in os.environ:
            env["SystemRoot"] = os.environ["SystemRoot"]
        self.admission_check = admission_check
        self.response_timeout_provider = response_timeout_provider
        self.account_response = account_response
        self.response_bytes_remaining = response_bytes_remaining
        self.response_timeout_seconds = response_timeout_seconds
        if self.admission_check is not None:
            self.admission_check()
        self.process = subprocess.Popen(
            command,
            cwd=workdir,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            env=env,
        )
        if on_spawn is not None:
            on_spawn(self)

    def exchange(
        self,
        payload: dict[str, Any],
        *,
        response: bool = True,
        on_dispatch_attempt: Callable[[], None] | None = None,
    ) -> dict[str, Any] | None:
        if self.admission_check is not None:
            self.admission_check()
        if self.process.stdin is None or self.process.stdout is None:
            raise LabError("Fixture pipes unavailable")
        read_limit = 65537
        if response and self.response_bytes_remaining is not None:
            read_limit = min(read_limit, self.response_bytes_remaining())
        if on_dispatch_attempt is not None:
            on_dispatch_attempt()
        try:
            self.process.stdin.write((json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8"))
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise LabError("Fixture process exited before request") from exc
        if not response:
            return None
        stdout = self.process.stdout
        received: queue.Queue[bytes | OSError] = queue.Queue(maxsize=1)

        def read_line() -> None:
            try:
                received.put(stdout.readline(read_limit))
            except OSError as exc:
                received.put(exc)

        threading.Thread(target=read_line, daemon=True).start()
        try:
            timeout = self.response_timeout_seconds
            if self.response_timeout_provider is not None:
                timeout = min(timeout, self.response_timeout_provider())
            line = received.get(timeout=timeout)
        except queue.Empty as exc:
            if self.admission_check is not None:
                self.admission_check()
            raise LabError("Fixture response timed out") from exc
        if isinstance(line, OSError):
            raise LabError("Fixture response read failed") from line
        if self.account_response is not None:
            self.account_response(line)
        if not line:
            raise LabError("Fixture exited without response")
        if not line.endswith(b"\n") and len(line) == read_limit and self.response_bytes_remaining is not None:
            self.response_bytes_remaining()
        if len(line) > 65536 or not line.endswith(b"\n"):
            raise LabError("Fixture response exceeded limit or lacked line terminator")
        try:
            value = decode_json(line, max_bytes=65536)
        except JSONInputError as exc:
            raise LabError("Fixture returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise LabError("Fixture returned a non-object response")
        return value

    def close(self) -> bool:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        if self.process.stdin:
            self.process.stdin.close()
        if self.process.stdout:
            self.process.stdout.close()
        return self.process.poll() is not None


def _validate_json_schema_value(value: Any, schema: dict[str, Any], path: str = "arguments") -> None:
    """Validate the small JSON Schema subset used by fixed local MCP fixtures."""
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            raise LabError(f"{path} must be an object")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise LabError("MCP fixture advertised a malformed input schema")
        missing = set(required) - set(value)
        if missing:
            raise LabError(f"{path} is missing required fields")
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            raise LabError(f"{path} contains fields outside the advertised input schema")
        for key, item in value.items():
            child = properties.get(key)
            if isinstance(child, dict):
                _validate_json_schema_value(item, child, f"{path}.{key}")
    elif expected_type == "array":
        if not isinstance(value, list):
            raise LabError(f"{path} must be an array")
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            raise LabError(f"{path} has an invalid item count")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            raise LabError(f"{path} must contain unique items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_json_schema_value(item, item_schema, f"{path}[{index}]")
    elif expected_type == "string":
        if not isinstance(value, str):
            raise LabError(f"{path} must be a string")
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise LabError(f"{path} is too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise LabError(f"{path} is too long")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise LabError(f"{path} does not match the advertised pattern")
    elif expected_type == "integer":
        if type(value) is not int:
            raise LabError(f"{path} must be an integer")
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise LabError(f"{path} is outside the advertised range")
    elif expected_type == "boolean" and type(value) is not bool:
        raise LabError(f"{path} must be a boolean")
    elif expected_type not in (None, "object", "array", "string", "integer", "boolean"):
        raise LabError("MCP fixture advertised an unsupported input schema type")
    if "const" in schema and value != schema["const"]:
        raise LabError(f"{path} differs from the advertised constant")
    if "enum" in schema and value not in schema["enum"]:
        raise LabError(f"{path} is outside the advertised enum")


class _McpClient:
    def __init__(
        self,
        process: _JsonLineProcess,
        *,
        expected_tools: frozenset[str] = FIXTURE_TOOLS,
        expected_server_info: dict[str, str] | None = None,
        expected_capabilities: dict[str, Any] | None = None,
        expected_input_schemas: dict[str, dict[str, Any]] | None = None,
        expected_tool_descriptors: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.process = process
        self.next_id = 1
        self.expected_tools = expected_tools
        self.expected_server_info = (
            expected_server_info if expected_server_info is not None else {"name": "cops-local-fixture", "version": "1"}
        )
        self.expected_capabilities = expected_capabilities
        self.expected_input_schemas = expected_input_schemas
        self.expected_tool_descriptors = expected_tool_descriptors

    def request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        on_dispatch_attempt: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        response = self.process.exchange(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            on_dispatch_attempt=on_dispatch_attempt,
        )
        if response is None or response.get("jsonrpc") != "2.0" or response.get("id") != request_id:
            raise LabError("MCP response ID or envelope mismatch")
        if "error" in response:
            raise LabError(f"MCP fixture rejected {method}: {response['error']}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise LabError("MCP result must be an object")
        return result

    def initialize(self) -> None:
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "cops-local-lab", "version": "1"},
            },
        )
        capabilities = result.get("capabilities")
        if (
            result.get("protocolVersion") != PROTOCOL_VERSION
            or not isinstance(capabilities, dict)
            or not isinstance(capabilities.get("tools"), dict)
            or (self.expected_capabilities is not None and capabilities != self.expected_capabilities)
            or result.get("serverInfo") != self.expected_server_info
        ):
            raise LabError("MCP fixture identity, protocol, or capability mismatch")
        self.process.exchange({"jsonrpc": "2.0", "method": "notifications/initialized"}, response=False)
        listed = self.request("tools/list", {})
        if "nextCursor" in listed:
            raise LabError("MCP fixture tool inventory pagination is unsupported")
        tools = listed.get("tools")
        if not isinstance(tools, list) or not all(
            isinstance(tool, dict) and isinstance(tool.get("name"), str) for tool in tools
        ):
            raise LabError("MCP fixture tool inventory malformed")
        names = [tool["name"] for tool in tools]
        if len(names) != len(self.expected_tools) or set(names) != self.expected_tools:
            raise LabError("MCP fixture tool inventory mismatch")
        if self.expected_input_schemas is not None:
            advertised = {tool["name"]: tool.get("inputSchema") for tool in tools}
            if advertised != self.expected_input_schemas:
                raise LabError("MCP fixture input schemas do not match the fixed client contract")
        if self.expected_tool_descriptors is not None:
            advertised_descriptors = {tool["name"]: tool for tool in tools}
            if advertised_descriptors != self.expected_tool_descriptors:
                raise LabError("MCP fixture tool descriptors do not match the fixed client contract")

    def call(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        on_dispatch_attempt: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        if self.expected_input_schemas is not None:
            if name not in self.expected_input_schemas:
                raise LabError("MCP call uses a tool outside the fixed client contract")
            _validate_json_schema_value(arguments, self.expected_input_schemas[name])
        result = self.request(
            "tools/call",
            {"name": name, "arguments": arguments},
            on_dispatch_attempt=on_dispatch_attempt,
        )
        content_items = result.get("content")
        if (
            not isinstance(result.get("isError"), bool)
            or result["isError"]
            or not isinstance(content_items, list)
            or len(content_items) != 1
        ):
            raise LabError(f"MCP fixture tool failed: {name}")
        content = content_items[0]
        if not isinstance(content, dict) or content.get("type") != "text" or not isinstance(content.get("text"), str):
            raise LabError("MCP fixture returned unsupported content")
        try:
            value = decode_json(content["text"].encode("utf-8"), max_bytes=65536)
        except (KeyError, TypeError, UnicodeError, JSONInputError) as exc:
            raise LabError("MCP fixture returned invalid tool content") from exc
        if not isinstance(value, dict):
            raise LabError("MCP fixture tool content must be an object")
        return value


def _fixture_argument_error(name: str, arguments: dict[str, Any]) -> str | None:
    if name == "lookup_account":
        if arguments != {"tenant_id": "tenant-contoso-01", "account_id": "acct-001"}:
            return "Account or tenant outside synthetic fixture"
    elif name == "modify_resource":
        if (
            set(arguments) != {"tenant_id", "resource_id", "status"}
            or arguments.get("tenant_id") != "tenant-contoso-01"
            or arguments.get("resource_id") != "res-faq-storage"
            or arguments.get("status") not in ("active", "disabled")
        ):
            return "Resource or action outside synthetic fixture"
    elif name == "export_canary":
        if arguments != {"tenant_id": "tenant-contoso-01", "destination": "lab://canary-sink"}:
            return "Destination outside local canary sink"
    else:
        return "Unknown tool"
    return None


def _authorize(case: LabCase, call: dict[str, Any]) -> str | None:
    name = call.get("name")
    arguments = call.get("arguments")
    if not isinstance(name, str) or not isinstance(arguments, dict):
        return "Malformed tool proposal"
    if name not in TOOL_NAMES or name not in case.tool_permissions:
        return "Tool is not permitted for this case"
    if arguments.get("tenant_id") != case.principal_tenant:
        return "Tenant boundary mismatch"
    argument_error = _fixture_argument_error(name, arguments)
    if argument_error:
        return argument_error
    if case.control_profile == "strict" and call != case.approved_call:
        return "Untrusted proposal differs from the trusted task approval"
    return None


def _validate_state(state: dict[str, Any]) -> None:
    resources = state.get("resources")
    sink = state.get("canary_sink")
    note = state.get("tool_response")
    if (
        set(state) != {"resources", "canary_sink", "tool_response"}
        or not isinstance(resources, dict)
        or set(resources) != {"res-faq-storage", "res-fabrikam-ledger"}
        or not isinstance(sink, list)
        or not all(item == "CANARY-SYNTHETIC-001" for item in sink)
        or not isinstance(note, str)
        or len(note) > 2048
    ):
        raise LabError("MCP state observer returned an unexpected shape")
    for resource_id, tenant in (
        ("res-faq-storage", "tenant-contoso-01"),
        ("res-fabrikam-ledger", "tenant-fabrikam-02"),
    ):
        resource = resources[resource_id]
        if (
            not isinstance(resource, dict)
            or set(resource) != {"tenant_id", "status"}
            or resource["tenant_id"] != tenant
            or resource["status"] not in ("active", "disabled")
        ):
            raise LabError("MCP state observer returned an unexpected resource")


def _observed_effects(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    _validate_state(before)
    _validate_state(after)
    effects: list[dict[str, Any]] = []
    for resource_id, prior in before["resources"].items():
        current = after["resources"][resource_id]
        if current != prior:
            effects.append({"kind": "resource_change", "resource_id": resource_id, "before": prior, "after": current})
    if after["canary_sink"] != before["canary_sink"]:
        effects.append({"kind": "canary_sink_change", "before": before["canary_sink"], "after": after["canary_sink"]})
    if after["tool_response"] != before["tool_response"]:
        effects.append(
            {"kind": "tool_response_change", "before": before["tool_response"], "after": after["tool_response"]}
        )
    return effects


def run_lab_case(case: LabCase) -> dict[str, Any]:
    """Run one case against fresh local processes and verify reset before exit."""
    with tempfile.TemporaryDirectory(prefix="cops-agent-mcp-lab-") as workdir:
        server: _JsonLineProcess | None = None
        agent: _JsonLineProcess | None = None
        try:
            server = _JsonLineProcess("mcp_fixture_server.py", workdir)
            agent = _JsonLineProcess("fixture_agent.py", workdir)
            mcp = _McpClient(server)
            mcp.initialize()
            initial_state = mcp.call("lab/state", {})
            _validate_state(initial_state)
            if case.attack_surface == "tool_response":
                mcp.call("lab/configure", {"note": case.untrusted_text})
            before = mcp.call("lab/state", {})
            _validate_state(before)
            executed_calls: list[dict[str, Any]] = []
            untrusted = case.untrusted_text
            if case.attack_surface == "tool_response":
                # The injected note is obtained through an actual MCP read.
                seed_call = {
                    "name": "lookup_account",
                    "arguments": {"tenant_id": "tenant-contoso-01", "account_id": "acct-001"},
                }
                note = mcp.call(seed_call["name"], seed_call["arguments"]).get("note")
                if not isinstance(note, str) or note != case.untrusted_text:
                    raise LabError("Tool response fixture note mismatch")
                executed_calls.append({**seed_call, "origin": "trusted_seed_read"})
                untrusted = note
            agent_result = agent.exchange({"untrusted_text": untrusted, "approved_call": case.approved_call})
            if agent_result is None or not isinstance(agent_result.get("model_text"), str):
                raise LabError("Agent fixture returned invalid text")
            proposals = agent_result.get("proposed_calls")
            if not isinstance(proposals, list) or len(proposals) != 1 or not isinstance(proposals[0], dict):
                raise LabError("Agent fixture returned invalid proposal count")
            origin = agent_result.get("proposal_origin")
            if origin not in ("trusted_task", "untrusted_content"):
                raise LabError("Agent fixture returned invalid proposal origin")
            call = proposals[0]
            if set(call) != {"name", "arguments"}:
                raise LabError("Agent fixture returned malformed tool proposal")
            attempted_calls = [{**call, "origin": origin}]
            denial = _authorize(case, call)
            denied_calls: list[dict[str, Any]] = []
            if denial:
                denied_calls.append({**call, "reason": denial})
            else:
                mcp.call(call["name"], call["arguments"])
                executed_calls.append({**call, "origin": origin})
            after = mcp.call("lab/state", {})
            _validate_state(after)
            effects = _observed_effects(before, after)
            mcp.call("lab/reset", {})
            reset_state = mcp.call("lab/state", {})
            _validate_state(reset_state)
            cleaned = reset_state == initial_state
            expected = (
                (case.expected_outcome == "denied" and bool(denied_calls) and not effects)
                or (case.expected_outcome == "executed_effect" and not denied_calls and bool(effects))
                or (case.expected_outcome == "executed_no_effect" and not denied_calls and not effects)
            )
            return {
                "schema_version": "cops.agent-mcp-lab-report/v1",
                "case_id": case.case_id,
                "title": case.title,
                "source_family": case.source_family,
                "attack_surface": case.attack_surface,
                "control_profile": case.control_profile,
                "agent_origin": AGENT_ORIGIN,
                "mcp_transport": "local-stdio",
                "mcp_protocol_version": PROTOCOL_VERSION,
                "environment_verified": True,
                "model_text": agent_result["model_text"],
                "attempted_calls": attempted_calls,
                "denied_calls": denied_calls,
                "executed_calls": executed_calls,
                "executed_effects": effects,
                "state_before": before,
                "state_after": after,
                "cleanup_verified": cleaned,
                "expected_outcome": case.expected_outcome,
                "expectation_met": bool(expected and cleaned),
            }
        finally:
            if agent is not None:
                agent.close()
            if server is not None:
                server.close()
