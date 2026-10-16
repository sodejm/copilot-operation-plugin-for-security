"""Declarative tool adapter registry for COPS execution worker runtime.

Enforces argument typing, parameter validation, allowed flags, and command template
assembly without arbitrary shell interpolation.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any


class AdapterError(ValueError):
    """Base error for adapter validation and assembly failures."""


class AdapterParameterError(AdapterError):
    """Parameter failed schema validation or regex constraint."""


class AdapterInjectionError(AdapterError):
    """Attempted shell injection, flag injection, or directory traversal detected."""


DEFINITIONS_DIR = Path(__file__).resolve().parent / "definitions"


@dataclass
class ToolParameter:
    """Definition for a typed command argument or flag."""

    name: str
    param_type: str  # "string", "integer", "boolean", "enum", "ip", "cidr"
    flag: str | None = None  # e.g. "-p", "--ports"
    required: bool = False
    default: Any | None = None
    allowed_values: list[str] = field(default_factory=list)
    regex_pattern: str | None = None

    def validate_and_format(self, value: Any) -> list[str]:
        """Validate input value and format as argument tokens."""
        if value is None:
            if self.required:
                raise AdapterParameterError(f"Missing required parameter '{self.name}'")
            return []

        # Traversal / injection guard
        str_val = str(value)
        if any(c in str_val for c in (";", "&", "|", "`", "$", "\n", "\r")):
            raise AdapterInjectionError(
                f"Shell metacharacters detected in parameter '{self.name}': {str_val!r}"
            )
        if ".." in str_val or str_val.startswith("/etc") or str_val.startswith("~"):
            raise AdapterInjectionError(
                f"Directory climbing or path traversal detected in parameter '{self.name}': {str_val!r}"
            )

        # Type checks
        if self.param_type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise AdapterParameterError(f"Parameter '{self.name}' must be an integer, got {value!r}")
            val_token = str(value)
        elif self.param_type == "boolean":
            if not isinstance(value, bool):
                raise AdapterParameterError(f"Parameter '{self.name}' must be a boolean, got {value!r}")
            if value and self.flag:
                return [self.flag]
            return []
        elif self.param_type == "enum":
            if str_val not in self.allowed_values:
                raise AdapterParameterError(
                    f"Parameter '{self.name}' value '{str_val}' not in allowed values: {self.allowed_values}"
                )
            val_token = str_val
        elif self.param_type == "ip":
            try:
                ipaddress.ip_address(str_val)
                val_token = str_val
            except ValueError:
                raise AdapterParameterError(f"Parameter '{self.name}' must be a valid IP address, got {str_val!r}") from None
        elif self.param_type == "cidr":
            try:
                ipaddress.ip_network(str_val, strict=False)
                val_token = str_val
            except ValueError:
                raise AdapterParameterError(f"Parameter '{self.name}' must be a valid CIDR network, got {str_val!r}") from None
        else:
            val_token = str_val

        # Regex check
        if self.regex_pattern:
            if not re.fullmatch(self.regex_pattern, val_token):
                raise AdapterParameterError(
                    f"Parameter '{self.name}' value '{val_token}' does not match regex pattern '{self.regex_pattern}'"
                )

        if self.flag:
            return [self.flag, val_token]
        if val_token.startswith("-"):
            raise AdapterInjectionError(
                f"Positional parameter '{self.name}' cannot start with '-' (option-like argument rejected): {val_token!r}"
            )
        return [val_token]


@dataclass
class ToolActionDefinition:
    """Definition for a specific action supported by a tool adapter."""

    action: str
    description: str
    base_args: list[str]
    parameters: dict[str, ToolParameter]


@dataclass(frozen=True)
class ExecutableVerification:
    """Pinned executable identity and version-probe contract.

    ``sha256`` is intentionally optional at parse time so the built-in catalog can
    describe tools that differ by platform.  Execution fails closed until a
    deployment supplies a platform-specific digest.
    """

    sha256: str | None
    version_args: tuple[str, ...]
    version_pattern: str
    max_size_bytes: int = 268_435_456


@dataclass
class ToolAdapter:
    """Registered tool adapter schema."""

    tool: str
    version: str
    binary: str
    provenance: dict[str, str]
    supported_environments: list[str]
    actions: dict[str, ToolActionDefinition]
    executable_verification: ExecutableVerification | None = None

    def assemble_command(self, action: str, arguments: dict[str, Any] | None = None) -> list[str]:
        """Assemble deterministic argument array for tool execution."""
        if action not in self.actions:
            raise AdapterError(f"Action '{action}' is not supported by tool '{self.tool}'. Allowed: {sorted(self.actions)}")

        current_env = "darwin" if sys.platform == "darwin" else ("linux" if sys.platform.startswith("linux") else sys.platform)
        if self.supported_environments and current_env not in self.supported_environments:
            raise AdapterError(
                f"Tool '{self.tool}' does not support environment '{current_env}'. Supported: {self.supported_environments}"
            )

        action_def = self.actions[action]
        cmd: list[str] = [self.binary] + list(action_def.base_args)

        args = arguments or {}
        # Check required parameters
        for param_name, param in action_def.parameters.items():
            val = args.get(param_name, param.default)
            tokens = param.validate_and_format(val)
            cmd.extend(tokens)

        # Reject unrecognized parameters
        unknown_params = set(args) - set(action_def.parameters)
        if unknown_params:
            raise AdapterParameterError(
                f"Unknown parameters {sorted(unknown_params)} passed to '{self.tool}:{action}'"
            )

        return cmd


class ToolAdapterRegistry:
    """Registry managing available tool adapters."""

    def __init__(
        self,
        definitions_path: Path | None = None,
        *,
        executable_sha256_pins: Mapping[str, str] | None = None,
    ) -> None:
        self.definitions_path = definitions_path or DEFINITIONS_DIR
        self._adapters: dict[str, ToolAdapter] = {}
        self._executable_sha256_pins = dict(executable_sha256_pins or {})
        for tool, sha256 in self._executable_sha256_pins.items():
            if not tool or not re.fullmatch(r"[0-9a-f]{64}", sha256):
                raise AdapterError(
                    f"platform executable pin for {tool!r} must be 64 lowercase hexadecimal characters"
                )
        self.load_definitions()
        unknown_pins = set(self._executable_sha256_pins) - set(self._adapters)
        if unknown_pins:
            raise AdapterError(f"executable pins reference unknown adapters: {sorted(unknown_pins)}")

    def load_definitions(self) -> None:
        """Load adapter JSON definitions from directory."""
        if not self.definitions_path.is_dir():
            return

        for p in sorted(self.definitions_path.glob("*.json")):
            data = json.loads(p.read_text(encoding="utf-8"))
            adapter = self._parse_adapter(data)
            pin = self._executable_sha256_pins.get(adapter.tool)
            if pin is not None:
                if adapter.executable_verification is None:
                    raise AdapterError(
                        f"adapter {adapter.tool!r} has no executable verification contract"
                    )
                adapter.executable_verification = replace(
                    adapter.executable_verification, sha256=pin
                )
            self._adapters[adapter.tool] = adapter

    def _parse_adapter(self, data: dict[str, Any]) -> ToolAdapter:
        actions: dict[str, ToolActionDefinition] = {}
        for action_name, act_data in data.get("actions", {}).items():
            params: dict[str, ToolParameter] = {}
            for p_name, p_data in act_data.get("parameters", {}).items():
                params[p_name] = ToolParameter(
                    name=p_name,
                    param_type=p_data.get("type", "string"),
                    flag=p_data.get("flag"),
                    required=p_data.get("required", False),
                    default=p_data.get("default"),
                    allowed_values=p_data.get("allowed_values", []),
                    regex_pattern=p_data.get("regex_pattern"),
                )
            actions[action_name] = ToolActionDefinition(
                action=action_name,
                description=act_data.get("description", ""),
                base_args=act_data.get("base_args", []),
                parameters=params,
            )

        verification = None
        execution_data = data.get("execution")
        if execution_data is not None:
            if not isinstance(execution_data, dict):
                raise AdapterError("adapter execution metadata must be an object")
            sha256 = execution_data.get("sha256")
            if sha256 is not None and (
                not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256)
            ):
                raise AdapterError("adapter execution sha256 must be 64 lowercase hexadecimal characters")
            version_args = execution_data.get("version_args", ["--version"])
            if not isinstance(version_args, list) or any(not isinstance(arg, str) for arg in version_args):
                raise AdapterError("adapter execution version_args must be a string list")
            version_pattern = execution_data.get("version_pattern")
            if not isinstance(version_pattern, str) or not version_pattern:
                raise AdapterError("adapter execution version_pattern must be a non-empty string")
            try:
                compiled_pattern = re.compile(version_pattern)
            except re.error as err:
                raise AdapterError(f"adapter execution version_pattern is invalid: {err}") from err
            if "version" not in compiled_pattern.groupindex and compiled_pattern.groups < 1:
                raise AdapterError(
                    "adapter execution version_pattern must contain a named 'version' or first capture group"
                )
            max_size_bytes = execution_data.get("max_size_bytes", 268_435_456)
            if not isinstance(max_size_bytes, int) or isinstance(max_size_bytes, bool) or max_size_bytes < 1:
                raise AdapterError("adapter execution max_size_bytes must be a positive integer")
            verification = ExecutableVerification(
                sha256=sha256,
                version_args=tuple(version_args),
                version_pattern=version_pattern,
                max_size_bytes=max_size_bytes,
            )

        return ToolAdapter(
            tool=data["tool"],
            version=data.get("version", "pinned"),
            binary=data.get("binary", data["tool"]),
            provenance=data.get("provenance", {}),
            supported_environments=data.get("supported_environments", ["linux", "darwin"]),
            actions=actions,
            executable_verification=verification,
        )

    def register_adapter(self, adapter: ToolAdapter) -> None:
        """Register an adapter programmatically."""
        self._adapters[adapter.tool] = adapter

    def get_adapter(self, tool: str) -> ToolAdapter:
        """Get an adapter by tool name."""
        if tool not in self._adapters:
            raise AdapterError(f"Tool '{tool}' is not registered in the adapter registry. Registered: {sorted(self._adapters)}")
        return self._adapters[tool]

    def list_tools(self) -> list[str]:
        """List registered tool names."""
        return sorted(self._adapters)
