"""Validate optional Agent Plugins v1.0.0 MCP configuration at authoring time."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
EXECUTABLE = re.compile(r"^[A-Za-z0-9_.+-]+$")
HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class MCPValidationError(ValueError):
    """An MCP configuration cannot be included in a portable package."""


def _contained(path: str, root: Path, location: str) -> None:
    if not path.startswith("./") or not (root / path).resolve().is_relative_to(root.resolve()):
        raise MCPValidationError(f"{location} must be a contained plugin-relative path")


def _contained_directory(path: str, root: Path, location: str) -> None:
    _contained(path, root, location)
    if not (root / path).is_dir():
        raise MCPValidationError(f"{location} must name a package directory")


def _validate_url(value: Any, location: str) -> None:
    if not isinstance(value, str):
        raise MCPValidationError(f"{location} must be an absolute HTTPS URL")
    if any(ord(char) <= 32 or char == "\\" for char in value):
        raise MCPValidationError(f"{location} has an invalid URL character")
    try:
        url = urlsplit(value)
        host = url.hostname
        port = url.port
    except ValueError as error:
        raise MCPValidationError(f"{location} has an invalid URL") from error
    if not host or port == 0 or url.username or url.password or url.fragment:
        raise MCPValidationError(f"{location} has an invalid URL or credentials")
    if url.scheme == "https":
        return
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if url.scheme != "http" or not loopback:
        raise MCPValidationError(f"{location} must use HTTPS except for loopback HTTP")


def validate_mcp_configuration(document: Any, location: str, root: Path) -> None:
    """Reject malformed or unsafe standard MCP entries before packaging."""

    if not isinstance(document, dict) or set(document) != {"$schema", "mcpServers"}:
        raise MCPValidationError(f"{location} must contain only $schema and mcpServers")
    if document["$schema"] != MCP_SCHEMA or not isinstance(document["mcpServers"], dict):
        raise MCPValidationError(f"{location} must use the Agent Plugins v1.0.0 MCP schema")
    for name, server in document["mcpServers"].items():
        item = f"{location}.mcpServers.{name}"
        if not isinstance(name, str) or not name or not isinstance(server, dict):
            raise MCPValidationError(f"{item} must be a named server object")
        kind = server.get("type")
        if kind == "stdio":
            if not {"type", "command"} <= set(server) or set(server) - {
                "type", "command", "args", "env", "cwd"
            }:
                raise MCPValidationError(f"{item} has invalid stdio fields")
            command = server["command"]
            if not isinstance(command, str) or not command:
                raise MCPValidationError(f"{item}.command must be one executable token")
            if command.startswith("./"):
                _contained(command, root, f"{item}.command")
                if not (root / command).is_file():
                    raise MCPValidationError(f"{item}.command must name a package file")
            elif not EXECUTABLE.fullmatch(command):
                raise MCPValidationError(f"{item}.command must be one executable token")
            args = server.get("args", [])
            if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
                raise MCPValidationError(f"{item}.args must be strings")
            env = server.get("env", {})
            if not isinstance(env, dict) or any(
                not isinstance(key, str) or not key or "=" in key or "\0" in key
                or key.casefold() in {"plugin_root", "plugin_data"}
                or not isinstance(value, str) or "\0" in value
                for key, value in env.items()
            ) or len({key.casefold() for key in env}) != len(env):
                raise MCPValidationError(
                    f"{item}.env must contain valid process environment names, "
                    "string values, and no reserved keys"
                )
            cwd = server.get("cwd")
            if cwd is not None:
                if not isinstance(cwd, str):
                    raise MCPValidationError(f"{item}.cwd must be a string")
                if cwd.startswith("./"):
                    _contained_directory(cwd, root, f"{item}.cwd")
                elif cwd.startswith("${PLUGIN_ROOT}"):
                    suffix = cwd[len("${PLUGIN_ROOT}"):]
                    if suffix and not suffix.startswith("/"):
                        raise MCPValidationError(f"{item}.cwd has invalid PLUGIN_ROOT syntax")
                    if suffix:
                        _contained_directory("." + suffix, root, f"{item}.cwd")
                elif cwd != "${PLUGIN_DATA}" and not cwd.startswith("${PLUGIN_DATA}/"):
                    raise MCPValidationError(f"{item}.cwd has an invalid root")
                elif ".." in Path(cwd[len("${PLUGIN_DATA}"):]).parts:
                    raise MCPValidationError(f"{item}.cwd escapes PLUGIN_DATA")
        elif kind in {"streamable-http", "sse"}:
            if not {"type", "url"} <= set(server) or set(server) - {"type", "url", "headers"}:
                raise MCPValidationError(f"{item} has invalid HTTP fields")
            _validate_url(server["url"], f"{item}.url")
            headers = server.get("headers", {})
            if not isinstance(headers, dict) or any(
                not isinstance(key, str) or not HEADER.fullmatch(key)
                or not isinstance(value, str) or "\r" in value or "\n" in value
                for key, value in headers.items()
            ) or len({key.lower() for key in headers}) != len(headers):
                raise MCPValidationError(f"{item}.headers must be unique valid HTTP fields")
        else:
            raise MCPValidationError(f"{item}.type is not supported by Agent Plugins v1.0.0")
