"""Bounded parsers for the supported lockfile and workflow subsets.

No include, environment substitution, URL, YAML tag, or action is evaluated.
Only package identities and content-free observation codes leave these parsers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


@dataclass
class SupplyInput:
    components: set[tuple[str, str, str]] = field(default_factory=set)
    codes: set[str] = field(default_factory=set)
    incomplete: bool = False


def package_name(value: str, ecosystem: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower() if ecosystem == "pypi" else value


def _registry_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "registry.npmjs.org"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
            and not any(char.isspace() for char in value)
        )
    except ValueError:
        return False


def npm_lock(data: dict[str, Any]) -> SupplyInput:
    result = SupplyInput()
    packages = data.get("packages")
    if not isinstance(packages, dict) or not packages:
        result.incomplete = True
        return result
    if len(packages) > 5000:
        result.incomplete = True
    for index, (path, record) in enumerate(packages.items()):
        if index >= 5000:
            break
        if not isinstance(path, str) or not isinstance(record, dict):
            result.incomplete = True
            continue
        # Root/workspace descriptions and symlinks are not registry tarballs.
        if not path or record.get("link") is True or "node_modules/" not in path:
            continue
        suffix = path.rsplit("node_modules/", 1)[1]
        name = record.get("name", suffix)
        version = record.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            result.incomplete = True
            continue
        result.components.add(("npm", name, version))
        if not _registry_url(record.get("resolved")):
            result.codes.add("npm_registry_resolution")
        if not isinstance(record.get("integrity"), str) or not record["integrity"].strip():
            result.codes.add("npm_integrity_missing")
    return result


def requirements_lock(content: str) -> SupplyInput:
    result = SupplyInput()
    logical: list[str] = []
    pending = ""
    for line in content.splitlines():
        pending += line.strip()
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        logical.append(re.split(r"\s+#", pending, maxsplit=1)[0].strip())
        pending = ""
        if len(logical) > 2000:
            result.incomplete = True
            break
    if pending:
        result.incomplete = True
    entries = [line for line in logical[:2000] if line and not line.startswith("#")]
    if not entries:
        result.incomplete = True
    for line in entries:
        if line.startswith("-") or "${" in line or " @ " in line or "://" in line or ";" in line:
            result.incomplete = True
            continue
        pin = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9,._-]+\])?==([^\s]+)", line)
        hashes = re.findall(r"(?:^|\s)--hash=sha256:([0-9a-fA-F]{64})(?=\s|$)", line)
        tail = line[pin.end() :] if pin else line
        remainder = re.sub(r"(?:^|\s)--hash=sha256:[0-9a-fA-F]{64}(?=\s|$)", "", tail).strip()
        if not pin or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", pin[2]) or not hashes or remainder:
            result.codes.add("python_dependency_unhashed")
            continue
        result.components.add(("pypi", package_name(pin[1], "pypi"), pin[2]))
    return result


def _scalar(value: str) -> str | None:
    value = value.strip()
    if value.startswith(("'", '"')):
        quote = value[0]
        end = value.find(quote, 1)
        tail = value[end + 1 :].strip() if end >= 0 else ""
        if end < 0 or (tail and not tail.startswith("#")):
            return None
        # Escaped/compound scalars are intentionally outside this subset.
        if "\\" in value[1:end] or quote in value[1:end]:
            return None
        return value[1:end]
    return value.split(" #", 1)[0].strip()


def github_actions(content: str) -> SupplyInput:
    result = SupplyInput()
    # A small indentation/scalar subset, not a general YAML interpreter.
    lines: list[tuple[int, str, str]] = []
    block_indent: int | None = None
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if block_indent is not None:
            if indent > block_indent:
                continue
            block_indent = None
        if "\t" in line[:indent] or re.search(r"(?:^|\s)[&*!][A-Za-z_]", line) or "<<:" in line:
            result.incomplete = True
        match = re.match(r"^\s*(?:-\s+)?([A-Za-z_][A-Za-z0-9_-]*|['\"]on['\"]):\s*(.*?)\s*$", line)
        if match:
            key, value = match.groups()
            if value in {"|", ">", "|-", ">-", "|+", ">+"}:
                block_indent = indent
                continue
            scalar = _scalar(value)
            if scalar is None:
                result.incomplete = True
                continue
            lines.append((indent, key.strip("'\""), scalar))
    uses = [(index, indent, value) for index, (indent, key, value) in enumerate(lines) if key == "uses"]
    if not uses:
        result.incomplete = True
    target_event = any(
        (key == "on" and "pull_request_target" in value) or key == "pull_request_target" for _, key, value in lines
    )
    for offset, (indent, key, value) in enumerate(lines):
        if key != "permissions":
            continue
        if value == "write-all" or re.search(r"\b[A-Za-z-]+\s*:\s*write\b", value):
            result.codes.add("workflow_write_permissions")
        elif value not in {"", "read-all", "{}"}:
            result.incomplete = True
        if not value:
            for child_indent, _, child_value in lines[offset + 1 :]:
                if child_indent <= indent:
                    break
                if child_value == "write":
                    result.codes.add("workflow_write_permissions")
                elif child_value not in {"read", "none"}:
                    result.incomplete = True
    for offset, indent, use in uses:
        if "${{" in use:
            result.incomplete = True
        if use.startswith("./"):
            if ".." in use.split("/") or "${{" in use:
                result.incomplete = True
            continue
        if use.startswith("docker://"):
            if not re.fullmatch(r"docker://[^\s@]+@sha256:[0-9a-fA-F]{64}", use):
                result.codes.add("action_container_unpinned")
        elif not re.fullmatch(r"[^\s@]+@[0-9a-fA-F]{40}", use):
            result.codes.add("action_unpinned")
        if target_event and use.split("@", 1)[0].lower() == "actions/checkout":
            for child_indent, child_key, child_value in lines[offset + 1 :]:
                if child_indent <= indent:
                    break
                if child_key in {"ref", "repository"} and re.search(
                    r"github\.event\.pull_request\.head\.", child_value
                ):
                    result.codes.add("workflow_untrusted_head")
    return result
