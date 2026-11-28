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


@dataclass(frozen=True)
class _WorkflowEntry:
    indent: int
    key: str
    value: str
    parent: int | None
    item: int | None


def _workflow_entries(content: str, result: SupplyInput) -> list[_WorkflowEntry]:
    # A small indentation/scalar subset, not a general YAML interpreter. Mapping
    # parents and sequence identities keep sibling steps from sharing inputs.
    lines: list[_WorkflowEntry] = []
    mappings: list[int] = []
    items: list[tuple[int, int]] = []
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
        match = re.match(r"^\s*(-\s+)?([A-Za-z_][A-Za-z0-9_-]*|['\"]on['\"]):\s*(.*?)\s*$", line)
        if not match:
            result.incomplete = True
            continue
        sequence, key, value = match.groups()
        key_indent = indent + len(sequence or "")
        while mappings and lines[mappings[-1]].indent >= (indent if sequence else key_indent):
            mappings.pop()
        while items and items[-1][0] >= indent:
            items.pop()
        if sequence:
            items.append((indent, len(lines)))
        scalar = _scalar(value)
        if scalar is None:
            result.incomplete = True
            scalar = value
        if value in {"|", ">", "|-", ">-", "|+", ">+"}:
            block_indent = key_indent
        lines.append(
            _WorkflowEntry(
                key_indent,
                key.strip("'\""),
                scalar,
                mappings[-1] if mappings else None,
                items[-1][1] if items else None,
            )
        )
        if scalar == "":
            mappings.append(len(lines) - 1)
    return lines


def _checkout_inputs(lines: list[_WorkflowEntry], entry: _WorkflowEntry, result: SupplyInput) -> None:
    if entry.item is None or entry.parent is None or lines[entry.parent].key != "steps":
        result.incomplete = True
        return
    siblings = [
        (index, item) for index, item in enumerate(lines) if item.parent == entry.parent and item.item == entry.item
    ]
    inputs = [(index, item) for index, item in siblings if item.key == "with"]
    if len(inputs) > 1 or sum(item.key == "uses" for _, item in siblings) != 1:
        result.incomplete = True
        return
    if not inputs:
        return
    offset, mapping = inputs[0]
    if mapping.value:
        result.incomplete = True
        return
    fields = [item for item in lines if item.parent == offset]
    if len({item.key for item in fields}) != len(fields):
        result.incomplete = True
        return
    for item in fields:
        if item.key in {"ref", "repository"} and re.search(r"github\.event\.pull_request\.head\.", item.value):
            result.codes.add("workflow_untrusted_head")


def github_actions(content: str) -> SupplyInput:
    result = SupplyInput()
    lines = _workflow_entries(content, result)
    uses = [entry for entry in lines if entry.key == "uses"]
    if not uses:
        result.incomplete = True
    triggers = [
        (index, entry)
        for index, entry in enumerate(lines)
        if entry.key == "on" and entry.parent is None and entry.item is None
    ]
    target_event = False
    if len(triggers) > 1:
        result.incomplete = True
    elif triggers:
        index, trigger = triggers[0]
        if not trigger.value:
            target_event = any(
                entry.parent == index and entry.item is None and entry.key == "pull_request_target" for entry in lines
            )
        else:
            value = trigger.value
            events = value[1:-1].split(",") if value.startswith("[") and value.endswith("]") else [value]
            names = [_scalar(event) for event in events]
            if any(name is None or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names):
                result.incomplete = True
            else:
                target_event = "pull_request_target" in names
    for offset, entry in enumerate(lines):
        indent, key, value = entry.indent, entry.key, entry.value
        if key != "permissions":
            continue
        if value == "write-all" or re.search(r"\b[A-Za-z-]+\s*:\s*write\b", value):
            result.codes.add("workflow_write_permissions")
        elif value not in {"", "read-all", "{}"}:
            result.incomplete = True
        if not value:
            for child in lines[offset + 1 :]:
                if child.indent <= indent:
                    break
                if child.value == "write":
                    result.codes.add("workflow_write_permissions")
                elif child.value not in {"read", "none"}:
                    result.incomplete = True
    for entry in uses:
        use = entry.value
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
            _checkout_inputs(lines, entry, result)
    return result
