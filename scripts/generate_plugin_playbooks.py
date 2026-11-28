#!/usr/bin/env python3
"""Generate deterministic, non-executing operator assets for catalog plugins."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "cops.plugin-playbook/v1"
EXPECTED_PLUGIN_COUNT = 25
PLAYBOOK_RELATIVE = PurePosixPath("playbooks/offline-assessment.json")
WALKTHROUGH_RELATIVE = PurePosixPath("walkthroughs/offline-assessment.md")
DOC_BLOCK_START = "<!-- BEGIN COPS GENERATED OFFLINE ASSESSMENT LINKS -->"
DOC_BLOCK_END = "<!-- END COPS GENERATED OFFLINE ASSESSMENT LINKS -->"


class GenerationError(ValueError):
    """Raised when source metadata cannot produce a safe playbook."""


@dataclass(frozen=True)
class RenderedAsset:
    path: Path
    content: str


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GenerationError(f"cannot read JSON object {path}: {error}") from error
    if not isinstance(value, dict):
        raise GenerationError(f"expected JSON object: {path}")
    return value


def _safe_relative(value: str, *, label: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise GenerationError(f"{label} must be a repository-relative POSIX path: {value!r}")
    return path


def _normalized_argv(raw: Any, *, root: Path, working_directory: PurePosixPath, label: str) -> list[str]:
    if not isinstance(raw, list) or len(raw) < 2 or not all(isinstance(item, str) and item for item in raw):
        raise GenerationError(f"{label} command must be an argv list with an interpreter and script")
    if any("\0" in item or "\n" in item or "\r" in item for item in raw):
        raise GenerationError(f"{label} argv contains an unsafe control character")
    if raw[0] not in {"$PYTHON", "python3"}:
        raise GenerationError(f"{label} must use $PYTHON or python3")
    if raw[1] in {"-c", "-m"} or not raw[1].endswith(".py"):
        raise GenerationError(f"{label} must name a Python script, not inline or module execution")

    script = _safe_relative(raw[1], label=f"{label} script")
    resolved = root / working_directory / script
    if not resolved.is_file():
        raise GenerationError(f"{label} script does not exist: {(working_directory / script).as_posix()}")
    for argument in raw[2:]:
        if argument.startswith(("/", "~/")):
            raise GenerationError(f"{label} argv contains an absolute path: {argument!r}")
    return ["python3", *raw[1:]]


def _timeout(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 900:
        raise GenerationError(f"{label} timeout_seconds must be an integer from 1 through 900")
    return value


def _dedupe_strings(values: list[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        if isinstance(value, str) and value and value not in result:
            result.append(value)
    return result


def _string_list(raw: Any, *, label: str) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(value, str) and value for value in raw):
        raise GenerationError(f"{label} must be a list of non-empty strings")
    return _dedupe_strings(raw)


def _flag_paths(
    argv: list[str],
    *,
    flags: frozenset[str],
    working_directory: PurePosixPath,
    label: str,
) -> list[str]:
    """Return explicit path values normalized to repository-relative destinations."""

    values: list[str] = []
    for index, argument in enumerate(argv[2:], start=2):
        value: str | None = None
        flag = argument
        if "=" in argument:
            flag, value = argument.split("=", 1)
        elif argument in flags and index + 1 < len(argv):
            value = argv[index + 1]
        if flag not in flags or value is None:
            continue
        path = _safe_relative(value, label=f"{label} {flag}")
        values.append((working_directory / path).as_posix())
    return _dedupe_strings(values)


def _explicit_outputs(argv: list[str], *, working_directory: PurePosixPath) -> list[str]:
    return _flag_paths(
        argv,
        flags=frozenset({"--output", "--output-dir", "--report", "--report-dir"}),
        working_directory=working_directory,
        label="output destination",
    )


def _explicit_inputs(argv: list[str], *, working_directory: PurePosixPath) -> list[str]:
    return _flag_paths(
        argv,
        flags=frozenset(
            {
                "--config",
                "--fixture",
                "--fixtures",
                "--input",
                "--input-file",
                "--plan",
                "--policy",
                "--source",
            }
        ),
        working_directory=working_directory,
        label="input path",
    )


def _auth_effect(limitations: list[str]) -> str:
    joined = " ".join(limitations).lower()
    if any(word in joined for word in ("authoriz", "active", "live execution", "rules of engagement")):
        return "explicit authorization required for any live follow-on; this entrypoint is offline only"
    return "not applicable to this offline entrypoint"


def _entrypoint(
    *,
    entrypoint_id: str,
    purpose: str,
    raw_command: Any,
    timeout_seconds: Any,
    root: Path,
    working_directory: PurePosixPath,
    inputs: list[str],
    schemas: list[str],
    limitations: list[str],
) -> dict[str, Any]:
    argv = _normalized_argv(
        raw_command,
        root=root,
        working_directory=working_directory,
        label=entrypoint_id,
    )
    writes = _explicit_outputs(argv, working_directory=working_directory)
    script_path = (working_directory / PurePosixPath(argv[1])).as_posix()
    reads = _dedupe_strings([script_path, *_explicit_inputs(argv, working_directory=working_directory)])
    return {
        "id": entrypoint_id,
        "purpose": purpose,
        "working_directory": working_directory.as_posix() if working_directory.parts else ".",
        "argv": argv,
        "timeout_seconds": _timeout(timeout_seconds, label=entrypoint_id),
        "expectations": {
            "inputs": {
                "argv": argv[2:],
                "review_sources": inputs,
                "implementation_selected": (
                    "package-local fixtures may be selected inside the declared script; "
                    "review the script before invocation"
                ),
            },
            "outputs": {
                "process": ["exit status", "standard output", "standard error"],
                "schemas": schemas,
                "durable_destinations": writes,
            },
            "evidence": [
                "the declared command exits successfully",
                "reported results are limited to the supplied offline fixtures and metadata",
            ],
        },
        "effects": {
            "reads": reads,
            "read_scope": (
                "exact argv-declared repository paths; the script can also select package-local "
                "fixtures, so inspect its implementation before invocation"
            ),
            "writes": writes,
            "write_scope": (
                "complete durable destinations explicitly declared in argv; an empty list means "
                "no durable destination is declared, not that the implementation performs no "
                "temporary writes"
            ),
            "temporary_storage": ("implementation-controlled and not retained; location is not declared by argv"),
            "network": "none declared by the offline package contract",
            "authorization": _auth_effect(limitations),
            "subprocess": (
                "the generator executes none; operator invocation may run subprocesses "
                "implemented by the declared repository script"
            ),
        },
    }


def _authored_commands(markdown: str) -> list[list[str]]:
    normalized = re.sub(r"\s+", " ", markdown)
    commands: list[list[str]] = []
    for text in re.findall(r"`(python3\s+scripts/[^`]+)`", normalized):
        try:
            argv = shlex.split(text)
        except ValueError as error:
            raise GenerationError(f"cannot parse authored walkthrough command: {text!r}") from error
        if argv not in commands:
            commands.append(argv)
    return commands


def _catalog_records(root: Path, expected_count: int) -> list[dict[str, Any]]:
    catalog = _load_object(root / "catalog/plugins.json")
    records = catalog.get("plugins")
    if not isinstance(records, list):
        raise GenerationError("catalog/plugins.json must contain a plugins list")
    if len(records) != expected_count:
        raise GenerationError(f"catalog contains {len(records)} plugins; expected {expected_count}")
    ids: set[str] = set()
    paths: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise GenerationError(f"catalog plugin {index} must be an object")
        plugin_id = record.get("id")
        path = record.get("path")
        if not isinstance(plugin_id, str) or not plugin_id:
            raise GenerationError(f"catalog plugin {index} has no id")
        if not isinstance(path, str):
            raise GenerationError(f"catalog plugin {plugin_id} has no path")
        _safe_relative(path, label=f"catalog plugin {plugin_id} path")
        if plugin_id in ids or path in paths:
            raise GenerationError(f"duplicate catalog plugin id or path: {plugin_id}")
        ids.add(plugin_id)
        paths.add(path)
    return records


def _render_operator_playbook(content: str) -> str:
    """Append or replace the one managed links block without changing author text."""

    block = "\n".join(
        [
            DOC_BLOCK_START,
            "## Generated offline assessment",
            "",
            "- [Machine-readable playbook](../playbooks/offline-assessment.json)",
            "- [Runnable offline walkthrough](../walkthroughs/offline-assessment.md)",
            DOC_BLOCK_END,
        ]
    )
    start_count = content.count(DOC_BLOCK_START)
    end_count = content.count(DOC_BLOCK_END)
    if start_count != end_count or start_count > 1:
        raise GenerationError("docs/PLAYBOOK.md must contain at most one complete managed links block")
    if start_count == 1:
        start = content.index(DOC_BLOCK_START)
        end_marker = content.find(DOC_BLOCK_END, start + len(DOC_BLOCK_START))
        if end_marker < 0:
            raise GenerationError("docs/PLAYBOOK.md has its managed links block markers out of order")
        end = end_marker + len(DOC_BLOCK_END)
        return f"{content[:start]}{block}{content[end:]}"

    if not content:
        return f"{block}\n"
    separator = "" if content.endswith("\n\n") else "\n" if content.endswith("\n") else "\n\n"
    return f"{content}{separator}{block}\n"


def _render_plugin(root: Path, record: dict[str, Any]) -> tuple[RenderedAsset, RenderedAsset, RenderedAsset]:
    plugin_id = record["id"]
    package_path = _safe_relative(record["path"], label=f"catalog plugin {plugin_id} path")
    package_dir = root / package_path
    metadata = _load_object(package_dir / "package.json")
    if metadata.get("id") != plugin_id:
        raise GenerationError(f"catalog id {plugin_id} does not match {package_path}/package.json")
    operator_playbook = package_dir / "docs/PLAYBOOK.md"
    if not operator_playbook.is_file():
        raise GenerationError(f"missing operator playbook: {package_path}/docs/PLAYBOOK.md")
    operator_playbook_content = operator_playbook.read_text(encoding="utf-8")

    limitations = _string_list(metadata.get("limitations"), label=f"{plugin_id} limitations")
    support = metadata.get("support")
    if not isinstance(support, dict):
        raise GenerationError(f"{plugin_id} package support must be an object")
    demo = metadata.get("demo")
    validations = metadata.get("validation")
    if not isinstance(demo, dict) or not isinstance(validations, list):
        raise GenerationError(f"{plugin_id} must declare demo and validation entrypoints")

    source_inputs = [
        f"{package_path.as_posix()}/package.json",
        f"{package_path.as_posix()}/docs/PLAYBOOK.md",
    ]
    entrypoints = [
        _entrypoint(
            entrypoint_id="demo",
            purpose=str(demo.get("description", "Run the declared offline demonstration.")),
            raw_command=demo.get("command"),
            timeout_seconds=demo.get("timeout_seconds"),
            root=root,
            working_directory=PurePosixPath(),
            inputs=source_inputs,
            schemas=[],
            limitations=limitations,
        )
    ]
    for index, validation in enumerate(validations):
        if not isinstance(validation, dict):
            raise GenerationError(f"{plugin_id} validation {index} must be an object")
        entrypoints.append(
            _entrypoint(
                entrypoint_id=f"validation-{index + 1}",
                purpose=str(validation.get("name", f"Validation {index + 1}")),
                raw_command=validation.get("command"),
                timeout_seconds=validation.get("timeout_seconds"),
                root=root,
                working_directory=PurePosixPath(),
                inputs=source_inputs,
                schemas=[],
                limitations=limitations,
            )
        )

    authored_path = package_dir / "docs/offline-assessment.json"
    authored_markdown_path = package_dir / "docs/offline-assessment.md"
    normalized_authored: dict[str, Any] | None = None
    authored_commands: list[list[str]] = []
    if authored_path.exists() or authored_markdown_path.exists():
        if not authored_path.is_file() or not authored_markdown_path.is_file():
            raise GenerationError(f"{plugin_id} authored offline assessment must include both JSON and Markdown")
        authored = _load_object(authored_path)
        if authored.get("package_id") != plugin_id:
            raise GenerationError(f"{plugin_id} authored offline assessment package_id does not match")
        authored_inputs = _string_list(authored.get("inputs"), label=f"{plugin_id} authored inputs")
        authored_outputs = _string_list(authored.get("outputs"), label=f"{plugin_id} authored outputs")
        for value in authored_inputs:
            safe = _safe_relative(value, label=f"{plugin_id} authored input")
            if not (package_dir / safe).exists():
                raise GenerationError(f"{plugin_id} authored input does not exist: {value}")
        authored_limitations = _string_list(authored.get("limitations"), label=f"{plugin_id} authored limitations")
        limitations = _dedupe_strings([*limitations, *authored_limitations])
        authored_commands = _authored_commands(authored_markdown_path.read_text(encoding="utf-8"))
        if not authored_commands:
            raise GenerationError(f"{plugin_id} authored walkthrough has no Python argv")
        for index, command in enumerate(authored_commands):
            entrypoints.append(
                _entrypoint(
                    entrypoint_id=f"authored-offline-{index + 1}",
                    purpose="Run a preserved command from docs/offline-assessment.md.",
                    raw_command=command,
                    timeout_seconds=120,
                    root=root,
                    working_directory=package_path,
                    inputs=[f"{package_path.as_posix()}/{value}" for value in authored_inputs],
                    schemas=authored_outputs,
                    limitations=limitations,
                )
            )
        normalized_authored = {
            "source_schema_version": authored.get("schema_version"),
            "capability": authored.get("capability"),
            "readiness": authored.get("readiness"),
            "entrypoints": authored.get("entrypoints"),
            "inputs": authored_inputs,
            "outputs": authored_outputs,
            "permissions": authored.get("permissions"),
        }

    playbook: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "plugin_id": plugin_id,
        "package_path": package_path.as_posix(),
        "purpose": metadata.get("summary"),
        "status": {
            "maturity": metadata.get("maturity"),
            "support": support,
            "offline_workflow": support.get("offline_workflow", "unverified"),
            "isolated_laboratory": "unverified",
        },
        "entrypoints": entrypoints,
        "limitations": limitations,
        "links": {
            "package_contract": "../package.json",
            "operator_playbook": "../docs/PLAYBOOK.md",
            "walkthrough": "../walkthroughs/offline-assessment.md",
        },
        "generation": {
            "source": "catalog/plugins.json and package metadata",
            "commands_executed": False,
        },
    }
    if normalized_authored is not None:
        playbook["authored_offline_assessment"] = normalized_authored
        playbook["links"]["authored_assessment_contract"] = "../docs/offline-assessment.json"
        playbook["links"]["authored_assessment_walkthrough"] = "../docs/offline-assessment.md"

    playbook_content = json.dumps(playbook, indent=2, sort_keys=True) + "\n"
    walkthrough_content = _render_walkthrough(
        plugin_id=plugin_id,
        package_path=package_path,
        summary=str(metadata.get("summary", "")),
        entrypoints=entrypoints,
        limitations=limitations,
        authored=normalized_authored,
    )
    return (
        RenderedAsset(package_dir / PLAYBOOK_RELATIVE, playbook_content),
        RenderedAsset(package_dir / WALKTHROUGH_RELATIVE, walkthrough_content),
        RenderedAsset(operator_playbook, _render_operator_playbook(operator_playbook_content)),
    )


def _render_walkthrough(
    *,
    plugin_id: str,
    package_path: PurePosixPath,
    summary: str,
    entrypoints: list[dict[str, Any]],
    limitations: list[str],
    authored: dict[str, Any] | None,
) -> str:
    lines = [
        f"# {plugin_id} offline walkthrough",
        "",
        summary,
        "",
        "This walkthrough uses only declared repository Python entrypoints. Review the",
        "[operator playbook](../docs/PLAYBOOK.md) and the",
        "[machine-readable playbook](../playbooks/offline-assessment.json) before running them.",
        "The generator records commands as argv and does not execute them.",
        "",
        "Run repository-root entrypoints from the repository root. Commands marked with the",
        "package directory run from the exported package directory.",
        "",
    ]
    for index, entrypoint in enumerate(entrypoints, start=1):
        working_directory = entrypoint["working_directory"]
        command = shlex.join(entrypoint["argv"])
        lines.extend(
            [
                f"## {index}. {entrypoint['id']}",
                "",
                str(entrypoint["purpose"]),
                "",
                f"Working directory: `{working_directory}`.",
                "",
                "```text",
                command,
                "```",
                "",
                "Expected evidence:",
                "",
                *[f"- {value}." for value in entrypoint["expectations"]["evidence"]],
                f"- Expected durable writes: `{entrypoint['effects']['writes']}`.",
                "",
            ]
        )

    lines.extend(["## Corrected and insufficient paths", ""])
    if authored is not None:
        lines.extend(
            [
                "The preserved authored playback reads `examples/correction-cases.json`, which",
                "contains vulnerable, corrected, insufficient, and benign comparison cases. A",
                "corrected result demonstrates only the fixture transition. An insufficient result",
                "must remain incomplete; it must not be promoted to live or production evidence.",
                "See the [authored offline walkthrough](../docs/offline-assessment.md).",
            ]
        )
    else:
        lines.extend(
            [
                "This package does not declare a separate corrected/insufficient fixture pair.",
                "A successful demo or validation exit status is therefore structural or offline",
                "evidence only; absence of that comparison is insufficient evidence of live",
                "effectiveness, installation, or authorization.",
            ]
        )

    lines.extend(["", "## Cleanup and reset", ""])
    write_paths = _dedupe_strings([path for entrypoint in entrypoints for path in entrypoint["effects"]["writes"]])
    if write_paths:
        lines.append("Remove only the declared generated destinations after reviewing their evidence:")
        lines.append("")
        for path in write_paths:
            lines.append(f"- `{path}`")
        lines.append("")
    else:
        lines.append("The declared entrypoints have no durable output destination in their argv.")
        lines.append("")
    lines.extend(
        [
            "Inspect package changes from the repository root:",
            "",
            "```text",
            f"git status --short -- {package_path.as_posix()}",
            "```",
            "",
            "Restore or delete only files created by the walkthrough. Do not reset unrelated work.",
            "",
            "## Limits",
            "",
            *[f"- {value}" for value in limitations],
            "- Isolated laboratory execution is unverified unless separate run evidence says otherwise.",
            "- These offline commands do not establish source authenticity or permission for live actions.",
            "",
        ]
    )
    return "\n".join(lines)


def render_repository(root: Path, *, expected_count: int = EXPECTED_PLUGIN_COUNT) -> list[RenderedAsset]:
    """Render all catalog assets in memory without executing package entrypoints."""

    root = root.resolve()
    assets: list[RenderedAsset] = []
    for record in _catalog_records(root, expected_count):
        assets.extend(_render_plugin(root, record))
    return assets


def synchronize(root: Path, *, check: bool, expected_count: int = EXPECTED_PLUGIN_COUNT) -> list[Path]:
    """Write or verify generated assets and return changed or stale paths."""

    root = root.resolve()
    assets = render_repository(root, expected_count=expected_count)
    changed: list[Path] = []
    for asset in assets:
        current = asset.path.read_text(encoding="utf-8") if asset.path.is_file() else None
        if current == asset.content:
            continue
        changed.append(asset.path.relative_to(root))
        if not check:
            asset.path.parent.mkdir(parents=True, exist_ok=True)
            asset.path.write_text(asset.content, encoding="utf-8")
    return changed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true", help="Report stale assets without writing them.")
    parser.add_argument("--expected-count", type=int, default=EXPECTED_PLUGIN_COUNT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        changed = synchronize(args.root, check=args.check, expected_count=args.expected_count)
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if args.check and changed:
        for path in changed:
            print(f"stale generated asset: {path}", file=sys.stderr)
        return 1
    action = "verified" if args.check else "generated"
    print(f"{action} {args.expected_count} plugin playbooks and walkthroughs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
