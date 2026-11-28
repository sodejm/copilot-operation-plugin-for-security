"""Source-backed feature inventory. Parsing files never proves implementation."""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

from .catalog import declarations
from .contracts import MAX_BYTES, OperationError, decode

SUPPORT_STATES = {"implemented", "externally_delegated", "blocked_by_prerequisite", "unsupported"}


def package_path(root, record):
    relative = Path(record["path"])
    if (
        len(relative.parts) != 3
        or relative.parts[0] != "plugins"
        or relative.parts[2] != record["id"]
        or any(not re.fullmatch(r"[a-z0-9-]+", part) for part in relative.parts)
    ):
        raise OperationError("unsafe_inventory_path")
    path = Path(root) / relative
    if not path.resolve().is_relative_to(Path(root).resolve()):
        raise OperationError("unsafe_inventory_path")
    return path


def _source(path, root):
    if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
        raise OperationError("unsafe_inventory_path")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise OperationError("inventory_source_limit")
    return raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()


def build_features(root: Path, records):
    features = []
    operations = declarations()
    for record in records:
        package = package_path(root, record)
        for path in sorted((package / "skills").glob("*/SKILL.md")):
            text, checksum = _source(path, root)
            relative = path.relative_to(root).as_posix()
            features.append(
                {
                    "feature_id": "skill:" + relative,
                    "plugin_id": record["id"],
                    "kind": "skill",
                    "source": relative,
                    "source_digest": checksum,
                    "headless_status": "externally_delegated",
                    "operation_ids": [],
                    "reason": "The harness interprets this skill; existence is not executable tool coverage.",
                }
            )
            for match in re.finditer(r"(?m)^[ \t]*(\d+)[.)][ \t]+(.+)$", text):
                ordinal = match.group(1)
                line = text.count("\n", 0, match.start()) + 1
                features.append(
                    {
                        "feature_id": "step:" + relative + ":" + str(line),
                        "plugin_id": record["id"],
                        "kind": "skill_step",
                        "source": relative,
                        "source_digest": checksum,
                        "line": line,
                        "ordinal": ordinal,
                        "headless_status": "unsupported",
                        "operation_ids": [],
                        "reason": "This specific prose step has no reviewed typed-operation binding yet.",
                    }
                )
        for path in sorted(package.rglob("*.py")):
            local = path.relative_to(package)
            if any(part in {"vendor", "tests", "__pycache__", ".venv"} for part in local.parts):
                continue
            text, checksum = _source(path, root)
            tree = ast.parse(text)
            relative = path.relative_to(root).as_posix()
            commands = []
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_parser"
                ):
                    name = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
                    commands.append((node.lineno, name if isinstance(name, str) else None))
            is_entrypoint = bool(re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]", text))
            if not commands and is_entrypoint:
                commands.append((1, "entrypoint"))
            for line, name in commands:
                features.append(
                    {
                        "feature_id": "cli:" + relative + ":" + str(line),
                        "plugin_id": record["id"],
                        "kind": "cli" if name is not None else "dynamic_cli",
                        "source": relative,
                        "source_digest": checksum,
                        "line": line,
                        "command": name,
                        "headless_status": "unsupported",
                        "operation_ids": [],
                        "reason": (
                            "No reviewed structured binding for this public CLI entrypoint."
                            if name
                            else "Dynamic CLI declarations require explicit review; not omitted."
                        ),
                    }
                )
        for operation in operations:
            if operation["owner"] != record["id"]:
                continue
            features.append(
                {
                    "feature_id": "operation:" + operation["operation_id"],
                    "plugin_id": record["id"],
                    "kind": "operation",
                    "source": "cops/operations/catalog.py",
                    "source_digest": hashlib.sha256((root / "cops/operations/catalog.py").read_bytes()).hexdigest(),
                    "headless_status": "implemented",
                    "operation_ids": [operation["operation_id"]],
                    "reason": "Reviewed shared Python handler with behavioral and distribution conformance.",
                    "behavioral_test": "tests/test_headless_operations.py",
                }
            )
    return features


def summarize(features):
    return {
        "total": len(features),
        "by_status": {
            state: sum(row["headless_status"] == state for row in features) for state in sorted(SUPPORT_STATES)
        },
        "unresolved_cli_declarations": sum(row["kind"] == "dynamic_cli" for row in features),
    }


def query(root, *, plugin_id=None, feature_id=None, offset=0, limit=50):
    with (Path(root) / "catalog/features.json").open("rb") as stream:
        document = decode(stream.read(MAX_BYTES + 1))
    features = document["features"]
    if feature_id is not None:
        result = next((row for row in features if row["feature_id"] == feature_id), None)
        if result is None:
            raise OperationError("unknown_feature")
        return {"feature": result, "execution_authorized": False}
    if plugin_id is not None:
        if plugin_id not in document["plugin_ids"]:
            raise OperationError("unknown_package")
        features = [row for row in features if row["plugin_id"] == plugin_id]
    return {
        "summary": summarize(features),
        "features": features[offset : offset + limit],
        "next_offset": offset + limit if offset + limit < len(features) else None,
        "package_feature_complete": False,
    }
