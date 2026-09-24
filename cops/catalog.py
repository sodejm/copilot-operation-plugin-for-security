"""Load the repository catalog and safely expand declared package commands."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


class CatalogError(ValueError):
    """The catalog or one of its package records is invalid."""


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def load_json(path: Path, root: Path = ROOT) -> dict[str, Any]:
    """Load a JSON object with repository-relative diagnostics."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise CatalogError(f"missing JSON file: {_relative(path, root)}") from error
    except json.JSONDecodeError as error:
        raise CatalogError(f"invalid JSON in {_relative(path, root)}: {error}") from error
    if not isinstance(value, dict):
        raise CatalogError(f"JSON document must be an object: {_relative(path, root)}")
    return value


@dataclass(frozen=True)
class PluginRecord:
    """One catalog entry paired with its repository governance contract."""

    id: str
    name: str
    version: str
    primary_category: str
    path: str
    tags: tuple[str, ...]
    package: dict[str, Any]

    @property
    def maturity(self) -> str:
        return str(self.package["maturity"])

    @property
    def support(self) -> dict[str, str]:
        value = self.package["support"]
        if not isinstance(value, dict):
            raise CatalogError(f"{self.id} support declaration must be an object")
        return {str(key): str(item) for key, item in value.items()}


def catalog_document(root: Path = ROOT) -> dict[str, Any]:
    return load_json(root / "catalog" / "plugins.json", root)


def plugin_records(root: Path = ROOT) -> list[PluginRecord]:
    """Return cataloged plugins in their declared display order."""

    document = catalog_document(root)
    raw_plugins = document.get("plugins")
    if not isinstance(raw_plugins, list):
        raise CatalogError("catalog/plugins.json.plugins must be an array")
    records: list[PluginRecord] = []
    for index, raw in enumerate(raw_plugins):
        if not isinstance(raw, dict):
            raise CatalogError(f"catalog/plugins.json.plugins[{index}] must be an object")
        try:
            plugin_id = str(raw["id"])
            path = str(raw["path"])
            raw_tags = raw["tags"]
            if not isinstance(raw_tags, list):
                raise CatalogError(
                    f"catalog/plugins.json.plugins[{index}].tags must be an array"
                )
            tags = tuple(str(tag) for tag in raw_tags)
            package = load_json(root / path / "package.json", root)
            records.append(
                PluginRecord(
                    id=plugin_id,
                    name=str(raw["name"]),
                    version=str(raw["version"]),
                    primary_category=str(raw["primary_category"]),
                    path=path,
                    tags=tags,
                    package=package,
                )
            )
        except KeyError as error:
            raise CatalogError(
                f"catalog/plugins.json.plugins[{index}] is missing {error.args[0]}"
            ) from error
    return records


def find_plugin(plugin_id: str, root: Path = ROOT) -> PluginRecord:
    for record in plugin_records(root):
        if record.id == plugin_id:
            return record
    choices = ", ".join(record.id for record in plugin_records(root))
    raise CatalogError(f"unknown plugin {plugin_id!r}; choose one of: {choices}")


def validate_declared_command(
    definition: dict[str, Any],
    record: PluginRecord,
    root: Path = ROOT,
) -> tuple[list[str], int]:
    """Validate and expand a command without involving a command shell.

    Package contracts intentionally permit only a repository-owned Python entry
    point. Arguments remain ordinary argv values, so shell operators, command
    substitution, and environment expansion have no execution semantics.
    """

    command = definition.get("command")
    if not isinstance(command, list) or len(command) < 2:
        raise CatalogError(f"{record.id} command must contain $PYTHON and a script path")
    if any(not isinstance(token, str) or not token for token in command):
        raise CatalogError(f"{record.id} command tokens must be non-empty strings")
    if any("\x00" in token or "\n" in token or "\r" in token for token in command):
        raise CatalogError(f"{record.id} command tokens must be single-line text")
    if command[0] != "$PYTHON":
        raise CatalogError(f"{record.id} commands must start with $PYTHON")

    script_token = command[1]
    script_path = Path(script_token)
    if script_path.is_absolute() or ".." in script_path.parts:
        raise CatalogError(f"{record.id} command script must stay inside its package")
    if script_path.suffix != ".py":
        raise CatalogError(f"{record.id} command must use a repository-relative Python script")
    resolved_script = (root / script_path).resolve()
    package_root = (root / record.path).resolve()
    if not resolved_script.is_relative_to(package_root):
        raise CatalogError(f"{record.id} command script must stay inside its package")
    if not resolved_script.is_file():
        raise CatalogError(f"{record.id} command script does not exist: {script_token}")

    timeout = definition.get("timeout_seconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 900:
        raise CatalogError(f"{record.id} command timeout_seconds must be an integer from 1 to 900")
    return [sys.executable, *command[1:]], timeout
