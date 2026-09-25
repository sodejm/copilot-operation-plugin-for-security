"""Deterministic COPS catalog, package, skill, and host-index validation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .catalog import CatalogError, PluginRecord, load_json, plugin_records, validate_declared_command
from .prerequisites import validate_prerequisites


ROOT = Path(__file__).resolve().parents[1]
AGENT_PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
AGENT_PLUGIN_KEYS = {
    "$schema", "name", "version", "description", "author", "homepage",
    "repository", "license", "keywords", "extensions",
}
PLUGIN_NAME = re.compile(r"^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
SKILL_NAME = re.compile(r"^(?!.*--)[a-z0-9]+(?:-[a-z0-9]+)*$")
EXTENSION_NAME = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9-]+)+$")
MATURITY = {"experimental", "beta", "stable"}
SUPPORT = {
    "structural_validation": {"validated", "unverified"},
    "offline_workflow": {"validated", "unverified", "not_applicable"},
    "host_installation": {"validated", "unverified", "not_applicable"},
    "live_integration": {"validated", "unverified", "not_applicable"},
}
HOST_INDEX_PATHS = {
    "Codex": Path(".agents/plugins/marketplace.json"),
    "GitHub Copilot": Path(".github/plugin/marketplace.json"),
    "Claude": Path(".claude-plugin/marketplace.json"),
}
PACKAGE_KEYS = {
    "schema_version",
    "id",
    "display_name",
    "maturity",
    "summary",
    "support",
    "limitations",
    "demo",
    "validation",
}
CATEGORY_KEYS = {"id", "name", "description"}
MARKETPLACE_KEYS = {"name", "owner"}
CATALOG_PLUGIN_KEYS = {
    "id",
    "name",
    "version",
    "primary_category",
    "path",
    "tags",
}


class ValidationError(CatalogError):
    """A deterministic repository contract failure."""


def validate_agent_plugin_manifest(manifest: Any, location: str) -> None:
    """Check the closed Agent Plugins v1.0.0 manifest contract offline."""

    if not isinstance(manifest, dict):
        raise ValidationError(f"{location} must be an object")
    unknown = set(manifest) - AGENT_PLUGIN_KEYS
    if unknown:
        raise ValidationError(f"{location} has unknown Agent Plugins fields: {sorted(unknown)}")
    if manifest.get("$schema") != AGENT_PLUGIN_SCHEMA:
        raise ValidationError(f"{location}.$schema must be {AGENT_PLUGIN_SCHEMA}")
    name = manifest.get("name")
    if not isinstance(name, str) or len(name) > 64 or not PLUGIN_NAME.fullmatch(name):
        raise ValidationError(f"{location}.name violates Agent Plugins v1.0.0 name constraints")
    for key in ("version", "description", "homepage", "repository", "license"):
        if key in manifest and not isinstance(manifest[key], str):
            raise ValidationError(f"{location}.{key} must be a string")
    if "author" in manifest:
        author = manifest["author"]
        if not isinstance(author, dict) or set(author) - {"name", "email", "url"}:
            raise ValidationError(f"{location}.author may contain only name, email, and url")
        if any(not isinstance(value, str) for value in author.values()):
            raise ValidationError(f"{location}.author values must be strings")
    if "keywords" in manifest:
        values = manifest["keywords"]
        if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
            raise ValidationError(f"{location}.keywords must be an array of strings")
    if "extensions" in manifest:
        extensions = manifest["extensions"]
        if not isinstance(extensions, dict) or any(
            not isinstance(key, str) or not EXTENSION_NAME.fullmatch(key)
            or not isinstance(value, dict)
            for key, value in extensions.items()
        ):
            raise ValidationError(f"{location}.extensions must map reverse-domain names to objects")


def _require_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{location} must be a non-empty string")
    return value


def _require_string_list(value: Any, location: str, *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "a non-empty array" if nonempty else "an array"
        raise ValidationError(f"{location} must be {qualifier}")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValidationError(f"{location} must contain non-empty strings")
    return value


def _validate_codex_manifest(manifest: dict[str, Any], record: PluginRecord) -> None:
    """Validate the stable Codex plugin identity and user-facing interface contract."""

    location = f"{record.path}/.codex-plugin/plugin.json"
    if manifest.get("name") != record.id or manifest.get("version") != record.version:
        raise ValidationError(f"{location} name and version must match the catalog")
    _require_string(manifest.get("description"), f"{location}.description")
    if manifest.get("skills") not in {"./skills", "./skills/"}:
        raise ValidationError(f"{location}.skills must reference ./skills/")

    author = manifest.get("author")
    if not isinstance(author, dict):
        raise ValidationError(f"{location}.author must be an object")
    _require_string(author.get("name"), f"{location}.author.name")

    interface = manifest.get("interface")
    if not isinstance(interface, dict):
        raise ValidationError(f"{location}.interface must be an object")
    for field in (
        "displayName",
        "shortDescription",
        "longDescription",
        "developerName",
        "category",
    ):
        _require_string(interface.get(field), f"{location}.interface.{field}")
    _require_string_list(interface.get("capabilities"), f"{location}.interface.capabilities")
    prompts = _require_string_list(
        interface.get("defaultPrompt"), f"{location}.interface.defaultPrompt"
    )
    if len(prompts) > 3:
        raise ValidationError(f"{location}.interface.defaultPrompt must contain at most 3 prompts")
    if any(len(prompt) > 128 for prompt in prompts):
        raise ValidationError(
            f"{location}.interface.defaultPrompt entries must not exceed 128 characters"
        )


def _skill_frontmatter(path: Path, root: Path) -> tuple[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise ValidationError(f"missing skill file: {path.relative_to(root)}") from error
    match = re.match(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)", text, re.DOTALL)
    if not match:
        raise ValidationError(f"{path.relative_to(root)} must start with YAML frontmatter")
    fields: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            raise ValidationError(f"{path.relative_to(root)} contains invalid frontmatter")
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip().strip('"').strip("'")
    if set(fields) != {"name", "description"}:
        raise ValidationError(
            f"{path.relative_to(root)} frontmatter must contain only name and description"
        )
    if fields["name"] != path.parent.name:
        raise ValidationError(f"{path.relative_to(root)} name must match its directory")
    if len(fields["name"]) > 64 or not SKILL_NAME.fullmatch(fields["name"]):
        raise ValidationError(f"{path.relative_to(root)} has an invalid Agent Skills name")
    _require_string(fields["description"], f"{path.relative_to(root)}.description")
    if len(fields["description"]) > 1024:
        raise ValidationError(f"{path.relative_to(root)}.description exceeds 1024 characters")
    return fields["name"], fields["description"]


def _validate_command_definition(
    definition: Any,
    location: str,
    record: PluginRecord,
    root: Path,
    *,
    require_name: bool,
) -> None:
    if not isinstance(definition, dict):
        raise ValidationError(f"{location} must be an object")
    expected_keys = {"command", "timeout_seconds", "name" if require_name else "description"}
    if set(definition) != expected_keys:
        raise ValidationError(f"{location} must declare exactly {sorted(expected_keys)}")
    if require_name:
        _require_string(definition.get("name"), f"{location}.name")
    try:
        validate_declared_command(definition, record, root)
    except CatalogError as error:
        raise ValidationError(f"{location}: {error}") from error


def validate_package(record: PluginRecord, root: Path = ROOT) -> None:
    """Validate one package's identity, governance, skills, and commands."""

    location = f"{record.path}/package.json"
    package = record.package
    if set(package) != PACKAGE_KEYS:
        raise ValidationError(f"{location} must declare exactly {sorted(PACKAGE_KEYS)}")
    if package.get("schema_version") != "1.0":
        raise ValidationError(f"{location}.schema_version must be '1.0'")
    if package.get("id") != record.id:
        raise ValidationError(f"{location}.id must match catalog id {record.id}")
    if package.get("display_name") != record.name:
        raise ValidationError(f"{location}.display_name must match the catalog")
    if package.get("maturity") not in MATURITY:
        raise ValidationError(f"{location}.maturity must be one of {sorted(MATURITY)}")
    _require_string(package.get("summary"), f"{location}.summary")
    _require_string_list(package.get("limitations"), f"{location}.limitations")

    support = package.get("support")
    if not isinstance(support, dict) or set(support) != set(SUPPORT):
        raise ValidationError(f"{location}.support must declare exactly {sorted(SUPPORT)}")
    for field, allowed in SUPPORT.items():
        if support[field] not in allowed:
            raise ValidationError(f"{location}.support.{field} must be one of {sorted(allowed)}")
    if support["host_installation"] == "validated":
        raise ValidationError(
            f"{location}.support.host_installation cannot be validated without a host evidence record"
        )
    if support["live_integration"] == "validated":
        raise ValidationError(
            f"{location}.support.live_integration cannot be validated without a live evidence record"
        )

    _validate_command_definition(package.get("demo"), f"{location}.demo", record, root, require_name=False)
    demo = package["demo"]
    _require_string(demo.get("description"), f"{location}.demo.description")
    validations = package.get("validation")
    if not isinstance(validations, list) or not validations:
        raise ValidationError(f"{location}.validation must be a non-empty array")
    names: set[str] = set()
    for index, definition in enumerate(validations):
        command_location = f"{location}.validation[{index}]"
        _validate_command_definition(definition, command_location, record, root, require_name=True)
        name = str(definition["name"])
        if name in names:
            raise ValidationError(f"{location}.validation contains duplicate name {name}")
        names.add(name)

    package_root = root / record.path
    resolved_root = package_root.resolve()
    prereq_path = "com.sodejm.copse/prerequisites.json"
    for relative in ("plugin.json", ".claude-plugin/plugin.json", ".codex-plugin/plugin.json",
                     prereq_path, "skills"):
        path = package_root / relative
        if not path.resolve().is_relative_to(resolved_root):
            raise ValidationError(f"{record.path}/{relative} escapes the plugin root")
    portable = load_json(package_root / "plugin.json", root)
    validate_agent_plugin_manifest(portable, f"{record.path}/plugin.json")
    if portable.get("name") != record.id or portable.get("version") != record.version:
        raise ValidationError(f"{record.path}/plugin.json name and version must match the catalog")
    _require_string(portable.get("description"), f"{record.path}/plugin.json.description")
    codex = load_json(package_root / ".codex-plugin" / "plugin.json", root)
    _validate_codex_manifest(codex, record)
    claude = load_json(package_root / ".claude-plugin" / "plugin.json", root)
    if claude.get("name") != record.id or claude.get("version") != record.version:
        raise ValidationError(
            f"{record.path}/.claude-plugin/plugin.json name and version must match the catalog"
        )
    _require_string(claude.get("description"), f"{record.path}/.claude-plugin/plugin.json.description")
    try:
        validate_prerequisites(load_json(package_root / prereq_path, root),
                               f"{record.path}/{prereq_path}")
    except ValueError as error:
        raise ValidationError(str(error)) from error

    if not (package_root / "skills").is_dir():
        raise ValidationError(f"{record.path}/skills must be a directory")
    skill_paths = sorted((package_root / "skills").glob("*/SKILL.md"))
    if not skill_paths:
        raise ValidationError(f"{record.path} must provide at least one skill")
    skill_names: set[str] = set()
    for skill_path in skill_paths:
        if not skill_path.resolve().is_relative_to(resolved_root) or not skill_path.is_file():
            raise ValidationError(f"{skill_path.relative_to(root)} must be a contained regular file")
        name, _ = _skill_frontmatter(skill_path, root)
        if name in skill_names:
            raise ValidationError(f"duplicate skill name in {record.id}: {name}")
        skill_names.add(name)


def marketplace_documents(root: Path = ROOT) -> dict[Path, dict[str, Any]]:
    """Render host indexes from the single canonical catalog."""

    catalog = load_json(root / "catalog" / "plugins.json", root)
    marketplace = catalog.get("marketplace")
    if not isinstance(marketplace, dict):
        raise ValidationError("catalog/plugins.json.marketplace must be an object")
    if set(marketplace) != MARKETPLACE_KEYS:
        raise ValidationError(
            "catalog/plugins.json.marketplace must declare exactly name and owner"
        )
    name = _require_string(marketplace.get("name"), "catalog/plugins.json.marketplace.name")
    owner = _require_string(marketplace.get("owner"), "catalog/plugins.json.marketplace.owner")

    codex_entries: list[dict[str, Any]] = []
    host_entries: list[dict[str, Any]] = []
    for record in plugin_records(root):
        manifest = load_json(root / record.path / "plugin.json", root)
        source = f"./{record.path}"
        codex_entries.append(
            {
                "name": record.id,
                "source": {"source": "local", "path": source},
                "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                "category": "Developer Tools",
            }
        )
        host_entries.append(
            {
                "name": record.id,
                "description": manifest["description"],
                "version": record.version,
                "source": source,
            }
        )
    return {
        HOST_INDEX_PATHS["Codex"]: {"name": name, "plugins": codex_entries},
        HOST_INDEX_PATHS["GitHub Copilot"]: {
            "$schema": "https://raw.githubusercontent.com/github/copilot-agent-plugins/main/schemas/marketplace.schema.json",
            "name": name,
            "owner": {"name": owner},
            "plugins": host_entries,
        },
        HOST_INDEX_PATHS["Claude"]: {
            "$schema": "https://json.schemastore.org/claude-code-marketplace.json",
            "name": name,
            "owner": {"name": owner},
            "plugins": host_entries,
        },
    }


def _serialized(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def generate_marketplaces(root: Path = ROOT, *, check: bool) -> list[Path]:
    """Write or check all derived host indexes."""

    changed: list[Path] = []
    for relative_path, document in marketplace_documents(root).items():
        path = root / relative_path
        expected = _serialized(document)
        actual = path.read_text(encoding="utf-8") if path.exists() else None
        if actual == expected:
            continue
        changed.append(relative_path)
        if not check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8")
    if check and changed:
        values = ", ".join(path.as_posix() for path in changed)
        raise ValidationError(f"generated host indexes are stale: {values}; run python3 -m cops generate")
    return changed


def validate_repository(root: Path = ROOT, *, check_indexes: bool = True) -> list[PluginRecord]:
    """Validate the catalog and every discovered plugin package."""

    categories = load_json(root / "catalog" / "categories.json", root)
    if categories.get("schema_version") != "1.0":
        raise ValidationError("catalog/categories.json.schema_version must be '1.0'")
    raw_categories = categories.get("categories")
    if not isinstance(raw_categories, list) or not raw_categories:
        raise ValidationError("catalog/categories.json.categories must be a non-empty array")
    category_ids: set[str] = set()
    for index, category in enumerate(raw_categories):
        if not isinstance(category, dict) or set(category) != CATEGORY_KEYS:
            raise ValidationError(
                f"catalog/categories.json.categories[{index}] must declare exactly "
                f"{sorted(CATEGORY_KEYS)}"
            )
        category_id = _require_string(category.get("id"), f"category[{index}].id")
        if category_id in category_ids:
            raise ValidationError(f"duplicate category id: {category_id}")
        category_ids.add(category_id)
        _require_string(category.get("name"), f"category {category_id}.name")
        _require_string(category.get("description"), f"category {category_id}.description")

    catalog = load_json(root / "catalog" / "plugins.json", root)
    if catalog.get("schema_version") != "1.0":
        raise ValidationError("catalog/plugins.json.schema_version must be '1.0'")
    if set(catalog) != {"schema_version", "marketplace", "plugins"}:
        raise ValidationError(
            "catalog/plugins.json must declare exactly schema_version, marketplace, and plugins"
        )
    marketplace = catalog.get("marketplace")
    if not isinstance(marketplace, dict) or set(marketplace) != MARKETPLACE_KEYS:
        raise ValidationError(
            "catalog/plugins.json.marketplace must declare exactly name and owner"
        )
    _require_string(marketplace.get("name"), "catalog/plugins.json.marketplace.name")
    _require_string(marketplace.get("owner"), "catalog/plugins.json.marketplace.owner")
    raw_plugins = catalog.get("plugins")
    if not isinstance(raw_plugins, list):
        raise ValidationError("catalog/plugins.json.plugins must be an array")
    for index, raw_plugin in enumerate(raw_plugins):
        if not isinstance(raw_plugin, dict) or set(raw_plugin) != CATALOG_PLUGIN_KEYS:
            raise ValidationError(
                f"catalog/plugins.json.plugins[{index}] must declare exactly "
                f"{sorted(CATALOG_PLUGIN_KEYS)}"
            )
    records = plugin_records(root)
    if not records:
        raise ValidationError("catalog/plugins.json.plugins must not be empty")
    ids: set[str] = set()
    paths: set[str] = set()
    global_skills: dict[str, str] = {}
    for record in records:
        if not record.id or record.id in ids:
            raise ValidationError(f"duplicate or empty plugin id: {record.id}")
        ids.add(record.id)
        if record.primary_category not in category_ids:
            raise ValidationError(f"plugin {record.id} uses unknown category {record.primary_category}")
        expected_path = f"plugins/{record.primary_category}/{record.id}"
        if record.path != expected_path:
            raise ValidationError(f"plugin {record.id} path must be {expected_path}")
        if record.path in paths:
            raise ValidationError(f"duplicate plugin path: {record.path}")
        paths.add(record.path)
        if not record.tags or any(not tag.strip() for tag in record.tags):
            raise ValidationError(f"plugin {record.id}.tags must contain non-empty strings")
        validate_package(record, root)
        for skill in sorted((root / record.path / "skills").glob("*/SKILL.md")):
            skill_name = skill.parent.name
            if skill_name in global_skills:
                raise ValidationError(
                    f"skill name {skill_name} collides between {global_skills[skill_name]} and {record.id}"
                )
            global_skills[skill_name] = record.id

    discovered = {
        path.parent.relative_to(root).as_posix()
        for path in (root / "plugins").glob("*/*/plugin.json")
    }
    if discovered != paths:
        raise ValidationError(
            "cataloged plugin paths differ from discovered packages: "
            f"catalog={sorted(paths)}, discovered={sorted(discovered)}"
        )
    load_json(root / "catalog" / "schemas" / "package.schema.json", root)
    if check_indexes:
        generate_marketplaces(root, check=True)
    return records
