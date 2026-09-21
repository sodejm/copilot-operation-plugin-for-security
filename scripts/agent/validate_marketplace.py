#!/usr/bin/env python3
"""Validate marketplace organization, host indexes, and evidence-backed findings."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
HOST_INDEXES = {
    "GitHub Copilot": ROOT / ".github" / "plugin" / "marketplace.json",
    "OpenAI": ROOT / ".agents" / "plugins" / "marketplace.json",
    "Claude": ROOT / ".claude-plugin" / "marketplace.json",
}
CLASSIFICATIONS = {"observation", "assessment", "unresolved"}
VERIFICATIONS = {"verified", "partially-verified", "unverified", "contradicted"}
CONFIDENCE = {"high", "limited", "unknown"}
COVERAGE = {"complete", "partial", "unknown"}
EVIDENCE_KINDS = {
    "file", "command", "test", "source", "hosted-check", "git-commit",
    "git-remote", "pull-request", "merge", "release", "deployment",
}
RESULTS = {"observed", "passed", "failed", "unavailable"}
FRESHNESS = {"current", "stale", "unknown"}
DELIVERY_EVIDENCE = {
    "validated-locally": ({"test", "command"}, {"passed"}),
    "committed": ({"git-commit"}, {"observed"}),
    "pushed": ({"git-remote"}, {"observed"}),
    "open-for-review": ({"pull-request"}, {"observed"}),
    "merged": ({"merge"}, {"observed"}),
    "released": ({"release"}, {"observed"}),
    "deployed": ({"deployment"}, {"observed"}),
}


class ValidationError(ValueError):
    """A deterministic marketplace or finding contract failure."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValidationError(f"missing JSON file: {path.relative_to(ROOT)}") from error
    except json.JSONDecodeError as error:
        raise ValidationError(f"invalid JSON in {path.relative_to(ROOT)}: {error}") from error
    if not isinstance(value, dict):
        raise ValidationError(f"JSON document must be an object: {path.relative_to(ROOT)}")
    return value


def require_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{location} must be a non-empty string")
    return value


def require_list(value: Any, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"{location} must be an array")
    return value


def unique_objects(document: dict[str, Any], key: str, location: str) -> list[dict[str, Any]]:
    values = require_list(document.get(key), location)
    objects: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise ValidationError(f"{location}[{index}] must be an object")
        identifier = require_string(value.get("id"), f"{location}[{index}].id")
        if identifier in seen:
            raise ValidationError(f"duplicate id in {location}: {identifier}")
        seen.add(identifier)
        objects.append(value)
    return objects


def index_entries(path: Path) -> dict[str, str]:
    document = load_json(path)
    plugins = require_list(document.get("plugins"), f"{path.relative_to(ROOT)}.plugins")
    result: dict[str, str] = {}
    for index, plugin in enumerate(plugins):
        location = f"{path.relative_to(ROOT)}.plugins[{index}]"
        if not isinstance(plugin, dict):
            raise ValidationError(f"{location} must be an object")
        name = require_string(plugin.get("name"), f"{location}.name")
        if name in result:
            raise ValidationError(f"duplicate plugin in {path.relative_to(ROOT)}: {name}")
        source = plugin.get("source")
        if isinstance(source, dict):
            if source.get("source") != "local":
                raise ValidationError(f"{location}.source.source must be local")
            source_path = require_string(source.get("path"), f"{location}.source.path")
        else:
            source_path = require_string(source, f"{location}.source")
        result[name] = source_path.removeprefix("./")
    return result


def validate_marketplace(root: Path = ROOT) -> None:
    categories_doc = load_json(root / "catalog" / "categories.json")
    plugins_doc = load_json(root / "catalog" / "plugins.json")
    categories = unique_objects(categories_doc, "categories", "catalog/categories.json.categories")
    category_ids = {item["id"] for item in categories}
    for category in categories:
        require_string(category.get("name"), f"category {category['id']}.name")
        require_string(category.get("description"), f"category {category['id']}.description")

    plugins = unique_objects(plugins_doc, "plugins", "catalog/plugins.json.plugins")
    expected: dict[str, str] = {}
    versions: dict[str, str] = {}
    for plugin in plugins:
        plugin_id = plugin["id"]
        category = require_string(plugin.get("primary_category"), f"plugin {plugin_id}.primary_category")
        if category not in category_ids:
            raise ValidationError(f"plugin {plugin_id} uses unknown category: {category}")
        expected_path = f"plugins/{category}/{plugin_id}"
        actual_path = require_string(plugin.get("path"), f"plugin {plugin_id}.path")
        if actual_path != expected_path:
            raise ValidationError(f"plugin {plugin_id} path must be {expected_path}, found {actual_path}")
        package = root / actual_path
        if not package.is_dir():
            raise ValidationError(f"plugin directory does not exist: {actual_path}")
        version = require_string(plugin.get("version"), f"plugin {plugin_id}.version")
        tags = require_list(plugin.get("tags"), f"plugin {plugin_id}.tags")
        if not tags or any(not isinstance(tag, str) or not tag.strip() for tag in tags):
            raise ValidationError(f"plugin {plugin_id}.tags must contain non-empty strings")

        portable = load_json(package / "plugin.json")
        require_string(portable.get("$schema"), f"{actual_path}/plugin.json.$schema")
        if portable.get("name") != plugin_id or portable.get("version") != version:
            raise ValidationError(f"{actual_path}/plugin.json name and version must match the catalog")
        require_string(portable.get("description"), f"{actual_path}/plugin.json.description")

        claude = load_json(package / ".claude-plugin" / "plugin.json")
        if claude.get("name") != plugin_id or claude.get("version") != version:
            raise ValidationError(f"{actual_path}/.claude-plugin/plugin.json name and version must match the catalog")

        expected[plugin_id] = actual_path
        versions[plugin_id] = version

    discovered = {
        str(path.parent.relative_to(root))
        for path in (root / "plugins").glob("*/*/plugin.json")
    }
    if discovered != set(expected.values()):
        raise ValidationError(
            "cataloged plugin paths differ from discovered package paths: "
            f"catalog={sorted(expected.values())}, discovered={sorted(discovered)}"
        )

    for host, path in HOST_INDEXES.items():
        entries = index_entries(path)
        if entries != expected:
            raise ValidationError(
                f"{host} marketplace differs from catalog: expected {expected}, found {entries}"
            )
        document = load_json(path)
        for entry in document["plugins"]:
            if "version" in entry and entry["version"] != versions[entry["name"]]:
                raise ValidationError(f"{host} version differs from catalog for {entry['name']}")


def _enum(value: Any, allowed: set[str], location: str) -> str:
    if value not in allowed:
        raise ValidationError(f"{location} must be one of {sorted(allowed)}, found {value!r}")
    return value


def validate_finding_document(document: dict[str, Any], source: str = "finding") -> None:
    if document.get("schema_version") != "1.0":
        raise ValidationError(f"{source}.schema_version must be '1.0'")
    findings = unique_objects(document, "findings", f"{source}.findings")
    if not findings:
        raise ValidationError(f"{source}.findings must not be empty")
    for finding in findings:
        finding_id = finding["id"]
        location = f"{source}.findings[{finding_id}]"
        for field in ("title", "claim"):
            require_string(finding.get(field), f"{location}.{field}")
        _enum(finding.get("classification"), CLASSIFICATIONS, f"{location}.classification")
        verification = _enum(finding.get("verification"), VERIFICATIONS, f"{location}.verification")
        confidence = _enum(finding.get("confidence"), CONFIDENCE, f"{location}.confidence")
        coverage = _enum(finding.get("coverage"), COVERAGE, f"{location}.coverage")

        scope = finding.get("scope")
        if not isinstance(scope, dict):
            raise ValidationError(f"{location}.scope must be an object")
        require_list(scope.get("examined"), f"{location}.scope.examined")
        require_list(scope.get("excluded"), f"{location}.scope.excluded")
        limitations = require_list(finding.get("limitations"), f"{location}.limitations")
        conflicts = require_list(finding.get("conflicts"), f"{location}.conflicts")
        if any(not isinstance(value, str) for value in limitations + conflicts):
            raise ValidationError(f"{location} limitations and conflicts must contain strings")

        evidence_items = require_list(finding.get("evidence"), f"{location}.evidence")
        if not evidence_items:
            raise ValidationError(f"{location}.evidence must not be empty")
        evidence: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(evidence_items):
            item_location = f"{location}.evidence[{index}]"
            if not isinstance(item, dict):
                raise ValidationError(f"{item_location} must be an object")
            evidence_id = require_string(item.get("id"), f"{item_location}.id")
            if evidence_id in evidence:
                raise ValidationError(f"duplicate evidence id in {location}: {evidence_id}")
            require_string(item.get("reference"), f"{item_location}.reference")
            _enum(item.get("kind"), EVIDENCE_KINDS, f"{item_location}.kind")
            _enum(item.get("result"), RESULTS, f"{item_location}.result")
            _enum(item.get("freshness"), FRESHNESS, f"{item_location}.freshness")
            evidence[evidence_id] = item

        uncertainty = finding.get("uncertainty")
        if not isinstance(uncertainty, str):
            raise ValidationError(f"{location}.uncertainty must be a string")
        needs_uncertainty = (
            confidence != "high"
            or verification != "verified"
            or coverage != "complete"
            or bool(conflicts)
            or any(item["freshness"] != "current" for item in evidence.values())
            or any(item["result"] not in {"observed", "passed"} for item in evidence.values())
        )
        if needs_uncertainty and not uncertainty.strip():
            raise ValidationError(f"{location} requires a plain-language uncertainty statement")
        if confidence == "high" or verification == "verified":
            if not (confidence == "high" and verification == "verified"):
                raise ValidationError(f"{location} high confidence and verified status must be used together")
            if coverage != "complete" or conflicts:
                raise ValidationError(f"{location} verified high-confidence findings require complete coverage and no conflicts")
            if any(item["freshness"] != "current" for item in evidence.values()):
                raise ValidationError(f"{location} verified high-confidence findings require current evidence")
            if any(item["result"] not in {"observed", "passed"} for item in evidence.values()):
                raise ValidationError(f"{location} verified high-confidence findings require successful evidence")

        delivery_claims = require_list(finding.get("delivery_claims"), f"{location}.delivery_claims")
        for index, claim in enumerate(delivery_claims):
            claim_location = f"{location}.delivery_claims[{index}]"
            if not isinstance(claim, dict):
                raise ValidationError(f"{claim_location} must be an object")
            state = claim.get("state")
            evidence_ids = require_list(claim.get("evidence_ids"), f"{claim_location}.evidence_ids")
            if not evidence_ids or any(item not in evidence for item in evidence_ids):
                raise ValidationError(f"{claim_location} references missing delivery evidence")
            selected = [evidence[item] for item in evidence_ids]
            if state == "ready-to-merge":
                requirements = [({"pull-request"}, {"observed"}), ({"hosted-check"}, {"passed"})]
            elif state in DELIVERY_EVIDENCE:
                requirements = [DELIVERY_EVIDENCE[state]]
            else:
                raise ValidationError(f"{claim_location}.state is not a supported delivery state")
            if any(item["freshness"] != "current" for item in selected):
                raise ValidationError(f"{claim_location} requires current delivery evidence")
            for kinds, results in requirements:
                if not any(item["kind"] in kinds and item["result"] in results for item in selected):
                    raise ValidationError(f"{claim_location} is missing evidence for delivery state {state}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finding", action="append", type=Path, default=[], help="additional finding JSON to validate")
    args = parser.parse_args(argv)
    try:
        validate_marketplace()
        finding_paths = [
            ROOT / "catalog" / "examples" / "verified-finding.json",
            ROOT / "catalog" / "examples" / "limited-finding.json",
            *args.finding,
        ]
        for path in finding_paths:
            validate_finding_document(load_json(path), str(path))
    except ValidationError as error:
        print(f"marketplace validation failed: {error}", file=sys.stderr)
        return 1
    print(f"Marketplace catalog and {len(finding_paths)} finding document(s) passed validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
