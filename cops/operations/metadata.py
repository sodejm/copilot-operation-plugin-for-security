"""Deterministic pilot traceability, without inferring whole-package completion."""

from __future__ import annotations

import json
from pathlib import Path

from cops._schema_validation import validate

from .catalog import declarations, validate_catalog
from .contracts import RESULT_SCHEMA, encode
from .inventory import build_features, summarize
from .runs import RUN_SCHEMA

ROOT = Path(__file__).resolve().parents[2]


def generated_files(root: Path = ROOT):
    catalog = declarations()
    validate_catalog(catalog)
    result = {
        Path("catalog/operations.json"): {
            "schema_version": "cops.operation-catalog/v1",
            "operations": catalog,
        },
        Path("catalog/schemas/operation-result.schema.json"): RESULT_SCHEMA,
        Path("catalog/schemas/operation-run.schema.json"): RUN_SCHEMA,
    }
    records = json.loads((root / "catalog/plugins.json").read_text())["plugins"]
    features = build_features(root, records)
    result[Path("catalog/features.json")] = {
        "schema_version": "cops.feature-inventory/v1",
        "features": features,
        "plugin_ids": [record["id"] for record in records],
        "summary": summarize(features),
        "limitations": [
            "Source-indexed inventory is not a complete product-requirements denominator.",
            "Unmapped CLI and prose steps remain unsupported by the typed headless surface.",
        ],
    }
    owners = {record["id"] for record in records} | {"cops-core"}
    if any(item["owner"] not in owners for item in catalog):
        raise ValueError("unknown_operation_owner")
    for record in records:
        operations = [item for item in catalog if item["owner"] == record["id"]]
        skills = sorted(str(path.relative_to(root)) for path in (root / record["path"] / "skills").glob("*/SKILL.md"))
        result[Path(record["path"]) / "org.cops/operations.json"] = {
            "schema_version": "cops.package-operations/v1",
            "plugin_id": record["id"],
            "coverage": "pilot_mapped" if operations else "not_mapped",
            "package_feature_complete": False,
            "runtime": "separate COPS headless bundle; not automatically included by plugin installation",
            "operations": operations,
            "skill_references": skills,
            "features": [row for row in features if row["plugin_id"] == record["id"]],
            "feature_inventory": summarize([row for row in features if row["plugin_id"] == record["id"]]),
            "limitations": [
                "Source inventory records unmapped skills and CLI steps explicitly; they are not implemented coverage.",
                "No host-installation, live-provider, or synthetic-laboratory readiness promotion.",
            ],
        }
    return result


def synchronize(root: Path = ROOT, *, check: bool = False):
    stale = []
    for relative, document in generated_files(root).items():
        content = json.dumps(document, indent=2, sort_keys=True) + "\n"
        path = root / relative
        if not path.is_file() or path.read_text() != content:
            stale.append(relative.as_posix())
            if not check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
    return stale


def validate_installed_metadata(root: Path = ROOT):
    """Validate persisted declarations as well as code-owned generation inputs."""
    if synchronize(root, check=True):
        raise ValueError("stale_operation_metadata")
    document = json.loads((root / "catalog/operations.json").read_text())
    validate_catalog(document["operations"])
    schema = json.loads((root / "catalog/schemas/operation.schema.json").read_text())
    for item in document["operations"]:
        validate(item, schema)
        encode(item)
    features = json.loads((root / "catalog/features.json").read_text())["features"]
    return {
        "status": "valid",
        "operations": len(document["operations"]),
        "features": summarize(features),
        "package_feature_complete": False,
    }
