from __future__ import annotations

import json
from pathlib import Path

import pytest

from cops.operations.contracts import OperationError
from cops.operations.inventory import SUPPORT_STATES, build_features
from cops.operations.metadata import validate_installed_metadata
from cops.operations.service import OperationService
from tests.test_operation_runs import call

ROOT = Path(__file__).resolve().parents[1]


def test_each_skill_and_numbered_step_is_inventoried():
    records = json.loads((ROOT / "catalog/plugins.json").read_text())["plugins"]
    rows = build_features(ROOT, records)
    ids = [row["feature_id"] for row in rows]
    assert len(ids) == len(set(ids))
    for record in records:
        skills = list((ROOT / record["path"] / "skills").glob("*/SKILL.md"))
        assert skills
        for path in skills:
            assert "skill:" + path.relative_to(ROOT).as_posix() in ids
    assert any(row["kind"] == "skill_step" for row in rows)
    assert any(row["kind"] == "dynamic_cli" for row in rows)
    assert all(row["headless_status"] in SUPPORT_STATES for row in rows)
    assert all(row["operation_ids"] for row in rows if row["headless_status"] == "implemented")
    assert all(row["headless_status"] == "unsupported" for row in rows if row["kind"] == "dynamic_cli")


def test_feature_query_is_bounded_and_preserves_unsupported_work():
    service = OperationService()
    result = call(service, "cops.features.list", {"plugin_id": "soc-investigation-workbench", "limit": 2})
    assert result["status"] == "succeeded"
    assert len(result["result"]["features"]) == 2
    assert result["result"]["next_offset"] == 2
    assert result["result"]["summary"]["by_status"]["unsupported"] > 0
    feature_id = result["result"]["features"][0]["feature_id"]
    info = call(service, "cops.features.info", {"feature_id": feature_id})
    assert info["result"]["feature"]["feature_id"] == feature_id
    assert call(service, "cops.features.info", {"feature_id": "/etc/passwd"})["status"] == "failed"
    assert validate_installed_metadata()["package_feature_complete"] is False


def test_inventory_rejects_catalog_escape_before_scanning(tmp_path):
    with pytest.raises(OperationError, match="unsafe_inventory_path"):
        build_features(tmp_path, [{"id": "private", "path": "../../private"}])
