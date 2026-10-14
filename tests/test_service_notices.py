"""Acceptance tests for the offline service attack notice registry."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from cops.cli import main as cli_main
from cops.service_notices import (
    ServiceNoticeError,
    assess_asset,
    load_json_file,
    load_registry,
    validate_registry,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "catalog/service_attack_notices.json"


def _dell_asset(version: str = "6.0.3") -> dict[str, object]:
    return {
        "asset_id": "asset-dell-rpv",
        "operating_system": "Dell RecoverPoint for VMs appliance",
        "product": "Dell RecoverPoint for VMs",
        "version": version,
        "services": [
            {
                "name": "Tomcat Manager",
                "transport": "tcp",
                "reachable": True,
                "configured": True,
            }
        ],
        "evidence": ["tomcat_manager_hard_coded_credential_risk_context"],
    }


def _result(report: dict[str, object], notice_id: str) -> dict[str, object]:
    return next(item for item in report["results"] if item["notice_id"] == notice_id)  # type: ignore[index]


def test_registry_validates_and_dell_context_is_only_a_candidate() -> None:
    registry = load_registry(REGISTRY_PATH)
    validate_registry(registry)

    report = assess_asset(registry, _dell_asset(), as_of=date(2026, 10, 14))
    result = _result(report, "COPS-SAN-2026-002")
    assert result["status"] == "candidate"
    assert report["input_verification"] == "unverified"
    assert result["input_verification"] == "unverified"
    assert result["mapping_application"] == "not_assessed"
    assert result["sources"]
    assert result["review_due"] == "2026-11-14"
    assert result["conditional_attack_mappings"][0]["technique_id"] == "T1210"
    assert "targeted investigation" in result["safe_next_action"].lower()
    assert "vulnerable" not in json.dumps(result).lower()
    assert "exploitable" not in json.dumps(result).lower()


def test_all_platform_mappings_are_conditional_and_source_backed() -> None:
    registry = load_registry(REGISTRY_PATH)
    assert len(registry["notices"]) == 3
    for notice in registry["notices"]:
        assert notice["sources"]
        assert notice["attack_mappings"]
        for mapping in notice["attack_mappings"]:
            assert mapping["required_evidence"]
            assert mapping["rationale"]

    apple = {
        "asset_id": "asset-mac-screen-sharing",
        "operating_system": "macOS Tahoe",
        "product": "macOS Tahoe",
        "version": "26.6",
        "services": [{"name": "Screen Sharing", "transport": "tcp", "reachable": True, "configured": True}],
        "evidence": ["screen_sharing_enabled"],
    }
    report = assess_asset(registry, apple, as_of=date(2026, 10, 14))
    result = _result(report, "COPS-SAN-2026-003")
    assert result["status"] == "candidate"
    assert result["mapping_application"] == "not_assessed"
    assert result["conditional_attack_mappings"][0]["required_evidence"] == [
        "screen_sharing_lateral_exploitation_observed"
    ]
    assert registry["notices"][2]["observation_date"] is None
    assert registry["notices"][2]["observation_context"]


def test_fixed_and_wrong_product_are_not_candidates() -> None:
    registry = load_registry(REGISTRY_PATH)
    fixed = assess_asset(registry, _dell_asset("6.1"), as_of=date(2026, 10, 14))
    assert _result(fixed, "COPS-SAN-2026-002")["status"] == "fixed"

    unrelated = copy.deepcopy(_dell_asset())
    unrelated["product"] = "Apache Tomcat"
    wrong_product = assess_asset(registry, unrelated, as_of=date(2026, 10, 14))
    assert _result(wrong_product, "COPS-SAN-2026-002")["status"] == "not_applicable"


def test_ambiguous_dell_version_remains_unknown() -> None:
    registry = load_registry(REGISTRY_PATH)
    report = assess_asset(registry, _dell_asset("6.0.3.1"), as_of=date(2026, 10, 14))
    result = _result(report, "COPS-SAN-2026-002")
    assert result["status"] == "unknown"
    assert "source_scoped_version_evidence" in result["missing_evidence"]


def test_port_only_and_missing_version_are_unknown() -> None:
    registry = load_registry(REGISTRY_PATH)
    port_only = {
        "asset_id": "asset-port-only",
        "services": [{"name": "Tomcat Manager", "transport": "tcp", "reachable": True}],
    }
    report = assess_asset(registry, port_only, as_of=date(2026, 10, 14))
    assert all(item["status"] != "candidate" for item in report["results"])
    assert {"product", "version", "configuration"}.issubset(report["missing_evidence"])

    missing_version = _dell_asset()
    del missing_version["version"]
    result = _result(
        assess_asset(registry, missing_version, as_of=date(2026, 10, 14)),
        "COPS-SAN-2026-002",
    )
    assert result["status"] == "unknown"
    assert "version" in result["missing_evidence"]


def test_stale_withdrawn_and_superseded_notices_cannot_be_candidates() -> None:
    registry = load_registry(REGISTRY_PATH)
    stale = assess_asset(registry, _dell_asset(), as_of=date(2026, 11, 15))
    assert _result(stale, "COPS-SAN-2026-002")["status"] == "unknown"

    for state in ("withdrawn", "superseded"):
        changed = copy.deepcopy(registry)
        notice = next(item for item in changed["notices"] if item["id"] == "COPS-SAN-2026-002")
        notice["status"] = state
        notice["lifecycle"]["state"] = state
        if state == "withdrawn":
            notice["lifecycle"]["withdrawn_reason"] = "Synthetic lifecycle test."
        else:
            successor = copy.deepcopy(notice)
            successor["id"] = "COPS-SAN-2026-099"
            successor["status"] = "active"
            successor["lifecycle"]["state"] = "active"
            changed["notices"].append(successor)
            notice["lifecycle"]["superseded_by"] = successor["id"]
        validate_registry(changed)
        result = _result(
            assess_asset(changed, _dell_asset(), as_of=date(2026, 10, 14)),
            "COPS-SAN-2026-002",
        )
        assert result["status"] == "not_applicable"


def test_registry_validation_rejects_duplicates_bad_sources_and_version_overlap() -> None:
    registry = load_registry(REGISTRY_PATH)

    duplicate = copy.deepcopy(registry)
    duplicate["notices"].append(copy.deepcopy(duplicate["notices"][0]))
    with pytest.raises(ServiceNoticeError, match="duplicate notice id"):
        validate_registry(duplicate)

    unsupported_source = copy.deepcopy(registry)
    unsupported_source["notices"][0]["sources"][0]["url"] = "https://example.com/advisory"
    with pytest.raises(ServiceNoticeError, match="unsupported source URL"):
        validate_registry(unsupported_source)

    overlap = copy.deepcopy(registry)
    product = overlap["notices"][1]["scope"]["products"][0]
    product["fixed_versions"].append(product["affected_versions"][0])
    with pytest.raises(ServiceNoticeError, match="version overlap"):
        validate_registry(overlap)

    future_review = copy.deepcopy(registry)
    future_review["notices"][0]["review_date"] = "2099-01-01"
    future_review["notices"][0]["review_due"] = "2099-01-31"
    with pytest.raises(ServiceNoticeError, match="date ordering"):
        validate_registry(future_review)

    late_review_due = copy.deepcopy(registry)
    late_review_due["notices"][0]["review_due"] = "2026-11-30"
    with pytest.raises(ServiceNoticeError, match="date ordering"):
        validate_registry(late_review_due)

    mismatched_publication = copy.deepcopy(registry)
    mismatched_publication["notices"][1]["publication_date"] = "2026-08-19"
    with pytest.raises(ServiceNoticeError, match="source publication dates"):
        validate_registry(mismatched_publication)

    source_after_review = copy.deepcopy(registry)
    source_after_review["notices"][0]["sources"][0]["published_on"] = "2026-11-01"
    with pytest.raises(ServiceNoticeError, match="source publication dates"):
        validate_registry(source_after_review)

    dangling_successor = copy.deepcopy(registry)
    dangling_successor["notices"][0]["status"] = "superseded"
    dangling_successor["notices"][0]["lifecycle"]["state"] = "superseded"
    dangling_successor["notices"][0]["lifecycle"]["superseded_by"] = "COPS-SAN-2026-099"
    with pytest.raises(ServiceNoticeError, match="unknown successor"):
        validate_registry(dangling_successor)


def test_successor_chain_must_be_compatible_acyclic_and_active() -> None:
    registry = load_registry(REGISTRY_PATH)
    dell = registry["notices"][1]
    for variant, expected in (
        ("different_product", "incompatible successor"),
        ("withdrawn", "withdrawn successor"),
        ("cycle", "successor cycle"),
    ):
        changed = copy.deepcopy(registry)
        original = changed["notices"][1]
        successor = copy.deepcopy(dell)
        successor["id"] = "COPS-SAN-2026-099"
        changed["notices"].append(successor)
        original["status"] = "superseded"
        original["lifecycle"]["state"] = "superseded"
        original["lifecycle"]["superseded_by"] = successor["id"]
        if variant == "different_product":
            successor["scope"]["products"][0]["name"] = "Unrelated appliance"
        elif variant == "withdrawn":
            successor["status"] = "withdrawn"
            successor["lifecycle"]["state"] = "withdrawn"
            successor["lifecycle"]["withdrawn_reason"] = "Synthetic withdrawal."
        else:
            successor["status"] = "superseded"
            successor["lifecycle"]["state"] = "superseded"
            successor["lifecycle"]["superseded_by"] = original["id"]
        with pytest.raises(ServiceNoticeError, match=expected):
            validate_registry(changed)


def test_duplicate_asset_service_cannot_create_conflicting_context() -> None:
    registry = load_registry(REGISTRY_PATH)
    asset = _dell_asset()
    asset["services"].append({"name": "tomcat manager", "transport": "tcp", "reachable": False})  # type: ignore[union-attr]
    with pytest.raises(ServiceNoticeError, match="duplicates an asset service"):
        assess_asset(registry, asset, as_of=date(2026, 10, 14))


def test_bounded_loader_rejects_parse_errors_and_oversized_input(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"asset_id":', encoding="utf-8")
    with pytest.raises(ServiceNoticeError, match="invalid JSON"):
        load_json_file(malformed, label="asset input")

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (256 * 1024 + 1))
    with pytest.raises(ServiceNoticeError, match="size limit"):
        load_json_file(oversized, label="asset input")

    nested = tmp_path / "nested.json"
    nested.write_text("[" * 1100 + "0" + "]" * 1100, encoding="utf-8")
    with pytest.raises(ServiceNoticeError, match="nesting limit"):
        load_json_file(nested, label="asset input")

    enormous_integer = tmp_path / "enormous-integer.json"
    enormous_integer.write_text('{"value": ' + "9" * 5000 + "}", encoding="utf-8")
    with pytest.raises(ServiceNoticeError, match="invalid JSON number"):
        load_json_file(enormous_integer, label="asset input")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are unavailable")
def test_bounded_loader_rejects_named_pipe_without_blocking(tmp_path: Path) -> None:
    named_pipe = tmp_path / "asset.pipe"
    os.mkfifo(named_pipe)
    script = (
        "from pathlib import Path\n"
        "from cops.service_notices import ServiceNoticeError, load_json_file\n"
        "try:\n"
        "    load_json_file(Path(__import__('sys').argv[1]), label='asset input')\n"
        "except ServiceNoticeError as error:\n"
        "    assert 'regular file' in str(error)\n"
        "else:\n"
        "    raise AssertionError('named pipe accepted')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(named_pipe)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_cli_validate_list_assess_and_parse_error_are_structured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli_main(["service-notices", "validate", "--json"], root=ROOT) == 0
    validated = json.loads(capsys.readouterr().out)
    assert validated["status"] == "valid"
    assert validated["notice_count"] == 3

    assert cli_main(["service-notices", "list", "--json"], root=ROOT) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["status"] == "ok"
    assert len(listed["notices"]) == 3

    asset_path = tmp_path / "asset.json"
    asset_path.write_text(json.dumps(_dell_asset()), encoding="utf-8")
    assert (
        cli_main(
            ["service-notices", "assess", "--input", str(asset_path), "--json"],
            root=ROOT,
        )
        == 0
    )
    assessed = json.loads(capsys.readouterr().out)
    assert assessed["assessed_on"] == date.today().isoformat()
    assert _result(assessed, "COPS-SAN-2026-002")["status"] in {"candidate", "unknown"}

    asset_path.write_text("{", encoding="utf-8")
    assert cli_main(["service-notices", "assess", "--input", str(asset_path), "--json"], root=ROOT) == 2
    failed = json.loads(capsys.readouterr().out)
    assert failed["status"] == "error"
    assert failed["reasons"]
    assert failed["safe_next_action"]
