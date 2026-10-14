"""Executable service attack notice acceptance scenarios."""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.service_notices import assess_asset, load_registry

REGISTRY_PATH = Path(__file__).resolve().parents[2] / "catalog/service_attack_notices.json"
DELL_NOTICE_ID = "COPS-SAN-2026-002"
REVIEW_DATE = date(2026, 10, 14)

scenarios("../../specs/features/service_attack_notices.feature")


def _dell_asset(version: str) -> dict[str, object]:
    return {
        "asset_id": "dell-rpv-example",
        "operating_system": "Dell RecoverPoint for VMs appliance",
        "product": "Dell RecoverPoint for VMs",
        "version": version,
        "services": [
            {"name": "Tomcat Manager", "transport": "tcp", "reachable": True, "configured": True}
        ],
        "evidence": ["tomcat_manager_hard_coded_credential_risk_context"],
    }


def _dell_result(report: dict[str, object]) -> dict[str, object]:
    return next(item for item in report["results"] if item["notice_id"] == DELL_NOTICE_ID)  # type: ignore[index]


@pytest.fixture
def notice_context() -> dict[str, object]:
    return {"registry": load_registry(REGISTRY_PATH), "asset": None, "report": None}


@given("a Dell RecoverPoint for VMs 6.0.3 asset with reachable Tomcat Manager")
def given_dell_603(notice_context: dict[str, object]) -> None:
    notice_context["asset"] = _dell_asset("6.0.3")


@given("a Dell RecoverPoint for VMs 6.0.3.1 asset with reachable Tomcat Manager")
def given_dell_6031(notice_context: dict[str, object]) -> None:
    notice_context["asset"] = _dell_asset("6.0.3.1")


@given("an asset with only a TCP service observation")
def given_port_only(notice_context: dict[str, object]) -> None:
    notice_context["asset"] = {
        "asset_id": "port-only-example",
        "services": [{"name": "Tomcat Manager", "transport": "tcp", "reachable": True}],
    }


@given("fixed or unrelated assets or a notice past its review due date")
def given_non_candidate_contexts(notice_context: dict[str, object]) -> None:
    unrelated = copy.deepcopy(_dell_asset("6.0.3"))
    unrelated["product"] = "Apache Tomcat"
    notice_context["cases"] = [
        (_dell_asset("6.0.3.1 HF1"), REVIEW_DATE, "fixed"),
        (unrelated, REVIEW_DATE, "not_applicable"),
        (_dell_asset("6.0.3"), date(2026, 11, 15), "unknown"),
    ]


@when("its service context is assessed offline")
def when_assessed(notice_context: dict[str, object]) -> None:
    notice_context["report"] = assess_asset(
        notice_context["registry"], notice_context["asset"], as_of=REVIEW_DATE  # type: ignore[arg-type]
    )


@when("their service contexts are assessed offline")
def when_all_assessed(notice_context: dict[str, object]) -> None:
    notice_context["reports"] = [
        (_dell_result(assess_asset(notice_context["registry"], asset, as_of=as_of)), expected)
        for asset, as_of, expected in notice_context["cases"]  # type: ignore[union-attr]
    ]


@when("its service context is assessed before the registry review date")
def when_assessed_historically(notice_context: dict[str, object]) -> None:
    notice_context["report"] = assess_asset(
        notice_context["registry"], notice_context["asset"], as_of=date(2026, 10, 13)  # type: ignore[arg-type]
    )


@then("the Dell notice is a candidate for targeted investigation")
def then_candidate(notice_context: dict[str, object]) -> None:
    result = _dell_result(notice_context["report"])  # type: ignore[arg-type]
    assert result["status"] == "candidate"
    assert "targeted investigation" in result["safe_next_action"].lower()  # type: ignore[union-attr]


@then("the result does not claim exploitability")
def then_no_exploitability(notice_context: dict[str, object]) -> None:
    report = notice_context["report"]
    result = _dell_result(report)  # type: ignore[arg-type]
    assert report["input_verification"] == "unverified"  # type: ignore[index]
    assert result["mapping_application"] == "not_assessed"
    assert "exploitable" not in json.dumps(result).lower()
    assert "vulnerable" not in json.dumps(result).lower()


@then("no notice is a candidate")
def then_none_candidate(notice_context: dict[str, object]) -> None:
    assert all(item["status"] != "candidate" for item in notice_context["report"]["results"])  # type: ignore[index]


@then("missing product, version, and configuration evidence is reported")
def then_missing_evidence(notice_context: dict[str, object]) -> None:
    assert {"product", "version", "configuration"}.issubset(
        notice_context["report"]["missing_evidence"]  # type: ignore[index]
    )


@then("an unlisted 6.0.2 version remains unknown pending product-specific source review")
def then_unlisted_version_unknown(notice_context: dict[str, object]) -> None:
    report = assess_asset(notice_context["registry"], _dell_asset("6.0.2"), as_of=REVIEW_DATE)  # type: ignore[arg-type]
    result = _dell_result(report)
    assert result["status"] == "unknown"
    assert "source_scoped_version_evidence" in result["missing_evidence"]  # type: ignore[operator]


@then("each result states why no current candidate is established")
def then_non_candidate_reasons(notice_context: dict[str, object]) -> None:
    for result, expected in notice_context["reports"]:  # type: ignore[union-attr]
        assert result["status"] == expected
        assert result["reasons"]
        assert result["safe_next_action"]


@then("the Dell notice is unknown pending a historical source snapshot")
def then_historical_unknown(notice_context: dict[str, object]) -> None:
    result = _dell_result(notice_context["report"])  # type: ignore[arg-type]
    assert result["status"] == "unknown"
    assert "historical_source_snapshot" in result["missing_evidence"]  # type: ignore[operator]
