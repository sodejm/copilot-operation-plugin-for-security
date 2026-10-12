"""Regression and abuse cases for offline model/effort advice."""

from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from cops.routing import cli
from cops.routing.model_advisor import ModelCatalogError, advise_models, assess_task, load_catalog, parse_catalog

NOW = datetime(2026, 10, 12, tzinfo=UTC)


def model(identifier="host-security", **overrides):
    return {
        "id": identifier,
        "family": "Daybreak",
        "tier": "flagship",
        "capabilities": ["general", "coding", "security", "advanced-security"],
        "available": True,
        "access": "granted",
        "efforts": ["low", "medium", "high"],
        "preference": 0,
        **overrides,
    }


def catalog(*models, observed_at=NOW.isoformat()):
    return {
        "schema_version": "cops.model-catalog/v1",
        "source": "test host inventory",
        "observed_at": observed_at,
        "models": list(models),
    }


@pytest.mark.parametrize(
    ("query", "kind", "tier", "effort"),
    [
        ("Fix a typo in the threat model guide", "routine", "efficient", "low"),
        ("Implement a report formatter", "coding", "balanced", "medium"),
        ("Implement a distributed indexing migration", "coding", "flagship", "high"),
        ("Review authorization trust boundaries", "security-review", "flagship", "high"),
        ("Authorized binary analysis and exploit development", "adversarial-research", "flagship", "high"),
        ("Plan a penetration test", "adversarial-research", "flagship", "high"),
    ],
)
def test_task_requirements(query, kind, tier, effort):
    result = assess_task(query)
    assert (result["kind"], result["minimum_tier"], result["minimum_effort"]) == (kind, tier, effort)


def test_explicit_scope_overrides_keywords():
    result = assess_task("Document exploit development", task_kind="routine", complexity="simple")
    assert result["minimum_effort"] == "low"
    assert assess_task("Formatter", task_kind="coding", complexity="simple")["minimum_tier"] == "efficient"


@pytest.mark.parametrize("family", ["Daybreak", "Fable", "Mythos", "Astra", "Future family"])
def test_families_use_exact_host_id_and_capabilities(family):
    candidate = model("host/exact-id", family=family)
    advice = advise_models("Review a trust boundary", catalog=catalog(candidate), now=NOW)
    assert advice["recommendation"]["model_id"] == "host/exact-id"
    candidate["capabilities"] = ["coding"]
    assert advise_models("Review a trust boundary", catalog=catalog(candidate), now=NOW)["recommendation"] is None


def test_least_tier_then_operator_preference_then_id_without_price_claims():
    candidates = [
        model("flagship", preference=0),
        model("z", tier="balanced", preference=2),
        model("b", tier="balanced", preference=1),
        model("a", tier="balanced", preference=1),
    ]
    advice = advise_models("Implement a formatter", catalog=catalog(*candidates), now=NOW)
    assert [advice["recommendation"]["model_id"], *[m["model_id"] for m in advice["alternatives"]]] == [
        "a",
        "b",
        "z",
        "flagship",
    ]
    assert advice["recommendation"]["effort"] == "medium"


def test_access_and_availability_are_independent_and_never_inferred_from_blue():
    advice = advise_models(
        "Review security",
        catalog=catalog(
            model("blue"),
            model("red", access="denied"),
            model("mythos", access="unknown"),
            model("fable", available=False),
        ),
        now=NOW,
    )
    assert advice["recommendation"]["model_id"] == "blue"
    assert advice["excluded"] == {"red": ["access_denied"], "mythos": ["access_unknown"], "fable": ["unavailable"]}


def test_capabilities_are_independent_without_implicit_inheritance():
    candidate = model(capabilities=["advanced-security"])
    review = advise_models("Review security", catalog=catalog(candidate), now=NOW)
    assert review["recommendation"] is None
    assert review["excluded"]["host-security"] == ["capability_missing"]
    research = advise_models("Authorized binary analysis", catalog=catalog(candidate), now=NOW)
    assert research["recommendation"]["model_id"] == "host-security"


@pytest.mark.parametrize("efforts", [["low", "medium"], ["xhigh"], ["max"], ["ultra"]])
def test_no_silent_effort_downgrade_or_manual_escalation(efforts):
    advice = advise_models("Review security", catalog=catalog(model(efforts=efforts)), now=NOW)
    assert advice["recommendation"] is None
    assert "automatic_effort_unsupported" in advice["excluded"]["host-security"]


@pytest.mark.parametrize(
    ("age", "status"),
    [
        (timedelta(hours=25), "catalog_stale"),
        (timedelta(minutes=-1), "catalog_future"),
        (timedelta(microseconds=-1), "catalog_future"),
    ],
)
def test_stale_or_future_evidence_never_confirms_current_or_recommends(age, status):
    advice = advise_models(
        "Review security",
        catalog=catalog(model(), observed_at=(NOW - age).isoformat()),
        current_model="host-security",
        current_effort="high",
        now=NOW,
    )
    assert advice["status"] == status
    assert advice["recommendation"] is None
    assert advice["current"]["status"] == "unverified"


@pytest.mark.parametrize("age", [timedelta(0), timedelta(hours=24)])
def test_catalog_freshness_boundaries(age):
    advice = advise_models("Review security", catalog=catalog(model(), observed_at=(NOW - age).isoformat()), now=NOW)
    assert advice["status"] == "suggested"


@pytest.mark.parametrize(
    ("current_model", "effort", "status"),
    [
        (None, None, "unverified"),
        ("missing", "high", "unverified"),
        ("host-security", None, "unverified"),
        ("host-security", "low", "change_recommended"),
        ("host-security", "high", "adequate"),
        ("host-security", "max", "adequate"),
        ("host-security", "ultra", "change_recommended"),
    ],
)
def test_current_model_and_effort_checked_independently(current_model, effort, status):
    advice = advise_models(
        "Review security",
        catalog=catalog(model(efforts=["low", "high", "max"])),
        current_model=current_model,
        current_effort=effort,
        now=NOW,
    )
    assert advice["current"]["status"] == status
    assert advice["recommendation"]["effort"] == "high"


@pytest.mark.parametrize(
    "change",
    [
        {"available": "true"},
        {"access": "inherited"},
        {"efforts": ["maximum"]},
        {"efforts": ["high", "high"]},
        {"capabilities": []},
        {"capabilities": ["cyber"]},
        {"preference": True},
        {"tier": "premium"},
        {"id": "$(echo secret)"},
        {"endpoint": "unexpected"},
    ],
)
def test_reject_invalid_or_ambiguous_records(change):
    with pytest.raises(ModelCatalogError):
        parse_catalog(catalog(model(**change)))


def test_duplicate_ids_and_missing_evidence_rejected():
    with pytest.raises(ModelCatalogError, match="duplicate model id"):
        parse_catalog(catalog(model(), model()))
    value = catalog(model())
    del value["models"][0]["access"]
    with pytest.raises(ModelCatalogError):
        parse_catalog(value)


@pytest.mark.parametrize("payload", [b'{"source":"a","source":"b"}', b"\xff", b"{", b"x" * (1024 * 1024 + 1)])
def test_bounded_strict_json_errors_are_safe(tmp_path, payload):
    path = tmp_path / "private-name.json"
    path.write_bytes(payload)
    with pytest.raises(ModelCatalogError) as error:
        load_catalog(path)
    assert str(path) not in str(error.value)
    assert "private-name" not in str(error.value)


def test_input_not_mutated():
    value = catalog(model())
    before = deepcopy(value)
    advise_models("Security review", catalog=value, now=NOW)
    assert value == before


def test_invalid_catalog_does_not_reach_authorization(tmp_path, monkeypatch, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{}")

    def unauthorized_call(**kwargs):
        pytest.fail("invalid catalog reached authorization")

    monkeypatch.setattr(cli, "ensure_authorization", unauthorized_call)
    assert cli.main(["route", "exploit a binary", "--critical", "--authorize", "--model-catalog", str(path)]) == 2
    assert "Model advice error:" in capsys.readouterr().err


@pytest.mark.parametrize("module", ["cops", "cops.routing"])
def test_both_cli_entry_points_preserve_default_and_offer_same_advice(module, tmp_path):
    command = [sys.executable, "-m", module, "route", "Review security", "--json"]
    baseline = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
    original = json.loads(baseline.stdout)
    assert "model_advice" not in original
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog(model(), observed_at=datetime.now(UTC).isoformat())))
    routed = subprocess.run(
        command + ["--model-catalog", str(path), "--current-model", "host-security", "--current-effort", "low"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    value = json.loads(routed.stdout)
    advice = value.pop("model_advice")
    assert value == original
    assert advice["recommendation"]["effort"] == "high"
    assert advice["current"]["status"] == "change_recommended"
    assert advice["advisory_only"] is True
