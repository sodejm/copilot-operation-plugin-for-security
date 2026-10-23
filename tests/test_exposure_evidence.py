from __future__ import annotations

import copy

import pytest

from cops.workflows.exposure_evidence import assess_exposure


def evidence(anonymous: int = 401) -> dict:
    endpoint = {"scheme": "https", "host": "preview.example.test", "port": 443, "route": "/admin"}
    source = {"observed_at": "2026-10-15T12:30:00Z", "evidence_ref": "fixture:exposure"}
    return {
        "scope": {"endpoints": [endpoint], "window": {"start": "2026-10-15T12:00:00Z", "end": "2026-10-15T13:00:00Z"}},
        "dns_service_inventory": {
            "complete": True,
            "records": [{**source, "host": endpoint["host"], "addresses": ["192.0.2.20"]}],
        },
        "port_route_evidence": {
            "complete": True,
            "checks": [{**source, **endpoint, "address": "192.0.2.20", "connected": True}],
        },
        "auth_evidence": {
            "complete": True,
            "checks": [
                {**source, **endpoint, "address": "192.0.2.20", "authorized_status": 200, "anonymous_status": anonymous}
            ],
        },
    }


@pytest.mark.parametrize(
    ("anonymous", "outcome"), [(200, "action_required"), (401, "no_exposure_observed"), (403, "no_exposure_observed")]
)
def test_exposure_correction(anonymous: int, outcome: str) -> None:
    result = assess_exposure(evidence(anonymous))
    assert result["outcome"] == outcome
    assert result["coverage_complete"] is True
    assert result["evidence_refs"] == ["fixture:exposure"]
    assert len(result["exposures"]) == (anonymous == 200)


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("auth_evidence", "host", "another.example.test"),
        ("auth_evidence", "port", 8443),
        ("auth_evidence", "scheme", "http"),
        ("auth_evidence", "route", "/other"),
        ("auth_evidence", "address", "192.0.2.21"),
        ("port_route_evidence", "address", "192.0.2.21"),
        ("port_route_evidence", "connected", False),
        ("port_route_evidence", "connected", 1),
        ("auth_evidence", "authorized_status", 403),
        ("auth_evidence", "anonymous_status", 302),
        ("auth_evidence", "anonymous_status", True),
        ("auth_evidence", "observed_at", "2026-10-14T12:00:00Z"),
        ("auth_evidence", "observed_at", "2026-10-15T12:30:00"),
        ("auth_evidence", "evidence_ref", ""),
    ],
)
def test_unbound_or_inconclusive_evidence_never_clears(section: str, field: str, value: object) -> None:
    inputs = evidence()
    inputs[section]["checks"][0][field] = value
    assert assess_exposure(inputs)["outcome"] == "insufficient_evidence"


@pytest.mark.parametrize("section", ["dns_service_inventory", "port_route_evidence", "auth_evidence"])
@pytest.mark.parametrize("fault", ["empty", "missing", "incomplete", "duplicate"])
def test_missing_and_conflicting_coverage_never_clears(section: str, fault: str) -> None:
    inputs = evidence()
    records = "records" if section == "dns_service_inventory" else "checks"
    if fault == "empty":
        inputs[section][records] = []
    elif fault == "missing":
        del inputs[section]
    elif fault == "incomplete":
        inputs[section]["complete"] = False
    else:
        inputs[section][records].append(copy.deepcopy(inputs[section][records][0]))
    assert assess_exposure(inputs)["outcome"] == "insufficient_evidence"


def test_all_scoped_endpoints_need_evidence() -> None:
    inputs = evidence()
    inputs["scope"]["endpoints"].append({**inputs["scope"]["endpoints"][0], "port": 8443})
    result = assess_exposure(inputs)
    assert result["outcome"] == "insufficient_evidence"
    assert result["coverage_complete"] is False
    assert len(result["checked"]) == 1
    assert result["evidence_refs"] == ["fixture:exposure"]


@pytest.mark.parametrize("address", [None, True, 2130706433, "not-an-address", "fe80::1%eth0", "127.000.000.001"])
def test_invalid_dns_address_never_establishes_coverage(address: object) -> None:
    inputs = evidence()
    inputs["dns_service_inventory"]["records"][0]["addresses"] = [address]
    inputs["port_route_evidence"]["checks"][0]["address"] = address
    inputs["auth_evidence"]["checks"][0]["address"] = address
    assert assess_exposure(inputs)["outcome"] == "insufficient_evidence"


@pytest.mark.parametrize("inputs", [{}, {"scope": []}, {"scope": {"endpoints": []}}, None])
def test_malformed_input_is_indeterminate(inputs: object) -> None:
    assert assess_exposure(inputs)["outcome"] == "insufficient_evidence"
