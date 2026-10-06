"""Executable acceptance scenarios for read-only threat intelligence enrichment."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

PACKAGE = Path(__file__).resolve().parents[2] / "plugins/detection-hunting/threat-intelligence-enrichment"
sys.path.insert(0, str(PACKAGE))
from threat_intel import Approval, Cache, Indicator, Source, conflicts, enrich, normalize  # noqa: E402

from cops.connectors.interfaces import Response  # noqa: E402

scenarios("../../specs/features/threat_intelligence_enrichment.feature")


class FakeTransport:
    calls = []
    response = Response(200, b"{}")

    def __init__(self, origin, path, method):
        self.origin, self.path, self.method = origin, path, method

    def send(self, request, headers, *, timeout, max_bytes):
        self.calls.append((request.method, request.url, timeout, max_bytes))
        return self.response


@pytest.fixture
def context():
    FakeTransport.calls.clear()
    return {}


@given("a URL with a path and query")
def sensitive_url(context):
    context["indicator"] = Indicator("url", "https://example.org/private?token=secret")
    context["source"] = Source("microsoft", "graph.microsoft.com", "/v1.0/servicePrincipals", "test-token")


@when("the analyst has not approved a Microsoft lookup")
def unapproved_lookup(context):
    approval = Approval("misp", context["indicator"].digest)
    context["result"] = enrich(context["indicator"], context["source"], approval, transport_factory=FakeTransport)


@then("no request is sent and the lookup is privacy denied")
def privacy_denied(context):
    assert context["result"]["status"] == "privacy_denied"
    assert FakeTransport.calls == []


@given("MISP and TAXII claims for the same domain disagree")
def conflicting_claims_setup(context):
    context["indicator"] = Indicator("domain", "example.org")
    context["misp_data"] = {
        "Attribute": [
            {"type": "domain", "value": "example.org", "to_ids": True, "timestamp": "1700000000"},
            {"type": "domain", "value": "example.org", "to_ids": False, "timestamp": "1700000001"},
        ]
    }
    context["taxii_data"] = {
        "objects": [
            {"type": "indicator", "pattern": "[domain-name:value = 'example.org']", "id": "taxii-indicator-1"}
        ]
    }


@when("the claims are normalized")
def normalize_claims(context):
    misp_claims = normalize("misp", context["indicator"], context["misp_data"])
    taxii_claims = normalize("taxii", context["indicator"], context["taxii_data"])
    context["claims"] = misp_claims + taxii_claims
    context["conflicts"] = conflicts(context["claims"])


@then("each claim keeps its source and the result records a conflict")
def claims_recorded_with_sources(context):
    sources = {c["source"] for c in context["claims"]}
    assert "misp" in sources and "taxii" in sources
    assert len(context["conflicts"]) == 1
    assert "misp" in context["conflicts"][0]["sources"]


@given("a positive claim cached beyond its configured TTL")
def cached_stale_claim(context):
    FakeTransport.response = Response(
        200,
        b'{"Attribute":[{"type":"domain","value":"example.org","to_ids":true,"timestamp":"1700000000"}]}',
    )
    context["indicator"] = Indicator("domain", "example.org")
    context["source"] = Source("misp", "misp.example.org", "/attributes/restSearch", "test-token")
    context["approval"] = Approval("misp", context["indicator"].digest)
    context["cache"] = Cache(positive_ttl=10, negative_ttl=5)
    enrich(
        context["indicator"],
        context["source"],
        context["approval"],
        cache=context["cache"],
        now=100,
        transport_factory=FakeTransport,
    )


@when("the analyst requests a cache-only lookup")
def cache_only_lookup(context):
    context["result"] = enrich(
        context["indicator"],
        context["source"],
        context["approval"],
        cache=context["cache"],
        now=111,
        cache_only=True,
        allow_stale=True,
    )


@then("the result is labeled stale")
def result_labeled_stale(context):
    assert context["result"]["cache"] == "stale"
