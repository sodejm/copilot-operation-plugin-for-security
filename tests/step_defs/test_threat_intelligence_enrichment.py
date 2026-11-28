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
        "objects": [{"type": "indicator", "pattern": "[domain-name:value = 'example.org']", "id": "taxii-indicator-1"}]
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
    assert all(c["retrieved_at"] and c["sharing_restrictions"] for c in context["claims"])
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


@given("an older marked claim was replaced by a later negative lookup")
def replaced_marked_claim(context):
    indicator = Indicator("domain", "example.org")
    source = Source("misp", "misp.example.org", "/attributes/restSearch", "test-token")
    approval = Approval("misp", indicator.digest)
    cache = Cache(positive_ttl=10, negative_ttl=5)
    FakeTransport.response = Response(
        200,
        b'{"Attribute":[{"type":"domain","value":"example.org","to_ids":true,"uuid":"old","distribution":0}]}',
    )
    enrich(indicator, source, approval, cache=cache, now=100, transport_factory=FakeTransport)
    FakeTransport.response = Response(200, b'{"Attribute":[]}')
    enrich(indicator, source, approval, cache=cache, now=120, transport_factory=FakeTransport)
    context.update(indicator=indicator, source=source, approval=approval, cache=cache)


@when("the analyst replays the cache before the later lookup")
def replay_old_claim(context):
    context["calls_before_replay"] = len(FakeTransport.calls)
    context["result"] = enrich(
        context["indicator"],
        context["source"],
        context["approval"],
        cache=context["cache"],
        as_of=115,
        transport_factory=FakeTransport,
    )


@then("the expired claim retains its retrieval time, marking, and source locator")
def expired_provenance_retained(context):
    result = context["result"]
    assert result["status"] == "positive" and result["cache"] == "stale"
    assert result["claims"][0]["retrieved_at"] == "1970-01-01T00:01:40Z"
    assert result["claims"][0]["sharing_restrictions"] == ["misp:distribution:0"]
    assert result["claims"][0]["provenance"] == "old"
    assert len(FakeTransport.calls) == context["calls_before_replay"]


@given("a provider responds with a rate limit")
def source_rate_limited(context):
    indicator = Indicator("domain", "example.org")
    source = Source("misp", "misp.example.org", "/attributes/restSearch", "test-token")
    cache = Cache()
    FakeTransport.response = Response(429, b"", retry_after="30")
    context["first"] = enrich(
        indicator,
        source,
        Approval("misp", indicator.digest),
        cache=cache,
        now=100,
        transport_factory=FakeTransport,
    )
    context.update(source=source, cache=cache)


@when("another indicator is looked up from the same source")
def other_indicator_same_source(context):
    indicator = Indicator("domain", "example.net")
    context["result"] = enrich(
        indicator,
        context["source"],
        Approval("misp", indicator.digest),
        cache=context["cache"],
        now=110,
        transport_factory=FakeTransport,
    )


@then("the source cooldown prevents an outbound request")
def cooldown_prevents_request(context):
    assert context["first"]["error"] == "rate_limited"
    assert context["result"]["retry_after_seconds"] == 20
    assert len(FakeTransport.calls) == 1
