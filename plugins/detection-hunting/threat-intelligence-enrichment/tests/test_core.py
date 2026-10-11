import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from threat_intel import Approval, Cache, Indicator, Source, conflicts, enrich, normalize

from cops.connectors.interfaces import Response


class FakeTransport:
    calls = []
    requests = []
    response = Response(200, b"{}")

    def __init__(self, origin, path, method):
        self.origin, self.path, self.method = origin, path, method

    def send(self, request, headers, *, timeout, max_bytes):
        self.calls.append((request.method, request.url, timeout, max_bytes))
        self.requests.append(request)
        return self.response


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        FakeTransport.calls.clear()
        FakeTransport.requests.clear()
        self.source = Source("misp", "misp.example.org", "/attributes/restSearch", "test-token")

    def test_sensitive_url_denied_before_request(self):
        indicator = Indicator("url", "https://example.org/private?token=secret")
        result = enrich(indicator, self.source, Approval("misp", indicator.digest), transport_factory=FakeTransport)
        self.assertEqual(result["status"], "privacy_denied")
        self.assertEqual(FakeTransport.calls, [])

    def test_source_specific_approval(self):
        indicator = Indicator("domain", "example.org")
        result = enrich(indicator, self.source, Approval("taxii", indicator.digest), transport_factory=FakeTransport)
        self.assertEqual(result["status"], "privacy_denied")

    def test_misp_positive_and_cache_stale(self):
        FakeTransport.response = Response(
            200, b'{"Attribute":[{"type":"domain","value":"example.org","to_ids":true,"timestamp":"1700000000"}]}'
        )
        indicator = Indicator("domain", "example.org")
        approval = Approval("misp", indicator.digest)
        cache = Cache(positive_ttl=10, negative_ttl=5)
        first = enrich(indicator, self.source, approval, cache=cache, now=100, transport_factory=FakeTransport)
        stale = enrich(indicator, self.source, approval, cache=cache, now=111, cache_only=True, allow_stale=True)
        self.assertEqual(first["status"], "positive")
        self.assertEqual(stale["cache"], "stale")
        self.assertEqual(len(FakeTransport.calls), 1)

    def test_negative_cache_and_error_not_cached(self):
        FakeTransport.response = Response(200, b'{"Attribute":[]}')
        indicator = Indicator("domain", "example.org")
        approval = Approval("misp", indicator.digest)
        cache = Cache(positive_ttl=10, negative_ttl=5)
        self.assertEqual(
            enrich(indicator, self.source, approval, cache=cache, now=100, transport_factory=FakeTransport)["status"],
            "negative",
        )
        self.assertEqual(
            enrich(indicator, self.source, approval, cache=cache, now=104, transport_factory=FakeTransport)["cache"],
            "fresh",
        )
        self.assertEqual(len(FakeTransport.calls), 1)

    def test_unsupported_provider_pair(self):
        indicator = Indicator("azure_application_id", "11111111-1111-1111-1111-111111111111")
        result = enrich(
            indicator, self.source, Approval("misp", indicator.digest, True), transport_factory=FakeTransport
        )
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(FakeTransport.calls, [])

    def test_microsoft_application_id_returns_tenant_context(self):
        indicator = Indicator("azure_application_id", "11111111-1111-1111-1111-111111111111")
        source = Source("microsoft", "graph.microsoft.com", "/v1.0/servicePrincipals", "test-token")
        FakeTransport.response = Response(
            200, b'{"id":"22222222-2222-2222-2222-222222222222","appId":"11111111-1111-1111-1111-111111111111"}'
        )
        denied = enrich(indicator, source, Approval("microsoft", indicator.digest), transport_factory=FakeTransport)
        self.assertEqual(denied["status"], "privacy_denied")
        self.assertEqual(FakeTransport.calls, [])
        result = enrich(
            indicator, source, Approval("microsoft", indicator.digest, True), transport_factory=FakeTransport
        )
        self.assertEqual(result["claims"][0]["assertion"], "tenant_service_principal")
        self.assertIn("servicePrincipals(appId='11111111-1111-1111-1111-111111111111')", FakeTransport.calls[0][1])

    def test_taxii_ipv6_and_certificate_sha256_patterns(self):
        ipv6 = Indicator("ip", "2001:db8::1")
        certificate = Indicator("certificate", "a" * 64)
        self.assertEqual(
            len(
                normalize(
                    "taxii",
                    ipv6,
                    {"objects": [{"type": "indicator", "pattern": "[ipv6-addr:value = '2001:db8::1']", "id": "one"}]},
                )
            ),
            1,
        )
        self.assertEqual(
            len(
                normalize(
                    "taxii",
                    certificate,
                    {
                        "objects": [
                            {
                                "type": "indicator",
                                "pattern": "[x509-certificate:hashes.'SHA-256' = '" + "a" * 64 + "']",
                                "id": "two",
                            }
                        ]
                    },
                )
            ),
            1,
        )

    def test_conflicting_claims_remain_separate(self):
        indicator = Indicator("domain", "example.org")
        claims = normalize(
            "misp",
            indicator,
            {
                "Attribute": [
                    {"type": "domain", "value": "example.org", "to_ids": True, "timestamp": "1700000000"},
                    {"type": "domain", "value": "example.org", "to_ids": False, "timestamp": "1700000001"},
                ]
            },
        )
        self.assertEqual(len(claims), 2)
        self.assertEqual(len(conflicts(claims)), 1)

    def test_taxii_partial_collection(self):
        source = Source("taxii", "taxii.example.org", "/taxii2/collections/demo/objects/", "test-token")
        indicator = Indicator("domain", "example.org")
        FakeTransport.response = Response(200, b'{"more":true,"objects":[]}')
        result = enrich(indicator, source, Approval("taxii", indicator.digest), transport_factory=FakeTransport)
        self.assertEqual(result["status"], "partial")

    def test_invalid_url_rejected(self):
        with self.assertRaises(ValueError):
            Indicator("url", "https://user:pass@example.org/a")

    def test_claims_record_retrieval_time_and_provider_sharing_restrictions(self):
        indicator = Indicator("domain", "example.org")
        marking = "marking-definition--00000000-0000-0000-0000-000000000001"
        misp = normalize(
            "misp",
            indicator,
            {
                "Attribute": [
                    {
                        "type": "domain",
                        "value": "example.org",
                        "to_ids": True,
                        "timestamp": "1700000000",
                        "distribution": 0,
                        "uuid": "misp-1",
                    },
                ]
            },
            retrieved_at=100,
        )
        taxii = normalize(
            "taxii",
            indicator,
            {
                "objects": [
                    {
                        "type": "indicator",
                        "pattern": "[domain-name:value = 'example.org']",
                        "id": "taxii-1",
                        "object_marking_refs": [marking],
                    },
                ]
            },
            retrieved_at=101,
        )
        unknown = normalize(
            "misp",
            indicator,
            {
                "Attribute": [
                    {"type": "domain", "value": "example.org", "to_ids": False},
                ]
            },
            retrieved_at=102,
        )
        self.assertEqual(misp[0]["retrieved_at"], "1970-01-01T00:01:40Z")
        self.assertEqual(misp[0]["sharing_restrictions"], ["misp:distribution:0"])
        self.assertEqual(taxii[0]["sharing_restrictions"], [f"stix:{marking}"])
        self.assertEqual(unknown[0]["sharing_restrictions"], ["unknown"])
        self.assertEqual(misp[0]["provenance"], "misp-1")

    def test_claim_schema_accepts_each_provider_and_requires_provenance_fields(self):
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "claim.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        indicator = Indicator("domain", "example.org")
        claims = [
            *normalize(
                "misp",
                indicator,
                {
                    "Attribute": [
                        {"type": "domain", "value": indicator.value, "to_ids": True, "distribution": 0},
                    ]
                },
                retrieved_at=100,
            ),
            *normalize(
                "taxii",
                indicator,
                {
                    "objects": [
                        {"type": "indicator", "pattern": "[domain-name:value = 'example.org']", "id": "taxii-1"},
                    ]
                },
                retrieved_at=101,
            ),
            *normalize("microsoft", indicator, {"host": indicator.value, "id": "microsoft-1"}, retrieved_at=102),
        ]
        self.assertEqual(len(claims), 3)
        for claim in claims:
            with self.subTest(source=claim["source"]):
                validator.validate(claim)
                for required in ("retrieved_at", "sharing_restrictions"):
                    incomplete = {key: value for key, value in claim.items() if key != required}
                    self.assertFalse(validator.is_valid(incomplete))

    def test_historical_replay_preserves_expired_claim_and_reports_evicted_history(self):
        indicator = Indicator("domain", "example.org")
        approval = Approval("misp", indicator.digest)
        cache = Cache(positive_ttl=10, negative_ttl=5)
        FakeTransport.response = Response(
            200, b'{"Attribute":[{"type":"domain","value":"example.org","to_ids":true,"uuid":"old","distribution":0}]}'
        )
        enrich(indicator, self.source, approval, cache=cache, now=100, transport_factory=FakeTransport)
        FakeTransport.response = Response(200, b'{"Attribute":[]}')
        enrich(indicator, self.source, approval, cache=cache, now=120, transport_factory=FakeTransport)
        calls = len(FakeTransport.calls)
        old = enrich(indicator, self.source, approval, cache=cache, as_of=115, transport_factory=FakeTransport)
        current = enrich(indicator, self.source, approval, cache=cache, as_of=122, transport_factory=FakeTransport)
        self.assertEqual(old["status"], "positive")
        self.assertEqual(old["cache"], "stale")
        self.assertEqual(old["claims"][0]["retrieved_at"], "1970-01-01T00:01:40Z")
        self.assertEqual(old["claims"][0]["sharing_restrictions"], ["misp:distribution:0"])
        self.assertEqual(old["claims"][0]["provenance"], "old")
        self.assertEqual(current["status"], "negative")
        self.assertEqual(len(FakeTransport.calls), calls)
        old["claims"][0]["sharing_restrictions"].clear()
        self.assertEqual(
            enrich(indicator, self.source, approval, cache=cache, as_of=115)["claims"][0]["sharing_restrictions"],
            ["misp:distribution:0"],
        )

        limited = Cache(positive_ttl=10, negative_ttl=5, history_limit=1)
        FakeTransport.response = Response(200, b'{"Attribute":[{"type":"domain","value":"example.org","to_ids":true}]}')
        enrich(indicator, self.source, approval, cache=limited, now=100, transport_factory=FakeTransport)
        FakeTransport.response = Response(200, b'{"Attribute":[]}')
        enrich(indicator, self.source, approval, cache=limited, now=120, transport_factory=FakeTransport)
        self.assertEqual(
            enrich(indicator, self.source, approval, cache=limited, as_of=105)["status"], "history_unavailable"
        )

    def test_replay_uses_latest_snapshot_when_retrieval_times_match(self):
        cache = Cache()
        key = ("source", "indicator")
        cache.put(key, {"status": "positive", "claims": [{"assertion": "old"}], "conflicts": []}, 100)
        cache.put(key, {"status": "negative", "claims": [], "conflicts": []}, 100)
        self.assertEqual(cache.replay(key, 100)["status"], "negative")

    def test_idn_canonicalization_precedes_digest_and_lookup(self):
        indicator = Indicator("domain", "BÜCHER.Example")
        self.assertEqual(indicator.value, "xn--bcher-kva.example")
        self.assertEqual(indicator.original_value, "BÜCHER.Example")
        self.assertEqual(indicator.digest, Indicator("domain", "xn--bcher-kva.example").digest)
        FakeTransport.response = Response(
            200, b'{"Attribute":[{"type":"domain","value":"xn--bcher-kva.example","to_ids":true}]}'
        )
        result = enrich(indicator, self.source, Approval("misp", indicator.digest), transport_factory=FakeTransport)
        self.assertEqual(result["status"], "positive")
        self.assertIn(b"xn--bcher-kva.example", FakeTransport.requests[0].body)

    def test_private_addresses_require_sensitive_approval(self):
        for indicator in (
            Indicator("ip", "10.0.0.1"),
            Indicator("ip", "fd00::1"),
            Indicator("url", "https://192.168.1.2/"),
            Indicator("url", "https://[::1]/"),
        ):
            with self.subTest(indicator=indicator.kind):
                self.assertTrue(indicator.sensitive)
                result = enrich(
                    indicator, self.source, Approval("misp", indicator.digest), transport_factory=FakeTransport
                )
                self.assertEqual(result["status"], "privacy_denied")
        self.assertEqual(FakeTransport.calls, [])
        public = Indicator("ip", "8.8.8.8")
        self.assertFalse(public.sensitive)

    def test_rate_limit_stops_retry_and_cools_down_source_scope(self):
        indicator = Indicator("domain", "example.org")
        other = Indicator("domain", "example.net")
        cache = Cache()
        FakeTransport.response = Response(429, b"", retry_after="30")
        first = enrich(
            indicator,
            self.source,
            Approval("misp", indicator.digest),
            cache=cache,
            now=100,
            transport_factory=FakeTransport,
        )
        blocked = enrich(
            other, self.source, Approval("misp", other.digest), cache=cache, now=110, transport_factory=FakeTransport
        )
        self.assertEqual(first["error"], "rate_limited")
        self.assertEqual(first["retry_after_seconds"], 30)
        self.assertEqual(blocked["retry_after_seconds"], 20)
        self.assertEqual(len(FakeTransport.calls), 1)
        FakeTransport.response = Response(200, b'{"Attribute":[]}')
        self.assertEqual(
            enrich(
                other,
                self.source,
                Approval("misp", other.digest),
                cache=cache,
                now=130,
                transport_factory=FakeTransport,
            )["status"],
            "negative",
        )
        self.assertEqual(len(FakeTransport.calls), 2)

    def test_rate_limit_handles_date_and_oversized_header(self):
        indicator = Indicator("domain", "example.org")
        approval = Approval("misp", indicator.digest)
        cases = (
            (503, "Thu, 01 Jan 1970 00:02:10 GMT", 30),
            (429, "9" * 5000, 60),
            (429, "99999", 86400),
            (429, "0", 1),
        )
        for status, header, expected in cases:
            with self.subTest(status=status, header_length=len(header)):
                FakeTransport.calls.clear()
                FakeTransport.response = Response(status, b"", retry_after=header)
                result = enrich(
                    indicator, self.source, approval, cache=Cache(), now=100, transport_factory=FakeTransport
                )
                self.assertEqual(result["error"], "rate_limited")
                self.assertEqual(result["retry_after_seconds"], expected)
                self.assertEqual(len(FakeTransport.calls), 1)


if __name__ == "__main__":
    unittest.main()
