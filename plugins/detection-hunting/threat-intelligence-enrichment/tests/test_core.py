import unittest

from threat_intel import Approval, Cache, Indicator, Source, conflicts, enrich, normalize

from cops.connectors.interfaces import Response


class FakeTransport:
    calls = []
    response = Response(200, b'{}')

    def __init__(self, origin, path, method):
        self.origin, self.path, self.method = origin, path, method

    def send(self, request, headers, *, timeout, max_bytes):
        self.calls.append((request.method, request.url, timeout, max_bytes))
        return self.response


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        FakeTransport.calls.clear()
        self.source = Source('misp', 'misp.example.org', '/attributes/restSearch', 'test-token')

    def test_sensitive_url_denied_before_request(self):
        indicator = Indicator('url', 'https://example.org/private?token=secret')
        result = enrich(indicator, self.source, Approval('misp', indicator.digest), transport_factory=FakeTransport)
        self.assertEqual(result['status'], 'privacy_denied')
        self.assertEqual(FakeTransport.calls, [])

    def test_source_specific_approval(self):
        indicator = Indicator('domain', 'example.org')
        result = enrich(indicator, self.source, Approval('taxii', indicator.digest), transport_factory=FakeTransport)
        self.assertEqual(result['status'], 'privacy_denied')

    def test_misp_positive_and_cache_stale(self):
        FakeTransport.response = Response(200, b'{"Attribute":[{"type":"domain","value":"example.org","to_ids":true,"timestamp":"1700000000"}]}')
        indicator = Indicator('domain', 'example.org')
        approval = Approval('misp', indicator.digest)
        cache = Cache(positive_ttl=10, negative_ttl=5)
        first = enrich(indicator, self.source, approval, cache=cache, now=100, transport_factory=FakeTransport)
        stale = enrich(indicator, self.source, approval, cache=cache, now=111, cache_only=True, allow_stale=True)
        self.assertEqual(first['status'], 'positive')
        self.assertEqual(stale['cache'], 'stale')
        self.assertEqual(len(FakeTransport.calls), 1)

    def test_negative_cache_and_error_not_cached(self):
        FakeTransport.response = Response(200, b'{"Attribute":[]}')
        indicator = Indicator('domain', 'example.org')
        approval = Approval('misp', indicator.digest)
        cache = Cache(positive_ttl=10, negative_ttl=5)
        self.assertEqual(enrich(indicator, self.source, approval, cache=cache, now=100, transport_factory=FakeTransport)['status'], 'negative')
        self.assertEqual(enrich(indicator, self.source, approval, cache=cache, now=104, transport_factory=FakeTransport)['cache'], 'fresh')
        self.assertEqual(len(FakeTransport.calls), 1)

    def test_unsupported_provider_pair(self):
        indicator = Indicator('azure_application_id', '11111111-1111-1111-1111-111111111111')
        result = enrich(indicator, self.source, Approval('misp', indicator.digest, True), transport_factory=FakeTransport)
        self.assertEqual(result['status'], 'unsupported')
        self.assertEqual(FakeTransport.calls, [])

    def test_microsoft_application_id_returns_tenant_context(self):
        indicator = Indicator('azure_application_id', '11111111-1111-1111-1111-111111111111')
        source = Source('microsoft', 'graph.microsoft.com', '/v1.0/servicePrincipals', 'test-token')
        FakeTransport.response = Response(200, b'{"id":"22222222-2222-2222-2222-222222222222","appId":"11111111-1111-1111-1111-111111111111"}')
        denied = enrich(indicator, source, Approval('microsoft', indicator.digest), transport_factory=FakeTransport)
        self.assertEqual(denied['status'], 'privacy_denied')
        self.assertEqual(FakeTransport.calls, [])
        result = enrich(indicator, source, Approval('microsoft', indicator.digest, True), transport_factory=FakeTransport)
        self.assertEqual(result['claims'][0]['assertion'], 'tenant_service_principal')
        self.assertIn("servicePrincipals(appId='11111111-1111-1111-1111-111111111111')", FakeTransport.calls[0][1])

    def test_taxii_ipv6_and_certificate_sha256_patterns(self):
        ipv6 = Indicator('ip', '2001:db8::1')
        certificate = Indicator('certificate', 'a' * 64)
        self.assertEqual(len(normalize('taxii', ipv6, {'objects': [
            {'type': 'indicator', 'pattern': "[ipv6-addr:value = '2001:db8::1']", 'id': 'one'}
        ]})), 1)
        self.assertEqual(len(normalize('taxii', certificate, {'objects': [
            {'type': 'indicator', 'pattern': "[x509-certificate:hashes.'SHA-256' = '" + 'a' * 64 + "']", 'id': 'two'}
        ]})), 1)

    def test_conflicting_claims_remain_separate(self):
        indicator = Indicator('domain', 'example.org')
        claims = normalize('misp', indicator, {'Attribute': [
            {'type': 'domain', 'value': 'example.org', 'to_ids': True, 'timestamp': '1700000000'},
            {'type': 'domain', 'value': 'example.org', 'to_ids': False, 'timestamp': '1700000001'},
        ]})
        self.assertEqual(len(claims), 2)
        self.assertEqual(len(conflicts(claims)), 1)

    def test_taxii_partial_collection(self):
        source = Source('taxii', 'taxii.example.org', '/taxii2/collections/demo/objects/', 'test-token')
        indicator = Indicator('domain', 'example.org')
        FakeTransport.response = Response(200, b'{"more":true,"objects":[]}')
        result = enrich(indicator, source, Approval('taxii', indicator.digest), transport_factory=FakeTransport)
        self.assertEqual(result['status'], 'partial')

    def test_invalid_url_rejected(self):
        with self.assertRaises(ValueError):
            Indicator('url', 'https://user:pass@example.org/a')


if __name__ == '__main__':
    unittest.main()
