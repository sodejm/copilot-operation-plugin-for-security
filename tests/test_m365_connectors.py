"""Offline Graph projection and correlation abuse cases."""
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'plugins/detection-hunting/soc-investigation-workbench'))

from investigationwb.m365 import correlate

from cops.connectors import Checkpoint, GraphCollection, Response, collect
from cops.connectors.adapters.m365 import SOURCES
from cops.evidence import EvidenceError, canonical

TENANT = '00000000-0000-0000-0000-000000000001'
USER = '00000000-0000-0000-0000-000000000002'
APP = '00000000-0000-0000-0000-000000000003'


class Credentials:
    calls = 0
    def headers(self, *, refresh=False):
        self.calls += 1
        return {'Authorization': 'Bearer offline-fixture'}


class Transport:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = 0
    def send(self, request, headers, *, timeout, max_bytes):
        self.calls += 1
        return Response(200, canonical(next(self.pages), max_bytes=max_bytes))


def acquire(directory, source, row):
    with Checkpoint(Path(directory) / source) as checkpoint:
        result = collect(GraphCollection(TENANT, source), checkpoint, Credentials(),
                         Transport([{'value': [row]}]), now=lambda: '2026-01-02T00:00:00Z')
    return result.records, result.receipt


class M365InvestigationTests(unittest.TestCase):
    def test_next_link_cannot_cross_origin(self):
        credentials = Credentials()
        transport = Transport([{'value': [{'id': 'event-one', 'userId': USER}],
                                '@odata.nextLink': 'https://attacker.example/v1.0/auditLogs/signIns?$top=100'}])
        with TemporaryDirectory() as directory, Checkpoint(Path(directory) / 'signins') as checkpoint:
            result = collect(GraphCollection(TENANT, 'signins'), checkpoint, credentials, transport,
                             now=lambda: '2026-01-02T00:00:00Z')
        self.assertEqual(result.receipt['status'], 'partial')
        self.assertEqual(result.receipt['reasons'], ['unsafe_destination'])
        self.assertEqual(transport.calls, 1)

    def test_only_explicit_identifiers_join_and_coverage_is_visible(self):
        with TemporaryDirectory() as directory:
            signins = acquire(directory, 'signins',
                              {'id': 'event-one', 'userId': USER, 'appId': APP, 'ipAddress': '192.0.2.1'})
            audits = acquire(directory, 'directory-audits',
                             {'id': 'event-two', 'initiatedBy': {'user': {'id': USER}}})
            principals = acquire(directory, 'service-principals', {'id': APP, 'appId': APP})
            report = correlate({'m365-signins': signins,
                                'm365-directory-audits': audits,
                                'm365-service-principals': principals})
        self.assertEqual(len(report['leads']), 2)
        self.assertEqual({tuple(lead['sources']) for lead in report['leads']},
                         {('m365-directory-audits', 'm365-signins'),
                          ('m365-service-principals', 'm365-signins')})
        self.assertNotIn('192.0.2.1', str(report))
        self.assertNotIn(USER, str(report))

    def test_cross_tenant_evidence_fails_closed(self):
        with TemporaryDirectory() as directory:
            records, receipt = acquire(directory, 'signins', {'id': 'event-one', 'userId': USER})
            changed = dict(receipt, tenant='00000000-0000-0000-0000-000000000009')
            with self.assertRaises(EvidenceError):
                correlate({'m365-signins': (records, changed)})

    def test_all_named_sources_accepted_by_adapter(self):
        self.assertEqual(len(SOURCES), 12)
        for source, (path, permission, fields) in SOURCES.items():
            adapter = GraphCollection(TENANT, source)
            self.assertEqual(adapter.path, path)
            self.assertEqual(adapter.permission, permission)
            req = adapter.request()
            self.assertTrue(req.url.startswith('https://graph.microsoft.com/v1.0/'))
            page = adapter.parse({'value': []})
            self.assertEqual(list(page.records), [])

    def test_oauth2_and_mail_correlation(self):
        with TemporaryDirectory() as directory:
            grants = acquire(directory, 'oauth2-permission-grants',
                             {'id': 'grant-1', 'clientId': APP, 'consentType': 'Principal',
                              'principalId': USER, 'scope': 'Mail.Read'})
            mail = acquire(directory, 'mail-messages',
                           {'id': 'msg-1', 'userId': USER, 'subject': 'Report'})
            principals = acquire(directory, 'service-principals',
                                 {'id': APP, 'appId': APP})
            report = correlate({'m365-oauth2-permission-grants': grants,
                                'm365-mail-messages': mail,
                                'm365-service-principals': principals})
        self.assertEqual(len(report['leads']), 2)
        self.assertEqual(set(report['coverage']),
                         {'m365-oauth2-permission-grants', 'm365-mail-messages', 'm365-service-principals'})

    def test_security_alerts_correlation(self):
        with TemporaryDirectory() as directory:
            alerts = acquire(directory, 'security-alerts',
                             {'id': 'alert-1', 'createdDateTime': '2026-01-01T00:00:00Z',
                              'userId': USER, 'appId': APP, 'severity': 'high'})
            signins = acquire(directory, 'signins',
                              {'id': 'signin-1', 'userId': USER, 'appId': APP, 'ipAddress': '198.51.100.1'})
            report = correlate({'m365-security-alerts': alerts, 'm365-signins': signins})
        self.assertEqual(len(report['leads']), 2)
        self.assertNotIn('198.51.100.1', str(report))

    def test_non_keyed_source_retained_in_coverage(self):
        with TemporaryDirectory() as directory:
            policies = acquire(directory, 'conditional-access',
                               {'id': 'policy-1', 'displayName': 'Require MFA', 'state': 'enabled'})
            signins = acquire(directory, 'signins',
                              {'id': 'signin-1', 'userId': USER, 'appId': APP, 'ipAddress': '198.51.100.1'})
            report = correlate({'m365-conditional-access': policies, 'm365-signins': signins})
        self.assertEqual(len(report['leads']), 0)
        self.assertEqual(set(report['coverage']), {'m365-conditional-access', 'm365-signins'})


if __name__ == '__main__':
    unittest.main()
