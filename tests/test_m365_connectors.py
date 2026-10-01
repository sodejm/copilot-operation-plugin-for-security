"""Offline Graph projection and correlation abuse cases."""
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'plugins/detection-hunting/soc-investigation-workbench'))

from cops.connectors import Checkpoint, GraphCollection, Response, collect
from cops.evidence import EvidenceError, canonical
from investigationwb.m365 import correlate

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


if __name__ == '__main__':
    unittest.main()
