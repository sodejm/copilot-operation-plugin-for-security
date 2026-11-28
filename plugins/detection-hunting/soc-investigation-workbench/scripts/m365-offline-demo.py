#!/usr/bin/env python3
"""Synthetic Microsoft 365 collection and correlation without credentials."""
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from investigationwb.m365 import correlate  # noqa: E402

from cops.connectors import Checkpoint, GraphCollection, Response, collect, preview  # noqa: E402
from cops.evidence import canonical  # noqa: E402

TENANT = '00000000-0000-0000-0000-000000000001'
USER = '00000000-0000-0000-0000-000000000002'
APP = '00000000-0000-0000-0000-000000000003'
PAGES = {
    'signins': {'value': [{'id': 'signin-1', 'userId': USER, 'appId': APP,
                          'createdDateTime': '2026-01-01T00:00:00Z'}]},
    'directory-audits': {'value': [{'id': 'audit-1', 'initiatedBy': {'user': {'id': USER}},
                                   'activityDateTime': '2026-01-01T00:05:00Z'}]},
    'service-principals': {'value': [{'id': APP, 'appId': APP, 'displayName': 'Synthetic app'}]},
}


class FixtureCredentials:
    def headers(self, *, refresh=False):
        return {'Authorization': 'Bearer synthetic'}


class FixtureTransport:
    def __init__(self, page):
        self.page = page

    def send(self, request, headers, *, timeout, max_bytes):
        return Response(200, canonical(self.page, max_bytes=max_bytes))


def main():
    sources = {}
    with TemporaryDirectory(prefix='cops-m365-demo-') as directory:
        for source, page in PAGES.items():
            adapter = GraphCollection(TENANT, source)
            with Checkpoint(Path(directory) / source) as checkpoint:
                result = collect(adapter, checkpoint, FixtureCredentials(),
                                 FixtureTransport(page), now=lambda: '2026-01-02T00:00:00Z')
            sources[adapter.name] = (result.records, result.receipt)
        print(json.dumps({'offline': True, 'live_integration': 'unverified',
                          'plans': {name: preview(GraphCollection(TENANT, name))
                                    for name in PAGES},
                          'correlation': correlate(sources)}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
