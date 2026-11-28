"""Synthetic, offline examples. Never resolves credentials or contacts a service."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from cops.evidence import EvidenceError, build_envelope, canonical, report

from . import Checkpoint, GraphUsers, Limits, ResourceGraph, Response, collect

TENANT = '00000000-0000-0000-0000-000000000001'
SUBSCRIPTION = '00000000-0000-0000-0000-000000000002'
AS_OF = '2026-01-02T00:00:00Z'


def offline_fixture(name):
    """Two pages per adapter, using invented identifiers and no source secrets."""
    if name == 'graph':
        return GraphUsers(TENANT), [
            {'value': [{'id': '00000000-0000-0000-0000-000000000003', 'userType': 'Member'}],
             '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?$skiptoken=offline-fixture'},
            {'value': [{'id': '00000000-0000-0000-0000-000000000004', 'userType': 'Guest'}]},
        ]
    if name == 'arg':
        prefix = f'/subscriptions/{SUBSCRIPTION}/resourceGroups/demo/providers/microsoft.compute/virtualMachines/'
        return ResourceGraph(TENANT, [SUBSCRIPTION]), [
            {'data': [{'id': prefix + 'a', 'type': 'microsoft.compute/virtualmachines', 'location': 'eastus'}],
             'count': 1, 'totalRecords': 2, 'resultTruncated': 'true', '$skipToken': 'offline-fixture'},
            {'data': [{'id': prefix + 'b', 'type': 'microsoft.compute/virtualmachines', 'location': 'eastus'}],
             'count': 1, 'totalRecords': 2, 'resultTruncated': 'false'},
        ]
    raise EvidenceError('invalid_adapter')


class FixtureCredentials:
    """In-memory placeholder; no environment, keychain, token, or identity lookup."""
    def __init__(self):
        self.calls = 0

    def headers(self, *, refresh=False):
        self.calls += 1
        return {'Authorization': 'Bearer offline-fixture'}


class FixtureTransport:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = 0

    def send(self, request, headers, *, timeout, max_bytes):
        self.calls += 1
        return Response(200, canonical(next(self.pages), max_bytes=max_bytes))


class FixtureInterruption(BaseException):
    """Simulates termination, which the runner must not turn into a normal result."""


def interrupt_after_commit(phase):
    if phase == 'after_commit':
        raise FixtureInterruption()


def stale_example(result):
    """Illustrate an explicitly observed timestamp without guessing provider times."""
    original = result.records[0]
    source = original['source']
    return build_envelope(
        acquisition_id=original['acquisition_id'], product=source['product'], api=source['api'],
        tenant=source['tenant'], scope=source['scope'], identity=source['identity'],
        locator=source['locator'], payload=original['payload'], source_version=source['version'],
        region=source['region']['value'], acquired_at=original['acquired_at'],
        transformed_at=original['transformed_at'], request_fingerprint=original['request_fingerprint'],
        page=original['page'], observed_at='2020-01-01T00:00:00Z')


def demonstration(directory):
    root = Path(directory)
    resumed = {}
    for name in ('graph', 'arg'):
        adapter, pages = offline_fixture(name)
        path = root / name
        try:
            with Checkpoint(path) as checkpoint:
                collect(adapter, checkpoint, FixtureCredentials(), FixtureTransport(pages),
                        now=lambda: AS_OF, fault=interrupt_after_commit)
        except FixtureInterruption:
            pass
        with Checkpoint(path) as checkpoint:
            result = collect(adapter, checkpoint, FixtureCredentials(), FixtureTransport(pages[1:]),
                             now=lambda: AS_OF)
        resumed[name] = {'records': len(result.records), 'pages': result.receipt['consumed']['pages'],
                         'assessment': report(result.records, result.receipt, as_of=AS_OF, max_age_seconds=86400)}
    adapter, pages = offline_fixture('graph')
    with Checkpoint(root / 'partial') as checkpoint:
        partial = collect(adapter, checkpoint, FixtureCredentials(), FixtureTransport(pages),
                          limits=Limits(records=1), now=lambda: AS_OF)
    return {'offline': True, 'live_integration': 'unverified', 'resume': resumed,
            'partial': report(partial.records, partial.receipt, as_of=AS_OF, max_age_seconds=86400),
            'stale': report([stale_example(result)], result.receipt, as_of=AS_OF, max_age_seconds=86400)}


def main():
    with TemporaryDirectory(prefix='cops-evidence-demo-') as directory:
        print(json.dumps(demonstration(directory), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
