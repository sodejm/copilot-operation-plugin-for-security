"""Executable Microsoft 365 offline acquisition scenarios."""
from pathlib import Path
import sys

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'plugins/detection-hunting/soc-investigation-workbench'))

from cops.connectors import Checkpoint, GraphCollection, Response, collect
from cops.evidence import canonical
from investigationwb.m365 import correlate

scenarios('../../specs/features/m365_investigation.feature')

TENANT = '00000000-0000-0000-0000-000000000001'
USER = '00000000-0000-0000-0000-000000000002'
APP = '00000000-0000-0000-0000-000000000003'


class Credentials:
    def headers(self, *, refresh=False):
        return {'Authorization': 'Bearer synthetic'}


class Transport:
    def __init__(self, page):
        self.page = page
        self.calls = 0

    def send(self, request, headers, *, timeout, max_bytes):
        self.calls += 1
        return Response(200, canonical(self.page, max_bytes=max_bytes))


@pytest.fixture
def state(tmp_path):
    return {'root': Path(tmp_path)}


def acquire(state, source, page):
    with Checkpoint(state['root'] / source) as checkpoint:
        return collect(GraphCollection(TENANT, source), checkpoint,
                       Credentials(), Transport(page),
                       now=lambda: '2026-01-02T00:00:00Z')


@given('a selected Microsoft 365 sign-in collection')
def selected(state):
    state['adapter'] = GraphCollection(TENANT, 'signins')


@when('the provider supplies a next link on another origin')
def cross_origin(state):
    state['transport'] = Transport({'value': [{'id': 'signin-1', 'userId': USER}],
                                    '@odata.nextLink': 'https://example.invalid/v1.0/auditLogs/signIns?$top=100'})
    with Checkpoint(state['root'] / 'cross-origin') as checkpoint:
        state['result'] = collect(state['adapter'], checkpoint, Credentials(),
                                  state['transport'], now=lambda: '2026-01-02T00:00:00Z')


@then('collection is partial and the next link is not requested')
def partial(state):
    assert state['result'].receipt['status'] == 'partial'
    assert state['transport'].calls == 1


@given('synthetic sign-in, audit, and service principal evidence')
def evidence(state):
    state['sources'] = {
        'm365-signins': acquire(state, 'signins', {'value': [
            {'id': 'signin-1', 'userId': USER, 'appId': APP, 'ipAddress': '192.0.2.1'}]}),
        'm365-directory-audits': acquire(state, 'directory-audits', {'value': [
            {'id': 'audit-1', 'initiatedBy': {'user': {'id': USER}}}]}),
        'm365-service-principals': acquire(state, 'service-principals', {'value': [
            {'id': APP, 'appId': APP}]}),
    }
    state['sources'] = {name: (result.records, result.receipt)
                        for name, result in state['sources'].items()}


@when('the analyst correlates the three source records')
def correlate_sources(state):
    state['report'] = correlate(state['sources'])


@then('the report preserves source provenance and a shared IP alone makes no identity match')
def leads(state):
    assert len(state['report']['leads']) == 2
    assert set(state['report']['coverage']) == set(state['sources'])
    assert '192.0.2.1' not in str(state['report'])
