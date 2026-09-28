"""Executable shared-consumer scenarios using synthetic adapters only."""
import pytest
from pytest_bdd import given, when, then, scenarios, parsers

from cops.connectors import Checkpoint, Limits, collect, preview
from cops.connectors.demo import (AS_OF, FixtureCredentials, FixtureInterruption,
    FixtureTransport, interrupt_after_commit, offline_fixture, stale_example)
from cops.evidence import report

scenarios('../../specs/features/shared_evidence_acquisition.feature')


@pytest.fixture
def acquisition():
    return {}


@given(parsers.parse('a private checkpoint for the "{name}" adapter'))
def private_checkpoint(acquisition, tmp_path, name):
    adapter, pages = offline_fixture(name)
    acquisition.update(adapter=adapter, pages=pages, path=tmp_path / 'private',
                       credentials=FixtureCredentials(), transport=FixtureTransport(pages))


@when('acquisition is interrupted after committing its first page')
def interrupt(acquisition):
    with pytest.raises(FixtureInterruption), Checkpoint(acquisition['path']) as checkpoint:
        collect(acquisition['adapter'], checkpoint, acquisition['credentials'], acquisition['transport'],
                now=lambda: AS_OF, fault=interrupt_after_commit)


@when('acquisition resumes with the same scope and budgets')
def resume(acquisition):
    with Checkpoint(acquisition['path']) as checkpoint:
        acquisition['result'] = collect(acquisition['adapter'], checkpoint, acquisition['credentials'],
            FixtureTransport(acquisition['pages'][1:]), now=lambda: AS_OF)


@then('two unique records and a complete receipt are available')
def complete(acquisition):
    result = acquisition['result']
    assert len({item['record_id'] for item in result.records}) == 2
    assert result.receipt['status'] == 'complete'
    assert result.receipt['generation'] == 2
    assert result.receipt['consumed']['pages'] == 2


@when('acquisition reaches its record limit before query exhaustion')
def exhaust(acquisition):
    with Checkpoint(acquisition['path']) as checkpoint:
        acquisition['result'] = collect(acquisition['adapter'], checkpoint, acquisition['credentials'],
            acquisition['transport'], limits=Limits(records=1), now=lambda: AS_OF)


@then('the common assessment reports partial and unknown freshness')
def partial(acquisition):
    result = acquisition['result']
    assessment = report(result.records, result.receipt, as_of=AS_OF, max_age_seconds=86400)
    assert result.receipt['reasons'] == ['record_limit']
    assert assessment['status'] == 'partial'
    assert len(assessment['records']) == 1
    assert assessment['records'][0]['completeness'] == 'partial'
    assert assessment['records'][0]['freshness'] == 'unknown'


@when('I preview its acquisition plan')
def dry_run(acquisition):
    acquisition['plan'] = preview(acquisition['adapter'])


@then('no credential or transport call occurs')
def no_side_effects(acquisition):
    assert acquisition['credentials'].calls == acquisition['transport'].calls == 0
    assert acquisition['plan']['tenant'] == acquisition['adapter'].tenant
    assert 'Authorization' not in acquisition['plan']['headers']


@when('a complete acquisition has an explicitly old observation')
def old_observation(acquisition):
    with Checkpoint(acquisition['path']) as checkpoint:
        acquisition['result'] = collect(acquisition['adapter'], checkpoint, acquisition['credentials'],
                                       acquisition['transport'], now=lambda: AS_OF)
    acquisition['old'] = stale_example(acquisition['result'])


@then('the common assessment reports complete and stale freshness')
def stale(acquisition):
    result = acquisition['result']
    assessment = report([acquisition['old']], result.receipt, as_of=AS_OF, max_age_seconds=86400)
    assert assessment['status'] == 'complete'
    assert assessment['records'][0]['completeness'] == 'complete'
    assert assessment['records'][0]['freshness'] == 'stale'
