"""Executable acceptance tests using local synthetic evidence; no paid calls."""
import json
from pathlib import Path
import subprocess
import sys

from pytest_bdd import given, when, then, scenarios

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / '.agents/skills/plugin-run-cost'
SCRIPT = SKILL / 'scripts/run_cost.py'
scenarios('../../specs/features/plugin_run_cost.feature')


def cli(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                          capture_output=True, text=True, timeout=10)


def output(*args):
    result = cli(*args)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@given('synthetic plugin cost inputs in a private workspace', target_fixture='cost_workspace')
def workspace(tmp_path):
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    manifest = json.loads((SKILL / 'examples/manifest.json').read_text())
    manifest['source_completeness'] = 'complete'
    manifest_path = private / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest))
    usage = dict(input_tokens=1000, cached_input_tokens=200, cache_write_input_tokens=100,
                 output_tokens=100, reasoning_output_tokens=50)
    records = [dict(type='session_meta', payload=dict(id='synthetic-session')),
               dict(type='turn_context', payload=dict(model='gpt-6-sol', effort='high'))]
    records.extend(dict(type='token_usage_record', payload=dict(
        thread_id='synthetic-session', response_id=response, usage=usage)) for response in ('one', 'two'))
    session = private / 'session.jsonl'
    session.write_text(''.join(json.dumps(dict(record, timestamp='2026-10-02T12:00:01Z'))+'\n'
                               for record in records))
    copied = private / 'copy.jsonl'
    copied.write_bytes(session.read_bytes())
    return dict(private=private, manifest=manifest_path, session=session, copied=copied,
                ledger=private/'runs.jsonl')


@given('the manifest has no service tier assumption')
def no_tier(cost_workspace):
    path = cost_workspace['manifest']
    manifest = json.loads(path.read_text())
    manifest.pop('assumed_service_tier')
    path.write_text(json.dumps(manifest))


@when('I import the session and its copy twice through the cost CLI')
def import_twice(cost_workspace):
    w = cost_workspace
    for _ in range(2):
        result = output('import', '--manifest', w['manifest'], '--path', w['session'],
                        '--path', w['copied'], '--ledger', w['ledger'])
        assert result['requests'] == 2
    assert len(w['ledger'].read_text().splitlines()) == 1
    assert str(w['private']) not in w['ledger'].read_text()


@when('I report the private cost ledger')
def report(cost_workspace):
    cost_workspace['report'] = output('report', '--ledger', cost_workspace['ledger'])


@then('two unique requests have a complete API equivalent and reproducible pricing')
def priced(cost_workspace):
    result = cost_workspace['report']
    accounting = result['runs'][0]['accounting']
    assert accounting['requests'] == 2
    assert accounting['complete_evidence'] is True
    assert accounting['total_usd'] == '0.005380'
    assert result['cohorts'][0]['cost_per_accepted_result_usd'] == '0.005380'
    assert accounting['pricing_provenance'][0]['rate']['verified_at']
    assert accounting['pricing_provenance'][0]['requests'] == 2
    assert 'API-equivalent' in result['basis']


@then('the run has unpriced requests and no accepted-result price')
def unpriced(cost_workspace):
    result = cost_workspace['report']
    accounting = result['runs'][0]['accounting']
    assert accounting['unpriced_requests'] == 2
    assert accounting['total_usd'] is None
    assert result['cohorts'][0]['cost_per_accepted_result_usd'] is None


@when('I profile repository wiki and threat model inputs through the cost CLI')
def profile(cost_workspace):
    root = cost_workspace['private']
    repository = root/'repo'
    repository.mkdir()
    (repository/'secretary.py').write_text('print("synthetic")')
    wiki = root/'wiki.md'
    wiki.write_text('print("synthetic")')
    threat = root/'threat.json'
    threat.write_text(json.dumps(dict(components=['fixture'], flows=[], threats=[])))
    result = output('profile', '--repository', repository, '--wiki', wiki, '--threat-model', threat)
    cost_workspace['profile'] = result
    path = root/'profile.json'
    path.write_text(json.dumps(result))
    cost_workspace['profile_path'] = path


@when('I forecast the profiled input through the cost CLI')
def forecast(cost_workspace):
    cost_workspace['forecast'] = output('estimate', '--config', SKILL/'examples/forecast.json',
                                        '--profile', cost_workspace['profile_path'])


@then('duplicate content is counted once and the forecast retains its assumptions')
def forecasted(cost_workspace):
    assert cost_workspace['profile']['unique_documents'] == 2
    assert cost_workspace['profile']['duplicate_documents'] == 1
    assert cost_workspace['profile']['graph_counts']['components'] == 1
    forecasts = cost_workspace['forecast']['scenarios']
    assert len(forecasts) == 3
    assert all(s['input_profile_used'] and s['assumptions'] and s['total_usd'] is not None for s in forecasts)


@when('I compare manual and hybrid work through the cost CLI')
def compare(cost_workspace):
    path = cost_workspace['private']/'business.json'
    path.write_text(json.dumps(dict(alternatives=[
        dict(name='manual', qualified=True, active_minutes=60),
        dict(name='hybrid', qualified=True, active_minutes=30, variable_usd=1)])))
    cost_workspace['business'] = output('compare', '--config', path)


@then('annual capacity and recurring savings use three runs weekly and the supplied hourly rates')
def compared(cost_workspace):
    result = cost_workspace['business']
    assert result['runs_per_year'] == 156
    assert result['average_runs_per_month'] == 13
    hybrid = result['alternatives'][1]
    assert hybrid['annual_capacity_hours'] == 78
    assert hybrid['at_hourly_rate']['75']['annual_recurring_savings_usd'] == '5694.000000'
    assert hybrid['at_hourly_rate']['150']['annual_recurring_savings_usd'] == '11544.000000'


@when('I request a cost profile with no sources', target_fixture='empty_profile')
def empty_profile():
    return cli('profile')


@then('the cost CLI reports missing input instead of zero cost')
def rejected(empty_profile):
    assert empty_profile.returncode != 0
    assert 'at least one profile input' in empty_profile.stderr
    assert not empty_profile.stdout
