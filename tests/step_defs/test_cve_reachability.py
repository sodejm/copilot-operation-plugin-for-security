"""CLI integration tests. Fixtures demonstrate structural checks, not real CVEs."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest
from pytest_bdd import given, when, then, scenarios, parsers

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'plugins/logging-telemetry/security-logging-advisor'
SKILL = PACKAGE / 'skills/cve-reachability'
SCRIPT = SKILL / 'scripts/reachability-report.py'
SPEC = importlib.util.spec_from_file_location('reachability_report', SCRIPT)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
scenarios('../../specs/features/cve_reachability.feature')


def cli(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                          capture_output=True, text=True, timeout=10)


@given('an empty repository and evidence workspace', target_fixture='workspace')
def workspace(tmp_path):
    repo = tmp_path / 'repo'
    repo.mkdir()
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    return {'repo': repo, 'root': evidence, 'report_path': tmp_path / 'report.json'}


@when('I initialize a report through the CLI')
def initialize(workspace):
    workspace['result'] = cli('init', '--repository', workspace['repo'],
                              '--cve', '[CVE]', '--component', '[VULNERABLE_COMPONENT]',
                              '--output', workspace['report_path'])


@then('the report is unresolved and the repository is unchanged')
def initialized(workspace):
    assert workspace['result'].returncode == 0
    report = json.loads(workspace['report_path'].read_text())
    assert (report['conclusion'], report['trigger'], report['impact']) == (
        'unresolved', 'unknown', 'untested')
    assert report['evidence'] == []
    assert list(workspace['repo'].iterdir()) == []
    result = cli('check', workspace['report_path'], '--evidence-root', workspace['root'])
    assert result.returncode == 0
    assert 'NOT validated' in result.stdout


@given('a structurally complete report with captured evidence')
def populated(workspace):
    (workspace['root'] / 'capture.txt').write_text('Synthetic structural fixture.\nNo real CVE.\n')
    result = cli('evidence', '--root', workspace['root'], '--file', 'capture.txt',
                 '--id', 'E1', '--start', 1, '--end', 2)
    assert result.returncode == 0, result.stderr
    report = HELPER.scaffold(str(workspace['repo']), '[CVE]', '[VULNERABLE_COMPONENT]')
    report['evidence'] = [json.loads(result.stdout)]
    for key in HELPER.SECTIONS:
        report[key] = {'summary': 'Synthetic fixture, not a semantic proof.', 'evidence': ['E1']}
    report['conclusion'] = 'confirmed'
    report['review'] = {'reviewer': 'fixture', 'basis': 'structural test only', 'evidence': ['E1']}
    report['paths'] = [{'entrypoint': 'handler', 'sink': 'sink', 'conditions': 'fixture',
                        'evidence': ['E1'], 'edges': [
                            {'caller': 'handler', 'callee': 'sink', 'dispatch': 'direct',
                             'resolved': True, 'evidence': ['E1']}]}]
    report['parameters'] = [{key: 'fixture' for key in (
        'sink', 'formal', 'actual', 'origin', 'control', 'transformations', 'guards', 'constraints')}]
    report['parameters'][0]['sink'] = 'sink'
    report['parameters'][0]['evidence'] = ['E1']
    report['tools'] = [{'name': 'uninstalled analyzer', 'status': 'unavailable', 'evidence': []}]
    workspace['report'] = report


@given(parsers.parse('the report or evidence has "{defect}"'))
def defect(workspace, defect):
    r = workspace['report']
    e = r['evidence'][0]
    source = workspace['root'] / 'capture.txt'
    if defect == 'changed bytes':
        source.write_text('changed\n')
    elif defect == 'missing file':
        source.unlink()
    elif defect == 'absolute path':
        e['path'] = str(source)
    elif defect in ('parent escape', 'symlink escape'):
        outside = workspace['root'].parent / 'outside.txt'
        outside.write_bytes(source.read_bytes())
        if defect == 'parent escape':
            e['path'] = '../outside.txt'
        else:
            source.unlink()
            source.symlink_to(outside)
    elif defect == 'directory':
        source.unlink()
        source.mkdir()
    elif defect == 'oversized file':
        source.write_bytes(b'a' * (HELPER.LIMIT + 1))
    elif defect == 'out of range lines':
        e['lines'] = [1, 99]
    elif defect == 'malformed line range':
        e['lines'] = [True, 'two']
    elif defect == 'null line bounds':
        e['lines'] = [None, None]
    elif defect == 'duplicate id':
        r['evidence'].append(copy.deepcopy(e))
    elif defect == 'unknown reference':
        r['scope']['evidence'] = ['missing']
    elif defect == 'invalid status':
        r['conclusion'] = 'proven-safe'
    elif defect == 'non-object report':
        workspace['report'] = []
    elif defect == 'malformed json':
        workspace['raw'] = '{ invalid json'
    elif defect == 'missing limitations':
        r['limitations'] = []
    elif defect == 'no path':
        r['paths'] = []
    elif defect == 'disconnected path':
        r['paths'][0]['edges'][0]['caller'] = 'another'
    elif defect == 'wrong sink':
        r['paths'][0]['sink'] = 'another'
    elif defect == 'unresolved dispatch':
        r['paths'][0]['edges'][0]['resolved'] = False
    elif defect == 'no parameters':
        r['parameters'] = []
    elif defect == 'missing guard analysis':
        del r['parameters'][0]['guards']
    elif defect == 'no review':
        r['review']['reviewer'] = ''
    elif defect == 'no scope evidence':
        r['scope']['evidence'] = []
    elif defect == 'negative without proof':
        r['conclusion'] = 'not_reachable'
        r['negative_argument'] = {'summary': 'no scan hits', 'evidence': []}
    elif defect == 'parameter sink mismatch':
        r['parameters'][0]['sink'] = 'different'
    elif defect == 'trigger without evidence':
        r['conclusion'] = 'unresolved'
        r['trigger'] = 'blocked'
        r['preconditions']['evidence'] = []
    elif defect == 'impact without review':
        r['conclusion'] = 'unresolved'
        r['impact'] = 'observed'
        r['review']['evidence'] = []
    elif defect == 'unevidenced execution':
        r['tools'][0]['status'] = 'executed'
    else:
        raise AssertionError('unhandled defect ' + defect)


@when('I check the report through the CLI')
def checked(workspace):
    workspace['report_path'].write_text(workspace.get('raw', json.dumps(workspace['report'])))
    workspace['result'] = cli('check', workspace['report_path'], '--evidence-root', workspace['root'])


@then('only structure and integrity are reported as checked')
def passed(workspace):
    result = workspace['result']
    assert result.returncode == 0, result.stderr
    assert 'structure and evidence integrity only' in result.stdout
    assert 'Reachability, semantic correctness, tool capability, and coverage are NOT validated' in result.stdout


@then('the check fails without a traceback')
def failed(workspace):
    result = workspace['result']
    assert result.returncode == 1
    assert 'ERROR:' in result.stderr
    assert 'Traceback' not in result.stderr
    assert 'PASS:' not in result.stdout


@then('the manifests and workflow assets resolve consistently')
def packaging():
    manifest = json.loads((PACKAGE / 'plugin.json').read_text())
    host_manifest = json.loads((PACKAGE / '.claude-plugin/plugin.json').read_text())
    assert manifest['name'] == host_manifest['name'] == 'security-logging-advisor'
    assert manifest['version'] == host_manifest['version']
    agent_path = PACKAGE / 'agents/cve-reachability.agent.md'
    host_agent = PACKAGE / 'com.github.copilot/agents/cve-reachability.agent.md'
    host_command = PACKAGE / 'com.github.copilot/commands/cve-reachability.md'
    assert host_agent.read_text() == agent_path.read_text().replace('../skills/', '../../skills/')
    assert host_command.read_text() == (PACKAGE / 'commands/cve-reachability.md').read_text()
    files = [agent_path, host_agent, host_command, PACKAGE / 'commands/cve-reachability.md', SKILL / 'SKILL.md',
             *sorted((SKILL / 'references').glob('*.md'))]
    for file in files:
        assert file.is_file()
        for link in re.findall(r'\]\(([^)]+)\)', file.read_text()):
            if not link.startswith('https://'):
                assert (file.parent / link).is_file(), (file, link)
    skill_text = (SKILL / 'SKILL.md').read_text()
    frontmatter = skill_text.split('---', 2)[1]
    assert set(re.findall(r'^(\w+):', frontmatter, re.M)) == {'name', 'description'}
    assert len(skill_text.splitlines()) < 500
    names = [re.search(r'^name: (.+)$', p.read_text(), re.M).group(1)
             for p in (PACKAGE / 'skills').glob('*/SKILL.md')]
    assert len(names) == len(set(names))
    assert 'tools:' not in agent_path.read_text().split('---', 2)[1]
    # Acceptance criterion -> executable Gherkin scenario parity, not behavior proof.
    spec = (ROOT / 'specs/cve-reachability.spec.md').read_text()
    feature = (ROOT / 'specs/features/cve_reachability.feature').read_text()
    for name in re.findall(r'Scenario(?: outline)?: ([^.]+)\.', spec):
        assert re.search(r'Scenario(?: Outline)?: ' + re.escape(name) + r'\n', feature)


@pytest.mark.parametrize('location', ['existing', 'inside', 'missing_repo'])
def test_init_preserves_existing_files(tmp_path, location):
    repo = tmp_path / 'repo'
    repo.mkdir()
    output = tmp_path / 'report.json'
    if location == 'existing':
        output.write_text('retain me')
    elif location == 'inside':
        output = repo / 'report.json'
    else:
        repo = tmp_path / 'absent'
    result = cli('init', '--repository', repo, '--cve', '[CVE]', '--component', 'fixture', '--output', output)
    assert result.returncode == 1
    assert 'Traceback' not in result.stderr
    if location == 'existing':
        assert output.read_text() == 'retain me'
    else:
        assert not output.exists()


@pytest.mark.parametrize('args', [[], ['--start', '1'], ['--start', '0', '--end', '2']])
def test_evidence_line_options(tmp_path, args):
    (tmp_path / 'source').write_text('one\ntwo\n')
    result = cli('evidence', '--root', tmp_path, '--file', 'source', '--id', 'E', *args)
    assert result.returncode == (0 if not args else 1)


@pytest.mark.parametrize('status', HELPER.STATUSES)
def test_supported_statuses_remain_structural(tmp_path, status):
    state = workspace(tmp_path)
    populated(state)
    state['report']['conclusion'] = status
    state['report']['tools'] = [{'name': 'synthetic fixture', 'status': 'executed',
        'version': 'fixture', 'command': 'fixture', 'exit_code': 1,
        'coverage': 'none', 'interpretation': 'failed fixture, no capability proven',
        'evidence': ['E1']}]
    checked(state)
    passed(state)
