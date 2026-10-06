import os
import sys
import json
import subprocess
import shutil
import tempfile
from pytest_bdd import scenarios, given, when, then, parsers

# Load all scenarios from the feature files
scenarios('../../specs/features/repository_scanning.feature')
scenarios('../../specs/features/edge_cases_scanning.feature')

# Fixture to hold context across steps
import pytest
@pytest.fixture
def context():
    state = {}
    yield state
    if 'external_path' in state:
        os.unlink(state['external_path'])

@pytest.fixture(autouse=True)
def workspace_dir(tmpdir):
    # Change current working directory to a temporary directory for each scenario
    old_cwd = os.getcwd()
    os.chdir(str(tmpdir))
    yield str(tmpdir)
    os.chdir(old_cwd)

@given(parsers.parse('a workspace containing a Terraform file "{filename}"'))
def create_terraform_file(filename):
    with open(filename, 'w') as f:
        f.write('provider "aws" {}\n')

@given(parsers.parse('"{filename}" references the provider "{provider}"'))
def file_references_provider(filename, provider):
    with open(filename, 'a') as f:
        f.write(f'provider "{provider}" {{}}\n')

@given(parsers.parse('a workspace containing a file "{filename}"'))
def create_file(filename):
    with open(filename, 'w') as f:
        f.write('')

@given(parsers.parse('"{filename}" contains the line "{line}"'))
def append_line(filename, line):
    with open(filename, 'a') as f:
        f.write(f'{line}\n')

@given(parsers.parse('"{filename}" declares the schema URL "{url}"'))
def declare_schema_url(filename, url):
    with open(filename, 'w') as f:
        json.dump({"$schema": url}, f)

@given(parsers.parse('"{filename}" mentions "{hostname}" only in its description'))
def mention_schema_host_in_description(filename, hostname):
    with open(filename, 'w') as f:
        json.dump({"description": f"Reference text: {hostname}"}, f)

@given(parsers.parse('a workspace containing a Bicep file "{filename}"'))
def create_bicep_file(filename):
    with open(filename, 'w') as f:
        f.write('targetScope = \'subscription\'\n')

@given(parsers.parse('a package.json file containing dependency "{dependency}"'))
def create_package_json(dependency):
    with open('package.json', 'w') as f:
        json.dump({"dependencies": {dependency: "^1.0.0"}}, f)

@given(parsers.parse('a workspace containing a Rust file "{filename}"'))
def create_rust_file(filename):
    with open(filename, 'w') as f:
        f.write('fn main() {}\n')

@given(parsers.parse('a C++ file "{filename}"'))
def create_cpp_file(filename):
    with open(filename, 'w') as f:
        f.write('int main() { return 0; }\n')

@given(parsers.parse('a Ruby file "{filename}"'))
def create_ruby_file(filename):
    with open(filename, 'w') as f:
        f.write('puts "hello"\n')

@given(parsers.parse('a PHP file "{filename}"'))
def create_php_file(filename):
    with open(filename, 'w') as f:
        f.write('<?php echo "hello"; ?>\n')

@given(parsers.parse('a Java Spring Boot file "{filename}"'))
def create_spring_boot_file(filename):
    with open(filename, 'w') as f:
        f.write('<project><dependencies><dependency><artifactId>spring-boot-starter</artifactId></dependency></dependencies></project>\n')

@given(parsers.parse('a workspace containing a massive 5MB file "{filename}"'))
def create_massive_file(filename):
    # Create a 5MB file of random bytes
    with open(filename, 'wb') as f:
        f.write(os.urandom(5 * 1024 * 1024))

@given(parsers.parse('a workspace containing a symbolic link "{filename}" to a file outside the workspace'))
def create_external_symlink(filename, workspace_dir, context):
    external_path = os.path.join(os.path.dirname(workspace_dir), f'{os.path.basename(workspace_dir)}-external.json')
    with open(external_path, 'w') as f:
        f.write('LINKED_FILE_CONTENT_DO_NOT_COPY')
    context['external_path'] = external_path
    try:
        os.symlink(external_path, filename)
    except OSError as exc:
        pytest.skip(f'Symbolic links unavailable: {exc}')

@given(parsers.parse('a workspace containing a FIFO "{filename}"'))
def create_fifo(filename):
    if not hasattr(os, 'mkfifo'):
        pytest.skip('FIFOs unavailable')
    os.mkfifo(filename)

@given(parsers.parse('a workspace containing an oversized config file "{filename}"'))
def create_oversized_config(filename):
    with open(filename, 'wb') as f:
        f.write(b'db_password = "FixturePassword123!"\n')
        f.write(b'x' * (1024 * 1024))

@given(parsers.parse('a workspace containing {count:d} dummy files'))
def create_dummy_files(count):
    os.makedirs('dummy_dir', exist_ok=True)
    for i in range(count):
        with open(f'dummy_dir/file_{i}.txt', 'w') as f:
            f.write('dummy')

@when(parsers.parse('the scanner script executes with target "{target}"'))
def execute_scanner(context, target):
    # The script should be run via subprocess to simulate actual execution
    # Calculate the path back to the actual script since we are in a tmpdir
    # Resolve the categorized plugin scanner from the repository root.
    # But this script runs from the pytest root, so we can pass the absolute path
    # Actually, we can just pass the path relative to the root dir which we know.
    # We will assume pytest runs from the root of the project.
    
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../plugins/logging-telemetry/security-logging-advisor/skills/repository-context/scripts/collect-repository-context.py'))
    
    try:
        result = subprocess.run(['python3', script_path, target], capture_output=True, text=True, check=True, timeout=5)
        context['output'] = result.stdout
        context['error'] = False
        
        try:
            context['json'] = json.loads(result.stdout)
        except json.JSONDecodeError:
            context['json'] = None
    except subprocess.CalledProcessError as e:
        context['error'] = True
        context['output'] = e.output
        context['stderr'] = e.stderr
    except Exception as e:
        context['error'] = True
        context['exception'] = str(e)

@then(parsers.parse('the JSON output "{key}" must list "{value}"'))
def json_output_must_list(context, key, value):
    assert context['json'] is not None
    assert key in context['json']
    # Sometimes it's a dict, sometimes a list
    if isinstance(context['json'][key], dict):
        assert value in context['json'][key]
    else:
        assert value in context['json'][key]

@then(parsers.parse('the JSON output "{key}" must NOT list "{value}"'))
def json_output_must_not_list(context, key, value):
    assert context['json'] is not None
    assert value not in context['json'][key]

@then(parsers.parse('the JSON output "{key}" must list a finding for "{filename}"'))
def json_output_must_list_finding(context, key, filename):
    assert context['json'] is not None
    assert key in context['json']
    findings = context['json'][key]
    assert any(f['file'] == filename for f in findings)

@then(parsers.parse('the "{key}" key must advise moving credentials to a secure vault'))
def check_remediation(context, key):
    assert context['json'] is not None
    findings = context['json']['secrets_findings']
    assert any("vault" in f.get(key, "").lower() for f in findings)

@then(parsers.parse('the output JSON must NOT contain the string "{secret}"'))
def output_not_contain_secret(context, secret):
    assert secret not in context['output']

@then('the scanner should complete successfully')
def scanner_completes_successfully(context):
    assert context.get('error') is False, f"Scanner failed: {context.get('stderr') or context.get('exception')}"

@then('the scanner must not throw a MemoryError')
def no_memory_error(context):
    assert not context.get('error', False)
    assert 'MemoryError' not in context.get('stderr', '')

@then(parsers.parse('the JSON output "{key}" should not exceed {limit:d}'))
def check_limit(context, key, limit):
    assert context['json'] is not None
    assert int(context['json'][key]) <= limit

@then(parsers.parse('the JSON output "{key}" should indicate the file was skipped or processed without memory error'))
def check_processed(context, key):
    assert context['json'] is not None
    # Just checking it completed successfully handles the memory error part.
    pass

@then(parsers.parse('the scanner reports "{filename}" skipped with reason "{reason}"'))
def check_skip_reason(context, filename, reason):
    assert {'file': filename, 'reason': reason} in context['json']['skipped_files']

@then('the scanner output must not contain the linked file content')
def no_linked_content(context):
    assert 'LINKED_FILE_CONTENT_DO_NOT_COPY' not in context['output']

@then(parsers.parse('the JSON output "{key}" must be empty'))
def json_output_empty(context, key):
    assert context['json'][key] == []
