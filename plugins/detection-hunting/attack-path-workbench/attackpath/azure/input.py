"""Bounded descriptor-based bundle ingestion with validated SDK provenance."""
import hashlib
import re
from pathlib import Path

from .._runtime.cops.evidence import assess, validate_receipt
from .._runtime.cops.evidence.canonical import EvidenceError, digest
from ..ingestion import DEFAULTS as INGEST_DEFAULTS
from ..ingestion import IngestError, Limits, RunBudget, iter_jsonl, parse_json
from ..ingestion import read_regular as bounded_read
from .model import AzureError, Budget, Graph, arm, object_id
from .normalize import FAMILIES, normalize


def read_regular(root, relative, limit, budget=None):
    try:
        return bounded_read(root, relative, limit, budget).data
    except IngestError as exc:
        raise AzureError(str(exc)) from None


def json_value(raw, limit, policy=None, record_cap=None, record_path=('records',)):
    try:
        return parse_json(raw, policy or Limits(), max_bytes=limit, record_cap=record_cap,
                          record_path=record_path)
    except IngestError as exc:
        raise AzureError(str(exc)) from None


def fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or set(value) - set(required) - set(optional):
        raise AzureError('invalid_contract')


def scenario_contract(scenario):
    fields(scenario, ('controlled', 'targets'), ('runtime', 'activations', 'assertions', 'pseudonymize', 'business_impact', 'owner_credential_rights', 'credential_restrictions'))
    if not isinstance(scenario['controlled'], list) or not isinstance(scenario['targets'], list):
        raise AzureError('invalid_scenario')
    for item in scenario['controlled']:
        fields(item, ('tenant', 'id'))
        if not all(isinstance(item[k], str) and 0 < len(item[k]) <= 256 for k in item):
            raise AzureError('invalid_scenario')
        object_id(item['tenant'], item['id'])
    for target in scenario['targets']:
        fields(target, ('tenant', 'scope', 'action', 'plane'))
        target['scope'] = arm(target['scope'])
        if not isinstance(target['tenant'], str) or not 0 < len(target['tenant']) <= 256 or not target['action']:
            raise AzureError('invalid_scenario')
        if target['plane'] not in ('control', 'data') or not isinstance(target['action'], str) or len(target['action']) > 512:
            raise AzureError('invalid_scenario')
        object_id(target['tenant'], target['scope'])
        if any(ord(c) < 32 for c in target['action']):
            raise AzureError('invalid_scenario')
    runtime = scenario.get('runtime', {})
    if not isinstance(runtime, dict):
        raise AzureError('invalid_scenario')
    allowed = {'vm_agent', 'token_endpoint', 'network', 'invocation', 'identity_action', 'automation_sandbox', 'function_deployment', 'logic_consumption'}
    for key, item in runtime.items():
        arm(key)
        if not isinstance(item, dict) or set(item) - allowed or any(type(v) is not bool for v in item.values()):
            raise AzureError('invalid_runtime_assumption')
    for name in ('assertions', 'owner_credential_rights', 'credential_restrictions'):
        if not isinstance(scenario.get(name, []), list):
            raise AzureError('invalid_scenario')
    for item in scenario.get('credential_restrictions', []):
        fields(item, ('tenant', 'object', 'credential_update_allowed'))
        if type(item['credential_update_allowed']) is not bool or any(not isinstance(item[k], str) or not item[k] or len(item[k]) > 256 for k in ('tenant', 'object')):
            raise AzureError('invalid_credential_restriction')
        object_id(item['tenant'], item['object'])
    scenario['runtime'] = {arm(k): v for k, v in runtime.items()}
    for assertion in scenario.get('assertions', []):
        fields(assertion, ('issuer', 'subject', 'audience', 'controlled'))
        if type(assertion['controlled']) is not bool or not all(isinstance(assertion[k], str) and len(assertion[k]) <= 2048 for k in ('issuer', 'subject', 'audience')):
            raise AzureError('invalid_assertion')
    activations = scenario.get('activations', {})
    if not isinstance(activations, dict):
        raise AzureError('invalid_activation')
    for key, item in activations.items():
        fields(item, ('duration_minutes',), ('approval', 'mfa', 'authentication_context'))
        if not isinstance(key, str) or not 0 < len(key) <= 2048 or any(ord(c) < 32 for c in key) or type(item['duration_minutes']) is not int or not 0 < item['duration_minutes'] <= 1440 or any(type(v) is not bool for k, v in item.items() if k != 'duration_minutes'):
            raise AzureError('invalid_activation')
    for item in scenario.get('owner_credential_rights', []):
        fields(item, ('tenant', 'principal', 'object'))
        if any(not isinstance(v, str) or not v or len(v) > 256 for v in item.values()):
            raise AzureError('invalid_owner_assumption')
        object_id(item['tenant'], item['principal'])
        object_id(item['tenant'], item['object'])
    impact = scenario.get('business_impact', {})
    if not isinstance(impact, dict):
        raise AzureError('invalid_business_impact')
    for key, value in impact.items():
        arm(key)
        if not isinstance(value, str) or len(value) > 256:
            raise AzureError('invalid_business_impact')
    scenario['business_impact'] = {arm(k): v for k, v in impact.items()}
    if type(scenario.get('pseudonymize', False)) is not bool:
        raise AzureError('invalid_scenario')


def load(manifest, as_of, cli_limits=None):
    try:
        return _load(manifest, as_of, cli_limits)
    except IngestError as exc:
        raise AzureError(str(exc)) from None


def _load(manifest, as_of, cli_limits):
    # Validate explicit limits before touching the manifest.
    provisional = Limits.from_values(cli_limits)
    manifest = Path(manifest).absolute()
    provisional_budget = RunBudget(provisional)
    manifest_bytes = read_regular(manifest.parent, manifest.name, min(262144, provisional.file_bytes), provisional_budget)
    data = json_value(manifest_bytes, 262144, provisional)
    fields(data, ('schema_version', 'sources', 'scenario'), ('limits',))
    if data['schema_version'] != 'attackpath.azure.input/v1' or not isinstance(data['sources'], list):
        raise AzureError('invalid_manifest')
    graph = Graph(as_of, data.get('limits'))
    effective = Limits.from_values({key: value for key, value in graph.limits.items()
                                    if key in INGEST_DEFAULTS}, ceiling_values=cli_limits)
    graph.limits.update(effective.export())
    budget = RunBudget(effective, bytes=len(manifest_bytes), files=1)
    if budget.bytes > effective.file_bytes:
        raise AzureError('file_limit')
    if budget.bytes > effective.total_bytes:
        raise AzureError('total_byte_limit')
    scenario_contract(data['scenario'])
    graph.scenario = data['scenario']
    if len(data['sources']) * 2 + 1 > graph.limits['files']:
        raise AzureError('file_count_limit')
    seen = set()
    for source in data['sources']:
        fields(source, ('id', 'family', 'api', 'tenant', 'scopes', 'path', 'sha256', 'receipt', 'receipt_sha256', 'max_age_seconds'), ('context',))
        if not all(isinstance(source[k], str) and 0 < len(source[k]) <= 256 for k in ('id', 'family', 'api', 'tenant')) or not isinstance(source.get('context', {}), dict):
            raise AzureError('invalid_source')
        if source['family'] not in FAMILIES or source['id'] in seen:
            raise AzureError('unsupported_or_duplicate_source')
        seen.add(source['id'])
        if type(source['max_age_seconds']) is not int or not 0 < source['max_age_seconds'] <= 31536000:
            raise AzureError('invalid_max_age')
        if not isinstance(source['scopes'], list) or not source['scopes'] or any(not isinstance(s, str) for s in source['scopes']):
            raise AzureError('invalid_scopes')
        for scope in source['scopes']:
            arm(scope)
        context = source.get('context', {})
        required_context = {'groupId'} if source['family'] == 'group_members' else {'objectId'} if source['family'] in ('owners', 'administrative_members', 'federated_credentials') else set()
        if set(context) != required_context:
            raise AzureError('invalid_source_context')
        for value in context.values():
            object_id(source['tenant'], value)
        object_id(source['tenant'], source['id'])
        from .collection import source_contract
        product = source_contract(source['family'], source['api'])
        if source['family'] == 'group_members' and (not isinstance(context.get('groupId'), str) or not context['groupId']):
            raise AzureError('missing_group_context')
        if source['family'] in ('owners', 'administrative_members', 'federated_credentials') and (not isinstance(context.get('objectId'), str) or not context['objectId']):
            raise AzureError('missing_object_context')
        receipt_bytes = read_regular(manifest.parent, source['receipt'], min(65536, effective.file_bytes), budget)
        raw = read_regular(manifest.parent, source['path'], effective.file_bytes, budget)
        for content, key in ((raw, 'sha256'), (receipt_bytes, 'receipt_sha256')):
            if not isinstance(source[key], str) or not re.fullmatch('[0-9a-f]{64}', source[key]) or hashlib.sha256(content).hexdigest() != source[key]:
                raise AzureError('integrity_mismatch')
        receipt = json_value(receipt_bytes, 65536, effective)
        try:
            validate_receipt(receipt)
        except EvidenceError:
            raise AzureError('invalid_receipt') from None
        complete = receipt['status'] == 'complete'
        source_refs = set()
        pages = []
        for line in iter_jsonl(raw, effective, budget):
            if not line.strip():
                raise AzureError('empty_record')
            budget.add_records()
            envelope = json_value(line, effective.line_bytes, effective,
                                  record_cap=effective.records - budget.records,
                                  record_path=('payload', 'value'))
            try:
                quality = assess(envelope, receipt, as_of=as_of, max_age_seconds=source['max_age_seconds'])
            except ValueError:
                raise AzureError('invalid_evidence') from None
            pages.append(envelope['page'])
            if envelope['page'] != len(pages):
                raise AzureError('page_sequence_mismatch')
            payload = envelope['payload']
            if not isinstance(payload, dict) or not isinstance(payload.get('value'), list):
                raise AzureError('unsupported_page_shape')
            budget.add_records(len(payload['value']))
            continuation = payload.get('@odata.nextLink', payload.get('nextLink'))
            if bool(continuation) != (len(pages) < receipt['consumed']['pages']):
                complete = False
            es = envelope['source']
            if es['product'] != product or es['tenant'] != source['tenant'] or es['scope'] != sorted(set(source['scopes'])) or es['api'] != source['api']:
                raise AzureError('source_mismatch')
            reasons = []
            if quality['freshness'] != 'fresh':
                reasons.append('observation_' + quality['freshness'])
            if quality['completeness'] != 'complete':
                reasons.append('acquisition_' + quality['completeness'])
            if envelope['observed'].get('redacted') or envelope.get('redactions'):
                reasons.append('redacted_evidence')
            source_refs.add(envelope['record_id'])
            graph.ledger.append({'record_id': envelope['record_id'], 'source_id': source['id'],
                'payload_sha256': digest(envelope['payload']), 'content_hash': envelope['content_hash'], 'file_sha256': source['sha256'], 'receipt_sha256': source['receipt_sha256'], 'observed_at': envelope['observed']['at'],
                'quality': reasons, 'acquisition_id': receipt['acquisition_id']})
            try:
                complete = normalize(graph, source, envelope, reasons) and complete
            except Budget as exc:
                graph.partial.append(str(exc))
                complete = False
        if receipt['consumed']['pages'] != len(pages) or receipt['consumed']['records'] != len(pages):
            raise AzureError('receipt_count_mismatch')
        if not complete:
            for row in graph.objects:
                if set(row.evidence) & source_refs:
                    row.quality = sorted(set(row.quality + ['incomplete_source']))
        # Graph v1 members omit service principals; never certify total absence.
        if source['family'] == 'group_members':
            complete = False
        graph.cover(source['family'], source['tenant'], source['scopes'], complete and bool(raw), sorted(source_refs))
    graph.ingestion = budget.receipt()
    return graph
