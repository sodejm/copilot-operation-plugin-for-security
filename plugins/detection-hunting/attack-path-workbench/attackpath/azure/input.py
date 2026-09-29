"""Bounded descriptor-based bundle ingestion with validated SDK provenance."""
import hashlib
import os
from pathlib import Path
import re
import stat
from .._runtime.cops.evidence import assess, validate_receipt
from .._runtime.cops.evidence.canonical import decode_json, digest, EvidenceError
from .model import AzureError, Budget, Graph, arm, object_id, absolute_parts
from .normalize import FAMILIES, normalize


def read_regular(root, relative, limit):
    if (not isinstance(relative, str) or not relative or len(relative) > 2048
            or relative.startswith('/') or '\\' in relative or any(ord(c) < 32 for c in relative)
            or any(p in ('', '.', '..') for p in relative.split('/'))):
        raise AzureError('unsafe_path')
    if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        # Conservative fallback: refusing this platform is safer than a race-prone lstat/open.
        raise AzureError('safe_reader_unavailable')
    descriptors = []
    try:
        descriptors.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY))
        parts = absolute_parts(root) + relative.split('/')
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index != len(parts) - 1:
                flags |= os.O_DIRECTORY
            descriptors.append(os.open(part, flags, dir_fd=descriptors[-1]))
        fd = descriptors[-1]
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise AzureError('nonregular_file')
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise AzureError('file_limit')
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise AzureError('file_changed')
        return b''.join(chunks)
    except OSError:
        raise AzureError('unsafe_file') from None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def json_value(raw, limit):
    try:
        return decode_json(raw, max_bytes=limit, max_depth=32)
    except EvidenceError:
        raise AzureError('invalid_json') from None


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


def load(manifest, as_of):
    manifest = Path(manifest).absolute()
    manifest_bytes = read_regular(manifest.parent, manifest.name, 262144)
    data = json_value(manifest_bytes, 262144)
    fields(data, ('schema_version', 'sources', 'scenario'), ('limits',))
    if data['schema_version'] != 'attackpath.azure.input/v1' or not isinstance(data['sources'], list):
        raise AzureError('invalid_manifest')
    graph = Graph(as_of, data.get('limits'))
    scenario_contract(data['scenario'])
    graph.scenario = data['scenario']
    if len(data['sources']) * 2 + 1 > graph.limits['files']:
        raise AzureError('file_count_limit')
    seen, total, records = set(), len(manifest_bytes), 0
    item_count = 0
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
        receipt_bytes = read_regular(manifest.parent, source['receipt'], 65536)
        raw = read_regular(manifest.parent, source['path'], graph.limits['file_bytes'])
        total += len(receipt_bytes) + len(raw)
        if total > graph.limits['total_bytes']:
            raise AzureError('total_byte_limit')
        for content, key in ((raw, 'sha256'), (receipt_bytes, 'receipt_sha256')):
            if not isinstance(source[key], str) or not re.fullmatch('[0-9a-f]{64}', source[key]) or hashlib.sha256(content).hexdigest() != source[key]:
                raise AzureError('integrity_mismatch')
        receipt = json_value(receipt_bytes, 65536)
        try:
            validate_receipt(receipt)
        except EvidenceError:
            raise AzureError('invalid_receipt') from None
        lines = raw.splitlines()
        if receipt['consumed']['pages'] != len(lines) or receipt['consumed']['records'] != len(lines):
            raise AzureError('receipt_count_mismatch')
        complete = receipt['status'] == 'complete'
        source_refs = set()
        pages = []
        for line in lines:
            if not line.strip():
                raise AzureError('empty_record')
            records += 1
            if records > graph.limits['records']:
                raise AzureError('record_limit')
            envelope = json_value(line, 1048576)
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
            item_count += len(payload['value'])
            if item_count > graph.limits['records']:
                raise AzureError('record_limit')
            continuation = payload.get('@odata.nextLink', payload.get('nextLink'))
            if bool(continuation) != (len(pages) < len(lines)):
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
        if not complete:
            for row in graph.objects:
                if set(row.evidence) & source_refs:
                    row.quality = sorted(set(row.quality + ['incomplete_source']))
        # Graph v1 members omit service principals; never certify total absence.
        if source['family'] == 'group_members':
            complete = False
        graph.cover(source['family'], source['tenant'], source['scopes'], complete and bool(raw), sorted(source_refs))
    return graph
