"""Offline cross-source leads from validated, tenant-bound evidence envelopes."""
from collections import defaultdict
from hashlib import sha256
import re

from cops.evidence import EvidenceError, validate_envelope, validate_receipt

GUID = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
KEY_FIELDS = {
    'm365-signins': ('userId', 'appId'),
    'm365-directory-audits': ('actorUserId',),
    'm365-service-principals': ('appId',),
    'm365-oauth2-permission-grants': ('principalId', 'clientId'),
    'm365-security-alerts': ('userId', 'appId'),
    'm365-mail-messages': ('userId',),
    'm365-auth-methods': ('userId',),
    'm365-conditional-access': (),
    'm365-security-incidents': (),
    'm365-purview-cases': (),
    'm365-sharepoint-sites': (),
    'm365-teams-chats': (),
}
KEY_KIND = {
    'userId': 'user',
    'actorUserId': 'user',
    'principalId': 'user',
    'appId': 'application',
    'clientId': 'application',
}


def correlate(sources):
    """Emit lead IDs and coverage, never raw IDs or a maliciousness verdict.

    `sources` maps a source name to a Result-like (records, receipt) pair.
    A shared IP does not establish identity; only explicit GUID fields join.
    """
    if not isinstance(sources, dict) or len(sources) > 32:
        raise EvidenceError('invalid_scope')
    tenants, coverage, keyed = set(), {}, defaultdict(lambda: defaultdict(set))
    for source, pair in sorted(sources.items()):
        if source not in KEY_FIELDS or not isinstance(pair, tuple) or len(pair) != 2:
            raise EvidenceError('invalid_scope')
        records, receipt = pair
        validate_receipt(receipt)
        if not isinstance(records, list) or len(records) > 10000:
            raise EvidenceError('record_limit')
        coverage[source] = {'status': receipt['status'], 'reasons': receipt['reasons'],
                            'records': len(records)}
        tenants.add(receipt['tenant'])
        for record in records:
            validate_envelope(record)
            if (record['source']['tenant'] != receipt['tenant']
                    or record['source']['api'] != 'v1.0/' + source.removeprefix('m365-')):
                raise EvidenceError('invalid_scope')
            payload = record['payload']
            for field in KEY_FIELDS[source]:
                value = payload.get(field)
                if value is None:
                    continue
                if not isinstance(value, str) or not GUID.fullmatch(value):
                    raise EvidenceError('schema_drift')
                digest = sha256((receipt['tenant'] + ':' + KEY_KIND[field] + ':' + value.lower()).encode()).hexdigest()
                keyed[digest][source].add(record['record_id'])
    if len(tenants) > 1:
        raise EvidenceError('invalid_scope')
    leads = []
    for entity, by_source in sorted(keyed.items()):
        if len(by_source) > 1:
            leads.append({'entity_key': entity, 'sources': sorted(by_source),
                          'record_ids': {name: sorted(ids) for name, ids in sorted(by_source.items())}})
    return {'schema_version': 'cops.m365-correlation/v1', 'tenant': next(iter(tenants), None),
            'coverage': coverage, 'leads': leads, 'assessment': 'analyst_review_required'}
