"""Bounded read-only lookups; provider claims are never combined into a verdict."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

from cops.connectors.interfaces import Request
from cops.connectors.transport import HttpsTransport
from cops.evidence import EvidenceError

KINDS = {'ip', 'domain', 'url', 'hash', 'certificate', 'email', 'azure_application_id'}
MISP_TYPES = {'ip': 'ip-src', 'domain': 'domain', 'url': 'url', 'hash': 'sha256',
              'certificate': 'x509-fingerprint-sha256', 'email': 'email-src'}
STIX_TYPES = {'ip': 'ipv4-addr', 'domain': 'domain-name', 'url': 'url', 'hash': 'file',
              'certificate': 'x509-certificate', 'email': 'email-addr'}
MAX_BODY = 1_048_576


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str = field(repr=False)

    def __post_init__(self):
        if self.kind not in KINDS or not isinstance(self.value, str) or not 1 <= len(self.value) <= 2048:
            raise ValueError('invalid_indicator')
        value = self.value
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('invalid_indicator')
        try:
            if self.kind == 'ip':
                ipaddress.ip_address(value)
            elif self.kind == 'domain':
                if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', value):
                    raise ValueError
            elif self.kind == 'url':
                part = urlsplit(value)
                if part.scheme not in ('http', 'https') or not part.hostname or part.username or part.password or part.fragment or part.port not in (None, 80, 443):
                    raise ValueError
            elif self.kind in ('hash', 'certificate'):
                if not re.fullmatch(r'[a-fA-F0-9]{64}', value):
                    raise ValueError
            elif self.kind == 'email':
                if not re.fullmatch(r'[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}', value):
                    raise ValueError
            elif self.kind == 'azure_application_id':
                if not re.fullmatch(r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', value):
                    raise ValueError
        except ValueError:
            raise ValueError('invalid_indicator') from None

    @property
    def digest(self):
        return hashlib.sha256(f'{self.kind}\0{self.value}'.encode()).hexdigest()

    @property
    def sensitive(self):
        if self.kind in ('email', 'azure_application_id'):
            return True
        if self.kind == 'url':
            part = urlsplit(self.value)
            return bool(part.path and part.path != '/' or part.query)
        return False


@dataclass(frozen=True)
class Approval:
    source: str
    indicator_digest: str
    allow_sensitive: bool = False


@dataclass(frozen=True)
class Source:
    name: str
    origin: str
    path: str
    token: str = field(repr=False)

    def __post_init__(self):
        if self.name not in ('misp', 'taxii', 'microsoft'):
            raise ValueError('invalid_source')
        if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', self.origin) or self.origin.startswith('.') or '..' in self.origin:
            raise ValueError('invalid_source')
        if not self.path.startswith('/') or '?' in self.path or '#' in self.path or '..' in self.path.split('/') or len(self.path) > 512:
            raise ValueError('invalid_source')
        if self.name == 'microsoft' and (self.origin != 'graph.microsoft.com' or self.path not in ('/v1.0/security/threatIntelligence/hosts', '/v1.0/servicePrincipals')):
            raise ValueError('invalid_source')
        if self.name == 'misp' and self.path != '/attributes/restSearch':
            raise ValueError('invalid_source')
        if self.name == 'taxii' and not re.fullmatch(r'/taxii2/collections/[A-Za-z0-9_-]{1,128}/objects/', self.path):
            raise ValueError('invalid_source')
        if not isinstance(self.token, str) or not self.token:
            raise ValueError('invalid_source')


class Cache:
    def __init__(self, positive_ttl=3600, negative_ttl=300):
        if not all(type(v) is int and 1 <= v <= 86400 for v in (positive_ttl, negative_ttl)):
            raise ValueError('invalid_cache_ttl')
        self.positive_ttl, self.negative_ttl = positive_ttl, negative_ttl
        self.entries = {}

    def get(self, key, now, allow_stale=False):
        item = self.entries.get(key)
        if item is None:
            return None
        result, expiry = item
        if now >= expiry and not allow_stale:
            return None
        return {**result, 'cache': 'stale' if now >= expiry else 'fresh'}

    def put(self, key, result, now):
        if result['status'] not in ('positive', 'negative'):
            return
        ttl = self.positive_ttl if result['status'] == 'positive' else self.negative_ttl
        self.entries[key] = ({**result, 'expires_at': _stamp(now + ttl)}, now + ttl)


def _stamp(seconds):
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace('+00:00', 'Z')


def _time(value):
    if type(value) in (int, float) or isinstance(value, str) and value.isdecimal():
        try:
            return _stamp(float(value))
        except (ValueError, OverflowError):
            return None
    if isinstance(value, str) and len(value) <= 40:
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                return None
            return parsed.astimezone(UTC).isoformat().replace('+00:00', 'Z')
        except ValueError:
            pass
    return None


def _claim(source, assertion, observed, confidence=None, expiry=None, locator=None):
    return {'source': source, 'assertion': assertion, 'observed_at': _time(observed),
            'confidence': confidence if type(confidence) in (int, float) and 0 <= confidence <= 100 else None,
            'expires_at': _time(expiry), 'provenance': locator}


def normalize(source, indicator, data):
    """Return only claims matching the selected indicator, with bounded cardinality."""
    if not isinstance(data, dict):
        raise ValueError('schema_drift')
    claims = []
    if source == 'misp':
        rows = data.get('Attribute', data.get('response', {}).get('Attribute', []))
        if not isinstance(rows, list):
            raise ValueError('schema_drift')
        for row in rows[:1000]:
            if not isinstance(row, dict) or row.get('value') != indicator.value:
                continue
            if row.get('type') != MISP_TYPES.get(indicator.kind):
                continue
            claims.append(_claim('misp', 'malicious' if row.get('to_ids') is True else 'context', row.get('timestamp'),
                                 locator=str(row.get('uuid', ''))[:128]))
    elif source == 'taxii':
        rows = data.get('objects')
        if not isinstance(rows, list):
            raise ValueError('schema_drift')
        for row in rows[:1000]:
            if not isinstance(row, dict) or row.get('type') != 'indicator':
                continue
            pattern = row.get('pattern')
            stix = 'ipv6-addr' if indicator.kind == 'ip' and ipaddress.ip_address(indicator.value).version == 6 else STIX_TYPES.get(indicator.kind)
            # Only exact simple STIX comparison patterns are treated as a match.
            if stix in ('file', 'x509-certificate'):
                expected = f"[{stix}:hashes.'SHA-256' = '{indicator.value}']"
            else:
                expected = f"[{stix}:value = '{indicator.value.replace(chr(39), chr(92)+chr(39))}']"
            if pattern != expected:
                continue
            claims.append(_claim('taxii', 'indicator', row.get('modified', row.get('created')),
                                 row.get('confidence'), row.get('valid_until'), str(row.get('id', ''))[:128]))
    elif source == 'microsoft':
        if indicator.kind == 'azure_application_id':
            if data.get('appId', '').lower() != indicator.value.lower() or not isinstance(data.get('id'), str):
                raise ValueError('schema_drift')
            claims.append(_claim('microsoft', 'tenant_service_principal', time.time(),
                                 locator=data['id'][:128]))
        else:
            if data.get('host') != indicator.value and data.get('id') != indicator.value:
                raise ValueError('schema_drift')
            claims.append(_claim('microsoft', 'host_record', data.get('lastSeenDateTime'),
                                 locator=str(data.get('id', ''))[:128]))
    else:
        raise ValueError('invalid_source')
    return claims


def conflicts(claims):
    assertions = {claim['assertion'] for claim in claims}
    return [{'assertions': sorted(assertions), 'sources': sorted({c['source'] for c in claims})}] if 'malicious' in assertions and 'context' in assertions else []


def _request(source, indicator):
    if source.name == 'misp':
        body = json.dumps({'type': MISP_TYPES[indicator.kind], 'value': indicator.value, 'limit': 1000}, separators=(',', ':')).encode()
        return Request('POST', f'https://{source.origin}{source.path}', body, {'Authorization': source.token, 'Content-Type': 'application/json', 'Accept': 'application/json'})
    if source.name == 'taxii':
        return Request('GET', f'https://{source.origin}{source.path}?limit=1000', headers={'Authorization': f'Bearer {source.token}', 'Accept': 'application/taxii+json;version=2.1'})
    return Request('GET', f'https://{source.origin}{_microsoft_path(source, indicator)}', headers={'Authorization': f'Bearer {source.token}', 'Accept': 'application/json'})


def _microsoft_path(source, indicator):
    if indicator.kind == 'azure_application_id':
        return f"{source.path}(appId='{indicator.value.lower()}')"
    return f'{source.path}/{quote(indicator.value, safe="")}'


def enrich(indicator, source, approval, *, cache=None, transport_factory=HttpsTransport,
           now=None, cache_only=False, allow_stale=False):
    """A privacy decision precedes every outbound lookup; no provider data is executed."""
    if not isinstance(indicator, Indicator) or not isinstance(source, Source):
        raise ValueError('invalid_input')
    if not isinstance(approval, Approval) or approval.source != source.name or approval.indicator_digest != indicator.digest or indicator.sensitive and not approval.allow_sensitive:
        return {'status': 'privacy_denied', 'claims': [], 'conflicts': [], 'cache': None}
    microsoft_supported = (source.path == '/v1.0/servicePrincipals' and indicator.kind == 'azure_application_id') or (source.path == '/v1.0/security/threatIntelligence/hosts' and indicator.kind in ('ip', 'domain'))
    if source.name == 'microsoft' and not microsoft_supported or source.name == 'misp' and indicator.kind not in MISP_TYPES or source.name == 'taxii' and indicator.kind not in STIX_TYPES:
        return {'status': 'unsupported', 'claims': [], 'conflicts': [], 'cache': None}
    now = time.time() if now is None else now
    cache = cache if cache is not None else Cache()
    # A shared in-memory cache must never return one credential scope's result
    # to another; retain only a digest of the credential in the cache key.
    key = (source.name, source.origin, source.path,
           hashlib.sha256(source.token.encode()).hexdigest(), indicator.digest)
    cached = cache.get(key, now, allow_stale=cache_only and allow_stale)
    if cached is not None:
        return cached
    if cache_only:
        return {'status': 'cache_miss', 'claims': [], 'conflicts': [], 'cache': None}
    request = _request(source, indicator)
    path = _microsoft_path(source, indicator) if source.name == 'microsoft' else source.path
    transport = transport_factory(source.origin, path, request.method)
    for attempt in range(3):
        try:
            response = transport.send(request, {}, timeout=10, max_bytes=MAX_BODY)
        except EvidenceError as error:
            if error.code in ('request_timeout', 'transport') and attempt < 2:
                continue
            return {'status': 'error', 'error': error.code, 'claims': [], 'conflicts': [], 'cache': None}
        if response.status in (429, 500, 502, 503, 504) and attempt < 2:
            continue
        if response.status == 404 and source.name == 'microsoft':
            result = {'status': 'negative', 'claims': [], 'conflicts': [], 'cache': None}
        elif response.status != 200:
            return {'status': 'error', 'error': f'http_{response.status}', 'claims': [], 'conflicts': [], 'cache': None}
        else:
            try:
                data = json.loads(response.body)
                if source.name == 'taxii' and data.get('more') is True or source.name == 'misp' and len(data.get('Attribute', [])) >= 1000:
                    return {'status': 'partial', 'error': 'pagination_limit', 'claims': normalize(source.name, indicator, data), 'conflicts': [], 'cache': None}
                claims = normalize(source.name, indicator, data)
            except (ValueError, UnicodeDecodeError, TypeError, AttributeError):
                return {'status': 'error', 'error': 'schema_drift', 'claims': [], 'conflicts': [], 'cache': None}
            result = {'status': 'positive' if claims else 'negative', 'claims': claims, 'conflicts': conflicts(claims), 'cache': None}
        cache.put(key, result, now)
        return {**result, 'expires_at': _stamp(now + (cache.positive_ttl if result['status'] == 'positive' else cache.negative_ttl))}
    return {'status': 'error', 'error': 'retry_exhausted', 'claims': [], 'conflicts': [], 'cache': None}
