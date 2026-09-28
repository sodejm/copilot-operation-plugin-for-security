"""Two reviewed, read-only projections; provider pagination stays private."""
import re
from urllib.parse import parse_qsl, urlsplit
from cops.evidence import EvidenceError
from cops.evidence.canonical import canonical
from ..interfaces import Page, Request

UUID = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')


def guid(value):
    if not isinstance(value, str) or not UUID.fullmatch(value):
        raise EvidenceError('invalid_scope')
    return value.lower()


def opaque(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 8192 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise EvidenceError('unsafe_destination')
    return value


def destination(url, origin, path):
    try:
        parts = urlsplit(opaque(url))
        if parts.scheme != 'https' or parts.netloc != origin or parts.path != path or parts.fragment:
            raise ValueError
        return parts
    except (ValueError, EvidenceError):
        raise EvidenceError('unsafe_destination') from None


class GraphUsers:
    name, version, product, api = 'graph-users', '1', 'microsoft-graph', 'v1.0/users'
    origin, path, method = 'graph.microsoft.com', '/v1.0/users', 'GET'

    def __init__(self, tenant):
        self.tenant, self.scope = guid(tenant), ['directory/users']

    def request(self, cursor=None):
        url = cursor or 'https://graph.microsoft.com/v1.0/users?$select=id,userType&$top=100'
        request = Request('GET', url, headers={'ConsistencyLevel': 'eventual'})
        self.validate_request(request)
        return request

    def validate_request(self, request):
        parts = destination(request.url, self.origin, self.path)
        try:
            pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True, max_num_fields=10)
        except ValueError:
            raise EvidenceError('unsafe_destination') from None
        query = dict(pairs)
        if request.method != self.method or request.body is not None or len(query) != len(pairs) or not query or query.keys() - {'$select', '$top', '$skiptoken', '$skipToken'}:
            raise EvidenceError('unsafe_destination')
        if ('$select' in query and query['$select'] != 'id,userType') or ('$top' in query and query['$top'] != '100'):
            raise EvidenceError('unsafe_destination')
        if any(not value for value in query.values()):
            raise EvidenceError('unsafe_destination')

    def parse(self, data, *, retried=False):
        if not isinstance(data, dict) or not isinstance(data.get('value'), list):
            raise EvidenceError('schema_drift')
        def records():
            for item in data['value']:
                if not isinstance(item, dict) or not UUID.fullmatch(str(item.get('id', ''))) or item.get('userType') not in ('Member', 'Guest', None):
                    raise EvidenceError('schema_drift')
                identity = item['id'].lower()
                yield {'identity': identity, 'locator': identity,
                       'payload': {'id': identity, 'userType': item.get('userType')}, 'region': None}
        cursor = data.get('@odata.nextLink')
        if cursor is not None:
            try:
                self.request(cursor)
            except EvidenceError:
                # Accept the current safe projection but never follow a hostile link.
                return Page(records(), reason='unsafe_destination')
        return Page(records(), cursor, 'retry_continuation' if retried and cursor is not None else None)


class ResourceGraph:
    name, version, product, api = 'azure-resource-graph', '1', 'azure-resource-graph', '2022-10-01/resources'
    origin, path, method = 'management.azure.com', '/providers/Microsoft.ResourceGraph/resources', 'POST'
    query = 'Resources | project id, type, location | order by id asc'

    def __init__(self, tenant, subscriptions):
        if not isinstance(subscriptions, (list, tuple)) or not 1 <= len(subscriptions) <= 1000:
            raise EvidenceError('invalid_scope')
        self.tenant, self.scope = guid(tenant), sorted({guid(s) for s in subscriptions})

    def request(self, cursor=None):
        options = {'resultFormat': 'objectArray', '$top': 100}
        if cursor is not None:
            options['$skipToken'] = opaque(cursor)
        request = Request('POST', 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01',
                          canonical({'query': self.query, 'subscriptions': self.scope, 'options': options}),
                          {'Content-Type': 'application/json'})
        self.validate_request(request)
        return request

    def validate_request(self, request):
        parts = destination(request.url, self.origin, self.path)
        if request.method != 'POST' or parts.query != 'api-version=2022-10-01':
            raise EvidenceError('unsafe_destination')
        # Body construction is owned by this trusted adapter, never by source data.

    def parse(self, data, *, retried=False):
        if not isinstance(data, dict) or not isinstance(data.get('data'), list) or data.get('resultTruncated') not in ('true', 'false'):
            raise EvidenceError('schema_drift')
        if type(data.get('count')) is not int or data['count'] != len(data['data']) or type(data.get('totalRecords')) is not int or data['totalRecords'] < data['count']:
            raise EvidenceError('schema_drift')
        def records():
            for item in data['data']:
                if not isinstance(item, dict):
                    raise EvidenceError('schema_drift')
                identity, kind, region = item.get('id'), item.get('type'), item.get('location')
                if not isinstance(identity, str) or len(identity) > 2048 or not re.fullmatch(r'/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9_.()-]+/providers/[A-Za-z0-9./_()-]+', identity):
                    raise EvidenceError('schema_drift')
                if identity.split('/')[2].lower() not in self.scope or not isinstance(kind, str) or not re.fullmatch(r'[A-Za-z0-9.]+/[A-Za-z0-9/]+', kind):
                    raise EvidenceError('schema_drift')
                if not isinstance(region, str) or not re.fullmatch(r'[a-z0-9-]{0,128}', region):
                    raise EvidenceError('schema_drift')
                yield {'identity': identity.lower(), 'locator': identity,
                       'payload': {'id': identity, 'type': kind.lower(), 'location': region}, 'region': region or None}
        cursor = data.get('$skipToken')
        if cursor is not None:
            try:
                opaque(cursor)
            except EvidenceError:
                return Page(records(), reason='unsafe_destination')
        reason = 'truncated_without_cursor' if data['resultTruncated'] == 'true' and cursor is None else None
        return Page(records(), cursor, reason)
