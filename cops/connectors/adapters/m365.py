"""Fixed, read-only Microsoft Graph collections for scoped investigations."""
from urllib.parse import parse_qsl, urlencode

from cops.evidence import EvidenceError

from ..interfaces import Page, Request
from .microsoft import destination, guid, opaque

# Fields are intentionally narrower than the provider responses. The caller
# cannot supply an arbitrary Graph path, projection, or OData expression.
SOURCES = {
    'signins': ('/v1.0/auditLogs/signIns', 'AuditLog.Read.All',
                ('id', 'createdDateTime', 'userId', 'appId', 'ipAddress')),
    'directory-audits': ('/v1.0/auditLogs/directoryAudits', 'AuditLog.Read.All',
                         ('id', 'activityDateTime', 'activityDisplayName', 'initiatedBy')),
    'service-principals': ('/v1.0/servicePrincipals', 'Application.Read.All',
                            ('id', 'appId', 'displayName')),
    'conditional-access': ('/v1.0/identity/conditionalAccess/policies', 'Policy.Read.All',
                             ('id', 'displayName', 'state')),
    'security-alerts': ('/v1.0/security/alerts_v2', 'SecurityAlert.Read.All',
                        ('id', 'createdDateTime', 'userId', 'appId', 'severity')),
    'security-incidents': ('/v1.0/security/incidents', 'SecurityIncident.Read.All',
                           ('id', 'createdDateTime', 'incidentWebUrl', 'severity')),
    'purview-cases': ('/v1.0/security/cases/ediscoveryCases', 'eDiscovery.Read.All',
                      ('id', 'displayName', 'status')),
    'mail-messages': ('/v1.0/messages', 'Mail.ReadBasic.All',
                      ('id', 'receivedDateTime', 'userId', 'subject')),
    'sharepoint-sites': ('/v1.0/sites', 'Sites.Read.All',
                         ('id', 'name', 'displayName', 'webUrl')),
    'teams-chats': ('/v1.0/chats', 'Chat.Read.All',
                    ('id', 'chatType', 'createdDateTime')),
    'auth-methods': ('/v1.0/reports/credentialUserRegistrationDetails', 'Reports.Read.All',
                     ('id', 'userId', 'userPrincipalName', 'authMethodStatus')),
    'oauth2-permission-grants': ('/v1.0/oauth2PermissionGrants', 'DelegatedPermissionGrant.Read.All',
                                 ('id', 'clientId', 'consentType', 'principalId', 'scope')),
}


class GraphCollection:
    version, product, origin, method = '1', 'microsoft-graph', 'graph.microsoft.com', 'GET'

    def __init__(self, tenant, source):
        if source not in SOURCES:
            raise EvidenceError('invalid_adapter')
        self.tenant = guid(tenant)
        self.name = f'm365-{source}'
        self.api = f'v1.0/{source}'
        self.path, self.permission, self.fields = SOURCES[source]
        self.scope = [source]
        self._query = {'$select': ','.join(self.fields), '$top': '100'}

    def request(self, cursor=None):
        url = cursor or f'https://{self.origin}{self.path}?{urlencode(self._query)}'
        request = Request('GET', url)
        self.validate_request(request)
        return request

    def validate_request(self, request):
        parts = destination(request.url, self.origin, self.path)
        try:
            pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True,
                              max_num_fields=5)
        except ValueError:
            raise EvidenceError('unsafe_destination') from None
        query = dict(pairs)
        if (request.method != 'GET' or request.body is not None or len(query) != len(pairs)
                or query.keys() - {'$select', '$top', '$skiptoken', '$skipToken'}
                or any(query.get(key) != value for key, value in self._query.items())
                or any(not value or len(value) > 8192 for value in query.values())):
            raise EvidenceError('unsafe_destination')
        if ('$skiptoken' in query) and ('$skipToken' in query):
            raise EvidenceError('unsafe_destination')

    def parse(self, data, *, retried=False):
        if not isinstance(data, dict) or not isinstance(data.get('value'), list):
            raise EvidenceError('schema_drift')

        def records():
            for item in data['value']:
                if not isinstance(item, dict):
                    raise EvidenceError('schema_drift')
                identity = opaque(item.get('id'))
                if len(identity) > 256:
                    raise EvidenceError('schema_drift')
                payload = {}
                for field in self.fields:
                    value = item.get(field)
                    if field == 'initiatedBy':
                        if value is not None and not isinstance(value, dict):
                            raise EvidenceError('schema_drift')
                        user = value.get('user') if value else None
                        if user is not None and not isinstance(user, dict):
                            raise EvidenceError('schema_drift')
                        value = user.get('id') if user else None
                        field = 'actorUserId'
                    if value is not None and (not isinstance(value, str) or len(value) > 2048
                                              or any(ord(char) < 32 for char in value)):
                        raise EvidenceError('schema_drift')
                    payload[field] = value
                yield {'identity': identity, 'locator': identity, 'payload': payload,
                       'region': None}

        cursor = data.get('@odata.nextLink')
        if cursor is not None:
            try:
                self.request(cursor)
            except EvidenceError:
                return Page(records(), reason='unsafe_destination')
        return Page(records(), cursor,
                    'retry_continuation' if retried and cursor is not None else None)
