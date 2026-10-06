"""Malformed metadata fails closed and permission modes remain distinct."""
import unittest

from attackpath.azure.identity import directory
from attackpath.azure.input import scenario_contract
from attackpath.azure.model import AzureError, Graph
from attackpath.azure.normalize import validate_projection
from attackpath.azure.permissions import evaluate
from test_azure_paths import NOW, SECRET, VAULT, T, base, role


class ContractTests(unittest.TestCase):
    def test_scenario_container_types_are_checked(self):
        for field in ('assertions', 'owner_credential_rights', 'credential_restrictions'):
            with self.subTest(field=field), self.assertRaises(AzureError):
                scenario_contract({'controlled': [], 'targets': [], field: {}})
        with self.assertRaises(AzureError):
            Graph(NOW, ['nodes'])
        with self.assertRaises(AzureError):
            Graph('not-a-time')

    def test_nested_authorization_metadata_is_checked(self):
        invalid = [
            ('deny_assignments', {'id': 'deny', 'properties': {'principals': [{'id': 4}]}}),
            ('role_definitions', {'id': '/roles/a', 'properties': {'assignableScopes': [4]}}),
            ('pim_policies', {'id': 'p', 'rules': [{'id': 'Approval_EndUser_Assignment', 'target': [], 'setting': []}]}),
            ('resources', {'id': VAULT, 'properties': {'accessPolicies': [{'permissions': []}]}}),
        ]
        for family, data in invalid:
            with self.subTest(family=family), self.assertRaises(AzureError):
                validate_projection(family, data)

    def test_key_vault_rbac_mode_required_for_data_role(self):
        g = base()
        role(g, 'user', data=[SECRET], scope=VAULT)
        self.assertEqual('allowed', evaluate(g, T, 'user', SECRET, VAULT, plane='data').state)
        g.rows('resources')[0].properties['enableRbacAuthorization'] = False
        self.assertEqual('denied', evaluate(g, T, 'user', SECRET, VAULT, plane='data').state)
        g.rows('resources')[0].properties.pop('enableRbacAuthorization')
        self.assertEqual('unknown', evaluate(g, T, 'user', SECRET, VAULT, plane='data').state)

    def test_duplicate_quality_is_not_lost(self):
        g = Graph(NOW)
        g.add('users', T, {'id': 'u'}, 'fresh')
        g.add('users', T, {'id': 'u'}, 'stale', ['observation_stale'])
        self.assertIn('observation_stale', g.rows('users')[0].quality)

    def test_administrative_unit_membership_cannot_grant_application_credentials(self):
        for kind in ('applications', 'servicePrincipals'):
            action = 'microsoft.directory/' + kind + '/credentials/update'
            for scope, expected in (('/', 'allowed'), ('/app', 'allowed'),
                                    ('/administrativeUnits/au', 'unknown')):
                with self.subTest(kind=kind, scope=scope):
                    g = Graph(NOW)
                    g.add('directory_definitions', T, {'id': 'role', 'rolePermissions': [
                        {'allowedResourceActions': [action]}]}, 'definition')
                    g.add('directory_assignments', T, {'id': 'assignment', 'principalId': 'user',
                        'roleDefinitionId': 'role', 'directoryScopeId': scope}, 'assignment')
                    g.add('administrative_members', T, {'id': 'app', 'objectId': 'au'}, 'member')
                    self.assertEqual(expected, directory(g, T, 'user', action, '/app').state)
