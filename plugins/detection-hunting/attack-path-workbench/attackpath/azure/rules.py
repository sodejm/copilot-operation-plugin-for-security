"""Pinned, bounded hypothetical transitions; no operations are executed."""
from .identity import directory, find, membership
from .model import Decision, arm, stable
from .permissions import DEPLOYMENT_OPERATIONS, evaluate, role_grant

VERSION = 'azure-rules/v1'
EXECUTION = {
    'microsoft.compute/virtualmachines': ('vm_execution',
        ['Microsoft.Compute/virtualMachines/write', 'Microsoft.Compute/virtualMachines/extensions/write'],
        ['vm_agent', 'network', 'token_endpoint']),
    'microsoft.automation/automationaccounts': ('automation_execution',
        ['Microsoft.Automation/automationAccounts/runbooks/draft/content/write',
         'Microsoft.Automation/automationAccounts/runbooks/publish/action', 'Microsoft.Automation/automationAccounts/jobs/write'],
        ['automation_sandbox', 'network', 'token_endpoint']),
    'microsoft.web/sites': ('functions_execution',
        ['Microsoft.Web/sites/write', 'Microsoft.Web/sites/publish/action'],
        ['function_deployment', 'invocation', 'network', 'token_endpoint']),
    'microsoft.logic/workflows': ('logic_execution',
        ['Microsoft.Logic/workflows/write', 'Microsoft.Logic/workflows/triggers/run/action'],
        ['logic_consumption', 'identity_action', 'invocation', 'network', 'token_endpoint']),
}
SECRET = 'microsoft.keyvault/vaults/secrets/getsecret/action'  # noqa: S105 - schema label or operation identifier, not a credential
OWNER = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
UAA = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'


def combine(decisions):
    states = [d.state for d in decisions]
    state = next((s for s in ('denied', 'unknown', 'latent_eligibility') if s in states), 'allowed')
    return Decision(state, [r for d in decisions for r in d.reasons],
                    [r for d in decisions for r in d.evidence], [r for d in decisions for r in d.cuts],
                    [r for d in decisions for r in d.assumptions])


def observation(row):
    return Decision('unknown' if row.quality else 'allowed', list(row.quality), row.evidence, [row.key])


def runtime(graph, resource, keys):
    declared = graph.scenario.get('runtime', {}).get(arm(resource), {})
    decisions = []
    for key in keys:
        value = declared.get(key)
        decisions.append(Decision('allowed' if value is True else 'denied' if value is False else 'unknown',
            [] if value is True else ['runtime_false:' + key] if value is False else ['runtime_missing:' + key],
            assumptions=['runtime:' + key + ':' + str(value).lower()] if value is not None else []))
    return combine(decisions)


def step(rule, resource, decisions, effect):
    return {'rule': rule, 'version': VERSION, 'resource': resource, 'effect': effect,
            'prerequisites': [d.export() for d in decisions]}


def identity_targets(graph, row):
    identity = row.data.get('identity', {})
    targets = []
    if identity.get('principalId'):
        targets.append((identity['principalId'], [observation(row)]))
    for rid in identity.get('userAssignedIdentities', {}):
        graph.tick()
        uami = find(graph, 'resources', row.tenant, lambda r, rid=rid: arm(r.data['id']) == arm(rid))
        if uami and uami.properties.get('principalId'):
            targets.append((uami.properties['principalId'], [observation(row), observation(uami)]))
    return targets


def execution(graph, tenant, principal, row):
    profile = EXECUTION.get(row.data.get('type', '').lower())
    if not profile:
        return None
    rule, operations, requirements = profile
    decisions = [observation(row)]
    if rule == 'functions_execution' and 'functionapp' not in row.data.get('kind', '').lower().split(','):
        decisions.append(Decision('unknown', ['unsupported_function_kind'], row.evidence))
    decisions += [evaluate(graph, tenant, principal, a, row.data['id'], scenario=graph.scenario) for a in operations]
    decisions.append(runtime(graph, row.data['id'], requirements))
    return rule, decisions



def required_operation(graph, tenant, principal, operation, scope):
    decision = evaluate(graph, tenant, principal, operation, scope, scenario=graph.scenario)
    decision.reasons.append('required_operation:' + operation)
    return decision


def identity_execution(graph, tenant, principal, row, profile):
    if profile:
        rule, decisions = profile
        for mi, witnesses in identity_targets(graph, row):
            ds = decisions + witnesses
            yield mi, ds, [step(rule, row.data['id'], ds, 'hypothetical_code_execution_as_identity')]
    # A scoped template can update an observed VM extension without VM creation rights.
    # Do not infer deployment scopes for nested resources or hypothetical new workloads.
    parts = arm(row.data['id']).strip('/').split('/')
    if (row.data.get('type', '').lower() != 'microsoft.compute/virtualmachines' or len(parts) != 8 or
            parts[0] != 'subscriptions' or parts[2] != 'resourcegroups' or
            parts[4:7] != ['providers', 'microsoft.compute', 'virtualmachines']):
        return
    scope = '/' + '/'.join(parts[:4])
    prepare = [required_operation(graph, tenant, principal, operation, scope)
               for operation in DEPLOYMENT_OPERATIONS]
    execute = [observation(row), required_operation(graph, tenant, principal,
        'Microsoft.Compute/virtualMachines/extensions/write', row.data['id']),
        runtime(graph, row.data['id'], ['vm_agent', 'network', 'token_endpoint'])]
    for mi, witnesses in identity_targets(graph, row):
        ds = execute + witnesses
        yield mi, prepare + ds, [
            step('arm_deployment', scope, prepare, 'hypothetical_scoped_template_deployment'),
            step('arm_deployment_execution', row.data['id'], ds, 'hypothetical_code_execution_as_identity')]


def linked_principals(graph, application):
    result = []
    for sp in graph.rows('service_principals', application.tenant):
        graph.tick()
        if sp.data.get('appId', '').lower() != application.data.get('appId', '').lower() or not application.data.get('appId'):
            continue
        d = combine([observation(application), observation(sp)])
        if sp.data.get('appOwnerOrganizationId') != application.tenant or sp.data.get('servicePrincipalType') != 'Application':
            d = combine([d, Decision('denied', ['application_tenant_or_type_mismatch'], sp.evidence)])
        result.append((sp.data['id'], d))
    return result


def credential_restriction(graph, tenant, row):
    values = [a['credential_update_allowed'] for a in graph.scenario.get('credential_restrictions', [])
              if a['tenant'] == tenant and a['object'].lower() == row.data['id'].lower()]
    if not values or len(set(values)) != 1:
        return Decision('unknown', ['credential_policy_restriction_unknown'], row.evidence)
    return Decision('allowed' if values[0] else 'denied', [] if values[0] else ['credential_policy_restriction'],
                    assumptions=['credential_update_allowed:' + str(values[0]).lower()])


def credential_right(graph, tenant, principal, row, family):
    action = 'microsoft.directory/' + family + '/credentials/update'
    permission = directory(graph, tenant, principal, action, '/' + row.data['id'], graph.scenario)
    if permission.state == 'allowed':
        return permission
    assumptions = graph.scenario.get('owner_credential_rights', [])
    for owner in graph.rows('owners', tenant):
        graph.tick()
        if owner.data.get('id', '').lower() != principal.lower() or owner.data.get('objectId', '').lower() != row.data['id'].lower():
            continue
        if any(a['tenant'] == tenant and a['principal'].lower() == principal.lower()
               and a['object'].lower() == row.data['id'].lower() for a in assumptions):
            return combine([observation(owner), Decision('allowed', assumptions=['owner_credential_right:' + owner.key])])
    return permission


def hypothetical_grant(graph, tenant, principal, definition, scope, target):
    """Evaluate the proposed role through the normal deny/scope/data evaluator."""
    clone = graph.without(None)
    clone.work = graph.work
    clone.add('role_assignments', tenant, {'id': 'hypothesis-' + definition.key,
        'properties': {'principalId': principal, 'roleDefinitionId': definition.data['id'], 'scope': scope}},
        definition.evidence[0])
    try:
        return evaluate(clone, tenant, principal, target['action'], target['scope'], plane=target['plane'], scenario=graph.scenario)
    finally:
        graph.work = clone.work


def transitions(graph, tenant, principal, target):
    """Yield proposed transitions or terminal target decisions, all with witnesses."""
    for row in graph.rows('resources', tenant):
        graph.tick()
        profile = execution(graph, tenant, principal, row)
        for mi, ds, steps in identity_execution(graph, tenant, principal, row, profile):
            yield {'tenant': tenant, 'principal': mi, 'decision': combine(ds), 'steps': steps}
        if profile:
            _, decisions = profile
            # Attaching a UAMI is a distinct mutation, requiring assignment rights.
            for uami in graph.rows('resources', tenant):
                graph.tick()
                if uami.data.get('type', '').lower() != 'microsoft.managedidentity/userassignedidentities' or not uami.properties.get('principalId'):
                    continue
                ds = decisions + [observation(uami), evaluate(graph, tenant, principal,
                    'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action', uami.data['id'], scenario=graph.scenario)]
                yield {'tenant': tenant, 'principal': uami.properties['principalId'], 'decision': combine(ds),
                       'steps': [step('uami_attach', row.data['id'], ds, 'hypothetical_identity_attachment_and_execution')]}
        if (tenant == target['tenant'] and target['plane'] == 'data' and target['action'].lower() == SECRET and
                row.data.get('type', '').lower() == 'microsoft.keyvault/vaults' and arm(row.data['id']) == arm(target['scope'])):
            if row.properties.get('enableRbacAuthorization') is False:
                ds = [observation(row), runtime(graph, row.data['id'], ['network', 'token_endpoint'])]
                policy = next((p for p in row.properties.get('accessPolicies', []) if p.get('tenantId') == tenant
                    and p.get('objectId', '').lower() == principal.lower() and 'get' in p.get('permissions', {}).get('secrets', [])), None)
                if policy:
                    yield {'terminal': True, 'decision': combine(ds), 'steps': [step('key_vault_access_policy', row.data['id'], ds, 'existing_secret_get_policy')]}
                ds.append(evaluate(graph, tenant, principal, 'Microsoft.KeyVault/vaults/accessPolicies/write', row.data['id'], scenario=graph.scenario))
                yield {'terminal': True, 'decision': combine(ds), 'steps': [step('key_vault_policy_change', row.data['id'], ds, 'hypothetical_secret_get_policy')]}
    if tenant == target['tenant']:
        for definition in graph.rows('role_definitions', tenant):
            graph.tick()
            if role_grant(definition, target['action'], target['plane']) is not True:
                continue
            ds = [observation(definition), evaluate(graph, tenant, principal, 'Microsoft.Authorization/roleAssignments/write',
                target['scope'], context={'roleDefinitionId': definition.data['id'], 'principalId': principal}, scenario=graph.scenario)]
            ds.append(hypothetical_grant(graph, tenant, principal, definition, target['scope'], target))
            yield {'terminal': True, 'decision': combine(ds), 'steps': [step('rbac_grant', target['scope'], ds, 'hypothetical_scoped_role_assignment')]}
    for app in graph.rows('applications', tenant):
        graph.tick()
        right = credential_right(graph, tenant, principal, app, 'applications')
        for sp, linkage in linked_principals(graph, app):
            ds = [observation(app), right, linkage, credential_restriction(graph, tenant, app)]
            yield {'tenant': tenant, 'principal': sp, 'decision': combine(ds),
                   'steps': [step('application_credentials', app.data['id'], ds, 'hypothetical_application_credential_addition')]}
    for sp in graph.rows('service_principals', tenant):
        graph.tick()
        if sp.data.get('servicePrincipalType') != 'Application':
            continue
        ds = [observation(sp), credential_right(graph, tenant, principal, sp, 'servicePrincipals'), credential_restriction(graph, tenant, sp)]
        if sp.data.get('appOwnerOrganizationId') != tenant:
            ds.append(Decision('unknown', ['protected_object_or_tenant_restriction'], sp.evidence))
        yield {'tenant': tenant, 'principal': sp.data['id'], 'decision': combine(ds),
               'steps': [step('application_credentials', sp.data['id'], ds, 'hypothetical_service_principal_credential_addition')]}
    for fic in graph.rows('federated_credentials', tenant):
        graph.tick()
        oid = fic.data.get('objectId', '')
        obj = find(graph, 'resources', tenant, lambda r, oid=oid: r.data['id'].lower() == oid.lower()) or find(graph, 'applications', tenant, lambda r, oid=oid: r.data['id'].lower() == oid.lower())
        if not obj:
            continue
        if obj.family == 'resources' and obj.data.get('type', '').lower() != 'microsoft.managedidentity/userassignedidentities':
            continue
        right = (evaluate(graph, tenant, principal, 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write', oid, scenario=graph.scenario)
                 if obj.family == 'resources' else directory(graph, tenant, principal,
                    'microsoft.directory/applications/credentials/update', '/' + oid, graph.scenario))
        assertions = graph.scenario.get('assertions', [])
        matching = [a for a in assertions if a['controlled'] and a['issuer'] == fic.properties.get('issuer')
                    and a['subject'] == fic.properties.get('subject') and a['audience'] in fic.properties.get('audiences', [])
                    and a['audience'] == 'api://AzureADTokenExchange']
        assertion = Decision('allowed' if matching else 'denied' if assertions else 'unknown',
            [] if matching else ['controlled_assertion_mismatch' if assertions else 'assertion_control_unknown'],
            assumptions=['controlled_assertion:' + stable(a) for a in matching])
        destinations = [(obj.properties.get('principalId'), observation(obj))] if obj.family == 'resources' else linked_principals(graph, obj)
        for dest, linkage in destinations:
            if dest:
                ds = [observation(fic), right, assertion, linkage]
                if obj.family == 'applications':
                    ds.append(credential_restriction(graph, tenant, obj))
                yield {'tenant': tenant, 'principal': dest, 'decision': combine(ds),
                       'steps': [step('federation', oid, ds, 'hypothetical_federated_credential_control')]}
    yield from delegated(graph, tenant, principal, target)


# Authorization operations are unavailable through Lighthouse delegated roles.
LIGHTHOUSE_EXCLUSIONS = ['Microsoft.Authorization/*']


def delegated(graph, tenant, principal, target):
    import copy
    principals = membership(graph, tenant, principal)
    for definition in graph.rows('lighthouse'):
        graph.tick()
        p = definition.properties
        if p.get('managedByTenantId') != tenant:
            continue
        for registration in graph.rows('lighthouse_assignments', definition.tenant):
            graph.tick()
            if registration.properties.get('registrationDefinitionId', '').lower() != definition.data['id'].lower():
                continue
            marker = '/providers/microsoft.managedservices/registrationassignments/'
            normalized_id = arm(registration.data['id'])
            if marker not in normalized_id:
                continue
            scope = normalized_id.rsplit(marker, 1)[0]
            ordinary, grants = [], []
            entries = [(a, False) for a in p.get('authorizations', [])] + [(a, True) for a in p.get('eligibleAuthorizations', [])]
            for authorization, eligible in entries:
                graph.tick()
                aid = authorization.get('principalId', '').lower()
                if aid not in principals:
                    continue
                role_id = authorization.get('roleDefinitionId', '').split('/')[-1].lower()
                role = find(graph, 'role_definitions', definition.tenant, lambda r, role_id=role_id: r.data['id'].split('/')[-1].lower() == role_id)
                if not role:
                    continue
                restricted = role.properties.get('roleType') != 'BuiltInRole' or role_id == OWNER or any(
                    item.get('dataActions') for item in role.properties.get('permissions', []))
                refs, cuts = principals[aid]
                ds = [observation(definition), observation(registration), observation(role),
                      Decision('denied' if restricted or (eligible and role_id == UAA) else 'latent_eligibility' if eligible else 'allowed',
                        ['unsupported_delegated_role'] if restricted or (eligible and role_id == UAA) else ['delegated_activation_unfulfilled'] if eligible else [],
                        refs, cuts + [definition.key, registration.key])]
                if role_id == UAA:
                    grants.append((authorization, ds))
                else:
                    ordinary.append((role, ds))
            # Inactive or unsupported authorizations cannot contaminate an active route.
            active = [entry for entry in ordinary if combine(entry[1]).state == 'allowed']
            inactive = [entry for entry in ordinary if entry not in active]
            cohorts = ([active] if active else []) + [active + [entry] for entry in inactive]
            activatable = [entry for entry in inactive if combine(entry[1]).state != 'denied']
            if len(activatable) > 1:
                cohorts.append(active + activatable)
            for cohort in cohorts:
                graph.tick()
                clone = graph.without(None)
                proxy = 'delegated-' + stable([definition.key, principal, [entry[0].key for entry in cohort]])
                delegation_ds = [d for _, witness in cohort for d in witness]
                for role, _ in cohort:
                    data = copy.deepcopy(role.data)
                    data['id'] += '-lighthouse-' + role.key[:12]
                    for permission in data.get('properties', data).get('permissions', []):
                        permission['notActions'] = permission.get('notActions', []) + LIGHTHOUSE_EXCLUSIONS
                    filtered = clone.add('role_definitions', definition.tenant, data, role.evidence[0], role.quality)
                    clone.add('role_assignments', definition.tenant, {'id': proxy + '-' + role.key, 'properties': {
                        'principalId': proxy, 'roleDefinitionId': filtered.data['id'], 'scope': scope}}, registration.evidence[0])
                if target['tenant'] == definition.tenant:
                    permission = evaluate(clone, definition.tenant, proxy, target['action'], target['scope'], plane=target['plane'], scenario=graph.scenario)
                    ds = delegation_ds + [permission]
                    yield {'terminal': True, 'decision': combine(ds), 'steps': [
                        step('lighthouse', scope, delegation_ds, 'delegated_customer_control_plane_operation'),
                        step('target_permission', target['scope'], [permission], 'requested_authorization')]}
                for resource in clone.rows('resources', definition.tenant):
                    clone.tick()
                    if not clone.contains(scope, resource.data['id'], definition.tenant):
                        continue
                    run = execution(clone, definition.tenant, proxy, resource)
                    for mi, execution_ds, execution_steps in identity_execution(clone, definition.tenant, proxy, resource, run):
                        combined = delegation_ds + execution_ds
                        yield {'tenant': definition.tenant, 'principal': mi, 'decision': combine(combined),
                            'steps': [step('lighthouse', scope, delegation_ds, 'delegated_customer_control_plane_operation')] + execution_steps}
                        if target['tenant'] != definition.tenant:
                            continue
                        for authorization, grant_ds in grants:
                            for rid in authorization.get('delegatedRoleDefinitionIds', []):
                                clone.tick()
                                role = find(clone, 'role_definitions', definition.tenant, lambda r, rid=rid: r.data['id'].split('/')[-1].lower() == rid.split('/')[-1].lower())
                                if not role or role.properties.get('roleType') != 'BuiltInRole' or role.data['id'].split('/')[-1].lower() in (OWNER, UAA):
                                    continue
                                check = hypothetical_grant(clone, definition.tenant, mi, role, scope, target)
                                all_ds = combined + grant_ds + [observation(role), check]
                                yield {'terminal': True, 'decision': combine(all_ds), 'steps': [
                                    step('lighthouse', scope, delegation_ds + grant_ds, 'delegated_customer_control_plane_operation'),
                                    step('lighthouse_uami_grant', scope, grant_ds + [check], 'hypothetical_listed_role_grant_to_managed_identity')] + execution_steps}
