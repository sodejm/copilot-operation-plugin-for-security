"""Direct membership witnesses and temporal/PIM decisions."""
from .model import Decision
from .._runtime.cops.evidence.canonical import timestamp


def find(graph, family, tenant, predicate):
    for row in graph.rows(family, tenant):
        graph.tick()
        if predicate(row):
            return row
    return None


def membership(graph, tenant, principal):
    found = {principal.lower(): ([], [])}
    queue = [(principal.lower(), 0)]
    for child, depth in queue:
        for row in graph.rows('group_members', tenant):
            graph.tick()
            if row.data['id'].lower() != child or row.quality:
                continue
            parent = row.data['groupId'].lower()
            if parent in found:
                continue
            if depth >= graph.limits['hops']:
                graph.partial.append('membership_depth_limit')
                continue
            refs, cuts = found[child]
            found[parent] = (refs + row.evidence, cuts + [row.key])
            queue.append((parent, depth + 1))
    return found


def temporal(graph, row, scenario=None):
    p = row.properties
    if row.quality:
        return Decision('unknown', row.quality, row.evidence, [row.key])
    now = timestamp(graph.as_of)
    for name, sign in (('startDateTime', 1), ('endDateTime', -1)):
        if p.get(name):
            value = timestamp(p[name])
            if (sign == 1 and value > now) or (sign == -1 and value <= now):
                return Decision('denied', ['future_or_expired'], row.evidence, [row.key])
    if row.family != 'pim_eligible':
        return Decision('allowed', [], row.evidence, [row.key])
    refs, cuts = list(row.evidence), [row.key]
    policy_id = p.get('policyId')
    if not policy_id:
        assignment = find(graph, 'pim_policy_assignments', row.tenant, lambda r:
            not r.quality and r.data.get('plane') == row.data.get('plane') and r.properties.get('roleDefinitionId', '').lower() == p['roleDefinitionId'].lower()
            and str(r.properties.get('scope', r.properties.get('scopeId'))).lower() == str(p.get('scope', p.get('directoryScopeId'))).lower())
        if assignment:
            policy_id = assignment.properties.get('policyId')
            refs += assignment.evidence
            cuts.append(assignment.key)
    policy = find(graph, 'pim_policies', row.tenant, lambda r: r.data['id'].lower() == (policy_id or '').lower() and not r.quality and r.data.get('plane') == row.data.get('plane'))
    if policy is None:
        return Decision('latent_eligibility', ['activation_policy_unknown'], refs, cuts)
    requirements = policy.data.get('requirements', {})
    activation = (scenario or {}).get('activations', {}).get(row.data['id'], {})
    required = ('approval', 'mfa', 'authentication_context')
    known = all(type(requirements.get(k)) is bool for k in required) and type(requirements.get('max_duration_minutes')) is int
    fulfilled = (known and not requirements.get('extra_requirements', True) and type(activation.get('duration_minutes')) is int
        and 0 < activation['duration_minutes'] <= requirements['max_duration_minutes']
        and all(not requirements[k] or activation.get(k) is True for k in required))
    return Decision('allowed' if fulfilled else 'latent_eligibility',
        [] if fulfilled else ['activation_requirements_unfulfilled'],
        refs + policy.evidence, cuts + [policy.key],
        ['activation:' + row.key] if fulfilled else [])


def directory(graph, tenant, principal, action, scope, scenario=None):
    principals = {principal.lower(): ([], [])}
    for member in graph.rows('group_members', tenant):
        graph.tick()
        if member.data['id'].lower() != principal.lower() or member.quality:
            continue
        group = find(graph, 'groups', tenant, lambda g: g.data['id'].lower() == member.data.get('groupId', '').lower())
        if group and not group.quality and group.data.get('isAssignableToRole') is True:
            principals[group.data['id'].lower()] = (member.evidence + group.evidence, [member.key, group.key])
    witnesses, unknown, latent = [], [], []
    for row in graph.rows('directory_assignments', tenant) + graph.rows('pim_eligible', tenant) + graph.rows('pim_active', tenant):
        graph.tick()
        p = row.properties
        if p.get('directoryScopeId') is None or p.get('principalId', '').lower() not in principals:
            continue
        assignment_scope = p['directoryScopeId']
        # Administrative units contain users, groups and devices, never application objects.
        if (assignment_scope.lower().startswith('/administrativeunits/')
                and action.lower().startswith(('microsoft.directory/applications/',
                                               'microsoft.directory/serviceprincipals/'))):
            unknown += row.evidence
            continue
        scope_refs, scope_cuts = [], []
        if assignment_scope.lower() not in ('/', scope.lower()):
            if not assignment_scope.lower().startswith('/administrativeunits/'):
                continue
            unit = assignment_scope.split('/')[-1].lower()
            member = find(graph, 'administrative_members', tenant, lambda r: not r.quality
                and r.data['objectId'].lower() == unit and '/' + r.data['id'].lower() == scope.lower())
            if not member:
                continue
            scope_refs, scope_cuts = member.evidence, [member.key]
        definition = find(graph, 'directory_definitions', tenant, lambda r: r.data['id'].lower() == p['roleDefinitionId'].lower())
        if not definition or definition.quality:
            unknown += row.evidence
            continue
        # Only exact actions and the universal wildcard have established semantics.
        actions = [a.lower() for item in definition.data.get('rolePermissions', []) for a in item.get('allowedResourceActions', [])]
        if action.lower() not in actions and '*' not in actions:
            if any('*' in a for a in actions):
                unknown += definition.evidence
            continue
        valid = temporal(graph, row, scenario)
        refs, cuts = principals[p['principalId'].lower()]
        d = Decision(valid.state, valid.reasons, valid.evidence + definition.evidence + refs + scope_refs,
                     valid.cuts + [definition.key] + cuts + scope_cuts, valid.assumptions)
        if d.state == 'allowed': witnesses.append(d)
        elif d.state == 'latent_eligibility': latent.append(d)
        elif d.state == 'unknown': unknown += d.evidence
    if witnesses: return sorted(witnesses, key=lambda d: d.evidence)[0]
    if latent: return latent[0]
    return Decision('unknown', ['directory_permission_not_established'], unknown)
