"""Deterministic bounded path traversal with explicit hypothetical steps."""
from .model import Budget, object_id, stable
from .permissions import evaluate
from .rules import combine, step, transitions


def classification(decision):
    if decision.state == 'denied':
        return 'blocked'
    if decision.state == 'latent_eligibility':
        return 'latent_eligibility'
    if decision.state == 'unknown':
        # Required-operation labels identify evaluated rights, not evidence gaps.
        gaps = [r for r in decision.reasons if not r.startswith('required_operation:')]
        return 'conditional' if gaps and all(r.startswith('runtime_missing:') for r in gaps) else 'unknown'
    return 'modelled_reachable'


def search(graph, *, controlled=None, targets=None):
    results = {}
    starts = controlled if controlled is not None else graph.scenario['controlled']
    targets = targets if targets is not None else graph.scenario['targets']
    try:
        for start in sorted(starts, key=lambda s: (s['tenant'], s['id'])):
            for target in sorted(targets, key=lambda t: (t['tenant'], t['scope'], t['action'])):
                queue = [(start['tenant'], start['id'], [], [], {object_id(start['tenant'], start['id'])})]
                cursor = 0
                while cursor < len(queue):
                    graph.tick()
                    tenant, principal, steps, decisions, visited = queue[cursor]
                    cursor += 1
                    if tenant == target['tenant'] and len(steps) + 1 <= graph.limits['hops']:
                        terminal = evaluate(graph, tenant, principal, target['action'], target['scope'], plane=target['plane'], scenario=graph.scenario)
                        emit(results, start, target, steps + [step('target_permission', target['scope'], [terminal], 'requested_authorization')], decisions + [terminal])
                        if len(results) >= graph.limits['paths']:
                            raise Budget('path_limit')
                    for transition in transitions(graph, tenant, principal, target):
                        graph.tick()
                        chain = steps + transition['steps']
                        ds = decisions + [transition['decision']]
                        if len(chain) > graph.limits['hops'] or (len(chain) == graph.limits['hops'] and not transition.get('terminal')):
                            graph.partial.append('path_depth_limit')
                            continue
                        if transition.get('terminal'):
                            emit(results, start, target, chain, ds)
                        else:
                            dest = object_id(transition['tenant'], transition['principal'])
                            if dest in visited:
                                continue
                            # Retain blocked/unknown candidates for explanation, but never call them reachable.
                            if len(queue) >= graph.limits['expansions']:
                                raise Budget('queue_limit')
                            queue.append((transition['tenant'], transition['principal'], chain, ds, visited | {dest}))
                        if len(results) >= graph.limits['paths']:
                            raise Budget('path_limit')
    except Budget as exc:
        graph.partial.append(str(exc))
    return sorted(results.values(), key=lambda p: (p['rank'], p['id']))


def emit(results, start, target, steps, decisions):
    d = combine(decisions)
    state = classification(d)
    evidence = sorted(set(d.evidence))
    identity = stable([start, target, steps, state])
    results[identity] = {'id': identity, 'start': start, 'target': target, 'classification': state,
        'steps': steps, 'evidence': evidence, 'assumptions': sorted(set(d.assumptions)), 'uncertainty': sorted(set(d.reasons)),
        'cuts': sorted(set(d.cuts)), 'rank': {'modelled_reachable': 0, 'conditional': 1,
            'latent_eligibility': 2, 'unknown': 3, 'blocked': 4}[state]}
