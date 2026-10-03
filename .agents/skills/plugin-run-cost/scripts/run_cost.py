#!/usr/bin/env python3
"""Local plugin run accounting. No network calls or plugin execution."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser_spec = importlib.util.spec_from_file_location(
    'codex_usage_for_cost', ROOT.parent / 'session-usage-audit/scripts/codex_token_usage.py')
usage_parser = importlib.util.module_from_spec(parser_spec)
parser_spec.loader.exec_module(usage_parser)
TOKENS = usage_parser.FIELDS


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def number(value):
    if isinstance(value, bool):
        raise ValueError('boolean is not a numeric amount')
    try:
        result = Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError('invalid numeric amount') from error
    if not result.is_finite() or result < 0:
        raise ValueError('amounts must be finite and nonnegative')
    return result


def money(value):
    # Keep sub-micro-dollar precision through aggregation; six places is a minimum.
    return format(value, '.6f') if value == value.quantize(Decimal('0.000001')) else format(value, 'f')


def integer(value):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError('token and request counts must be nonnegative integers')
    return value


def price(request, card, as_of=None):
    """Price one request. Missing cache writes produce bounds, never a point price."""
    u = request['usage']
    for key in TOKENS:
        if key in u:
            integer(u[key])
    for subset, parent in [('reasoning_output_tokens', 'output_tokens'),
                           ('cached_input_tokens', 'input_tokens')]:
        if subset in u and parent in u and u[subset] > u[parent]:
            raise ValueError(f'{subset} exceeds {parent}')
    if all(k in u for k in ('input_tokens', 'cached_input_tokens', 'cache_write_input_tokens')):
        if u['cached_input_tokens'] + u['cache_write_input_tokens'] > u['input_tokens']:
            raise ValueError('cache read plus write exceeds input')
    unpriced = dict(amount_usd=None, bounds_usd=None, reason=None)
    if not all(k in u for k in ('input_tokens', 'cached_input_tokens', 'output_tokens')):
        return dict(unpriced, reason='missing input/cache-read/output usage')
    timestamp = usage_parser.parse_timestamp(as_of or request['timestamp'])
    rates = [r for r in card['rates'] if all(request.get(k) == r.get(k) for k in
             ('provider', 'model', 'service_tier', 'region')) and
             usage_parser.parse_timestamp(r['valid_from']) <= timestamp <
             usage_parser.parse_timestamp(r['valid_until']) and
             r['input_min'] <= u['input_tokens'] and
             (r['input_max'] is None or u['input_tokens'] <= r['input_max'])]
    if len(rates) != 1:
        return dict(unpriced, reason='no unique exact dated rate for model/tier/region/context')
    rate = rates[0]
    if rate['currency'] != 'USD':
        raise ValueError('v1 supports USD rates only')
    provenance = dict(source=rate['source'], verified_at=rate['verified_at'], rate=rate,
                      rate_sha256=hashlib.sha256(json.dumps(rate, sort_keys=True).encode()).hexdigest())
    inp, cache, write, out = [number(rate[k]) for k in ('input', 'cache_read', 'cache_write', 'output')]
    i, c, o = [u[k] for k in ('input_tokens', 'cached_input_tokens', 'output_tokens')]
    base = (i-c)*inp + c*cache + o*out
    if 'cache_write_input_tokens' not in u:
        limits = sorted([base, base + (i-c)*(write-inp)])
        return dict(unpriced, reason='cache-write usage missing',
                    bounds_usd=[money(v/1000000) for v in limits], **provenance)
    total = (base + u['cache_write_input_tokens']*(write-inp))/1000000
    return dict(amount_usd=money(total), bounds_usd=[money(total), money(total)],
                reason=None, **provenance)


def private_path(path):
    """Reject symlinks and any Git checkout; storage is always private local data."""
    path = Path(os.path.abspath(path.expanduser()))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('ledger paths must not traverse symlinks')
        if (part / '.git').exists():
            raise ValueError('ledger must be outside Git working trees')
    # A symlinked .git or bare repository must not bypass this boundary.
    for part in path.parents:
        if (part / '.git').is_symlink() or ((part / 'HEAD').is_file() and (part / 'objects').is_dir()):
            raise ValueError('ledger must be outside Git repositories')
    return path


def read_ledger(path):
    path = private_path(Path(path))
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]


def save_run(path, run, requests):
    """Replace one run atomically, allowing additional requests but no rewritten evidence."""
    path = private_path(Path(path))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.stat().st_mode & 0o077:
        raise ValueError('ledger directory must be owner-only (mode 700)')
    lock = path.with_name(path.name + '.lock')
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    temp = None
    try:
        os.close(descriptor)
        rows = read_ledger(path)
        own = next((r for r in rows if r['run']['run_id'] == run['run_id']), None)
        if own and own['run'] != run:
            raise ValueError('run metadata is immutable; use a new run ID or correct the source before import')
        known = {q['id']: (r['run']['run_id'], q) for r in rows for q in r['requests']}
        combined = {q['id']: q for q in own['requests']} if own else {}
        for request in requests:
            prior = known.get(request['id'])
            if prior and (prior[0] != run['run_id'] or prior[1] != request):
                raise ValueError('request already owned by another run or conflicting evidence')
            if request['id'] in combined and combined[request['id']] != request:
                raise ValueError('conflicting duplicate request')
            combined[request['id']] = request
        rows = [r for r in rows if r['run']['run_id'] != run['run_id']]
        rows.append(dict(schema_version=1, run=run,
                         requests=sorted(combined.values(), key=lambda q: (q['timestamp'], q['id']))))
        fd, temp = tempfile.mkstemp(prefix='.run-cost-', dir=path.parent)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if temp and os.path.exists(temp):
            os.unlink(temp)
        lock.unlink()
    return dict(run_id=run['run_id'], requests=len(combined), ledger_updated=True)


def safe_label(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,160}', value):
        raise ValueError('metadata labels require 1..160 letters, digits, dot, colon, underscore or hyphen')
    return value


def import_run(manifest, paths):
    """Explicit membership is the authorization boundary for session attribution."""
    required = ('run_id', 'plugin', 'version', 'cohort', 'scope', 'acceptance', 'config')
    run = {key: safe_label(manifest[key]) for key in required}
    for key, choices in dict(kind=['execution', 'development', 'planning'],
                             status=['completed', 'failed', 'aborted', 'partial'],
                             attribution=['confirmed', 'inferred'],
                             source_completeness=['complete', 'partial', 'unknown']).items():
        if manifest[key] not in choices:
            raise ValueError(f'invalid {key}')
        run[key] = manifest[key]
    if type(manifest['accepted']) is not bool:
        raise ValueError('accepted must be boolean')
    if manifest['accepted'] and manifest['status'] != 'completed':
        raise ValueError('only completed runs may be accepted')
    run['accepted'] = manifest['accepted']
    run['human_active_minutes'] = str(number(manifest.get('human_active_minutes', 0)))
    run['human_time_observed'] = 'human_active_minutes' in manifest
    run['fees_usd'] = {safe_label(k): str(number(v)) for k, v in manifest.get('fees_usd', {}).items()}
    run['actual_invoice_usd'] = (str(number(manifest['actual_invoice_usd']))
                                  if 'actual_invoice_usd' in manifest else None)
    if run['actual_invoice_usd'] is not None:
        run['invoice_reference'] = safe_label(manifest['invoice_reference'])
    members = manifest['members']
    if not members or not paths:
        raise ValueError('explicit members and session paths are required')
    region = safe_label(manifest.get('region', 'unknown'))
    assumed_tier = safe_label(manifest.get('assumed_service_tier', 'unknown'))
    requests, windows, diagnostics = {}, [], Counter()
    normalized_members = []
    for member in members:
        sid = safe_label(member['session_id'])
        stage = safe_label(member['stage'])
        start, end = [usage_parser.parse_timestamp(member[k]) for k in ('start', 'end')]
        if end <= start:
            raise ValueError('member end must follow start')
        if any(sid == s and start < b and a < end for s, a, b in windows):
            raise ValueError('overlapping windows for the same session')
        windows.append((sid, start, end))
        role = member['role']
        if role not in ('root', 'child', 'continuation', 'retry'):
            raise ValueError('invalid member role')
        normalized_members.append(dict(session_id=sid, start=start.isoformat(), end=end.isoformat(),
                                       stage=stage, role=role))
        report = usage_parser.aggregate(paths, start, end, {sid}, include_requests=True)
        diagnostics.update(report['diagnostics'])
        for request in report['requests']:
            request.update(provider='openai', region=region, role=role, stage=stage)
            for field in ('model', 'requested_effort', 'effective_effort', 'service_tier'):
                request[field] = safe_label(request[field])
            # An explicit assumption is distinguishable from an observed service tier.
            request['tier_basis'] = 'observed'
            if request['service_tier'] == 'unknown' and assumed_tier != 'unknown':
                request['service_tier'] = assumed_tier
                request['tier_basis'] = 'assumed'
            requests[request['id']] = request
    run['members'] = normalized_members
    run['elapsed_window_seconds'] = (max(b for _, _, b in windows)-min(a for _, a, _ in windows)).total_seconds()
    # Diagnostic counters vary as logs grow; return them, never rewrite persisted identity.
    return run, list(requests.values()), dict(diagnostics)


def summarize_requests(requests, card, as_of=None):
    priced, unpriced, groups, reasons = Decimal(0), 0, {}, Counter()
    coverage, tokens = Counter(), Counter()
    provenance = {}
    lower, upper, bounded = Decimal(0), Decimal(0), True
    for request in requests:
        result = price(request, card, as_of)
        if 'rate_sha256' in result:
            entry = provenance.setdefault(result['rate_sha256'], dict(
                rate_sha256=result['rate_sha256'], rate=result['rate'], requests=0))
            entry['requests'] += 1
        key = '|'.join(str(request.get(k, 'unknown')) for k in
                       ('model', 'requested_effort', 'service_tier', 'stage', 'role'))
        group = groups.setdefault(key, dict(requests=0, priced_subtotal_usd=Decimal(0), unpriced_requests=0))
        group['requests'] += 1
        if result['amount_usd'] is None:
            unpriced += 1
            group['unpriced_requests'] += 1
            reasons[result['reason']] += 1
        else:
            amount = Decimal(result['amount_usd'])
            priced += amount
            group['priced_subtotal_usd'] += amount
        if result['bounds_usd']:
            lower += Decimal(result['bounds_usd'][0])
            upper += Decimal(result['bounds_usd'][1])
        else:
            bounded = False
        for field, value in request['usage'].items():
            if field in TOKENS:
                tokens[field] += value
                coverage[field] += 1
    for group in groups.values():
        group['priced_subtotal_usd'] = money(group['priced_subtotal_usd'])
    return dict(requests=len(requests), priced_requests=len(requests)-unpriced,
                unpriced_requests=unpriced, priced_subtotal_usd=money(priced),
                total_usd=money(priced) if not unpriced and requests else None,
                bounds_usd=[money(lower), money(upper)] if bounded and requests else None,
                unpriced_reasons=dict(reasons), groups=groups,
                rate_card_sha256=hashlib.sha256(json.dumps(card, sort_keys=True).encode()).hexdigest(),
                pricing_provenance=[provenance[k] for k in sorted(provenance)],
                observed_tokens=dict(tokens), field_coverage_requests=dict(coverage))


def report_runs(rows, card, as_of=None):
    runs, cohorts = [], defaultdict(list)
    for row in rows:
        run = row['run']
        summary = summarize_requests(row['requests'], card, as_of)
        fees = sum((number(v) for v in run.get('fees_usd', {}).values()), Decimal(0))
        summary['fees_usd'] = money(fees)
        summary['attempt_usd'] = (money(number(summary['total_usd']) + fees)
                                  if summary['total_usd'] is not None else None)
        complete = bool(row['requests']) and run.get('source_completeness') == 'complete' and run.get('attribution') == 'confirmed'
        summary['complete_evidence'] = complete
        runs.append(dict(run=run, accounting=summary))
        # Scope/config/version/acceptance prevent inappropriate cross-run averaging.
        key = tuple(run.get(k) for k in ('plugin', 'version', 'config', 'cohort', 'scope', 'acceptance', 'kind'))
        cohorts[key].append((run, summary))
    cohort_rows = []
    for key, values in cohorts.items():
        accepted = sum(run['accepted'] for run, _ in values)
        complete = all(s['complete_evidence'] and s['attempt_usd'] is not None for _, s in values)
        cost = sum((number(s['attempt_usd']) for _, s in values if s['attempt_usd'] is not None), Decimal(0))
        cohort_rows.append(dict(identity=list(key), attempts=len(values), accepted=accepted,
                               complete_evidence=complete,
                               known_attempt_subtotal_usd=money(cost),
                               cost_per_accepted_result_usd=money(cost/accepted) if accepted and complete else None))
    return dict(schema_version=1, basis='API-equivalent; not a subscription bill',
                repriced_as_of=as_of, runs=runs, cohorts=cohort_rows,
                limitations=['Source completeness is operator-declared, not independently proven.',
                             'Requested effort is metadata, never a price multiplier.',
                             'Elapsed membership windows include waits and are not employee effort.'])


SKIP_DIRS = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'dist', 'build', 'vendor', '.next'}
TEXT_SUFFIXES = {'.py', '.js', '.ts', '.tsx', '.jsx', '.md', '.txt', '.json', '.yaml', '.yml',
                 '.toml', '.rs', '.go', '.java', '.c', '.h', '.cpp', '.cs', '.swift', '.tf', '.html'}


def profile(repositories, wikis, threat_models, max_files=10000, max_bytes=20000000, max_entries=100000):
    if not (repositories or wikis or threat_models):
        raise ValueError('at least one profile input is required')
    for limit in (max_files, max_bytes, max_entries):
        if not integer(limit):
            raise ValueError('profile limits must be positive')
    counts, kinds, hashes, suffixes = Counter(), Counter(), set(), Counter()
    scanned_bytes = 0
    graph = Counter()
    for kind, roots in [('repository', repositories), ('wiki', wikis), ('threat_model', threat_models)]:
        for root in map(Path, roots):
            if counts['scan_limit_reached']:
                break
            if root.is_symlink():
                counts['entries_visited'] += 1
                if counts['entries_visited'] >= max_entries:
                    counts['scan_limit_reached'] = 1
                counts['symlinks_skipped'] += 1
                continue
            if not root.exists():
                raise ValueError('profile input does not exist')
            def walk():
                # Iterate directories without materializing their contents. The shared
                # budget counts roots, directories and excluded entries across all inputs.
                pending = [(root, False)]
                while pending:
                    path, counted = pending.pop()
                    if counts['entries_visited'] >= max_entries:
                        counts['scan_limit_reached'] = 1
                        return
                    if not counted:
                        counts['entries_visited'] += 1
                    if path.is_dir() and not path.is_symlink():
                        with os.scandir(path) as entries:
                            for entry in entries:
                                if counts['entries_visited'] >= max_entries:
                                    counts['scan_limit_reached'] = 1
                                    return
                                if entry.is_dir(follow_symlinks=False):
                                    # Count queued directories now, before exclusions.
                                    counts['entries_visited'] += 1
                                    if entry.name not in SKIP_DIRS and not entry.name.startswith('.'):
                                        pending.append((Path(entry.path), True))
                                else:
                                    counts['entries_visited'] += 1
                                    yield Path(entry.path)
                    else:
                        yield path
            for path in walk():
                name = path.name.lower()
                secret_name = re.search(r'(^|[._-])(secrets?|credentials?|private[-_]key)([._-]|$)', name)
                if path.is_symlink() or name.startswith('.') or secret_name or path.suffix.lower() not in TEXT_SUFFIXES:
                    counts['excluded_files'] += 1
                    continue
                if counts['files_read'] >= max_files or scanned_bytes >= max_bytes:
                    counts['scan_limit_reached'] += 1
                    break
                if path.stat().st_size > min(2000000, max_bytes-scanned_bytes):
                    counts['oversize_files'] += 1
                    continue
                data = path.read_bytes()
                counts['files_read'] += 1
                scanned_bytes += len(data)
                try:
                    text = data.decode('utf-8')
                except UnicodeDecodeError:
                    counts['binary_files'] += 1
                    continue
                if '\0' in text:
                    counts['binary_files'] += 1
                    continue
                # Normalize line endings and trailing whitespace, without semantic rewriting.
                normalized = '\n'.join(line.rstrip() for line in text.splitlines()).strip()
                digest = hashlib.sha256(normalized.encode()).hexdigest()
                if digest in hashes:
                    counts['duplicate_documents'] += 1
                    continue
                hashes.add(digest)
                counts['unique_documents'] += 1
                counts['characters'] += len(normalized)
                kinds[kind] += len(normalized)
                suffixes[path.suffix.lower()] += 1
                if kind == 'threat_model' and path.suffix == '.json':
                    try:
                        value = json.loads(text)
                        for key in ('components', 'flows', 'trust_boundaries', 'threats'):
                            if isinstance(value, dict) and isinstance(value.get(key), list):
                                graph[key] += len(value[key])
                    except ValueError:
                        counts['invalid_threat_json'] += 1
    chars = counts['characters']
    return dict(schema_version=1, **{k: counts[k] for k in ('unique_documents', 'duplicate_documents', 'characters')},
                source_characters=dict(kinds), suffix_counts=dict(suffixes), graph_counts=dict(graph),
                approximate_tokens=dict(low=math.ceil(chars/5), base=math.ceil(chars/4), high=chars),
                diagnostics=dict(counts), source_bytes_read=scanned_bytes,
                limitations=['Heuristic token range, not tokenizer output or semantic complexity.',
                             'Wiki inputs must be local text exports; freshness and scope are supplied by the operator.',
                             'Name exclusions reduce exposure but are not a secret scanner; no source content is exported.'])


def estimate(config, card, input_profile=None):
    results = []
    for scenario in config['scenarios']:
        requests = []
        for shape in scenario['request_shapes']:
            count = integer(shape['count'])
            if count > 10000 or len(requests)+count > 10000:
                raise ValueError('forecast limited to 10000 requests per scenario')
            usage = dict(shape['usage'])
            if input_profile is not None:
                # Each request shape declares how much of the profiled corpus it reads.
                basis = scenario.get('profile_token_basis', 'base')
                selected = number(input_profile['approximate_tokens'][basis])
                fraction = number(shape['selected_input_fraction'])
                if fraction > 1:
                    raise ValueError('selected_input_fraction must be between zero and one')
                scale = number(scenario.get('input_scale', 1))
                fixed = integer(shape.get('fixed_input_tokens', 0))
                tools = integer(shape.get('tool_input_tokens', 0))
                repeated = integer(shape.get('repeated_context_tokens', 0))
                usage['input_tokens'] = fixed + tools + repeated + math.ceil(selected*fraction*scale)
                cache_fraction = number(scenario.get('cache_read_fraction', 0))
                write_fraction = number(scenario.get('cache_write_fraction', 0))
                if cache_fraction + write_fraction > 1:
                    raise ValueError('forecast cache fractions must sum to at most one')
                usage['cached_input_tokens'] = math.floor(usage['input_tokens']*cache_fraction)
                usage['cache_write_input_tokens'] = math.floor(usage['input_tokens']*write_fraction)
            for index in range(count):
                requests.append(dict(id=str(index), provider=config['provider'], model=shape['model'],
                                     service_tier=config['service_tier'], region=config['region'],
                                     timestamp=config['as_of'], requested_effort=shape['effort'],
                                     stage=shape['stage'], role=shape.get('role', 'root'), usage=usage))
        results.append(dict(name=safe_label(scenario['name']), assumptions=scenario['assumptions'],
                            input_profile_used=input_profile is not None, request_shapes=scenario['request_shapes'],
                            input_scale=scenario.get('input_scale', 1),
                            **summarize_requests(requests, card)))
    return dict(basis='forecast API equivalent', scenarios=results,
                calibration='Use matched accepted runs; early scenarios are assumptions, not confidence intervals.')


def compare(config):
    weekly = number(config.get('runs_per_week', 3))
    annual = weekly*52
    if not annual:
        raise ValueError('runs_per_week must be positive')
    rates = sorted({number(v) for v in config.get('hourly_rates', [75, 150])})
    if not rates:
        raise ValueError('at least one hourly rate is required')
    alternatives = config['alternatives']
    baseline = next(a for a in alternatives if a['name'] == 'manual')
    baseline_minutes = number(baseline['active_minutes'])
    results = []
    for option in alternatives:
        minutes = number(option['active_minutes'])
        hours = (baseline_minutes-minutes)*annual/60
        item = dict(name=safe_label(option['name']), qualified=option.get('qualified') is True,
                    annual_capacity_hours=float(hours), at_hourly_rate={})
        for rate in rates:
            def recurring(a):
                return ((number(a['active_minutes'])/60*rate + number(a.get('variable_usd', 0)))*annual +
                        number(a.get('monthly_maintenance_hours', 0))*rate*12 +
                        number(a.get('monthly_maintenance_usd', 0))*12 + number(a.get('annual_license_usd', 0)))
            cost, manual = recurring(option), recurring(baseline)
            setup = number(option.get('build_hours', 0))*rate + number(option.get('build_usd', 0))
            savings = manual-cost
            qualified = item['qualified'] and baseline.get('qualified') is True
            item['at_hourly_rate'][str(rate)] = dict(annual_recurring_usd=money(cost),
                recurring_per_run_usd=money(cost/annual), setup_usd=money(setup),
                annual_recurring_savings_usd=money(savings) if qualified else None,
                first_year_net_value_usd=money(savings-setup) if qualified else None,
                break_even_runs=float(setup/(savings/annual)) if qualified and savings > 0 else None)
        results.append(item)
    opportunities = []
    for candidate in config.get('opportunities', []):
        rate = rates[0]
        annual_benefit = (number(candidate['saved_usd_per_run']) + number(candidate['saved_minutes_per_run'])/60*rate)*annual
        maintenance = number(candidate['monthly_maintenance_hours'])*rate*12
        build = number(candidate['build_hours'])*rate
        net = annual_benefit-maintenance
        opportunities.append(dict(name=safe_label(candidate['name']), evidence=candidate['evidence'],
                                  first_year_net_value_usd=money(net-build),
                                  break_even_runs=float(build/(net/annual)) if net > 0 else None))
    opportunities.sort(key=lambda o: Decimal(o['first_year_net_value_usd']), reverse=True)
    return dict(runs_per_year=float(annual), average_runs_per_month=float(annual/12),
                alternatives=results, opportunities=opportunities,
                limitations=['Capacity value is not cash savings without a staffing or contractor change.',
                             'Qualified means operator-declared equivalent scope and acceptance quality.',
                             'Active minutes include preparation, review and corrections; wall time is separate.',
                             'Opportunity ranking uses the lower supplied hourly rate and declared evidence.'])


def markdown(value):
    lines = ['# Plugin run cost report', '', str(value.get('basis', 'Local scenario comparison')), '']
    if 'runs' in value:
        lines += ['| Run | Requests | Priced subtotal USD | Unpriced | Complete evidence |',
                  '|---|---:|---:|---:|---|']
        for row in value['runs']:
            a = row['accounting']
            lines.append(f"| {row['run']['run_id']} | {a['requests']} | {a['priced_subtotal_usd']} | {a['unpriced_requests']} | {a['complete_evidence']} |")
    lines += ['', 'Machine-readable detail (includes coverage, assumptions and limitations):', '',
              '```json', json.dumps(value, indent=2), '```', '']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format', choices=['json', 'markdown'], default='json')
    parser.add_argument('--prices', type=Path, default=ROOT/'references/prices.json')
    commands = parser.add_subparsers(dest='command', required=True)
    scan = commands.add_parser('profile')
    for kind in ('repository', 'wiki', 'threat-model'):
        scan.add_argument('--'+kind, type=Path, action='append', default=[])
    imp = commands.add_parser('import')
    imp.add_argument('--manifest', type=Path, required=True)
    imp.add_argument('--path', type=Path, action='append', required=True)
    imp.add_argument('--ledger', type=Path, required=True)
    report = commands.add_parser('report')
    report.add_argument('--ledger', type=Path, required=True)
    report.add_argument('--as-of', help='Explicit API-equivalent repricing date, not historical billing')
    for name in ('estimate', 'compare'):
        command = commands.add_parser(name)
        command.add_argument('--config', type=Path, required=True)
        if name == 'estimate':
            command.add_argument('--profile', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'profile':
            result = profile(args.repository, args.wiki, args.threat_model)
        elif args.command == 'import':
            run, requests, diagnostics = import_run(read_json(args.manifest), args.path)
            result = save_run(args.ledger, run, requests)
            result['diagnostics'] = diagnostics
        elif args.command == 'report':
            result = report_runs(read_ledger(args.ledger), read_json(args.prices), args.as_of)
        elif args.command == 'estimate':
            result = estimate(read_json(args.config), read_json(args.prices),
                              read_json(args.profile) if args.profile else None)
        else:
            result = compare(read_json(args.config))
        print(markdown(result) if args.format == 'markdown' else json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        parser.error(str(error))


if __name__ == '__main__':
    raise SystemExit(main())
