import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('run_cost', ROOT / 'scripts/run_cost.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CostTests(unittest.TestCase):
    def setUp(self):
        self.card = m.read_json(ROOT / 'references/prices.json')
        self.request = dict(id='r', session_id='s', timestamp='2026-10-02T12:00:00Z',
                            model='gpt-6-sol', requested_effort='high', effective_effort='unknown',
                            service_tier='standard', provider='openai', region='default',
                            usage=dict(input_tokens=1000, cached_input_tokens=200,
                                       cache_write_input_tokens=100, output_tokens=100,
                                       reasoning_output_tokens=50))

    def test_price_subsets_and_reasoning(self):
        self.assertEqual(m.price(self.request, self.card)['amount_usd'], '0.002690')

    def test_unknown_and_expired_are_unpriced(self):
        for key, value in [('model', 'sol'), ('service_tier', 'unknown'),
                           ('timestamp', '2026-10-01T12:00:00Z')]:
            request = dict(self.request, **{key: value})
            self.assertIsNone(m.price(request, self.card)['amount_usd'])

    def test_cache_write_missing_has_bounds(self):
        del self.request['usage']['cache_write_input_tokens']
        result = m.price(self.request, self.card)
        self.assertIsNone(result['amount_usd'])
        self.assertEqual(result['bounds_usd'], ['0.002640', '0.003040'])

    def test_long_context_per_request(self):
        self.request['usage'].update(input_tokens=272001, cached_input_tokens=0,
                                    cache_write_input_tokens=0, output_tokens=0,
                                    reasoning_output_tokens=0)
        self.assertEqual(m.price(self.request, self.card)['amount_usd'], '1.088004')

    def test_invalid_usage_rejected(self):
        for value in [-1, True, 1.5]:
            self.request['usage']['input_tokens'] = value
            with self.assertRaises(ValueError):
                m.price(self.request, self.card)

    def test_ledger_idempotence_conflicts_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'private' / 'runs.jsonl'
            run = dict(run_id='one', kind='execution', cohort='same', accepted=True)
            m.save_run(path, run, [self.request])
            m.save_run(path, run, [self.request])
            self.assertEqual(len(m.read_ledger(path)), 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                m.save_run(path, dict(run, run_id='two'), [self.request])
            with self.assertRaises(ValueError):
                m.save_run(path, run, [dict(self.request, model='other')])

    def test_ledger_rejects_git_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / '.git').mkdir()
            with self.assertRaises(ValueError):
                m.save_run(root / 'runs.jsonl', {}, [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'link').symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                m.save_run(root / 'link' / 'runs.jsonl', {}, [])

    def test_profile_excludes_secrets_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'one.py').write_text('print(1)')
            (root / 'two.py').write_text('print(1)')
            (root / '.env').write_text('SECRET=private')
            result = m.profile([root], [], [])
            self.assertEqual(result['unique_documents'], 1)
            self.assertEqual(result['duplicate_documents'], 1)
            self.assertNotIn('private', json.dumps(result))

    def test_business_volume_and_capacity(self):
        result = m.compare(dict(alternatives=[dict(name='manual', qualified=True, active_minutes=60),
                                             dict(name='hybrid', qualified=True, active_minutes=30,
                                                  variable_usd=1)]))
        self.assertEqual(result['runs_per_year'], 156)
        hybrid = result['alternatives'][1]
        self.assertEqual(hybrid['annual_capacity_hours'], 78)
        self.assertEqual(hybrid['at_hourly_rate']['75']['annual_recurring_savings_usd'], '5694.000000')

    def test_forecast_prices_requests_individually(self):
        config = m.read_json(ROOT / 'examples/forecast.json')
        result = m.estimate(config, self.card)
        self.assertEqual(len(result['scenarios']), 3)
        self.assertGreater(float(result['scenarios'][2]['priced_subtotal_usd']),
                           float(result['scenarios'][0]['priced_subtotal_usd']))

    def test_forecast_example_supports_input_profile(self):
        config = m.read_json(ROOT / 'examples/forecast.json')
        result = m.estimate(config, self.card, {'approximate_tokens': {'low': 1000, 'base': 2000, 'high': 4000}})
        self.assertTrue(all(s['input_profile_used'] for s in result['scenarios']))
        self.assertTrue(all(s['total_usd'] is not None for s in result['scenarios']))

    def test_price_provenance_survives_summary(self):
        for missing_write in (False, True):
            if missing_write:
                self.request['usage'].pop('cache_write_input_tokens')
            result = m.summarize_requests([self.request], self.card)
            provenance = result['pricing_provenance']
            self.assertEqual(len(provenance), 1)
            self.assertEqual(provenance[0]['requests'], 1)
            self.assertIn('verified_at', provenance[0]['rate'])
            self.assertEqual(len(result['rate_card_sha256']), 64)

    def test_profile_requires_input_and_preserves_ordinary_names(self):
        with self.assertRaises(ValueError):
            m.profile([], [], [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('secretary.py', 'credentialing.json', 'secrets.json', 'app.credentials.json', 'private-key.txt'):
                (root/name).write_text(name)
            result = m.profile([root], [], [])
            self.assertEqual(result['unique_documents'], 2)
            self.assertEqual(result['diagnostics']['excluded_files'], 3)

    def test_profile_bounds_all_entries_across_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for i in range(20):
                (root/f'entry{i}.bin').write_bytes(b'x')
            result = m.profile([root, root], [], [], max_entries=5)
            self.assertEqual(result['diagnostics']['entries_visited'], 5)
            self.assertEqual(result['diagnostics']['scan_limit_reached'], 1)
            self.assertEqual(result['unique_documents'], 0)

    def test_profile_bounds_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for i in range(20):
                (root/f'directory{i}').mkdir()
            result = m.profile([root], [], [], max_entries=5)
            self.assertEqual(result['diagnostics']['entries_visited'], 5)
            self.assertEqual(result['diagnostics']['scan_limit_reached'], 1)

    def test_selected_fraction_is_bounded(self):
        config = m.read_json(ROOT/'examples/forecast.json')
        config['scenarios'][0]['request_shapes'][0]['selected_input_fraction'] = 25
        with self.assertRaises(ValueError):
            m.estimate(config, self.card, dict(approximate_tokens=dict(low=10, base=10, high=10)))


class ImportTests(unittest.TestCase):
    def fixture(self, root):
        manifest = m.read_json(ROOT / 'examples/manifest.json')
        manifest['source_completeness'] = 'complete'
        path = root / 'session.jsonl'
        def row(kind, payload, second=1):
            return dict(type=kind, timestamp=f'2026-10-02T12:00:{second:02d}Z', payload=payload)
        usage = dict(input_tokens=1000, cached_input_tokens=200, cache_write_input_tokens=100,
                     output_tokens=100, reasoning_output_tokens=50)
        records = [row('session_meta', dict(id='synthetic-session')),
                   row('turn_context', dict(model='gpt-6-sol', effort='high')),
                   row('token_usage_record', dict(thread_id='synthetic-session', response_id='one', usage=usage)),
                   row('event_msg', dict(type='token_count', info=dict(last_token_usage=usage))),
                   row('turn_context', dict(model='gpt-6-luna', effort='low'), 2),
                   row('token_usage_record', dict(thread_id='synthetic-session', response_id='two', usage=usage), 2)]
        path.write_text(''.join(json.dumps(record)+'\n' for record in records))
        return manifest, path

    def test_import_mirrors_copies_model_effort_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            manifest, path = self.fixture(root)
            copy = root/'copy.jsonl'
            copy.write_bytes(path.read_bytes())
            run, requests, diagnostics = m.import_run(manifest, [path, copy])
            self.assertEqual(len(requests), 2)
            self.assertEqual([q['requested_effort'] for q in requests], ['high', 'low'])
            self.assertEqual(requests[1]['model'], 'gpt-6-luna')
            self.assertEqual(requests[0]['tier_basis'], 'assumed')
            self.assertEqual(requests[0]['effective_effort'], 'unknown')
            self.assertNotIn(str(root), json.dumps([run, requests]))
            self.assertGreater(diagnostics['duplicate_usage_records_ignored'], 0)
            report = m.report_runs([dict(run=run, requests=requests)], m.read_json(ROOT/'references/prices.json'))
            self.assertEqual(report['cohorts'][0]['cost_per_accepted_result_usd'], '0.0028245')

    def test_overlapping_windows_and_exclusive_end(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, path = self.fixture(Path(directory).resolve())
            manifest['members'][0]['end'] = '2026-10-02T12:00:02Z'
            _, requests, _ = m.import_run(manifest, [path])
            self.assertEqual(len(requests), 1)
            manifest['members'].append(dict(manifest['members'][0]))
            with self.assertRaises(ValueError):
                m.import_run(manifest, [path])

    def test_failed_attempts_in_accepted_cost(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, path = self.fixture(Path(directory).resolve())
            run, requests, _ = m.import_run(manifest, [path])
            failed = dict(run, run_id='failed', accepted=False, status='failed')
            report = m.report_runs([dict(run=run, requests=requests), dict(run=failed, requests=requests)],
                                   m.read_json(ROOT/'references/prices.json'))
            self.assertEqual(report['cohorts'][0]['accepted'], 1)
            self.assertEqual(report['cohorts'][0]['cost_per_accepted_result_usd'], '0.005649')
            failed['source_completeness'] = 'partial'
            report = m.report_runs([dict(run=run, requests=requests), dict(run=failed, requests=requests)],
                                   m.read_json(ROOT/'references/prices.json'))
            self.assertIsNone(report['cohorts'][0]['cost_per_accepted_result_usd'])

    def test_scaled_profile_and_cache_validation(self):
        config = m.read_json(ROOT/'examples/forecast.json')
        card = m.read_json(ROOT/'references/prices.json')
        for scenario in config['scenarios']:
            scenario['request_shapes'][0]['selected_input_fraction'] = 1
        profile = dict(approximate_tokens=dict(low=1000, base=1000, high=1000))
        first = m.estimate(config, card, profile)
        config['scenarios'][0]['input_scale'] = 2
        second = m.estimate(config, card, profile)
        self.assertEqual(second['scenarios'][0]['observed_tokens']['input_tokens'],
                         first['scenarios'][0]['observed_tokens']['input_tokens'] +
                         config['scenarios'][0]['request_shapes'][0]['count']*1000)
        config['scenarios'][0]['cache_read_fraction'] = 2
        with self.assertRaises(ValueError):
            m.estimate(config, card, profile)

    def test_conflicting_canonical_copies_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            manifest, path = self.fixture(root)
            copy = root/'copy.jsonl'
            records = [json.loads(line) for line in path.read_text().splitlines()]
            records[2]['payload']['usage']['output_tokens'] = 101
            copy.write_text(''.join(json.dumps(r)+'\n' for r in records))
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                m.import_run(manifest, [path, copy])

    def test_all_persisted_labels_are_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for field in ('model', 'effort', 'service_tier', 'effective_reasoning_effort'):
                manifest, path = self.fixture(root)
                records = [json.loads(line) for line in path.read_text().splitlines()]
                index = 2 if field == 'effective_reasoning_effort' else 1
                records[index]['payload'][field] = '/private/path with spaces'
                path.write_text(''.join(json.dumps(r)+'\n' for r in records))
                with self.assertRaises(ValueError, msg=field):
                    m.import_run(manifest, [path])
            for field in ('region', 'assumed_service_tier', 'stage'):
                manifest, path = self.fixture(root)
                manifest['members'][0]['start'] = '2026-10-02T13:00:00Z'
                target = manifest['members'][0] if field == 'stage' else manifest
                target[field] = '/private/path with spaces'
                with self.assertRaises(ValueError, msg=field):
                    m.import_run(manifest, [path])

    def test_empty_membership_is_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, path = self.fixture(Path(directory))
            manifest['members'][0]['start'] = '2026-10-02T13:00:00Z'
            run, requests, _ = m.import_run(manifest, [path])
            report = m.report_runs([dict(run=run, requests=requests)], m.read_json(ROOT/'references/prices.json'))
            self.assertFalse(report['runs'][0]['accounting']['complete_evidence'])
            self.assertIsNone(report['cohorts'][0]['cost_per_accepted_result_usd'])

    def test_partial_copies_merge_known_metadata_in_either_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, path = self.fixture(root)
            partial = root/'partial.jsonl'
            records = [json.loads(line) for line in path.read_text().splitlines()]
            partial.write_text(''.join(json.dumps(r)+'\n' for r in records if r['type'] != 'turn_context'))
            expected = m.import_run(manifest, [path])[1]
            for paths in ([path, partial], [partial, path]):
                actual = m.import_run(manifest, paths)[1]
                self.assertEqual(actual, expected)
                member = manifest['members'][0]
                parsed = m.usage_parser.aggregate(paths, m.usage_parser.parse_timestamp(member['start']),
                    m.usage_parser.parse_timestamp(member['end']), {'synthetic-session'}, include_requests=True)
                self.assertNotIn('unknown', json.dumps(parsed['by_model']))

    def test_conflicting_known_model_copies_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, path = self.fixture(root)
            other = root/'other.jsonl'
            other.write_text(path.read_text().replace('gpt-6-sol', 'gpt-6-astra'))
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                m.import_run(manifest, [path, other])


if __name__ == '__main__':
    unittest.main()
