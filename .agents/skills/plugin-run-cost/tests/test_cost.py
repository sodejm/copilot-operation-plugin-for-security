import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
