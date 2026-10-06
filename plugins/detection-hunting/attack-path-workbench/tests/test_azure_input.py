"""Hostile local bundles fail before analysis; no payloads escape errors."""
import os
import tempfile
import unittest
from pathlib import Path

from attackpath.azure.input import load, read_regular
from attackpath.azure.model import AzureError
from attackpath.ingestion import IngestError, Limits, RunBudget, iter_jsonl, parse_json
from azure_fixtures import NOW, write_bundle
from test_azure_paths import base


class InputTests(unittest.TestCase):
    def test_descriptor_reader_rejects_links_traversal_and_nonregular(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'data').write_bytes(b'abc')
            (root / 'link').symlink_to(root / 'data')
            (root / 'dir').mkdir()
            os.mkfifo(root / 'fifo')
            self.assertEqual(b'abc', read_regular(root, 'data', 3))
            for name in ('link', '../data', '/data', 'dir', 'fifo'):
                with self.subTest(name=name), self.assertRaises(AzureError):
                    read_regular(root, name, 10)
            with self.assertRaisesRegex(AzureError, 'file_limit'):
                read_regular(root, 'data', 2)

    def test_duplicate_nonfinite_and_unknown_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'manifest.json'
            for text in ('{"schema_version":1,"schema_version":2}', '{"x":NaN}', '{}'):
                file.write_text(text)
                with self.assertRaises(AzureError):
                    load(file, '2026-09-28T12:00:00Z')

    def test_azure_limits_count_manifest_receipts_sources_and_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_bundle(tmp, base())
            graph = load(manifest, NOW)
            receipt = graph.ingestion
            self.assertEqual(1 + 2 * len(graph.coverage), receipt['files'])
            self.assertEqual(len(graph.coverage) + 1, receipt['records'])
            self.assertEqual(len(graph.coverage), receipt['lines'])
            self.assertEqual(receipt, load(manifest, NOW).ingestion)
            with self.assertRaisesRegex(AzureError, 'file_count_limit'):
                load(manifest, NOW, {'files': receipt['files'] - 1})
            with self.assertRaisesRegex(AzureError, 'record_limit'):
                load(manifest, NOW, {'records': receipt['records'] - 1})
            with self.assertRaisesRegex(AzureError, 'total_byte_limit'):
                load(manifest, NOW, {'total_bytes': manifest.stat().st_size})

    def test_manifest_limits_and_cli_caps(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_bundle(tmp, base(), limits={'records': 20, 'line_bytes': 2097152})
            graph = load(manifest, NOW)
            self.assertEqual(20, graph.ingestion['limits']['records'])
            self.assertEqual(2097152, graph.ingestion['limits']['line_bytes'])
            with self.assertRaisesRegex(AzureError, 'record_limit'):
                load(manifest, NOW, {'records': 3})
            with self.assertRaisesRegex(AzureError, 'invalid_limit'):
                load(manifest, NOW, {'line_bytes': 4194305})

    def test_manifest_cannot_lower_its_own_file_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_bundle(tmp, base(), limits={'file_bytes': 1})
            with self.assertRaisesRegex(AzureError, 'file_limit'):
                load(manifest, NOW)

    def test_jsonl_physical_line_and_nested_json_bounds(self):
        limits = Limits.from_values({'line_bytes': 3, 'json_depth': 2})
        budget = RunBudget(limits)
        self.assertEqual([b'abc'], list(iter_jsonl(b'abc\n', limits, budget)))
        with self.assertRaisesRegex(IngestError, 'line_limit'):
            list(iter_jsonl(b'abc\r\n', limits, budget))
        with self.assertRaisesRegex(IngestError, 'json_depth_limit'):
            parse_json(b'{"a":{"b":{"c":1}}}', limits, max_bytes=100)
