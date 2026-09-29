"""Hostile local bundles fail before analysis; no payloads escape errors."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from attackpath.azure.input import read_regular, load
from attackpath.azure.model import AzureError

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
