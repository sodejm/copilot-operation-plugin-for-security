"""Boundary tests for local, untrusted evidence files."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from attackpath.core import GateError, analyze
from attackpath.ingestion import CEILINGS, IngestError, Limits, RunBudget, iter_jsonl, parse_json, read_regular

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "illustrative"


class IngestionTests(unittest.TestCase):
    def test_policy_rejects_invalid_before_file_access(self):
        for value in (True, 0, -1, 16777217, "4"):
            with self.subTest(value=value), self.assertRaisesRegex(IngestError, "invalid_limit"):
                Limits.from_values({"file_bytes": value})
        with self.assertRaisesRegex(GateError, "invalid_limit"):
            analyze(Path("absent"), {"unknown": 1})

    def test_file_and_aggregate_bounds_include_rechecks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").write_bytes(b"abc")
            limits = Limits.from_values({"file_bytes": 3, "total_bytes": 6})
            budget = RunBudget(limits)
            self.assertEqual(b"abc", read_regular(root, "data", 3, budget).data)
            self.assertEqual(b"abc", read_regular(root, "data", 3, budget, count_file=False).data)
            self.assertEqual(1, budget.files)
            self.assertEqual(6, budget.bytes)
            with self.assertRaisesRegex(IngestError, "total_byte_limit"):
                read_regular(root, "data", 3, budget, count_file=False)
            (root / "data").write_bytes(b"abcd")
            with self.assertRaisesRegex(IngestError, "file_limit"):
                read_regular(root, "data", 3, RunBudget(limits))

    def test_configured_ingestion_ceilings_accept_below_and_at_but_reject_above(self):
        for name, ceiling in CEILINGS.items():
            for offset in (-1, 0, 1):
                value = ceiling + offset
                with self.subTest(limit=name, value=value):
                    if offset > 0:
                        with self.assertRaisesRegex(IngestError, "invalid_limit"):
                            Limits.from_values({name: value})
                    else:
                        self.assertEqual(value, getattr(Limits.from_values({name: value}), name))

    def test_file_byte_limit_accepts_below_and_at_but_rejects_above(self):
        limits = Limits.from_values({"file_bytes": 3})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for size in (2, 3, 4):
                (root / "data").write_bytes(b"x" * size)
                with self.subTest(size=size):
                    if size > limits.file_bytes:
                        with self.assertRaisesRegex(IngestError, "file_limit"):
                            read_regular(root, "data", limits.file_bytes, RunBudget(limits))
                    else:
                        result = read_regular(root, "data", limits.file_bytes, RunBudget(limits))
                        self.assertEqual(size, len(result.data))

    def test_aggregate_byte_limit_accepts_below_and_at_but_rejects_above(self):
        limits = Limits.from_values({"file_bytes": 1, "total_bytes": 3})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(4):
                (root / f"data-{index}").write_bytes(b"x")
            budget = RunBudget(limits)
            for index in range(2):
                self.assertEqual(b"x", read_regular(
                    root, f"data-{index}", limits.file_bytes, budget).data)
            self.assertEqual(2, budget.bytes)
            self.assertEqual(b"x", read_regular(
                root, "data-2", limits.file_bytes, budget).data)
            self.assertEqual(3, budget.bytes)
            with self.assertRaisesRegex(IngestError, "total_byte_limit"):
                read_regular(root, "data-3", limits.file_bytes, budget)
            self.assertEqual(3, budget.bytes)

    def test_file_count_limit_accepts_below_and_at_but_rejects_above(self):
        limits = Limits.from_values({"files": 2})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(3):
                (root / f"data-{index}").write_bytes(b"x")
            for count in (1, 2, 3):
                with self.subTest(count=count):
                    budget = RunBudget(limits)
                    if count > limits.files:
                        with self.assertRaisesRegex(IngestError, "file_count_limit"):
                            for index in range(count):
                                read_regular(root, f"data-{index}", limits.file_bytes, budget)
                    else:
                        for index in range(count):
                            read_regular(root, f"data-{index}", limits.file_bytes, budget)
                        self.assertEqual(count, budget.files)

    def test_record_limit_accepts_below_and_at_but_rejects_above(self):
        limits = Limits.from_values({"records": 2})
        for count in (1, 2, 3):
            raw = json.dumps({"records": [{}] * count}).encode()
            with self.subTest(count=count):
                if count > limits.records:
                    with self.assertRaisesRegex(IngestError, "record_limit"):
                        parse_json(raw, limits, max_bytes=100, record_cap=limits.records)
                else:
                    parsed = parse_json(raw, limits, max_bytes=100,
                                        record_cap=limits.records)
                    self.assertEqual(count, len(parsed["records"]))
                    budget = RunBudget(limits)
                    budget.add_records(count)
                    self.assertEqual(count, budget.records)

    def test_record_budget_accumulates_across_admitted_batches(self):
        budget = RunBudget(Limits.from_values({"records": 3}))
        budget.add_records(2)
        self.assertEqual(2, budget.records)
        budget.add_records(1)
        self.assertEqual(3, budget.records)
        with self.assertRaisesRegex(IngestError, "record_limit"):
            budget.add_records(1)
        self.assertEqual(3, budget.records)

    def test_physical_line_limit_accepts_below_and_at_but_rejects_above(self):
        limits = Limits.from_values({"line_bytes": 3})
        for size in (2, 3, 4):
            budget = RunBudget(limits)
            with self.subTest(size=size):
                if size > limits.line_bytes:
                    with self.assertRaisesRegex(IngestError, "line_limit"):
                        list(iter_jsonl(b"x" * size + b"\n", limits, budget))
                else:
                    self.assertEqual([b"x" * size], list(iter_jsonl(
                        b"x" * size + b"\n", limits, budget)))
                    self.assertEqual(1, budget.lines)

    def test_json_depth_limit_accepts_below_and_at_but_rejects_above(self):
        limits = Limits.from_values({"json_depth": 2})
        for depth in (1, 2, 3):
            raw = b"[" * depth + b"0" + b"]" * depth
            with self.subTest(depth=depth):
                if depth > limits.json_depth:
                    with self.assertRaisesRegex(IngestError, "json_depth_limit"):
                        parse_json(raw, limits, max_bytes=100)
                else:
                    self.assertIsNotNone(parse_json(raw, limits, max_bytes=100))

    def test_reader_denies_links_and_nonregular_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").write_bytes(b"abc")
            outside = root.parent / (root.name + "-outside")
            outside.write_bytes(b"outside")
            try:
                os.link(outside, root / "hardlink")
                with self.assertRaisesRegex(IngestError, "unsafe_file"):
                    read_regular(root, "hardlink", 10)
            finally:
                outside.unlink()
            (root / "link").symlink_to("data")
            (root / "folder").mkdir()
            (root / "folder" / "link").symlink_to(root)
            if hasattr(os, "mkfifo"):
                os.mkfifo(root / "fifo")
            for name in ("link", "../data", "folder/link/data", "folder", "fifo"):
                with self.subTest(name=name), self.assertRaises(IngestError):
                    read_regular(root, name, 10)

    def test_legacy_manifest_and_source_limits(self):
        size = (FIXTURE / "input.json").stat().st_size
        with self.assertRaisesRegex(GateError, "file_limit"):
            analyze(FIXTURE / "input.json", {"file_bytes": size - 1})
        with self.assertRaisesRegex(GateError, "total_byte_limit"):
            analyze(FIXTURE / "input.json", {"total_bytes": size})
        with self.assertRaisesRegex(GateError, "file_count_limit"):
            analyze(FIXTURE / "input.json", {"files": 1})
        with self.assertRaisesRegex(GateError, "record_limit"):
            analyze(FIXTURE / "input.json", {"records": 1})

    def test_report_receipt_is_deterministic(self):
        first = analyze(FIXTURE / "input.json")
        second = analyze(FIXTURE / "input.json")
        self.assertEqual(first["ingestion"], second["ingestion"])
        self.assertEqual(first["run"]["run_id"], second["run"]["run_id"])
        self.assertGreater(first["ingestion"]["bytes"], 0)
        self.assertEqual(2, first["ingestion"]["files"])

    def test_record_cap_is_checked_before_json_decode(self):
        limits = Limits.from_values({"records": 2})
        with self.assertRaisesRegex(IngestError, "record_limit"):
            parse_json(b'{"records":[{}, {}, {}]}', limits, max_bytes=100, record_cap=2)
        azure = b'{"payload":{"value":[1,2]},"metadata":{"value":[1,2,3]}}'
        self.assertEqual(azure, json.dumps(parse_json(
            azure, limits, max_bytes=100, record_cap=2,
            record_path=("payload", "value")), separators=(",", ":")).encode())
        with self.assertRaisesRegex(IngestError, "record_limit"):
            parse_json(azure, limits, max_bytes=100, record_cap=1,
                       record_path=("payload", "value"))
