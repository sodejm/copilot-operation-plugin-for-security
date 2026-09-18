"""Accounting invariants; synthetic records contain no personal transcripts."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("audit", Path(__file__).parents[1] / "scripts/codex_token_usage.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def ts(second):
    return f"2026-09-01T00:{second // 60:02}:{second % 60:02}Z"


def row(kind, p, second=1):
    return {"timestamp": ts(second), "type": kind, "payload": p}


def usage(n=10):
    return dict(input_tokens=n, cached_input_tokens=n // 2, cache_write_input_tokens=0,
                output_tokens=4, reasoning_output_tokens=2, total_tokens=n + 4)


def legacy(second, last=None, total=None):
    return row("event_msg", {"type": "token_count", "info": {"last_token_usage": last, "total_token_usage": total}}, second)


def canonical(second=2, response="r1", owner="task", values=None):
    return row("token_usage_record", {"thread_id": owner, "response_id": response, "usage": values or usage()}, second)


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = []

    def file(self, rows, name=None, meta=None):
        path = Path(self.temp.name) / (name or f"{len(self.paths)}.jsonl")
        records = [row("session_meta", meta or {"id": "task", "timestamp": ts(0)}, 0), *rows]
        path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
        self.paths.append(path)
        return path

    def report(self, start=0, end=120):
        return audit.aggregate(self.paths, audit.parse_timestamp(ts(start)), audit.parse_timestamp(ts(end)))

    def test_canonical_mirror_and_hybrid(self):
        self.file([legacy(1, usage(), usage()), canonical(2), legacy(2, usage(), usage(20))])
        r = self.report()
        self.assertEqual(r["total"]["requests"], 2)
        self.assertEqual(r["diagnostics"]["canonical_mirrors_ignored"], 1)

    def test_canonical_response_identity_preserves_distinct_requests(self):
        self.file([canonical(), canonical(response="r2"), canonical(second=3)])
        self.assertEqual(self.report()["total"]["requests"], 2)

    def test_delayed_mirror_after_tools_with_different_cumulative_totals(self):
        self.file([canonical(1), row("response_item", {"type": "function_call", "name": "read", "call_id": "c1"}, 2),
                   legacy(10, usage(), usage(100))])
        r = self.report()
        self.assertEqual(r["total"]["requests"], 1)
        self.assertEqual(r["diagnostics"]["canonical_mirrors_ignored"], 1)

    def test_legacy_context_size_is_not_request_usage(self):
        snapshot = dict(input_tokens=0, output_tokens=0, total_tokens=20000)
        self.file([legacy(1, snapshot, usage()), legacy(2, usage(), usage(20))])
        r = self.report()
        self.assertEqual(r["total"]["tokens"]["total_tokens"], 14)
        self.assertEqual(r["diagnostics"]["legacy_context_size_snapshots_ignored"], 1)

    def test_duplicate_active_and_archived_copies(self):
        records = [legacy(1, usage(), usage()), canonical(2), legacy(2, usage(), usage(20))]
        self.file(records, "active.jsonl")
        self.file(records, "archive.jsonl")
        self.assertEqual(self.report()["total"]["requests"], 2)

    def test_repeated_cumulative_snapshot_but_identical_real_requests(self):
        self.file([legacy(1, usage(), usage()), legacy(2, usage(), usage()), legacy(3, usage(), usage(20))])
        self.assertEqual(self.report()["total"]["requests"], 2)

    def test_cache_and_reasoning_are_subsets(self):
        self.file([canonical()])
        tokens = self.report()["total"]["tokens"]
        self.assertEqual(tokens["total_tokens"], 14)
        self.assertEqual(tokens["uncached_input_tokens"], 5)
        self.assertEqual(tokens["output_tokens"], 4)

    def test_missing_invalid_fields_are_not_zero(self):
        bad = dict(input_tokens=10, output_tokens=4, total_tokens=14,
                   cached_input_tokens=True, reasoning_output_tokens=-1)
        self.file([canonical(values=bad)])
        r = self.report()
        self.assertIsNone(r["total"]["tokens"]["cached_input_tokens"])
        self.assertIsNone(r["total"]["tokens"]["uncached_input_tokens"])
        self.assertEqual(r["total"]["field_coverage_requests"]["input_tokens"], 1)
        self.assertEqual(r["diagnostics"]["invalid_usage_fields"], 2)

    def test_model_switch_and_unknown(self):
        self.file([canonical(1, "a"), row("turn_context", {"model": "model-a"}, 2),
                   canonical(3, "b"), row("turn_context", {"model": "model-b"}, 4), canonical(5, "c")])
        self.assertEqual(set(self.report()["by_model"]), {"unknown", "model-a", "model-b"})

    def test_fork_inherited_context_and_explicit_owner(self):
        self.file([row("turn_context", {"model": "parent-model"}, 2),
                   legacy(3, usage(), usage()), canonical(11, "foreign", owner="parent"),
                   legacy(12, usage(), usage()), row("turn_context", {"model": "child-model"}, 13),
                   canonical(14)], meta={"id": "task", "parent_thread_id": "parent", "timestamp": ts(10)})
        r = self.report()
        self.assertEqual(r["total"]["requests"], 1)
        self.assertEqual(set(r["by_model"]), {"child-model"})
        self.assertEqual(r["diagnostics"]["ambiguous_fork_usage_ignored"], 1)

    def test_cumulative_only_baseline_delta_and_reset(self):
        first = dict(input_tokens=10, output_tokens=4, total_tokens=14)
        second = dict(input_tokens=30, output_tokens=8, total_tokens=38)
        self.file([legacy(1, total=first), legacy(2, total=second), legacy(3, total=first),
                   legacy(4, usage(), second)])
        r = self.report()
        self.assertEqual(r["total"]["requests"], 2)
        self.assertEqual(r["total"]["tokens"]["input_tokens"], 30)
        self.assertEqual(r["diagnostics"]["legacy_counter_resets"], 1)

    def test_window_retains_baseline_and_excludes_end(self):
        self.file([legacy(1, usage(), usage()), legacy(10, usage(), usage()), canonical(11), canonical(20, "end")])
        self.assertEqual(self.report(start=10, end=20)["total"]["requests"], 1)

    def test_top_level_only_compaction_and_tool_metrics(self):
        call = {"type": "function_call", "name": "read", "arguments": "{}", "call_id": "c1"}
        output = {"type": "function_call_output", "output": "é", "call_id": "c1"}
        self.file([row("response_item", call), row("response_item", call),
                   row("response_item", {**call, "call_id": "c2"}, 2), row("response_item", output),
                   row("event_msg", {"type": "item_completed", "item": call}),
                   row("compacted", {"window_id": "w1", "replacement_history": [canonical()], "latest_token_usage_record": canonical()})])
        r = self.report()
        self.assertEqual(r["total"]["requests"], 0)
        self.assertEqual(r["metrics"]["tool_calls"], 2)
        self.assertEqual(r["metrics"]["tool_output_bytes"], 2)
        self.assertEqual(r["metrics"]["repeated_tool_call_signatures"], 1)
        self.assertEqual(r["metrics"]["compactions"], 1)

    def test_paired_clipped_turns_and_unpaired(self):
        self.file([row("event_msg", {"type": "task_started", "turn_id": "a"}, 1),
                   row("event_msg", {"type": "task_complete", "turn_id": "a"}, 20),
                   row("event_msg", {"type": "task_started", "turn_id": "b"}, 11),
                   row("event_msg", {"type": "turn_aborted", "turn_id": "b"}, 12),
                   row("event_msg", {"type": "task_started", "turn_id": "c"}, 13)])
        metrics = self.report(start=10, end=15)["metrics"]
        self.assertEqual(metrics["recorded_turn_seconds"], 6)
        self.assertEqual(metrics["paired_turns"], 2)
        self.assertEqual(metrics["unpaired_turn_starts"], 1)

    def test_malformed_lines_and_shapes_do_not_abort(self):
        path = self.file([canonical()])
        with path.open("a") as handle:
            handle.write('{"truncated":\n[]\n')
        r = self.report()
        self.assertEqual(r["total"]["requests"], 1)
        self.assertEqual(r["diagnostics"]["malformed_lines"], 1)
        self.assertEqual(r["diagnostics"]["invalid_record_shapes"], 1)

    def test_excerpt_hard_bound_large_line_and_line_selection(self):
        path = Path(self.temp.name) / "large.jsonl"
        path.write_text("x" * 150000 + "\nsecond\n" + "y" * 150000)
        text = audit.excerpt(path, 2, 2, 128)
        self.assertTrue(text.startswith("2: second\n3: "))
        self.assertEqual(len(text), 128)
        self.assertEqual(audit.excerpt(path, 20, 1, 128), "")
        with self.assertRaises(ValueError):
            audit.excerpt(path, 1, 21, 128)

    def test_session_filter(self):
        self.file([canonical()])
        r = audit.aggregate(self.paths, audit.parse_timestamp(ts(0)), audit.parse_timestamp(ts(120)), {"other"})
        self.assertEqual(r["total"]["requests"], 0)


if __name__ == "__main__":
    unittest.main()
