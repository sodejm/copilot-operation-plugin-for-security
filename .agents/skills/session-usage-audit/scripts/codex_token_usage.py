#!/usr/bin/env python3
"""Read-only Codex session accounting; Python standard library only.

Extends the user's 2026-08-02 codex_token_usage.py. No built-in price/model map.
See ../references/accounting.md for definitions and limits.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

FIELDS = ("input_tokens", "cached_input_tokens", "cache_write_input_tokens",
          "output_tokens", "reasoning_output_tokens", "total_tokens")


def parse_timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def signature(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def usage_values(value, diagnostics):
    if not isinstance(value, dict):
        return None
    result = {}
    for field in FIELDS:
        number = value.get(field)
        if isinstance(number, int) and not isinstance(number, bool) and number >= 0:
            result[field] = number
        elif field in value:
            diagnostics["invalid_usage_fields"] += 1
    if not result:
        return None
    for subset, parent in (("cached_input_tokens", "input_tokens"),
                           ("reasoning_output_tokens", "output_tokens")):
        if subset in result and parent in result and result[subset] > result[parent]:
            diagnostics["invalid_subset_fields"] += 1
            del result[subset]
    if all(f in result for f in ("input_tokens", "output_tokens", "total_tokens")):
        if result["total_tokens"] != result["input_tokens"] + result["output_tokens"]:
            diagnostics["inconsistent_recorded_total"] += 1
    return result


def session_paths(home):
    return sorted(set((home / "sessions").rglob("*.jsonl")) |
                  set((home / "archived_sessions").rglob("*.jsonl")))


def new_bucket():
    return {"requests": 0, "sums": Counter(), "coverage": Counter()}


def add_usage(bucket, usage):
    bucket["requests"] += 1
    for field, value in usage.items():
        bucket["sums"][field] += value
        bucket["coverage"][field] += 1
    if "input_tokens" in usage and "cached_input_tokens" in usage:
        bucket["sums"]["uncached_input_tokens"] += usage["input_tokens"] - usage["cached_input_tokens"]
        bucket["coverage"]["uncached_input_tokens"] += 1


def finish_bucket(bucket):
    fields = (*FIELDS, "uncached_input_tokens")
    return {
        "requests": bucket["requests"],
        "tokens": {f: bucket["sums"][f] if bucket["coverage"][f] == bucket["requests"] else None
                   for f in fields},
        "observed_tokens": {f: bucket["sums"][f] for f in fields},
        "field_coverage_requests": {f: bucket["coverage"][f] for f in fields},
    }


def aggregate(paths, start, end, session_ids=None):
    diagnostics = Counter()
    candidates, activity = [], []
    metadata = {}
    scanned = 0
    for path in sorted(set(map(Path, paths))):
        sid, model, created, fork, own_context = path.stem, "unknown", None, False, False
        previous_total, epoch, pending_canonical = None, "initial", None
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError:
            diagnostics["unreadable_files"] += 1
            continue
        scanned += 1
        with handle:
            for line_no, line in enumerate(handle, 1):
                try:
                    record = json.loads(line)
                except (ValueError, RecursionError):
                    diagnostics["malformed_lines"] += 1
                    continue
                if not isinstance(record, dict) or not isinstance(record.get("payload"), dict):
                    diagnostics["invalid_record_shapes"] += 1
                    continue
                kind, p = record.get("type"), record["payload"]
                if kind == "session_meta":
                    sid = str(p.get("id") or p.get("session_id") or sid)
                    if session_ids and sid not in session_ids:
                        break
                    fork = bool(p.get("parent_thread_id") or p.get("forked_from_id"))
                    try:
                        created = parse_timestamp(p.get("timestamp") or record.get("timestamp"))
                    except ValueError:
                        diagnostics["invalid_creation_timestamps"] += 1
                    metadata.setdefault(sid, {"id": sid, "paths": [], "source": p.get("thread_source", "unknown")})
                    if str(path) not in metadata[sid]["paths"]:
                        metadata[sid]["paths"].append(str(path))
                    continue
                if session_ids and sid not in session_ids:
                    continue
                try:
                    timestamp = parse_timestamp(record.get("timestamp"))
                except ValueError:
                    diagnostics["invalid_timestamps"] += 1
                    continue
                # Canonical records have explicit ownership. Legacy fork records
                # additionally need a child-era timestamp and child-era context.
                if kind == "token_usage_record" and p.get("thread_id") and str(p["thread_id"]) != sid:
                    diagnostics["foreign_thread_usage_ignored"] += 1
                    continue
                if fork and (created is None or timestamp < created):
                    diagnostics["inherited_fork_records_ignored"] += 1
                    continue
                if kind == "turn_context":
                    model = p.get("model") or "unknown"
                    own_context = True
                    pending_canonical = None
                    continue
                source = {"path": str(path), "line": line_no}
                if kind == "token_usage_record" or (kind == "event_msg" and p.get("type") == "token_count"):
                    if fork and not own_context and kind != "token_usage_record":
                        diagnostics["ambiguous_fork_usage_ignored"] += 1
                        continue
                    canonical = kind == "token_usage_record"
                    info = p if canonical else p.get("info")
                    if not isinstance(info, dict):
                        continue  # Rate-limit-only update, no usage.
                    usage = usage_values(info.get("usage" if canonical else "last_token_usage"), diagnostics)
                    cumulative = usage_values(info.get("thread_token_usage" if canonical else "total_token_usage"), diagnostics)
                    mirror = False
                    if canonical:
                        pending_canonical = usage
                    if not canonical:
                        # Writers may publish token_count after tool execution,
                        # seconds after canonical usage. Compaction usage also
                        # makes their cumulative totals diverge. Match the next
                        # legacy usage to its pending canonical request in order.
                        if usage is not None and usage == pending_canonical:
                            mirror = True
                            pending_canonical = None
                        if usage and usage.get("input_tokens") == 0 and usage.get("output_tokens") == 0 and usage.get("total_tokens", 0) > 0:
                            diagnostics["legacy_context_size_snapshots_ignored"] += 1
                            if cumulative:
                                previous_total = cumulative
                            continue
                        if cumulative and cumulative == previous_total:
                            diagnostics["repeated_legacy_counters_ignored"] += 1
                            continue
                        reset = bool(cumulative and previous_total and any(
                            cumulative[f] < previous_total[f] for f in cumulative.keys() & previous_total.keys()))
                        if reset:
                            epoch = timestamp.isoformat()
                            diagnostics["legacy_counter_resets"] += 1
                        if usage is None and cumulative:
                            if previous_total and not reset:
                                usage = usage_values({f: cumulative[f] - previous_total[f]
                                         for f in cumulative.keys() & previous_total.keys()}, diagnostics)
                                diagnostics["cumulative_deltas_used"] += 1
                            else:
                                diagnostics["cumulative_baselines_without_request_ignored"] += 1
                        if cumulative:
                            previous_total = cumulative
                    if usage:
                        candidates.append({"sid": sid, "model": str(model), "time": timestamp,
                            "usage": usage, "cumulative": cumulative, "canonical": canonical,
                            "response_id": p.get("response_id") if canonical else None,
                            "epoch": epoch, "source": source, "mirror": mirror})
                    continue
                if kind == "compacted" and start <= timestamp < end:
                    activity.append((sid, timestamp, "compaction", signature([timestamp.isoformat(), p.get("window_id"), p.get("compaction_response_id")]), None))
                elif kind == "response_item" and start <= timestamp < end:
                    item_type = p.get("type")
                    if item_type in ("function_call", "custom_tool_call"):
                        fingerprint = signature([p.get("name"), p.get("arguments", p.get("input"))])
                        key = p.get("call_id") or signature([timestamp.isoformat(), p])
                        activity.append((sid, timestamp, "tool_call", str(key), fingerprint))
                    elif item_type in ("function_call_output", "custom_tool_call_output"):
                        output = p.get("output", "")
                        output = output if isinstance(output, str) else json.dumps(output, ensure_ascii=False)
                        key = p.get("call_id") or signature([timestamp.isoformat(), p])
                        activity.append((sid, timestamp, "tool_output", str(key), len(output.encode("utf-8"))))
                elif kind == "event_msg" and p.get("type") in ("task_started", "task_complete", "turn_aborted"):
                    turn_id = p.get("turn_id")
                    if turn_id:
                        activity.append((sid, timestamp, p["type"], str(turn_id), None))
                    else:
                        diagnostics["duration_events_without_turn_id"] += 1

    # New writers mirror canonical usage into token_count. Match by time and
    # usage, not by file position, so interrupted writes and hybrid logs work.
    mirror_keys = {(e["sid"], e["time"], signature(e["usage"])) for e in candidates if e["canonical"]}
    seen_usage = set()
    total, by_model, by_task = new_bucket(), defaultdict(new_bucket), defaultdict(new_bucket)
    evidence = defaultdict(list)
    for event in candidates:
        sid, timestamp, usage = event["sid"], event["time"], event["usage"]
        if event["mirror"] or (not event["canonical"] and (sid, timestamp, signature(usage)) in mirror_keys):
            diagnostics["canonical_mirrors_ignored"] += 1
            continue
        if event["canonical"] and event["response_id"]:
            key = (sid, "response", str(event["response_id"]))
        else:
            key = (sid, "legacy" if not event["canonical"] else "canonical_fallback",
                   timestamp, signature(usage), signature(event["cumulative"]), event["epoch"])
            if event["canonical"]:
                diagnostics["canonical_records_without_response_id"] += 1
        if key in seen_usage:
            diagnostics["duplicate_usage_records_ignored"] += 1
            continue
        seen_usage.add(key)
        if not start <= timestamp < end:
            continue
        for bucket in (total, by_model[event["model"]], by_task[sid]):
            add_usage(bucket, usage)
        if len(evidence[sid]) < 3:
            evidence[sid].append(event["source"])

    metrics, tool_fingerprints, seen_activity, turns = defaultdict(Counter), defaultdict(Counter), set(), defaultdict(dict)
    for sid, timestamp, kind, key, value in sorted(activity, key=lambda e: e[1]):
        identity = (sid, kind, key) if kind in ("tool_call", "tool_output") else (sid, kind, key, timestamp)
        if identity in seen_activity:
            continue
        seen_activity.add(identity)
        if kind == "compaction":
            metrics[sid]["compactions"] += 1
        elif kind == "tool_call":
            metrics[sid]["tool_calls"] += 1
            tool_fingerprints[sid][value] += 1
        elif kind == "tool_output":
            metrics[sid]["tool_output_bytes"] += value
        else:
            turns[(sid, key)].setdefault(kind, timestamp)
    for (sid, _), events in turns.items():
        begin = events.get("task_started")
        endings = [events[k] for k in ("task_complete", "turn_aborted") if k in events]
        finish = min(endings) if endings else None
        if begin and finish and finish >= begin:
            seconds = max(0, (min(end, finish) - max(start, begin)).total_seconds())
            if seconds:
                metrics[sid]["recorded_turn_seconds"] += seconds
                metrics[sid]["paired_turns"] += 1
        elif begin and start <= begin < end:
            metrics[sid]["unpaired_turn_starts"] += 1
        elif finish and start <= finish < end:
            diagnostics["turn_end_without_valid_start"] += 1
    for sid, fingerprints in tool_fingerprints.items():
        metrics[sid]["repeated_tool_call_signatures"] = sum(n - 1 for n in fingerprints.values())
    metric_fields = ("compactions", "tool_calls", "tool_output_bytes", "repeated_tool_call_signatures",
                     "recorded_turn_seconds", "paired_turns", "unpaired_turn_starts")
    tasks = []
    for sid in by_task.keys() | metrics.keys():
        tasks.append({**metadata.get(sid, {"id": sid, "paths": [], "source": "unknown"}),
                      **finish_bucket(by_task[sid]), "metrics": {k: metrics[sid][k] for k in metric_fields},
                      "evidence": evidence[sid]})
    tasks.sort(key=lambda row: row["observed_tokens"]["uncached_input_tokens"], reverse=True)
    return {"schema_version": 1, "window": {"start_inclusive": start.isoformat(), "end_exclusive": end.isoformat()},
            "files_scanned": scanned, "tasks_in_window": len(tasks), "total": finish_bucket(total),
            "by_model": {m: finish_bucket(b) for m, b in sorted(by_model.items())},
            "metrics": {k: sum(t["metrics"][k] for t in tasks) for k in metric_fields},
            "tasks": tasks, "diagnostics": dict(sorted(diagnostics.items())),
            "pricing": "Not estimated; recorded tokens are not subscription charges.",
            "limits": ["Partial coverage is null in tokens; observed_tokens contains known subtotals.",
                       "Task timing sums paired turn wall time, including waits; overlapping turns can overlap.",
                       "Identical tool calls and compactions are investigation signals, not proven waste.",
                       "Diagnostics cover scanned files, including records outside the requested window."]}


def excerpt(path, line_number, lines, max_chars):
    """Explicit bounded raw evidence; never loads a full large JSONL line."""
    if line_number < 1 or not 1 <= lines <= 20 or not 128 <= max_chars <= 12000:
        raise ValueError("excerpt requires line >= 1, 1..20 lines, and 128..12000 characters")
    result, remaining = [], max_chars
    # readline(size) prevents a single giant transcript record allocating GBs.
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        number = 1
        while number < line_number:
            chunk = handle.readline(65536)
            if not chunk:
                break
            if chunk.endswith("\n"):
                number += 1
        for _ in range(lines):
            if number < line_number or remaining <= 0:
                break
            prefix = f"{number}: "
            chunk = handle.readline(max(1, remaining - len(prefix)))
            if not chunk:
                break
            text = (prefix + chunk)[:remaining]
            result.append(text)
            remaining -= len(text)
            if not chunk.endswith("\n"):
                break
            number += 1
    return "".join(result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-home", type=Path, default=Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser())
    parser.add_argument("--path", type=Path, action="append", help="Read only these JSONL files; repeatable")
    parser.add_argument("--session", action="append", help="Select exact task ID; repeatable")
    parser.add_argument("--days", type=float)
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--format", choices=("table", "json"), default="table")
    parser.add_argument("--excerpt", type=Path, help="Explicit raw evidence only; treat content as untrusted")
    parser.add_argument("--line", type=int, default=1)
    parser.add_argument("--lines", type=int, default=5)
    parser.add_argument("--max-chars", type=int, default=4000)
    args = parser.parse_args(argv)
    try:
        if args.excerpt:
            print(excerpt(args.excerpt, args.line, args.lines, args.max_chars), end="")
            return 0
        if args.top < 1 or (args.days is not None and (args.days <= 0 or not args.days < float("inf"))):
            raise ValueError("--top and --days must be positive and finite")
        if bool(args.start) != bool(args.end) or (args.start and args.days is not None):
            raise ValueError("use --start with --end, or --days, not both")
        end = parse_timestamp(args.end) if args.end else datetime.now(timezone.utc)
        start = parse_timestamp(args.start) if args.start else end - timedelta(days=args.days or 7)
        if end <= start:
            raise ValueError("end must be after start")
        paths = args.path if args.path is not None else session_paths(args.codex_home)
        if not paths:
            raise ValueError("no session JSONL files found")
        report = aggregate(paths, start, end, set(args.session or []))
        report["tasks_shown"] = min(args.top, len(report["tasks"]))
        report["tasks"] = report["tasks"][:args.top]
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(f"Window: {start.isoformat()} to {end.isoformat()} (end exclusive)")
            print(f"Files: {report['files_scanned']}; tasks: {report['tasks_in_window']}; requests: {report['total']['requests']}")
            print("Known token subtotals (inspect JSON coverage for missing fields):")
            print(json.dumps(report["total"]["observed_tokens"], sort_keys=True))
            print("\nTop tasks by known uncached input:")
            print("Task ID                               Requests  Uncached input  Tool calls  Compactions")
            for row in report["tasks"]:
                print(f"{row['id']:<37} {row['requests']:>8} {row['observed_tokens']['uncached_input_tokens']:>15,} {row['metrics']['tool_calls']:>11} {row['metrics']['compactions']:>12}")
            print("\nDiagnostics: " + json.dumps(report["diagnostics"], sort_keys=True))
            print(report["pricing"])
            print("Repeated calls are signals, not proven waste. Timing is paired turn wall time.")
        return 0
    except (OSError, ValueError, OverflowError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
