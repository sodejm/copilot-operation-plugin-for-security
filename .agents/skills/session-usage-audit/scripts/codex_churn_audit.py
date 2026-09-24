#!/usr/bin/env python3
"""Local, read-only agent churn and workflow adviser. Python standard library + Git."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sys

import codex_token_usage as tokens
from churn_git import CATEGORIES, Classifier, contract_evidence, git, history, inventory
from churn_sessions import scan

SCHEMA_VERSION = 1
MEASUREMENT_VERSION = "1.0"
DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config/churn.example.json"
USAGE_FIELDS = (*tokens.FIELDS, "uncached_input_tokens")


def read_config(path):
    config = json.loads(Path(path).read_text())
    if not isinstance(config, dict) or config.get("config_version") != 1:
        raise ValueError("configuration must have config_version: 1")
    if not isinstance(config.get("repositories"), list) or not all(isinstance(p, str) for p in config["repositories"]):
        raise ValueError("configuration repositories must be a list of paths")
    for rule in config.get("classification", []):
        if (not isinstance(rule, dict) or rule.get("category") not in CATEGORIES
                or not isinstance(rule.get("patterns"), list) or not all(isinstance(p, str) for p in rule["patterns"])):
            raise ValueError("invalid classification rule")
    for path in config.get("contract_paths", []):
        if not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("contract paths must stay within the repository")
    return config


def usage_view(bucket):
    """Keep known zero distinct from no recorded usage, without changing the helper."""
    return {"requests": bucket["requests"],
            "tokens": {f: bucket["tokens"][f] if bucket["requests"] else None for f in USAGE_FIELDS},
            "observed_tokens": {f: bucket["observed_tokens"][f] if bucket["field_coverage_requests"][f] else None for f in USAGE_FIELDS},
            "field_coverage_requests": dict(bucket["field_coverage_requests"]),
            "scope": "recorded requests only; completeness of task logs is unknown"}


def sum_buckets(buckets):
    result = tokens.new_bucket()
    for row in buckets:
        result["requests"] += row["requests"]
        for f in USAGE_FIELDS:
            result["sums"][f] += row["observed_tokens"][f] or 0
            result["coverage"][f] += row["field_coverage_requests"][f]
    return tokens.finish_bucket(result)


def token_group(task):
    if task["unresolved_edit_paths"]:
        return "shared_or_unresolved"
    return task["repo_ids"][0] if len(task["repo_ids"]) == 1 else "shared_multiple_repositories"


def agent_metrics(tasks, rid=None, start=None, end=None):
    selected = [t for t in tasks if rid is None or rid in t["repo_ids"]]
    edits = [(t["id"], e) for t in selected for e in t["edits"]
             if (rid is None or e["repo_id"] == rid)
             and (start is None or start <= tokens.parse_timestamp(e["timestamp"]) < end)]
    volumes = {c: {"observed_added_lines": 0, "observed_deleted_lines": 0,
                   "confirmed_file_touches": 0, "unknown_added_counts": 0, "unknown_deleted_counts": 0}
               for c in (*CATEGORIES, "unresolved")}
    ops = defaultdict(set)
    touches = Counter()
    for sid, edit in edits:
        ops[edit["outcome"]].add((sid, edit["call_id"], edit["patch_index"]))
        touches[(sid, edit["repo_id"], edit["path"], edit["worktree"])] += 1
        if edit["outcome"] == "confirmed":
            bucket = volumes[edit["category"]]
            bucket["confirmed_file_touches"] += 1
            for kind in ("added", "deleted"):
                value = edit[kind + "_lines"]
                bucket["unknown_" + kind + "_counts"] += int(value is None)
                bucket["observed_" + kind + "_lines"] += value or 0
    checks = [v for t in selected for v in t["validations"]
              if start is None or start <= tokens.parse_timestamp(v["timestamp"]) < end]
    return {"change_volume": volumes, "patch_operations": {k: len(ops[k]) for k in ("confirmed", "failed", "uncertain")},
            "file_touches": len(edits), "repeated_touches": sum(n - 1 for n in touches.values()),
            "validation_outcomes": dict(Counter(v["outcome"] for v in checks)),
            "validation_scope": "associated tasks; checks may also concern another repository",
            "confirmed_agent_rework": None, "rework_status": "complete agent mutation sequences not evidenced",
            "cumulative_to_final_ratio": None,
            "ratio_status": "not computed without complete task-attributed base-to-end sequence"}


def file_snapshot(paths):
    result = {}
    for path in paths:
        try:
            stat = Path(path).stat()
            result[str(path)] = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
        except OSError:
            result[str(path)] = None
    return result


def scoped_accounting(tasks, start, end):
    paths = sorted({p for t in tasks for p in t["paths"]})
    # The legacy helper treats an empty selection as all tasks. Empty paths are
    # intentional when there is no attribution evidence.
    return tokens.aggregate(paths, start, end, {t["id"] for t in tasks})


def classify_edits(tasks, repos, config):
    classifiers = {r["id"]: Classifier(r, config) for r in repos}
    groups = defaultdict(list)
    for task in tasks:
        # Historical attributes when available; otherwise explicitly label HEAD.
        for edit in task["edits"]:
            rid = edit["repo_id"]
            ref = task["git_metadata"].get("commit_hash")
            if rid:
                repo = next(r for r in repos if r["id"] == rid)
                ref = ref if isinstance(ref, str) and len(ref) in (40, 64) and all(c in "0123456789abcdef" for c in ref.lower()) else "HEAD"
                groups[(rid, ref)].append(edit)
            else:
                edit["category"], edit["classification_basis"] = "unresolved", "unresolved repository path"
    for (rid, ref), edits in groups.items():
        classifier = classifiers[rid]
        if git(classifier.repo["path"], "cat-file", "-e", ref + "^{commit}", check=False) is None:
            ref = "HEAD"
        classifier.prime([e["path"] for e in edits], ref)
        for edit in edits:
            edit["category"], edit["classification_basis"] = classifier.classify(edit["path"], ref)
            edit["classification_ref"] = ref


def opportunities(tasks, repos, config):
    candidates = []
    for repo in repos:
        for reversal in repo["git_history"]["rework"]:
            # A filename match cannot establish authorship, branch, or timing.
            candidates.append((2, 0, repo, None, None, reversal))
    for task in tasks:
        for hotspot in task["hotspots"]:
            if hotspot["repo_id"] and hotspot["repeated_touches"] >= 2:
                repo = next(r for r in repos if r["id"] == hotspot["repo_id"])
                candidates.append((1, hotspot["repeated_touches"], repo, task, hotspot, None))
    # Corroborated immutable state evidence first; tokens only break ties.
    candidates.sort(key=lambda c: (c[0], c[1], (c[3] or {}).get("associated_usage", {}).get("observed_tokens", {}).get("uncached_input_tokens") or 0,
                                   c[2]["id"], (c[4] or c[5])["path"]), reverse=True)
    result, seen = [], set()
    for strength, _, repo, task, hotspot, reversal in candidates:
        path = (hotspot or reversal)["path"]
        key = (repo["id"], path)
        if key in seen:
            continue
        seen.add(key)
        ref = task["git_metadata"].get("commit_hash") if task else None
        if reversal:
            parent = git(repo["path"], "rev-parse", "--verify", reversal["earlier_commit"] + "^", check=False)
            ref = parent.decode().strip() if parent else None
        historical = contract_evidence(repo, ref, config)
        historical["scope"] = "task-start commit" if task else "commit preceding Git change; task attribution not evidenced"
        category = reversal["category"] if reversal else next((e["category"] for e in task["edits"] if e["path"] == path and e["repo_id"] == repo["id"]), "unclassified")
        failed = hotspot and hotspot["outcomes"].get("failed", 0)
        if failed:
            topic = "acceptance"
            explanation = "Stale patch context or an incorrect starting-state assumption may have caused retries; concurrent edits and normal iteration are also plausible."
            prevention = "In the existing task plan and acceptance criteria, record the starting commit, expected file state, and a focused preflight check before preparing the patch. Re-read the changed context after a failed attempt."
        elif category == "documentation":
            topic = "scope"
            explanation = "Scope or terminology may have changed during the task; the recorded pattern alone does not show that the edits were avoidable."
            prevention = "Settle scope, non-goals, and domain terminology in the existing issue or planning section before implementation; record a reason before revising an agreed term."
        elif category == "tests" or (task and task["validation_retries"]):
            topic = "acceptance"
            explanation = "An untested failure case or late validation may explain some iteration; ordinary test-driven development remains a plausible explanation."
            prevention = "Add the relevant failure case and its expected behavior to existing acceptance criteria; run the smallest check that tests the assumption before expanding the implementation."
        else:
            topic = "interfaces"
            explanation = "An interface or behavior assumption may have been revised; neither code reversal nor repeated editing establishes the reason or avoidability."
            prevention = "In the existing design or task plan, agree on inputs, outputs, invariants, ownership, and failure behavior before editing this boundary. Validate the riskiest assumption with a small check first."
        sections = [s for s in historical["sections"] if s["section"] == topic]
        evidence = (reversal["evidence"] if reversal else []) + (hotspot["evidence"] if hotspot else [])
        result.append({"priority": len(result) + 1, "repo_id": repo["id"], "repository": repo["name"], "path": path,
            "task_id": task["id"] if task else None, "kind": "verified_git_state_reversal" if reversal else "repeated_edit_candidate",
            "observed_pattern": ("An ordered first-parent Git history returns the whole file to its immediately preceding state. Agent authorship is not established."
                                 if reversal else f"{hotspot['edit_operations']} recorded edit operations touch this file within one task; outcomes: {hotspot['outcomes']}."),
            "agent_attribution": "not evidenced for Git reversal" if reversal else "explicit recorded edit paths",
            "plausible_explanation": explanation, "prevention_step": prevention,
            "existing_section_targets": sections,
            "target_status": "historical section located; task-specific adequacy unassessed" if sections else "not evidenced; use the existing task plan or issue section",
            "task_start_contract": task["task_start_contract"] if task else {"status": "not evidenced"},
            "historical_contract": historical, "associated_usage": task["associated_usage"] if task else None,
            "usage_scope": "entire task in the window; not assigned to this file or estimated as waste",
            "evidence": evidence[:6], "manual_review_status": "requires bounded evidence review before drawing a causal conclusion"})
        if len(result) == 3:
            break
    return result


def comparison(report, prior):
    reasons = []
    if prior.get("inputs", {}).get("session_mode", "codex") != report["inputs"].get("session_mode", "codex"):
        reasons.append("session evidence modes differ")
    if prior.get("schema_version") != SCHEMA_VERSION or prior.get("measurement_version") != MEASUREMENT_VERSION:
        reasons.append("schema or measurement version differs")
    if prior.get("measurement_config_hash") != report["measurement_config_hash"]:
        reasons.append("classification or contract configuration differs")
    if {r["id"] for r in prior.get("repositories", [])} != {r["id"] for r in report["repositories"]}:
        reasons.append("repository common-directory identities differ")
    elif {r["id"]: r["path"] for r in prior.get("repositories", [])} != {r["id"]: r["path"] for r in report["repositories"]}:
        reasons.append("configured primary checkouts differ")
    try:
        def bounds(r):
            return (tokens.parse_timestamp(r["window"]["start_inclusive"]), tokens.parse_timestamp(r["window"]["end_exclusive"]))
        a, b = bounds(prior), bounds(report)
        if a[1] - a[0] != b[1] - b[0]:
            reasons.append("window durations differ")
        overlap = max(0, (min(a[1], b[1]) - max(a[0], b[0])).total_seconds())
    except (ValueError, KeyError, TypeError):
        reasons.append("prior report window is invalid")
        overlap = None
    result = {"compatible": not reasons, "incompatibilities": reasons, "overlapping_window_seconds": overlap,
              "interpretation": "descriptive comparison only; task mix, coverage, and overlapping windows can explain changes",
              "before": prior.get("summary"), "after": report["summary"], "metric_deltas": None}
    def measurements(value):
        return {"associated_usage": value.get("associated_usage"),
                "agent_change_volume": value.get("agent_metrics", {}).get("change_volume"),
                "git_by_repository": {r["id"]: {k: (r["git_history"].get("primary") or {}).get(k)
                    for k in ("change_volume", "final_change_size", "volume_coverage", "verified_contiguous_range")}
                    for r in value.get("repositories", [])}}
    result["measurements_before"], result["measurements_after"] = measurements(prior), measurements(report)
    if not reasons:
        result["metric_deltas"] = {k: report["summary"][k] - prior["summary"][k]
                                   for k in ("tasks", "tasks_with_recorded_usage", "file_touches", "repeated_touches", "failed_patch_operations", "verified_git_reversals")}
        result["recorded_token_deltas"] = {f: (report["associated_usage"]["tokens"][f] - prior["associated_usage"]["tokens"][f])
            if report["associated_usage"]["tokens"][f] is not None and prior["associated_usage"]["tokens"][f] is not None else None
            for f in USAGE_FIELDS}
    return result


def build_report(paths, repo_paths, start, end, config, progress=lambda message: None, session_mode="codex"):
    if session_mode not in ("codex", "git_only") or (session_mode == "git_only" and paths):
        raise ValueError("invalid session evidence mode or session inputs")
    before = file_snapshot(paths)
    repos = inventory(repo_paths)
    progress(f"Reading {len(paths)} session files; repositories: {len(repos)}")
    tasks, diagnostics, unattributed = scan(paths, start, end, repos)
    progress(f"Reconciling original token accounting for {len(tasks)} attributed tasks")
    accounting = scoped_accounting(tasks, start, end)
    by_id = {t["id"]: t for t in accounting["tasks"]}
    zero = tokens.finish_bucket(tokens.new_bucket())
    for task in tasks:
        row = by_id.get(task["id"], zero)
        task["associated_usage"] = usage_view(row)
        task["token_evidence"] = row.get("evidence", [])
        task["token_group"] = token_group(task)
        task["recorded_task_metrics"] = row.get("metrics", {})
    reconciled = sum_buckets([t["associated_usage"] for t in tasks])
    if reconciled != accounting["total"]:
        raise ValueError("task token totals do not reconcile with the original helper")
    classify_edits(tasks, repos, config)
    allocations = []
    for group in sorted({t["token_group"] for t in tasks}):
        grouped = [t for t in tasks if t["token_group"] == group]
        allocations.append({"group": group, "tasks": len(grouped), "usage": usage_view(sum_buckets([t["associated_usage"] for t in grouped]))})
    for repo in repos:
        progress("Measuring independent Git histories: " + repo["name"])
        repo["git_history"] = history(repo, start, end, config)
        repo["agent_metrics"] = agent_metrics(tasks, repo["id"])
        repo["associated_tasks"] = sum(repo["id"] in t["repo_ids"] for t in tasks)
        repo["task_categories"] = dict(Counter(t["category"] for t in tasks if repo["id"] in t["repo_ids"]))
        repo.pop("_remotes")
    metrics = agent_metrics(tasks)
    summary = {"tasks": len(tasks), "tasks_with_recorded_usage": sum(t["associated_usage"]["requests"] > 0 for t in tasks),
               "task_categories": dict(sorted(Counter(t["category"] for t in tasks).items())),
               "model_mix": {m: usage_view(b) for m, b in accounting["by_model"].items()},
               "file_touches": metrics["file_touches"], "repeated_touches": metrics["repeated_touches"],
               "failed_patch_operations": metrics["patch_operations"]["failed"],
               "verified_git_reversals": sum(len(r["git_history"]["rework"]) for r in repos),
               "coverage": {"confirmed_patch_operations": metrics["patch_operations"]["confirmed"],
                            "uncertain_patch_operations": metrics["patch_operations"]["uncertain"],
                            "unsupported_edit_calls": sum(t["unsupported_edit_calls"] for t in tasks),
                            "opaque_calls": sum(t["opaque_calls"] for t in tasks),
                            "unresolved_edit_paths": sum(t["unresolved_edit_paths"] for t in tasks),
                            "tasks_with_partial_records": sum(t["coverage"]["malformed_records"] > 0 for t in tasks),
                            "tasks_starting_before_window": sum(t["coverage"]["starts_before_window"] for t in tasks),
                            "complete_agent_sequences": 0, "task_log_completeness": "unknown"}}
    weeks = []
    cursor = start
    while cursor < end:
        finish = min(end, cursor + timedelta(days=7))
        progress("Weekly accounting: " + cursor.date().isoformat())
        weekly = scoped_accounting(tasks, cursor, finish)
        active_ids = {t["id"] for t in weekly["tasks"]}
        active_ids.update(t["id"] for t in tasks if any(cursor <= tokens.parse_timestamp(e["timestamp"]) < finish for e in t["edits"]))
        git_weeks = {}
        for repo in repos:
            primary = repo["git_history"]["primary"]
            ids = set(primary["commit_ids"]) if primary else set()
            rows = [c for c in repo["git_history"].get("commit_summaries", []) if c["commit"] in ids and cursor <= tokens.parse_timestamp(c["timestamp"]) < finish]
            git_weeks[repo["id"]] = {"primary_commits": len(rows), "change_volume": {
                c: {f: sum(r["change_volume"][c][f] for r in rows) for f in ("added_lines", "deleted_lines", "binary_or_unknown_files")} for c in CATEGORIES}}
        weeks.append({"window": weekly["window"], "tasks": len(active_ids),
                      "task_categories": dict(Counter(t["category"] for t in tasks if t["id"] in active_ids)),
                      "tasks_with_recorded_usage": sum(t["requests"] > 0 for t in weekly["tasks"]),
                      "associated_usage": usage_view(weekly["total"]),
                      "model_mix": {m: usage_view(b) for m, b in weekly["by_model"].items()},
                      "agent_metrics": agent_metrics(tasks, start=cursor, end=finish), "git": git_weeks})
        cursor = finish
    if sum_buckets([w["associated_usage"] for w in weeks]) != accounting["total"]:
        raise ValueError("weekly recorded token totals do not reconcile")
    after = file_snapshot(paths)
    config_hash = tokens.signature({k: v for k, v in config.items() if k != "repositories"})
    report = {"schema_version": SCHEMA_VERSION, "measurement_version": MEASUREMENT_VERSION,
              "window": accounting["window"], "measurement_config_hash": config_hash,
              "summary": summary, "associated_usage": usage_view(accounting["total"]),
              "token_allocation": allocations, "agent_metrics": metrics, "repositories": repos,
              "tasks": tasks, "weekly": weeks, "unattributed_or_out_of_scope_tasks": unattributed,
              "diagnostics": {"sessions": diagnostics, "token_accounting": accounting["diagnostics"]},
              "reconciliation": {"original_helper_totals_match": True, "weekly_token_totals_match": True,
                                 "original_total_sha256": tokens.signature(accounting["total"])},
              "inputs": {"session_mode": session_mode, "session_files_scanned": len(before), "session_inventory_sha256": tokens.signature(before),
                         "changed_during_audit": sorted(p for p in before if before[p] != after.get(p)),
                         "repository_identity": "shared Git common directory; worktrees and identical commits deduplicated",
                         "reproducibility": "fixed window, configuration, Git objects/refs and attribute overrides, and unchanged session inputs required"},
              "limits": ["Git and confirmed agent line volumes overlap; never add them together.",
                         "Git lineages overlap and are never summed as a repository change volume. Commit IDs are deduplicated; rewritten equivalent commits remain in separate lineages.",
                         "Repeated edits and exact Git state reversals do not establish avoidability or agent authorship of Git commits.",
                         "Agent rework and cumulative-to-final ratios require a complete task-attributed mutation sequence, which these logs do not establish.",
                         "Opaque scripts, ambiguous results, missing events, binary changes, and full-file deletions with no body reduce coverage.",
                         "Task categories use source metadata. User-origin tasks may include coding or other work; unknown stays unknown.",
                         "Tokens are recorded associated usage, not file-level cost, wasted tokens, charges, or estimated savings. Shared tasks are counted once.",
                         "Tasks with no evidence linking selected repositories are listed separately and excluded from scoped totals.",
                         "Historical contract section signals do not establish that a task had an adequate contract; absence is not evidenced.",
                         "Git reflects committed states, not uncommitted edits; final sizes use verified first-parent base/end ranges."]}
    report["opportunities"] = opportunities(tasks, repos, config)
    return report


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("`", "'")


def number(value):
    return f"{value:,}" if value is not None else "unknown"


def volume_total(volume, field):
    return sum(v[field] for v in volume.values()) if volume is not None else None


def evidence_text(pointer):
    if "line" in pointer:
        return f"{cell(pointer['path'])}:{pointer['line']}"
    return f"{cell(pointer.get('repo', ''))} @ {pointer.get('commit', '')} : {cell(pointer.get('path', ''))}"


def markdown(report):
    s, usage = report["summary"], report["associated_usage"]
    session_note = ("No session files were read; agent activity and token usage are unknown."
                    if report["inputs"].get("session_mode") == "git_only" else
                    "Codex session evidence only; missing or unsupported activity remains unknown.")
    lines = ["# Local agent churn audit", "", f"Window: {report['window']['start_inclusive']} to {report['window']['end_exclusive']} (end exclusive).",
             "", f"{s['tasks']} attributed tasks; {s['tasks_with_recorded_usage']} with recorded usage. {usage['requests']:,} recorded requests.",
             session_note,
             "Git history and confirmed agent edits are overlapping views and are not added together.", "",
             "## Repository overview", "", "| Repository | Registered worktrees | Associated tasks* | Git primary + / − | Confirmed agent observed + / − | Confirmed / failed / uncertain patches |",
             "|---|---:|---:|---|---|---|"]
    for repo in report["repositories"]:
        primary = repo["git_history"]["primary"]
        vol = primary["change_volume"] if primary else None
        agent = repo["agent_metrics"]
        ops = agent["patch_operations"]
        lines.append(f"| {cell(repo['name'])} | {len(repo['worktrees'])} | {repo['associated_tasks']} | {number(volume_total(vol, 'added_lines'))} / {number(volume_total(vol, 'deleted_lines'))} | {volume_total(agent['change_volume'], 'observed_added_lines'):,} / {volume_total(agent['change_volume'], 'observed_deleted_lines'):,} | {ops['confirmed']} / {ops['failed']} / {ops['uncertain']} |")
    lines += ["", "*A shared task appears in each associated repository's task count. Its tokens appear once in the allocation below. Git primary is the configured checkout's first-parent history; other branches remain separate in JSON. No in-window primary range is shown as unknown.",
              "", "## Recorded token usage", "", "| Field | Known subtotal | Requests with field |", "|---|---:|---:|"]
    for f in ("input_tokens", "cached_input_tokens", "uncached_input_tokens", "output_tokens"):
        lines.append(f"| {f} | {number(usage['observed_tokens'][f])} | {usage['field_coverage_requests'][f]} / {usage['requests']} |")
    lines += ["", "These are associated tokens for recorded requests. Missing task usage remains unknown; they are not estimated waste or savings.",
              "", "| Token allocation | Tasks | Known uncached input | Known output |", "|---|---:|---:|---:|"]
    names = {r["id"]: r["name"] for r in report["repositories"]}
    for group in report["token_allocation"]:
        u = group["usage"]["observed_tokens"]
        lines.append(f"| {cell(names.get(group['group'], group['group']))} | {group['tasks']} | {number(u['uncached_input_tokens'])} | {number(u['output_tokens'])} |")
    lines += ["", "## File categories and final change size", "", "| Repository | Category | Git primary + / − | Git base-to-end + / − | Confirmed agent observed + / − | Unknown agent counts |", "|---|---|---|---|---|---:|"]
    for repo in report["repositories"]:
        primary = repo["git_history"]["primary"]
        for c in CATEGORIES:
            cum = primary["change_volume"][c] if primary else {}
            final = (primary.get("final_change_size") or {}).get(c, {}) if primary else {}
            a = repo["agent_metrics"]["change_volume"][c]
            lines.append(f"| {cell(repo['name'])} | {c} | {number(cum.get('added_lines'))} / {number(cum.get('deleted_lines'))} | {number(final.get('added_lines'))} / {number(final.get('deleted_lines'))} | {a['observed_added_lines']:,} / {a['observed_deleted_lines']:,} | {a['unknown_added_counts'] + a['unknown_deleted_counts']} |")
    lines += ["", "Git totals exclude binary/unknown line counts, which are recorded in JSON. Agent values are observed confirmed-patch subtotals only. Full-file deletion sizes can remain unknown. No cumulative-to-final ratio is inferred.",
              "", "## Task and file hotspots", "", "| Task | Repository / file | Operations | Repeated touches | Confirmed / failed / uncertain |", "|---|---|---:|---:|---|"]
    hotspots = sorted(((t, h) for t in report["tasks"] for h in t["hotspots"]), key=lambda pair: (-pair[1]["repeated_touches"], pair[0]["id"], pair[1]["path"]))[:10]
    for task, h in hotspots:
        o = h["outcomes"]
        lines.append(f"| {task['id']} | {cell(names.get(h['repo_id'], 'unresolved'))} / {cell(h['path'])} | {h['edit_operations']} | {h['repeated_touches']} | {o.get('confirmed', 0)} / {o.get('failed', 0)} / {o.get('uncertain', 0)} |")
    lines += ["", "Repetition is a candidate for investigation. It can be legitimate iteration, testing, or exploration.", "", "## Prioritized workflow opportunities", ""]
    if not report["opportunities"]:
        lines.append("No supported opportunity met the minimum evidence rule in this window. Do not infer that churn is absent.")
    for item in report["opportunities"]:
        lines += [f"### {item['priority']}. {cell(item['repository'])}: {cell(item['path'])}", "", item["observed_pattern"], "", item["plausible_explanation"], "", "Prevention: " + item["prevention_step"], "", "Contract evidence: " + item["target_status"] + "."]
        for target in item["existing_section_targets"][:2]:
            lines.append(f"Existing {target['section']} section: `{cell(target['path'])}:{target['line']}` at `{target['commit']}`.")
        if item["associated_usage"]:
            lines.append(f"Associated task uncached input: {number(item['associated_usage']['observed_tokens']['uncached_input_tokens'])}. {item['usage_scope']}.")
        lines += ["", "Evidence:", ""] + ["- `" + evidence_text(p) + "`" for p in item["evidence"]] + [""]
    lines += ["## Weekly breakdown", "", "| Week starting UTC | Tasks* | With usage | Confirmed / failed / uncertain patches | Known uncached input | Known output |", "|---|---:|---:|---|---:|---:|"]
    for week in report["weekly"]:
        u, o = week["associated_usage"]["observed_tokens"], week["agent_metrics"]["patch_operations"]
        lines.append(f"| {week['window']['start_inclusive']} | {week['tasks']} | {week['tasks_with_recorded_usage']} | {o['confirmed']} / {o['failed']} / {o['uncertain']} | {number(u['uncached_input_tokens'])} | {number(u['output_tokens'])} |")
    lines += ["", "*Tasks can span weeks; weekly task counts are not additive. Weekly recorded token totals reconcile with the full window. JSON also contains weekly Git volumes, task categories, model mix, and field coverage.", "", "## Coverage and interpretation", "", "Task categories: " + cell(json.dumps(s["task_categories"], sort_keys=True)), "", "Model mix (recorded requests): " + cell(json.dumps({m: u['requests'] for m, u in s['model_mix'].items()}, sort_keys=True)), ""]
    lines += [f"- {cell(k)}: {cell(v)}" for k, v in sorted(s["coverage"].items())]
    lines += ["", f"Tasks without selected-repository attribution: {len(report['unattributed_or_out_of_scope_tasks'])}; listed separately in JSON.",
              f"Session files changed during audit: {len(report['inputs']['changed_during_audit'])}.",
              "Diagnostics: " + cell(json.dumps(report["diagnostics"], sort_keys=True)), ""]
    lines += ["- " + item for item in report["limits"]]
    if "comparison" in report:
        c = report["comparison"]
        lines += ["", "## Saved-report comparison", "", "Compatible measurement: " + str(c["compatible"]) + ".", "", c["interpretation"], ""]
        lines += ["- " + reason for reason in c["incompatibilities"]]
        lines += ["", "```json", json.dumps(c, indent=2, sort_keys=True), "```"]
    lines += ["", f"Report schema {SCHEMA_VERSION}; measurement {MEASUREMENT_VERSION}. No raw source or transcript bodies are included.", ""]
    return "\n".join(lines)


def save_reports(report, output_dir):
    output_dir = Path(output_dir).expanduser().resolve()
    # Prevent reports from mutating an audited source repository or session tree.
    protected = [Path(w["worktree"]).resolve() for r in report["repositories"] for w in r["worktrees"]]
    protected += [Path(r["common_git_dir"]).resolve() for r in report["repositories"]]
    for root in protected:
        if output_dir == root or root in output_dir.parents:
            raise ValueError("output directory must be outside audited repositories and Git directories")
    payload = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    key = hashlib.sha256(payload.encode()).hexdigest()[:12]
    start = tokens.parse_timestamp(report["window"]["start_inclusive"]).strftime("%Y%m%dT%H%M%SZ")
    end = tokens.parse_timestamp(report["window"]["end_exclusive"]).strftime("%Y%m%dT%H%M%SZ")
    stem = f"churn-v{SCHEMA_VERSION}-{start}-{end}-{key}"
    output_dir.mkdir(parents=True, exist_ok=True)
    result = {}
    for suffix, body in (("json", payload), ("md", markdown(report))):
        path = output_dir / (stem + "." + suffix)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(body)
        except FileExistsError:
            if path.read_text() != body:
                raise ValueError("existing report differs; refusing overwrite")
        result[suffix] = str(path)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", action="append", help="Repository or linked worktree; repeatable; overrides configured defaults")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG,
                        help="Classification and repository configuration; bundled example has no repository defaults")
    parser.add_argument("--git-only", action="store_true", help="Use Git evidence without discovering or reading agent sessions")
    parser.add_argument("--codex-home", type=Path, help="Codex session root; defaults to CODEX_HOME or ~/.codex")
    parser.add_argument("--path", action="append", type=Path, help="Explicit session JSONL files; repeatable")
    parser.add_argument("--days", type=float)
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output-dir", type=Path, default=Path.cwd() / "outputs")
    parser.add_argument("--compare", type=Path, help="Saved versioned JSON report")
    args = parser.parse_args(argv)
    try:
        if args.git_only and (args.path is not None or args.codex_home is not None):
            raise ValueError("--git-only cannot be combined with --path or --codex-home")
        if args.days is not None and (args.days <= 0 or not math.isfinite(args.days)):
            raise ValueError("--days must be positive and finite")
        if bool(args.start) != bool(args.end) or (args.start and args.days is not None):
            raise ValueError("use --start and --end together, or --days")
        end = tokens.parse_timestamp(args.end) if args.end else datetime.now(timezone.utc)
        start = tokens.parse_timestamp(args.start) if args.start else end - timedelta(days=args.days or 7)
        if end <= start:
            raise ValueError("end must be after start")
        config = read_config(args.config)
        repo_paths = args.repo if args.repo is not None else config["repositories"]
        if not repo_paths:
            raise ValueError("select at least one repository using --repo or --config")
        codex_home = (args.codex_home or Path(os.environ.get("CODEX_HOME", "~/.codex"))).expanduser()
        paths = [] if args.git_only else args.path if args.path is not None else tokens.session_paths(codex_home)
        out = args.output_dir.expanduser().resolve()
        for session_root in (codex_home.resolve() / "sessions", codex_home.resolve() / "archived_sessions"):
            if out == session_root or session_root in out.parents:
                raise ValueError("output directory must be outside source session trees")
        report = build_report(paths, repo_paths, start, end, config,
                              progress=lambda m: print(m, file=sys.stderr, flush=True),
                              session_mode="git_only" if args.git_only else "codex")
        if args.compare:
            report["comparison"] = comparison(report, json.loads(args.compare.read_text()))
        saved = save_reports(report, out)
        print(json.dumps(report, indent=2, sort_keys=True) if args.format == "json" else markdown(report))
        print("Saved: " + ", ".join(saved.values()), file=sys.stderr)
        return 0
    except (OSError, ValueError, OverflowError, KeyError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
