"""Static transcript extraction. Nothing read from a transcript is executed."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path
import re
import shlex

import codex_token_usage as tokens
from churn_git import metadata_repos, resolve_path


def js_tokens(script):
    """Small lexical scanner, deliberately not a JS interpreter.

    Literal strings, comments, identifiers and punctuation suffice to recognize
    direct tool calls. Dynamic template strings are opaque, including their body.
    """
    result, i = [], 0
    while i < len(script):
        c = script[i]
        if c.isspace():
            i += 1
        elif script.startswith("//", i):
            end = script.find("\n", i)
            i = end if end >= 0 else len(script)
        elif script.startswith("/*", i):
            end = script.find("*/", i + 2)
            i = end + 2 if end >= 0 else len(script)
        elif c in "\"'`":
            quote, buf, valid = c, [], True
            i += 1
            closed = False
            while i < len(script):
                c = script[i]
                i += 1
                if c == quote:
                    closed = True
                    break
                if quote == "`" and c == "$" and i < len(script) and script[i] == "{":
                    # Nested templates/expressions need a real JS parser. Do not
                    # accidentally interpret their contents as literal calls.
                    return [("opaque", "")]
                if c == "\\":
                    if i >= len(script):
                        valid = False
                        break
                    esc = script[i]
                    i += 1
                    table = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0",
                             "\\": "\\", "\"": "\"", "'": "'", "`": "`", "$": "$"}
                    if esc in table:
                        buf.append(table[esc])
                    elif esc in ("u", "x"):
                        length = 4 if esc == "u" else 2
                        part = script[i:i + length]
                        if len(part) == length and re.fullmatch(r"[0-9a-fA-F]+", part):
                            buf.append(chr(int(part, 16)))
                            i += length
                        else:
                            valid = False
                    elif esc == "\n":
                        pass
                    else:
                        valid = False
                else:
                    buf.append(c)
            result.append(("string" if valid and closed else "opaque", "".join(buf)))
        elif c.isalpha() or c in "_$":
            end = i + 1
            while end < len(script) and (script[end].isalnum() or script[end] in "_$"):
                end += 1
            result.append(("id", script[i:end]))
            i = end
        elif c.isdigit():
            end = i + 1
            while end < len(script) and script[end].isdigit():
                end += 1
            result.append(("number", script[i:end]))
            i = end
        elif c == "/":
            # Regex literals can contain tool-looking text. Reject ambiguity.
            return [("opaque", "")]
        else:
            result.append(("punct", c))
            i += 1
    return result


def static_calls(script):
    items = js_tokens(script)
    bindings, declarations = {}, Counter()
    for i in range(len(items) - 4):
        if items[i] == ("id", "const") and items[i + 1][0] == "id":
            name = items[i + 1][1]
            declarations[name] += 1
            if items[i + 2][1] == "=" and items[i + 3][0] == "string" and items[i + 4][1] == ";":
                bindings[name] = items[i + 3][1]
    bindings = {k: v for k, v in bindings.items() if declarations[k] == 1}

    def literal(i):
        kind, value = items[i] if i < len(items) else ("", "")
        if kind == "string":
            return value, i + 1
        if kind == "id" and value in bindings:
            return bindings[value], i + 1
        if kind == "number":
            return int(value), i + 1
        if kind == "id" and value in ("true", "false", "null"):
            return {"true": True, "false": False, "null": None}[value], i + 1
        if value == "{":
            obj, i = {}, i + 1
            while i < len(items) and items[i][1] != "}":
                if items[i][0] not in ("id", "string") or i + 1 >= len(items) or items[i + 1][1] != ":":
                    raise ValueError("dynamic object")
                key = items[i][1]
                obj[key], i = literal(i + 2)
                if i < len(items) and items[i][1] == ",":
                    i += 1
                elif i >= len(items) or items[i][1] != "}":
                    raise ValueError("dynamic object")
            if i >= len(items):
                raise ValueError("unclosed object")
            return obj, i + 1
        raise ValueError("dynamic argument")

    calls = []
    for i in range(len(items) - 4):
        if items[i] != ("id", "tools") or items[i + 1][1] != "." or items[i + 2][0] != "id" or items[i + 3][1] != "(":
            continue
        name, argument = items[i + 2][1], None
        try:
            argument, end = literal(i + 4)
            if end >= len(items) or items[end][1] != ")":
                argument = None
        except (ValueError, RecursionError):
            pass
        calls.append({"name": name, "argument": argument})
    return calls


def ambiguous_script(script):
    """Recovered literals do not prove execution through control flow or aliases."""
    items = js_tokens(script)
    forbidden = {"if", "else", "for", "while", "switch", "function", "return", "throw",
                 "try", "catch", "finally", "class", "eval", "let", "var"}
    if any(k == "opaque" or (k == "id" and v in forbidden) for k, v in items):
        return True
    if any(items[i][1] == "=" and items[i + 1][1] == ">" for i in range(len(items) - 1)):
        return True
    if any(k == "punct" and v in ("?", "&", "|") for k, v in items):
        return True
    # Never recover a binding from a later statement or from a shadowed tool object.
    first_call = next((i for i, token in enumerate(items) if token == ("id", "tools")), len(items))
    return any(token == ("id", "const") and (i > first_call or (i + 1 < len(items) and items[i + 1] == ("id", "tools")))
               for i, token in enumerate(items))


def extract_calls(payload):
    name = str(payload.get("name", "")).split(".")[-1]
    value = payload.get("arguments", payload.get("input", ""))
    if name == "apply_patch":
        if isinstance(value, str) and value.lstrip().startswith("*** Begin Patch"):
            return [{"name": name, "argument": value}], False
        try:
            obj = json.loads(value) if isinstance(value, str) else value
            return [{"name": name, "argument": obj.get("patch", obj.get("input")) if isinstance(obj, dict) else obj}], False
        except (ValueError, RecursionError):
            return [{"name": name, "argument": None}], False
    if name in ("exec", "exec_command"):
        if name == "exec_command":
            try:
                return [{"name": name, "argument": json.loads(value) if isinstance(value, str) else value}], False
            except (ValueError, RecursionError):
                return [{"name": name, "argument": None}], True
        if isinstance(value, str):
            # Some exporters wrap the script in {code: ...}.
            try:
                obj = json.loads(value)
                if isinstance(obj, dict) and isinstance(obj.get("code"), str):
                    value = obj["code"]
            except (ValueError, RecursionError):
                pass
            calls = static_calls(value)
            return calls, not calls or ambiguous_script(value) or any(c["argument"] is None for c in calls)
    return [], True


def parse_patch(patch):
    if not isinstance(patch, str):
        raise ValueError("nonliteral patch")
    lines = patch.splitlines()
    if not lines or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise ValueError("unsupported patch envelope")
    files, current = [], None
    for line in lines[1:-1]:
        match = re.match(r"^\*\*\* (Add|Update|Delete) File: (.+)$", line)
        if match:
            current = {"operation": match[1].lower(), "path": match[2], "added_lines": 0,
                       "deleted_lines": None if match[1] == "Delete" else 0, "_plus": [], "_minus": [], "_context": []}
            files.append(current)
        elif current is None:
            raise ValueError("missing file header")
        elif line.startswith("*** Move to: "):
            current["move_to"] = line[len("*** Move to: "):]
        elif line.startswith("+"):
            current["added_lines"] += 1
            current["_plus"].append(line[1:])
        elif line.startswith("-") and current["operation"] == "update":
            current["deleted_lines"] += 1
            current["_minus"].append(line[1:])
        elif line.startswith(" ") or line.startswith("@@"):
            current["_context"].append(line)
        elif line == "*** End of File":
            current["_context"].append(line)
        else:
            raise ValueError("unsupported patch body")
    if not files:
        raise ValueError("empty patch")
    for row in files:
        row["_forward"] = tokens.signature([row["_minus"], row["_plus"], row["_context"]])
        row["_reverse"] = tokens.signature([row["_plus"], row["_minus"], row["_context"]])
        for key in ("_plus", "_minus", "_context"):
            del row[key]
    return files


def output_parts(value):
    """Flatten tool result text/JSON, keeping it private to extraction."""
    if isinstance(value, str):
        yield value
        try:
            decoded = json.loads(value)
            if isinstance(decoded, (dict, list)):
                yield from output_parts(decoded)
        except (ValueError, RecursionError):
            pass
    elif isinstance(value, list):
        for item in value:
            yield from output_parts(item)
    elif isinstance(value, dict):
        yield value
        for key in ("text", "output", "content", "result"):
            if key in value:
                yield from output_parts(value[key])


def patch_outcome(outputs, single):
    text = "\n".join(p for value in outputs for p in output_parts(value) if isinstance(p, str))
    if not single:
        return "uncertain", "multiple nested calls lack individual result identity"
    failed = re.search(r"apply_patch verification failed|Failed to apply patch|Invalid patch|invalid patch|patch rejected", text)
    if failed and "Success. Updated the following files:" in text:
        return "uncertain", "conflicting patch results"
    if failed:
        return "failed", "explicit patch failure"
    if "Success. Updated the following files:" in text and not re.search(r"Script failed|verification failed", text):
        return "confirmed", "explicit apply_patch success"
    return "uncertain", "no explicit patch result" if outputs else "missing tool result"


def validation(argument):
    if not isinstance(argument, dict) or not isinstance(argument.get("cmd"), str):
        return None
    cmd = argument["cmd"]
    if any(char in cmd for char in "\n;|&><`$"):
        return None
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return None
    if not argv:
        return None
    program = Path(argv[0]).name
    if program not in ("make", "npm", "pnpm", "yarn", "uv", "python", "python3", "pytest", "cargo", "go", "ruff"):
        return None
    if not any(re.search(r"(^|[:/_-])(test|tests|check|lint|typecheck|pytest|unittest)([:/_-]|$)", arg) for arg in argv):
        return None
    return {"signature": tokens.signature([argv, argument.get("workdir")]), "program": program,
            "workdir": argument.get("workdir")}


def validation_outcome(outputs, single):
    if not single:
        return None
    codes = set()
    for value in outputs:
        for part in output_parts(value):
            if isinstance(part, dict) and isinstance(part.get("exit_code"), int):
                codes.add(part["exit_code"])
            elif isinstance(part, str):
                codes.update(int(n) for n in re.findall(r"Process exited with code (\d+)", part))
    return next(iter(codes)) if len(codes) == 1 else None


def summarize_output(value):
    """Discard transcript bodies as soon as result markers have been read."""
    status, _ = patch_outcome([value], True)
    result = {"text": "Success. Updated the following files:" if status == "confirmed" else
                      "apply_patch verification failed" if status == "failed" else ""}
    code = validation_outcome([value], True)
    if code is not None:
        result["exit_code"] = code
    return result


def task_category(source):
    source = source.lower() if isinstance(source, str) else "unknown"
    if "review" in source:
        return "automatic_review" if "auto" in source else "review"
    if any(term in source for term in ("setup", "environment")):
        return "environment_setup"
    return "coding_or_other_user_task" if source == "user" else "unknown"


def scan(paths, start, end, repos):
    tasks, calls, results = {}, {}, defaultdict(list)
    diagnostics, seen_records = Counter(), {}
    for path in sorted(set(map(Path, paths))):
        sid, cwd, created, fork, own_context, model = path.stem, None, None, False, False, "unknown"
        task = None
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError:
            diagnostics["unreadable_session_files"] += 1
            continue
        with handle:
            for number, line in enumerate(handle, 1):
                pointer = {"path": str(path), "line": number}
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError("record")
                    p = record["payload"]
                    if not isinstance(p, dict):
                        raise ValueError("payload")
                    when = tokens.parse_timestamp(record.get("timestamp"))
                except (ValueError, KeyError, TypeError, RecursionError):
                    diagnostics["malformed_or_undated_records"] += 1
                    if task:
                        task["_gaps"].append(pointer)
                    continue
                kind = record.get("type")
                if kind == "session_meta":
                    sid = str(p.get("id") or p.get("session_id") or sid)
                    cwd = p.get("cwd")
                    try:
                        created = tokens.parse_timestamp(p.get("timestamp", record.get("timestamp")))
                    except ValueError:
                        created = None
                    fork = bool(p.get("parent_thread_id") or p.get("forked_from_id"))
                    source = p.get("thread_source", "unknown")
                    task = tasks.setdefault(sid, {"id": sid, "source": source, "category": task_category(source),
                        "repo_ids": set(), "paths": set(), "created": created.isoformat() if created else None,
                        "git_metadata": {k: v for k, v in (p.get("git") or {}).items() if k in ("commit_hash", "branch", "repository_url")} if isinstance(p.get("git"), dict) else {},
                        "models": set(),
                        "edits": [], "validations": [], "_gaps": [], "_active": False,
                        "task_start_contract": {"status": "not evidenced", "section_signals": []},
                        "unresolved_edit_paths": 0, "unsupported_edit_calls": 0, "opaque_calls": 0})
                    task["paths"].add(str(path))
                    task["repo_ids"].update(metadata_repos(cwd, task["git_metadata"].get("repository_url"), repos))
                    continue
                if task is None:
                    diagnostics["records_without_session_metadata"] += 1
                    continue
                if p.get("thread_id") and str(p["thread_id"]) != sid:
                    diagnostics["foreign_thread_records_ignored"] += 1
                    continue
                if fork and (created is None or when < created or (not own_context and kind not in ("turn_context", "token_usage_record"))):
                    diagnostics["inherited_or_ambiguous_fork_records_ignored"] += 1
                    continue
                if kind == "turn_context":
                    cwd = p.get("cwd", cwd)
                    model = str(p.get("model") or "unknown")
                    own_context = True
                    if when < end:
                        task["repo_ids"].update(metadata_repos(cwd, None, repos))
                    continue
                if (kind == "response_item" and p.get("type") == "message" and p.get("role") == "user"
                        and created and 0 <= (when - created).total_seconds() <= 300 and when < end
                        and task["task_start_contract"]["status"] == "not evidenced"):
                    body = "\n".join(x for x in output_parts(p.get("content")) if isinstance(x, str))[:12000]
                    signals = [name for name, pattern in (("scope", r"\bscope\b|non.goals"),
                               ("interfaces", r"\binvariants?\b|\binterfaces?\b"),
                               ("acceptance", r"acceptance criteria|failure cases|validation plan")) if re.search(pattern, body, re.I)]
                    if signals:
                        task["task_start_contract"] = {"status": "recorded section signals; completeness unassessed",
                            "section_signals": signals, "evidence": pointer}
                if not start <= when < end:
                    continue
                task["_active"] = True
                task["models"].add(model)
                if kind != "response_item":
                    continue
                item_type = p.get("type")
                cid = str(p.get("call_id") or tokens.signature([when.isoformat(), p]))
                key = (sid, item_type, cid)
                # Multiple yielded output records may share call_id; dedup their bodies.
                if item_type in ("function_call_output", "custom_tool_call_output"):
                    key += (tokens.signature(p.get("output")),)
                if key in seen_records:
                    if seen_records[key] != tokens.signature(p):
                        diagnostics["conflicting_tool_records"] += 1
                        task["_gaps"].append(pointer)
                        if (sid, cid) in calls:
                            calls[(sid, cid)]["opaque"] = True
                    else:
                        diagnostics["duplicate_tool_records_ignored"] += 1
                    continue
                if item_type in ("function_call", "custom_tool_call", "function_call_output", "custom_tool_call_output"):
                    seen_records[key] = tokens.signature(p)
                if item_type in ("function_call", "custom_tool_call"):
                    nested, opaque = extract_calls(p)
                    calls[(sid, cid)] = {"nested": nested, "opaque": opaque, "time": when, "cwd": cwd,
                                         "evidence": pointer, "name": p.get("name")}
                elif item_type in ("function_call_output", "custom_tool_call_output"):
                    results[(sid, cid)].append({"output": summarize_output(p.get("output")), "time": when, "evidence": pointer})

    for (sid, cid), call in sorted(calls.items(), key=lambda kv: (kv[1]["time"], kv[0])):
        task = tasks[sid]
        outputs = [r["output"] for r in results[(sid, cid)] if r["time"] >= call["time"]]
        pointers = [call["evidence"]] + [r["evidence"] for r in results[(sid, cid)]][:3]
        single = len(call["nested"]) == 1 and not call["opaque"]
        if call["opaque"]:
            task["opaque_calls"] += 1
        for index, nested in enumerate(call["nested"]):
            if nested["name"] == "apply_patch":
                try:
                    changes = parse_patch(nested["argument"])
                except ValueError:
                    task["unsupported_edit_calls"] += 1
                    diagnostics["unsupported_patch_formats"] += 1
                    continue
                outcome, reason = patch_outcome(outputs, single)
                for change in changes:
                    rid, relative, tree = resolve_path(change["path"], call["cwd"], repos)
                    if rid:
                        task["repo_ids"].add(rid)
                    else:
                        task["unresolved_edit_paths"] += 1
                    moved = change.get("move_to")
                    if moved:
                        moved_repo, _, _ = resolve_path(moved, call["cwd"], repos)
                        if moved_repo:
                            task["repo_ids"].add(moved_repo)
                        else:
                            task["unresolved_edit_paths"] += 1
                    task["edits"].append({**change, "repo_id": rid, "path": relative or change["path"],
                        "worktree": tree if rid else None, "call_id": cid, "patch_index": index,
                        "timestamp": call["time"].isoformat(), "outcome": outcome, "outcome_basis": reason,
                        "attribution": "explicit edit path" if rid else "unresolved path", "evidence": pointers})
            elif nested["name"] == "exec_command":
                arg = nested["argument"]
                if isinstance(arg, dict) and isinstance(arg.get("workdir"), str):
                    task["repo_ids"].update(metadata_repos(arg["workdir"], None, repos))
                check = validation(arg)
                if check:
                    code = validation_outcome(outputs, single)
                    task["validations"].append({**check, "timestamp": call["time"].isoformat(),
                        "exit_code": code, "outcome": "unknown" if code is None else "passed" if code == 0 else "failed",
                        "evidence": pointers})
                else:
                    task["opaque_calls"] += 1

    selected, unattributed = [], []
    for task in tasks.values():
        if not task["_active"]:
            continue
        if not task["repo_ids"]:
            diagnostics["out_of_scope_or_unattributed_tasks"] += 1
            unattributed.append({"id": task["id"], "source": task["source"], "paths": sorted(task["paths"]),
                                 "edit_file_touches": len(task["edits"]),
                                 "reason": "no evidence links this task to a selected repository; excluded from scoped totals"})
            continue
        task["repo_ids"] = sorted(task["repo_ids"])
        task["paths"] = sorted(task["paths"])
        task["models"] = sorted(task["models"])
        task["git_metadata"].pop("repository_url", None)
        task["coverage"] = {"starts_before_window": bool(task["created"] and tokens.parse_timestamp(task["created"]) < start),
                            "malformed_records": len(task.pop("_gaps")), "edit_sequence_complete": False,
                            "reason": "session logs do not prove a complete filesystem mutation sequence"}
        task.pop("_active")
        task["patch_operations"] = len({(e["call_id"], e["patch_index"]) for e in task["edits"]})
        hotspots = defaultdict(list)
        for edit in task["edits"]:
            hotspots[(edit["repo_id"], edit["path"], edit["worktree"])].append(edit)
        task["hotspots"] = []
        for (rid, path, tree), edits in sorted(hotspots.items(), key=lambda kv: str(kv[0])):
            outcomes = Counter(e["outcome"] for e in edits)
            candidate_pairs = []
            for a, b in zip(edits, edits[1:]):
                if a["operation"] == b["operation"] == "update" and a["_reverse"] == b["_forward"] and a["_forward"] != b["_forward"]:
                    candidate_pairs.append({"kind": "inverse_patch_candidate", "confirmed": False,
                                           "evidence": [a["evidence"][0], b["evidence"][0]]})
            task["hotspots"].append({"repo_id": rid, "path": path, "worktree": tree, "edit_operations": len(edits),
                "repeated_touches": max(0, len(edits) - 1), "outcomes": dict(outcomes),
                "inverse_candidates": candidate_pairs, "evidence": [e["evidence"][0] for e in edits[:3]]})
        previous, retries = {}, []
        for check in task["validations"]:
            prior = previous.get(check["signature"])
            if prior and prior["outcome"] == "failed":
                retries.append({"earlier": prior["evidence"][0], "later": check["evidence"][0],
                                "later_outcome": check["outcome"], "program": check["program"]})
            previous[check["signature"]] = check
        task["validation_retries"] = retries
        # Hashes are sufficient for matching but unnecessary in the aggregate.
        for edit in task["edits"]:
            edit.pop("_forward")
            edit.pop("_reverse")
        selected.append(task)
    return sorted(selected, key=lambda t: t["id"]), dict(sorted(diagnostics.items())), sorted(unattributed, key=lambda t: t["id"])
