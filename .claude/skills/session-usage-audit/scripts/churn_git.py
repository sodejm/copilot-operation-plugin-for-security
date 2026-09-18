"""Read-only Git inventory and immutable, first-parent history measurements."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import os
from pathlib import Path
import subprocess

CATEGORIES = ("production", "tests", "documentation", "generated_dependency", "unclassified")


def git(path, *args, data=None, check=True):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1")
    # Do not let inherited Git plumbing variables redirect the audited repository.
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_EXTERNAL_DIFF"):
        env.pop(name, None)
    result = subprocess.run(["git", "--no-optional-locks", "--no-replace-objects", "-C", str(path),
                             "-c", "core.quotePath=false", *args], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if check and result.returncode:
        # Error bodies may contain private source; report only the operation.
        raise ValueError(f"Git {args[0]} failed in {path} (exit {result.returncode})")
    return result.stdout if result.returncode == 0 else None


def decode(value):
    return value.decode("utf-8", "replace")


def normalize_remote(value):
    value = value.strip().removesuffix(".git").rstrip("/")
    if value.startswith("git@"):
        value = value[4:].replace(":", "/", 1)
    for prefix in ("https://", "http://", "ssh://git@"):
        value = value.removeprefix(prefix)
    return value.casefold()


def inventory(paths):
    repos = {}
    for supplied in paths:
        path = Path(supplied).expanduser().resolve()
        root = Path(decode(git(path, "rev-parse", "--show-toplevel")).strip())
        common = Path(decode(git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")).strip()).resolve()
        if str(common) in repos:
            continue
        rid = hashlib.sha256(str(common).encode()).hexdigest()[:16]
        rows = decode(git(root, "worktree", "list", "--porcelain", "-z")).split("\0")
        worktrees, current = [], {}
        for row in rows:
            if not row:
                if current:
                    worktrees.append(current)
                    current = {}
                continue
            key, _, value = row.partition(" ")
            current[key] = value or True
        if current:
            worktrees.append(current)
        remote = git(root, "config", "--get-regexp", r"remote\..*\.url", check=False) or b""
        urls = sorted({normalize_remote(line.split(" ", 1)[1]) for line in decode(remote).splitlines() if " " in line})
        repos[str(common)] = {"id": rid, "name": root.name, "path": str(root),
                              "common_git_dir": str(common), "worktrees": worktrees,
                              "_remotes": urls}
    return list(repos.values())


def resolve_path(value, cwd, repos):
    if not isinstance(value, str) or not value or "\x00" in value:
        return None, None, None
    path = Path(value).expanduser()
    if not path.is_absolute():
        if not cwd or not Path(cwd).is_absolute():
            return None, None, value
        path = Path(cwd) / path
    # Prefer the recorded path. A fallback handles macOS /var -> /private/var
    # aliases and repositories opened through a directory symlink.
    path = Path(os.path.normpath(path))
    for candidate in dict.fromkeys((path, path.resolve())):
        matches = []
        for repo in repos:
            for tree in repo["worktrees"]:
                root = Path(str(tree.get("worktree", "")))
                try:
                    relative = candidate.relative_to(root)
                    matches.append((len(root.parts), repo["id"], relative.as_posix(), str(root)))
                except ValueError:
                    pass
        if matches:
            _, rid, relative, root = max(matches)
            return rid, relative, root
    return None, None, str(path)


def metadata_repos(cwd, remote, repos):
    rid, _, _ = resolve_path(cwd, None, repos)
    result = {rid} if rid else set()
    if remote:
        matches = [r["id"] for r in repos if normalize_remote(remote) in r["_remotes"]]
        if len(matches) == 1:
            result.add(matches[0])
    return result


class Classifier:
    def __init__(self, repo, config):
        self.repo, self.config, self.cache, self.attrs = repo, config, {}, {}
        self.unavailable = set()
        self.valid_refs = {}

    def prime(self, paths, ref="HEAD"):
        missing = sorted({p for p in paths if (p, ref) not in self.attrs})
        if not missing:
            return
        if ref not in self.valid_refs:
            self.valid_refs[ref] = git(self.repo["path"], "cat-file", "-e", ref + "^{tree}", check=False) is not None
        raw = (git(self.repo["path"], "check-attr", f"--source={ref}", "-z", "--stdin", "churn-category",
                   "linguist-generated", "linguist-vendored", data=("\0".join(missing) + "\0").encode(), check=False)
               if self.valid_refs[ref] else None)
        for path in missing:
            self.attrs[(path, ref)] = {}
        if raw is None:
            self.unavailable.update((path, ref) for path in missing)
        if raw:
            parts = decode(raw).split("\0")
            for i in range(0, len(parts) - 2, 3):
                self.attrs.setdefault((parts[i], ref), {})[parts[i + 1]] = parts[i + 2]

    def classify(self, path, ref="HEAD"):
        key = (path, ref)
        if key in self.cache:
            return self.cache[key]
        result = ("unclassified", "no configured rule or Git attribute")
        # Git reads the requested tree; info/global attribute overrides may apply.
        for rule in self.config.get("classification", []):
            if rule.get("category") not in CATEGORIES:
                continue
            if any(fnmatchcase(path, pattern) for pattern in rule.get("patterns", [])):
                result = (rule["category"], "local configuration")
                break
        self.prime([path], ref)
        values = self.attrs[(path, ref)]
        if values:
            if values.get("churn-category") in CATEGORIES:
                result = (values["churn-category"], f"Git attributes using tree {ref}; local attribute overrides may apply")
            elif any(values.get(k) in ("set", "true") for k in ("linguist-generated", "linguist-vendored")):
                result = ("generated_dependency", f"Git attributes using tree {ref}; local attribute overrides may apply")
        if key in self.unavailable:
            result = (result[0], result[1] + "; historical Git attributes unavailable")
        self.cache[key] = result
        return result


def empty_volume():
    return {"added_lines": 0, "deleted_lines": 0, "binary_or_unknown_files": 0}


def numstat(raw):
    result = []
    for record in decode(raw).split("\0"):
        if not record:
            continue
        parts = record.split("\t", 2)
        if len(parts) == 3:
            a, d, path = parts
            result.append({"path": path, "added_lines": int(a) if a.isdigit() else None,
                           "deleted_lines": int(d) if d.isdigit() else None})
    return result


def add_volume(bucket, change):
    if change["added_lines"] is None or change["deleted_lines"] is None:
        bucket["binary_or_unknown_files"] += 1
    else:
        bucket["added_lines"] += change["added_lines"]
        bucket["deleted_lines"] += change["deleted_lines"]


def history(repo, start, end, config):
    root = repo["path"]
    head_raw = git(root, "rev-parse", "--verify", "HEAD", check=False)
    if not head_raw:
        return {"primary": None, "lineages": [], "unique_commits": 0, "rework": [],
                "diagnostics": {"unborn_head": 1}}
    head = decode(head_raw).strip()
    shallow_path = Path(repo["common_git_dir"]) / "shallow"
    shallow = set(shallow_path.read_text().split()) if shallow_path.is_file() else set()
    empty_tree = decode(git(root, "hash-object", "-t", "tree", "--stdin", data=b"")).strip()
    tips = {head: ["configured checkout HEAD"]}
    refs = decode(git(root, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads/", "refs/remotes/"))
    for line in refs.splitlines():
        sha, label = line.split(" ", 1)
        tips.setdefault(sha, []).append(label)
    for tree in repo["worktrees"]:
        if tree.get("HEAD"):
            tips.setdefault(tree["HEAD"], []).append("worktree:" + str(tree["worktree"]))
    classifier = Classifier(repo, config)
    cache, lineages, rework, unique, commit_summaries = {}, [], {}, set(), {}
    diagnostics = Counter()

    def changes(sha, parent):
        if sha not in cache:
            raw = git(root, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--no-abbrev", "--raw", "--numstat", "-z", parent, sha, "--")
            chunks, blobs, i = decode(raw).split("\0"), {}, 0
            stats = []
            while i < len(chunks):
                item = chunks[i]
                if item.startswith(":") and i + 1 < len(chunks):
                    fields = item.split()
                    blobs[chunks[i + 1]] = (fields[2], fields[3])
                    i += 2
                else:
                    stats.extend(numstat(item.encode() + b"\0"))
                    i += 1
            classifier.prime([row["path"] for row in stats], sha)
            for row in stats:
                row["old_blob"], row["new_blob"] = blobs.get(row["path"], (None, None))
                row["category"], row["classification_basis"] = classifier.classify(row["path"], sha)
            cache[sha] = stats
        return cache[sha]

    # Each first-parent lineage is independent. Never concatenate branch timelines.
    for tip, labels in sorted(tips.items()):
        raw = git(root, "log", "--first-parent", "--format=%H %P%x09%ct", tip, "--", check=False)
        if raw is None:
            diagnostics["unavailable_worktree_heads"] += 1
            continue
        chain = []
        for line in decode(raw).splitlines():
            ids, epoch = line.split("\t")
            fields = ids.split()
            chain.append((fields[0], fields[1:], datetime.fromtimestamp(int(epoch), timezone.utc)))
        # Locate an immutable end then a contiguous ancestry range. Nonmonotonic
        # commit dates are diagnosed and disable range ratios/rework.
        before_end = [c for c in chain if c[2] < end]
        if not before_end:
            continue
        endpoint = before_end[0]
        sequence = chain[chain.index(endpoint):]
        selected = [c for c in sequence if start <= c[2] < end]
        if not selected:
            continue
        contiguous = sequence[:len(selected)] == selected
        if not contiguous:
            diagnostics["noncontiguous_timestamp_windows"] += 1
        missing_boundary = any(c[0] in shallow for c in selected)
        if missing_boundary:
            contiguous = False
            diagnostics["shallow_boundaries_in_window"] += 1
        base = (selected[-1][1][0] if selected[-1][1] else empty_tree) if not missing_boundary else None
        volumes = {c: empty_volume() for c in CATEGORIES}
        previous = {}
        pairs, merges = [], 0
        for sha, parents, when in reversed(selected):
            unique.add(sha)
            if sha in shallow:
                previous.clear()
                continue
            delta = changes(sha, parents[0] if parents else empty_tree)
            if len(parents) > 1:
                previous.clear()
                merges += 1
            for row in delta:
                add_volume(volumes[row["category"]], row)
                prior = previous.get(row["path"])
                if (contiguous and len(parents) <= 1 and prior and not prior["merge"] and row["old_blob"] != row["new_blob"]
                        and row["new_blob"] == prior["old_blob"] and row["old_blob"] == prior["new_blob"]
                        and row["added_lines"] is not None and prior["added_lines"] is not None):
                    identity = (prior["commit"], sha, row["path"])
                    pair = {"kind": "verified_git_state_reversal", "repo_id": repo["id"],
                            "path": row["path"], "category": row["category"],
                            "earlier_commit": prior["commit"], "later_commit": sha,
                            "timestamp": when.isoformat(), "agent_attribution": "not evidenced",
                            "evidence": [{"repo": root, "commit": prior["commit"], "path": row["path"]},
                                         {"repo": root, "commit": sha, "path": row["path"]}]}
                    rework[identity] = pair
                    pairs.append(list(identity))
                previous[row["path"]] = {**row, "commit": sha, "merge": len(parents) > 1}
            if sha not in commit_summaries:
                summary = {c: empty_volume() for c in CATEGORIES}
                for row in delta:
                    add_volume(summary[row["category"]], row)
                commit_summaries[sha] = {"commit": sha, "timestamp": when.isoformat(), "change_volume": summary}
        final = {c: empty_volume() for c in CATEGORIES}
        if contiguous:
            final_stats = numstat(git(root, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--numstat", "-z", base, endpoint[0], "--"))
            classifier.prime([row["path"] for row in final_stats], endpoint[0])
            for row in final_stats:
                category, _ = classifier.classify(row["path"], endpoint[0])
                add_volume(final[category], row)
        lineages.append({"tip": tip, "labels": sorted(set(labels)), "end_commit": endpoint[0], "base_commit": base,
                         "commits": len(selected), "commit_ids": [c[0] for c in reversed(selected)],
                         "merge_commits": merges, "change_volume": volumes,
                         "volume_coverage": "known commit deltas only; shallow boundary omitted" if missing_boundary else "selected commit deltas",
                         "final_change_size": final if contiguous else None,
                         "verified_contiguous_range": contiguous, "state_reversals": len(pairs),
                         "ratio": None, "ratio_status": "not computed; history is not task-attributed"})
    return {"primary": next((v for v in lineages if v["tip"] == head), None),
            "lineages": lineages, "unique_commits": len(unique), "rework": list(rework.values()),
            "commit_summaries": [commit_summaries[k] for k in sorted(commit_summaries)],
            "diagnostics": {**dict(diagnostics), "attribute_lookups_unavailable": len(classifier.unavailable)},
            "volume_scope": "primary checkout first-parent history; other lineages are separate overlapping views"}


def contract_evidence(repo, ref, config):
    """Inventory existing historical contract sections, without exporting bodies."""
    if not isinstance(ref, str) or not ref or not all(c in "0123456789abcdefABCDEF" for c in ref):
        return {"status": "not evidenced", "reason": "no verified task-start commit", "sections": []}
    if git(repo["path"], "cat-file", "-e", ref + "^{commit}", check=False) is None:
        return {"status": "not evidenced", "reason": "task-start commit unavailable", "sections": []}
    sections = []
    keywords = {"scope": ("scope", "non-goal", "terminology"),
                "interfaces": ("interface", "invariant", "contract", "architecture"),
                "acceptance": ("acceptance", "failure", "validation", "test plan")}
    for path in config.get("contract_paths", []):
        size = git(repo["path"], "cat-file", "-s", ref + ":" + path, check=False)
        if not size or not size.strip().isdigit() or int(size) > 128000:
            continue
        content = git(repo["path"], "show", ref + ":" + path, check=False)
        if content is None:
            continue
        for number, line in enumerate(decode(content).splitlines(), 1):
            # Headings/issue form labels only: do not treat prose mentions as a contract.
            trimmed = line.strip().lower()
            if not (trimmed.startswith("#") or trimmed.startswith("label:") or trimmed.startswith("- label:")):
                continue
            for section, terms in keywords.items():
                if any(term in trimmed for term in terms):
                    sections.append({"path": path, "commit": ref, "line": number, "section": section})
    return {"status": "historical sections available" if sections else "not evidenced",
            "task_specific_completeness": "not assessed", "sections": sections[:24]}
