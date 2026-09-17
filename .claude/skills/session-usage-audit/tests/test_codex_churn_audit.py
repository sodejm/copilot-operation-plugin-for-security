"""Integration fixtures exercise evidence boundaries, not implementation mirrors."""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch as mock_patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import codex_churn_audit as audit
import codex_token_usage as tokens
import churn_git as cg
import churn_sessions as cs

START = datetime(2026, 9, 1, tzinfo=timezone.utc)
END = datetime(2026, 9, 29, tzinfo=timezone.utc)
SECRET = "private source sentinel never exported"
CONFIG = {"config_version": 1, "repositories": [], "classification": [
    {"category": "tests", "patterns": ["tests/*"]},
    {"category": "documentation", "patterns": ["*.md"]},
    {"category": "production", "patterns": ["*.py"]}], "contract_paths": ["AGENTS.md"]}


def row(kind, payload, second=1, day=2):
    return {"type": kind, "timestamp": f"2026-09-{day:02}T00:00:{second:02}Z", "payload": payload}


def patch(path="code.py", old="old", new="new"):
    return f"*** Begin Patch\n*** Update File: {path}\n@@\n-{old}\n+{new}\n*** End Patch"


def call(cid="c1", body=None, second=3, name="functions.apply_patch"):
    return row("response_item", {"type": "custom_tool_call", "name": name,
                                "call_id": cid, "input": body or patch()}, second)


def output(cid="c1", value="Success. Updated the following files:\nM code.py", second=4):
    return row("response_item", {"type": "custom_tool_call_output", "call_id": cid, "output": value}, second)


def usage(sid="task", second=5, rid="response", amount=10):
    return row("token_usage_record", {"thread_id": sid, "response_id": rid,
        "usage": {"input_tokens": amount, "cached_input_tokens": amount // 2,
                  "output_tokens": 4, "total_tokens": amount + 4}}, second)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.g("init", "-q", "-b", "main")
        self.g("config", "user.name", "Fixture")
        self.g("config", "user.email", "fixture@example.invalid")
        self.g("config", "commit.gpgsign", "false")
        self.initial = self.commit({"code.py": "old\n", "AGENTS.md": "# Scope\n# Interface invariants\n# Acceptance criteria\n"}, "2026-08-30T00:00:00Z")

    def tearDown(self):
        self.tmp.cleanup()

    def g(self, *args, cwd=None, date=None):
        env = dict(os.environ)
        if date:
            env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
        result = subprocess.run(["git", "-C", str(cwd or self.repo), *args], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return result.stdout.decode().strip()

    def commit(self, files, date="2026-09-02T00:00:00Z", cwd=None):
        root = cwd or self.repo
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            if body is None:
                p.unlink()
            elif isinstance(body, bytes):
                p.write_bytes(body)
            else:
                p.write_text(body)
        self.g("add", "-A", cwd=root)
        self.g("commit", "-qm", "fixture", cwd=root, date=date)
        return self.g("rev-parse", "HEAD", cwd=root)

    def session(self, records, sid="task", root=None, name=None, meta=None):
        payload = {"id": sid, "cwd": str(root or self.repo), "thread_source": "user",
                   "git": {"commit_hash": self.initial}}
        payload.update(meta or {})
        path = self.base / (name or (sid + ".jsonl"))
        rows = [row("session_meta", payload, 0), row("turn_context", {"cwd": payload["cwd"], "model": "fixture-model"}, 1), *records]
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        return path

    def scan(self, paths, repos=None):
        return cs.scan(paths, START, END, cg.inventory(repos or [self.repo]))

    def report(self, paths, repos=None):
        return audit.build_report(paths, repos or [self.repo], START, END, CONFIG)

    def fingerprint(self, root):
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in root.rglob("*") if p.is_file() and not p.is_symlink()}


class GitEvidence(Fixture):
    def test_linked_worktrees_have_one_repository_identity(self):
        linked = self.base / "linked"
        self.g("worktree", "add", "-qb", "feature", str(linked))
        repos = cg.inventory([self.repo, linked])
        self.assertEqual(len(repos), 1)
        self.assertEqual(len(repos[0]["worktrees"]), 2)
        self.assertEqual(cg.resolve_path(str(linked / "code.py"), None, repos)[:2], (repos[0]["id"], "code.py"))

    def test_exact_reversal_and_final_size_in_one_lineage(self):
        forward = self.commit({"code.py": "new\n"})
        backward = self.commit({"code.py": "old\n"}, "2026-09-03T00:00:00Z")
        r = cg.history(cg.inventory([self.repo])[0], START, END, CONFIG)
        self.assertEqual(len(r["rework"]), 1)
        self.assertEqual((r["rework"][0]["earlier_commit"], r["rework"][0]["later_commit"]), (forward, backward))
        self.assertEqual(r["primary"]["change_volume"]["production"]["added_lines"], 2)
        self.assertEqual(r["primary"]["final_change_size"]["production"]["added_lines"], 0)
        self.assertIsNone(r["primary"]["ratio"])

    def test_cherry_pick_and_squash_branches_stay_separate(self):
        self.g("checkout", "-qb", "feature")
        first = self.commit({"code.py": "new\n"})
        self.g("checkout", "main")
        self.g("cherry-pick", first, date="2026-09-03T00:00:00Z")
        self.g("checkout", "-qb", "squashed", self.initial)
        self.commit({"code.py": "new\n"}, "2026-09-04T00:00:00Z")
        self.g("branch", "copy-of-squashed")
        r = cg.history(cg.inventory([self.repo])[0], START, END, CONFIG)
        self.assertEqual(r["unique_commits"], 3)
        self.assertEqual(len(r["lineages"]), 3)
        self.assertFalse(r["rework"])
        self.assertTrue(all(x["change_volume"]["production"]["added_lines"] == 1 for x in r["lineages"]))

    def test_rebased_alternative_retains_independent_lineage(self):
        self.g("checkout", "-qb", "feature")
        self.commit({"code.py": "new\n"})
        self.g("branch", "before-rebase")
        self.g("checkout", "main")
        self.commit({"other.py": "value\n"}, "2026-09-03T00:00:00Z")
        self.g("checkout", "feature")
        self.g("rebase", "main", date="2026-09-04T00:00:00Z")
        r = cg.history(cg.inventory([self.repo])[0], START, END, CONFIG)
        self.assertFalse(r["rework"])
        self.assertEqual(r["unique_commits"], 3)

    def test_merge_cannot_prove_reversal(self):
        self.g("checkout", "-qb", "feature")
        self.commit({"other.py": "value\n"})
        self.g("checkout", "main")
        self.commit({"code.py": "new\n"})
        self.g("merge", "--no-ff", "-m", "merge", "feature", date="2026-09-03T00:00:00Z")
        self.commit({"code.py": "old\n"}, "2026-09-04T00:00:00Z")
        r = cg.history(cg.inventory([self.repo])[0], START, END, CONFIG)
        self.assertFalse(r["rework"])
        self.assertEqual(r["primary"]["merge_commits"], 1)

    def test_nonmonotonic_window_cannot_confirm_rework_or_range(self):
        self.commit({"code.py": "new\n"})
        self.commit({"other.py": "outside\n"}, "2026-08-31T00:00:00Z")
        self.commit({"code.py": "old\n"}, "2026-09-04T00:00:00Z")
        r = cg.history(cg.inventory([self.repo])[0], START, END, CONFIG)
        self.assertFalse(r["rework"])
        self.assertIsNone(r["primary"]["final_change_size"])

    def test_shallow_boundary_is_not_a_root_addition_or_verified_range(self):
        self.commit({"code.py": "new\n"})
        self.commit({"code.py": "old\n"}, "2026-09-03T00:00:00Z")
        shallow = self.base / "shallow"
        self.g("clone", "-q", "--depth", "1", self.repo.as_uri(), str(shallow))
        r = cg.history(cg.inventory([shallow])[0], START, END, CONFIG)
        self.assertIsNone(r["primary"]["final_change_size"])
        self.assertFalse(r["primary"]["verified_contiguous_range"])
        self.assertFalse(r["rework"])
        self.assertGreater(r["diagnostics"]["shallow_boundaries_in_window"], 0)
        self.assertEqual(r["primary"]["change_volume"]["production"]["added_lines"], 0)

    def test_git_reversal_filename_does_not_attribute_it_to_an_agent(self):
        self.commit({"code.py": "new\n"})
        self.commit({"code.py": "old\n"}, "2026-09-03T00:00:00Z")
        p = self.session([call(), output(), usage()])
        opportunity = self.report([p])["opportunities"][0]
        self.assertEqual(opportunity["kind"], "verified_git_state_reversal")
        self.assertIsNone(opportunity["task_id"])
        self.assertIsNone(opportunity["associated_usage"])

    def test_unavailable_historical_attributes_are_explicit(self):
        classifier = cg.Classifier(cg.inventory([self.repo])[0], CONFIG)
        category, basis = classifier.classify("code.py", "0" * 40)
        self.assertEqual(category, "production")
        self.assertIn("attributes unavailable", basis)

    def test_historical_attributes_binary_and_root_commit(self):
        self.commit({".gitattributes": "code.py churn-category=tests\nasset.bin linguist-generated\n",
                     "asset.bin": b"\0binary\0", "code.py": "new\n", "unknown.xyz": "unknown\n"})
        repo = cg.inventory([self.repo])[0]
        classifier = cg.Classifier(repo, CONFIG)
        self.assertEqual(classifier.classify("code.py")[0], "tests")
        self.assertEqual(classifier.classify("code.py", self.initial)[0], "production")
        self.assertEqual(classifier.classify("asset.bin")[0], "generated_dependency")
        r = cg.history(repo, datetime(2026, 8, 1, tzinfo=timezone.utc), END, CONFIG)
        self.assertTrue(r["primary"]["verified_contiguous_range"])
        self.assertEqual(r["primary"]["change_volume"]["generated_dependency"]["binary_or_unknown_files"], 1)
        self.assertEqual(r["primary"]["change_volume"]["unclassified"]["added_lines"], 3)

    def test_contracts_from_start_commit_only(self):
        self.commit({"AGENTS.md": "# Unrelated\n"})
        repo = cg.inventory([self.repo])[0]
        found = cg.contract_evidence(repo, self.initial, CONFIG)
        self.assertEqual({s["section"] for s in found["sections"]}, {"scope", "interfaces", "acceptance"})
        self.assertEqual(cg.contract_evidence(repo, "HEAD", CONFIG)["status"], "not evidenced")


class SessionEvidence(Fixture):
    def test_outcomes_literal_scripts_failures_and_opaque_scripts(self):
        script = "const patch=" + json.dumps(patch()) + "; text(await tools.apply_patch(patch));"
        opaque = "if (false) { text(await tools.apply_patch(" + json.dumps(patch()) + ")); }"
        paths = [self.session([call(), output(), call("failed", second=5), output("failed", "apply_patch verification failed", 6),
                              call("uncertain", second=7), output("uncertain", "Script completed. Output: {}", 8),
                              call("script", script, 9, "functions.exec"), output("script", second=10),
                              call("conditional", opaque, 11, "functions.exec"), output("conditional", second=12),
                              call("dynamic", "text(await tools.apply_patch(buildPatch()));", 13, "functions.exec")])]
        tasks, diag, _ = self.scan(paths)
        outcomes = {e["call_id"]: e["outcome"] for e in tasks[0]["edits"]}
        self.assertEqual(outcomes, {"c1": "confirmed", "failed": "failed", "uncertain": "uncertain", "script": "confirmed", "conditional": "uncertain"})
        self.assertEqual(diag["unsupported_patch_formats"], 1)

    def test_static_scanner_does_not_execute_or_read_script_content(self):
        sentinel = self.base / "must-not-exist"
        script = f'const data="tools.apply_patch(fake)"; /* tools.apply_patch(fake) */ text(await tools.exec_command({{cmd:"touch {sentinel}"}}));'
        calls = cs.static_calls(script)
        self.assertEqual([c["name"] for c in calls], ["exec_command"])
        self.assertFalse(sentinel.exists())
        self.assertEqual(cs.static_calls('const s = `${tools.apply_patch(fake)}`;'), [])
        self.assertEqual(cs.static_calls('/tools.apply_patch(fake)/;'), [])

    def test_duplicate_records_and_copied_files_do_not_inflate_edits_or_tokens(self):
        p = self.session([call(), output(), usage(), call(), output(), usage()])
        copy = self.base / "copied.jsonl"
        copy.write_bytes(p.read_bytes())
        r = self.report([p, copy])
        self.assertEqual(r["agent_metrics"]["patch_operations"]["confirmed"], 1)
        self.assertEqual(r["associated_usage"]["requests"], 1)
        expected = tokens.aggregate([p, copy], START, END, {"task"})
        self.assertEqual(audit.sum_buckets([r["associated_usage"]]), expected["total"])

    def test_inherited_fork_history_not_owned_by_child(self):
        parent = self.session([call(), output(), usage()], sid="parent")
        records = [row("session_meta", {"id": "child", "cwd": str(self.repo), "parent_thread_id": "parent", "thread_source": "user"}, 10),
                   call(), output(), row("turn_context", {"cwd": str(self.repo)}, 1),
                   usage("parent", 11), usage("child", 12, "child-response"),
                   row("turn_context", {"cwd": str(self.repo)}, 13), call("child-edit", second=14), output("child-edit", second=15)]
        child = self.base / "child.jsonl"
        child.write_text("".join(json.dumps(r) + "\n" for r in records))
        r = self.report([parent, child])
        t = {t["id"]: t for t in r["tasks"]}
        self.assertEqual(len(t["child"]["edits"]), 1)
        self.assertEqual(t["child"]["associated_usage"]["requests"], 1)
        self.assertEqual(r["agent_metrics"]["patch_operations"]["confirmed"], 2)

    def test_shared_task_tokens_allocated_once_and_unresolved_retained(self):
        other = self.base / "other"
        self.g("clone", "-q", str(self.repo), str(other))
        p = self.session([call(body=patch(str(other / "code.py"))), output(), usage()])
        r = self.report([p], [self.repo, other])
        self.assertEqual(len(r["tasks"][0]["repo_ids"]), 2)
        self.assertEqual(r["token_allocation"][0]["group"], "shared_multiple_repositories")
        self.assertEqual(r["token_allocation"][0]["usage"]["requests"], 1)
        p = self.session([call(body=patch("/outside/unknown.py")), output(), usage()])
        r = self.report([p])
        self.assertEqual(r["tasks"][0]["unresolved_edit_paths"], 1)
        self.assertEqual(r["token_allocation"][0]["group"], "shared_or_unresolved")

    def test_worktree_explicit_paths_override_metadata_for_edits(self):
        linked = self.base / "linked"
        self.g("worktree", "add", "-qb", "feature", str(linked))
        p = self.session([call(body=patch(str(linked / "code.py"))), output()])
        tasks, _, _ = self.scan([p])
        self.assertEqual(tasks[0]["edits"][0]["worktree"], str(linked.resolve()))
        self.assertEqual(len(tasks[0]["repo_ids"]), 1)

    def test_missing_results_partial_logs_and_inverse_never_confirm_rework(self):
        p = self.session([call(body=patch(old=SECRET)), call("inverse", patch(old="new", new=SECRET), 5)])
        with p.open("a") as handle:
            handle.write('{"truncated":\n')
        r = self.report([p])
        task = r["tasks"][0]
        self.assertEqual(task["hotspots"][0]["inverse_candidates"][0]["confirmed"], False)
        self.assertEqual(task["coverage"]["malformed_records"], 1)
        self.assertIsNone(r["agent_metrics"]["confirmed_agent_rework"])
        self.assertIsNone(r["agent_metrics"]["cumulative_to_final_ratio"])
        self.assertTrue(all(v is None for v in task["associated_usage"]["tokens"].values()))
        self.assertTrue(all(v is None for v in task["associated_usage"]["observed_tokens"].values()))
        self.assertNotIn(SECRET, json.dumps(r))

    def test_conflicting_calls_and_outputs_do_not_count_as_confirmed(self):
        p = self.session([call(), call(body=patch(new="different")), output(), call("conflict", second=6),
                          output("conflict", second=7), output("conflict", "apply_patch verification failed", 8)])
        tasks, diag, _ = self.scan([p])
        self.assertEqual(diag["conflicting_tool_records"], 1)
        self.assertEqual([e["outcome"] for e in tasks[0]["edits"]], ["uncertain", "uncertain"])

    def test_validation_retry_is_separate_from_applied_edits(self):
        body = json.dumps({"cmd": "python3 -m unittest", "workdir": str(self.repo)})
        p = self.session([call("check1", body, 3, "functions.exec_command"), output("check1", {"exit_code": 1, "output": SECRET}, 4),
                          call("check2", body, 5, "functions.exec_command"), output("check2", {"exit_code": 0}, 6)])
        r = self.report([p])
        self.assertEqual(len(r["tasks"][0]["validation_retries"]), 1)
        self.assertEqual(r["agent_metrics"]["file_touches"], 0)
        self.assertNotIn(SECRET, json.dumps(r))

    def test_deletion_size_unknown_and_unsupported_format_reported(self):
        p = self.session([call(body="*** Begin Patch\n*** Delete File: code.py\n*** End Patch"), output(), call("unsupported", "diff --git a/x b/x", 5)])
        r = self.report([p])
        production = r["agent_metrics"]["change_volume"]["production"]
        self.assertEqual(production["unknown_deleted_counts"], 1)
        self.assertEqual(r["summary"]["coverage"]["unsupported_edit_calls"], 1)

    def test_no_attribution_not_silently_assigned_to_selected_repo(self):
        p = self.session([usage()], root=self.base)
        r = self.report([p])
        self.assertEqual(r["summary"]["tasks"], 0)
        self.assertEqual(len(r["unattributed_or_out_of_scope_tasks"]), 1)
        self.assertIsNone(r["associated_usage"]["tokens"]["input_tokens"])


class Portability(Fixture):
    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = audit.main(["--start", START.isoformat(), "--end", END.isoformat(),
                                 "--output-dir", str(self.base / "reports"), "--format", "json", *args])
        self.assertEqual(result, 0, stderr.getvalue())
        return json.loads(stdout.getvalue())

    def test_git_only_never_discovers_sessions_and_keeps_usage_unknown(self):
        self.commit({"code.py": "new\n"})
        self.commit({"code.py": "old\n"}, "2026-09-03T00:00:00Z")
        with mock_patch.object(tokens, "session_paths", side_effect=AssertionError("unexpected session access")):
            report = self.invoke("--git-only", "--repo", str(self.repo))
        self.assertEqual(report["inputs"]["session_mode"], "git_only")
        self.assertEqual(report["inputs"]["session_files_scanned"], 0)
        self.assertEqual(report["summary"]["verified_git_reversals"], 1)
        self.assertEqual(report["tasks"], [])
        self.assertTrue(all(value is None for value in report["associated_usage"]["tokens"].values()))
        self.assertIn("No session files were read", audit.markdown(report))
        self.assertEqual(len(list((self.base / "reports").iterdir())), 2)
        codex_report = self.report([])
        compared = audit.comparison(report, codex_report)
        self.assertFalse(compared["compatible"])
        self.assertIn("session evidence modes differ", compared["incompatibilities"])
        self.assertIsNone(compared["metric_deltas"])

    def test_default_config_requires_explicit_repository_selection(self):
        stderr = io.StringIO()
        with mock_patch.object(tokens, "session_paths", side_effect=AssertionError("unexpected session access")):
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
                audit.main(["--git-only"])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--repo or --config", stderr.getvalue())

    def test_git_only_rejects_explicit_session_inputs(self):
        for flag in ("--path", "--codex-home"):
            stderr = io.StringIO()
            with self.subTest(flag=flag), redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
                audit.main(["--git-only", "--repo", str(self.repo), flag, str(self.base)])
            self.assertEqual(error.exception.code, 2)
            self.assertIn("--git-only cannot be combined", stderr.getvalue())

    def test_explicit_config_selects_repositories_without_changing_token_interface(self):
        config = self.base / "churn.local.json"
        config.write_text(json.dumps(dict(CONFIG, repositories=[str(self.repo)])))
        session = self.session([usage()])
        report = self.invoke("--config", str(config), "--path", str(session))
        self.assertEqual(report["inputs"]["session_mode"], "codex")
        self.assertEqual(report["summary"]["tasks"], 1)
        self.assertEqual(report["associated_usage"]["tokens"]["input_tokens"], 10)
        self.assertTrue(report["reconciliation"]["original_helper_totals_match"])

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits")
    def test_new_reports_are_owner_only_even_with_permissive_umask(self):
        report = self.report([])
        previous = os.umask(0)
        try:
            saved = audit.save_reports(report, self.base / "private-reports")
        finally:
            os.umask(previous)
        for path in saved.values():
            self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)


class Delivery(Fixture):
    def test_repeatable_reports_and_read_only_dirty_index_source_logs(self):
        self.commit({"code.py": "new\n"})
        (self.repo / "code.py").write_text("dirty unstaged\n")
        (self.repo / "staged.py").write_text("staged\n")
        self.g("add", "staged.py")
        (self.repo / "untracked.txt").write_text("preserve\n")
        p = self.session([call(body=patch(old=SECRET)), output(), usage()])
        before, source = self.fingerprint(self.repo), p.read_bytes()
        first = self.report([p])
        second = self.report([p])
        self.assertEqual(first, second)
        self.assertEqual(self.fingerprint(self.repo), before)
        self.assertEqual(p.read_bytes(), source)
        one = audit.save_reports(first, self.base / "reports")
        two = audit.save_reports(second, self.base / "reports")
        self.assertEqual(one, two)
        restored = json.loads(Path(one["json"]).read_text())
        self.assertEqual(audit.markdown(restored), Path(one["md"]).read_text())
        self.assertEqual(audit.save_reports(restored, self.base / "reports"), one)
        self.assertNotIn(SECRET, Path(one["md"]).read_text())
        self.assertNotIn(SECRET, Path(one["json"]).read_text())
        with self.assertRaises(ValueError):
            audit.save_reports(first, self.repo / "reports")

    def test_comparison_shows_mix_coverage_and_incompatibilities(self):
        p = self.session([usage()])
        report = self.report([p])
        comparison = audit.comparison(report, report)
        self.assertTrue(comparison["compatible"])
        self.assertEqual(comparison["metric_deltas"]["tasks"], 0)
        self.assertIn("model_mix", comparison["before"])
        self.assertIn("coverage", comparison["after"])
        compared = dict(report, comparison=comparison)
        restored = json.loads(json.dumps(compared, sort_keys=True))
        self.assertEqual(audit.markdown(compared), audit.markdown(restored))
        prior = dict(report, measurement_version="incompatible")
        self.assertFalse(audit.comparison(report, prior)["compatible"])
        self.assertIsNone(audit.comparison(report, prior)["metric_deltas"])

    def test_opportunities_are_bounded_and_target_existing_sections(self):
        records = [row("response_item", {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Scope and acceptance criteria " + SECRET}]}, 2)]
        for i in range(4):
            records += [call(str(i), second=3 + 2 * i), output(str(i), second=4 + 2 * i)]
        p = self.session(records)
        r = self.report([p])
        self.assertEqual(len(r["opportunities"]), 1)
        self.assertEqual(r["opportunities"][0]["kind"], "repeated_edit_candidate")
        self.assertTrue(r["opportunities"][0]["existing_section_targets"])
        self.assertNotIn(SECRET, json.dumps(r))

    def test_cli_validates_window_and_writes_both_formats(self):
        p = self.session([usage()])
        cmd = [sys.executable, str(audit.Path(audit.__file__)), "--repo", str(self.repo), "--path", str(p), "--output-dir", str(self.base / "reports")]
        result = subprocess.run(cmd + ["--start", START.isoformat(), "--end", END.isoformat(), "--format", "json"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["schema_version"], 1)
        self.assertEqual(len(list((self.base / "reports").iterdir())), 2)
        bad = subprocess.run(cmd + ["--start", START.isoformat(), "--days", "7"], capture_output=True)
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
