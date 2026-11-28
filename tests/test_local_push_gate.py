"""Regression tests for exact-commit push policy and failure propagation."""

from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "local_push_gate", ROOT / "tools/push_gate/gate.py"
)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
CHECKS_SPEC = importlib.util.spec_from_file_location(
    "local_push_checks", ROOT / "tools/push_gate/checks.py"
)
CHECKS = importlib.util.module_from_spec(CHECKS_SPEC)
CHECKS_SPEC.loader.exec_module(CHECKS)


class PolicyTests(unittest.TestCase):
    """Exercise closed policy and meaningful assertion detection."""

    def test_draft_update_is_scoped_to_destination(self):
        sha = "a" * 40
        draft = ("local", sha, "refs/heads/codex/draft/detection", "0" * 40)
        ordinary = ("local", sha, "refs/heads/codex/draftish", "0" * 40)
        self.assertEqual(GATE.push_profiles([draft]), {sha: True})
        for updates in ([draft, ordinary], [ordinary, draft], [ordinary]):
            self.assertEqual(GATE.push_profiles(updates), {sha: False})

    def test_draft_requires_enforced_full_checks(self):
        config = json.loads((ROOT / "tools/push_gate/draft-ruleset.json").read_text())
        rule = config["rules"][0]
        effective = [dict(rule, ruleset_id=42), {"type": "pull_request"}]
        remote = "git@github.com:sodejm/copilot-operation-plugin-for-security.git"
        ruleset = dict(config, bypass_actors=[])
        for url, rules, detail, allowed in (
            (remote, effective, ruleset, True),
            (remote, [effective[0]], ruleset, False),
            (remote, effective, dict(ruleset, bypass_actors=[{"actor_id": 1}]), False),
            (remote, effective, dict(ruleset, enforcement="evaluate"), False),
            (remote, [{"type": "pull_request"}], ruleset, False),
            (remote + ".elsewhere", effective, ruleset, False),
        ):
            with self.subTest(url=url, rules=rules, allowed=allowed):
                with mock.patch.object(
                    GATE,
                    "run",
                    side_effect=[
                        json.dumps(rules).encode(),
                        json.dumps(detail).encode(),
                    ],
                ):
                    if allowed:
                        GATE.require_draft_protection(ROOT, url, config)
                    else:
                        with self.assertRaises(GATE.GateError):
                            GATE.require_draft_protection(ROOT, url, config)

    def test_draft_review_workflow_blocks_until_ready_and_all_jobs_pass(self):
        workflow = (ROOT / GATE.REVIEW_WORKFLOW).read_text()
        events = workflow.split("  pull_request:", 1)[1].split("  push:", 1)[0]
        for event in (
            "opened",
            "synchronize",
            "reopened",
            "ready_for_review",
            "converted_to_draft",
        ):
            self.assertIn(event, events)
        jobs, validate = workflow.split("  validate:\n")
        for job in ("isolated-service-laboratory", "portability-smoke"):
            self.assertIn(
                f"  {job}:\n    if: github.event_name != 'pull_request' || !github.event.pull_request.draft",
                jobs,
            )
        self.assertIn("  headless-conformance:\n", jobs)
        self.assertIn(
            "needs: [headless-conformance, isolated-service-laboratory, portability-smoke]",
            validate,
        )
        self.assertIn(
            "HEADLESS_RESULT: ${{ needs.headless-conformance.result }}", validate
        )
        self.assertIn("if: always()", validate)
        self.assertIn("python3 tools/push_gate/checks.py cops-full-suite", validate)
        script = textwrap.dedent(
            validate.split("        run: |\n", 1)[1].split("      - name:", 1)[0]
        )
        results = ("success", "failure", "skipped", "cancelled")
        for draft, headless, lab, smoke in itertools.product(
            ("true", "false"), results, results, results
        ):
            with self.subTest(draft=draft, headless=headless, lab=lab, smoke=smoke):
                proc = subprocess.run(
                    ["bash", "-e", "-c", script],
                    env={
                        "DRAFT": draft,
                        "HEADLESS_RESULT": headless,
                        "LAB_RESULT": lab,
                        "SMOKE_RESULT": smoke,
                    },
                    check=False,
                )
                self.assertEqual(
                    proc.returncode == 0,
                    draft == "false" and headless == lab == smoke == "success",
                )

    def test_draft_defers_only_the_full_suite(self):
        def commands(profile):
            with (
                mock.patch.object(sys, "argv", ["checks.py", profile, "base", "head"]),
                mock.patch.object(CHECKS, "run") as run,
                mock.patch.object(CHECKS.glob, "glob", return_value=[]),
                mock.patch.object(CHECKS.subprocess, "check_output", return_value=""),
                mock.patch.dict(os.environ),
            ):
                CHECKS.main()
            return [call.args for call in run.call_args_list]

        draft = commands("cops-draft")
        full = commands("cops")
        self.assertTrue(any("pip_audit" in c for c in draft))
        self.assertTrue(any("tools/push_gate/session_delivery.py" in c for c in draft))
        deferred = [c for c in full if c not in draft]
        self.assertEqual(len(deferred), 3)
        self.assertEqual(deferred[0][:2], ("make", "check"))
        self.assertIn("pytest", deferred[1])
        self.assertIn("report", deferred[2])
        self.assertEqual(draft, [c for c in full if c not in deferred])

    def test_current_scanner_pins_match_operator_prerequisites(self):
        policy = json.loads((ROOT / "tools/push_gate/policy.json").read_text())
        expected = {"semgrep": "1.182.0", "trivy": "0.76.1"}
        self.assertEqual(policy["tools"], expected)
        documentation = (ROOT / "docs/LOCAL_PUSH_GATE.md").read_text()
        for name, version in expected.items():
            self.assertIn(f"{name.capitalize()} **{version}**", documentation)

    def test_assertions_must_change(self):
        self.assertFalse(
            GATE.executable_test(
                "test_a.py", "assert x == 1", "# comment\nassert x == 1"
            )
        )
        self.assertFalse(GATE.executable_test("test_a.py", "assert x == 1", ""))
        self.assertTrue(
            GATE.executable_test("test_a.py", "assert x == 1", "assert x == 2")
        )
        self.assertTrue(GATE.executable_test("a.test.ts", "", "expect(result).toBe(2)"))

    def test_unsupported_and_default_updates_fail(self):
        sha = "a" * 40
        for target, revision in (
            ("refs/heads/main", sha),
            ("refs/tags/v1", sha),
            ("refs/heads/topic", "0" * 40),
        ):
            with self.subTest(target=target, revision=revision):
                with self.assertRaises(GATE.GateError):
                    GATE.parse_updates(
                        f"refs/heads/topic {revision} {target} {'0' * 40}", "main"
                    )
        self.assertEqual(
            GATE.parse_updates(f"HEAD {sha} refs/heads/topic {'0' * 40}", "main")[0][1],
            sha,
        )

    def test_absent_executable_fails_closed(self):
        with self.assertRaises(GATE.GateError):
            GATE.run(["push-gate-deliberately-absent-2fcb63a7"], ROOT)

    def test_terraform_assertions_must_change(self):
        self.assertFalse(
            GATE.executable_test(
                "main.tftest.hcl", "condition = true", "# note\ncondition = true"
            )
        )
        self.assertTrue(
            GATE.executable_test(
                "main.tftest.hcl", "condition = true", "condition = output.ok == true"
            )
        )

    def test_inherited_overrides_removed(self):
        os.environ["TRIVY_SKIP_FILES"] = "*"
        os.environ["SEMGREP_RULES"] = "unreviewed"
        try:
            self.assertNotIn("TRIVY_SKIP_FILES", GATE.clean_environment())
            self.assertNotIn("SEMGREP_RULES", GATE.clean_environment())
        finally:
            del os.environ["TRIVY_SKIP_FILES"]
            del os.environ["SEMGREP_RULES"]

    def test_cops_coverage_excludes_removed_authorization_source_copies(self):
        commands = []
        with (
            mock.patch.object(sys, "argv", ["checks.py", "cops", "base", "head"]),
            mock.patch.object(
                CHECKS, "run", side_effect=lambda *args: commands.append(args)
            ),
            mock.patch.object(CHECKS.glob, "glob", return_value=[]),
            mock.patch.object(CHECKS.subprocess, "check_output", return_value=""),
            mock.patch.dict(os.environ, {"PATH": os.environ.get("PATH", "")}),
        ):
            CHECKS.main()
        coverage_runs = [
            command for command in commands if command[1:4] == ("-m", "coverage", "run")
        ]
        self.assertEqual(len(coverage_runs), 1)
        self.assertIn("--omit=*/cops-auth-source-*/*", coverage_runs[0])
        self.assertIn((coverage_runs[0][0], "-m", "coverage", "report"), commands)


def handoff_record(code, stage):
    """Describe an ordinary callable and its two observable outcomes."""
    paths = [code, "tests/test_behavior.py"]
    return {
        "stage": stage,
        "request": "Clamp a negative count to zero while preserving positive counts.",
        "scope": "Expose clamp_count in the count module and exercise its public input.",
        "setup": "Use Python 3 and the standard library unittest runner.",
        "constraints": "Return integers and accept zero as a valid count.",
        "steps": [
            {
                "action": "Define clamp_count(value) and add positive and negative input tests.",
                "paths": paths,
                "verify": {
                    "command": "python3 -m unittest discover -s tests -p test_behavior.py",
                    "expected": "Both tests pass for positive and negative inputs.",
                },
            }
        ],
        "acceptance": [
            {
                "kind": kind,
                "entrypoint": "clamp_count(value)",
                "given": given,
                "when": "Call clamp_count with the given integer.",
                "then": expected,
                "paths": paths,
                "runner": "unittest",
                "test": "tests/test_behavior.py::Counts::test_" + kind,
            }
            for kind, given, expected in [
                ("success", "A count of 4", "Return 4"),
                ("boundary", "A count of -1", "Return 0"),
            ]
        ],
        "pending": [],
    }


def write_handoff(root, record):
    """Write the feature's versioned plan in the fixture repository."""
    path = root / "docs/session-plans/clamp-count.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")


def write_count(root, code, boundary="self.assertEqual(clamp(-1), 0)"):
    """Install the public function and separate executable acceptance cases."""
    source = root / code
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "def clamp_count(value):\n    return max(0, value)\n", encoding="utf-8"
    )
    suite = root / "tests/test_behavior.py"
    suite.parent.mkdir(exist_ok=True)
    suite.write_text(
        "import runpy\nimport unittest\n"
        f"clamp = runpy.run_path({code!r})['clamp_count']\n"
        "class Counts(unittest.TestCase):\n"
        "    def test_success(self):\n        self.assertEqual(clamp(4), 4)\n"
        f"    def test_boundary(self):\n        {boundary}\n",
        encoding="utf-8",
    )


def exercise_handoff_success(root, git, code):
    """Commit a plan for future files and push it, then implement and push the feature."""
    before = git("rev-parse", "HEAD").stdout
    write_handoff(root, {"stage": "plan"})
    git("add", "docs")
    write_handoff(root, handoff_record(code, "plan"))
    result = git("commit", "-m", "Incomplete staged plan", success=False)
    assert result.returncode and b"request needs concrete text" in result.stderr, (
        result.stderr
    )
    assert git("rev-parse", "HEAD").stdout == before
    incomplete = handoff_record(code, "plan")
    incomplete["steps"][0]["verify"] = {"command": "python3 -m unittest"}
    write_handoff(root, incomplete)
    git("add", "docs")
    result = git("commit", "-m", "Omit the expected result", success=False)
    assert result.returncode and b"step.verify.expected" in result.stderr
    assert git("rev-parse", "HEAD").stdout == before
    write_handoff(root, handoff_record(code, "plan"))
    git("add", "docs")
    git("commit", "-m", "Plan count behavior")
    git("push", "origin", "feature/gate")
    write_count(root, code)
    git("add", code, "tests/test_behavior.py")
    result = git("commit", "-m", "Implementation without mapping", success=False)
    assert (
        result.returncode
        and b"missing implementation acceptance coverage" in result.stderr
    )
    write_handoff(root, handoff_record(code, "implementation"))
    git("add", "docs")
    git("commit", "-m", "Implement count behavior")
    git("push", "origin", "feature/gate")
    assert (
        git("rev-parse", "HEAD").stdout.strip()
        in git("ls-remote", "origin", "feature/gate").stdout
    )


def exercise_handoff_rejections(root, git, code):
    """Keep the remote branch absent for skipped, failing, and missing acceptance."""
    record = handoff_record(code, "implementation")
    write_handoff(root, record)
    for body, expected in [
        ("pass", b"empty acceptance test"),
        ("self.skipTest('unavailable')", b"required test did not pass"),
        ("self.assertEqual(clamp(-1), 7)", b"required test did not pass"),
    ]:
        write_count(root, code, body)
        git("add", "docs", code, "tests/test_behavior.py")
        git("commit", "-m", "Record a boundary case")
        result = git("push", "origin", "feature/gate", success=False)
        assert result.returncode and expected in result.stderr + result.stdout, (
            result.stderr
        )
        assert not git("ls-remote", "origin", "feature/gate").stdout
    write_count(root, code)
    (root / code).write_text(
        "def clamp_count(value):\n    return value\n", encoding="utf-8"
    )
    git("add", code, "tests/test_behavior.py")
    git("commit", "-m", "Remove the clamp while retaining its tests")
    result = git("push", "origin", "feature/gate", success=False)
    assert (
        result.returncode
        and b"required test did not pass" in result.stdout + result.stderr
    )
    assert not git("ls-remote", "origin", "feature/gate").stdout
    # Restore the implementation so the next failure isolates the missing selector.
    write_count(root, code)
    git("add", code)
    record["acceptance"][1]["test"] = "tests/test_missing.py::Counts::test_boundary"
    write_handoff(root, record)
    git("add", "docs")
    git("commit", "-m", "Point to missing selector")
    result = git("push", "origin", "feature/gate", success=False)
    assert (
        result.returncode
        and b"missing acceptance test" in result.stderr + result.stdout
    ), result.stderr
    assert not git("ls-remote", "origin", "feature/gate").stdout


class RemoteTests(unittest.TestCase):
    """Disposable remotes prove nonzero gates prevent remote updates.

    Scanner doubles exercise orchestration; real scanners require separate runs.
    """

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="push-gate-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / "repo"
        self.remote = self.root / "remote.git"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = dict(
            os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1"
        )
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]
        self.command(
            "git", "init", "--quiet", "--bare", str(self.remote), cwd=self.root
        )
        self.command(
            "git", "init", "--quiet", "-b", "main", str(self.repo), cwd=self.root
        )
        self.command("git", "config", "user.name", "Synthetic Gate Test")
        self.command("git", "config", "user.email", "gate@example.test")
        self.command("git", "config", "commit.gpgsign", "false")
        self.command("git", "remote", "add", "origin", str(self.remote))
        shutil.copytree(ROOT / "tools/push_gate", self.repo / "tools/push_gate")
        (self.repo / "tests").mkdir()
        (self.repo / "tests/test_local_push_gate.py").write_text(
            "import unittest\nclass T(unittest.TestCase):\n def test_ok(self):\n  self.assertTrue(True)\n"
        )
        (self.repo / "implementation.py").write_text("VALUE = 1\n")
        (self.repo / ".gitattributes").write_text("committed-only.py export-ignore\n")
        (self.repo / "committed-only.py").write_text("VALUE = 1\n")
        policy = {
            "default_branch": "main",
            "tools": {"semgrep": "1.182.0", "trivy": "0.76.1"},
            "test_areas": [
                {
                    "name": "application",
                    "implementation": [r"^implementation\.py$"],
                    "tests": [r"^tests/.*\.py$"],
                }
            ],
            "checks": [
                [
                    "{python}",
                    "-c",
                    "import implementation; assert implementation.VALUE == 1",
                ]
            ],
        }
        if self._testMethodName.startswith("test_handoff"):
            policy["session_handoffs"] = True
            policy["checks"] = [
                [
                    "{python}",
                    "tools/push_gate/session_delivery.py",
                    "push",
                    "{base}",
                    "{sha}",
                ]
            ]
        (self.repo / "tools/push_gate/policy.json").write_text(json.dumps(policy))
        self.commit("fixture baseline")
        self.command("git", "push", "--quiet", "origin", "main")
        self.command("git", "checkout", "--quiet", "-b", "feature/gate")
        scanner = """#!/usr/bin/env python3
import json,pathlib,sys
name=pathlib.Path(sys.argv[0]).name
if '--version' in sys.argv:
 print('1.182.0' if name=='semgrep' else 'Version: 0.76.1');sys.exit(0)
assert not pathlib.Path('private-untracked.txt').exists()
assert pathlib.Path('committed-only.py').exists()
report=pathlib.Path(sys.argv[sys.argv.index('--output')+1])
data = {'results': [], 'errors': []} if name=='semgrep' else {'Results': []}
report.write_text(json.dumps(data))
if pathlib.Path(name+'-fail').exists(): sys.exit(1)
"""
        for name in ("semgrep", "trivy"):
            path = self.bin / name
            path.write_text(scanner)
            path.chmod(0o755)
        self.command(sys.executable, "tools/push_gate/gate.py", "install")
        (self.repo / "private-untracked.txt").write_text(
            "PRIVATE LOCAL DATA MUST NEVER BE SCANNED\n"
        )

    def command(self, *argv, cwd=None, success=True):
        result = subprocess.run(
            argv, cwd=cwd or self.repo, env=self.env, capture_output=True, check=False
        )
        if success:
            self.assertEqual(
                result.returncode, 0, result.stderr.decode(errors="replace")
            )
        return result

    def commit(self, message):
        self.command("git", "add", "--", ".", ":(exclude)private-untracked.txt")
        self.command("git", "commit", "--quiet", "--allow-empty", "-m", message)
        return self.command("git", "rev-parse", "HEAD").stdout.strip()

    def remote_tip(self):
        return self.command(
            "git", "ls-remote", "origin", "refs/heads/feature/gate"
        ).stdout

    def fixture_git(self, *args, success=True):
        """Invoke the installed hooks with the disposable Git configuration."""
        return self.command("git", *args, success=success)

    def test_handoff_success(self):
        """Deliver a planning-only change and its eventual working implementation."""
        exercise_handoff_success(self.repo, self.fixture_git, "implementation.py")

    def test_handoff_documentation_and_prompt(self):
        """Ordinary docs pass alone while a plugin command still needs coverage."""
        nested = self.repo / "plugins/example/docs/operations.md"
        nested.parent.mkdir(parents=True)
        nested.write_text("# Operations guide\n")
        (self.repo / "SECURITY.md").write_text("# Reporting a concern\n")
        self.fixture_git("add", "SECURITY.md", "plugins")
        self.fixture_git("commit", "-m", "Update the security and operations guides")
        self.fixture_git("push", "origin", "feature/gate")
        prompt = self.repo / "plugins/example/commands/count.md"
        prompt.parent.mkdir()
        prompt.write_text("Count the selected items.\n")
        self.fixture_git("add", "plugins")
        result = self.fixture_git(
            "commit", "-m", "Change command behavior", success=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"missing implementation acceptance coverage", result.stderr)

    def test_handoff_incremental_without_main(self):
        """A previously committed implementation record covers only its named paths."""
        code = "implementation.py"
        write_handoff(self.repo, handoff_record(code, "implementation"))
        write_count(self.repo, code)
        self.commit("Implement count behavior")
        self.fixture_git("update-ref", "-d", "refs/remotes/origin/main")
        self.fixture_git("branch", "-D", "main")
        (self.repo / code).write_text(
            "def clamp_count(value):\n    return max(value, 0)\n"
        )
        self.fixture_git("add", code)
        self.fixture_git("commit", "-m", "Refine the same count behavior")
        self.fixture_git("push", "origin", "feature/gate")
        (self.repo / "other.py").write_text("VALUE = 2\n")
        self.fixture_git("add", "other.py")
        result = self.fixture_git(
            "commit", "-m", "Add an unrelated behavior", success=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            b"missing implementation acceptance coverage for other.py", result.stderr
        )

    def test_handoff_rejections(self):
        """Refuse skipped, failing, and missing selectors even with a passing neighbor."""
        exercise_handoff_rejections(self.repo, self.fixture_git, "implementation.py")

    def test_success_uses_pushed_commit_with_dirty_worktree(self):
        sha = self.commit("successful fixture")
        (self.repo / "implementation.py").write_text(
            "raise RuntimeError('dirty file must not run')\n"
        )
        self.command("git", "push", "--quiet", "origin", "feature/gate")
        self.assertIn(sha, self.remote_tip())

    def test_push_validates_selected_commit_when_head_differs(self):
        selected = self.commit("selected good commit").decode()
        (self.repo / "implementation.py").write_text("VALUE = 2\n")
        self.commit("bad HEAD that is not being pushed")
        self.command(
            "git", "push", "--quiet", "origin", selected + ":refs/heads/feature/gate"
        )
        self.assertIn(selected.encode(), self.remote_tip())

    def test_nonbehavioral_exemption_requires_exact_hashes(self):
        original = (self.repo / "implementation.py").read_text()
        changed = original.rstrip() + "  # documented equivalent comment\n"
        (self.repo / "implementation.py").write_text(changed)
        exemption = {
            "implementation.py": {
                "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
                "after_sha256": hashlib.sha256(changed.encode()).hexdigest(),
                "reason": (
                    "Only an explanatory comment changes; execution remains equivalent."
                ),
            }
        }
        (self.repo / "push-gate-nonbehavioral.json").write_text(json.dumps(exemption))
        self.commit("exact nonbehavioral exemption")
        self.command("git", "push", "--quiet", "origin", "feature/gate")
        original_tip = self.remote_tip()
        (self.repo / "implementation.py").write_text(changed + "# stale exemption\n")
        self.commit("stale exemption must fail")
        result = self.command(
            "git", "push", "--quiet", "origin", "feature/gate", success=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Meaningful test update", result.stderr)
        self.assertEqual(self.remote_tip(), original_tip)

    def test_checks_and_scanners_prevent_remote_update(self):
        self.command("git", "push", "--quiet", "origin", "feature/gate")
        original = self.remote_tip()
        for name in ("semgrep", "trivy"):
            with self.subTest(scanner=name):
                (self.repo / (name + "-fail")).write_text("failure canary\n")
                self.commit("scanner failure fixture")
                result = self.command(
                    "git", "push", "--quiet", "origin", "feature/gate", success=False
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.remote_tip(), original)
                (self.repo / (name + "-fail")).unlink()
        (self.repo / "implementation.py").write_text("VALUE = 2\n")
        (self.repo / "tests/test_changed.py").write_text(
            "def test_changed():\n assert 2 == 2\n"
        )
        self.commit("canonical check failure fixture")
        result = self.command(
            "git", "push", "--quiet", "origin", "feature/gate", success=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.remote_tip(), original)

    def test_missing_tool_prevents_remote_update(self):
        self.commit("missing tool fixture")
        (self.bin / "semgrep").unlink()
        # A failing executable is used because another installation may be on PATH.
        (self.bin / "semgrep").write_text("#!/bin/sh\nexit 127\n")
        (self.bin / "semgrep").chmod(0o755)
        result = self.command(
            "git", "push", "--quiet", "origin", "feature/gate", success=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.remote_tip(), b"")

    def test_obsolete_scanner_versions_prevent_remote_update(self):
        for name, version in (("semgrep", "1.179.0"), ("trivy", "Version: 0.75.0")):
            with self.subTest(scanner=name):
                executable = self.bin / name
                original = executable.read_text()
                try:
                    executable.write_text(
                        f"#!/usr/bin/env python3\nprint({version!r})\n"
                    )
                    result = self.command(
                        "git",
                        "push",
                        "--quiet",
                        "origin",
                        "feature/gate",
                        success=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"Required {name} version".encode(), result.stderr)
                    self.assertEqual(self.remote_tip(), b"")
                finally:
                    executable.write_text(original)

    def test_branch_wide_requirement_survives_previous_push(self):
        self.command("git", "push", "--quiet", "origin", "feature/gate")
        original = self.remote_tip()
        (self.repo / "implementation.py").write_text(
            "VALUE = 1  # implementation edit\n"
        )
        self.commit("implementation without assertions")
        result = self.command(
            "git", "push", "--quiet", "origin", "feature/gate", success=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Meaningful test update", result.stderr)
        self.assertEqual(self.remote_tip(), original)

    def test_changed_policy_is_blocked(self):
        (self.repo / "tools/push_gate/semgrep.yml").write_text("rules: []\n")
        self.commit("unreviewed policy change")
        result = self.command(
            "git", "push", "--quiet", "origin", "feature/gate", success=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"differs from installed", result.stderr)
        self.assertEqual(self.remote_tip(), b"")

    def test_symlink_prevents_remote_update(self):
        (self.repo / "linked-private.txt").symlink_to(self.root / "outside.txt")
        self.commit("symlink fixture")
        result = self.command(
            "git", "push", "--quiet", "origin", "feature/gate", success=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Unsupported symlink", result.stderr)
        self.assertEqual(self.remote_tip(), b"")

    def test_install_preserves_hooks_and_restores_configuration(self):
        self.command(sys.executable, "tools/push_gate/gate.py", "uninstall")
        hooks = self.repo / ".githooks"
        hooks.mkdir()
        original = hooks / "pre-push"
        original.write_text("#!/bin/sh\nexit 8\n")
        original.chmod(0o755)
        before_commit = hooks / "pre-commit"
        before_commit.write_text("#!/bin/sh\ntouch hook-executed\n")
        before_commit.chmod(0o755)
        self.command("git", "config", "core.hooksPath", ".githooks")
        revision = self.command("git", "rev-parse", "HEAD").stdout.decode().strip()
        rejected = self.command(
            sys.executable, "tools/push_gate/gate.py", "install", success=False
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.command(
            sys.executable,
            "tools/push_gate/gate.py",
            "install",
            "--replace",
            "--revision",
            revision,
        )
        self.assertEqual(original.read_text(), "#!/bin/sh\nexit 8\n")
        self.command(
            "git", "commit", "--quiet", "--allow-empty", "-m", "forward other hook"
        )
        self.assertTrue((self.repo / "hook-executed").exists())
        self.command(sys.executable, "tools/push_gate/gate.py", "uninstall")
        self.assertEqual(
            self.command("git", "config", "--get", "core.hooksPath").stdout.strip(),
            b".githooks",
        )

    def test_hook_uses_actual_push_destination(self):
        alternate = self.root / "alternate.git"
        self.command("git", "init", "--quiet", "--bare", str(alternate), cwd=self.root)
        self.command("git", "config", "remote.origin.pushurl", str(alternate))
        result = self.command(
            "git", "push", "--quiet", "origin", "feature/gate", success=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Remote default branch is absent", result.stderr)
        self.assertEqual(self.command("git", "ls-remote", str(alternate)).stdout, b"")


if __name__ == "__main__":
    unittest.main()
