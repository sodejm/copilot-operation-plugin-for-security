"""Regression tests for exact-commit push policy and failure propagation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "local_push_gate", ROOT / "tools/push_gate/gate.py"
)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class PolicyTests(unittest.TestCase):
    """Exercise closed policy and meaningful assertion detection."""

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
            "import unittest\nclass T(unittest.TestCase):\n"
            " def test_ok(self):\n  self.assertTrue(True)\n"
        )
        (self.repo / "implementation.py").write_text("VALUE = 1\n")
        (self.repo / ".gitattributes").write_text("committed-only.py export-ignore\n")
        (self.repo / "committed-only.py").write_text("VALUE = 1\n")
        policy = {
            "default_branch": "main",
            "tools": {"semgrep": "1.179.0", "trivy": "0.75.0"},
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
        (self.repo / "tools/push_gate/policy.json").write_text(json.dumps(policy))
        self.commit("fixture baseline")
        self.command("git", "push", "--quiet", "origin", "main")
        self.command("git", "checkout", "--quiet", "-b", "feature/gate")
        scanner = """#!/usr/bin/env python3
import json,pathlib,sys
name=pathlib.Path(sys.argv[0]).name
if '--version' in sys.argv:
 print('1.179.0' if name=='semgrep' else 'Version: 0.75.0');sys.exit(0)
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
