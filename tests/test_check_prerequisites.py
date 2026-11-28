# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Offline regression tests for the contributor prerequisite preflight."""

import importlib.metadata
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "agent"))
import check as gate
import check_prerequisites as prerequisites


class PrerequisiteTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "requirements.txt").write_text(
            "# Contributor test dependencies\npytest>=8.0\npytest-bdd>=8.0\n",
            encoding="utf-8",
        )
        self.output = StringIO()

    def verify(self, versions=None, *, python_version=(3, 14, 0), import_error=None):
        if versions is None:
            versions = {"pytest": "8.3.5", "pytest-bdd": "8.1.0"}

        def installed(name):
            if name not in versions:
                raise importlib.metadata.PackageNotFoundError(name)
            return versions[name]

        with (
            patch.object(prerequisites.sys, "version_info", python_version),
            patch.object(prerequisites, "version", side_effect=installed),
            patch.object(prerequisites, "import_module", side_effect=import_error) as imports,
            patch.object(subprocess, "run", side_effect=AssertionError("unexpected subprocess")),
            redirect_stdout(self.output),
            redirect_stderr(self.output),
        ):
            result = prerequisites.check_prerequisites(self.root)
        return result, imports

    def test_prepared_environment_imports_every_declared_dependency(self):
        result, imports = self.verify()
        self.assertTrue(result)
        self.assertEqual([call.args[0] for call in imports.call_args_list], ["pytest", "pytest_bdd"])
        self.assertIn("Test prerequisites are ready", self.output.getvalue())

    def test_missing_dependency_has_actionable_remediation(self):
        result, _ = self.verify({"pytest": "8.3.5"})
        self.assertFalse(result)
        self.assertIn("pytest-bdd: missing", self.output.getvalue())
        self.assertIn("python -m pip install -r requirements.txt", self.output.getvalue())
        self.assertIn("virtual environment", self.output.getvalue())

    def test_unsupported_python_stops_before_dependency_imports(self):
        result, imports = self.verify(python_version=(3, 13, 16))
        self.assertFalse(result)
        imports.assert_not_called()
        self.assertIn("Python 3.14 or newer", self.output.getvalue())

    def test_incompatible_declared_version(self):
        result, _ = self.verify({"pytest": "7.4.4", "pytest-bdd": "8.1.0"})
        self.assertFalse(result)
        self.assertIn("pytest: installed 7.4.4, requires >=8.0", self.output.getvalue())

    def test_exclusive_upper_bound_is_enforced(self):
        (self.root / "requirements.txt").write_text("pytest>=9.1.1,<9.2\n", encoding="utf-8")
        for installed, accepted in (
            ("9.1.1", True),
            ("9.1.9", True),
            ("9.2", False),
            ("9.2.0.post1", False),
            ("10.0", False),
        ):
            with self.subTest(installed=installed):
                self.output = StringIO()
                result, _ = self.verify({"pytest": installed})
                self.assertEqual(result, accepted)
                if not accepted:
                    self.assertIn(f"pytest: installed {installed}, requires <9.2", self.output.getvalue())

    def test_broken_import_is_a_prerequisite_failure(self):
        result, _ = self.verify(import_error=ImportError("broken test dependency"))
        self.assertFalse(result)
        self.assertIn("pytest: cannot import pytest", self.output.getvalue())

    def test_unsupported_declaration_is_not_ignored(self):
        (self.root / "requirements.txt").write_text("pytest~=8.0\n", encoding="utf-8")
        result, imports = self.verify()
        self.assertFalse(result)
        imports.assert_not_called()
        self.assertIn("requirements.txt:1", self.output.getvalue())

    def test_invalid_version_range_is_rejected(self):
        (self.root / "requirements.txt").write_text("pytest>=9.2,<9.2.0\n", encoding="utf-8")
        result, imports = self.verify()
        self.assertFalse(result)
        imports.assert_not_called()
        self.assertIn("minimum must be less than exclusive upper bound", self.output.getvalue())

    def test_release_version_comparison(self):
        for installed, accepted in (
            ("8.0", True),
            ("8.0.0", True),
            ("8.0.0.post1", True),
            ("8.10.0", True),
            ("8.0rc1", False),
            ("8.0.dev1", False),
        ):
            with self.subTest(installed=installed):
                result, _ = self.verify({"pytest": installed, "pytest-bdd": "8.1.0"})
                self.assertEqual(result, accepted)

    def test_empty_or_missing_declarations_fail(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                path = self.root / "requirements.txt"
                if missing:
                    path.unlink()
                else:
                    path.write_text("# No declarations\n", encoding="utf-8")
                result, imports = self.verify()
                self.assertFalse(result)
                imports.assert_not_called()

    def test_duplicate_declarations_fail(self):
        (self.root / "requirements.txt").write_text("pytest\npytest>=8.0\n", encoding="utf-8")
        result, imports = self.verify()
        self.assertFalse(result)
        imports.assert_not_called()
        self.assertIn("duplicate dependency pytest", self.output.getvalue())

    def test_both_entry_points_use_an_empty_selected_environment(self):
        environment = self.root / "empty-environment"
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(environment)], check=True)
        executable = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        commands = [[str(executable), "scripts/agent/check.py"]]
        if shutil.which("make"):
            commands.append(["make", "check", f"PYTHON={executable}"])
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(str(executable), output)
                self.assertIn("pytest: missing", output)
                self.assertIn("python -m pip install -r requirements.txt", output)
                self.assertNotIn("Python sources parse successfully", output)
                self.assertFalse(any(line.startswith("+ ") for line in output.splitlines()))
        self.assertFalse(any(environment.rglob("pytest*")))

    def test_gate_stops_before_any_repository_checks(self):
        with (
            patch.object(gate, "check_prerequisites", return_value=False),
            patch.object(gate, "validate_python") as syntax,
            patch.object(gate, "run") as run,
        ):
            self.assertEqual(gate.main(), 1)
        syntax.assert_not_called()
        run.assert_not_called()

    def test_push_gate_coverage_option_runs_root_tests_once_with_its_policy(self):
        commands = []
        with (
            patch.object(gate, "check_prerequisites", return_value=True),
            patch.object(gate, "validate_python", return_value=True),
            patch.object(gate, "run", side_effect=lambda command, **_: commands.append(command) or True),
            patch.object(gate, "repository_files", return_value=[]),
        ):
            self.assertEqual(gate.main(["--pytest-coverage"]), 0)

        coverage_runs = [command for command in commands if command[1:4] == ["-m", "coverage", "run"]]
        self.assertEqual(len(coverage_runs), 1)
        self.assertEqual(
            coverage_runs[0],
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--branch",
                "--omit=*/cops-auth-source-*/*",
                "-m",
                "pytest",
            ],
        )
        self.assertIn([sys.executable, "-m", "coverage", "report"], commands)

    def test_default_check_keeps_the_standard_root_pytest_command(self):
        commands = []
        with (
            patch.object(gate, "check_prerequisites", return_value=True),
            patch.object(gate, "validate_python", return_value=True),
            patch.object(gate, "run", side_effect=lambda command, **_: commands.append(command) or True),
            patch.object(gate, "repository_files", return_value=[]),
        ):
            self.assertEqual(gate.main([]), 0)

        self.assertIn([sys.executable, "-m", "pytest", "tests", "-q"], commands)
        self.assertFalse(any(command[1:4] == ["-m", "coverage", "run"] for command in commands))

    def test_push_gate_coverage_option_skips_report_after_failed_root_tests(self):
        commands = []

        def record(command, **_):
            commands.append(command)
            return command[1:4] != ["-m", "coverage", "run"]

        with (
            patch.object(gate, "check_prerequisites", return_value=True),
            patch.object(gate, "validate_python", return_value=True),
            patch.object(gate, "run", side_effect=record),
            patch.object(gate, "repository_files", return_value=[]),
        ):
            self.assertEqual(gate.main(["--pytest-coverage"]), 1)

        self.assertNotIn([sys.executable, "-m", "coverage", "report"], commands)


if __name__ == "__main__":
    unittest.main()
