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

    def verify(self, versions=None, *, python_version=(3, 11, 0), import_error=None):
        if versions is None:
            versions = {"pytest": "8.3.5", "pytest-bdd": "8.1.0"}

        def installed(name):
            if name not in versions:
                raise importlib.metadata.PackageNotFoundError(name)
            return versions[name]

        with patch.object(prerequisites.sys, "version_info", python_version), \
             patch.object(prerequisites, "version", side_effect=installed), \
             patch.object(prerequisites, "import_module", side_effect=import_error) as imports, \
             patch.object(subprocess, "run", side_effect=AssertionError("unexpected subprocess")), \
             redirect_stdout(self.output), redirect_stderr(self.output):
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
        result, imports = self.verify(python_version=(3, 10, 16))
        self.assertFalse(result)
        imports.assert_not_called()
        self.assertIn("Python 3.11 or newer", self.output.getvalue())

    def test_incompatible_declared_version(self):
        result, _ = self.verify({"pytest": "7.4.4", "pytest-bdd": "8.1.0"})
        self.assertFalse(result)
        self.assertIn("pytest: installed 7.4.4, requires >=8.0", self.output.getvalue())

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

    def test_release_version_comparison(self):
        for installed, accepted in (("8.0", True), ("8.0.0", True),
                                    ("8.0.0.post1", True), ("8.10.0", True),
                                    ("8.0rc1", False), ("8.0.dev1", False)):
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
        with patch.object(gate, "check_prerequisites", return_value=False), \
             patch.object(gate, "validate_python") as syntax, \
             patch.object(gate, "run") as run:
            self.assertEqual(gate.main(), 1)
        syntax.assert_not_called()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
