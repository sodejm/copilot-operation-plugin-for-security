#!/usr/bin/env python3
"""Read-only repository checks; generated artifacts stay in the disposable snapshot."""

from __future__ import annotations

import glob
import os
import subprocess
import sys
from pathlib import Path


def run(*argv):
    """Propagate missing executables, signal failures and nonzero exit status."""
    print("validation: " + " ".join(argv), flush=True)
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL)


def main():
    """Run the repository's established validation entry points."""
    stack, base, sha = sys.argv[1:]
    # This file is called only inside the detached, committed snapshot.
    venv = Path.cwd().parent / "validation-venv"
    run("uv", "venv", str(venv), "--python", sys.executable)
    python = str(venv / "bin/python")
    run(
        "uv",
        "pip",
        "install",
        "--python",
        python,
        "-r",
        "tools/push_gate/requirements.txt",
    )
    test_file = (
        "gate_tests/test_local_push_gate.py"
        if stack in {"dateutil", "ancestry"}
        else "tests/test_local_push_gate.py"
    )
    run(
        python,
        "-m",
        "ruff",
        "check",
        "--config",
        "tools/push_gate/ruff.toml",
        "tools/push_gate",
        test_file,
    )
    run(
        python,
        "-m",
        "ruff",
        "format",
        "--check",
        "--config",
        "tools/push_gate/ruff.toml",
        "tools/push_gate",
        test_file,
    )
    workflows = sorted(
        glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml")
    )
    if workflows:
        run("actionlint", *workflows)
    shell = subprocess.check_output(["git", "ls-files", "*.sh"], text=True).splitlines()
    for path in shell:
        run("bash", "-n", path)
    if shell:
        run("shellcheck", "--severity=error", *shell)
    dockerfiles = [
        path
        for path in subprocess.check_output(["git", "ls-files"], text=True).splitlines()
        if Path(path).name == "Dockerfile" or path.endswith(".Dockerfile")
    ]
    for path in dockerfiles:
        run("hadolint", "--failure-threshold", "error", path)
    if stack == "park":
        os.environ["PATH"] = str(Path(python).parent) + os.pathsep + os.environ["PATH"]
        run("make", "check")
        run(
            python,
            "-m",
            "coverage",
            "run",
            "--branch",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
        )
        run(python, "-m", "coverage", "report")
    elif stack == "cops":
        run(
            "uv",
            "pip",
            "install",
            "--python",
            python,
            "-r",
            "requirements.txt",
        )
        os.environ["PATH"] = str(Path(python).parent) + os.pathsep + os.environ["PATH"]
        run("make", "check", "PYTHON=" + python)
        run(
            python,
            "scripts/agent/check_issue_coverage.py",
            "--base",
            base,
            "--head",
            sha,
            "--branch",
            "codex/local-pre-push-gate",
        )
        run(python, "-m", "ruff", "check", ".")
        changed_python = [
            path
            for path in subprocess.check_output(
                ["git", "diff", "--name-only", "--diff-filter=ACMR", base, sha],
                text=True,
            ).splitlines()
            if path.endswith(".py")
            and not path.startswith("tools/push_gate/")
            and path != "tests/test_local_push_gate.py"
            and Path(path).is_file()
        ]
        if changed_python:
            run(python, "-m", "ruff", "format", "--check", *changed_python)
        run(python, "-m", "coverage", "run", "--branch", "-m", "pytest")
        run(python, "-m", "coverage", "report")
    elif stack == "best":
        run("uv", "pip", "install", "--python", python, ".[dev]")
        run(python, "-m", "ruff", "check", "src", "tests")
        run(python, "-m", "ruff", "format", "--check", "src", "tests")
        run(python, "-m", "mypy", "src")
        run(
            python,
            "-m",
            "coverage",
            "run",
            "--branch",
            "--source=best_rangehood",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
        )
        run(
            python,
            "-W",
            "error::RuntimeWarning",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
        )
        run(python, "-m", "coverage", "report")
        run(python, "-m", "build")
    elif stack == "aegis":
        run("pnpm", "install", "--frozen-lockfile")
        run("pnpm", "exec", "playwright", "install", "chromium")
        run("pnpm", "run", "verify")
        run("pnpm", "--dir", "apps/web", "build")
        run("go", "build", "./...")
    elif stack == "ancestry":
        run(
            "make",
            "setup",
            "lock-check",
            "test",
            "lint",
            "typecheck",
            "security",
            "workflow-audit",
            "container-policy",
            "package",
        )
        run(
            "make",
            "desktop-install",
            "desktop-check",
            "desktop-security",
            "code-docs-check",
        )
        run("pnpm", "--dir", "desktop", "test:coverage")
        run("pnpm", "--dir", "desktop", "exec", "playwright", "install", "chromium")
        run("make", "desktop-e2e")
    elif stack == "legend":
        run("uv", "pip", "install", "--python", python, ".[credentials]")
        run(
            python,
            "-m",
            "coverage",
            "run",
            "--branch",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
        )
        run(python, "-m", "coverage", "report")
        run(python, "-m", "build")
        run("bash", "scripts/terraform-quality.sh")
    elif stack in {"dateutil", "ancestry"}:
        run(
            "uv",
            "pip",
            "install",
            "--python",
            python,
            "-r",
            "requirements-dev.txt",
            "-r",
            "docs/requirements-docs.txt",
        )
        # Force the source package: documentation dependencies may install a
        # released dateutil that would otherwise receive the generated archive.
        os.environ["PYTHONPATH"] = str(Path.cwd() / "src")
        run(python, "updatezinfo.py")
        del os.environ["PYTHONPATH"]
        run("uv", "pip", "install", "--python", python, ".")
        run(
            python,
            "-m",
            "pytest",
            "tests",
            "docs",
            "--cov-config=tox.ini",
            "--cov=dateutil",
        )
        run(
            "uv",
            "pip",
            "install",
            "--python",
            python,
            "darker==3.0.0",
            "black",
            "isort>5.9",
        )
        run(
            str(Path(python).parent / "darker"),
            "--check",
            "--isort",
            "--revision",
            base + "..." + sha,
            "src",
            "tests",
        )
        run(python, "-m", "build", "--wheel", "--sdist")
        run(python, "-m", "sphinx", "-W", "-b", "html", "docs", "build/push-gate-html")
        run(
            python,
            "-m",
            "sphinx",
            "-W",
            "-b",
            "linkcheck",
            "docs",
            "build/push-gate-links",
        )
        run(python, "setup.py", "check", "-r", "-s")
    else:
        raise ValueError("Unknown repository validation profile")
    run(python, "-m", "pip_audit", "--timeout", "60")


if __name__ == "__main__":
    main()
