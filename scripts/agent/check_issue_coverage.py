#!/usr/bin/env python3
"""
Verify that documentation and test cases have been built/updated for an active issue/feature.
Standard-library Python only.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@dataclass
class EvaluationResult:
    issue_id: str | None = None
    doc_files: list[str] = field(default_factory=list)
    test_files: list[str] = field(default_factory=list)
    doc_exempt: bool = False
    doc_exempt_reason: str | None = None
    test_exempt: bool = False
    test_exempt_reason: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0


def extract_issue_identifier(branch_name: str, commit_messages: list[str]) -> str | None:
    """Extract issue number, scenario code, or feature slug from branch or commit messages."""
    # 1. Branch name: explicit issue prefix/suffix
    m = re.search(r"(?:issue|issues)[/-](\d+)", branch_name, re.IGNORECASE)
    if m:
        return m.group(1)

    m = re.search(r"^(\d+)[-_]", branch_name)
    if m:
        return m.group(1)

    # 2. Commit messages: Fixes #123, Resolves #123, Issue #123, #123
    for msg in commit_messages:
        m = re.search(r"(?:fixes|resolves|closes|issue)\s*#?(\d+)", msg, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"#(\d+)", msg)
        if m:
            return m.group(1)
        m = re.search(r"\b(COPS-[A-Z0-9\.]+-S\d+)\b", msg)
        if m:
            return m.group(1)

    # 3. Branch name: codex/slug or feat/slug
    m = re.search(r"(?:codex|feature|feat|fix)/([a-zA-Z0-9\-_]+)", branch_name, re.IGNORECASE)
    if m:
        return m.group(1)

    return None


def is_doc_file(filepath: str) -> bool:
    """Return True if path represents a documentation or specification file."""
    norm = filepath.replace("\\", "/").strip()
    if norm.startswith("docs/"):
        return True
    if norm.startswith("specs/") and not norm.startswith("specs/features/"):
        return True
    root_docs = {
        "readme.md",
        "architecture.md",
        "contributing.md",
        "security.md",
        "changelog.md",
        "governance.md",
    }
    if norm.lower() in root_docs:
        return True
    if re.search(r"^plugins/.+/README\.md$", norm, re.IGNORECASE):
        return True
    if re.search(r"^plugins/.+/docs/.+\.md$", norm, re.IGNORECASE):
        return True
    return False


def is_test_file(filepath: str) -> bool:
    """Return True if path represents an automated test or BDD scenario."""
    norm = filepath.replace("\\", "/").strip()
    if norm.startswith("tests/"):
        return True
    if norm.startswith("specs/features/"):
        return True
    if re.search(r"^plugins/.+/tests/.+\.py$", norm, re.IGNORECASE):
        return True
    return False


def check_exemptions(commit_messages: list[str]) -> tuple[bool, str | None, bool, str | None]:
    """Check for explicit documentation or test exemption tokens in commit messages."""
    doc_exempt = False
    doc_reason = None
    test_exempt = False
    test_reason = None

    for msg in commit_messages:
        dm = re.search(r"\[skip-docs(?::\s*([^\]]+))?\]", msg, re.IGNORECASE)
        if dm:
            doc_exempt = True
            doc_reason = (dm.group(1) or "explicit exemption").strip()

        tm = re.search(r"\[skip-tests(?::\s*([^\]]+))?\]", msg, re.IGNORECASE)
        if tm:
            test_exempt = True
            test_reason = (tm.group(1) or "explicit exemption").strip()

    return doc_exempt, doc_reason, test_exempt, test_reason


def evaluate_coverage(
    branch_name: str,
    modified_files: list[str],
    commit_messages: list[str],
) -> EvaluationResult:
    """Evaluate whether documentation and test requirements are satisfied."""
    result = EvaluationResult()
    result.issue_id = extract_issue_identifier(branch_name, commit_messages)
    doc_exempt, doc_reason, test_exempt, test_reason = check_exemptions(commit_messages)
    result.doc_exempt = doc_exempt
    result.doc_exempt_reason = doc_reason
    result.test_exempt = test_exempt
    result.test_exempt_reason = test_reason

    # Filter files
    for path in modified_files:
        if is_doc_file(path):
            result.doc_files.append(path)
        if is_test_file(path):
            result.test_files.append(path)

    issue_label = f"issue {result.issue_id}" if result.issue_id else "active change"

    # Validate documentation
    if not result.doc_files and not result.doc_exempt:
        result.errors.append(f"Missing documentation changes for {issue_label}")

    # Validate tests
    if not result.test_files and not result.test_exempt:
        result.errors.append(f"Missing test case changes for {issue_label}")

    return result


def get_git_diff_files(base: str | None, head: str, staged: bool) -> list[str]:
    """Retrieve list of modified/added files from Git."""
    if staged:
        cmd = ["git", "diff", "--name-only", "--cached"]
        res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]

    base_ref = base or "origin/main"
    files = set()

    # 1. Committed diff between base and head
    res = subprocess.run(["git", "diff", "--name-only", f"{base_ref}...{head}"], cwd=ROOT, capture_output=True, text=True, check=False)
    if res.returncode == 0:
        files.update(line.strip() for line in res.stdout.splitlines() if line.strip())
    elif base:
        res = subprocess.run(["git", "diff", "--name-only", base_ref, head], cwd=ROOT, capture_output=True, text=True, check=False)
        if res.returncode == 0:
            files.update(line.strip() for line in res.stdout.splitlines() if line.strip())

    # 2. If inspecting HEAD in working tree, also check unstaged/staged working tree modifications and untracked files
    if head == "HEAD":
        res_worktree = subprocess.run(["git", "diff", "--name-only"], cwd=ROOT, capture_output=True, text=True, check=False)
        if res_worktree.returncode == 0:
            files.update(line.strip() for line in res_worktree.stdout.splitlines() if line.strip())
        res_cached = subprocess.run(["git", "diff", "--name-only", "--cached"], cwd=ROOT, capture_output=True, text=True, check=False)
        if res_cached.returncode == 0:
            files.update(line.strip() for line in res_cached.stdout.splitlines() if line.strip())
        res_untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True, check=False)
        if res_untracked.returncode == 0:
            files.update(line.strip() for line in res_untracked.stdout.splitlines() if line.strip())

    return sorted(files)


def get_git_commit_messages(base: str | None, head: str, staged: bool) -> list[str]:
    """Retrieve commit messages from Git."""
    if staged:
        # Check last commit message or environment variable
        res = subprocess.run(["git", "log", "-1", "--format=%B"], cwd=ROOT, capture_output=True, text=True, check=False)
        return [res.stdout.strip()] if res.stdout.strip() else []

    base_ref = base or "origin/main"
    cmd = ["git", "log", f"{base_ref}..{head}", "--format=%B%x00"]
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        return []
    messages = [m.strip() for m in res.stdout.split("\x00") if m.strip()]
    return messages


def get_current_branch() -> str:
    res = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    return res.stdout.strip() if res.returncode == 0 else "unknown"


def run_tests(test_files: list[str]) -> bool:
    """Run pytest on the detected test files."""
    if not test_files:
        return True
    py_tests = [f for f in test_files if f.endswith(".py") and f.startswith("tests/")]
    if not py_tests:
        return True
    cmd = [sys.executable, "-m", "pytest", *py_tests, "-q"]
    print(f"+ {' '.join(cmd)}", flush=True)
    res = subprocess.run(cmd, cwd=ROOT, check=False)
    return res.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check issue documentation and test coverage.")
    parser.add_argument("--base", help="Base git reference (default: origin/main or main)")
    parser.add_argument("--head", default="HEAD", help="Head git reference (default: HEAD)")
    parser.add_argument("--staged", action="store_true", help="Check staged changes")
    parser.add_argument("--branch", help="Override branch name for testing")
    parser.add_argument("--files", nargs="*", help="Override file list for testing")
    parser.add_argument("--message", nargs="*", help="Override commit messages for testing")
    parser.add_argument("--run-tests", action="store_true", help="Execute detected tests")

    args = parser.parse_args()

    branch = args.branch or get_current_branch()
    files = args.files if args.files is not None else get_git_diff_files(args.base, args.head, args.staged)
    messages = args.message if args.message is not None else get_git_commit_messages(args.base, args.head, args.staged)

    # In local branch mode on main without diff, skip or pass
    if branch in ("main", "master") and not files and not args.staged:
        print("On default branch with no pending changes; issue coverage gate is idle.")
        return 0

    result = evaluate_coverage(branch, files, messages)

    print("=== COPS Issue Coverage Gate ===")
    print(f"Branch:            {branch}")
    print(f"Detected Issue:    {result.issue_id or 'none detected'}")
    print(f"Files Modified:    {len(files)}")
    print(f"Docs Modified:     {len(result.doc_files)}" + (f" (Exemption: {result.doc_exempt_reason})" if result.doc_exempt else ""))
    for doc in result.doc_files:
        print(f"  - {doc}")
    print(f"Tests Modified:    {len(result.test_files)}" + (f" (Exemption: {result.test_exempt_reason})" if result.test_exempt else ""))
    for test in result.test_files:
        print(f"  - {test}")

    if not result.passed:
        print("\n[FAILED] Issue coverage requirements not met:", file=sys.stderr)
        for err in result.errors:
            print(f"  - {err}", file=sys.stderr)
        print("\nRemediation per AGENTS.md and Constitution:", file=sys.stderr)
        print("  1. Update affected documentation in docs/, specs/, or root markdown files.", file=sys.stderr)
        print("  2. Add or update behavioral tests in tests/ or specs/features/.", file=sys.stderr)
        print("  3. For documented exceptions, include '[skip-docs: <rationale>]' or '[skip-tests: <rationale>]' in commit message.", file=sys.stderr)
        return 1

    print("\n[PASSED] Issue documentation and test case requirements satisfied.")

    if args.run_tests and result.test_files:
        print("\nExecuting detected test files...")
        if not run_tests(result.test_files):
            print("\n[FAILED] One or more detected tests failed.", file=sys.stderr)
            return 1
        print("[PASSED] All detected tests executed successfully.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
