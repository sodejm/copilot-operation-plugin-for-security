#!/usr/bin/env python3
"""Validate committed push tips in disposable Git snapshots.

The installed copy is trusted local policy. Repository content is executable code;
this runner is isolation from dirty files, not an operating-system sandbox.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SOURCE = "tools/push_gate"


class GateError(RuntimeError):
    """A failed prerequisite, policy, scan, or validation command."""


def run(argv, cwd, *, env=None, capture=True):
    """Run without a shell, preserving all nonzero and signal failures."""
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            check=False,
        )
    except OSError as exc:
        raise GateError(f"Cannot launch {argv[0]}: {exc.strerror}") from exc
    if result.returncode:
        # Command output can contain secret matches. Never echo it from the hook.
        raise GateError(f"{Path(argv[0]).name} failed (exit {result.returncode})")
    return result.stdout or b""


def git(root, *args):
    """Read Git using the caller's repository, without invoking a shell."""
    return run(["git", *args], root)


def clean_environment():
    """Remove inherited Git state, scanner overrides and application credentials."""
    allowed = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TERM", "SSH_AUTH_SOCK")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "PYTHONNOUSERSITE": "1",
            "CI": "true",
            "NO_COLOR": "1",
        }
    )
    return env


def tree(root, sha):
    """Enumerate every committed path, including export-ignored files."""
    entries = []
    for entry in git(root, "ls-tree", "-rz", sha).split(b"\0"):
        if entry:
            header, path = entry.split(b"\t", 1)
            mode, kind, oid = header.decode().split()
            name = path.decode("utf-8", errors="strict")
            if mode not in ("100644", "100755") or kind != "blob":
                raise GateError(f"Unsupported symlink/submodule: {name}")
            if "\n" in name or "\r" in name:
                raise GateError("Newline filenames are unsupported")
            entries.append((mode, oid, name))
    return entries


def policy_manifest(root, sha):
    """Bind the installed runner, rules, and commands to committed Git objects."""
    return {
        name: [mode, oid]
        for mode, oid, name in tree(root, sha)
        if name.startswith(SOURCE + "/")
    }


def state_directory(root):
    """Keep installation state in Git metadata, outside committed files."""
    return Path(
        git(root, "rev-parse", "--path-format=absolute", "--git-path", "push-gate")
        .decode()
        .strip()
    )


def shell_forward(argv):
    """Quote fixed executable paths; forward Git's arguments unchanged."""
    return (
        "#!/bin/sh\n# managed-local-push-gate\nexec "
        + " ".join(shlex.quote(str(arg)) for arg in argv)
        + ' "$@"\n'
    )


def install(root, replace=False, revision="HEAD"):
    """Install a reviewed committed revision without changing tracked hooks."""
    sha = git(root, "rev-parse", "--verify", revision + "^{commit}").decode().strip()
    manifest = policy_manifest(root, sha)
    if not manifest:
        raise GateError("Commit the gate before installation")
    state = state_directory(root)
    hooks = state / "hooks"
    effective = Path(
        git(root, "rev-parse", "--path-format=absolute", "--git-path", "hooks")
        .decode()
        .strip()
    )
    previous = effective / "pre-push"
    managed = effective == hooks
    if previous.is_file() and not managed and not replace:
        raise GateError("Existing pre-push hook: review it, then use install --replace")
    state.mkdir(parents=True, exist_ok=True)
    recovery = state / "installation.json"
    if not managed:
        if recovery.exists():
            raise GateError(
                "Prior installation state exists; reconcile recovery before reinstalling"
            )
        old = subprocess.run(
            ["git", "config", "--local", "--get", "core.hooksPath"],
            cwd=root,
            capture_output=True,
            check=False,
        )
        if old.returncode not in (0, 1):
            raise GateError("Cannot read prior hooksPath")
        recovery.write_text(
            json.dumps(
                {
                    "local_hooks_path": old.stdout.decode().strip()
                    if old.returncode == 0
                    else None,
                    "previous_hooks": str(effective),
                },
                indent=2,
            )
            + "\n"
        )
        hooks.mkdir(exist_ok=True)
        if previous.is_file():
            shutil.copy2(previous, state / "pre-push.before-local-push-gate")
        # Other Git hooks continue at their original paths and retain their cwd.
        if effective.is_dir():
            for existing in effective.iterdir():
                if (
                    existing.name != "pre-push"
                    and existing.is_file()
                    and os.access(existing, os.X_OK)
                ):
                    forward = hooks / existing.name
                    forward.write_text(shell_forward([existing]))
                    forward.chmod(0o755)
    elif not recovery.exists():
        raise GateError("Managed hooks have no recovery metadata")
    for name, (mode, oid) in manifest.items():
        destination = state / name.removeprefix(SOURCE + "/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(git(root, "cat-file", "blob", oid))
        destination.chmod(0o755 if mode == "100755" else 0o644)
    (state / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    hook = hooks / "pre-push"
    hook.write_text(shell_forward([sys.executable, state / "gate.py", "hook"]))
    hook.chmod(0o755)
    git(root, "config", "--local", "core.hooksPath", str(hooks))
    print(f"Installed committed policy {sha} at {hook}")


def uninstall(root):
    """Restore the exact prior local hooksPath; retain backups for review."""
    state = state_directory(root)
    recovery = state / "installation.json"
    if not recovery.exists():
        raise GateError("No installation recovery metadata")
    current = Path(
        git(root, "rev-parse", "--path-format=absolute", "--git-path", "hooks")
        .decode()
        .strip()
    )
    if current != state / "hooks":
        raise GateError("hooksPath changed after installation; reconcile it manually")
    previous = json.loads(recovery.read_text())["local_hooks_path"]
    if previous is None:
        git(root, "config", "--local", "--unset", "core.hooksPath")
    else:
        git(root, "config", "--local", "core.hooksPath", previous)
    recovery.rename(state / "installation.uninstalled.json")
    print("Restored prior hooksPath; policy and hook backup retained in " + str(state))


def parse_updates(data, default_branch):
    """Reject unsupported or protected updates before any remote ref is changed."""
    updates = []
    for line in data.splitlines():
        fields = line.split()
        if len(fields) != 4:
            raise GateError("Malformed pre-push input")
        local_ref, sha, remote_ref, old_sha = fields
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
            raise GateError("Invalid push object ID")
        if set(sha) == {"0"}:
            raise GateError("Deletion pushes require a separately reviewed bypass")
        if not remote_ref.startswith("refs/heads/"):
            raise GateError(
                "Tag and non-branch pushes require a separately reviewed bypass"
            )
        if remote_ref == "refs/heads/" + default_branch:
            raise GateError("Direct default-branch pushes are blocked")
        updates.append((local_ref, sha, remote_ref, old_sha))
    return updates


def executable_test(path, before, after):
    """Require changed executable test assertions, not comments or test deletion."""
    if path.endswith(".py"):

        def assertions(source):
            try:
                parsed = ast.parse(source)
            except (SyntaxError, ValueError):
                return set()
            return {
                ast.dump(node, include_attributes=False)
                for node in ast.walk(parsed)
                if isinstance(node, ast.Assert)
                or (
                    isinstance(node, ast.Call)
                    and (
                        isinstance(node.func, ast.Attribute)
                        and (
                            node.func.attr.startswith("assert")
                            or node.func.attr == "raises"
                        )
                    )
                )
            }

        return bool(assertions(after) - assertions(before))
    # Language heuristics are deliberately limited; review establishes relevance.
    if path.endswith(".tftest.hcl"):
        pattern = r"(?m)^\s*(?:condition|error_message)\s*=.+$"
        return bool(set(re.findall(pattern, after)) - set(re.findall(pattern, before)))
    pattern = (
        r"(?m)^.*(?:\bexpect\(|\bassert[.(]|\bt\.(?:Error|Fatal)|\bThen(?:\(|\s+)).*$"
    )
    return bool(set(re.findall(pattern, after)) - set(re.findall(pattern, before)))


def test_development(root, base, sha, policy):
    """Compare the whole branch against its default-branch merge base."""
    changed = git(root, "diff", "--name-only", "-z", base, sha).decode().split("\0")
    changed = [name for name in changed if name]

    def blob(revision, path):
        result = subprocess.run(
            ["git", "show", f"{revision}:{path}"],
            cwd=root,
            capture_output=True,
            check=False,
        )
        return (
            result.stdout.decode("utf-8", errors="replace")
            if not result.returncode
            else ""
        )

    exemptions_path = root / "push-gate-nonbehavioral.json"
    exemptions = (
        json.loads(exemptions_path.read_text()) if exemptions_path.exists() else {}
    )
    for area in policy["test_areas"]:
        implementations = [
            name
            for name in changed
            if any(re.search(expr, name) for expr in area["implementation"])
            and not any(re.search(expr, name) for expr in area["tests"])
        ]
        pending = []
        for name in implementations:
            exemption = exemptions.get(name, {})
            old_hash = hashlib.sha256(blob(base, name).encode()).hexdigest()
            new_hash = hashlib.sha256(blob(sha, name).encode()).hexdigest()
            if (
                exemption.get("before_sha256") == old_hash
                and exemption.get("after_sha256") == new_hash
                and len(exemption.get("reason", "").strip()) >= 40
            ):
                continue
            pending.append(name)
        if pending and not any(
            any(re.search(expr, name) for expr in area["tests"])
            and executable_test(name, blob(base, name), blob(sha, name))
            for name in changed
        ):
            raise GateError(
                f"Meaningful test update required for {area['name']}: "
                + ", ".join(pending[:5])
            )


def scanner_run(argv, snapshot, env, report_path, findings_key):
    """Expose useful identifiers without printing matched source or secret bytes."""
    result = subprocess.run(
        argv,
        cwd=snapshot,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    if report_path.exists():
        report = json.loads(report_path.read_text())
        if findings_key == "results":
            for finding in report.get("results", []):
                print(
                    "Semgrep: " + finding["check_id"] + " " + finding["path"],
                    file=sys.stderr,
                )
            for error in report.get("errors", []):
                print(
                    "Semgrep analysis error: " + str(error.get("path", "unknown path")),
                    file=sys.stderr,
                )
        else:
            for target in report.get("Results", []):
                for kind in ("Vulnerabilities", "Secrets", "Misconfigurations"):
                    for item in target.get(kind, []):
                        if (
                            item.get("Severity") in ("HIGH", "CRITICAL")
                            and item.get("Status") != "PASS"
                        ):
                            identifier = item.get(
                                "VulnerabilityID",
                                item.get("ID", item.get("RuleID", "unknown")),
                            )
                            print(
                                "Trivy: "
                                + identifier
                                + " "
                                + target.get("Target", "unknown path"),
                                file=sys.stderr,
                            )
    else:
        raise GateError(
            "Scanner produced no report; check installation and network access"
        )
    if result.returncode:
        raise GateError(
            f"{argv[0]} failed (exit {result.returncode}); findings above or scanner error"
        )
    return report


def scanners(snapshot, files, policy, env, temporary):
    """Run pinned scanners with local rules and no repository suppression files."""
    for tool in ("semgrep", "trivy"):
        output = run([tool, "--version"], snapshot, env=env).decode()
        if not re.search(
            r"(?<![\d.])" + re.escape(policy["tools"][tool]) + r"(?![\d.])", output
        ):
            raise GateError(f"Required {tool} version: {policy['tools'][tool]}")
    for name in files:
        data = (snapshot / name).read_bytes()
        if re.search(rb"(?m)^\s*(?:#|//|/\*)\s*trivy:\s*ignore", data):
            raise GateError(f"Inline Trivy suppression must be resolved: {name}")
    targets = [
        "./" + name
        for name in files
        if Path(name).suffix
        in (
            ".py",
            ".js",
            ".mjs",
            ".ts",
            ".tsx",
            ".go",
            ".sh",
            ".yaml",
            ".yml",
            ".tf",
            ".hcl",
        )
    ]
    empty_ignore = temporary / "empty-semgrep-ignore"
    empty_ignore.write_text("")
    semgrep_report = temporary / "semgrep.json"
    report = scanner_run(
        [
            "semgrep",
            "scan",
            "--config",
            str(snapshot / SOURCE / "semgrep.yml"),
            "--strict",
            "--error",
            "--metrics=off",
            "--disable-version-check",
            "--disable-nosem",
            "--no-git-ignore",
            "--max-target-bytes=0",
            "--x-semgrepignore-filename",
            str(empty_ignore),
            "--json",
            "--output",
            str(semgrep_report),
            *targets,
        ],
        snapshot,
        env,
        semgrep_report,
        "results",
    )
    if report.get("errors") or report.get("results"):
        raise GateError("Semgrep findings or incomplete analysis")
    trivy_report = temporary / "trivy.json"
    report = scanner_run(
        [
            "trivy",
            "fs",
            "--config",
            "",
            "--ignorefile",
            "",
            "--secret-config",
            "",
            "--scanners",
            "vuln,secret,misconfig",
            "--severity",
            "HIGH,CRITICAL",
            "--include-dev-deps",
            "--show-suppressed",
            "--exit-code",
            "1",
            "--format",
            "json",
            "--disable-telemetry",
            "--skip-version-check",
            "--timeout",
            "15m",
            "--skip-dirs",
            ".git",
            "--output",
            str(trivy_report),
            ".",
        ],
        snapshot,
        env,
        trivy_report,
        "Results",
    )
    for result in report.get("Results", []):
        for kind in (
            "Vulnerabilities",
            "Secrets",
            "Misconfigurations",
            "ExperimentalModifiedFindings",
        ):
            if any(
                item.get("Severity") in ("HIGH", "CRITICAL")
                and item.get("Status", "FAIL") != "PASS"
                for item in result.get(kind, [])
            ):
                raise GateError(
                    "Trivy HIGH/CRITICAL findings (including suppressed results)"
                )


def validate(root, sha, remote_url, policy, manifest):
    """Validate the pushed object, never the caller's index or worktree."""
    if policy_manifest(root, sha) != manifest:
        raise GateError(
            "Pushed gate policy differs from installed policy; review and reinstall"
        )
    if git(root, "cat-file", "-t", sha).strip() != b"commit":
        raise GateError("Push tip must be a commit object")
    entries = tree(root, sha)
    env = clean_environment()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="local-push-gate-") as directory:
        temporary = Path(directory)
        snapshot = temporary / "snapshot"
        run(
            [
                "git",
                "-c",
                "core.hooksPath=" + os.devnull,
                "clone",
                "--quiet",
                "--local",
                "--no-hardlinks",
                "--no-checkout",
                "--template=",
                str(root),
                str(snapshot),
            ],
            temporary,
            env=env,
        )
        run(
            [
                "git",
                "-c",
                "core.hooksPath=" + os.devnull,
                "checkout",
                "--quiet",
                "--detach",
                sha,
            ],
            snapshot,
            env=env,
        )
        # A remote baseline is fetched into the disposable repository only.
        advertised = (
            run(
                [
                    "git",
                    "ls-remote",
                    remote_url,
                    "refs/heads/" + policy["default_branch"],
                ],
                snapshot,
                env=env,
            )
            .decode()
            .split()
        )
        if advertised:
            run(
                ["git", "fetch", "--quiet", "--no-tags", remote_url, advertised[0]],
                snapshot,
                env=env,
            )
            baseline = advertised[0]
        elif policy.get("empty_remote_base"):
            if run(["git", "ls-remote", remote_url], snapshot, env=env).strip():
                raise GateError("Remote is not empty and its default branch is absent")
            baseline = policy["empty_remote_base"]
        else:
            raise GateError(
                "Remote default branch is absent; establish a reviewed baseline"
            )
        base = git(snapshot, "merge-base", baseline, sha).decode().strip()
        test_development(snapshot, base, sha, policy)
        git(snapshot, "diff", "--check", base, sha)
        scanners(snapshot, [entry[2] for entry in entries], policy, env, temporary)
        run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                policy.get("gate_tests", "tests"),
                "-p",
                "test_local_push_gate.py",
            ],
            snapshot,
            env=env,
        )
        for command in policy["checks"]:
            argv = [
                item.replace("{python}", sys.executable)
                .replace("{base}", base)
                .replace("{sha}", sha)
                for item in command
            ]
            print("push-gate check: " + " ".join(argv), flush=True)
            run(argv, snapshot, env=env, capture=False)
    print(
        json.dumps(
            {
                "commit": sha,
                "policy_sha256": hashlib.sha256(
                    json.dumps(manifest, sort_keys=True).encode()
                ).hexdigest(),
                "status": "passed",
                "seconds": round(time.monotonic() - started, 1),
            }
        ),
        flush=True,
    )


def main():
    """Install or run trusted local policy against pre-push Git input."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "uninstall", "hook", "check"))
    parser.add_argument("arguments", nargs="*")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--remote", default="origin")
    args = parser.parse_args()
    root = Path(git(Path.cwd(), "rev-parse", "--show-toplevel").decode().strip())
    if args.action == "install":
        install(root, args.replace, args.revision)
        return
    if args.action == "uninstall":
        uninstall(root)
        return
    trusted = Path(__file__).resolve().parent
    if not (trusted / "manifest.json").exists():
        raise GateError(
            "Run the installed gate from git rev-parse --git-path push-gate/gate.py"
        )
    policy = json.loads((trusted / "policy.json").read_text())
    manifest = json.loads((trusted / "manifest.json").read_text())
    if args.action == "check":
        if len(args.arguments) != 1:
            raise GateError("check requires one committed object ID")
        remote_url = (
            git(root, "remote", "get-url", "--push", args.remote).decode().strip()
        )
        sha = (
            git(root, "rev-parse", "--verify", args.arguments[0] + "^{commit}")
            .decode()
            .strip()
        )
        validate(root, sha, remote_url, policy, manifest)
    else:
        if len(args.arguments) != 2:
            raise GateError("Git pre-push requires remote name and URL")
        updates = parse_updates(sys.stdin.read(), policy["default_branch"])
        for sha in dict.fromkeys(update[1] for update in updates):
            validate(root, sha, args.arguments[1], policy, manifest)


if __name__ == "__main__":
    try:
        main()
    except (GateError, ValueError, UnicodeError, OSError) as error:
        print(f"push-gate BLOCKED: {error}", file=sys.stderr)
        sys.exit(1)
