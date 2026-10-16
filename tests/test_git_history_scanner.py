from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from cops.assessments import assess
from cops.assessments.git_history import GitHistoryScanError, ScanLimits, scan_git_history


SYNTHETIC_SECRET = "COPS_TEST_TOKEN_0123456789abcdef"
AS_OF = "2026-10-15T12:00:00Z"
GIT = shutil.which("git")
GIT_SHA256 = hashlib.sha256(Path(GIT).resolve().read_bytes()).hexdigest() if GIT else None


pytestmark = pytest.mark.skipif(GIT is None, reason="git is required for history scanner tests")


def _git(repository: Path, *arguments: str) -> str:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "COPS Synthetic Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "COPS Synthetic Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2026-10-15T12:00:00+00:00",
        "GIT_COMMITTER_DATE": "2026-10-15T12:00:00+00:00",
        "LC_ALL": "C",
    }
    completed = subprocess.run(
        [GIT, *arguments],
        cwd=repository,
        env=environment,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet", "--template=")
    return repository


def _commit(repository: Path, path: str, content: str, message: str) -> str:
    target = repository / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    _git(repository, "add", "--", path)
    _git(repository, "commit", "--quiet", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _assert_secret_absent(value: Any) -> None:
    serialized = json.dumps(value, sort_keys=True)
    assert SYNTHETIC_SECRET not in serialized
    assert "0123456789abcdef" not in serialized


def _snapshot(repository: Path) -> dict[str, tuple[int, str]]:
    return {
        item.relative_to(repository).as_posix(): (
            item.stat().st_mode, hashlib.sha256(item.read_bytes()).hexdigest(),
        )
        for item in repository.rglob("*") if item.is_file()
    }


@pytest.mark.parametrize("pin", [None, "", "not-a-digest", "A" * 64])
def test_unpinned_executable_is_rejected(tmp_path: Path, pin: str | None) -> None:
    repository = _repository(tmp_path)
    with pytest.raises(GitHistoryScanError, match="git_sha256_pin_required"):
        scan_git_history(repository, expected_git_sha256=pin)


def test_changed_executable_is_rejected_before_scanning(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    with pytest.raises(GitHistoryScanError, match="git_sha256_mismatch"):
        scan_git_history(repository, expected_git_sha256="0" * 64)


def test_scan_preserves_repository_metadata_and_worktree(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _commit(repository, "fixture.txt", SYNTHETIC_SECRET + "\n", "fixture")
    (repository / "untracked.txt").write_text("operator working copy\n")
    before = _snapshot(repository)
    scan_git_history(repository, expected_git_sha256=GIT_SHA256)
    assert _snapshot(repository) == before


def test_clean_nonempty_history_has_bounded_clearance(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _commit(repository, "fixture.txt", "no synthetic credentials\n", "fixture")
    artifact = scan_git_history(repository, expected_git_sha256=GIT_SHA256)
    assert artifact["content"]["assessment_status"] == "no_synthetic_match_observed"
    assessment = assess("credential_history", [artifact], as_of=AS_OF)
    assert not assessment["finding_codes"]


def test_vulnerable_history_emits_only_redacted_provenance_and_assesses_exposure(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    commit = _commit(repository, "config/settings.txt", f"token={SYNTHETIC_SECRET}\n", "fixture")

    artifact = scan_git_history(repository, expected_git_sha256=GIT_SHA256)

    assert artifact["schema_version"] == "cops.git-history-scan/v1"
    assert artifact["kind"] == "git_history"
    assert artifact["content"]["assessment_status"] == "exposure_observed"
    assert artifact["content"]["containment_status"] == "unknown"
    occurrence = artifact["content"]["occurrences"][0]
    assert set(occurrence) == {"fingerprint", "path", "commit", "source", "exposed", "redacted"}
    assert occurrence["path"] == "config/settings.txt"
    assert occurrence["commit"] == commit
    assert occurrence["redacted"] is True
    assert len(occurrence["fingerprint"]) == 64
    _assert_secret_absent(artifact)

    assessment = assess("credential_history", [artifact], as_of=AS_OF)
    assert "credential_not_contained" in assessment["finding_codes"].values()
    assert "exposure_identity_correlation_insufficient_evidence" in assessment[
        "finding_codes"
    ].values()
    _assert_secret_absent(assessment)


def test_corrected_head_still_reports_reachable_historical_exposure(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    exposed_commit = _commit(repository, "settings.txt", f"token={SYNTHETIC_SECRET}\n", "add fixture")
    corrected_commit = _commit(repository, "settings.txt", "token sourced from environment\n", "correct fixture")

    artifact = scan_git_history(repository, expected_git_sha256=GIT_SHA256)

    occurrences = artifact["content"]["occurrences"]
    assert {item["commit"] for item in occurrences} == {exposed_commit}
    assert artifact["content"]["source"]["head_commit"] == corrected_commit
    assert artifact["content"]["containment_status"] == "unknown"
    assert "registered-adapter:provider-revocation-check@1" in artifact["content"][
        "adapter_prerequisites"
    ]["required"]
    _assert_secret_absent(artifact)


def test_empty_repository_is_insufficient_evidence(tmp_path: Path) -> None:
    artifact = scan_git_history(_repository(tmp_path), expected_git_sha256=GIT_SHA256)

    assert artifact["content"]["assessment_status"] == "insufficient_evidence"
    assert artifact["content"]["coverage"]["commits_examined"] == 0
    assert artifact["content"]["coverage"]["complete_within_configured_bounds"] is False
    assert artifact["content"]["occurrences"] == []
    assert any("No reachable commits" in item for item in artifact["content"]["limitations"])
    assessment = assess("credential_history", [artifact], as_of=AS_OF)
    assert "credential_history_coverage_insufficient_evidence" in assessment["finding_codes"].values()


def test_commit_and_blob_bounds_are_reported_without_false_clearance(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _commit(repository, "old.txt", f"token={SYNTHETIC_SECRET}\n", "old")
    _commit(repository, "old.txt", "credential removed\n", "current")

    commit_limited = scan_git_history(repository, expected_git_sha256=GIT_SHA256, limits=ScanLimits(max_commits=1))
    assert commit_limited["content"]["assessment_status"] == "insufficient_evidence"
    assert commit_limited["content"]["coverage"]["commits_examined"] == 1
    assert commit_limited["content"]["occurrences"] == []
    assert any("commits" in item for item in commit_limited["content"]["limitations"])
    assessment = assess("credential_history", [commit_limited], as_of=AS_OF)
    assert "credential_history_coverage_insufficient_evidence" in assessment["finding_codes"].values()

    blob_limited = scan_git_history(repository, expected_git_sha256=GIT_SHA256, limits=ScanLimits(max_blob_bytes=8))
    assert blob_limited["content"]["assessment_status"] == "insufficient_evidence"
    assert blob_limited["content"]["occurrences"] == []
    assert any("blob_bytes" in item for item in blob_limited["content"]["limitations"])
    _assert_secret_absent(blob_limited)


def test_secret_bearing_path_is_fingerprinted_instead_of_emitted(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    secret_path = f"fixtures/{SYNTHETIC_SECRET}.txt"
    _commit(repository, secret_path, SYNTHETIC_SECRET + "\n", "fixture")

    artifact = scan_git_history(repository, expected_git_sha256=GIT_SHA256)

    occurrence = artifact["content"]["occurrences"][0]
    assert occurrence["path"].startswith("redacted-path/sha256-")
    assert "redacted_paths" in " ".join(artifact["content"]["limitations"])
    _assert_secret_absent(artifact)


def test_control_character_path_is_skipped_without_false_clearance(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _commit(repository, "unsafe\nname.txt", SYNTHETIC_SECRET + "\n", "fixture")

    artifact = scan_git_history(repository, expected_git_sha256=GIT_SHA256)

    assert artifact["content"]["occurrences"] == []
    assert artifact["content"]["assessment_status"] == "insufficient_evidence"
    assert "unsafe_paths" in " ".join(artifact["content"]["limitations"])
    _assert_secret_absent(artifact)


@pytest.mark.skipif(os.name == "nt", reason="symlink fixture requires POSIX Git semantics")
def test_git_symlink_entry_is_not_followed_and_makes_coverage_insufficient(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text(SYNTHETIC_SECRET + "\n", encoding="utf-8")
    link = repository / "linked.txt"
    link.symlink_to(outside)
    _git(repository, "add", "--", "linked.txt")
    _git(repository, "commit", "--quiet", "-m", "symlink fixture")

    artifact = scan_git_history(repository, expected_git_sha256=GIT_SHA256)

    assert artifact["content"]["occurrences"] == []
    assert artifact["content"]["assessment_status"] == "insufficient_evidence"
    assert "symlink_entries" in " ".join(artifact["content"]["limitations"])
    _assert_secret_absent(artifact)


@pytest.mark.skipif(os.name == "nt", reason="symlink fixture requires POSIX semantics")
def test_symlinked_root_and_git_metadata_are_rejected(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    root_link = tmp_path / "repository-link"
    root_link.symlink_to(repository, target_is_directory=True)

    with pytest.raises(GitHistoryScanError, match="root_symlink_or_not_directory"):
        scan_git_history(root_link)

    head = repository / ".git" / "HEAD"
    head_value = head.read_text(encoding="utf-8")
    target = repository / ".git" / "HEAD.target"
    target.write_text(head_value, encoding="utf-8")
    head.unlink()
    head.symlink_to(target.name)
    with pytest.raises(GitHistoryScanError, match="git_metadata_symlink"):
        scan_git_history(repository, expected_git_sha256=GIT_SHA256)


@pytest.mark.skipif(os.name == "nt", reason="symlink fixture requires POSIX semantics")
def test_nested_git_metadata_symlink_is_rejected_before_git_reads_it(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    commit = _commit(repository, "fixture.txt", "safe fixture\n", "fixture")
    ref_name = _git(repository, "symbolic-ref", "HEAD")
    ref = repository / ".git" / ref_name
    outside_ref = tmp_path / "outside-ref"
    outside_ref.write_text(commit + "\n", encoding="ascii")
    ref.unlink()
    ref.symlink_to(outside_ref)

    with pytest.raises(GitHistoryScanError, match="git_metadata_symlink"):
        scan_git_history(repository, expected_git_sha256=GIT_SHA256)


def test_package_entrypoint_scans_explicit_root_without_secret_output(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _commit(repository, "fixture.txt", SYNTHETIC_SECRET + "\n", "fixture")
    script = (
        Path(__file__).parents[1]
        / "plugins/identity-access/secrets-remediation-workbench/scripts/scan_git_history.py"
    )

    completed = subprocess.run(
        [sys.executable, str(script), "--root", str(repository), "--git-sha256", GIT_SHA256],
        cwd=Path(__file__).parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr
    artifact = json.loads(completed.stdout)
    assert artifact["content"]["assessment_status"] == "exposure_observed"
    assert completed.stderr == ""
    assert SYNTHETIC_SECRET not in completed.stdout
    assert SYNTHETIC_SECRET not in completed.stderr
