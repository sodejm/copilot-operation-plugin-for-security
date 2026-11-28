"""Safe, bounded repository-context collection tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

from cops.context import collect_repository_context


def test_collect_repository_context_finds_supported_artifacts_and_excludes_sensitive_files(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "check.yml").write_text("name: check\n", encoding="utf-8")
    rendered = tmp_path / "rendered"
    rendered.mkdir()
    (rendered / "deployment.yaml").write_text(
        "# Source: chart/templates/deployment.yaml\napiVersion: apps/v1\nkind: Deployment\n",
        encoding="utf-8",
    )
    plan = {"format_version": "1.2", "planned_values": {}}
    (tmp_path / "release.tfplan.json").write_text(json.dumps(plan), encoding="utf-8")
    (tmp_path / "terraform.tfstate").write_text('{"secret":"do-not-read"}', encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=do-not-read", encoding="utf-8")
    secret_dir = tmp_path / "credentials"
    secret_dir.mkdir()
    (secret_dir / "package.json").write_text("{}", encoding="utf-8")
    history = tmp_path / ".git"
    history.mkdir()
    (history / "package.json").write_text("{}", encoding="utf-8")
    unrelated = tmp_path / "notes"
    unrelated.mkdir()
    (unrelated / "meeting.txt").write_text("private notes", encoding="utf-8")

    result = collect_repository_context(tmp_path)
    categories = {(artifact.path, artifact.category) for artifact in result.artifacts}

    assert categories == {
        (".github/workflows/check.yml", "ci_workflow"),
        ("package-lock.json", "dependency_manifest"),
        ("release.tfplan.json", "terraform_plan"),
        ("rendered/deployment.yaml", "kubernetes_rendered"),
    }
    assert result.network_collection == "separate"
    assert "do-not-read" not in json.dumps(result.to_dict())


def test_context_excludes_kubernetes_secrets_links_and_special_files(tmp_path: Path) -> None:
    rendered = tmp_path / "rendered"
    rendered.mkdir()
    (rendered / "secret.yaml").write_text("apiVersion: v1\nkind:  Secret # private\n", encoding="utf-8")
    outside = tmp_path / "outside-package.json"
    outside.write_text("{}", encoding="utf-8")
    (tmp_path / "package.json").symlink_to(outside)
    if hasattr(os, "mkfifo"):
        os.mkfifo(tmp_path / "requirements.txt")

    result = collect_repository_context(tmp_path)
    assert result.artifacts == ()


def test_context_limits_are_explicit_and_deterministic(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"requirements-{index}.txt").write_text("ignored", encoding="utf-8")
    for name in ("package.json", "pyproject.toml", "uv.lock"):
        (tmp_path / name).write_text("{}", encoding="utf-8")

    result = collect_repository_context(tmp_path, max_artifacts=2)
    assert len(result.artifacts) == 2
    assert result.truncated
    assert list(result.artifacts) == sorted(result.artifacts, key=lambda item: (item.category, item.path))
