"""Acceptance checks for project instruction budgets through the contract CLI."""

from pathlib import Path
import shutil
import subprocess
import sys


SOURCE = Path(__file__).resolve().parents[1]


def fixture(tmp_path):
    scripts = tmp_path / "scripts/agent"
    scripts.mkdir(parents=True)
    for name in ("validate_contract.py", "repository_files.py"):
        shutil.copyfile(SOURCE / "scripts/agent" / name, scripts / name)
    for name in ("AGENTS.md", "CLAUDE.md", ".github/copilot-instructions.md",
                 "docs/COMPATIBILITY.md", "docs/SECURITY_MODEL.md"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    (tmp_path / ".agents/skills").mkdir(parents=True)
    return tmp_path


def run_contract(root):
    return subprocess.run(
        [sys.executable, str(root / "scripts/agent/validate_contract.py")],
        capture_output=True, text=True, check=False,
    )


def test_exact_budget_passes(tmp_path):
    root = fixture(tmp_path)
    (root / "AGENTS.md").write_bytes(b"x" * 8192)
    # Ordinary linked documentation is outside automatic project instruction loading.
    (root / "docs/AGENT_CONTRACT.md").write_bytes(b"x" * 20000)
    result = run_contract(root)
    assert result.returncode == 0, result.stderr


def test_one_byte_over_budget_fails(tmp_path):
    root = fixture(tmp_path)
    (root / "AGENTS.md").write_bytes(b"x" * 8193)
    result = run_contract(root)
    assert result.returncode == 1
    assert "8193 bytes exceeds 8192-byte project instruction budget" in result.stderr
    assert "AGENTS.md" in result.stderr


def test_nested_chain_counts_bytes_and_keeps_siblings_separate(tmp_path):
    root = fixture(tmp_path)
    (root / "AGENTS.md").write_text("é" * 2048, encoding="utf-8")
    for name in ("first", "second"):
        (root / name).mkdir()
        (root / name / "AGENTS.md").write_bytes(b"x" * 4096)
    assert run_contract(root).returncode == 0
    (root / "first/AGENTS.md").write_bytes(b"x" * 4097)
    result = run_contract(root)
    assert result.returncode == 1
    assert "first/AGENTS.md" in result.stderr
    assert "8193 bytes" in result.stderr
    assert "second/AGENTS.md" not in result.stderr


def test_override_takes_precedence_per_directory(tmp_path):
    root = fixture(tmp_path)
    (root / "AGENTS.md").write_bytes(b"x" * 20000)
    (root / "AGENTS.override.md").write_bytes(b"x" * 8192)
    assert run_contract(root).returncode == 0
    # Empty override files are skipped during instruction discovery.
    (root / "AGENTS.override.md").write_bytes(b"")
    assert run_contract(root).returncode == 1


def test_repaired_squad_skills_pass_contract_validation(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "repository_contract", SOURCE / "scripts/agent/validate_contract.py")
    sys.path.insert(0, str(SOURCE / "scripts/agent"))
    try:
        contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(contract)
    finally:
        sys.path.pop(0)
    paths = [SOURCE / root / name / "SKILL.md"
             for root in (".claude/skills", ".squad/templates/skills")
             for name in ("humanizer", "e2e-template-testing")]
    assert all(path.is_file() for path in paths)
    monkeypatch.setattr(contract, "repository_files", lambda root: paths)
    errors = []
    contract.validate_portability(errors)
    contract.validate_markdown_links(errors)
    assert errors == []
