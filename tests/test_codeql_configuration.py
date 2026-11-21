"""Keep production CodeQL coverage and its offline regression suite connected."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "codeql/python/tests"


def _block(document: str, key: str, indent: int) -> str:
    """Read one block in these indentation-based YAML files without a YAML dependency."""
    lines = document.splitlines()
    starts = [index for index, line in enumerate(lines) if re.fullmatch(rf" {{{indent}}}{re.escape(key)}:.*", line)]
    assert len(starts) == 1, f"Expected one {key!r} entry at indentation {indent}"
    start = starts[0] + 1
    end = next(
        (
            index
            for index in range(start, len(lines))
            if lines[index].strip()
            and not lines[index].lstrip().startswith("#")
            and len(lines[index]) - len(lines[index].lstrip()) <= indent
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def _scalar(document: str, key: str, indent: int) -> str:
    matches = re.findall(rf"(?m)^ {{{indent}}}{re.escape(key)}: ([^\n]+)$", document)
    assert len(matches) == 1, f"Expected one scalar {key!r}"
    return matches[0].strip().strip("\"'")


def _steps(job: str) -> list[str]:
    return re.split(r"(?m)^      - ", _block(job, "steps", 4))[1:]


@pytest.mark.parametrize("job_id,language", [("analyze", "python"), ("actions", "actions")])
def test_extended_analysis_covers_python_and_actions(job_id: str, language: str) -> None:
    workflow = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
    job = _block(_block(workflow, "jobs", 0), job_id, 2)
    steps = _steps(job)
    initializers = [step for step in steps if "uses: github/codeql-action/init@" in step]
    analyzers = [step for step in steps if "uses: github/codeql-action/analyze@" in step]
    assert len(initializers) == len(analyzers) == 1
    options = _block(initializers[0], "with", 8)
    assert _scalar(options, "languages", 10) == language
    config = ROOT / _scalar(options, "config-file", 10)
    assert config.is_file()
    queries = _block(config.read_text(encoding="utf-8"), "queries", 0)
    assert "security-extended" in re.findall(r"(?m)^  - uses: (.+)$", queries)
    assert _scalar(_block(analyzers[0], "with", 8), "category", 10) == f"/language:{language}"


def test_python_analysis_includes_guard_and_excludes_only_inert_fixtures() -> None:
    config = (ROOT / ".github/codeql/python.yml").read_text(encoding="utf-8")
    uses = re.findall(r"(?m)^  - uses: (.+)$", _block(config, "queries", 0))
    query_directories = [ROOT / path for path in uses if path.startswith("./")]
    assert query_directories == [ROOT / "codeql/python/queries"]
    assert list(query_directories[0].glob("*.ql"))
    excluded = re.findall(r"(?m)^  - (.+)$", _block(config, "paths-ignore", 0))
    assert excluded == [str(FIXTURES.relative_to(ROOT))]
    assert not re.search(r"(?m)^paths:", config), "Production analysis must retain the full source tree"
    assert (ROOT / "cops/execution/evidence.py").is_file()
    for case in ("bad", "good"):
        fixture = FIXTURES / case
        assert (fixture / "test.py").is_file()
        references = list(fixture.glob("*.qlref"))
        assert references, f"No query reference for {case} fixtures"
        for reference in references:
            query = (fixture / reference.read_text(encoding="utf-8").strip()).resolve()
            assert query.is_file() and query.parent == query_directories[0]
            assert reference.with_suffix(".expected").is_file()


def test_ci_runs_fixture_regressions_with_initialized_cli_before_analysis() -> None:
    workflow = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
    steps = _steps(_block(_block(workflow, "jobs", 0), "analyze", 2))
    init = next(index for index, step in enumerate(steps) if "uses: github/codeql-action/init@" in step)
    analyze = next(index for index, step in enumerate(steps) if "uses: github/codeql-action/analyze@" in step)
    regressions = [(index, step) for index, step in enumerate(steps) if '"$CODEQL" test run' in step]
    assert len(regressions) == 1
    index, regression = regressions[0]
    assert init < index < analyze
    init_id = _scalar(steps[init], "id", 8)
    assert _scalar(_block(regression, "env", 8), "CODEQL", 10) == f"${{{{ steps.{init_id}.outputs.codeql-path }}}}"
    commands = [shlex.split(line) for line in _block(regression, "run", 8).splitlines() if line.strip()]
    assert commands == [
        ["$CODEQL", "pack", "install", "codeql/python"],
        ["$CODEQL", "test", "run", str(FIXTURES.relative_to(ROOT))],
    ]
    pack = ROOT / commands[0][-1]
    assert (pack / "qlpack.yml").is_file()
    assert FIXTURES.is_relative_to(pack)
