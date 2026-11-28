from __future__ import annotations

import hashlib
import inspect
import sqlite3
import textwrap

import pytest

from cops.assessments import assess
from cops.laboratory.boundary_scanner_fixtures import query_scanner_fixture
from cops.laboratory.service_boundaries import _corrected_query, _vulnerable_query


@pytest.mark.parametrize("query", [_vulnerable_query, _corrected_query])
@pytest.mark.parametrize("value", ["quote'", "' OR 2=2 --", "'; DROP TABLE objects; --", "' UNION SELECT 'x', 'y' --"])
def test_unregistered_sql_input_is_a_literal(query, value: str) -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE objects(id TEXT, owner TEXT)")
        connection.executemany("INSERT INTO objects VALUES (?, ?)", [("owner-object", "owner"), (value, "literal")])
        assert query(connection, value) == [(value, "literal")]
        assert connection.execute("SELECT COUNT(*) FROM objects").fetchone() == (2,)


@pytest.mark.parametrize("query,expected", [(_vulnerable_query, 2), (_corrected_query, 0)])
def test_reviewed_seed_preserves_real_sqlite_outcomes(query, expected: int) -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE objects(id TEXT, owner TEXT)")
        connection.executemany(
            "INSERT INTO objects VALUES (?, ?)", [("owner-object", "owner"), ("other-object", "other")]
        )
        assert query(connection, "owner-object") == [("owner-object", "owner")]
        assert len(query(connection, "' OR 1=1 --")) == expected


@pytest.mark.parametrize("profile,expected", [("vulnerable", ["sql_interpolation"]), ("corrected", [])])
def test_static_scanner_examples_are_separate_from_executable_queries(profile: str, expected: list[str]) -> None:
    fixture = query_scanner_fixture(profile)
    report = assess("application_security", [fixture], as_of="2026-10-18T00:00:00Z")
    assert report["readiness"] == "supported"
    assert sorted(report["finding_codes"].values()) == expected
    assert report["evidence"][0]["sha256"] == fixture["sha256"]
    assert fixture["execution"] == "static-only"

    query = _vulnerable_query if profile == "vulnerable" else _corrected_query
    executable_source = textwrap.dedent(inspect.getsource(query))
    assert hashlib.sha256(executable_source.encode()).hexdigest() != fixture["sha256"]
    runtime_report = assess(
        "application_security",
        [{"artifact_id": "runtime", "kind": "python_source", "content": executable_source}],
        as_of="2026-10-18T00:00:00Z",
    )
    assert runtime_report["readiness"] == "supported"
    assert not runtime_report["finding_codes"]


@pytest.mark.parametrize(
    "artifacts,expected_codes",
    [
        ([], []),
        (
            [{"artifact_id": "missing", "kind": "python_source", "content": "def broken("}],
            ["python_source_insufficient_evidence"],
        ),
    ],
)
def test_missing_or_invalid_scanner_evidence_remains_insufficient(artifacts, expected_codes) -> None:
    report = assess("application_security", artifacts, as_of="2026-10-18T00:00:00Z")
    assert report["readiness"] == "insufficient_evidence"
    assert sorted(report["finding_codes"].values()) == expected_codes


def test_unknown_scanner_profile_fails_closed() -> None:
    with pytest.raises(ValueError, match="unsupported boundary profile"):
        query_scanner_fixture("unknown")
