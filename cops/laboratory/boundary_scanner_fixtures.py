"""Static scanner examples, never imported or executed as query implementations."""

from __future__ import annotations

import hashlib


def query_scanner_fixture(profile: str) -> dict[str, str]:
    """Return explicit vulnerable/corrected source text for AST assessment only."""
    if profile == "vulnerable":
        source = """def query(connection, value):
    return connection.execute(f"SELECT id, owner FROM objects WHERE id = '{value}'").fetchall()
"""
    elif profile == "corrected":
        source = """def query(connection, value):
    return connection.execute("SELECT id, owner FROM objects WHERE id = ?", (value,)).fetchall()
"""
    else:
        raise ValueError("unsupported boundary profile")
    return {
        "artifact_id": "lab-query-" + profile,
        "kind": "python_source",
        "content": source,
        "sha256": hashlib.sha256(source.encode()).hexdigest(),
        "execution": "static-only",
    }
