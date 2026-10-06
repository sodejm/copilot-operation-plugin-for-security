"""Tests for Jekyll site post-processing script (prepare_pages.py)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "agent" / "prepare_pages.py"

spec = importlib.util.spec_from_file_location("prepare_pages", SCRIPT_PATH)
prepare_pages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare_pages)


def test_prepare_pages_purges_md_and_creates_clean_indexes(tmp_path: Path):
    """Verify prepare_pages purges .md files, rewrites links, and copies directory indexes."""
    # Setup simulated Jekyll output
    home_html = tmp_path / "index.html"
    home_html.write_text(
        '<html><body><a href="getting-started.md">Getting Started</a>'
        '<a href="sub/deep.md#section">Deep Link</a>'
        '<a href="https://example.com/external.md">External</a></body></html>',
        encoding="utf-8",
    )

    getting_started_html = tmp_path / "getting-started.html"
    getting_started_html.write_text(
        '<html><head><title>Getting Started</title></head><body><h1>Content</h1></body></html>',
        encoding="utf-8",
    )

    stray_md = tmp_path / "getting-started.md"
    stray_md.write_text("Stray markdown that should be purged", encoding="utf-8")

    not_found_html = tmp_path / "404.html"
    not_found_html.write_text('<html><body>404</body></html>', encoding="utf-8")

    assert stray_md.exists()

    result = prepare_pages.process_site(tmp_path)
    assert result == 0

    # 1. Verify stray .md file was purged
    assert not stray_md.exists()
    assert list(tmp_path.rglob("*.md")) == []

    # 2. Verify links in index.html were rewritten to .html (and external links untouched)
    updated_home = home_html.read_text(encoding="utf-8")
    assert 'href="getting-started.html"' in updated_home
    assert 'href="sub/deep.html#section"' in updated_home
    assert 'href="https://example.com/external.md"' in updated_home

    # 3. Verify directory index was created with matching content
    dir_index = tmp_path / "getting-started" / "index.html"
    assert dir_index.is_file()
    assert dir_index.read_text(encoding="utf-8") == getting_started_html.read_text(encoding="utf-8")

    # 4. Verify 404.html did not create 404/index.html
    assert not (tmp_path / "404" / "index.html").exists()
