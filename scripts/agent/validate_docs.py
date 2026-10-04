#!/usr/bin/env python3
"""Validate the COPS GitHub Pages documentation site structure and links."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
DOCS_DIR = ROOT / "docs"

REQUIRED_PAGES = (
    "index.md",
    "getting-started.md",
    "plugin-guide.md",
    "specialist-agents.md",
    "contributing.md",
    "troubleshooting.md",
    "_config.yml",
    "_layouts/documentation.html",
    "_includes/sidebar.html",
    "assets/css/documentation.css",
)

MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\((?P<target><[^>]+>|[^)\s]+)")


def validate_required_files(errors: list[str]) -> None:
    for relative in REQUIRED_PAGES:
        target = DOCS_DIR / relative
        if not target.exists():
            errors.append(f"Missing required documentation file: docs/{relative}")


def validate_plugin_coverage(errors: list[str]) -> None:
    plugins_file = ROOT / "catalog" / "plugins.json"
    if not plugins_file.is_file():
        errors.append("Missing catalog/plugins.json")
        return

    data = json.loads(plugins_file.read_text(encoding="utf-8"))
    plugin_ids = {entry["id"] for entry in data.get("plugins", [])}

    guide_file = DOCS_DIR / "plugin-guide.md"
    if not guide_file.is_file():
        errors.append("Missing docs/plugin-guide.md")
        return

    guide_text = guide_file.read_text(encoding="utf-8")
    for plugin_id in sorted(plugin_ids):
        if plugin_id not in guide_text:
            errors.append(f"docs/plugin-guide.md does not document catalog plugin: {plugin_id}")


def validate_internal_links(errors: list[str]) -> None:
    for path in DOCS_DIR.rglob("*.md"):
        relative = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8")
        in_fence = False
        for line_number, line in enumerate(text.splitlines(), start=1):
            if re.match(r"^\s*(```|~~~)", line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue

            for match in MARKDOWN_LINK.finditer(line):
                target = match.group("target").strip("<>")
                parsed = urlsplit(target)
                if parsed.scheme or parsed.netloc or target.startswith(("#", "/")) or not parsed.path:
                    continue
                # Resolve relative path
                destination = (path.parent / unquote(parsed.path)).resolve()
                if not destination.exists():
                    errors.append(f"{relative}:{line_number}: Broken relative link to: {target}")


def main() -> int:
    errors: list[str] = []
    validate_required_files(errors)
    validate_plugin_coverage(errors)
    validate_internal_links(errors)

    if errors:
        for error in errors:
            print(f"docs-error: {error}", file=sys.stderr)
        return 1

    print(f"Documentation site structure and links are valid ({len(list(DOCS_DIR.glob('*.md')))} pages verified).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
