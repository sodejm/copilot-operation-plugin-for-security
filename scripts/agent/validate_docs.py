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
COUNT_WORDS = {
    "thirteen": 13,
    "fourteen": 14,
    "eighteen": 18,
    "thirty-two": 32,
    "thirty-seven": 37,
    "sixty-three": 63,
    "sixty-nine": 69,
}
COUNT_CLAIM = re.compile(
    r"\b(?P<count>[1-9]\d*|" + "|".join(COUNT_WORDS) + r")\s+"
    r"(?:(?:distributed|available|dedicated|specialized|security|cybersecurity|"
    r"specialist|canonical|callable|AI|agent|total)\s+)*"
    r"(?P<kind>plugins?|packages?|specialists?|profiles?|scenarios?|capabilities?|agents?)\b",
    re.IGNORECASE,
)


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

    for relative in ("README.md", "docs/CAPABILITIES.md", "docs/plugin-guide.md", "docs/index.md"):
        page = ROOT / relative
        if not page.is_file():
            errors.append(f"Missing {relative}")
            continue
        page_text = page.read_text(encoding="utf-8")
        for plugin_id in sorted(plugin_ids):
            if plugin_id not in page_text:
                errors.append(f"{relative} does not document catalog plugin: {plugin_id}")


def validate_catalog_counts(errors: list[str]) -> None:
    """Compare advertised counts with the three canonical catalog registries."""
    registries = (
        ("plugin", "catalog/plugins.json", "plugins"),
        ("specialist", "agents/registry.json", "specialists"),
        ("scenario", "catalog/scenarios.json", "scenarios"),
    )
    counts: dict[str, int] = {}
    for kind, relative, key in registries:
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"Missing {relative}")
            return
        entries = json.loads(path.read_text(encoding="utf-8")).get(key)
        if not isinstance(entries, list):
            errors.append(f"{relative} must contain a {key} list")
            return
        counts[kind] = len(entries)
    counts["capability"] = sum(counts.values())

    pages = [ROOT / "README.md", *sorted(DOCS_DIR.glob("*.md"))]
    pages.extend((
        ROOT / "specs/capability-reconciliation.spec.md",
        ROOT / ".agents/skills/capability-coverage-audit/SKILL.md",
        ROOT / "cops/capabilities/auditor.py",
    ))
    for path in pages:
        if not path.is_file():
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for claim in COUNT_CLAIM.finditer(line):
                noun = claim["kind"].lower()
                if noun.startswith(("plugin", "package")):
                    kind = "plugin"
                elif noun.startswith("scenario"):
                    kind = "scenario"
                elif noun.startswith("capabilit"):
                    kind = "capability"
                else:
                    kind = "specialist"
                token = claim["count"].lower()
                advertised = int(token) if token.isdecimal() else COUNT_WORDS[token]
                if advertised != counts[kind]:
                    relative = path.relative_to(ROOT)
                    label = "capabilities" if kind == "capability" else f"{kind}s"
                    errors.append(
                        f"{relative}:{line_number}: advertises {advertised} {label}; "
                        f"canonical catalog has {counts[kind]}"
                    )


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
    validate_catalog_counts(errors)
    validate_internal_links(errors)

    if errors:
        for error in errors:
            print(f"docs-error: {error}", file=sys.stderr)
        return 1

    print(
        "Documentation structure, catalog claims, and links are valid "
        f"({len(list(DOCS_DIR.glob('*.md')))} pages verified)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
