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
    "plugin-verification.md",
    "templates/PLUGIN_VERIFICATION_RECORD.md",
    "specialist-agents.md",
    "contributing.md",
    "troubleshooting.md",
    "_config.yml",
    "_layouts/documentation.html",
    "_includes/sidebar.html",
    "assets/css/documentation.css",
)

MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\((?P<target><[^>]+>|[^)\s]+)")
VERIFICATION_SECTIONS = (
    "Scope and prerequisites",
    "Baseline checks",
    "End-to-end exercise",
    "Acceptance criteria",
    "Failure and recovery",
    "Host exercise",
    "Record and promote",
)
MATURITY_BADGE = re.compile(
    r'<span\b[^>]*class="[^"]*\bbadge-(experimental|beta|stable)\b[^"]*"[^>]*>'
    r"\s*([^<]+)\s*</span>"
)
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
    pages.extend(
        (
            ROOT / "specs/capability-reconciliation.spec.md",
            ROOT / ".agents/skills/capability-coverage-audit/SKILL.md",
            ROOT / "cops/capabilities/auditor.py",
        )
    )
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


def unfenced_lines(text: str) -> list[str]:
    """Exclude code examples from checks of rendered documentation claims."""
    lines: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if re.match(r"^\s*(```|~~~)", line):
            in_fence = not in_fence
        elif not in_fence:
            lines.append(line)
    return lines


def validate_plugin_verification(errors: list[str]) -> None:
    catalog = ROOT / "catalog/plugins.json"
    if not catalog.is_file():
        return
    index = DOCS_DIR / "plugin-verification.md"
    index_links = MARKDOWN_LINK.finditer(index.read_text(encoding="utf-8") if index.is_file() else "")
    index_targets = [match["target"].strip("<>") for match in index_links]
    for entry in json.loads(catalog.read_text(encoding="utf-8"))["plugins"]:
        plugin_id = entry["id"]
        package = ROOT / entry["path"]
        playbook = package / "docs/VERIFICATION.md"
        relative = playbook.relative_to(ROOT).as_posix()
        if not playbook.is_file():
            errors.append(f"{plugin_id}: missing end-to-end verification playbook: {relative}")
            continue
        text = playbook.read_text(encoding="utf-8")
        headings = {line.removeprefix("## ").strip() for line in unfenced_lines(text) if line.startswith("## ")}
        for section in VERIFICATION_SECTIONS:
            if section not in headings:
                errors.append(f"{plugin_id}: missing section: {section}")
        for action in ("info", "demo", "check"):
            command = f"python3 -m cops {action} {plugin_id}"
            if not re.search(rf"(?m)^\s*{re.escape(command)}\s*$", text):
                errors.append(f"{plugin_id}: missing baseline command: {command}")
        readme = package / "README.md"
        readme_text = readme.read_text(encoding="utf-8") if readme.is_file() else ""
        if not any(match["target"].strip("<>") == "docs/VERIFICATION.md" for match in MARKDOWN_LINK.finditer(readme_text)):
            errors.append(f"{plugin_id}: README.md must link to docs/VERIFICATION.md")
        if not any(
            (index.parent / unquote(urlsplit(target).path)).resolve() == playbook.resolve()
            if not urlsplit(target).scheme
            else urlsplit(target).netloc == "github.com" and urlsplit(target).path.endswith(f"/{relative}")
            for target in index_targets
        ):
            errors.append(f"{plugin_id}: verification index must link to {relative}")


def maturity_label(text: str) -> tuple[str, str] | None:
    badge = MATURITY_BADGE.search(text)
    if badge:
        return badge[1], badge[2].strip().lower()
    for cell in text.split("|"):
        label = cell.strip().strip("*`").lower()
        if label in {"experimental", "beta", "stable"}:
            return label, label
    return None


def check_maturity(errors: list[str], location: str, plugin_id: str, text: str, expected: str) -> None:
    label = maturity_label(text)
    if label is None or label[0] != expected:
        observed = label[0] if label else "missing"
        errors.append(f"{location}: {plugin_id} maturity is {observed}; manifest is {expected}")
    elif label[1] != expected:
        errors.append(f"{location}: {plugin_id} badge text is {label[1]}; manifest is {expected}")


def validate_public_maturity(errors: list[str]) -> None:
    catalog = ROOT / "catalog/plugins.json"
    if not catalog.is_file():
        return
    entries = json.loads(catalog.read_text(encoding="utf-8"))["plugins"]
    maturity: dict[str, str] = {}
    for entry in entries:
        manifest = ROOT / entry["path"] / "package.json"
        if manifest.is_file():
            maturity[entry["id"]] = json.loads(manifest.read_text(encoding="utf-8"))["maturity"]
    for relative in ("README.md", "docs/CAPABILITIES.md", "docs/plugin-guide.md"):
        path = ROOT / relative
        lines = unfenced_lines(path.read_text(encoding="utf-8")) if path.is_file() else []
        for plugin_id, expected in maturity.items():
            rows = [line for line in lines if line.startswith("|") and re.search(rf"(?<![\w-]){re.escape(plugin_id)}(?![\w-])", line)]
            if not rows:
                errors.append(f"{relative}: {plugin_id} missing maturity table row")
            for row in rows:
                check_maturity(errors, relative, plugin_id, row, expected)

    guide = DOCS_DIR / "plugin-guide.md"
    guide_text = "\n".join(unfenced_lines(guide.read_text(encoding="utf-8"))) if guide.is_file() else ""
    sections = re.split(r"(?m)^#### ", guide_text)
    for entry in entries:
        plugin_id = entry["id"]
        if plugin_id not in maturity:
            continue
        section = next((section for section in sections if f"`{entry['path']}/" in section), "")
        label = re.search(r"(?m)^- \*\*Maturity\*\*:\s*(.+)$", section)
        if label is None:
            errors.append(f"docs/plugin-guide.md: {plugin_id} missing detailed maturity")
        else:
            check_maturity(errors, "docs/plugin-guide.md detailed maturity", plugin_id, label[1], maturity[plugin_id])

    index = DOCS_DIR / "index.md"
    lines = unfenced_lines(index.read_text(encoding="utf-8")) if index.is_file() else []
    for line in lines:
        plugin_ids = re.findall(r'href="plugin-guide\.html#([\w-]+)"', line)
        badges = list(MATURITY_BADGE.finditer(line))
        # A shared category badge cannot be attributed to an individual plugin.
        if len(plugin_ids) != len(badges):
            continue
        for plugin_id, badge in zip(plugin_ids, badges, strict=True):
            if plugin_id in maturity:
                check_maturity(errors, "docs/index.md", plugin_id, badge[0], maturity[plugin_id])


def validate_internal_links(errors: list[str]) -> None:
    pages = [*DOCS_DIR.rglob("*.md"), *ROOT.glob("plugins/*/*/docs/VERIFICATION.md")]
    for path in pages:
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
    validate_plugin_verification(errors)
    validate_public_maturity(errors)
    validate_internal_links(errors)

    if errors:
        for error in errors:
            print(f"docs-error: {error}", file=sys.stderr)
        return 1

    print(
        "Documentation structure, catalog claims, verification playbooks, maturity, and links are valid "
        f"({len(list(DOCS_DIR.glob('*.md')))} pages verified)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
