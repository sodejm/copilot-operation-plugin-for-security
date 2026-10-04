#!/usr/bin/env python3
"""Post-process Jekyll generated site to ensure clean index structure and link integrity.

Rules:
1. Purge any raw .md files in the build output directory (_site/).
   GitHub Pages serves *.md files as 'Content-Type: text/markdown'. If a redirect
   or HTML page is saved with a .md extension, browsers will display raw HTML tags
   as plain text rather than parsing and executing them. By removing *.md files,
   any request ending in .md triggers GitHub Pages' 404 handler (404.html), which
   is served as 'Content-Type: text/html' and executes an instant client-side redirect.
2. Rewrite any remaining relative .md links in generated HTML files to .html.
3. For every HTML page (e.g. getting-started.html), create a clean directory index
   (e.g. getting-started/index.html) so requests with or without trailing slashes
   resolve cleanly.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def process_site(site_dir: Path) -> int:
    if not site_dir.is_dir():
        print(f"Error: site directory does not exist: {site_dir}", file=sys.stderr)
        return 1

    # 1. Purge any raw .md files so GitHub Pages will not serve them as text/markdown.
    removed_md = 0
    for md_path in list(site_dir.rglob("*.md")):
        try:
            md_path.unlink()
            removed_md += 1
        except Exception as err:
            print(f"Warning: could not delete {md_path}: {err}", file=sys.stderr)

    html_files = list(site_dir.rglob("*.html"))
    created_indexes = 0

    # 2. Rewrite any remaining .md links in generated HTML files to .html
    for html_path in html_files:
        try:
            content = html_path.read_text(encoding="utf-8")
            rewritten = re.sub(
                r'href="([^":#?]+\.md)(#[^"]*)?"',
                lambda m: f'href="{m.group(1)[:-3]}.html{m.group(2) or ""}"',
                content,
            )
            if rewritten != content:
                html_path.write_text(rewritten, encoding="utf-8")
        except Exception as err:
            print(f"Warning: could not rewrite links in {html_path}: {err}", file=sys.stderr)

    # 3. For every HTML file (e.g., getting-started.html), ensure directory index exists
    for html_path in list(site_dir.rglob("*.html")):
        if html_path.name in ("index.html", "404.html"):
            continue

        stem = html_path.stem
        dir_index = html_path.parent / stem / "index.html"
        if not dir_index.exists():
            try:
                dir_index.parent.mkdir(parents=True, exist_ok=True)
                # Copy the full HTML content so direct directory hits render without redirect hops
                dir_index.write_text(
                    html_path.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                created_indexes += 1
            except Exception as err:
                print(f"Warning: could not create {dir_index}: {err}", file=sys.stderr)

    print(
        f"Pages post-processing complete: removed {removed_md} .md file(s), created {created_indexes} directory index(es)."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--site",
        type=Path,
        default=Path("_site"),
        help="Path to generated site directory",
    )
    args = parser.parse_args()
    return process_site(args.site)


if __name__ == "__main__":
    raise SystemExit(main())
