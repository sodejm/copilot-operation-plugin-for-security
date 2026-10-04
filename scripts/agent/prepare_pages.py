#!/usr/bin/env python3
"""Post-process Jekyll generated site to ensure all index and .md redirects exist."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MD_REDIRECT_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url={target_url}">
  <link rel="canonical" href="{target_url}">
  <script>window.location.replace("{target_url}");</script>
</head>
<body>
  <p>Redirecting to <a href="{target_url}">{target_url}</a>...</p>
</body>
</html>
"""


def process_site(site_dir: Path) -> int:
    if not site_dir.is_dir():
        print(f"Error: site directory does not exist: {site_dir}", file=sys.stderr)
        return 1

    html_files = list(site_dir.rglob("*.html"))
    created_indexes = 0
    created_redirects = 0

    # 1. Rewrite any remaining .md links in generated HTML files to .html
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

    # 2. For every HTML file (e.g., getting-started.html), create:
    #    a) getting-started.md redirect file
    #    b) getting-started/index.html directory index
    for html_path in list(site_dir.rglob("*.html")):
        if html_path.name in ("index.html", "404.html"):
            continue

        stem = html_path.stem

        # a) Create .md redirect file matching the html file
        md_file = html_path.with_suffix(".md")
        if not md_file.exists():
            target_url = html_path.name
            try:
                md_file.write_text(
                    MD_REDIRECT_TEMPLATE.format(target_url=target_url),
                    encoding="utf-8",
                )
                created_redirects += 1
            except Exception as err:
                print(f"Warning: could not create {md_file}: {err}", file=sys.stderr)

        # b) Create directory index (e.g., getting-started/index.html)
        dir_index = html_path.parent / stem / "index.html"
        if not dir_index.exists():
            try:
                dir_index.parent.mkdir(parents=True, exist_ok=True)
                dir_index.write_text(
                    MD_REDIRECT_TEMPLATE.format(target_url=f"../{html_path.name}"),
                    encoding="utf-8",
                )
                created_indexes += 1
            except Exception as err:
                print(f"Warning: could not create {dir_index}: {err}", file=sys.stderr)

    print(
        f"Pages post-processing complete: created {created_redirects} .md redirect(s) and {created_indexes} directory index(es)."
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
