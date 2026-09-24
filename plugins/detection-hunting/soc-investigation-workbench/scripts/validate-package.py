#!/usr/bin/env python3
"""Repository packaging checks; default gate requires a real vendor snapshot."""

import argparse
import json
from pathlib import Path
import re
import sys

PACKAGE = Path(__file__).resolve().parents[1]


def find_repository_root(package):
    """Find the nearest ancestor carrying the repository acceptance contract."""
    for candidate in package.parents:
        if (candidate / "LICENSE").is_file() and (candidate / "specs/features/soc_investigation.feature").is_file():
            return candidate
    return package.parents[2]


ROOT = find_repository_root(PACKAGE)
sys.path.insert(0, str(PACKAGE))

from investigationwb.cli import read_json
from investigationwb.engine import ContractError, require, validate
from investigationwb.vendor import verify


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def check(allow_pending_vendor=False):
    copilot = read_json(PACKAGE / "plugin.json")
    codex = read_json(PACKAGE / ".codex-plugin/plugin.json")
    claude = read_json(PACKAGE / ".claude-plugin/plugin.json")
    require(copilot["name"] == "soc-investigation-workbench"
            and copilot["$schema"].startswith("https://"), "Unexpected Copilot plugin identity or schema.")
    require(bool(copilot["version"]) and bool(copilot["description"])
            and copilot["author"]["name"] == "Justin Soderberg", "Copilot plugin metadata is incomplete.")
    identity = (copilot["name"], copilot["version"])
    require((codex["name"], codex["version"]) == identity
            and (claude["name"], claude["version"]) == identity,
            "Copilot, Codex, and Claude plugin identities must match.")
    require(codex["skills"] in {"./skills", "./skills/"},
            "Codex manifest must reference the package skills directory.")
    interface = codex["interface"]
    required_interface = {"displayName", "shortDescription", "longDescription",
                          "developerName", "category", "capabilities", "defaultPrompt"}
    require(required_interface <= set(interface)
            and isinstance(interface["capabilities"], list) and bool(interface["capabilities"])
            and isinstance(interface["defaultPrompt"], list) and bool(interface["defaultPrompt"]),
            "Codex manifest interface metadata is incomplete.")
    skills = sorted((PACKAGE / "skills").glob("*/SKILL.md"))
    expected = {"soc-investigation-planning", "soc-investigation-review"}
    names = set()
    for skill in skills:
        content = skill.read_text(encoding="utf-8")
        match = re.match(r"\A---\nname: ([a-z0-9-]+)\ndescription: ([^\n]+)\n---\n", content)
        require(match is not None and len(content.splitlines()) <= 500,
                "Owned skill frontmatter or length is invalid.")
        name, description = match.groups()
        require(name == skill.parent.name and name not in names and len(description) <= 1024,
                "Owned skill identity or description is invalid.")
        names.add(name)
    require(names == expected, "Owned skills differ from the documented ownership boundary.")
    for other in ROOT.glob("plugins/*/*/skills/*/SKILL.md"):
        if other not in skills:
            content = other.read_text(encoding="utf-8")
            match = re.search(r"^name: (.+)$", content, re.M)
            require(not match or match[1] not in names, "Owned skill name collides with another package.")
    for path in [PACKAGE / "README.md", *sorted((PACKAGE / "docs").glob("*.md")), *skills]:
        for link in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if not re.match(r"[a-z]+://|#", link):
                require((path.parent / link.split("#")[0]).is_file(), "Local documentation link is broken.")
    require((PACKAGE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes(),
            "Package license differs from the repository license.")
    spec = (ROOT / "specs/soc-investigation-workbench.spec.md").read_text(encoding="utf-8")
    feature = (ROOT / "specs/features/soc_investigation.feature").read_text(encoding="utf-8")
    criteria = re.findall(r"^- \[[ x]\] (AC\d+):", spec, re.M)
    scenarios = re.findall(r"^  Scenario: (AC\d+) ", feature, re.M)
    require(len(criteria) == 10 and len(set(criteria)) == 10 and sorted(criteria) == sorted(scenarios),
            "Acceptance criteria and executable scenarios do not match.")
    validate(read_json(PACKAGE / "examples/case.json"))
    if (allow_pending_vendor and all(absent(path)
                                    for path in (PACKAGE / "vendor-lock.json", PACKAGE / "vendor"))):
        return {"status": "development_only", "release_ready": False, "owned_skills": sorted(names),
                "acceptance_scenarios": len(scenarios), "vendor": "pending_canonical_source"}
    dependency = verify(PACKAGE)
    return {"status": "package_checks_passed", "dependency_ready": True, "owned_skills": sorted(names),
            "acceptance_scenarios": len(scenarios), "vendor": dependency,
            "remaining_checks": "Run behavior tests and upstream qualification; package integrity is not hunt assurance."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-pending-vendor", action="store_true", help="Development only; never release ready.")
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.allow_pending_vendor), indent=2))
        return 0
    except ContractError as exc:
        print(json.dumps({"status": "blocked", "message": str(exc), "release_ready": False}), file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(json.dumps({"status": "blocked", "message": "Package or repository contract is malformed or unavailable.",
                          "release_ready": False}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
