"""Synchronize the reviewed stdlib assessment runtime into portable packages."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = (
    "governance-compliance/compliance-posture-workbench",
    "vulnerability-management/cloud-posture-workbench",
    "vulnerability-management/supply-chain-cicd-workbench",
    "identity-access/secrets-remediation-workbench",
    "vulnerability-management/network-segmentation-workbench",
    "vulnerability-management/tls-crypto-workbench",
)
MODULES = (
    "cops/adapters/registry.py",
    "cops/adapters/definitions/git.json",
    "cops/contracts/models.py",
    "cops/contracts/lifecycle.py",
    "cops/contracts/validation.py",
    "cops/evidence/canonical.py",
    "cops/evidence/validation.py",
    "cops/reporting/assessment.py",
)


def main() -> int:
    for package in PACKAGES:
        destination = ROOT / "plugins" / package / "vendor" / "runtime"
        destination.mkdir(parents=True, exist_ok=True)
        for module in MODULES:
            target = destination / module
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / module, target)
        for name in ("cops", "cops/adapters", "cops/contracts", "cops/evidence", "cops/reporting"):
            (destination / name / "__init__.py").write_text('"""Portable assessment runtime."""\n')
        shutil.copytree(
            ROOT / "cops/assessments",
            destination / "cops/assessments",
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        shutil.copytree(ROOT / "catalog/schemas", destination / "catalog/schemas", dirs_exist_ok=True)
        hashes = {str(p.relative_to(destination)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(destination.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}
        (destination.parent / "runtime-lock.json").write_text(json.dumps({"schema_version": "cops.runtime-lock/v1", "files": hashes}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
