"""Diagnostic runner coordinating system, tools, packages, and capability audits."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cops.capabilities.auditor import audit_capabilities
from cops.evidence.canonical import utc_now

from .models import DiagnosticReport, PackageDiagnostic
from .packages import diagnose_packages, diagnose_plugin_package
from .system import detect_system_platform, diagnose_host_tools


def run_diagnostics(
    root: Path,
    *,
    package_id: str | None = None,
    tools_only: bool = False,
    strict: bool = False,
) -> DiagnosticReport:
    """Run comprehensive or scoped diagnostics for COPS."""
    now_iso = utc_now()
    plugins_dir = root / "plugins"

    # 1. System diagnostics
    system_diag = detect_system_platform()

    # 2. Tool diagnostics
    tools_diag = diagnose_host_tools()

    # 3. Package diagnostics
    package_diags: list[PackageDiagnostic] = []
    if not tools_only:
        if package_id:
            # Find specific package
            matched = False
            for cat_dir in sorted(plugins_dir.iterdir()):
                if cat_dir.is_dir() and (cat_dir / package_id).is_dir():
                    package_diags.append(diagnose_plugin_package(cat_dir / package_id))
                    matched = True
                    break
            if not matched:
                from .models import DiagnosticCheck
                package_diags.append(PackageDiagnostic(
                    package_id=package_id,
                    category="unknown",
                    status="unready",
                    manifest_valid=False,
                    skills_count=0,
                    has_playbook=False,
                    has_validation_script=False,
                    checks=[DiagnosticCheck("not_found", "failed", f"Package '{package_id}' not found in plugins/")],
                ))
        else:
            package_diags = diagnose_packages(plugins_dir)

    # 4. Capability truth audit
    try:
        cap_results = audit_capabilities(root=root)
        capability_truth_passed = True
        capability_count = cap_results.get("total_capabilities", 0)
    except Exception:
        capability_truth_passed = False
        capability_count = 0

    # 5. Evaluate all_ready
    all_packages_ready = all(p.status in ("ready", "degraded") for p in package_diags) if package_diags else True
    all_tools_ready = all(t.status == "available" for t in tools_diag)

    if strict:
        all_ready = (
            system_diag.is_supported
            and all_tools_ready
            and all(p.status == "ready" for p in package_diags)
            and capability_truth_passed
        )
    else:
        all_ready = (
            system_diag.is_supported
            and all_packages_ready
            and capability_truth_passed
        )

    summary: dict[str, Any] = {
        "strict_mode": strict,
        "packages_count": len(package_diags),
        "packages_ready": sum(1 for p in package_diags if p.status == "ready"),
        "packages_degraded": sum(1 for p in package_diags if p.status == "degraded"),
        "packages_unready": sum(1 for p in package_diags if p.status == "unready"),
        "tools_available": sum(1 for t in tools_diag if t.status == "available"),
        "tools_missing": sum(1 for t in tools_diag if t.status == "missing"),
        "tools_version_mismatch": sum(1 for t in tools_diag if t.status == "version_mismatch"),
    }

    return DiagnosticReport(
        timestamp=now_iso,
        system=system_diag,
        tools=tools_diag,
        packages=package_diags,
        capability_truth_passed=capability_truth_passed,
        capability_count=capability_count,
        all_ready=all_ready,
        summary=summary,
    )
