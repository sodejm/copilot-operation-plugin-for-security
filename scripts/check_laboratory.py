#!/usr/bin/env python3
"""Fail-closed acceptance gate for the disposable COPS service laboratories."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cops.laboratory.service_lab import ServiceLaboratory, probe_isolated_runtime
from cops.evidence.canonical import digest
from cops.laboratory.container_runtime import run_container_acceptance
from cops.laboratory.acceptance_cases import ACCEPTANCE_CASE_IDS, INTEGRATED_WORKFLOW_IDS
from cops.laboratory.integrated_lab import WORKFLOW_STAGES, run_integrated_service_laboratory
from cops.laboratory.workflow_lab import (
    IsolationRequiredError,
    run_workflow_service_laboratory,
)
from cops.adapters.evtx import EvtxImportError, import_evtx

SCHEMA_VERSION = "cops.laboratory-acceptance-gate/v1"


def _expect(failures: list[str], condition: bool, detail: str) -> None:
    if not condition:
        failures.append(detail)


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _check_events(
    failures: list[str],
    events: tuple[dict[str, Any], ...],
    alerts: tuple[dict[str, Any], ...],
    *,
    correlation_id: str | None,
    require_alerts: bool = True,
) -> None:
    _expect(failures, bool(events), "telemetry events are absent")
    if require_alerts:
        _expect(failures, bool(alerts), "alert events are absent")
    for index, event in enumerate(events):
        correlation = event.get("correlation_id")
        _expect(failures, isinstance(correlation, str) and bool(correlation), f"telemetry[{index}] has no correlation_id")
        if correlation_id is not None:
            _expect(failures, correlation == correlation_id, f"telemetry[{index}] correlation_id differs from run_id")
        _expect(failures, _valid_timestamp(event.get("timestamp")), f"telemetry[{index}] has no RFC3339 timestamp")
    for index, alert in enumerate(alerts):
        _expect(failures, alert.get("alert") is True, f"alert[{index}] is not an actual alert")
        _expect(failures, _valid_timestamp(alert.get("timestamp")), f"alert[{index}] has no RFC3339 timestamp")
        if correlation_id is not None:
            _expect(failures, alert.get("correlation_id") == correlation_id, f"alert[{index}] correlation_id differs from run_id")


def _persisted_telemetry_matches(path: Path, events: tuple[dict[str, Any], ...]) -> bool:
    if not path.is_file():
        return False
    persisted = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    return persisted == list(events)


def _run_case(name: str, operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        result = operation()
        result.update({"name": name, "passed": not result["failures"]})
        return result
    except Exception as exc:  # keep the gate machine readable while running remaining cases
        return {
            "name": name,
            "passed": False,
            "failures": [f"execution raised {type(exc).__name__}"],
            "metrics": {},
        }


def _offline_case(laboratory: ServiceLaboratory) -> dict[str, Any]:
    report = laboratory.run_offline_playback()
    failures: list[str] = []
    _expect(failures, report.service_activity == {"fixtures_read": 4, "events_evaluated": 8}, "offline fixture/event counts differ")
    _expect(failures, report.detection_counts.get("class:attack") == 4, "offline attack count differs")
    _expect(failures, report.detection_counts.get("class:benign") == 4, "offline benign count differs")
    _check_events(failures, report.telemetry_events, report.alert_events, correlation_id=None)
    return {
        "failures": failures,
        "metrics": {
            "fixtures": report.service_activity.get("fixtures_read"),
            "telemetry": len(report.telemetry_events),
            "alerts": len(report.alert_events),
        },
    }


def _evtx_case() -> dict[str, Any]:
    """Require the real pinned parser; missing prerequisites fail this gate."""
    fixture_root = ROOT / "cops/laboratory/service_fixtures"
    failures: list[str] = []
    metrics = {}
    for profile in ("vulnerable", "corrected", "insufficient"):
        path = fixture_root / f"sysmon-{profile}.evtx"
        before = path.read_bytes()
        source_hash = hashlib.sha256(before).hexdigest()
        report = import_evtx(path, expected_sha256=source_hash)
        expected_indicators = 1 if profile == "vulnerable" else 0
        expected_status = "partial" if profile == "insufficient" else "imported"
        expected_records = 1 if profile == "insufficient" else 2
        _expect(failures, report["status"] == expected_status, f"{profile}: incorrect coverage status")
        _expect(failures, report["records_total"] == expected_records, f"{profile}: records missing")
        _expect(failures, report["indicator_counts"] == {"powershell_network": expected_indicators, "encoded_command": expected_indicators}, f"{profile}: correction indicators differ")
        _expect(failures, path.read_bytes() == before, f"{profile}: original source changed")
        _expect(failures, all(event["evidence_ref"].startswith(f"evtx:sha256:{source_hash}:record:") for event in report["events"]), f"{profile}: evidence identity absent")
        _expect(failures, all(value not in json.dumps(report) for value in ("SYNTHETIC_SECRET", "CommandLine", "lab-user")), f"{profile}: source content leaked")
        if profile == "insufficient":
            _expect(failures, report["coverage_status"] == "indeterminate" and report["records_incomplete"] == 1 and not report["events"], "insufficient evidence was promoted")
        metrics[profile] = {key: report[key] for key in ("source_sha256", "records_total", "records_normalized", "status", "indicator_counts")}
        with tempfile.TemporaryDirectory(prefix="cops-evtx-integrity-") as directory:
            changed = Path(directory) / "changed.evtx"
            altered = bytearray(before)
            altered[5000] ^= 1
            changed.write_bytes(altered)
            try:
                import_evtx(changed, expected_sha256=source_hash)
            except EvtxImportError as exc:
                _expect(failures, str(exc) == "source_hash_mismatch", f"{profile}: changed source failed for unexpected reason")
            else:
                failures.append(f"{profile}: changed source accepted")
    return {"failures": failures, "metrics": metrics}


def _service_case(
    laboratory: ServiceLaboratory,
    profile: str,
    state_dir: Path,
    *,
    isolation_verified: bool,
) -> dict[str, Any]:
    report = laboratory.run_process_acceptance(profile, telemetry_directory=state_dir)  # type: ignore[arg-type]
    failures: list[str] = []
    activity = report.service_activity
    expected_lateral = 200 if profile == "vulnerable" else 403
    expected_reached = profile == "vulnerable"
    expected_rule = "rule:lateral-movement" if expected_reached else "rule:lateral-movement-blocked"
    expectations = {
        "identity_issue_status": 201,
        "authenticated_status": 200,
        "lateral_status": expected_lateral,
        "lateral_target_reached": expected_reached,
        "profile_configuration_verified": True,
        "ioc_ingest_status": 201,
        "hunt_status": 200,
        "hunt_hit": True,
        "containment_status": 200,
        "post_revoke_authenticated_status": 401,
        "actual_tcp_services": 4,
        "loopback_bind_verified": True,
        "graph_was_dirty_before_final_reset": True,
    }
    for field, expected in expectations.items():
        _expect(failures, activity.get(field) == expected, f"{field} expected {expected!r}, got {activity.get(field)!r}")
    for rule in (
        expected_rule,
        "rule:credential-revocation",
        "rule:post-revocation-auth-failure",
        "rule:ioc-hunt-hit",
        "rule:ioc-containment",
    ):
        _expect(failures, report.detection_counts.get(rule) == 1, f"{rule} count is not one")
    _expect(
        failures,
        report.tls
        == {
            "valid_client_status": 204,
            "missing_client_rejected": True,
            "untrusted_client_rejected": True,
            "untrusted_server_rejected": True,
            "server_address": "127.0.0.1",
            "protocol": "TLS",
        },
        "ephemeral mTLS valid/invalid outcomes differ",
    )
    api = activity.get("api", {})
    expected_verdict = "fail" if profile == "vulnerable" else "pass"
    _expect(failures, api.get("authorization_verdict") == expected_verdict, "REST/GraphQL object authorization outcome differs")
    _expect(failures, api.get("rate_limit_verdict") == expected_verdict, "API throttling outcome differs")
    _expect(failures, api.get("actual_requests") == 10, "six role/object cases and four throttling attempts were not exercised")
    _expect(failures, api.get("reset_verified") is True and api.get("service_stopped") is True, "API baseline or service cleanup is incomplete")
    jwt = activity.get("jwt", {})
    statuses = jwt.get("statuses", {})
    _expect(failures, jwt.get("actual_requests") == 9 and len(statuses) == 9, "JWT authentication cases were not exercised")
    _expect(failures, statuses.get("valid") == 204 and all(value == 401 for key, value in statuses.items() if key != "valid"), "JWT verifier accepted an invalid token or rejected the valid token")
    _expect(failures, jwt.get("service_stopped") is True, "JWT HTTP service did not stop")
    boundaries = activity.get("boundaries", {})
    _expect(failures, boundaries.get("benign_query_preserved") is True, "parameterized query changed the permitted result")
    _expect(failures, boundaries.get("injection_exposed_other_object") is expected_reached, "SQL injection correction outcome differs")
    _expect(failures, boundaries.get("injection_rows") == (2 if expected_reached else 0), "SQL injection row count differs")
    _expect(failures, boundaries.get("allowed_tool_status") == 200, "tool gateway rejected the allowed call")
    _expect(failures, boundaries.get("denied_attack_calls") == (0 if expected_reached else 4), "direct/indirect tool or resource scope outcome differs")
    _expect(failures, bool(boundaries.get("application_codes")) is expected_reached, "source assessment disagrees with observed SQL injection")
    expected_gateway = {"foundry_tool_scope", "foundry_resource_scope", "foundry_prompt_injection"} if expected_reached else set()
    _expect(failures, set(boundaries.get("gateway_codes", [])) == expected_gateway, "tool gateway findings disagree with observed scope controls")
    _expect(failures, boundaries.get("actual_requests") == 7 and boundaries.get("service_stopped") is True, "boundary service activity or cleanup is incomplete")
    acquisition = activity.get("acquisition", {})
    for field in ("original_unchanged", "permission_rejected", "modified_source_rejected", "no_partial_outputs", "disposable_root_removed"):
        _expect(failures, acquisition.get(field) is True, f"forensic acquisition {field} is incomplete")
    _expect(failures, acquisition.get("finding_codes") == [], "acquired evidence failed provenance assessment")
    _expect(failures, all(report.restoration.values()), "success/failure/cancellation/final graph restoration is incomplete")
    _expect(
        failures,
        report.isolation.verified is isolation_verified,
        "service report isolation evidence differs from the gate preflight",
    )
    _check_events(failures, report.telemetry_events, report.alert_events, correlation_id=report.run_id)
    _expect(failures, _persisted_telemetry_matches(state_dir / "telemetry.jsonl", report.telemetry_events), "persisted telemetry differs from the report")
    return {
        "failures": failures,
        "metrics": {
            "profile": profile,
            "tcp_services": activity.get("actual_tcp_services"),
            "lateral_status": activity.get("lateral_status"),
            "post_revoke_status": activity.get("post_revoke_authenticated_status"),
            "telemetry": len(report.telemetry_events),
            "alerts": len(report.alert_events),
            "restored": all(report.restoration.values()),
            "api_requests": api.get("actual_requests"),
            "api_authorization": api.get("authorization_verdict"),
            "api_rate_limit": api.get("rate_limit_verdict"),
            "jwt_requests": jwt.get("actual_requests"),
            "jwt_rejections": sum(value == 401 for value in statuses.values()),
            "boundary_requests": boundaries.get("actual_requests"),
            "tool_scope_denials": boundaries.get("denied_attack_calls"),
            "injection_exposed_other_object": boundaries.get("injection_exposed_other_object"),
            "acquisition_verified": acquisition.get("original_unchanged") is True and not acquisition.get("finding_codes"),
        },
    }


def _workflow_case(mode: str, state_dir: Path, *, require_isolation: bool) -> dict[str, Any]:
    report = run_workflow_service_laboratory(state_dir, mode=mode, require_isolation=require_isolation)  # type: ignore[arg-type]
    failures: list[str] = []
    expected = {
        "success": ("success", 3, [201, 201, 200, 200, 401]),
        "failure": ("partial_failure", 2, [201, 201, 200]),
        "cancellation": ("cancelled", 1, [201, 201]),
    }[mode]
    statuses = [request.get("status") for request in report.service_activity.get("requests", [])]
    _expect(failures, report.status == expected[0], f"workflow status expected {expected[0]}, got {report.status}")
    _expect(failures, report.authorization.get("consumed") == expected[1], "authorization consumption count differs")
    _expect(failures, report.authorization.get("one_use_store") is True, "one-use authorization store is not reported")
    _expect(failures, statuses == expected[2], f"actual TCP request statuses differ: {statuses}")
    _expect(failures, report.service_activity.get("actual_tcp_services") == 4, "four TCP services were not exercised")
    if mode == "success":
        _expect(failures, report.workflow.get("outputs") == {"contained": True, "post_revoke_status": 401}, "success outputs do not prove containment and post-revoke denial")
        for rule in (
            "rule:credential-revocation",
            "rule:post-revocation-auth-failure",
            "rule:ioc-hunt-hit",
            "rule:ioc-containment",
        ):
            _expect(failures, report.detection_counts.get(rule) == 1, f"{rule} count is not one")
    _expect(failures, report.restoration.get("baseline_restored") is True, "workflow baseline was not restored")
    _expect(failures, report.restoration.get("services_stopped") is True, "workflow services were not stopped")
    _expect(failures, report.restoration.get("cleanup_invoked") is (mode == "failure"), "cleanup invocation differs from expected failure behavior")
    _expect(
        failures,
        report.isolation.verified is require_isolation,
        "workflow report isolation evidence differs from the gate preflight",
    )
    _check_events(
        failures,
        report.telemetry_events,
        report.alert_events,
        correlation_id=report.run_id,
        require_alerts=mode != "cancellation",
    )
    if mode == "cancellation":
        _expect(failures, not report.alert_events, "cancelled workflow unexpectedly emitted an alert")
    _expect(failures, _persisted_telemetry_matches(state_dir / "telemetry.jsonl", report.telemetry_events), "persisted telemetry differs from the report")
    return {
        "failures": failures,
        "metrics": {
            "mode": mode,
            "status": report.status,
            "tcp_requests": len(statuses),
            "authorizations_consumed": report.authorization.get("consumed"),
            "telemetry": len(report.telemetry_events),
            "alerts": len(report.alert_events),
            "restored": report.restoration.get("baseline_restored") is True,
            "services_stopped": report.restoration.get("services_stopped") is True,
        },
    }


def _integrated_case(workflow_id: str, state_dir: Path, *, require_isolation: bool) -> dict[str, Any]:
    report = run_integrated_service_laboratory(
        state_dir, workflow_id=workflow_id, require_isolation=require_isolation,
    )
    failures: list[str] = []
    stages = list(WORKFLOW_STAGES[workflow_id])
    authorization = report["authorization"]
    assessment = report["outputs"].get("assessment", {})
    _expect(failures, report["status"] == "success", "integrated workflow did not succeed")
    _expect(failures, report["setup_status"] == 201, "credential setup did not succeed")
    _expect(failures, report["stages"] == stages, "workflow stage order differs")
    _expect(failures, authorization["provisioned"] == authorization["consumed"] == len(stages), "not every action consumed its own authorization")
    _expect(failures, len(set(authorization["plan_digests"].values())) == len(stages), "different stages reused a plan digest")
    _expect(failures, all(value.startswith("http://127.0.0.1:") for value in authorization["bound_destinations"].values()), "approval destinations escape the loopback laboratory")
    _expect(failures, report["restoration"] == {"baseline_restored": True, "services_stopped": True}, "integrated service baseline or listeners were not restored")
    _expect(failures, report["telemetry_matches_memory"] is True, "persisted telemetry differs from captured activity")
    _expect(failures, report["isolation"]["verified"] == require_isolation, "integrated isolation evidence differs from preflight")
    _check_events(failures, tuple(report["events"]), tuple(report["alerts"]), correlation_id=report["run_id"], require_alerts=workflow_id != "cve-reachability-triage")
    _expect(failures, _persisted_telemetry_matches(state_dir / "telemetry.jsonl", tuple(report["events"])), "integrated telemetry file differs from the report")
    if workflow_id == "leaked-credential-blast-radius":
        _expect(failures, [assessment.get(key) for key in ("before_revocation", "revocation", "after_revocation")] == [200, 200, 401], "credential revocation did not change real authentication")
        _expect(failures, assessment.get("bundle", {}).get("signature_verified") is True, "evidence bundle signature was not verified")
        exposure = assessment.get("synthetic_exposure", {})
        for key in (
            "value_redacted", "same_credential_observed", "historical_exposure_observed",
            "repository_unchanged_by_scan", "disposable_repository_removed",
        ):
            _expect(failures, exposure.get(key) is True, f"credential history proof is missing: {key}")
        content = exposure.get("artifact", {}).get("content", {})
        _expect(failures, content.get("coverage", {}).get("complete_within_configured_bounds") is True, "credential history enumeration was incomplete")
        prerequisites = content.get("adapter_prerequisites", {}).get("satisfied", [])
        _expect(failures, any(
            item.get("id") == "registered-adapter:git-object-enumerator@1"
            and item.get("version", "").startswith("git version 2.")
            and re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
            for item in prerequisites
        ), "credential history scanner lacks its pinned Git prerequisite")
    elif workflow_id == "cve-reachability-triage":
        _expect(failures, assessment.get("vulnerable", {}).get("injection_rows") == 2, "vulnerable SQL query did not expose the seeded objects")
        _expect(failures, assessment.get("corrected", {}).get("injection_rows") == 0 and assessment.get("remediation_verified") is True, "corrected query did not preserve the boundary")
        _expect(failures, assessment.get("without_runtime_evidence") == {"reachability": "unknown", "non_exploitable": False}, "missing runtime evidence became non-exploitability")
    elif workflow_id == "illicit-consent-remediation":
        _expect(failures, [assessment.get(key) for key in ("grant_access_before", "revocation", "grant_access_after")] == [200, 200, 401], "grant revocation did not change real authentication")
    elif workflow_id == "detection-rule-ci-validation":
        _expect(failures, assessment.get("event_counts", {}).get("class:attack") == 3 and assessment.get("event_counts", {}).get("class:benign") == 3, "detection measurements lack attack or benign execution")
        _expect(failures, len(assessment.get("alerts", [])) == 2, "detection measurements differ from actual alerts")
        purple = assessment.get("purple_team", {})
        _expect(failures, purple.get("source") == "captured-service-activity", "purple outcomes lack a captured service source")
        _expect(failures, purple.get("source_digests") == {"telemetry": digest(report["events"]), "alerts": digest(report["alerts"])}, "purple source digests differ from captured service activity")
        _expect(failures, purple.get("handoff_digest") == digest(purple.get("handoff")), "purple handoff digest differs")
        expected_states = {
            "captured": "verified_detection", "logs_withheld": "instrumentation_gap",
            "alerts_withheld": "detection_gap", "alert_evidence_unavailable": "indeterminate",
        }
        views = purple.get("views", {})
        _expect(failures, {name: view.get("result", {}).get("status") for name, view in views.items()} == expected_states, "purple evidence views do not produce all four outcomes")
        for name, view in views.items():
            result = view.get("result", {})
            _expect(failures, "captured service" in view.get("evidence_view", ""), f"purple view {name} does not label its evidence")
            _expect(failures, result.get("fixture_counts") == {"attack_matches": 1, "benign_matches": 0}, f"purple view {name} lacks attack and benign measurements")
            execution = result.get("rule_execution", {})
            _expect(failures, execution.get("counts_agree") is True, f"purple view {name} rule proposals disagree")
            for engine in ("sigma", "kql"):
                measured = execution.get(engine, {})
                _expect(failures, measured.get("status") == "executed" and measured.get("attack_matches") == 1 and measured.get("benign_matches") == 0, f"purple view {name} {engine} proposal was not executed against captured events")
    else:
        _expect(failures, assessment.get("authorized_status") == 200 and assessment.get("anonymous_status") == 401, "exposure audit did not verify authenticated and anonymous access")
    return {"failures": failures, "metrics": {
        "workflow_id": workflow_id, "status": report["status"], "stages": len(stages),
        "authorizations_consumed": authorization["consumed"], "tcp_requests": len(report["requests"]),
        "telemetry": len(report["events"]), "alerts": len(report["alerts"]),
        "restored": report["restoration"]["baseline_restored"], "services_stopped": report["restoration"]["services_stopped"],
    }}


def run_acceptance_gate(state_root: Path) -> tuple[int, dict[str, Any]]:
    """Run all evidence cases and return the exit code plus compact summary."""
    isolation = probe_isolated_runtime()
    cases: list[dict[str, Any]] = []
    laboratory = ServiceLaboratory()
    cases.append(_run_case("offline-playback", lambda: _offline_case(laboratory)))
    cases.append(_run_case("binary-evtx", _evtx_case))
    for profile in ("vulnerable", "corrected"):
        cases.append(
            _run_case(
                f"service-{profile}",
                lambda profile=profile: _service_case(
                    laboratory,
                    profile,
                    state_root / f"service-{profile}",
                    isolation_verified=isolation.verified,
                ),
            )
        )

    strict_preflight: dict[str, Any]
    if isolation.verified:
        strict_preflight = {"passed": True, "state_created": False, "detail": "verified isolation probe permits strict execution"}
    else:
        strict_state = state_root / "strict-preflight-must-not-exist"
        try:
            run_workflow_service_laboratory(strict_state, require_isolation=True)
        except IsolationRequiredError as exc:
            strict_preflight = {"passed": not strict_state.exists(), "state_created": strict_state.exists(), "detail": str(exc)}
        except Exception as exc:
            strict_preflight = {"passed": False, "state_created": strict_state.exists(), "detail": f"unexpected {type(exc).__name__}"}
        else:
            strict_preflight = {"passed": False, "state_created": strict_state.exists(), "detail": "strict execution ran without verified isolation"}

    for mode in ("success", "failure", "cancellation"):
        cases.append(
            _run_case(
                f"workflow-{mode}",
                lambda mode=mode: _workflow_case(mode, state_root / f"workflow-{mode}", require_isolation=isolation.verified),
            )
        )

    for workflow_id in INTEGRATED_WORKFLOW_IDS:
        cases.append(_run_case(
            "integrated-" + workflow_id,
            lambda workflow_id=workflow_id: _integrated_case(
                workflow_id, state_root / ("integrated-" + workflow_id), require_isolation=isolation.verified,
            ),
        ))

    failures = [f"{case['name']}: {detail}" for case in cases for detail in case["failures"]]
    if not strict_preflight["passed"]:
        failures.append(f"strict-isolation-preflight: {strict_preflight['detail']}")
    blockers = [] if isolation.verified else [isolation.blocker or "isolation probe returned unverified without a blocker"]
    status = "failed" if failures else ("passed" if isolation.verified else "blocked")
    exit_code = 0 if status == "passed" else (2 if status == "blocked" else 1)
    return exit_code, {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "isolation": isolation.to_dict(),
        "strict_preflight": strict_preflight,
        "cases": cases,
        "failures": failures,
        "blockers": blockers,
        "summary": {
            "cases_passed": sum(case["passed"] for case in cases),
            "cases_total": len(cases),
            "functional_evidence_only": not isolation.verified,
        },
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, help="retain disposable acceptance state at this path")
    parser.add_argument("--runtime", choices=("process", "docker"), default="process")
    parser.add_argument("--image", help="already installed immutable Docker image ID (sha256:<64 hex>)")
    parser.add_argument("--timeout", type=int, default=240, help="container deadline in seconds (30-600)")
    parser.add_argument("--container-child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.runtime == "docker" and (args.state_dir is not None or args.container_child):
        parser.error("Docker acceptance does not accept --state-dir or --container-child")
    if args.runtime == "docker" and not args.image:
        parser.error("Docker acceptance requires --image with an installed immutable image ID")
    if args.runtime == "process" and args.image:
        parser.error("--image requires --runtime docker")
    if not 30 <= args.timeout <= 600:
        parser.error("--timeout must be between 30 and 600 seconds")
    return args


def main() -> int:
    args = _parse_args()
    if args.runtime == "docker":
        try:
            exit_code, summary = run_container_acceptance(ROOT, image=args.image, timeout=args.timeout)
        except ValueError:
            exit_code, summary = 2, {"schema_version": SCHEMA_VERSION, "status": "blocked", "blockers": ["Docker acceptance requires a valid installed immutable image ID"]}
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return exit_code
    if args.container_child:
        isolation = probe_isolated_runtime()
        if not isolation.verified:
            print(json.dumps({"schema_version": SCHEMA_VERSION, "status": "blocked", "isolation": isolation.to_dict(), "blockers": [isolation.blocker], "summary": {"cases_passed": 0, "cases_total": len(ACCEPTANCE_CASE_IDS), "functional_evidence_only": True}}, sort_keys=True, separators=(",", ":")))
            return 2
    if args.state_dir is not None:
        args.state_dir.mkdir(parents=True, exist_ok=True)
        exit_code, summary = run_acceptance_gate(args.state_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="cops-laboratory-gate-") as temporary:
            exit_code, summary = run_acceptance_gate(Path(temporary))
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
