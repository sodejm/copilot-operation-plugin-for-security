"""Authorized IOC-to-hunt-to-containment acceptance over disposable TCP services."""

from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from cops.contracts.models import ActionPlan, Engagement
from cops.evidence.canonical import digest
from cops.execution.authorization import (
    AuthorizationSigner,
    AuthorizationTrustStore,
    TrustedAuthorizationKey,
    create_execution_authorization,
    verify_execution_authorization,
)
from cops.execution.control import ApprovalConsumptionReceipt
from cops.execution.store import ApprovalStore
from cops.workflows.contracts import WorkflowDefinition
from cops.workflows.runtime import StageExecutionResult, WorkflowRunner, compile_action_plan

from .service_lab import (
    FIXTURE_DIRECTORY,
    IsolationProbe,
    _execute_detection_rules,
    _Graph,
    _request_json,
    _Telemetry,
    probe_isolated_runtime,
    verify_fixture_manifest,
)

REPORT_SCHEMA = "cops.workflow-service-laboratory-report/v1"
IOC = "203.0.113.77"
WORKER = "workflow-laboratory-worker"


class IsolationRequiredError(RuntimeError):
    """Strict execution was requested without a verified isolation boundary."""

    def __init__(self, probe: IsolationProbe) -> None:
        self.probe = probe
        super().__init__(probe.blocker or "isolation is not verified")


@dataclass(frozen=True)
class WorkflowServiceLaboratoryReport:
    run_id: str
    mode: str
    status: str
    workflow: dict[str, Any]
    authorization: dict[str, Any]
    service_activity: dict[str, Any]
    detection_counts: dict[str, int]
    restoration: dict[str, bool]
    isolation: IsolationProbe
    fixture_manifest_digest: str
    telemetry_events: tuple[dict[str, Any], ...]
    alert_events: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]
    schema_version: str = REPORT_SCHEMA
    artifact_kind: str = "service_laboratory_report"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["isolation"] = self.isolation.to_dict()
        return result


def _action(name: str) -> dict[str, Any]:
    return {
        "target": "laboratory-loopback-services",
        "specialist_id": "laboratory-runner",
        "tool": "cops-workflow-service-laboratory",
        "tool_version": "1.0.0",
        "action": name,
        "timeout_seconds": 10,
        "limits": {"max_duration_seconds": 30, "max_output_bytes": 65536, "egress_allowed": False},
        "expected_evidence": [f"tcp:{name}"],
        "side_effects": ["disposable laboratory state only"],
        "cleanup": {"action": "restore_baseline"},
    }


def build_workflow_definition() -> WorkflowDefinition:
    """Return the stable, typed workflow used by this laboratory."""
    return WorkflowDefinition.from_dict(
        {
            "schema_version": "cops.workflow-definition/v1",
            "workflow_id": "ioc-hunt-containment-laboratory",
            "engagement_id": "eng-workflow-laboratory",
            "scenario_id": "scen-ioc-hunt-containment",
            "description": "Issue a synthetic credential, ingest and hunt an IOC, contain it, and prove revocation.",
            "inputs": {"ioc": {"type": "string", "required": True}},
            "outputs": {
                "contained": {"type": "boolean", "source": "stage.contain.output.contained"},
                "post_revoke_status": {"type": "integer", "source": "stage.contain.output.post_revoke_status"},
            },
            "budget": {"max_stages": 3, "max_total_attempts": 3, "max_output_bytes": 262144, "max_evidence_refs": 32},
            "stages": [
                {
                    "stage_id": "ingest",
                    "depends_on": [],
                    "inputs": {"ioc": {"type": "string", "source": "workflow.input.ioc"}},
                    "outputs": {"ioc": {"type": "string"}, "ingested": {"type": "boolean"}},
                    "action": _action("ingest_ioc"),
                },
                {
                    "stage_id": "hunt",
                    "depends_on": ["ingest"],
                    "inputs": {"ioc": {"type": "string", "source": "stage.ingest.output.ioc"}},
                    "outputs": {"ioc": {"type": "string"}, "hit": {"type": "boolean"}},
                    "action": _action("hunt_ioc"),
                },
                {
                    "stage_id": "contain",
                    "depends_on": ["hunt"],
                    "inputs": {
                        "ioc": {"type": "string", "source": "stage.hunt.output.ioc"},
                        "hit": {"type": "boolean", "source": "stage.hunt.output.hit"},
                    },
                    "outputs": {"contained": {"type": "boolean"}, "post_revoke_status": {"type": "integer"}},
                    "action": _action("contain_ioc"),
                },
            ],
        }
    )


class _LaboratoryApprovalControl:
    """In-process adapter exercising the production signer, verifier, and one-use store."""

    def __init__(self, store: ApprovalStore, trust: AuthorizationTrustStore, engagement: Engagement, now: str) -> None:
        self.store, self.trust, self.engagement, self.now = store, trust, engagement, now
        self._receipts: set[int] = set()

    def assert_ready(self, worker_identity: str) -> None:
        if worker_identity != WORKER:
            raise RuntimeError("unexpected laboratory worker")

    def consume_authorization(
        self, authorization_id: str, action_plan: ActionPlan, worker_identity: str
    ) -> ApprovalConsumptionReceipt:
        stored = self.store.get_authorization(authorization_id)
        verified = verify_execution_authorization(
            stored,
            action_plan,
            trust_store=self.trust,
            engagement=self.engagement,
            worker_identity=worker_identity,
            current_time_iso=self.now,
        )
        consumed = self.store.atomically_consume(
            authorization_id,
            expected_authorization=verified,
            worker_identity=worker_identity,
            current_time_iso=self.now,
        )
        receipt = ApprovalConsumptionReceipt(
            authorization_id=authorization_id,
            authorization_digest=digest(consumed.to_dict()),
            action_plan_id=action_plan.plan_id,
            plan_digest=action_plan.plan_digest,
            engagement_id=action_plan.engagement_id,
            worker_identity=worker_identity,
            target=action_plan.target,
        )
        self._receipts.add(id(receipt))
        return receipt

    def validate_receipt_provenance(self, receipt: ApprovalConsumptionReceipt) -> ApprovalConsumptionReceipt:
        if id(receipt) not in self._receipts:
            raise RuntimeError("receipt was not issued by the laboratory approval adapter")
        return receipt

    def release_receipt_provenance(self, receipt: ApprovalConsumptionReceipt) -> None:
        self._receipts.discard(id(receipt))


class _Executor:
    def __init__(self, graph: _Graph, token: str, mode: str) -> None:
        self.graph, self.token, self.mode = graph, token, mode
        self.requests: list[dict[str, Any]] = []
        self.completed = 0
        self.cleanup_invoked = False

    def _record(self, stage: str, method: str, service: str, path: str, status: int) -> None:
        self.requests.append({"stage": stage, "method": method, "service": service, "path": path, "status": status})

    def execute(
        self, plan: ActionPlan, _receipt: ApprovalConsumptionReceipt, *, idempotency_key: str
    ) -> StageExecutionResult:
        operation = plan.to_dict()["operations"][0]
        action, args = operation["action"], operation["arguments"]
        if action == "ingest_ioc":
            status, body = _request_json(f"{self.graph.hunt.url}/ioc", method="POST", payload={"value": args["ioc"]})
            self._record("ingest", "POST", "hunt", "/ioc", status)
            result = StageExecutionResult(
                "success", {"ioc": args["ioc"], "ingested": body.get("ingested") is True}, (f"tcp:{idempotency_key}",)
            )
        elif action == "hunt_ioc":
            status, body = _request_json(f"{self.graph.hunt.url}/hunt?value={args['ioc']}")
            self._record("hunt", "GET", "hunt", "/hunt", status)
            if self.mode == "failure":
                return StageExecutionResult("failed", {}, (f"tcp:{idempotency_key}",), "injected_after_hunt")
            result = StageExecutionResult(
                "success", {"ioc": args["ioc"], "hit": body.get("hit") is True}, (f"tcp:{idempotency_key}",)
            )
        elif action == "contain_ioc":
            status, body = _request_json(f"{self.graph.hunt.url}/contain", method="POST", payload={"token": self.token})
            self._record("contain", "POST", "hunt", "/contain", status)
            revoked, _ = _request_json(f"{self.graph.resource.url}/protected", token=self.token)
            self._record("contain", "GET", "resource", "/protected", revoked)
            result = StageExecutionResult(
                "success",
                {"contained": body.get("contained") is True, "post_revoke_status": revoked},
                (f"tcp:{idempotency_key}",),
            )
        else:
            raise RuntimeError(f"unsupported laboratory action: {action}")
        self.completed += 1
        return result

    def cleanup(self, _plan: ActionPlan, *, idempotency_key: str) -> None:
        del idempotency_key
        self.graph.state.restore(self.graph.baseline)
        self.cleanup_invoked = True


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def run_workflow_service_laboratory(
    state_dir: str | Path,
    *,
    mode: Literal["success", "failure", "cancellation"] = "success",
    require_isolation: bool = False,
    run_id: str | None = None,
) -> WorkflowServiceLaboratoryReport:
    """Run real loopback TCP activity under exact one-use stage authorizations."""
    if mode not in {"success", "failure", "cancellation"}:
        raise ValueError("mode must be success, failure, or cancellation")
    isolation = probe_isolated_runtime()
    if require_isolation and not isolation.verified:
        raise IsolationRequiredError(isolation)

    state_path = Path(state_dir)
    state_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_id = run_id or f"workflow-lab-{uuid.uuid4().hex[:12]}"
    telemetry = _Telemetry(state_path / "telemetry.jsonl", correlation_id=run_id)
    configuration = json.loads((FIXTURE_DIRECTORY / "corrected.json").read_text(encoding="utf-8"))
    definition = build_workflow_definition()
    token = secrets.token_urlsafe(24)
    requests: list[dict[str, Any]] = []
    now_dt = datetime.now(UTC).replace(microsecond=0)
    now, trust_start, auth_end, trust_end = map(
        _utc, (now_dt, now_dt - timedelta(minutes=5), now_dt + timedelta(hours=2), now_dt + timedelta(hours=3))
    )
    key = secrets.token_bytes(32)
    signer = AuthorizationSigner("workflow-lab-key", "laboratory-operator", key, trust_start, trust_end)
    trust = AuthorizationTrustStore(
        [TrustedAuthorizationKey("workflow-lab-key", "laboratory-operator", key, trust_start, trust_end)]
    )
    engagement = Engagement.from_dict(
        {
            "schema_version": "cops.engagement/v1",
            "engagement_id": definition.engagement_id,
            "name": "Workflow service laboratory",
            "status": "active",
            "scope": {"included_targets": ["laboratory-loopback-services"], "excluded_targets": []},
            "window": {"started_at": trust_start, "authorized_until_utc": trust_end},
            "operator": "laboratory-operator",
            "rules_of_engagement": {
                "max_intensity": "low",
                "allowed_actions": ["contain_ioc", "hunt_ioc", "ingest_ioc"],
                "emergency_contact": "soc@example.test",
                "safe_mode": True,
            },
            "created_at": trust_start,
            "mode": "laboratory",
        }
    )
    store = ApprovalStore(state_path / "approvals.sqlite3")

    with _Graph(configuration, telemetry) as graph:
        issued, _ = _request_json(f"{graph.identity.url}/issue", method="POST", payload={"token": token})
        requests.append({"stage": "setup", "method": "POST", "service": "identity", "path": "/issue", "status": issued})
        resolved = {"ingest": {"ioc": IOC}, "hunt": {"ioc": IOC}, "contain": {"ioc": IOC, "hit": True}}
        authorization_ids: dict[str, str] = {}
        plan_digests: dict[str, str] = {}
        for stage, arguments in resolved.items():
            plan = compile_action_plan(definition, run_id, stage, arguments, now)
            auth = create_execution_authorization(
                plan,
                signer=signer,
                engagement=engagement,
                worker_identity=WORKER,
                issued_at=now,
                authorized_until_utc=auth_end,
                authorization_id=f"auth-{digest({'run_id': run_id, 'stage': stage})[:24]}",
            )
            store.store_authorization(auth)
            authorization_ids[stage] = auth.authorization_id
            plan_digests[stage] = plan.plan_digest
        approval = _LaboratoryApprovalControl(store, trust, engagement, now)
        executor = _Executor(graph, token, mode)
        runner = WorkflowRunner(state_path / "workflow-state", approval, WORKER, executor, clock=lambda: now)
        result = runner.run(
            definition,
            run_id,
            {"ioc": IOC},
            authorization_ids,
            cancellation_requested=(lambda: mode == "cancellation" and executor.completed >= 1),
        )
        requests.extend(executor.requests)
        cleanup_invoked = executor.cleanup_invoked
        baseline_before_exit = graph.state.snapshot() == graph.baseline.snapshot()

    counts, alerts = _execute_detection_rules(telemetry.events)
    consumed = sum(
        1 for stage in authorization_ids if store.get_authorization(authorization_ids[stage]).status == "consumed"
    )
    return WorkflowServiceLaboratoryReport(
        run_id=run_id,
        mode=mode,
        status=result.status,
        workflow={
            "workflow_id": definition.workflow_id,
            "definition_digest": definition.definition_digest,
            "outputs": result.outputs,
            "stages": result.stages,
        },
        authorization={
            "mechanism": "signed exact ActionPlan plus atomic one-use ApprovalStore",
            "provisioned": len(authorization_ids),
            "consumed": consumed,
            "authorization_ids": authorization_ids,
            "plan_digests": plan_digests,
            "one_use_store": True,
            "boundary": "in-process laboratory adapter; production authority requires Linux SO_PEERCRED and a distinct UID",
        },
        service_activity={"actual_tcp_services": 4, "bind_address": "127.0.0.1", "requests": requests},
        detection_counts=counts,
        restoration={
            "cleanup_invoked": cleanup_invoked,
            "baseline_before_graph_exit": baseline_before_exit,
            "baseline_restored": graph.final_reset_verified,
            "services_stopped": all(not service.thread.is_alive() for service in graph.services),
        },
        isolation=isolation,
        fixture_manifest_digest=verify_fixture_manifest(),
        telemetry_events=tuple(telemetry.events),
        alert_events=alerts,
        limitations=(
            "Loopback TCP proves real service activity but does not prove network namespace isolation.",
            "The approval adapter exercises production signing, verification, exact-plan binding, and atomic consumption without claiming the production separate-UID boundary.",
        ),
    )
