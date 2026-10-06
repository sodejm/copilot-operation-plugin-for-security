"""Inert test fixtures for laboratory harness development and offline validation."""

from __future__ import annotations

from cops.contracts.models import (
    ActionPlan,
    Engagement,
    ExecutionAuthorization,
    LaboratoryEnvironment,
)
from cops.contracts.validation import build_action_plan_digest
from cops.evidence.canonical import digest, utc_now


def make_inert_container_environment(
    environment_id: str = "env-lab-container-01",
    owner: str = "lab-operator",
) -> LaboratoryEnvironment:
    """Create a valid inert container laboratory environment contract."""
    now_iso = utc_now()
    return LaboratoryEnvironment(
        schema_version="cops.laboratory-environment/v1",
        environment_id=environment_id,
        environment_type="container",
        status="registered",
        platform={
            "os": "linux",
            "distribution": "ubuntu",
            "architecture": "x86_64",
            "runtime": "container",
            "runtime_version": "24.0.5",
        },
        tool_matrix={
            "kubectl": "1.28.0",
            "kube-bench": "0.7.0",
            "kube-hunter": "0.6.8",
            "kubescape": "3.0.0",
            "nmap": "7.94",
            "python3": "3.11.8",
        },
        isolation={
            "isolation_type": "container_unprivileged",
            "network_isolated": True,
            "egress_restricted": True,
            "verification_status": "unverified",
            "verification_timestamp": None,
            "verification_notes": None,
        },
        canary={
            "canary_id": "canary-token-k8s-01",
            "canary_token": "canary-k8s",
            "location": "/var/run/secrets/canary.txt",
            "verified": False,
        },
        reset_configuration={
            "strategy": "container_recreate",
            "reproducible": True,
            "command": "echo 'container recreated'",
            "last_reset_timestamp": None,
        },
        owner=owner,
        created_at=now_iso,
        updated_at=now_iso,
    )


def make_inert_vm_environment(
    environment_id: str = "env-lab-vm-01",
    owner: str = "lab-operator",
) -> LaboratoryEnvironment:
    """Create a valid inert VM laboratory environment contract."""
    now_iso = utc_now()
    return LaboratoryEnvironment(
        schema_version="cops.laboratory-environment/v1",
        environment_id=environment_id,
        environment_type="vm",
        status="registered",
        platform={
            "os": "linux",
            "distribution": "debian",
            "architecture": "x86_64",
            "runtime": "vm",
            "runtime_version": "8.0.0",
        },
        tool_matrix={
            "kubectl": "1.26.1",
            "kube-bench": "0.6.5",
            "nmap": "7.92",
            "python3": "3.11.2",
        },
        isolation={
            "isolation_type": "vm_hypervisor",
            "network_isolated": True,
            "egress_restricted": True,
            "verification_status": "unverified",
            "verification_timestamp": None,
            "verification_notes": None,
        },
        canary={
            "canary_id": "canary-vm-01",
            "canary_token": "canary-vm",
            "location": "/etc/canary.token",
            "verified": False,
        },
        reset_configuration={
            "strategy": "snapshot_rollback",
            "reproducible": True,
            "command": "echo 'snapshot reverted'",
            "last_reset_timestamp": None,
        },
        owner=owner,
        created_at=now_iso,
        updated_at=now_iso,
    )


def make_inert_engagement(
    engagement_id: str = "eng-lab-01",
    target_cidr: str = "10.200.0.0/24",
) -> Engagement:
    """Create a valid engagement contract for laboratory scenarios."""
    now_iso = utc_now()
    return Engagement(
        schema_version="cops.engagement/v1",
        engagement_id=engagement_id,
        name="Scenario Laboratory Controlled Assessment",
        status="active",
        mode="laboratory",
        scope={
            "included_networks": [target_cidr],
            "excluded_networks": ["169.254.169.254/32", "0.0.0.0/0"],
        },
        window={
            "started_at": now_iso,
            "authorized_until_utc": "2029-12-31T23:59:59Z",
        },
        operator="secops-lead",
        rules_of_engagement={
            "allowed_hours": "24/7",
            "approval_required": True,
            "prohibited_actions": ["external_egress", "host_kernel_reboot"],
        },
        created_at=now_iso,
        credential_references=["env:LAB_API_KEY"],
    )


def make_inert_action_plan(
    plan_id: str = "plan-lab-01",
    engagement_id: str = "eng-lab-01",
    scenario_id: str = "COPS-E03.03-S01",
    target: str = "10.200.0.10",
    specialist_id: str = "cops-pentest-specialist",
) -> ActionPlan:
    """Create a valid ActionPlan with canonical plan_digest."""
    now_iso = utc_now()
    operations = [
        {
            "step_id": "step-01",
            "tool": "kube-bench",
            "action": "run_cis_benchmark",
            "arguments": {"target": target, "standards": "cis-1.7"},
            "timeout_seconds": 60,
        }
    ]
    limits = {
        "max_duration_seconds": 120,
        "max_output_bytes": 1048576,
        "egress_allowed": False,
    }
    plan_digest = build_action_plan_digest(
        target=target,
        specialist_id=specialist_id,
        operations=operations,
        limits=limits,
    )
    return ActionPlan(
        schema_version="cops.action-plan/v1",
        plan_id=plan_id,
        engagement_id=engagement_id,
        scenario_id=scenario_id,
        target=target,
        specialist_id=specialist_id,
        status="approved",
        operations=operations,
        limits=limits,
        plan_digest=plan_digest,
        created_at=now_iso,
        credential_references=[],
    )


def make_inert_execution_authorization(
    plan: ActionPlan,
    authorization_id: str = "auth-lab-00000001",
    operator: str = "secops-lead",
    worker_identity: str = "lab-operator",
) -> ExecutionAuthorization:
    """Create a cryptographically bound ExecutionAuthorization envelope."""
    now_iso = utc_now()
    bound_params = {
        "target": plan.target,
        "specialist_id": plan.specialist_id,
        "worker_identity": worker_identity,
        "limits": plan.limits,
        "credential_references": plan.credential_references,
        "operations_summary": [
            {"step_id": op["step_id"], "tool": op["tool"], "action": op["action"]}
            for op in plan.operations
        ],
    }
    payload = {
        "action_plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "engagement_id": plan.engagement_id,
        "operator": operator,
        "issued_at": now_iso,
        "authorized_until_utc": "2029-12-31T23:59:59Z",
        "bound_parameters": bound_params,
        "approval_mode": "pre_signed_envelope",
    }
    signature_digest = digest(payload)
    return ExecutionAuthorization(
        schema_version="cops.execution-authorization/v1",
        authorization_id=authorization_id,
        action_plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        operator=operator,
        issued_at=now_iso,
        authorized_until_utc="2029-12-31T23:59:59Z",
        bound_parameters=bound_params,
        approval_mode="pre_signed_envelope",
        signature_digest=signature_digest,
        status="approved",
    )
