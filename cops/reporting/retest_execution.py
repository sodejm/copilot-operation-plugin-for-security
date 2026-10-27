"""Fail-closed verification of durable, lab-only execution evidence for retest review."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from dataclasses import fields as dataclass_fields
from typing import Any

from cops.contracts.models import ActionPlan, CleanupReceipt, ExecutionAuthorization, LaboratoryEnvironment
from cops.contracts.validation import validate_contract
from cops.evidence.canonical import digest, timestamp
from cops.execution.authorization import AuthorizationTrustStore, verify_execution_authorization
from cops.execution.ssh_execution import RemoteAuthorizedRun, validate_remote_authorized_run
from cops.execution.ssh_transport import SSHRemoteEndpointInventory, endpoint_identity
from cops.execution.supervisor_attestation import verify_attested_authorized_run
from cops.laboratory.receipts import LaboratoryCaseObservation, LaboratoryObservationTrustStore, verify_worker_receipt


class RetestExecutionEvidenceError(ValueError):
    """The execution bundle is incomplete, mismatched, replayed, or untrusted."""


@dataclass(frozen=True)
class RetestReviewInput:
    finding_id: str
    asset_id: str
    outcome: str
    plan_id: str
    plan_digest: str
    result_id: str
    evidence_digest: str
    closure_status: str = "blocked"
    independent_review_required: bool = True


@dataclass(frozen=True)
class TrustedLaboratoryContext:
    """Operator-verified context loaded independently of the evidence bundle.

    ``provenance`` identifies the trusted registration/baseline source used by
    the caller; it must not be copied from the bundle under verification.
    """

    environment: LaboratoryEnvironment
    plan: ActionPlan
    target: str
    provenance: str


def verify_retest_execution_evidence_reference(
    reference: Mapping[str, Any], *, evidence_store: Any, **verification: Any
) -> RetestReviewInput:
    """Resolve a laboratory artifact reference before verifying it for review."""
    try:
        bundle = evidence_store.read_json(reference)
    except Exception as err:
        raise RetestExecutionEvidenceError("cannot authenticate persisted laboratory evidence bytes") from err
    return verify_retest_execution_evidence(bundle, evidence_store=evidence_store, **verification)


_FIELDS = {
    "schema_version",
    "environment_id",
    "case_type",
    "classification_status",
    "action_plan",
    "action_plan_sha256",
    "authorization",
    "supervisor_exchange",
    "authorized_run",
    "observation",
    "cleanup_receipt",
    "case_journal_record",
    "baseline_finding_id",
    "asset_id",
}


def verify_retest_execution_evidence(
    bundle: Mapping[str, Any],
    *,
    trust_store: AuthorizationTrustStore,
    endpoint_inventory: SSHRemoteEndpointInventory,
    observation_trust_store: LaboratoryObservationTrustStore,
    engagement: Any,
    finding_id: str,
    asset_id: str,
    trusted_context: TrustedLaboratoryContext,
    trusted_terminal_journal_record_digest: str,
    previously_consumed_authorization_ids: Sequence[str],
    evidence_store: Any,
) -> RetestReviewInput:
    """Verify a versioned laboratory bundle before producing retest review inputs.

    This function does not close findings. Callers must retain independent review as a gate.
    """
    if not isinstance(bundle, Mapping):
        raise RetestExecutionEvidenceError("execution evidence must be a mapping")
    try:
        validate_contract(dict(bundle), "laboratory_retest_evidence")
    except Exception as err:
        raise RetestExecutionEvidenceError("laboratory retest evidence contract validation failed") from err
    if set(bundle) != _FIELDS:
        raise RetestExecutionEvidenceError("execution evidence fields are incomplete or unknown")
    if bundle["schema_version"] != "cops.laboratory-retest-evidence/v1":
        raise RetestExecutionEvidenceError("unsupported laboratory retest evidence schema")
    if not isinstance(finding_id, str) or not finding_id or not isinstance(asset_id, str) or not asset_id:
        raise RetestExecutionEvidenceError("exact baseline finding and asset identities are required")
    try:
        if not isinstance(trusted_context, TrustedLaboratoryContext):
            raise ValueError("independently sourced trusted laboratory context is required")
        if not isinstance(trusted_context.provenance, str) or not trusted_context.provenance.strip():
            raise ValueError("trusted laboratory context provenance is required")
        env = trusted_context.environment
        validate_contract(env.to_dict(), "laboratory_environment")
        if env.environment_id != bundle.get("environment_id"):
            raise ValueError("evidence environment differs from the independently trusted registration")
        if (
            env.status != "verified"
            or env.environment_type not in {"container", "vm"}
            or env.isolation.get("verification_status") != "verified"
            or env.isolation.get("network_isolated") is not True
            or env.isolation.get("egress_restricted") is not True
            or env.canary.get("verified") is not True
        ):
            raise ValueError("trusted context is not a verified disposable laboratory")
        plan = ActionPlan.from_dict(dict(bundle["action_plan"]))
        if plan.plan_digest != bundle["action_plan_sha256"]:
            raise ValueError("plan digest mismatch")
        if (
            plan.plan_id != trusted_context.plan.plan_id
            or plan.plan_digest != trusted_context.plan.plan_digest
            or plan.to_dict() != trusted_context.plan.to_dict()
        ):
            raise ValueError("plan changed from the expected baseline plan")
        if plan.target != trusted_context.target:
            raise ValueError("execution target differs from trusted laboratory context")
        auth = ExecutionAuthorization.from_dict(dict(bundle["authorization"]))
        if not isinstance(previously_consumed_authorization_ids, Sequence) or isinstance(
            previously_consumed_authorization_ids, (str, bytes)
        ):
            raise ValueError("prior authorization-consumption ledger snapshot is required")
        if auth.authorization_id in previously_consumed_authorization_ids:
            raise ValueError("authorization is present in the supplied prior-consumption ledger snapshot")
        worker = auth.bound_parameters.get("worker_identity")
        if not isinstance(worker, str) or not worker or plan.target != trusted_context.target:
            raise ValueError("signed authorization worker or exact baseline target identity is missing")
        auth = verify_execution_authorization(
            auth,
            plan,
            trust_store=trust_store,
            worker_identity=worker,
            engagement=engagement,
            current_time_iso=str(bundle["authorized_run"]["result"]["started_at"]),
        )
        exchange = bundle["supervisor_exchange"]
        endpoint = endpoint_inventory.resolve(worker)
        trusted_endpoint_identity = endpoint_identity(endpoint)
        if (
            exchange["worker_identity"] != worker
            or exchange["endpoint_host"] != endpoint.host
            or exchange["attestation_key_id"] != endpoint.attestation_key_id
            or exchange.get("endpoint_identity") != trusted_endpoint_identity
        ):
            raise ValueError("supervisor endpoint or worker identity changed")
        if exchange["authorization_id"] != auth.authorization_id or exchange["action_plan"] != plan.to_dict():
            raise ValueError("supervisor request does not match the signed authorization and plan")
        remote = verify_attested_authorized_run(
            exchange["response_payload"],
            attestation_key_id=endpoint.attestation_key_id,
            attestation_key=endpoint.attestation_key,
            request_id=exchange["request_id"],
            exchange_nonce=exchange["exchange_nonce"],
            host=endpoint.host,
            worker_identity=worker,
            authorization_id=auth.authorization_id,
            action_plan_document=plan.to_dict(),
            timeout_seconds=exchange["timeout_seconds"],
            max_output_bytes=exchange["max_output_bytes"],
            endpoint_identity_digest=digest(trusted_endpoint_identity),
        )
        authorized_run = RemoteAuthorizedRun.from_dict(remote)
        if authorized_run.to_dict() != dict(bundle["authorized_run"]):
            raise ValueError("persisted authorized run differs from the supervisor-attested response")
        validate_remote_authorized_run(
            authorized_run, approved_worker_identity=worker, authorization_id=auth.authorization_id, action_plan=plan
        )
        receipt = authorized_run.approval_receipt
        if (
            receipt.authorization_id != auth.authorization_id
            or not re.fullmatch(r"[a-f0-9]{64}", receipt.authorization_digest)
            or receipt.worker_identity != worker
        ):
            raise ValueError("approval consumption receipt is missing or mismatched")
        cleanup_doc = bundle["cleanup_receipt"]
        if not isinstance(cleanup_doc, Mapping):
            raise ValueError("typed worker cleanup receipt is missing")
        cleanup = CleanupReceipt.from_dict(dict(cleanup_doc))
        if authorized_run.cleanup_receipt != cleanup or cleanup.status not in {"completed", "not_required"}:
            raise ValueError("cleanup receipt is incomplete or differs from the supervisor-attested run")
        if (
            cleanup.plan_id != plan.plan_id
            or cleanup.engagement_id != plan.engagement_id
            or cleanup.worker_identity != worker
        ):
            raise ValueError("cleanup receipt identity differs from the exact plan or worker")
        if timestamp(cleanup.completed_at) < timestamp(authorized_run.result.finished_at):
            raise ValueError("authenticated cleanup completed before the authorized result")
        observation_doc = dict(bundle["observation"])
        if set(observation_doc) != {item.name for item in dataclass_fields(LaboratoryCaseObservation)}:
            raise ValueError("signed observation fields are incomplete or unknown")
        observation_doc.pop("key_id", None)
        observation_doc.pop("signature", None)
        observation = LaboratoryCaseObservation(
            **observation_doc,
            key_id=bundle["observation"]["key_id"],
            signature=bundle["observation"]["signature"],
        )
        verify_worker_receipt(
            observation,
            trust_store=observation_trust_store,
            worker_identity=worker,
            after=authorized_run.result.started_at,
        )
        if (
            observation.environment_id != bundle["environment_id"]
            or observation.worker_identity != worker
            or observation.authorization_id != auth.authorization_id
            or observation.plan_digest != plan.plan_digest
            or observation.result_id != authorized_run.result.result_id
            or observation.result_finished_at != authorized_run.result.finished_at
        ):
            raise ValueError("signed observation does not bind the exact authorized result")
        if timestamp(cleanup.completed_at) > timestamp(observation.observed_at):
            raise ValueError("authenticated cleanup completed after the signed post-cleanup observation")
        journal = bundle["case_journal_record"]
        if not isinstance(journal, Mapping) or journal.get("result_id") != authorized_run.result.result_id:
            raise ValueError("exact case journal record is missing or mismatched")
        if set(journal) != {"attempt_id", "result_id", "environment_id", "state", "payload", "result"}:
            raise ValueError("case journal record fields are incomplete or unknown")
        if not isinstance(trusted_terminal_journal_record_digest, str) or not re.fullmatch(
            r"[a-f0-9]{64}", trusted_terminal_journal_record_digest
        ):
            raise ValueError("independently trusted terminal journal digest is required")
        if digest(dict(journal)) != trusted_terminal_journal_record_digest:
            raise ValueError("case journal record differs from the independently trusted terminal anchor")
        if journal.get("environment_id") != bundle["environment_id"]:
            raise ValueError("case journal environment identity changed")
        if journal.get("state") != "classified" or not isinstance(journal.get("result"), Mapping):
            raise ValueError("case journal record is not terminal")
        journal_result = journal["result"]
        expected_status = {"positive": "success", "negative": "rejected", "remediated": "remediated"}
        if (
            bundle["classification_status"] != expected_status.get(bundle["case_type"])
            or journal_result.get("case_type") != bundle["case_type"]
            or journal_result.get("status") != expected_status.get(bundle["case_type"])
            or journal_result.get("observed_case_type") != bundle["case_type"]
        ):
            raise ValueError("case journal does not record a successful matching classification")
        journal_payload = journal.get("payload")
        details = journal_result.get("details")
        evidence_records = details.get("durable_evidence") if isinstance(details, Mapping) else None
        payload_evidence = journal_payload.get("durable_evidence") if isinstance(journal_payload, Mapping) else None
        cleanup_refs = (
            [
                item
                for item in evidence_records or []
                if isinstance(item, Mapping) and item.get("kind") == "cleanup-receipt"
            ]
            if isinstance(evidence_records, list)
            else []
        )
        if evidence_store is None or not callable(getattr(evidence_store, "read_json", None)):
            raise ValueError("durable evidence store is required")
        durable_documents = [evidence_store.read_json(item) for item in evidence_records or []]
        pre_execution_documents = [
            document
            for reference, document in zip(evidence_records or [], durable_documents, strict=True)
            if isinstance(reference, Mapping) and reference.get("kind") == "pre-execution-observation"
        ]
        run_documents = [
            document
            for reference, document in zip(evidence_records or [], durable_documents, strict=True)
            if isinstance(reference, Mapping) and reference.get("kind") == "run-result"
        ]
        cleanup_documents = [
            document
            for reference, document in zip(evidence_records or [], durable_documents, strict=True)
            if isinstance(reference, Mapping) and reference.get("kind") == "cleanup-receipt"
        ]
        failures = []
        if not isinstance(journal_payload, Mapping):
            failures.append("payload mapping")
        if journal_payload.get("plan_digest") != plan.plan_digest:
            failures.append("plan digest")
        if journal_payload.get("plan_id") != plan.plan_id:
            failures.append("plan id")
        if journal_payload.get("authorization_id") != auth.authorization_id:
            failures.append("auth id")
        if journal_payload.get("case_type") != bundle["case_type"]:
            failures.append("case type")
        if journal_payload.get("dispatch_request_id") != exchange["request_id"]:
            failures.append("dispatch")
        if journal_payload.get("operator_pre_execution_observation") != details.get(
            "operator_pre_execution_observation"
        ):
            failures.append("pre detail")
        if not pre_execution_documents:
            failures.append("pre docs")
        if pre_execution_documents and pre_execution_documents[0] != journal_payload.get(
            "operator_pre_execution_observation"
        ):
            failures.append("pre doc match")
        if not isinstance(payload_evidence, list):
            failures.append("payload evidence")
        if not isinstance(evidence_records, list):
            failures.append("evidence records")
        if (
            isinstance(evidence_records, list)
            and isinstance(payload_evidence, list)
            and evidence_records[: len(payload_evidence)] != payload_evidence
        ):
            failures.append("evidence prefix")
        if not cleanup_refs:
            failures.append("cleanup refs")
        if cleanup_refs and journal_result.get("cleanup_receipt_digest") != cleanup_refs[-1].get("sha256"):
            failures.append("cleanup digest")
        if not run_documents:
            failures.append("run docs")
        if run_documents and run_documents[0] != authorized_run.to_dict():
            failures.append("run match")
        if not cleanup_documents:
            failures.append("cleanup docs")
        if cleanup_documents and cleanup_documents[-1].get("result_id") != authorized_run.result.result_id:
            failures.append("cleanup result")
        if cleanup_documents and cleanup_documents[-1].get("authorization_id") != auth.authorization_id:
            failures.append("cleanup auth")
        if cleanup_documents and cleanup_documents[-1].get("plan_digest") != plan.plan_digest:
            failures.append("cleanup plan")
        if cleanup_documents and cleanup_documents[-1].get("dispatch_request_id") != exchange["request_id"]:
            failures.append("cleanup dispatch")
        if cleanup_documents and cleanup_documents[-1].get("worker_cleanup_receipt") != cleanup.to_dict():
            failures.append("cleanup receipt")
        if cleanup_documents and cleanup_documents[-1].get("cleanup_status") != authorized_run.result.cleanup_status:
            failures.append("cleanup status")
        if details.get("operator_case_observation") != dict(bundle["observation"]):
            failures.append("case observation")
        if not journal.get("attempt_id"):
            failures.append("attempt")
        if (
            not isinstance(journal_result.get("run_result"), Mapping)
            or journal_result["run_result"] != authorized_run.result.to_dict()
        ):
            failures.append("journal run result")
        if journal.get("result_id") != authorized_run.result.result_id:
            failures.append("result id")
        if failures:
            raise ValueError("case journal binding mismatch: " + ", ".join(failures))
        if bundle.get("baseline_finding_id") != finding_id or bundle.get("asset_id") != asset_id:
            raise ValueError("execution evidence is not bound to the exact baseline finding and asset")
        journal_details = journal_result.get("details")
        if (
            not isinstance(journal_details, Mapping)
            or journal_details.get("baseline_finding_id") != finding_id
            or journal_details.get("asset_id") != asset_id
        ):
            raise ValueError("case journal is not bound to the exact baseline finding and asset")
        if bundle["case_type"] not in {"remediated", "positive", "negative"}:
            raise ValueError("laboratory case outcome is not reviewable")
        outcome = {
            "positive": "candidate_still_vulnerable",
            "negative": "blocked",
            "remediated": "candidate_fixed",
        }[bundle["case_type"]]
        return RetestReviewInput(
            finding_id,
            asset_id,
            outcome,
            plan.plan_id,
            plan.plan_digest,
            authorized_run.result.result_id,
            digest(dict(bundle)),
        )
    except RetestExecutionEvidenceError:
        raise
    except Exception as err:
        raise RetestExecutionEvidenceError("laboratory execution evidence verification failed") from err
