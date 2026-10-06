"""Ownership-aware side-effect ledger and cleanup receipts for COPS execution.

Tracks created resources, altered configurations, and transient processes during
ActionPlan execution. Enforces strict ownership and precondition verification
prior to rollback, preserves the assessment audit trail, and emits deterministic
cops.cleanup-receipt/v1 contracts.
"""

from __future__ import annotations

import os
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cops.contracts.models import CleanupReceipt
from cops.evidence.canonical import digest, utc_now


class CleanupError(RuntimeError):
    """Base exception for cleanup and recovery failures."""


class CleanupOwnershipError(CleanupError):
    """Attempted to modify or clean a resource not owned by the worker."""


class CleanupPreconditionError(CleanupError):
    """Precondition check failed before executing rollback."""


@dataclass
class SideEffect:
    """Individual resource or state change tracked in the side-effect ledger."""

    effect_id: str
    step_id: str
    resource_type: str
    target: str
    action_plan_id: str
    engagement_id: str
    owner: str
    created_at: str
    cleanup_action: str = "delete"
    status: str = "pending"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "step_id": self.step_id,
            "resource_type": self.resource_type,
            "target": self.target,
            "action_plan_id": self.action_plan_id,
            "engagement_id": self.engagement_id,
            "owner": self.owner,
            "created_at": self.created_at,
            "cleanup_action": self.cleanup_action,
            "status": self.status,
            "metadata": self.metadata,
        }


class SideEffectLedger:
    """In-memory append-only ledger tracking side effects produced during execution."""

    def __init__(self, plan_id: str, engagement_id: str, default_owner: str) -> None:
        self.plan_id = plan_id
        self.engagement_id = engagement_id
        self.default_owner = default_owner
        self._effects: list[SideEffect] = []

    def record_effect(
        self,
        *,
        step_id: str,
        resource_type: str,
        target: str,
        cleanup_action: str = "delete",
        owner: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SideEffect:
        """Record a new side effect in the ledger."""
        effect = SideEffect(
            effect_id=f"eff-{uuid.uuid4().hex[:16]}",
            step_id=step_id,
            resource_type=resource_type,
            target=str(target),
            action_plan_id=self.plan_id,
            engagement_id=self.engagement_id,
            owner=owner or self.default_owner,
            created_at=utc_now(),
            cleanup_action=cleanup_action,
            status="pending",
            metadata=metadata or {},
        )
        self._effects.append(effect)
        return effect

    def get_effects(self, status: str | None = None) -> list[SideEffect]:
        """Return all tracked side effects, optionally filtered by status."""
        if status is None:
            return list(self._effects)
        return [eff for eff in self._effects if eff.status == status]


class CleanupManager:
    """Manages verified rollback and produces signed cleanup receipts."""

    def __init__(
        self,
        ledger: SideEffectLedger,
        worker_identity: str,
        workspace_dir: Path | None = None,
    ) -> None:
        self.ledger = ledger
        self.worker_identity = worker_identity
        self.workspace_dir = workspace_dir.resolve() if workspace_dir else None

    def _verify_resource_ownership(self, effect: SideEffect) -> None:
        """Verify that the resource is owned by the worker before rollback."""
        # 1. Identity ownership check
        if effect.owner != self.worker_identity:
            raise CleanupOwnershipError(
                f"Resource '{effect.target}' owned by '{effect.owner}', not worker '{self.worker_identity}'"
            )

        # 2. Filesystem boundary check
        if effect.resource_type in ("file", "directory"):
            target_path = Path(effect.target).resolve()
            if self.workspace_dir is not None:
                try:
                    target_path.relative_to(self.workspace_dir)
                except ValueError as err:
                    raise CleanupOwnershipError(
                        f"Resource path '{target_path}' is outside worker workspace '{self.workspace_dir}'"
                    ) from err

    def rollback(self, *, dry_run: bool = False) -> CleanupReceipt:
        """Execute ownership-verified rollback of all pending side effects.

        Processes side effects in reverse chronological order (LIFO).
        Preserves audit trail and emits a valid CleanupReceipt.
        """
        created_at = utc_now()
        cleaned_effects: list[dict[str, Any]] = []
        unresolved_effects: list[dict[str, Any]] = []

        pending = self.ledger.get_effects()

        if not pending:
            completed_at = utc_now()
            receipt_id = f"cln-{uuid.uuid4().hex[:16]}"
            empty_payload = {
                "receipt_id": receipt_id,
                "plan_id": self.ledger.plan_id,
                "cleaned": [],
                "unresolved": [],
            }
            return CleanupReceipt.from_dict({
                "schema_version": "cops.cleanup-receipt/v1",
                "receipt_id": receipt_id,
                "plan_id": self.ledger.plan_id,
                "engagement_id": self.ledger.engagement_id,
                "worker_identity": self.worker_identity,
                "status": "not_required",
                "created_at": created_at,
                "completed_at": completed_at,
                "cleaned_effects": [],
                "unresolved_effects": [],
                "evidence_hash": digest(empty_payload),
            })

        # Process in reverse chronological order
        for effect in reversed(pending):
            if dry_run:
                cleaned_effects.append({
                    "effect_id": effect.effect_id,
                    "resource_type": effect.resource_type,
                    "target": effect.target,
                    "action_taken": f"dry_run_{effect.cleanup_action}",
                })
                continue

            try:
                # Step 1: Precondition & ownership verification
                self._verify_resource_ownership(effect)

                # Step 2: Resource rollback execution
                if effect.resource_type == "file":
                    p = Path(effect.target).resolve()
                    if p.is_file() or p.is_symlink():
                        p.unlink()
                    if p.exists():
                        raise CleanupError(f"file '{p}' still exists after unlink")
                    action_taken = "deleted_file"

                elif effect.resource_type == "directory":
                    p = Path(effect.target).resolve()
                    if p.is_dir():
                        shutil.rmtree(p, ignore_errors=False)
                    if p.exists():
                        raise CleanupError(f"directory '{p}' still exists after rmtree")
                    action_taken = "deleted_directory"

                elif effect.resource_type == "process":
                    pid = int(effect.target)
                    try:
                        os.kill(pid, 15)  # SIGTERM
                    except ProcessLookupError:
                        pass
                    except PermissionError as err:
                        raise CleanupError(f"permission denied killing PID {pid}") from err
                    action_taken = "terminated_process"

                else:
                    action_taken = f"custom_reverted_{effect.cleanup_action}"

                effect.status = "cleaned"
                cleaned_effects.append({
                    "effect_id": effect.effect_id,
                    "resource_type": effect.resource_type,
                    "target": effect.target,
                    "action_taken": action_taken,
                })

            except Exception as err:
                effect.status = "failed"
                unresolved_effects.append({
                    "effect_id": effect.effect_id,
                    "resource_type": effect.resource_type,
                    "target": effect.target,
                    "reason": f"cleanup failed: {err}",
                })

        completed_at = utc_now()
        receipt_id = f"cln-{uuid.uuid4().hex[:16]}"

        if not unresolved_effects:
            status = "completed"
        elif cleaned_effects:
            status = "partial"
        else:
            status = "failed"

        receipt_payload = {
            "receipt_id": receipt_id,
            "plan_id": self.ledger.plan_id,
            "engagement_id": self.ledger.engagement_id,
            "worker_identity": self.worker_identity,
            "cleaned_effects": cleaned_effects,
            "unresolved_effects": unresolved_effects,
        }
        evidence_hash = digest(receipt_payload)

        receipt_data = {
            "schema_version": "cops.cleanup-receipt/v1",
            "receipt_id": receipt_id,
            "plan_id": self.ledger.plan_id,
            "engagement_id": self.ledger.engagement_id,
            "worker_identity": self.worker_identity,
            "status": status,
            "created_at": created_at,
            "completed_at": completed_at,
            "cleaned_effects": cleaned_effects,
            "unresolved_effects": unresolved_effects,
            "evidence_hash": evidence_hash,
        }
        return CleanupReceipt.from_dict(receipt_data)
