"""Interactive and envelope-based authorization engine for COPS security operations.

Ensures that high-consequence, offensive, or destructive actions (such as penetration testing,
red team kill-chain emulation, and incident response containment) require verified,
tamper-evident operator consent before execution.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from cops.evidence.canonical import canonical, digest, utc_now


class AuthorizationError(ValueError):
    """Base error for operational authorization failures."""


class AuthorizationRequiredError(AuthorizationError):
    """Operation requires explicit authorization but none was supplied or confirmed."""


class AuthorizationDeniedError(AuthorizationError):
    """Operator explicitly denied or aborted the authorization request."""


@dataclass(frozen=True)
class AuthorizationReceipt:
    """Tamper-evident authorization receipt certifying human operator consent."""

    schema_version: str
    receipt_id: str
    timestamp_utc: str
    operator: str
    specialist_id: str
    action_type: str
    target_scope: tuple[str, ...]
    allowed_operations: tuple[str, ...]
    authorized_until_utc: str
    approval_mode: str
    verification_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "timestamp_utc": self.timestamp_utc,
            "operator": self.operator,
            "specialist_id": self.specialist_id,
            "action_type": self.action_type,
            "target_scope": list(self.target_scope),
            "allowed_operations": list(self.allowed_operations),
            "authorized_until_utc": self.authorized_until_utc,
            "approval_mode": self.approval_mode,
            "verification_hash": self.verification_hash,
        }


def _compute_receipt_hash(payload: dict[str, Any]) -> str:
    """Compute verification hash excluding the verification_hash and receipt_id fields."""
    data = {k: v for k, v in payload.items() if k not in {"verification_hash", "receipt_id"}}
    return digest(data)


def create_authorization_receipt(
    *,
    operator: str,
    specialist_id: str,
    action_type: str,
    target_scope: Sequence[str],
    allowed_operations: Sequence[str],
    valid_hours: int = 4,
    approval_mode: str = "interactive_confirmation",
) -> AuthorizationReceipt:
    """Create and sign a new authorization receipt."""
    if not target_scope:
        raise AuthorizationError("target_scope must contain at least one target")
    if not allowed_operations:
        raise AuthorizationError("allowed_operations must contain at least one operation")
    if approval_mode not in {"interactive_confirmation", "pre_signed_envelope"}:
        raise AuthorizationError(f"invalid approval_mode: {approval_mode}")

    now = datetime.now(timezone.utc)
    timestamp_str = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    expiry_str = (now + timedelta(hours=valid_hours)).isoformat(timespec="seconds").replace("+00:00", "Z")

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "timestamp_utc": timestamp_str,
        "operator": operator,
        "specialist_id": specialist_id,
        "action_type": action_type,
        "target_scope": sorted(target_scope),
        "allowed_operations": sorted(allowed_operations),
        "authorized_until_utc": expiry_str,
        "approval_mode": approval_mode,
    }
    verification_hash = _compute_receipt_hash(payload)
    receipt_id = hashlib.sha256(f"{verification_hash}:{timestamp_str}".encode("utf-8")).hexdigest()[:24]

    return AuthorizationReceipt(
        schema_version="1.0",
        receipt_id=receipt_id,
        timestamp_utc=timestamp_str,
        operator=operator,
        specialist_id=specialist_id,
        action_type=action_type,
        target_scope=tuple(sorted(target_scope)),
        allowed_operations=tuple(sorted(allowed_operations)),
        authorized_until_utc=expiry_str,
        approval_mode=approval_mode,
        verification_hash=verification_hash,
    )


def validate_receipt_document(document: dict[str, Any]) -> AuthorizationReceipt:
    """Validate an existing receipt document against cryptographic hash and expiration."""
    required = {
        "schema_version",
        "receipt_id",
        "timestamp_utc",
        "operator",
        "specialist_id",
        "action_type",
        "target_scope",
        "allowed_operations",
        "authorized_until_utc",
        "approval_mode",
        "verification_hash",
    }
    missing = required - set(document)
    if missing:
        raise AuthorizationError(f"authorization receipt missing required fields: {sorted(missing)}")

    expected_hash = _compute_receipt_hash(document)
    actual_hash = document["verification_hash"]
    if actual_hash != expected_hash:
        raise AuthorizationError("authorization receipt cryptographic verification hash mismatch (tampered)")

    try:
        expiry = datetime.fromisoformat(document["authorized_until_utc"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if now > expiry:
            raise AuthorizationError(f"authorization receipt expired at {document['authorized_until_utc']}")
    except ValueError as err:
        raise AuthorizationError("invalid expiration timestamp in authorization receipt") from err

    return AuthorizationReceipt(
        schema_version=document["schema_version"],
        receipt_id=document["receipt_id"],
        timestamp_utc=document["timestamp_utc"],
        operator=document["operator"],
        specialist_id=document["specialist_id"],
        action_type=document["action_type"],
        target_scope=tuple(document["target_scope"]),
        allowed_operations=tuple(document["allowed_operations"]),
        authorized_until_utc=document["authorized_until_utc"],
        approval_mode=document["approval_mode"],
        verification_hash=actual_hash,
    )


def request_interactive_authorization(
    *,
    specialist_id: str,
    action_type: str,
    target_scope: Sequence[str],
    allowed_operations: Sequence[str],
    valid_hours: int = 4,
    input_func: Callable[[str], str] | None = None,
    output_stream: Any = sys.stdout,
) -> AuthorizationReceipt:
    """Prompt the operator interactively for explicit authorization."""
    if input_func is None:
        # Check if stdin is an interactive terminal
        if not sys.stdin.isatty():
            raise AuthorizationRequiredError(
                f"Interactive authorization required for {specialist_id} ({action_type}), "
                "but standard input is not a terminal. Provide a pre-signed receipt."
            )
        input_func = input

    try:
        current_user = getpass.getuser()
    except Exception:
        current_user = os.environ.get("USER", "unknown-operator")

    banner = [
        "\n" + "=" * 65,
        "  [!] COPS OPERATIONAL AUTHORIZATION GATE REQUIRED",
        "=" * 65,
        f"  Specialist Profile : {specialist_id}",
        f"  Action / Operation : {action_type}",
        f"  Target Scope       : {', '.join(target_scope)}",
        f"  Allowed Operations : {', '.join(allowed_operations)}",
        f"  Authorization TTL  : {valid_hours} hour(s)",
        f"  Requesting User    : {current_user}",
        "=" * 65,
        "  CRITICAL: This operation involves sensitive or offensive security actions.",
        "  Type 'APPROVE' to confirm authorization, or anything else to abort.",
        "-" * 65,
    ]
    print("\n".join(banner), file=output_stream, flush=True)

    response = input_func("Enter confirmation [APPROVE/abort]: ").strip()
    if response != "APPROVE":
        raise AuthorizationDeniedError(
            f"Authorization for {specialist_id} ({action_type}) was aborted by operator (received '{response}')."
        )

    receipt = create_authorization_receipt(
        operator=current_user,
        specialist_id=specialist_id,
        action_type=action_type,
        target_scope=target_scope,
        allowed_operations=allowed_operations,
        valid_hours=valid_hours,
        approval_mode="interactive_confirmation",
    )
    print(f"  [+] Authorization granted: Receipt ID {receipt.receipt_id}", file=output_stream, flush=True)
    print(f"  [+] Verification Hash: {receipt.verification_hash}\n", file=output_stream, flush=True)
    return receipt


def ensure_authorization(
    *,
    specialist_id: str,
    action_type: str,
    target_scope: Sequence[str],
    allowed_operations: Sequence[str],
    receipt_path: Path | None = None,
    interactive: bool = True,
    input_func: Callable[[str], str] | None = None,
) -> AuthorizationReceipt:
    """Ensure valid authorization exists, checking receipts first or prompting interactively."""
    if receipt_path is not None and receipt_path.is_file():
        try:
            document = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt = validate_receipt_document(document)
            # Verify that receipt matches the requested action and specialist
            if receipt.specialist_id != specialist_id:
                raise AuthorizationError(
                    f"receipt specialist mismatch: expected {specialist_id}, found {receipt.specialist_id}"
                )
            return receipt
        except (json.JSONDecodeError, AuthorizationError) as err:
            raise AuthorizationError(f"failed to validate receipt at {receipt_path}: {err}") from err

    if interactive:
        return request_interactive_authorization(
            specialist_id=specialist_id,
            action_type=action_type,
            target_scope=target_scope,
            allowed_operations=allowed_operations,
            input_func=input_func,
        )

    raise AuthorizationRequiredError(
        f"Authorization required for {specialist_id} ({action_type}), but no valid receipt provided "
        "and interactive mode is disabled."
    )
