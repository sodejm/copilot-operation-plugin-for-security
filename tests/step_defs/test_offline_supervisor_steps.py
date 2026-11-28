"""Profile-selection scenarios; no deployed SSH or independent observer claim."""

import io
import json
from dataclasses import replace
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.contracts import ActionPlan
from cops.execution import WorkerExecutionError
from cops.remote_worker import SSH_EXECUTION_REQUEST_SCHEMA, SSH_PROTOCOL
from cops.worker_supervisor import WorkerSupervisorError
from tests.test_worker_supervisor import _test_receiver

scenarios("../../specs/features/offline_supervisor.feature")


@given("an owner-provisioned offline supervisor with signed test approval", target_fixture="supervisor_context")
def provisioned(tmp_path, monkeypatch):
    return _test_receiver(tmp_path, monkeypatch)


@when("the supervisor constructs its worker")
def constructed(supervisor_context):
    assert supervisor_context.receiver.worker is not None


@then("only the offline profile is required and no external capabilities are configured")
def offline_only(supervisor_context):
    worker = supervisor_context.receiver.worker
    assert worker.required_execution_profile == "offline-research/v1"
    assert worker.scope_guard is None
    assert worker.credential_resolver is None
    assert worker._egress_identity_verifier is None


@when("a relay request omits the offline profile")
def remove_profile(supervisor_context):
    snapshot = supervisor_context.plan.approved_snapshot()
    snapshot.pop("schema_version")
    snapshot.pop("offline_research")
    request = {
        "protocol": SSH_PROTOCOL, "request_id": "stripped-profile-test",
        "expected_host": supervisor_context.config.expected_host,
        "expected_worker_id": supervisor_context.config.worker_identity,
        "payload": {
            "schema_version": SSH_EXECUTION_REQUEST_SCHEMA,
            "action_plan": ActionPlan.create(**snapshot).to_dict(),
            "authorization_id": supervisor_context.authorization.authorization_id,
            "timeout_seconds": 30, "max_output_bytes": 4096, "exchange_nonce": "a" * 43,
        },
    }
    with pytest.raises(WorkerExecutionError, match="requires offline-research/v1"):
        supervisor_context.receiver.serve_one(io.BytesIO(json.dumps(request).encode() + b"\n"), io.BytesIO())


@then("the request is rejected before approval consumption")
def unconsumed(supervisor_context):
    assert supervisor_context.control.consume_calls == []
    assert supervisor_context.store.get_authorization(supervisor_context.authorization.authorization_id).status == "approved"


@when("offline configuration includes credentials or egress", target_fixture="configuration_rejections")
def external_config(supervisor_context):
    for options in ({"credential_manifest_path": Path("/unused/manifest.json")}, {"egress_trust_domain": "example.test"}):
        with pytest.raises(WorkerSupervisorError, match="cannot configure credentials or egress"):
            replace(supervisor_context.config, **options)
    return 2


@then("every conflicting configuration is rejected")
def rejected(configuration_rejections):
    assert configuration_rejections == 2
