"""Loopback acceptance wiring with explicit authority and sandbox doubles.

The real worker, replay child, broker, and mediator execute; this helper does not
qualify the host's production sandbox.
"""

import subprocess

from cops.evidence.canonical import digest
from cops.execution.credentials import CredentialGrant
from cops.execution.process import BoundedProcessResult
from tests.test_adapter_execution import _approval_control, _sandbox
from tests.test_web_api_worker_integration import _configured_worker


def loopback_worker(tmp_path, monkeypatch, plan, scope_guard, credentials=None):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    credentials = credentials or {}
    grants = []
    for index, operation in enumerate(plan.to_dict()["operations"]):
        for binding in operation["arguments"]["envelope"]["credential_references"]:
            grants.append(CredentialGrant(
                reference=binding["reference"], environment_variable="COPS_CREDENTIAL_TEST",
                plan_id=plan.plan_id, plan_digest=plan.plan_digest, engagement_id=plan.engagement_id,
                worker_identity="test-worker-01", target=plan.target, step_id=operation["step_id"],
                tool=operation["tool"], tool_version=operation["tool_version"], action=operation["action"],
                operation_index=index, operation_digest=digest(operation),
            ))

    class Provider:
        def resolve(self, reference):
            return credentials[reference]

    worker, authorization_id = _configured_worker(
        tmp_path, monkeypatch, plan, credential_provider=Provider() if grants else None,
        credential_grants=grants,
    )
    worker.scope_guard = scope_guard

    def run_child(command, **kwargs):
        completed = subprocess.run(
            command, env={**kwargs["env"], **kwargs["operation_env"]},
            pass_fds=kwargs["capability_fds"], capture_output=True,
            timeout=kwargs["timeout_seconds"], check=False,
        )
        return BoundedProcessResult(
            stdout=completed.stdout, stderr=completed.stderr, returncode=completed.returncode,
            timed_out=False, output_limit_exceeded=False,
        )

    _sandbox(worker).run_callback = run_child
    return worker, authorization_id, _approval_control(worker)
