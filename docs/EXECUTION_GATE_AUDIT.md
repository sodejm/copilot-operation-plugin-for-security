# Execution gate audit for provider assessment

This audit covers the repository contracts for closed issues [#82–#87](https://github.com/sodejm/copilot-operation-plugin-for-security/issues/82) and the [#90 provider laboratory](https://github.com/sodejm/copilot-operation-plugin-for-security/issues/90). It is source and local test evidence for the gateway emulator phase. It does not establish that a particular production worker, authority service, gateway, or cloud account has been deployed securely.

| Gate | Repository evidence reviewed | Deployment evidence still required |
| --- | --- | --- |
| #82 one-use approval | `tests/test_execution_authorization.py` covers plan and worker binding, expiry, revocation, and replay rejection. | Independent authority identity, key custody, and atomic approval consumption on the intended host. |
| #83 worker isolation and SSH | `tests/test_ssh_execution.py`, `tests/test_isolated_worker.py`, and `tests/test_worker_supervisor.py` cover pinned SSH host identity and sandbox readiness. | Host key provisioning, separate relay and worker accounts, measured isolation, and worker process identity. |
| #84 exact scope and egress | `tests/test_execution_egress_policy.py`, `tests/test_execution_worker_egress.py`, and `tests/test_execution_egress.py` cover target allowlists, authenticated destination identity, DNS and peer checks, and bounded mediation. | The deployed network policy, trust domain, gateway certificate identity, and denial of direct provider egress. |
| #85 pinned typed adapters | `tests/test_adapter_registry.py` and `tests/test_adapter_execution.py` cover adapter registration, executable pins, and action compatibility. | The exact installed executable hashes and supported host inventory. |
| #86 scoped credentials and redaction | `tests/test_scoped_credentials.py`, `tests/test_credential_evidence.py`, and `tests/test_supervisor_credential_provider.py` cover operation binding, credential delivery, and evidence redaction. | Separate gateway credential ownership, cloud account or project scope, key rotation, and log redaction. |
| #87 cancellation and cleanup | `tests/test_cleanup_recovery.py` and `tests/test_isolated_worker.py` cover cancellation and journal recovery. | Observed provider-side cancellation, retained resource cleanup, and reconciliation of uncertain attempts. |
| #90 laboratory | `tests/test_provider_assessment.py` and `tests/test_assessment_budget.py` cover offline provider fixtures, budget admission, malformed responses, uncertain usage, and report redaction. | A controlled emulator and gateway deployment for the exact revision before a real canary. |

No existing gate defect was demonstrated by this audit's source review and focused local tests. The regression test added by this audit verifies that the v1 broker rejects a direct provider POST before DNS resolution or connection. Provider gateway dispatch is a separate implementation. These tests do not close the operational gate: a real canary still needs an engagement-specific authorization, approved request digest and budget, independent production worker and gateway evidence, credential and residency review, billing reconciliation, and exact-revision security review.

The audit's focused suite ran under Python 3.11.17 in a virtual environment:

```bash
python -m pytest -q \
  tests/test_execution_authorization.py tests/test_ssh_execution.py \
  tests/test_isolated_worker.py tests/test_worker_supervisor.py \
  tests/test_execution_egress_policy.py tests/test_execution_worker_egress.py \
  tests/test_execution_egress.py tests/test_adapter_registry.py \
  tests/test_adapter_execution.py tests/test_scoped_credentials.py \
  tests/test_credential_evidence.py tests/test_supervisor_credential_provider.py \
  tests/test_cleanup_recovery.py tests/test_provider_assessment.py \
  tests/test_assessment_budget.py
```

The command exited successfully with six skips. Those skips and the absence of a deployed worker or gateway limit this finding to the repository contracts tested here.
