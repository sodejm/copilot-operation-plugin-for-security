# COPS Microsoft Foundry Adversarial Agent Review Harness: end-to-end verification

## Scope and prerequisites

Qualify local scenario loading, mock agent review, independent authorization-gate behavior, local laboratory receipts, and offline provider-fixture normalization. Fixture results do not attest a hosted model, provider service, Foundry service, OS isolation, or network denial.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python -m venv .venv
if [[ -f .venv/Scripts/activate ]]; then
  source .venv/Scripts/activate
else
  source .venv/bin/activate
fi
python -m cops info foundry-agent-harness
python -m cops demo foundry-agent-harness
python -m cops check foundry-agent-harness
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/offensive-security/foundry-agent-harness
COPS_FOUNDRY_RUN=$(mktemp -d)
python "$P/foundryharness/cli.py" list --scenarios-dir "$P/scenarios"
python "$P/foundryharness/cli.py" evaluate --scenarios-dir "$P/scenarios" --json --output "$COPS_FOUNDRY_RUN/scenarios.json"
python "$P/foundryharness/cli.py" lab --json --output "$COPS_FOUNDRY_RUN/lab.json"
python "$P/scripts/run_provider_assessment.py" > "$COPS_FOUNDRY_RUN/providers.json"
```

Inventory the scenario, laboratory case, and provider fixture files before loading them. Compare loaded IDs/counts, expected denials, observed mock effects, normalized provider states, budget results, and cleanup receipts with the files. Repeat with bounded synthetic copies whose required refusal and allowed effect an independent reviewer has specified.

## Delegation authorization batch (#236)

The legacy `evaluate` and `lab` commands above do not exercise the signed,
two-tenant delegation workflow. Follow the [delegation authorization playbook](PLAYBOOK.md#run-and-inspect-delegation-authorization)
to build and inspect one immutable plan, issue one signed COPS assessment
authorization, and run the selected batch unattended with `auth-lab`. The
approval authorizes the assessment run only; the target fixture independently
requires its synthetic grant. No per-case approval is expected. This fixed local
fixture is not the full plain-language coordinator or durable crash-resume path
tracked by issue #283.

Before the run, compare the plan's selected case IDs, tool inventory, fixture
hashes, identities, and aggregate limits with the checked-in cases. Keep the
plan, signed receipt, trust store, approval database, and report in private
storage. After the run, reconcile every planned case and attempt against the
report; require both positive delegated controls, cross-tenant denials in both
directions, and zero independently observed effects for each hostile peer
probe. Inspect `assessment_authorization`, `observations` (peer and target),
`observed_effects`, `cleanup`, `evidence_complete`, `security_pass`,
`pending_case_ids`, `recovery_actions`, and `next_action`. Missing identity or
effect telemetry, unavailable observation, unsupported behavior, failed setup,
or failed cleanup is inconclusive even when the declared expectation matches.
Follow all recovery actions before authorizing a new run; a consumed receipt is
not retryable, and an uncertain external effect must be reconciled first.

Exercise `lost_response_after_effect` with an allowed write followed by another
case. Confirm the independent ledger retains the write, the batch stops, the
interrupted and unstarted cases remain pending, and the consumed receipt cannot
be replayed. Reconcile the uncertain effect before approving a new plan.

Record the exact command, revision, Python and OS versions, plan and case
digests, case-by-case outcomes, independent effect observations, and cleanup
result in the private run record. The fixture covers the legacy MCP
`initialize` handshake and exact capability/tool descriptors over local
synthetic stdio only. It rejects a paginated tool inventory rather than
assuming the first page is complete. The pinned server name and version are
advertised metadata, not cryptographic peer authentication. Do not infer remote
HTTP, OAuth, hosted-provider, cross-provider interoperability, current
per-request metadata, Windows runtime, or OS-enforced network-isolation
support from this exercise.

## Acceptance criteria

- Every intended scenario is loaded; warnings/skipped malformed files are coverage gaps even when the command exits zero.
- Expected unauthorized calls are denied by the independent gate, and allowed mock effects match the scenario contract.
- All required laboratory expectations and cleanup receipts pass, with failures represented explicitly. Local subprocess fixtures cannot certify host/network isolation.
- The #236 authorization batch reconciles every planned case and attempt, its two-tenant controls, all four hostile peer probes, independent effects, and cleanup. It passes only when each result has complete evidence and `security_pass` is true; otherwise report the exact inconclusive or failed cases.
- The provider report contains all 14 bundled cases under deterministic SHA-256 references from `report_case_id`, with no source case IDs. The four provider-family success cases settle as `completed`; exact endpoint, tenant/account, model, tool, canary, and request mismatches are denied before response processing; the AWS tool case remains a `tool_proposal`; the partial case records `no_effect`, `unknown` usage, and `usage_unknown`; and the final budget case is denied before response processing.
- Authorized and budget-admitted responses must pass their strict provider-specific envelope schema before normalization. Malformed, unknown-field, cross-provider, unsupported-status, inconsistent AWS tool-use, unrequested tool proposals, invalid usage counts, and output token counts above the approved request cap fail the assessment. Denied and budget-refused cases remain `not_processed` regardless of their response content.
- Provider `all_expectations_met` and temporary-ledger `cleanup_verified` are true, and `budget.over_budget` is false. A deliberately over-budget completed report exits nonzero while retaining the budget and cleanup evidence. The report contains only the schema fields documented in `specs/ai-provider-assessment.spec.md`; it contains no response text, prompt, source case ID, endpoint URL, account identifier, canary value, or credential.
- Package tests cover authorization misuse, malformed scenarios, laboratory failure, cleanup, provider binding and parsing, budget denial, tool proposals, and conservative partial responses. No provider or model result is inferred from synthetic output.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Place a malformed scenario in a private scenario-directory copy; inspect the warning and reconcile the inventory. Run the laboratory failure/cleanup cases in the package gate and inspect their expected receipts. In reviewed private provider-fixture copies, exercise a binding mismatch and confirm denial without envelope processing; then use an admitted case to exercise a malformed or cross-provider response envelope and confirm assessment failure before normalization. Exercise an admitted receipt that exceeds the aggregate budget and confirm the report is emitted, `budget.over_budget` is true, cleanup is recorded, and the command exits nonzero. Correct the copies, rerun in a fresh output directory, and confirm no child process or run-owned resource remains.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **foundry-agent-review**, **ai-agent-mcp-laboratories**, and **ai-provider-assessment** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Review and run the local mock scenarios, laboratory fixtures, and provider-shaped response fixtures. Reconcile the loaded inventory, authorization denials, normalized outcomes, expected effects, budget states, and cleanup receipts. Explain any gaps without claiming Foundry, model, provider, billing, or OS isolation validation.

Check discovery, referenced-file/script resolution, output against the CLI and
independent oracle, refusal/uncertainty behavior, and test-installation cleanup.
Record unavailable hosts as blocked and failed installation/invocation as failed.
The host exercise itself supplies no live-service or offensive-action authority.

## Record and promote

Follow [the shared qualification and status-update guide](https://sodejm.github.io/copilot-operation-plugin-for-security/plugin-verification.html)
to save a sanitized run record, apply every intervening maturity gate, and request
independent review. After acceptance, update package.json maturity and all public
status labels together, link the accepted record here and in the README, and run
the repository checks. Keep unsupported integrations and remaining gaps explicit.
No status changes automatically when these commands finish.
