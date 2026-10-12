# COPS Incident Response Sandbox: end-to-end verification

## Scope and prerequisites

Qualify fixture-only plan, dry-run, receipt binding, simulated containment, replay rejection, and recovery. The approver assertion is fixture provenance and grants no real containment authority.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info incident-response-sandbox
python3 -m cops demo incident-response-sandbox
python3 -m cops check incident-response-sandbox
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/incident-response/incident-response-sandbox
COPS_IR_RUN=$(mktemp -d)
cp "$P/fixtures/synthetic/fixture.json" "$COPS_IR_RUN/fixture.json"
chmod 600 "$COPS_IR_RUN/fixture.json"
COPS_IR_EXPIRY=$(python3 -c 'from datetime import UTC, datetime, timedelta; print((datetime.now(UTC) + timedelta(hours=1)).isoformat())')
python3 "$P/scripts/ir.py" plan --action isolate-host --tenant example-tenant --target host-1 --expires-at "$COPS_IR_EXPIRY" --nonce qualification-1 --approver-assertion fixture-operator > "$COPS_IR_RUN/plan.json"
python3 "$P/scripts/ir.py" dry-run "$COPS_IR_RUN/plan.json" "$COPS_IR_RUN/fixture.json" > "$COPS_IR_RUN/receipt.json"
python3 "$P/scripts/ir.py" execute "$COPS_IR_RUN/plan.json" "$COPS_IR_RUN/receipt.json" "$COPS_IR_RUN/fixture.json"
# Expected refusal: repeat the consumed execution; retain its nonzero exit code.
python3 "$P/scripts/ir.py" execute "$COPS_IR_RUN/plan.json" "$COPS_IR_RUN/receipt.json" "$COPS_IR_RUN/fixture.json"
```

Inspect the private fixture before and after dry-run, and after execute. The original package fixture must stay unchanged. Compare plan/receipt hashes, scope, expiry, revision, execution ledger, target state, and reported provenance. Repeat with a fresh fixture, nonce, and receipt.

## Acceptance criteria

- Dry-run is ready without mutating fixture state. Execute applies the permitted fixture action, advances its revision, and records a bound execution.
- Repeated execution fails because receipt/fixture state has changed; altered plan, expiry, tenant, target, or permission cannot reuse the receipt.
- Package tests cover partial failure with rollback, rollback failure, throttling, and unavailable verification. Inspect each expected state; unavailable verification cannot pass.
- Output identifies fixture execution and unverified operator assertions. No live account, host, or provider is changed.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Run the package recovery tests and inspect their fixture outcomes: partial failure restores the active state when rollback succeeds; rollback failure remains isolated with an explicit unresolved result. Verification-unavailable stays unverified. Never retry an uncertain live action based on this simulation. Preserve receipts and remove the private fixture/output directory.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **incident-response-sandbox** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> On a private copy of this synthetic fixture, create and dry-run an isolate-host plan, execute the bound receipt once, and verify replay refusal. Report fixture provenance, verification limits, and recovery outcomes. Perform no real containment.

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
