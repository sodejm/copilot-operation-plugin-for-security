# COPS Offensive Engagement Workbench: end-to-end verification

## Scope and prerequisites

Qualify offline engagement intake, scope/prerequisite checks, immutable action planning, specialist handoff, and offline model/effort advice. This workflow depends on the repository SDK; a valid proposal still requires execution approval.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info offensive-engagement-workbench
python3 -m cops demo offensive-engagement-workbench
python3 -m cops check offensive-engagement-workbench
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/offensive-security/offensive-engagement-workbench
COPS_ENGAGEMENT_RUN=$(mktemp -d)
python3 "$P/scripts/demo.py" --tool-version python3=3.11.9 \
  --output-dir "$COPS_ENGAGEMENT_RUN"
```

The tool version argument matches the synthetic fixture's pinned metadata;
record the actual Python version separately. Inspect the six files in
`$COPS_ENGAGEMENT_RUN`, including the approval-pending handoff and final result.
Independently inspect engagement scope, targets, tools/versions, limits, and
validity windows. Compare the plan and handoff with those facts. Repeat with a
sanitized engagement and independently prepared scope/prerequisite oracle.

Exercise the advisory workflow with synthetic catalogs. These fixtures test the
advisor's rules; they provide no evidence of real host availability or access.

```bash
COPS_MODEL_RUN=$(mktemp -d)
python3 - "$COPS_MODEL_RUN" <<'PY'
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

root = Path(sys.argv[1])
now = datetime.now(timezone.utc)
for case, age, access in (
    ("fresh", 0, "granted"),
    ("stale", 25, "granted"),
    ("denied", 0, "denied"),
):
    catalog = {
        "schema_version": "cops.model-catalog/v1",
        "source": "Synthetic qualification fixture",
        "observed_at": (now - timedelta(hours=age)).isoformat(),
        "models": [{
            "id": "qualification-model",
            "family": "Synthetic model",
            "tier": "flagship",
            "capabilities": ["security"],
            "available": True,
            "access": access,
            "efforts": ["high"],
            "preference": 0,
        }],
    }
    (root / f"{case}.json").write_text(json.dumps(catalog), encoding="utf-8")
PY
for COPS_MODEL_CASE in fresh stale denied; do
  python3 -m cops route "Review the issue's authorization boundary" \
    --task-kind security-review --suggest-model \
    --model-catalog "$COPS_MODEL_RUN/$COPS_MODEL_CASE.json" \
    --current-model qualification-model --current-effort high --json \
    > "$COPS_MODEL_RUN/$COPS_MODEL_CASE-advice.json"
done
python3 - "$COPS_MODEL_RUN" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
for case, status in (
    ("fresh", "suggested"),
    ("stale", "catalog_stale"),
    ("denied", "no_eligible_model"),
):
    result = json.loads((root / f"{case}-advice.json").read_text(encoding="utf-8"))
    advice = result["model_advice"]
    assert advice["advisory_only"] is True
    assert advice["status"] == status, advice
    if case == "fresh":
        assert advice["current"]["status"] == "adequate", advice
        assert advice["recommendation"]["model_id"] == "qualification-model"
        assert advice["recommendation"]["effort"] == "high"
    else:
        assert advice["recommendation"] is None, advice
    print(f"{case}: {status}")
PY
```

Inspect the saved advice against the three fixture inputs and retain sanitized
evidence before removing the temporary directory. A valid advisory result can
exit successfully with no eligible model; inspect its fields. See
[model routing](MODEL_ROUTING.md) for the catalog contract and real host discovery.

## Acceptance criteria

- Intake and handoff preserve engagement, specialist, action, target, time, tool/version, and evidence bindings.
- The action plan is immutable and its digest agrees across handoffs; valid planning remains approval-required. The playback runs only its local inert observation child and performs no planned assessment operation.
- Package tests reject missing tools, stale windows, scope expansion, incompatible prerequisites, and invalid approval/hash assumptions.
- Fresh eligible model advice matches the fixture's supported pair; stale and denied catalogs produce no recommendation. Advice remains advisory and supplies no execution approval or automatic model switch.
- Host installation resolves the repository SDK dependency explicitly. Offline success cannot establish worker readiness, signed approval, or live execution.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Repeat with a missing/mismatched tool version and out-of-scope target in private inputs; inspect the prerequisite/scope refusal with no dispatch. Restore the approved input and rerun. Confirm no external operation, target change, or credential creation occurred; retain sanitized plan/handoff evidence and remove private copies.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **engagement-intake-and-planning**, **engagement-specialist-handoffs**, and **model-effort-routing** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Build an offline action proposal and specialist handoff from this synthetic engagement. Verify scope, windows, tool versions, prerequisites, and plan digest. Keep execution approval pending and do not dispatch an operation.

For model advice, independently discover the host's current model IDs, access,
capabilities, supported efforts, and selected pair. Supply that fresh catalog to
the host skill and compare the advice with the CLI and the observed catalog.
Confirm that the host does not change settings or dispatch work automatically.
Record missing discovery/access evidence as blocked; synthetic catalogs alone
cannot pass this host criterion.

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
