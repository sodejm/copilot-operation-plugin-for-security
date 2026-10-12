# COPS SOC Investigation Workbench: end-to-end verification

## Scope and prerequisites

Qualify offline intake, case progression, result imports, review, and evidence handoff. Vendor integrations remain pending where declared; the offline result does not attest Sentinel, Splunk, or M365 execution.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info soc-investigation-workbench
python3 -m cops demo soc-investigation-workbench
python3 -m cops check soc-investigation-workbench
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/detection-hunting/soc-investigation-workbench
COPS_SOC_RUN=$(mktemp -d)
python3 "$P/scripts/investigate.py" intake --case-id incident-402 --tenant tenant-a --workspace workspace-a --start 2026-01-01T00:00:00Z --end 2026-01-02T00:00:00Z --sources sentinel:"$P/examples/intake/sentinel-incidents.json" splunk:"$P/examples/intake/splunk-events.json" entra:"$P/examples/intake/entra-signins.json" --out "$COPS_SOC_RUN/intake.json"
python3 "$P/scripts/investigate.py" next "$P/examples/case.json"
python3 "$P/scripts/investigate.py" import "$P/examples/case.json" "$P/examples/signin-result.json" --out "$COPS_SOC_RUN/case-01.json"
python3 "$P/scripts/investigate.py" import "$COPS_SOC_RUN/case-01.json" "$P/examples/consent-result.json" --out "$COPS_SOC_RUN/case-02.json"
python3 "$P/scripts/investigate.py" import "$COPS_SOC_RUN/case-02.json" "$P/examples/mailbox-gap.json" --out "$COPS_SOC_RUN/case-03.json"
python3 "$P/scripts/investigate.py" report "$COPS_SOC_RUN/case-03.json"
python3 "$P/scripts/investigate.py" export-handoff "$COPS_SOC_RUN/case-03.json" --out-dir "$COPS_SOC_RUN/handoff"
python3 "$P/scripts/m365-offline-demo.py"
```

Compare the normalized intake with all three source fixtures. Follow the imported case through the report and handoff artifacts. Repeat on a sanitized case with an independently specified timeline, evidence references, hypotheses, and known gaps.

## Acceptance criteria

- Tenant, workspace, time window, case revision, and evidence digests remain bound across intake, imports, report, and handoff.
- The mailbox gap remains a gap. The next-step proposal and report distinguish observations, hypotheses, and unperformed collection.
- Package checks reject tenant/workspace drift, missing proof, invalid revisions/digests, unsafe output, and duplicate handoff destinations. Inspect redaction results and expected refusals, not just the final exit code.
- Vendor-pending validation is recorded as pending vendor evidence. It cannot satisfy an advertised live workflow.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Try exporting again to the same handoff destination; expect refusal without overwriting prior evidence. Preserve the first bundle and retry in a fresh destination. Confirm source fixtures did not change, no provider call occurred, and only the private output directory was created.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **soc-investigation-planning and soc-investigation-review** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Continue the supplied offline case using the example results, preserving tenant, workspace, revision, and evidence bindings. Produce an investigation report and handoff, retain the mailbox evidence gap, and propose the next authorized collection step without executing it.

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
