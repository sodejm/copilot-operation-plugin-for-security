# COPS Kubernetes Assessment Workbench: end-to-end verification

## Scope and prerequisites

Qualify offline Kubernetes context and namespace authorization assessment. Imported cluster information does not establish current cluster state, connectivity, or permission to use kubectl.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info kubernetes-assessment-workbench
python3 -m cops demo kubernetes-assessment-workbench
python3 -m cops check kubernetes-assessment-workbench
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/offensive-security/kubernetes-assessment-workbench
python3 "$P/scripts/assess.py" "$P/fixtures/synthetic/context.json"
```

Independently inventory the fixture's cluster identity, observed namespaces, approved namespaces, and evidence gaps. Compare the assessment with that inventory. Repeat with a sanitized exported context and an independently approved namespace list.

## Acceptance criteria

- The assessment preserves cluster identity/UID and distinguishes observed scope from authorized scope.
- Out-of-scope namespaces and missing authorization are blocked or explicitly unassessed; partial imports remain partial.
- Package tests reject malformed context and exercise scope and cluster-identity mismatches. No ambient kubeconfig/context silently supplies missing authority.
- Output recommendations are tied to supplied evidence and do not claim a live cluster assessment or successful kubectl command.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Alter namespace authorization and cluster identity only in private fixture copies, then inspect the rejection/partial result. Return to the original input and rerun. Confirm kubeconfig, source data, and cluster resources were untouched; remove private copies and output after preserving evidence.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **kubernetes-assessment-context** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Assess the supplied offline Kubernetes context against the approved namespace scope. Report cluster-identity mismatches, unassessed namespaces, and evidence gaps. Do not select an ambient context or contact a cluster.

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
