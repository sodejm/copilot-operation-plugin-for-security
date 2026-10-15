# COPS Host Assessment Workbench: end-to-end verification

## Scope and prerequisites

Qualify two distinct paths:

- deterministic Linux and Windows classification from synthetic or sanitized
  operator exports; and
- the bounded native Windows collector, bridge import, and assessment-owned
  lifecycle cleanup receipt.

An offline canary assertion remains source-reported. The native lifecycle canary
proves only that the collector created and removed its own harmless marker. It
does not cross a privilege boundary.

Use a trusted repository checkout and Python 3.11 or newer. The native exercise
also requires Windows PowerShell or PowerShell 7 on a disposable or otherwise
authorized Windows host. Record the repository revision, Windows build,
architecture, Python and PowerShell versions, export digest, and receipt result.
Keep operator evidence private.

## Baseline checks

```bash
python3 -m cops info host-assessment-workbench
python3 -m cops demo host-assessment-workbench
python3 -m cops check host-assessment-workbench
```

The demo exercises synthetic classification only. The package gate additionally
checks the native bridge contract and collector source constraints; it does not
execute the PowerShell collector on non-Windows hosts.

## End-to-end exercise

Run both exercises below. The synthetic path validates classification across
the supported evidence states. The Windows path validates the bounded native
collector, bridge import, and assessment-owned cleanup at the candidate
revision.

### Synthetic classification exercise

```bash
P=plugins/offensive-security/host-assessment-workbench
python3 "$P/scripts/assess.py" "$P/fixtures/synthetic/host_linux_positive_v1.json"
python3 "$P/scripts/assess.py" "$P/fixtures/synthetic/host_windows_positive_v1.json"
python3 "$P/scripts/demo.py"
```

Inspect the positive, protected/negative, remediated/fixed, unsupported-build,
and incomplete-cleanup branches. Compare source kind, boundary premise, canary
result, prerequisite state, and coverage with each fixture. A fixture supplies
classification evidence; it does not establish current host state.

### Native Windows bridge exercise

From the repository root in PowerShell, create a fresh run directory and an
empty assessment-owned canary root:

```powershell
$P = "plugins/offensive-security/host-assessment-workbench"
$Run = Join-Path $env:RUNNER_TEMP ("cops-windows-" + [Guid]::NewGuid())
$Canary = Join-Path $Run "canary"
New-Item -ItemType Directory -Path $Canary -Force | Out-Null

pwsh -NoProfile -File "$P/scripts/collect-windows.ps1" `
  -OutputPath "$Run/export.json" `
  -ReceiptPath "$Run/receipt.json" `
  -CanaryRoot $Canary
python "$P/scripts/assess.py" "$Run/export.json"
python "$P/scripts/validate-windows-bridge.py" `
  "$Run/receipt.json" "$Run/export.json" --canary-root $Canary

if (@(Get-ChildItem -LiteralPath $Canary -Force).Count -ne 0) {
  throw "assessment-owned canary root is not empty"
}
```

The collector reads fixed or bounded Windows metadata for service permissions,
scheduled-task permissions, token privileges, registry controls, filesystem
controls, local credential *references*, and version-dependent families. It
never reads a stored password value or attempts impersonation, elevation, task
execution, service changes, registry writes, or ACL changes.

Inspect `coverage` before interpreting observations. `access_denied`,
`not_assessed`, and `unsupported` remain gaps and do not establish a safe host.
The validator must rehash the exact export, match all declared capabilities, and
confirm the supplied canary root is still empty. Remove only the run directory
created for this exercise after retaining the required private evidence:

```powershell
Remove-Item -LiteralPath $Run -Recurse -Force
```

## Acceptance criteria

- Synthetic vulnerable, protected, remediated, unsupported-build, and malformed
  evidence paths retain their supplied provenance and expected classification.
- Native mode declares all seven Windows capabilities. Every emitted observation
  belongs to an assessed surface; denied, failed, or over-limit probes remain
  explicit in coverage.
- Platform, build, architecture, token, UAC, and available protection context
  remain visible. Unknown protections are not treated as disabled.
- The independent validator binds the receipt to the exact export SHA-256,
  verifies the capability set, and finds an empty operator-supplied canary root.
- The lifecycle canary is assessment-owned, initially absent, created, removed,
  and reported with three evidence markers. No result claims a privilege crossing.
- A native Windows run at the exact candidate revision passes before claiming
  the native integration is qualified. Linux/macOS package checks establish only
  the offline and static-contract paths.

Record each criterion separately, including failures, unperformed steps, and
blockers. A probe that the runner cannot access is valid `access_denied` evidence,
not a successful assessment of that surface.

## Failure and recovery

Alter a private copy of the receipt hash or capability list and confirm the
validator rejects it. Add a harmless file to a private canary-root copy and
confirm empty-root validation fails. Restore the original inputs and repeat.
Do not weaken filesystem permissions or run elevated solely to turn a coverage
gap into an assessed result.

Repeat the complete exercise in a fresh Windows runner or disposable host with a
second operator. Compare semantic results, export digests, and lifecycle receipts;
host-dependent observations may differ while the contract and cleanup invariants
remain stable.

## Host exercise

Install the documented adapter in each advertised host/OS using a clean profile.
Invoke `host-linux-privilege-boundaries` for Linux imports and
`host-windows-privilege-boundaries` for Windows imports or an explicitly
authorized local native collection. Check skill discovery, referenced files,
output against the CLI, refusal behavior, and cleanup. Record unavailable hosts
as blocked and failed installation or invocation as failed.

## Record and promote

Follow [the shared qualification and status-update guide](https://sodejm.github.io/copilot-operation-plugin-for-security/plugin-verification.html)
to save a sanitized run record, apply every intervening maturity gate, and request
independent review. Update maturity and public status labels only after the exact
revision has the required Windows evidence. Keep unsupported integrations and
remaining coverage gaps explicit.
