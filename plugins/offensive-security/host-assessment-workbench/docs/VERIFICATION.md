# COPS Host Assessment Workbench: end-to-end verification

## Scope and prerequisites

Qualify two distinct paths:

- deterministic Linux and Windows classification from synthetic or sanitized
  operator exports; and
- the bounded native Windows collector, bridge import, and assessment-owned
  lifecycle cleanup receipt.

An offline canary assertion remains source-reported. The native lifecycle canary
uses a separate process under the same Windows token to observe the owned marker
absent, readable with its exact hash, and absent after cleanup. It does not test a
second identity or cross a privilege boundary.

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
python3 "$P/scripts/assess.py" "$P/fixtures/synthetic/host_windows_vulnerable_v1.json"
python3 "$P/scripts/demo.py"
```

Inspect the positive, protected/negative, remediated/fixed, unsupported-build,
and incomplete-cleanup branches. Compare source kind, boundary premise, canary
result, prerequisite state, and coverage with each fixture. A fixture supplies
classification evidence; it does not establish current host state.

### Native Windows bridge exercise

From the repository root in PowerShell, run the same entry point used by the
hosted Windows job. Supply a new path whose parent is an existing local,
non-reparse directory:

```powershell
$P = "plugins/offensive-security/host-assessment-workbench"
$Run = Join-Path $env:TEMP ("cops-windows-" + [Guid]::NewGuid().ToString("N"))
& "$P/scripts/exercise-windows-bridge.ps1" -RunRoot $Run
```

The collector reads fixed or bounded Windows metadata across seven declared
surfaces. The service probe identifies unquoted paths but does not collect
service ACL permissions. The registry probe reads AlwaysInstallElevated but not
Run keys. Local credential references cover the `DefaultPassword` value name and
two unattend-file locations but not Credential Manager. The bounded scheduled-task
ACL inventory has no pinned E01.1 source mapping. The collector never reads a
stored password value or attempts impersonation, elevation, task execution,
service changes, registry writes, or ACL changes.

Inspect `coverage` before interpreting observations. `access_denied`,
`not_assessed`, and `unsupported` remain gaps and do not establish a safe host.
The exercise runs the collector, importer, and validator; checks all declared
capabilities and coverage values; exercises the explicit ACL mutation predicate
with read-only and writable rights; rejects a native junction-ancestor fixture;
injects a partial temporary-file write and requires cleanup with no final
artifact or temporary residue; and invokes a separate same-token process to
observe the resource absent before creation, readable with the exact marker hash
after creation, and absent after deletion. The validator rehashes the exact
export, binds the receipt's canonical root and child identities to the supplied
root, and independently confirms the root is empty. Remove only the run directory
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
- The independent validator binds the receipt to the exact export SHA-256 and
  canonical operator-supplied canary root, verifies its owned child identity and
  capability set, and finds that root empty.
- The lifecycle canary is assessment-owned. A separate same-token process observes
  it absent, readable with the exact owned marker, and absent after cleanup. The
  collector independently verifies its marker hash before deletion; a mismatch
  fails closed. No result claims cross-identity denial or a privilege crossing.
- User paths are fixed-drive paths whose existing ancestors contain no reparse
  point. The native self-tests reject a junction ancestor and leave no final or
  temporary artifact after the injected partial-write failure.
- A native Windows run at the exact candidate revision passes before claiming
  the native integration is qualified. Linux/macOS package checks establish only
  the offline and static-contract paths.

Record each criterion separately, including failures, unperformed steps, and
blockers. A probe that the runner cannot access is valid `access_denied` evidence,
not a successful assessment of that surface.

## Failure and recovery

Alter a private copy of the receipt hash or capability list and confirm the
validator rejects it. Supply a different empty canary root and confirm identity
binding fails. Add a harmless file to a private canary-root copy and confirm
empty-root validation fails. Restore the original inputs and repeat.
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
