# Review host privilege-boundary evidence

Use this playback to distinguish synthetic classification, native Windows
collection coverage, assessment-owned lifecycle cleanup, and unresolved host
context. The [README](../README.md) describes the data contract and safety limits.

## 1. Run the synthetic branches

From the repository root with Python 3.11 or newer:

```bash
python3 -m cops demo host-assessment-workbench
```

The demo calls `scripts/assess.py` for Linux and Windows synthetic cases. It
distinguishes vulnerable/reported crossing, protected/blocked, remediated/fixed,
unsupported-build, and incomplete-cleanup evidence. The demo is deterministic,
creates no host resources, and performs no live canary.

Inspect `source`, `host`, `coverage`, and each observation's prerequisite
`decision` before reading its classification. `cleanup_reported: true` records
what the source states; it is not cleanup performed by the importer.

## 2. Review an operator export

Use the exact `linux-1.0` or `windows-1.0` contract with approved sanitized
evidence and opaque IDs. Preserve `not_assessed`, `unsupported`,
`access_denied`, and unknown protection values. Do not fill gaps with
assumptions. A configuration candidate requires separate authorization and
evidence before active assessment.

```bash
python3 plugins/offensive-security/host-assessment-workbench/scripts/assess.py PATH_TO_EXPORT.json
```

If the importer rejects a record, correct contradictory or absent assertions
rather than weakening the contract.

## 3. Exercise the bounded Windows collector

On an authorized Windows host, create a fresh private run directory and empty
assessment-owned canary root:

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
```

The collector declares service, task, token, registry, filesystem, local
credential-reference, and versioned-family capabilities. It reads bounded
metadata only. It does not read password values, execute a task or service,
change ACLs or registry values, impersonate another token, or attempt elevation.

Review each coverage field. An omitted observation with `access_denied` or
`not_assessed` coverage is an explicit gap. Native observations are configuration
candidates, not proof of a working escalation. The canary receipt establishes only
that this assessment's harmless local marker was absent, created, and removed.

After retaining required private evidence, remove only the run-owned directory:

```powershell
Remove-Item -LiteralPath $Run -Recurse -Force
```

## 4. Verify and close

```bash
python3 -m cops check host-assessment-workbench
```

The package check validates fixture semantics, strict native receipt binding,
declared capabilities, and collector source constraints. Native collection is
qualified only by a Windows run at the exact candidate revision. Record the exact
revision and result using the [verification procedure](VERIFICATION.md).
