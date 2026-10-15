[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RunRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "The native Windows bridge exercise can run only on Windows."
}

. (Join-Path $PSScriptRoot "windows-bridge-common.ps1")

# Exercise the exact ACL predicate used by the collector on the native runtime.
if (Test-CopsExplicitMutationRight -Rights (
        [Security.AccessControl.FileSystemRights]::ReadAndExecute
    )) {
    throw "ReadAndExecute must not be classified as a mutation right."
}
if (-not (Test-CopsExplicitMutationRight -Rights (
            [Security.AccessControl.FileSystemRights]::WriteData
        ))) {
    throw "WriteData must be classified as a mutation right."
}
if ((Resolve-CopsIntegrityLevel -Rids @()) -ne "unknown") {
    throw "A missing token integrity SID must remain unknown."
}
if ((Resolve-CopsIntegrityLevel -Rids @(8192)) -ne "medium") {
    throw "The medium token integrity SID must resolve to medium."
}
if ((Resolve-CopsIntegrityLevel -Rids @(8192, 12288)) -ne "unknown") {
    throw "Ambiguous token integrity SIDs must remain unknown."
}
$ambiguousFallbackProbe = [pscustomobject]@{ Invoked = $false }
$ambiguousSourceResult = Resolve-CopsIntegrityLevelFromSources `
    -PrimaryRids @(8192, 12288) `
    -FallbackResolver {
        $ambiguousFallbackProbe.Invoked = $true
        @(8192)
    }
if ($ambiguousSourceResult -ne "unknown" -or $ambiguousFallbackProbe.Invoked) {
    throw "Ambiguous primary token integrity SIDs must fail closed without fallback."
}
$missingFallbackProbe = [pscustomobject]@{ Invoked = $false }
$missingSourceResult = Resolve-CopsIntegrityLevelFromSources `
    -PrimaryRids @() `
    -FallbackResolver {
        $missingFallbackProbe.Invoked = $true
        @(8192)
    }
if ($missingSourceResult -ne "medium" -or -not $missingFallbackProbe.Invoked) {
    throw "A missing primary token integrity SID must use the bounded fallback."
}
$ambiguousFallbackResult = Resolve-CopsIntegrityLevelFromSources `
    -PrimaryRids @() `
    -FallbackResolver { @(8192, 12288) }
if ($ambiguousFallbackResult -ne "unknown") {
    throw "Ambiguous fallback token integrity SIDs must fail closed."
}
$failedFallbackResult = Resolve-CopsIntegrityLevelFromSources `
    -PrimaryRids @() `
    -FallbackResolver { throw "controlled fallback failure" }
if ($failedFallbackResult -ne "unknown") {
    throw "A failed token integrity fallback must fail closed."
}

$runFull = [IO.Path]::GetFullPath($RunRoot)
if ($runFull.StartsWith("\\") -or (Test-Path -LiteralPath $runFull)) {
    throw "RunRoot must be a new path on a local filesystem."
}
$parent = Split-Path -Parent $runFull
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw "RunRoot parent directory does not exist."
}
$parentItem = Get-Item -LiteralPath $parent -Force
if ($parentItem.PSProvider.Name -ne "FileSystem" -or $parentItem.PSDrive.DisplayRoot -or
    ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "RunRoot parent must be a local non-reparse filesystem directory."
}
New-Item -ItemType Directory -Path $runFull -ErrorAction Stop | Out-Null
$runItem = Get-Item -LiteralPath $runFull -Force
if (($runItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    -not [IO.Path]::GetFullPath($runItem.FullName).Equals(
        $runFull, [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "RunRoot identity validation failed."
}

$canaryRoot = Join-Path $runFull "canary"
$exportPath = Join-Path $runFull "windows-export.json"
$receiptPath = Join-Path $runFull "windows-receipt.json"
$reportPath = Join-Path $runFull "windows-report.json"
$validatedReceiptPath = Join-Path $runFull "windows-validated-receipt.json"
New-Item -ItemType Directory -Path $canaryRoot -ErrorAction Stop | Out-Null

& (Join-Path $PSScriptRoot "collect-windows.ps1") `
    -OutputPath $exportPath `
    -ReceiptPath $receiptPath `
    -CanaryRoot $canaryRoot
if (-not $?) {
    throw "Native Windows collection failed."
}

$reportJson = (& python (Join-Path $PSScriptRoot "assess.py") $exportPath | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "Native Windows assessment failed."
}
$report = $reportJson | ConvertFrom-Json
if ($report.mode -ne "native_bridge_import" -or
    $report.bridge.mode -ne "native_windows_bridge") {
    throw "Native Windows assessment did not preserve the bridge mode."
}
$expectedSurfaces = @(
    "service_permissions",
    "scheduled_task_permissions",
    "token_privileges",
    "registry_controls",
    "filesystem_controls",
    "local_credential_references",
    "versioned_escalation_families"
)
$allowedCoverage = @("assessed", "not_assessed", "unsupported", "access_denied")
foreach ($surface in $expectedSurfaces) {
    if ($report.bridge.capabilities -notcontains $surface) {
        throw "Native Windows bridge omitted capability $surface."
    }
    $coverageProperty = $report.coverage.PSObject.Properties[$surface]
    if ($null -eq $coverageProperty) {
        throw "Native Windows bridge omitted coverage for $surface."
    }
    $state = $coverageProperty.Value
    if ($allowedCoverage -notcontains $state) {
        throw "Native Windows bridge emitted invalid coverage for $surface."
    }
}

$validatedJson = (& python (Join-Path $PSScriptRoot "validate-windows-bridge.py") `
        $receiptPath $exportPath --canary-root $canaryRoot | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "Native Windows receipt validation failed."
}
$validated = $validatedJson | ConvertFrom-Json
if (-not $validated.canary.ownership_verified -or -not $validated.canary.cleanup_verified) {
    throw "Native Windows receipt did not establish owned lifecycle cleanup."
}
if (@(Get-ChildItem -LiteralPath $canaryRoot -Force).Count -ne 0) {
    throw "Native Windows bridge left assessment-owned canary residue."
}

$utf8 = New-Object System.Text.UTF8Encoding -ArgumentList $false
[IO.File]::WriteAllText($reportPath, $reportJson.Trim(), $utf8)
[IO.File]::WriteAllText($validatedReceiptPath, $validatedJson.Trim(), $utf8)

[ordered]@{
    run_root = $runFull
    export = $exportPath
    receipt = $receiptPath
    report = $reportPath
    validated_receipt = $validatedReceiptPath
    coverage = $report.coverage
} | ConvertTo-Json -Depth 5 -Compress
