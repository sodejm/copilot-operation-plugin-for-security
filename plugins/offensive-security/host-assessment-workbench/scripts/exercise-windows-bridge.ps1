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
$enabledPrivileges = @(Resolve-CopsEnabledPrivileges -Rows @(
    '"SeImpersonatePrivilege","Impersonate a client","Disabled"',
    '"SeChangeNotifyPrivilege","Bypass traverse checking","Enabled"'
))
if ($enabledPrivileges.Count -ne 1 -or
    $enabledPrivileges[0] -ne "SeChangeNotifyPrivilege") {
    throw "Disabled token privileges must not count as enabled."
}
$remotePathRejected = $false
try {
    Assert-CopsLocalPathEntry -Path '\\server\share'
} catch {
    $remotePathRejected = $true
}
if (-not $remotePathRejected) {
    throw "A remote PATH entry must be rejected before filesystem inspection."
}

$runFull = Resolve-CopsLocalPath -Path $RunRoot -Name "RunRoot" -Kind NewDirectory
$parent = Split-Path -Parent $runFull

# Exercise ancestor-junction rejection and partial-write cleanup on the native
# filesystem before the actual run writes any artifacts.
$selfTestRoot = Join-Path $parent (".cops-windows-bridge-test-" + [Guid]::NewGuid().ToString("N"))
$selfTestRoot = Resolve-CopsLocalPath -Path $selfTestRoot -Name "Self-test root" -Kind NewDirectory
New-Item -ItemType Directory -Path $selfTestRoot -ErrorAction Stop | Out-Null
try {
    $targetRoot = Join-Path $selfTestRoot "target"
    $carrierRoot = Join-Path $selfTestRoot "carrier"
    $targetRoot = Resolve-CopsLocalPath -Path $targetRoot -Name "Self-test target" -Kind NewDirectory
    $carrierRoot = Resolve-CopsLocalPath -Path $carrierRoot -Name "Self-test carrier" -Kind NewDirectory
    New-Item -ItemType Directory -Path $targetRoot -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path $carrierRoot -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $targetRoot "nested") -ErrorAction Stop | Out-Null
    $junction = Join-Path $carrierRoot "junction"
    New-Item -ItemType Junction -Path $junction -Target $targetRoot -ErrorAction Stop | Out-Null
    $junctionRejected = $false
    try {
        $null = Resolve-CopsLocalPath `
            -Path (Join-Path $junction "nested\artifact.json") `
            -Name "Junction self-test path" -Kind NewFile
    } catch {
        if ($_.Exception.Message -match "reparse point") {
            $junctionRejected = $true
        } else {
            throw
        }
    }
    if (-not $junctionRejected) {
        throw "Ancestor junction self-test did not fail closed."
    }

    $partialPath = Join-Path $selfTestRoot "partial.json"
    $partialWriteRejected = $false
    try {
        Invoke-CopsExclusiveFileWrite -Path $partialPath -Writer {
            param($stream)
            $stream.WriteByte(123)
            throw "controlled partial write failure"
        }
    } catch {
        if ($_.Exception.Message -match "controlled partial write failure") {
            $partialWriteRejected = $true
        } else {
            throw
        }
    }
    if (-not $partialWriteRejected -or
        (Test-Path -LiteralPath $partialPath) -or
        @(Get-ChildItem -LiteralPath $selfTestRoot -Filter ".partial.json.cops-*.tmp" -Force).Count -ne 0) {
        throw "Partial-write cleanup self-test did not fail closed without residue."
    }

    # Exercise two successive completed writes because collection emits its
    # export and receipt through separate invocations of the same primitive.
    $firstWritePath = Join-Path $selfTestRoot "sequential-first.json"
    $secondWritePath = Join-Path $selfTestRoot "sequential-second.json"
    Write-CopsNewUtf8File -Path $firstWritePath -Content '{"sequence":1}'
    Write-CopsNewUtf8File -Path $secondWritePath -Content '{"sequence":2}'
    $null = Resolve-CopsLocalPath -Path $firstWritePath -Name "First sequential write" -Kind ExistingFile
    $null = Resolve-CopsLocalPath -Path $secondWritePath -Name "Second sequential write" -Kind ExistingFile
    if ((Get-Content -LiteralPath $firstWritePath -Raw) -ne '{"sequence":1}' -or
        (Get-Content -LiteralPath $secondWritePath -Raw) -ne '{"sequence":2}' -or
        @(Get-ChildItem -LiteralPath $selfTestRoot -Filter "*.cops-*.tmp" -Force).Count -ne 0) {
        throw "Sequential atomic-write self-test did not preserve both completed files."
    }
} finally {
    $junction = Join-Path (Join-Path $selfTestRoot "carrier") "junction"
    if (Test-Path -LiteralPath $junction) {
        Remove-Item -LiteralPath $junction -Force -ErrorAction Stop
    }
    Remove-Item -LiteralPath $selfTestRoot -Recurse -Force -ErrorAction Stop
}

New-Item -ItemType Directory -Path $runFull -ErrorAction Stop | Out-Null
$runFull = Resolve-CopsLocalPath -Path $runFull -Name "RunRoot" -Kind ExistingDirectory

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

try {
    $null = Resolve-CopsLocalPath -Path $exportPath -Name "Collected export" -Kind ExistingFile
    $null = Resolve-CopsLocalPath -Path $receiptPath -Name "Collected receipt" -Kind ExistingFile
} catch {
    $expectedNames = @(
        Split-Path -Leaf $exportPath
        Split-Path -Leaf $receiptPath
    )
    $observedNames = @(
        Get-ChildItem -LiteralPath $runFull -File -Force |
            Where-Object { $expectedNames -contains $_.Name } |
            Select-Object -ExpandProperty Name |
            Sort-Object
    )
    $observed = if ($observedNames.Count -eq 0) { '<none>' } else { $observedNames -join ', ' }
    throw "Native Windows collection did not materialize its required files; observed expected artifact names: $observed. $($_.Exception.Message)"
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
if ($validated.schema_version -ne "windows-bridge-receipt-1.2" -or
    -not $validated.canary.ownership_verified -or -not $validated.canary.cleanup_verified -or
    $validated.canary.observer_kind -ne "separate_same_token_process" -or
    $validated.canary.before_observation -ne "resource_absent" -or
    $validated.canary.after_create_observation -ne "readable_owned_marker" -or
    $validated.canary.after_cleanup_observation -ne "resource_absent") {
    throw "Native Windows receipt did not establish owned lifecycle cleanup."
}
if (@(Get-ChildItem -LiteralPath $canaryRoot -Force).Count -ne 0) {
    throw "Native Windows bridge left assessment-owned canary residue."
}

Write-CopsNewUtf8File -Path $reportPath -Content $reportJson.Trim()
Write-CopsNewUtf8File -Path $validatedReceiptPath -Content $validatedJson.Trim()

[ordered]@{
    artifacts = @(
        "windows-export.json",
        "windows-receipt.json",
        "windows-report.json",
        "windows-validated-receipt.json"
    )
    coverage = $report.coverage
} | ConvertTo-Json -Depth 5 -Compress
