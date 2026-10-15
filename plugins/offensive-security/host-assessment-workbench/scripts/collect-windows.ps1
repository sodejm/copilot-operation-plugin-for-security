[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [Parameter(Mandatory = $true)]
    [string]$ReceiptPath,
    [Parameter(Mandatory = $true)]
    [string]$CanaryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "windows-bridge-common.ps1")

if ($env:OS -ne "Windows_NT") {
    throw "The native Windows bridge can run only on Windows."
}

function Resolve-NewLocalFile {
    param([string]$Path, [string]$Name)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith("\\")) {
        throw "$Name must be on a local filesystem."
    }
    if (Test-Path -LiteralPath $full) {
        throw "$Name already exists."
    }
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "$Name parent directory does not exist."
    }
    $parentItem = Get-Item -LiteralPath $parent -Force
    if ($parentItem.PSProvider.Name -ne "FileSystem" -or $parentItem.PSDrive.DisplayRoot) {
        throw "$Name must be on a local filesystem."
    }
    return $full
}

function Get-CopsStringSha256 {
    param([string]$Value)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
                $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
            )).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

$outputFull = Resolve-NewLocalFile -Path $OutputPath -Name "OutputPath"
$receiptFull = Resolve-NewLocalFile -Path $ReceiptPath -Name "ReceiptPath"
$canaryFull = [IO.Path]::GetFullPath($CanaryRoot)
if ($canaryFull.StartsWith("\\") -or -not (Test-Path -LiteralPath $canaryFull -PathType Container)) {
    throw "CanaryRoot must be an existing local directory."
}
$canaryItem = Get-Item -LiteralPath $canaryFull -Force
if ($canaryItem.PSProvider.Name -ne "FileSystem" -or $canaryItem.PSDrive.DisplayRoot -or
    ($canaryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "CanaryRoot cannot be a reparse point."
}
$canaryFull = [IO.Path]::GetFullPath($canaryItem.FullName)
if (@(Get-ChildItem -LiteralPath $canaryFull -Force).Count -ne 0) {
    throw "CanaryRoot must be empty before assessment."
}
$canaryPrefix = $canaryFull.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if ($outputFull.StartsWith($canaryPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    $receiptFull.StartsWith($canaryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Output files cannot be placed under CanaryRoot."
}
if ($outputFull.Equals($receiptFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputPath and ReceiptPath must be different files."
}

$version = [Environment]::OSVersion.Version
$osBuild = "$($version.Major).$($version.Minor).$($version.Build)"
$architecture = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    "X64" { "x64" }
    "X86" { "x86" }
    "Arm64" { "arm64" }
    default { throw "Unsupported Windows architecture." }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$integrityRid = @(
    $identity.Groups |
        ForEach-Object { $_.Value } |
        Where-Object { $_ -match '^S-1-16-[0-9]+$' } |
        ForEach-Object { [int]($_ -replace '^S-1-16-', '') }
)
if ($integrityRid.Count -ne 1) {
    throw "Unable to determine a single Windows token integrity level."
}
$integrity = if ($integrityRid[0] -ge 16384) {
    "system"
} elseif ($integrityRid[0] -ge 12288) {
    "high"
} elseif ($integrityRid[0] -ge 8192) {
    "medium"
} else {
    "low"
}

$privilegeCoverage = "assessed"
$privileges = @()
try {
    $privilegeRows = @(& "$env:SystemRoot\System32\whoami.exe" /priv /fo csv /nh 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw "whoami privilege collection failed."
    }
    foreach ($line in $privilegeRows) {
        $row = $line | ConvertFrom-Csv -Header Privilege, Description, State
        if ($row.Privilege -match '^Se[A-Za-z0-9]+Privilege$') {
            $privileges += $row.Privilege
        }
    }
    $privileges = @($privileges | Sort-Object -Unique)
} catch {
    $privilegeCoverage = "not_assessed"
    $privileges = @()
}

$uac = "unknown"
try {
    $uacValue = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction Stop).EnableLUA
    $uac = if ([int]$uacValue -eq 1) { "enabled" } else { "disabled" }
} catch {
    $uac = "unknown"
}

$registryCoverage = "assessed"
$registryConfiguration = "ordinary"
try {
    $machineKey = Get-Item -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $userKey = Get-Item -LiteralPath "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $machineEnabled = $null -ne $machineKey -and [int]$machineKey.GetValue("AlwaysInstallElevated", 0) -eq 1
    $userEnabled = $null -ne $userKey -and [int]$userKey.GetValue("AlwaysInstallElevated", 0) -eq 1
    if ($machineEnabled -and $userEnabled) {
        $registryConfiguration = "interesting"
    }
} catch [System.UnauthorizedAccessException] {
    $registryCoverage = "access_denied"
} catch {
    $registryCoverage = "not_assessed"
}

$credentialCoverage = "assessed"
$credentialConfiguration = "ordinary"
try {
    $winlogonKey = Get-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction Stop
    $autoLogonReference = $winlogonKey.GetValueNames() -contains "DefaultPassword"
    $unattendedReference = @(@(
            Join-Path $env:WINDIR "Panther\Unattend.xml"
            Join-Path $env:WINDIR "Panther\Unattend\Unattend.xml"
        ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($autoLogonReference -or $unattendedReference.Count -gt 0) {
        $credentialConfiguration = "interesting"
    }
} catch [System.UnauthorizedAccessException] {
    $credentialCoverage = "access_denied"
} catch {
    $credentialCoverage = "not_assessed"
}

$serviceCoverage = "assessed"
$serviceConfiguration = "ordinary"
try {
    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Select-Object -First 1025)
    if ($services.Count -gt 1024) {
        $serviceCoverage = "not_assessed"
    } else {
        $unquotedService = @($services | Where-Object {
                $_.PathName -match '^[A-Za-z]:\\[^"\r\n]*\s[^"\r\n]*\.exe(?:\s|$)'
            }).Count -gt 0
        if ($unquotedService) {
            $serviceConfiguration = "interesting"
        }
    }
} catch [System.UnauthorizedAccessException] {
    $serviceCoverage = "access_denied"
} catch {
    $serviceCoverage = "not_assessed"
}

$taskCoverage = "assessed"
$taskConfiguration = "ordinary"
$broadPrincipalSids = @("S-1-1-0", "S-1-5-11", "S-1-5-32-545")
try {
    $taskFiles = @(Get-ChildItem -LiteralPath (Join-Path $env:WINDIR "System32\Tasks") -File -Recurse -Force -ErrorAction Stop | Select-Object -First 513)
    if ($taskFiles.Count -gt 512) {
        $taskCoverage = "not_assessed"
    } else {
        $weakTaskAcl = $false
        foreach ($taskFile in $taskFiles) {
            $acl = Get-Acl -LiteralPath $taskFile.FullName -ErrorAction Stop
            foreach ($rule in $acl.Access) {
                try {
                    $principalSid = $rule.IdentityReference.Translate(
                        [Security.Principal.SecurityIdentifier]
                    ).Value
                } catch {
                    continue
                }
                $weakPrincipal = $broadPrincipalSids -contains $principalSid
                $writeRight = Test-CopsExplicitMutationRight -Rights $rule.FileSystemRights
                if ($weakPrincipal -and $rule.AccessControlType -eq "Allow" -and $writeRight) {
                    $weakTaskAcl = $true
                    break
                }
            }
            if ($weakTaskAcl) { break }
        }
        if ($weakTaskAcl) {
            $taskConfiguration = "interesting"
        }
    }
} catch [System.UnauthorizedAccessException] {
    $taskCoverage = "access_denied"
} catch {
    $taskCoverage = "not_assessed"
}

$filesystemCoverage = "assessed"
$filesystemConfiguration = "ordinary"
try {
    $pathDirectories = @($env:PATH -split ';' | Where-Object { $_ } | Sort-Object -Unique)
    if ($pathDirectories.Count -gt 128) {
        $filesystemCoverage = "not_assessed"
    } else {
      foreach ($directory in $pathDirectories) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) { continue }
        $acl = Get-Acl -LiteralPath $directory -ErrorAction Stop
        foreach ($rule in $acl.Access) {
            try {
                $principalSid = $rule.IdentityReference.Translate(
                    [Security.Principal.SecurityIdentifier]
                ).Value
            } catch {
                continue
            }
            $weakPrincipal = $broadPrincipalSids -contains $principalSid
            $writeRight = Test-CopsExplicitMutationRight -Rights $rule.FileSystemRights
            if ($weakPrincipal -and $rule.AccessControlType -eq "Allow" -and $writeRight) {
                $filesystemConfiguration = "interesting"
                break
            }
        }
        if ($filesystemConfiguration -eq "interesting") { break }
      }
    }
} catch [System.UnauthorizedAccessException] {
    $filesystemCoverage = "access_denied"
} catch {
    $filesystemCoverage = "not_assessed"
}

$familyCoverage = if ($privilegeCoverage -eq "assessed") { "assessed" } else { "not_assessed" }
$familyConfiguration = if ($privileges -contains "SeImpersonatePrivilege" -or
    $privileges -contains "SeAssignPrimaryTokenPrivilege") { "interesting" } else { "ordinary" }

$requirements = [ordered]@{
    build_min = $osBuild
    build_max = $osBuild
    architecture = $architecture
    token = [ordered]@{
        min_integrity = $integrity
        elevated = $elevated
        privileges = $privileges
    }
    protections = [ordered]@{}
}
$observations = @()
if ($serviceCoverage -eq "assessed") {
    $observations += [ordered]@{
        id = "native_service_permissions"
        surface = "service_permissions"
        configuration = $serviceConfiguration
        evidence_ids = @("service_paths_evaluated")
        requirements = $requirements
    }
}
if ($taskCoverage -eq "assessed") {
    $observations += [ordered]@{
        id = "native_scheduled_task_permissions"
        surface = "scheduled_task_permissions"
        configuration = $taskConfiguration
        evidence_ids = @("scheduled_task_acls_evaluated")
        requirements = $requirements
    }
}
if ($privilegeCoverage -eq "assessed") {
    $observations += [ordered]@{
        id = "native_token_privileges"
        surface = "token_privileges"
        configuration = $familyConfiguration
        evidence_ids = @("token_privileges_evaluated")
        requirements = $requirements
    }
}
if ($registryCoverage -eq "assessed") {
    $observations += [ordered]@{
        id = "native_registry_controls"
        surface = "registry_controls"
        configuration = $registryConfiguration
        evidence_ids = @("registry_aie_evaluated")
        requirements = $requirements
    }
}
if ($credentialCoverage -eq "assessed") {
    $observations += [ordered]@{
        id = "native_local_credential_references"
        surface = "local_credential_references"
        configuration = $credentialConfiguration
        evidence_ids = @("credential_references_evaluated")
        requirements = $requirements
    }
}
if ($filesystemCoverage -eq "assessed") {
    $observations += [ordered]@{
        id = "native_filesystem_controls"
        surface = "filesystem_controls"
        configuration = $filesystemConfiguration
        evidence_ids = @("path_directory_acls_evaluated")
        requirements = $requirements
    }
}
if ($familyCoverage -eq "assessed") {
    $observations += [ordered]@{
        id = "native_versioned_escalation_families"
        surface = "versioned_escalation_families"
        family_id = "token_impersonation_family"
        configuration = $familyConfiguration
        evidence_ids = @("os_build_evaluated", "token_privileges_evaluated")
        requirements = $requirements
    }
}

$export = [ordered]@{
    schema_version = "windows-1.0"
    source_kind = "operator_export"
    source_id = "native_windows_bridge"
    bridge = [ordered]@{
        mode = "native_windows_bridge"
        platform = "windows"
        capabilities = @(
            "service_permissions",
            "scheduled_task_permissions",
            "token_privileges",
            "registry_controls",
            "filesystem_controls",
            "local_credential_references",
            "versioned_escalation_families"
        )
        canary_assertions = $false
    }
    host = [ordered]@{
        os_build = $osBuild
        architecture = $architecture
        token = [ordered]@{
            integrity = $integrity
            elevated = $elevated
            privileges = $privileges
            privileges_complete = ($privilegeCoverage -eq "assessed")
        }
        protections = [ordered]@{
            uac = $uac
            wdac = "unknown"
            credential_guard = "unknown"
            vbs = "unknown"
            applocker = "unknown"
        }
    }
    coverage = [ordered]@{
        service_permissions = $serviceCoverage
        scheduled_task_permissions = $taskCoverage
        token_privileges = $privilegeCoverage
        registry_controls = $registryCoverage
        filesystem_controls = $filesystemCoverage
        local_credential_references = $credentialCoverage
        versioned_escalation_families = $familyCoverage
    }
    observations = $observations
}

$resourceId = "cops_canary_" + [Guid]::NewGuid().ToString("N")
$canaryPath = [IO.Path]::GetFullPath((Join-Path $canaryFull $resourceId))
$ownershipToken = [Guid]::NewGuid().ToString("N")
$markerContent = "COPS assessment-owned lifecycle canary:$ownershipToken"
$markerPath = [IO.Path]::GetFullPath((Join-Path $canaryPath "marker.txt"))
$ownershipHash = Get-CopsStringSha256 -Value $markerContent
$beforeAbsent = -not (Test-Path -LiteralPath $canaryPath)
$created = $false
$removed = $false
$ownershipVerified = $false
if (-not $beforeAbsent) {
    throw "Assessment-owned canary path already exists."
}
New-Item -ItemType Directory -Path $canaryPath -ErrorAction Stop | Out-Null
$createdItem = Get-Item -LiteralPath $canaryPath -Force -ErrorAction Stop
$createdIdentity = [IO.Path]::GetFullPath($createdItem.FullName)
if ($createdItem.PSProvider.Name -ne "FileSystem" -or $createdItem.PSDrive.DisplayRoot -or
    ($createdItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    -not $createdIdentity.Equals($canaryPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Assessment-owned canary directory identity validation failed."
}
$utf8 = New-Object System.Text.UTF8Encoding -ArgumentList $false
[IO.File]::WriteAllText($markerPath, $markerContent, $utf8)
$created = Test-Path -LiteralPath $canaryPath -PathType Container

$ownedItem = Get-Item -LiteralPath $canaryPath -Force -ErrorAction Stop
$ownedMarker = Get-Item -LiteralPath $markerPath -Force -ErrorAction Stop
$ownedIdentity = [IO.Path]::GetFullPath($ownedItem.FullName)
$ownedMarkerIdentity = [IO.Path]::GetFullPath($ownedMarker.FullName)
$markerHash = (Get-FileHash -LiteralPath $markerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ownedItem.PSProvider.Name -ne "FileSystem" -or $ownedItem.PSDrive.DisplayRoot -or
    ($ownedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    -not $ownedIdentity.Equals($canaryPath, [StringComparison]::OrdinalIgnoreCase) -or
    $ownedMarker.PSProvider.Name -ne "FileSystem" -or
    ($ownedMarker.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    -not $ownedMarkerIdentity.Equals($markerPath, [StringComparison]::OrdinalIgnoreCase) -or
    $markerHash -ne $ownershipHash) {
    throw "Assessment-owned canary ownership validation failed."
}
$ownershipVerified = $true
Remove-Item -LiteralPath $canaryPath -Recurse -Force -ErrorAction Stop
$removed = -not (Test-Path -LiteralPath $canaryPath)
if (-not ($beforeAbsent -and $created -and $ownershipVerified -and $removed)) {
    throw "Assessment-owned canary lifecycle validation failed."
}

$exportJson = $export | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText($outputFull, $exportJson, $utf8)
$exportHash = (Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash.ToLowerInvariant()
$receipt = [ordered]@{
    schema_version = "windows-bridge-receipt-1.1"
    platform = "windows"
    bridge_mode = "native_windows_bridge"
    export_sha256 = $exportHash
    capabilities = @(
        "service_permissions",
        "scheduled_task_permissions",
        "token_privileges",
        "registry_controls",
        "filesystem_controls",
        "local_credential_references",
        "versioned_escalation_families"
    )
    canary = [ordered]@{
        resource_id = $resourceId
        root_identity = $canaryFull
        resource_identity = $canaryPath
        ownership_sha256 = $ownershipHash
        assessment_owned = $true
        before_absent = $true
        created = $true
        ownership_verified = $true
        removed = $true
        cleanup_verified = $true
        evidence_ids = @(
            "canary_before",
            "canary_identity_bound",
            "canary_created",
            "canary_ownership_verified",
            "canary_removed"
        )
    }
}
$receiptJson = $receipt | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($receiptFull, $receiptJson, $utf8)
