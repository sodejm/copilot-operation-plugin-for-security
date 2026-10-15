[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CanaryRoot,
    [Parameter(Mandatory = $true)]
    [string]$ResourceId,
    [Parameter(Mandatory = $true)]
    [ValidateSet("absent", "readable")]
    [string]$ExpectedState,
    [string]$ExpectedSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "The Windows canary observer can run only on Windows."
}
if ($ResourceId -notmatch '^[A-Za-z0-9._-]{1,128}$') {
    throw "ResourceId must be a bounded path token."
}
if ($ExpectedState -eq "readable" -and $ExpectedSha256 -notmatch '^[0-9a-f]{64}$') {
    throw "ExpectedSha256 must be a lowercase SHA-256 value for readable observations."
}

$rootFull = [IO.Path]::GetFullPath($CanaryRoot)
if ($rootFull.StartsWith("\\") -or -not (Test-Path -LiteralPath $rootFull -PathType Container)) {
    throw "CanaryRoot must be an existing local directory."
}
$rootItem = Get-Item -LiteralPath $rootFull -Force -ErrorAction Stop
if ($rootItem.PSProvider.Name -ne "FileSystem" -or $rootItem.PSDrive.DisplayRoot -or
    ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "CanaryRoot must be a local non-reparse filesystem directory."
}
$rootFull = [IO.Path]::GetFullPath($rootItem.FullName)
$resourceFull = [IO.Path]::GetFullPath((Join-Path $rootFull $ResourceId))
$expectedResource = $rootFull.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar + $ResourceId
if (-not $resourceFull.Equals($expectedResource, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ResourceId must identify a direct child of CanaryRoot."
}

$ownershipHash = $null
if ($ExpectedState -eq "absent") {
    if ((Test-Path -LiteralPath $resourceFull) -or
        @(Get-ChildItem -LiteralPath $rootFull -Force).Count -ne 0) {
        throw "The assessment-owned canary root is not empty."
    }
    $observedState = "resource_absent"
} else {
    $rootChildren = @(Get-ChildItem -LiteralPath $rootFull -Force)
    if ($rootChildren.Count -ne 1 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($rootChildren[0].FullName),
            $resourceFull,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "CanaryRoot must contain exactly the assessment-owned resource."
    }
    $resourceItem = Get-Item -LiteralPath $resourceFull -Force -ErrorAction Stop
    $resourceIdentity = [IO.Path]::GetFullPath($resourceItem.FullName)
    if (-not $resourceItem.PSIsContainer -or
        $resourceItem.PSProvider.Name -ne "FileSystem" -or $resourceItem.PSDrive.DisplayRoot -or
        ($resourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not $resourceIdentity.Equals($resourceFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The assessment-owned canary resource identity is invalid."
    }
    $resourceChildren = @(Get-ChildItem -LiteralPath $resourceFull -Force)
    $markerFull = [IO.Path]::GetFullPath((Join-Path $resourceFull "marker.txt"))
    if ($resourceChildren.Count -ne 1 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($resourceChildren[0].FullName),
            $markerFull,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "The assessment-owned canary must contain exactly its marker."
    }
    $markerItem = Get-Item -LiteralPath $markerFull -Force -ErrorAction Stop
    $markerIdentity = [IO.Path]::GetFullPath($markerItem.FullName)
    if ($markerItem.PSIsContainer -or $markerItem.PSProvider.Name -ne "FileSystem" -or
        ($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not $markerIdentity.Equals($markerFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The assessment-owned canary marker identity is invalid."
    }
    $ownershipHash = (Get-FileHash -LiteralPath $markerFull -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ownershipHash -ne $ExpectedSha256) {
        throw "The assessment-owned canary marker hash does not match."
    }
    $observedState = "readable_owned_marker"
}

[ordered]@{
    schema_version = "windows-canary-observation-1.0"
    observer_pid = $PID
    state = $observedState
    root_identity = $rootFull
    resource_identity = $resourceFull
    ownership_sha256 = $ownershipHash
} | ConvertTo-Json -Compress
