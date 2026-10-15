Set-StrictMode -Version Latest

function Resolve-CopsEnabledPrivileges {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Rows)

    $enabled = @()
    foreach ($line in $Rows) {
        $row = $line | ConvertFrom-Csv -Header Privilege, Description, State
        if ($row.Privilege -notmatch '^Se[A-Za-z0-9]+Privilege$' -or
            $row.State -notin @('Enabled', 'Disabled')) {
            throw 'Unable to establish Windows token privilege state.'
        }
        if ($row.State -eq 'Enabled') {
            $enabled += $row.Privilege
        }
    }
    return @($enabled | Sort-Object -Unique)
}

function Assert-CopsLocalPathEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    # Reject remote and ambiguous paths before any filesystem probe. A mapped
    # drive can also cause an apparently local Test-Path/Get-Acl to authenticate
    # to a remote server.
    if ($Path -notmatch '^[A-Za-z]:\\' -or
        $Path -match '(^|[\\/])\.{1,2}([\\/]|$)' -or
        $Path.Substring(2).Contains(':')) {
        throw 'PATH entry is not a fully qualified local drive path.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    $driveName = $full.Substring(0, 1)
    $drive = Get-PSDrive -Name $driveName -PSProvider FileSystem -ErrorAction Stop
    if ($drive.DisplayRoot -or
        [IO.DriveInfo]::new("${driveName}:\").DriveType -ne [IO.DriveType]::Fixed) {
        throw 'PATH entry is on a remote or non-fixed drive.'
    }
    # Inspect each ancestor before descending through it. Probing the leaf
    # first could follow a junction to a remote location.
    $root = [IO.Path]::GetPathRoot($full)
    $parts = @($full.Substring($root.Length).Split(
        [IO.Path]::DirectorySeparatorChar) | Where-Object { $_ })
    $cursor = $root
    foreach ($part in @('') + $parts) {
        if ($part) {
            $cursor = Join-Path $cursor $part
        }
        try {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        } catch [System.Management.Automation.ItemNotFoundException] {
            break
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'PATH entry traverses a reparse point.'
        }
    }
}

function Write-CopsNewUtf8File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
        $bytes = $encoding.GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally {
        $stream.Dispose()
    }
}

$script:CopsExplicitMutationRights = (
    [Security.AccessControl.FileSystemRights]::WriteData -bor
    [Security.AccessControl.FileSystemRights]::AppendData -bor
    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership
)

function Test-CopsExplicitMutationRight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemRights]$Rights
    )

    return ($Rights -band $script:CopsExplicitMutationRights) -ne 0
}

function Resolve-CopsIntegrityLevel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$Rids
    )

    $uniqueRids = @($Rids | Sort-Object -Unique)
    if ($uniqueRids.Count -ne 1) {
        return "unknown"
    }
    if ($uniqueRids[0] -ge 16384) {
        return "system"
    }
    if ($uniqueRids[0] -ge 12288) {
        return "high"
    }
    if ($uniqueRids[0] -ge 8192) {
        return "medium"
    }
    return "low"
}

function Resolve-CopsIntegrityLevelFromSources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$PrimaryRids,

        [Parameter(Mandatory = $true)]
        [scriptblock]$FallbackResolver
    )

    $uniquePrimaryRids = @($PrimaryRids | Sort-Object -Unique)
    if ($uniquePrimaryRids.Count -gt 0) {
        return (Resolve-CopsIntegrityLevel -Rids $uniquePrimaryRids)
    }

    try {
        $fallbackRids = [int[]]@(& $FallbackResolver)
    } catch {
        return "unknown"
    }
    return (Resolve-CopsIntegrityLevel -Rids $fallbackRids)
}
