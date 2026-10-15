Set-StrictMode -Version Latest

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
