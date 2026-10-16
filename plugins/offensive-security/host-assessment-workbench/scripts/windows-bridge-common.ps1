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

function Resolve-CopsLocalPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('AllowMissing', 'ExistingDirectory', 'ExistingFile', 'NewFile', 'NewDirectory')]
        [string]$Kind
    )

    # Reject remote and ambiguous paths before any filesystem probe. A mapped
    # drive can also cause an apparently local Test-Path/Get-Acl to authenticate
    # to a remote server.
    if ($Path -notmatch '^[A-Za-z]:\\' -or
        $Path -match '(^|[\\/])\.{1,2}([\\/]|$)' -or
        $Path.Substring(2).Contains(':')) {
        throw "$Name is not a fully qualified local drive path."
    }
    $full = [IO.Path]::GetFullPath($Path)
    $driveName = $full.Substring(0, 1)
    $drive = Get-PSDrive -Name $driveName -PSProvider FileSystem -ErrorAction Stop
    if ($drive.DisplayRoot -or
        [IO.DriveInfo]::new("${driveName}:\").DriveType -ne [IO.DriveType]::Fixed) {
        throw "$Name is on a remote or non-fixed drive."
    }
    # Inspect each ancestor before descending through it. Probing the leaf
    # first could follow a junction to a remote location.
    $root = [IO.Path]::GetPathRoot($full)
    $parts = @($full.Substring($root.Length).Split(
        [IO.Path]::DirectorySeparatorChar) | Where-Object { $_ })
    $cursor = $root
    $lastItem = $null
    $firstMissingIndex = $null
    $index = -1
    foreach ($part in @('') + $parts) {
        $index += 1
        if ($part) {
            $cursor = Join-Path $cursor $part
        }
        try {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        } catch [System.Management.Automation.ItemNotFoundException] {
            $firstMissingIndex = $index
            break
        }
        if ($item.PSProvider.Name -ne 'FileSystem') {
            throw "$Name is not on a filesystem drive."
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Name traverses a reparse point."
        }
        $lastItem = $item
    }

    $leafIndex = $parts.Count
    if ($Kind -in @('ExistingDirectory', 'ExistingFile')) {
        $expectedContainer = $Kind -eq 'ExistingDirectory'
        if ($null -ne $firstMissingIndex -or $null -eq $lastItem -or
            $lastItem.PSIsContainer -ne $expectedContainer) {
            $expectedType = if ($expectedContainer) { 'directory' } else { 'file' }
            throw "$Name must be an existing local $expectedType."
        }
    } elseif ($Kind -in @('NewFile', 'NewDirectory')) {
        if ($null -eq $firstMissingIndex) {
            throw "$Name already exists."
        }
        if ($firstMissingIndex -ne $leafIndex -or $null -eq $lastItem -or -not $lastItem.PSIsContainer) {
            throw "$Name parent directory does not exist."
        }
    }
    return $full
}

function Assert-CopsLocalPathEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $null = Resolve-CopsLocalPath -Path $Path -Name 'PATH entry' -Kind AllowMissing
}

function Initialize-CopsNativeFileDisposition {
    if ($null -ne ('CopsFileDisposition.NativeMethods' -as [type])) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CopsFileDisposition {
    public static class NativeMethods {
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_LIST_DIRECTORY = 0x00000001;
        private const uint FILE_READ_ATTRIBUTES = 0x00000080;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint DELETE = 0x00010000;
        private const uint CREATE_NEW = 1;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const int FILE_RENAME_INFORMATION_CLASS = 10;

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_STATUS_BLOCK {
            public IntPtr Status;
            public UIntPtr Information;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_DISPOSITION_INFO {
            [MarshalAs(UnmanagedType.Bool)]
            public bool DeleteFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle hFile,
            int FileInformationClass,
            ref FILE_DISPOSITION_INFO lpFileInformation,
            uint dwBufferSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        public static SafeFileHandle CreateExclusive(string path) {
            SafeFileHandle handle = CreateFileW(path, GENERIC_WRITE | DELETE, 0,
                IntPtr.Zero, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (handle.IsInvalid) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            return handle;
        }

        public static SafeFileHandle OpenDirectory(string path) {
            SafeFileHandle handle = CreateFileW(path,
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero);
            if (handle.IsInvalid) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            return handle;
        }

        public static void DeleteOnClose(SafeFileHandle handle) {
            FILE_DISPOSITION_INFO info = new FILE_DISPOSITION_INFO { DeleteFile = true };
            if (!SetFileInformationByHandle(handle, 4, ref info,
                    (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO)))) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public static void RenameNoReplace(
                SafeFileHandle handle, SafeFileHandle directory, string leaf) {
            if (String.IsNullOrEmpty(leaf) || Path.GetFileName(leaf) != leaf ||
                    leaf.IndexOf(Path.AltDirectorySeparatorChar) >= 0 || leaf.IndexOf(':') >= 0) {
                throw new ArgumentException("Output leaf name is invalid.", "leaf");
            }
            byte[] name = System.Text.Encoding.Unicode.GetBytes(leaf);
            int rootOffset = IntPtr.Size;
            int lengthOffset = rootOffset + IntPtr.Size;
            int nameOffset = lengthOffset + sizeof(uint);
            IntPtr buffer = Marshal.AllocHGlobal(nameOffset + name.Length);
            try {
                for (int index = 0; index < nameOffset; index++) {
                    Marshal.WriteByte(buffer, index, 0);
                }
                Marshal.WriteIntPtr(buffer, rootOffset, directory.DangerousGetHandle());
                Marshal.WriteInt32(buffer, lengthOffset, name.Length);
                Marshal.Copy(name, 0, IntPtr.Add(buffer, nameOffset), name.Length);
                IO_STATUS_BLOCK statusBlock;
                int status = NtSetInformationFile(handle, out statusBlock, buffer,
                    (uint)(nameOffset + name.Length), FILE_RENAME_INFORMATION_CLASS);
                if (status < 0) {
                    throw new InvalidOperationException(
                        String.Format("Atomic output publication failed with NTSTATUS 0x{0:X8}.",
                            unchecked((uint)status)));
                }
            } finally {
                Marshal.FreeHGlobal(buffer);
            }
        }

        [DllImport("ntdll.dll")]
        private static extern int NtSetInformationFile(
            SafeFileHandle hFile,
            out IO_STATUS_BLOCK ioStatusBlock,
            IntPtr fileInformation,
            uint length,
            int fileInformationClass);
    }
}
'@
}

function Invoke-CopsExclusiveFileWrite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Writer
    )

    $full = Resolve-CopsLocalPath -Path $Path -Name 'Output file' -Kind NewFile
    $parent = Split-Path -Parent $full
    $leaf = Split-Path -Leaf $full
    $temporary = Join-Path $parent ('.' + $leaf + '.cops-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $temporary = Resolve-CopsLocalPath -Path $temporary -Name 'Temporary output file' -Kind NewFile
    Initialize-CopsNativeFileDisposition
    $directoryHandle = [CopsFileDisposition.NativeMethods]::OpenDirectory($parent)
    $handle = $null
    $stream = $null
    try {
        $handle = [CopsFileDisposition.NativeMethods]::CreateExclusive($temporary)
        try {
            $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Write)
            & $Writer $stream
            $stream.Flush($true)
            [CopsFileDisposition.NativeMethods]::RenameNoReplace(
                $stream.SafeFileHandle, $directoryHandle, $leaf)
        } catch {
            $writeFailure = $_
            try {
                [CopsFileDisposition.NativeMethods]::DeleteOnClose($handle)
            } catch {
                throw "Output write failed and handle-bound cleanup could not be established; temporary residue may remain. Original failure: $writeFailure"
            }
            throw $writeFailure
        }
    } finally {
        try {
            if ($null -ne $stream) {
                $stream.Dispose()
            } elseif ($null -ne $handle) {
                $handle.Dispose()
            }
        } finally {
            $directoryHandle.Dispose()
        }
    }
    # Verify the rename after closing the handle so callers never proceed on a
    # successful return unless the final path is a local, regular file.
    $null = Resolve-CopsLocalPath -Path $full -Name 'Output file' -Kind ExistingFile
}

function Write-CopsNewUtf8File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    Invoke-CopsExclusiveFileWrite -Path $Path -Writer {
        param($stream)
        $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
        $bytes = $encoding.GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
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
