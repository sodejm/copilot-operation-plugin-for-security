[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ReceiptPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "Native Windows SCM acceptance requires Windows." }
. (Join-Path $PSScriptRoot "windows-bridge-common.ps1")
. (Join-Path $PSScriptRoot "windows-service-acl.ps1")
$receiptFull = Resolve-CopsLocalPath -Path $ReceiptPath -Name "Acceptance receipt" -Kind NewFile

# Mutation APIs are confined to this disposable acceptance fixture. The collector
# opens services only with READ_CONTROL. No service is ever started by this test.
if (-not ("Cops.ServiceDaclFixture" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace Cops {
    public sealed class ServiceDaclFixture : IDisposable {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true,
            EntryPoint = "OpenSCManagerW")]
        static extern IntPtr OpenSCManager(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true,
            EntryPoint = "CreateServiceW")]
        static extern IntPtr CreateService(IntPtr manager, string name, string display,
            uint access, uint type, uint start, uint error, string binary,
            string group, IntPtr tag, string dependencies, string account, string password);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true,
            EntryPoint = "OpenServiceW")]
        static extern IntPtr OpenService(IntPtr manager, string name, uint access);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetServiceObjectSecurity(IntPtr service, uint information, byte[] descriptor);
        [StructLayout(LayoutKind.Sequential)]
        struct Status {
            public uint type, state, accepted, win32Exit, serviceExit, checkpoint, waitHint;
        }
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool QueryServiceStatus(IntPtr service, out Status status);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DeleteService(IntPtr service);
        [DllImport("advapi32.dll")]
        static extern bool CloseServiceHandle(IntPtr handle);
        IntPtr manager, service;
        public readonly string Name = "CopsAcl" + Guid.NewGuid().ToString("N");
        int statusFailuresRemaining;
        readonly Action absenceVerified;
        public ServiceDaclFixture() : this(0, null) {}
        ServiceDaclFixture(int statusFailures, Action absenceVerified) {
            this.statusFailuresRemaining = statusFailures;
            this.absenceVerified = absenceVerified;
            try {
                manager = OpenSCManager(null, null, 3); // CONNECT | CREATE_SERVICE
                if (manager == IntPtr.Zero) throw new Win32Exception();
                string binary = System.IO.Path.Combine(Environment.GetFolderPath(
                    Environment.SpecialFolder.System), Name + ".exe");
                if (System.IO.File.Exists(binary)) throw new InvalidOperationException("Fixture binary exists.");
                service = CreateService(manager, Name, Name, 0x000f01ff, 0x10, 3, 1,
                    "\"" + binary + "\"", null, IntPtr.Zero, null, null, null);
                if (service == IntPtr.Zero) throw new Win32Exception();
                AssertStopped();
            } catch (Exception primary) {
                try { Dispose(); }
                catch (Exception cleanup) {
                    throw new AggregateException("Fixture creation and cleanup failed.", primary, cleanup);
                }
                throw;
            }
        }
        public void AssertStopped() {
            if (statusFailuresRemaining > 0) {
                statusFailuresRemaining--;
                throw new InvalidOperationException("Controlled status-query failure.");
            }
            Status status;
            if (!QueryServiceStatus(service, out status)) throw new Win32Exception();
            if (status.state != 1) throw new InvalidOperationException("Fixture service must remain stopped.");
        }
        public void SetDacl(string sddl) {
            AssertStopped();
            var descriptor = new RawSecurityDescriptor(sddl);
            var bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            if (!SetServiceObjectSecurity(service, 4, bytes)) throw new Win32Exception();
            AssertStopped();
        }
        public void Dispose() {
            // Each cleanup action is attempted even if status inspection fails.
            // Delete only this randomly named owned service using its retained handle.
            var errors = new List<Exception>();
            try {
                if (service != IntPtr.Zero) {
                    try { AssertStopped(); } catch (Exception error) { errors.Add(error); }
                    try {
                        if (!DeleteService(service)) throw new Win32Exception();
                    } catch (Exception error) { errors.Add(error); }
                    finally { CloseServiceHandle(service); service = IntPtr.Zero; }
                    try {
                        IntPtr remaining = OpenService(manager, Name, 0x00020000);
                        if (remaining != IntPtr.Zero) {
                            CloseServiceHandle(remaining);
                            throw new InvalidOperationException("Fixture service survived deletion.");
                        }
                        if (Marshal.GetLastWin32Error() != 1060)
                            throw new InvalidOperationException("Service absence was not verified.");
                        if (absenceVerified != null) absenceVerified();
                    } catch (Exception error) { errors.Add(error); }
                }
            } finally {
                if (manager != IntPtr.Zero) { CloseServiceHandle(manager); manager = IntPtr.Zero; }
            }
            if (errors.Count != 0) throw new AggregateException("Fixture cleanup failed.", errors);
        }
        public static bool VerifyStatusFailureCleanup() {
            bool absent = false;
            try {
                using (var fixture = new ServiceDaclFixture(2, () => absent = true)) {}
            } catch (AggregateException error) {
                var errors = error.Flatten().InnerExceptions;
                if (!absent || errors.Count != 2) throw;
                foreach (Exception item in errors)
                    if (!(item is InvalidOperationException) ||
                        item.Message != "Controlled status-query failure.") throw;
                return true;
            }
            throw new InvalidOperationException("Status-query failures were not observed.");
        }
    }
}
'@
}

$cases = @(
    @("O:SYD:(A;;0x2;;;WD)", "assessed", "interesting"),
    @("O:SYD:(A;;0x2;;;AU)", "assessed", "interesting"),
    @("O:SYD:(A;;0x2;;;BU)", "assessed", "interesting"),
    @("O:SYD:(A;;WD;;;BU)", "assessed", "interesting"),
    @("O:SYD:(A;;WO;;;BU)", "assessed", "interesting"),
    @("O:SYD:(A;;GW;;;BU)", "assessed", "interesting"),
    @("O:SYD:(A;;GA;;;BU)", "assessed", "interesting"),
    @("O:SYD:(A;;0x2008d;;;BU)", "assessed", "ordinary"),
    @("O:SYD:", "assessed", "ordinary"),
    @("O:SYG:SY", "assessed", "interesting"),
    @("O:BUD:", "assessed", "interesting"),
    @("O:AUD:", "assessed", "interesting"),
    @("O:WDD:", "assessed", "interesting"),
    @("O:BUD:(A;;RC;;;OW)", "assessed", "ordinary"),
    @("O:BUD:(A;;WD;;;OW)", "assessed", "interesting"),
    @("O:BUD:(D;;WD;;;OW)", "not_assessed", "unknown"),
    @("O:SYD:(A;;WD;;;OW)", "assessed", "ordinary"),
    @("D:", "not_assessed", "unknown"),
    @("invalid", "not_assessed", "unknown"),
    @("O:SYD:(D;;0x2;;;BU)(A;;GA;;;BU)", "not_assessed", "unknown"),
    @("O:SYD:(A;;GA;;;BU)(D;;RC;;;WD)", "not_assessed", "unknown"),
    @("O:SYD:(A;CI;GA;;;BU)", "not_assessed", "unknown"),
    @("O:SYD:(OA;;GA;00000000-0000-0000-0000-000000000001;;BU)", "not_assessed", "unknown")
)
foreach ($case in $cases) {
    $actual = [Cops.ServiceDacl]::AnalyzeSddl($case[0])
    if ($actual.coverage -ne $case[1] -or $actual.configuration -ne $case[2]) {
        throw "Service DACL semantic correction case failed: $($case[0])"
    }
}

$fixture = [Cops.ServiceDaclFixture]::new()
try {
    $fixture.SetDacl("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x2;;;BU)")
    $vulnerable = [Cops.ServiceDacl]::Read($fixture.Name)
    if ($vulnerable.coverage -ne "assessed" -or $vulnerable.configuration -ne "interesting") {
        throw "The native collector did not detect the seeded change-config grant."
    }
    $fixture.SetDacl("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x2008d;;;BU)")
    $corrected = [Cops.ServiceDacl]::Read($fixture.Name)
    if ($corrected.coverage -ne "assessed" -or $corrected.configuration -ne "ordinary") {
        throw "The corrected read-only service grant did not clear the finding."
    }
    # OWNER RIGHTS suppresses the owner's implicit READ_CONTROL grant as well.
    $fixture.SetDacl("D:(D;;RC;;;WD)(D;;RC;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)")
    $denied = [Cops.ServiceDacl]::Read($fixture.Name)
    if ($denied.coverage -ne "access_denied") {
        throw "An unreadable native service DACL must remain access_denied."
    }
    $fixture.AssertStopped()
} finally { $fixture.Dispose() }
$missing = [Cops.ServiceDacl]::Read($fixture.Name)
if ($missing.coverage -ne "not_assessed") { throw "Missing service evidence must remain not_assessed." }

$failedFixture = [Cops.ServiceDaclFixture]::new()
$failureObserved = $false
try {
    try {
        $failedFixture.SetDacl("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x2;;;BU)")
        throw "controlled acceptance failure"
    } finally { $failedFixture.Dispose() }
} catch {
    if ($_.Exception.Message -ne "controlled acceptance failure") { throw }
    $failureObserved = $true
}
if (-not $failureObserved) { throw "Controlled fixture failure was not observed." }
$statusFailureCleanup = [Cops.ServiceDaclFixture]::VerifyStatusFailureCleanup()
Write-CopsNewUtf8File -Path $receiptFull -Content ([ordered]@{
    schema_version = "windows-service-acl-acceptance-1.0"
    vulnerable = $vulnerable.configuration
    corrected = $corrected.configuration
    missing = $missing.coverage
    denied = $denied.coverage
    semantic_cases = $cases.Count
    success_cleanup_verified = $true
    failure_cleanup_verified = $true
    status_failure_cleanup_verified = $statusFailureCleanup
    service_started = $false
} | ConvertTo-Json -Compress)
