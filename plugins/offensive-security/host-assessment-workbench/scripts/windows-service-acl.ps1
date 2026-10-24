# Read-only, local SCM access. Service access masks are not filesystem rights.
if (-not ("Cops.ServiceDacl" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace Cops {
    public sealed class ServiceDaclResult {
        public string coverage;
        public string configuration;
        public ServiceDaclResult(string coverage, string configuration) {
            this.coverage = coverage;
            this.configuration = configuration;
        }
    }

    public static class ServiceDacl {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true,
            EntryPoint = "OpenSCManagerW")]
        static extern IntPtr OpenSCManager(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true,
            EntryPoint = "OpenServiceW")]
        static extern IntPtr OpenService(IntPtr manager, string name, uint access);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool QueryServiceObjectSecurity(IntPtr service, uint information,
            byte[] descriptor, uint size, out uint needed);
        [DllImport("advapi32.dll")]
        static extern bool CloseServiceHandle(IntPtr handle);

        static ServiceDaclResult Unknown() {
            return new ServiceDaclResult("not_assessed", "unknown");
        }
        static ServiceDaclResult NativeFailure() {
            return Marshal.GetLastWin32Error() == 5
                ? new ServiceDaclResult("access_denied", "unknown") : Unknown();
        }
        static uint MutationMask(int access) {
            uint mask = unchecked((uint)access);
            // GENERIC_ALL / GENERIC_WRITE both include SERVICE_CHANGE_CONFIG.
            if ((mask & 0x50000000u) != 0) mask |= 2u;
            return mask & 0x000c0002u;
        }
        static bool IsBroadSid(string sid) {
            return sid == "S-1-1-0" || sid == "S-1-5-11" || sid == "S-1-5-32-545";
        }
        public static ServiceDaclResult AnalyzeSddl(string sddl) {
            if (sddl == null || sddl.Length > 65536) return Unknown();
            try { return Analyze(new RawSecurityDescriptor(sddl)); }
            catch (ArgumentException) { return Unknown(); }
        }
        static ServiceDaclResult Analyze(RawSecurityDescriptor descriptor) {
            if (descriptor.Owner == null) return Unknown();
            bool broadOwner = IsBroadSid(descriptor.Owner.Value);
            RawAcl acl = descriptor.DiscretionaryAcl;
            // An absent/null DACL grants full access; an empty DACL grants none.
            if (acl == null) return new ServiceDaclResult("assessed", "interesting");
            if (acl.Count > 256) return Unknown();
            bool interesting = false;
            bool allowSeen = false;
            bool ownerRightsSeen = false;
            foreach (GenericAce raw in acl) {
                CommonAce ace = raw as CommonAce;
                if (ace == null || ace.IsCallback || ace.AceFlags != AceFlags.None)
                    return Unknown();
                string sid = ace.SecurityIdentifier.Value;
                // Any OWNER RIGHTS ACE suppresses the owner's implicit READ_CONTROL
                // and WRITE_DAC; unsupported semantics still fail closed below.
                if (sid == "S-1-3-4") ownerRightsSeen = true;
                if (ace.AceQualifier == AceQualifier.AccessDenied) {
                    // No token membership inference or approximate effective access.
                    if (allowSeen || MutationMask(ace.AccessMask) != 0) return Unknown();
                    continue;
                }
                if (ace.AceQualifier != AceQualifier.AccessAllowed) return Unknown();
                allowSeen = true;
                if ((IsBroadSid(sid) || (broadOwner && sid == "S-1-3-4"))
                    && MutationMask(ace.AccessMask) != 0) interesting = true;
            }
            if (broadOwner && !ownerRightsSeen) interesting = true;
            return new ServiceDaclResult("assessed", interesting ? "interesting" : "ordinary");
        }
        public static ServiceDaclResult Read(string name) {
            if (String.IsNullOrEmpty(name) || name.Length > 256) return Unknown();
            foreach (char c in name)
                if (Char.IsControl(c) || c == '/' || c == '\\') return Unknown();
            IntPtr manager = IntPtr.Zero, service = IntPtr.Zero;
            try {
                manager = OpenSCManager(null, null, 1);
                if (manager == IntPtr.Zero) return NativeFailure();
                service = OpenService(manager, name, 0x00020000);
                if (service == IntPtr.Zero) return NativeFailure();
                byte[] buffer = new byte[65536];
                uint needed;
                if (!QueryServiceObjectSecurity(service, 5, buffer, (uint)buffer.Length, out needed))
                    return NativeFailure();
                if (needed == 0 || needed > buffer.Length) return Unknown();
                return Analyze(new RawSecurityDescriptor(buffer, 0));
            } catch (ArgumentException) { return Unknown(); }
            finally {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                if (manager != IntPtr.Zero) CloseServiceHandle(manager);
            }
        }
    }
}
'@
}
