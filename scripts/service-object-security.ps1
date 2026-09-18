$script:BridgeServiceObjectCanonicalDacl = 'D:(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)'
$script:BridgeTrustedServiceOwnerSids = @('S-1-5-18', 'S-1-5-32-544')

function Initialize-BridgeServiceObjectSecurityApi {
    if ($null -ne ('HermesBridge.ServiceObjectSecurityApi' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace HermesBridge {
    public static class ServiceObjectSecurityApi {
        const uint SC_MANAGER_CONNECT = 0x0001, READ_CONTROL = 0x00020000, WRITE_DAC = 0x00040000;
        const uint OWNER_SECURITY_INFORMATION = 0x00000001, DACL_SECURITY_INFORMATION = 0x00000004;
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool QueryServiceObjectSecurity(IntPtr service, uint information, byte[] descriptor, uint size, out uint needed);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool SetServiceObjectSecurity(IntPtr service, uint information, byte[] descriptor);
        [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
        static void Fail(string operation) { throw new Win32Exception(Marshal.GetLastWin32Error(), operation); }
        static IntPtr Open(uint access, string name) {
            IntPtr manager=OpenSCManagerW(null,null,SC_MANAGER_CONNECT), service=IntPtr.Zero;
            if(manager==IntPtr.Zero) Fail("OpenSCManagerW");
            try { service=OpenServiceW(manager,name,access); if(service==IntPtr.Zero) Fail("OpenServiceW"); return service; }
            finally { CloseServiceHandle(manager); }
        }
        static byte[] Read(IntPtr service) {
            uint needed; QueryServiceObjectSecurity(service,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,null,0,out needed);
            if(needed==0||needed>1048576) throw new InvalidOperationException("ServiceObjectSecurityDescriptorInvalid");
            var descriptor=new byte[needed];
            if(!QueryServiceObjectSecurity(service,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,descriptor,needed,out needed)) Fail("QueryServiceObjectSecurity");
            return descriptor;
        }
        public static byte[] ReadDescriptor(string name) {
            IntPtr service=Open(READ_CONTROL,name); try { return Read(service); } finally { CloseServiceHandle(service); }
        }
        public static byte[] SetCanonicalDaclAndRead(string name, byte[] daclDescriptor) {
            IntPtr service=Open(READ_CONTROL|WRITE_DAC,name);
            try { if(!SetServiceObjectSecurity(service,DACL_SECURITY_INFORMATION,daclDescriptor)) Fail("SetServiceObjectSecurity"); return Read(service); }
            finally { CloseServiceHandle(service); }
        }
    }
}
'@
}

function Test-BridgeServiceObjectSecurityDescriptor {
    param([Parameter(Mandatory)][Security.AccessControl.RawSecurityDescriptor]$Descriptor)
    if ($null -eq $Descriptor.Owner -or $Descriptor.Owner.Value -notin $script:BridgeTrustedServiceOwnerSids) { return $false }
    if ($null -eq $Descriptor.DiscretionaryAcl) { return $false }
    $canonical = [Security.AccessControl.RawSecurityDescriptor]::new($script:BridgeServiceObjectCanonicalDacl)
    $actualBytes = New-Object byte[] ($Descriptor.DiscretionaryAcl.BinaryLength)
    $expectedBytes = New-Object byte[] ($canonical.DiscretionaryAcl.BinaryLength)
    $Descriptor.DiscretionaryAcl.GetBinaryForm($actualBytes, 0)
    $canonical.DiscretionaryAcl.GetBinaryForm($expectedBytes, 0)
    return [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($actualBytes, $expectedBytes)
}

function Get-BridgeServiceObjectSecurityState {
    param([Parameter(Mandatory)][string]$Name)
    try {
        Initialize-BridgeServiceObjectSecurityApi
        $bytes = [HermesBridge.ServiceObjectSecurityApi]::ReadDescriptor($Name)
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
        return Test-BridgeServiceObjectSecurityDescriptor -Descriptor $descriptor
    } catch { return $false }
}

function Set-BridgeCreatedServiceObjectProtection {
    param([Parameter(Mandatory)][string]$Name)
    Initialize-BridgeServiceObjectSecurityApi
    $canonical = [Security.AccessControl.RawSecurityDescriptor]::new($script:BridgeServiceObjectCanonicalDacl)
    $bytes = New-Object byte[] ($canonical.BinaryLength)
    $canonical.GetBinaryForm($bytes, 0)
    $actual = [Security.AccessControl.RawSecurityDescriptor]::new(
        [HermesBridge.ServiceObjectSecurityApi]::SetCanonicalDaclAndRead($Name, $bytes), 0
    )
    if (-not (Test-BridgeServiceObjectSecurityDescriptor -Descriptor $actual)) {
        throw [Security.SecurityException]::new('BridgeCreatedServiceObjectSecurityVerificationFailed')
    }
}
