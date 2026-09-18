using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace HermesBridge.ServiceHost;

public static partial class AnchorDirectory
{
    internal const string ProductName = "HermesWindowsBridge";
    internal const string EvaluationPrefix = "HermesWindowsBridgeEval-";

    public static AnchorContext Require(ServiceProfile profile)
    {
        var baseDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        var programFiles = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
        var relative = Path.GetRelativePath(programFiles, baseDirectory).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (relative.Any(part => part is "." or ".."))
        {
            throw new HostFailure("invalid-anchor");
        }

        string programRoot;
        string digest;
        string? contextNonce;
        if (relative.Length == 4 && string.Equals(relative[0], ProductName, StringComparison.Ordinal) &&
            string.Equals(relative[1], "hosts", StringComparison.Ordinal) && IsLowerHex(relative[2]) &&
            string.Equals(relative[3], HostConfiguration.ToConfigValue(profile), StringComparison.Ordinal))
        {
            programRoot = Path.Combine(programFiles, ProductName);
            digest = relative[2];
            contextNonce = null;
        }
        else if (relative.Length == 4 && relative[0].StartsWith(EvaluationPrefix, StringComparison.Ordinal) &&
            IsLowerHex(relative[0][EvaluationPrefix.Length..], 32) && string.Equals(relative[1], "hosts", StringComparison.Ordinal) &&
            IsLowerHex(relative[2]) && string.Equals(relative[3], HostConfiguration.ToConfigValue(profile), StringComparison.Ordinal))
        {
            programRoot = Path.Combine(programFiles, relative[0]);
            digest = relative[2];
            contextNonce = relative[0][EvaluationPrefix.Length..];
        }
        else
        {
            throw new HostFailure("invalid-anchor");
        }

        RequireProtectedTree(baseDirectory, programFiles);
        return new AnchorContext(baseDirectory, programRoot, digest, contextNonce);
    }

    internal static void RequireProtectedFile(string path, string protectedRoot)
    {
        var fullPath = Path.GetFullPath(path);
        var safeRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(protectedRoot));
        if (!fullPath.StartsWith(safeRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new HostFailure("unprotected-binding");
        }

        var file = new FileInfo(fullPath);
        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0 || !HasSingleLink(fullPath) || HasUntrustedWriteAccess(file))
        {
            throw new HostFailure("unprotected-binding");
        }

        RequireProtectedAncestors(file.Directory?.FullName ?? throw new HostFailure("unprotected-binding"), safeRoot);
    }

    private static void RequireProtectedTree(string anchorDirectory, string protectedRoot)
    {
        RequireProtectedAncestors(anchorDirectory, protectedRoot);
        if (Directory.EnumerateFiles(anchorDirectory, "*", SearchOption.AllDirectories).Any(path =>
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 || !HasSingleLink(path) || HasUntrustedWriteAccess(new FileInfo(path))))
        {
            throw new HostFailure("unprotected-anchor");
        }
    }

    private static void RequireProtectedAncestors(string anchorDirectory, string protectedRoot)
    {
        var current = new DirectoryInfo(anchorDirectory);
        while (true)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0 || HasUntrustedWriteAccess(current))
            {
                throw new HostFailure("unprotected-anchor");
            }

            if (string.Equals(current.FullName, protectedRoot, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            current = current.Parent ?? throw new HostFailure("unprotected-anchor");
        }
    }

    private static bool HasUntrustedWriteAccess(FileSystemInfo entry)
    {
        var trusted = new HashSet<SecurityIdentifier>
        {
            new(WellKnownSidType.LocalSystemSid, null),
            new(WellKnownSidType.BuiltinAdministratorsSid, null),
            new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),
        };
        var writeMask = FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories | FileSystemRights.AppendData |
            FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes | FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        FileSystemSecurity security = entry switch
        {
            DirectoryInfo directory => directory.GetAccessControl(),
            FileInfo file => file.GetAccessControl(),
            _ => throw new HostFailure("unprotected-anchor"),
        };
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>();
        return security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !trusted.Contains(owner) ||
            new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null || rules.Any(rule => rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference is SecurityIdentifier sid &&
            !trusted.Contains(sid) && (rule.FileSystemRights & writeMask) != 0);
    }

    private static bool HasSingleLink(string path)
    {
        using SafeFileHandle handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return AnchorNative.GetFileInformationByHandle(handle, out var information) && information.NumberOfLinks == 1;
    }

    private static bool IsLowerHex(string value) => IsLowerHex(value, 64);

    private static bool IsLowerHex(string value, int length) => value.Length == length && value.All(c =>
        (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
}

public sealed record AnchorContext(string Directory, string ProgramRoot, string Digest, string? ContextNonce)
{
    public string ExpectedRuntimeBindingPath(ServiceProfile profile) => Path.Combine(ProgramRoot, "bindings", $"{HostConfiguration.ToConfigValue(profile)}.json");

    public string ExpectedProgramDataRoot => ContextNonce is null
        ? throw new HostFailure("runtime-binding-not-supported")
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), $"{AnchorDirectory.EvaluationPrefix}{ContextNonce}");

    public string ExpectedConfigPath => ContextNonce is null
        ? throw new HostFailure("runtime-binding-not-supported")
        : Path.Combine(ExpectedProgramDataRoot, AnchorDirectory.ProductName, "config.yaml");

    public string ExpectedServiceName(ServiceProfile profile) => ContextNonce is null
        ? profile == ServiceProfile.Gateway ? "HermesWindowsBridgeGateway" : "HermesWindowsBridgePrivileged"
        : $"{AnchorDirectory.EvaluationPrefix}{ContextNonce}-{(profile == ServiceProfile.Gateway ? "Gateway" : "Privileged")}";
}

[StructLayout(LayoutKind.Sequential)]
internal struct ByHandleFileInformation
{
    public uint FileAttributes;
    public uint CreationTimeLow;
    public uint CreationTimeHigh;
    public uint LastAccessTimeLow;
    public uint LastAccessTimeHigh;
    public uint LastWriteTimeLow;
    public uint LastWriteTimeHigh;
    public uint VolumeSerialNumber;
    public uint FileSizeHigh;
    public uint FileSizeLow;
    public uint NumberOfLinks;
    public uint FileIndexHigh;
    public uint FileIndexLow;
}

internal static partial class AnchorNative
{
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation information);
}
