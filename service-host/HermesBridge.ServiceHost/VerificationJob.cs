using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace HermesBridge.ServiceHost;

internal sealed partial class VerificationJob : IDisposable
{
    private const uint ExtendedLimitInformation = 9;
    private const uint KillOnClose = 0x00002000;
    private readonly SafeFileHandle _handle;

    private VerificationJob(SafeFileHandle handle) => _handle = handle;

    public static VerificationJob Attach(System.Diagnostics.Process process)
    {
        var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid || !SetKillOnClose(job) || !AssignProcessToJobObject(job, process.SafeHandle.DangerousGetHandle()))
        {
            job.Dispose();
            throw new HostFailure("verifier-job-failed");
        }

        return new VerificationJob(job);
    }

    public void Dispose() => _handle.Dispose();

    private static bool SetKillOnClose(SafeFileHandle job)
    {
        var information = new ExtendedLimit { Basic = new BasicLimit { LimitFlags = KillOnClose } };
        return SetInformationJobObject(job, ExtendedLimitInformation, ref information, Marshal.SizeOf<ExtendedLimit>());
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimit { public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount; public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimit { public BasicLimit Basic; public IoCounters IoInfo; public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit; public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed; }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] private static partial SafeFileHandle CreateJobObjectW(IntPtr attributes, string? name);
    [LibraryImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
    [LibraryImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool SetInformationJobObject(SafeFileHandle job, uint informationClass, ref ExtendedLimit information, int informationLength);
}
