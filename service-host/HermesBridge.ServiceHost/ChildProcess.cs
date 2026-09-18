using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace HermesBridge.ServiceHost;

public sealed partial class ChildProcess : IManagedChild, IDisposable
{
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint ExtendedLimitInformationClass = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int StartfUseStdHandles = 0x00000100;
    private const int ProcThreadAttributeHandleList = 0x00020002;
    private readonly SafeFileHandle _job;
    private readonly SafeFileHandle _process;
    private readonly SafeFileHandle _thread;
    private readonly StreamWriter _stdin;
    private readonly StreamReader _stderr;
    private readonly Task _stderrDrain;
    private readonly StreamReader _stdout;
    private Task _stdoutWatch = Task.CompletedTask;
    private bool _stdinClosed;

    private ChildProcess(SafeFileHandle job, SafeFileHandle process, SafeFileHandle thread, StreamWriter stdin, StreamReader stdout, StreamReader stderr, Task stderrDrain)
    {
        _job = job;
        _process = process;
        _thread = thread;
        _stdin = stdin;
        _stdout = stdout;
        _stderr = stderr;
        _stderrDrain = stderrDrain;
    }

    public static async Task<ChildProcess> StartAsync(ReleaseVerification verification, ServiceProfile profile, RuntimeBinding? binding, CancellationToken cancellationToken)
        => await StartCoreAsync(verification.ServiceExecutable, BuildCommandLine(verification.ServiceExecutable, profile, binding), verification.ReleaseRoot, TimeSpan.FromSeconds(60), cancellationToken, null);

    internal static async Task<ChildProcess> StartFixtureAsync(string executable, string arguments, string workingDirectory, TimeSpan readinessTimeout, CancellationToken cancellationToken, StartupFixtureFault? startupFault = null)
        => await StartCoreAsync(executable, $"\"{executable}\" {arguments}", workingDirectory, readinessTimeout, cancellationToken, startupFault);

    private static async Task<ChildProcess> StartCoreAsync(string executable, string commandLine, string workingDirectory, TimeSpan readinessTimeout, CancellationToken cancellationToken, StartupFixtureFault? startupFault)
    {
        AnonymousPipeServerStream? stdinWrite = null;
        AnonymousPipeServerStream? stdoutRead = null;
        AnonymousPipeServerStream? stderrRead = null;
        SafeFileHandle? rawProcess = null;
        SafeFileHandle? rawThread = null;
        SafeFileHandle? job = null;
        StreamWriter? stdin = null;
        StreamReader? stdout = null;
        StreamReader? stderr = null;
        Task? stderrDrain = null;
        ChildProcess? child = null;

        try
        {
            stdinWrite = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable);
            stdoutRead = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
            stderrRead = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
            var standardHandles = new[]
            {
                stdinWrite.ClientSafePipeHandle.DangerousGetHandle(),
                stdoutRead.ClientSafePipeHandle.DangerousGetHandle(),
                stderrRead.ClientSafePipeHandle.DangerousGetHandle(),
            };

            using (var attributes = new StartupAttributeList(standardHandles))
            {
                var startupInfo = new StartupInfoEx
                {
                    StartupInfo = new StartupInfo
                    {
                        cb = Marshal.SizeOf<StartupInfoEx>(),
                        dwFlags = StartfUseStdHandles,
                        hStdInput = standardHandles[0],
                        hStdOutput = standardHandles[1],
                        hStdError = standardHandles[2],
                    },
                    lpAttributeList = attributes.Pointer,
                };
                if (!CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true, CreateSuspended | CreateUnicodeEnvironment | ExtendedStartupInfoPresent, IntPtr.Zero, workingDirectory, ref startupInfo, out var processInformation))
                {
                    throw new HostFailure("child-start-failed");
                }

                rawProcess = new SafeFileHandle(processInformation.hProcess, ownsHandle: true);
                rawThread = new SafeFileHandle(processInformation.hThread, ownsHandle: true);
                job = CreateJobObjectW(IntPtr.Zero, null);
                if (job.IsInvalid)
                {
                    throw new HostFailure("job-create-failed");
                }

                ConfigureKillOnClose(job);
                if (!AssignProcessToJobObject(job, rawProcess))
                {
                    throw new HostFailure("job-assign-failed");
                }

                startupFault?.ObserveThenThrow(rawProcess, job, processInformation.dwProcessId);
                stdinWrite.DisposeLocalCopyOfClientHandle();
                stdoutRead.DisposeLocalCopyOfClientHandle();
                stderrRead.DisposeLocalCopyOfClientHandle();
                stdin = new StreamWriter(stdinWrite) { AutoFlush = true };
                stdinWrite = null;
                stdout = new StreamReader(stdoutRead);
                stdoutRead = null;
                stderr = new StreamReader(stderrRead);
                stderrRead = null;
                stderrDrain = DrainAsync(stderr, cancellationToken);

                child = new ChildProcess(job, rawProcess, rawThread, stdin, stdout, stderr, stderrDrain);
                job = null;
                rawProcess = null;
                rawThread = null;
                stdin = null;
                stdout = null;
                stderr = null;
                stderrDrain = null;

                if (ResumeThread(child._thread) == uint.MaxValue)
                {
                    throw new HostFailure("child-resume-failed");
                }

                var ready = await ReadReadyAsync(child._stdout, readinessTimeout, cancellationToken);
                ReadyProtocol.RequireExact(ready);
                child._stdoutWatch = WatchUnexpectedStdoutAsync(child._stdout, cancellationToken);
                var started = child;
                child = null;
                return started;
            }
        }
        catch
        {
            if (child is not null)
            {
                TryTerminateJob(child._job);
                TryDispose(child);
            }
            else if (rawProcess is not null)
            {
                TryTerminateProcess(rawProcess);
            }

            throw;
        }
        finally
        {
            TryDispose(stdin);
            TryDispose(stdout);
            TryDispose(stderr);
            TryDispose(stdinWrite);
            TryDispose(stdoutRead);
            TryDispose(stderrRead);
            TryDispose(rawThread);
            TryDispose(rawProcess);
            TryDispose(job);
        }
    }

    public void SendStop()
    {
        if (!_stdinClosed)
        {
            _stdin.Write("STOP\n");
        }
    }

    public void CloseStdin()
    {
        if (!_stdinClosed)
        {
            _stdinClosed = true;
            _stdin.Dispose();
        }
    }

    public async Task<bool> WaitForExitAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = deadline - DateTime.UtcNow;
            var result = WaitForSingleObject(_process, checked((uint)Math.Min(100, Math.Max(1, remaining.TotalMilliseconds))));
            if (result == 0)
            {
                try
                {
                    await _stderrDrain.WaitAsync(TimeSpan.FromMilliseconds(Math.Max(1, (deadline - DateTime.UtcNow).TotalMilliseconds)), cancellationToken);
                    await _stdoutWatch;
                    return true;
                }
                catch (TimeoutException)
                {
                    KillJob();
                    return false;
                }
            }

            if (result != 258)
            {
                throw new HostFailure("child-wait-failed");
            }
        }

        return WaitForSingleObject(_process, 0) == 0;
    }

    public bool HasProtocolViolation => _stdoutWatch.IsFaulted;

    public void KillJob() => TerminateJobObject(_job, 1);

    public void Dispose()
    {
        try { CloseStdin(); }
        finally
        {
            try { _stdout.Dispose(); }
            finally
            {
                try { _stderr.Dispose(); }
                finally
                {
                    try { _thread.Dispose(); }
                    finally
                    {
                        try { _process.Dispose(); }
                        finally { _job.Dispose(); }
                    }
                }
            }
        }
    }

    internal static string BuildCommandLine(string executable, ServiceProfile profile, RuntimeBinding? binding) =>
        binding is null
            ? $"\"{executable}\" -I -B -m hermes_windows_bridge.service_child --profile {HostConfiguration.ToConfigValue(profile)}"
            : $"\"{executable}\" -I -B -m hermes_windows_bridge.service_child --profile {HostConfiguration.ToConfigValue(profile)} --runtime-binding \"{binding.BindingPath}\" --runtime-binding-sha256 {binding.Sha256}";

    private static SafeFileHandle Duplicate(SafeFileHandle source)
    {
        if (!DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), out var duplicate, 0, false, 2))
        {
            throw new HostFailure("handle-duplicate-failed");
        }

        return duplicate;
    }

    private static void ConfigureKillOnClose(SafeFileHandle job)
    {
        var information = new JobObjectExtendedLimitInformation { BasicLimitInformation = new JobObjectBasicLimitInformation { LimitFlags = JobObjectLimitKillOnJobClose } };
        if (!SetInformationJobObject(job, ExtendedLimitInformationClass, ref information, Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
        {
            throw new HostFailure("job-configure-failed");
        }
    }

    private static async Task<byte[]> ReadReadyAsync(StreamReader reader, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var bytes = new List<byte>(16);
        while (bytes.Count <= 16)
        {
            var character = new char[1];
            int count;
            try
            {
                count = await reader.ReadAsync(character.AsMemory(), deadline.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new HostFailure("ready-timeout");
            }
            var value = count == 0 ? -1 : character[0];
            if (value < 0)
            {
                throw new HostFailure("ready-eof");
            }

            if (value > 127)
            {
                throw new HostFailure("malformed-ready");
            }

            bytes.Add((byte)value);
            if (value == '\n')
            {
                await RejectAdditionalReadyOutputAsync(reader, cancellationToken);
                return bytes.ToArray();
            }
        }

        throw new HostFailure("malformed-ready");
    }

    private static async Task RejectAdditionalReadyOutputAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        using var probeCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        probeCancellation.CancelAfter(TimeSpan.FromMilliseconds(50));
        var character = new char[1];
        try
        {
            if (await reader.ReadAsync(character.AsMemory(), probeCancellation.Token) != 0)
            {
                throw new HostFailure("malformed-ready");
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // READY 뒤에는 stdout가 계속 열려 있으므로 짧은 무출력 구간만 허용합니다.
        }
    }

    private static async Task WatchUnexpectedStdoutAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var character = new char[1];
        if (await reader.ReadAsync(character.AsMemory(), cancellationToken) != 0)
        {
            throw new HostFailure("malformed-ready");
        }
    }

    private static async Task DrainAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var buffer = new char[1024];
        var remaining = 16 * 1024;
        while (remaining > 0)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken);
            if (read == 0)
            {
                return;
            }

            remaining -= read;
        }

        throw new HostFailure("child-stderr-too-large");
    }

    private static void TryTerminateJob(SafeFileHandle job)
    {
        try { _ = TerminateJobObject(job, 1); }
        catch { }
    }

    private static void TryTerminateProcess(SafeFileHandle process)
    {
        try { _ = TerminateProcess(process, 1); }
        catch { }
    }

    private static void TryDispose(IDisposable? value)
    {
        try { value?.Dispose(); }
        catch { }
    }

    internal sealed class StartupFixtureFault(HostFailure failure) : IDisposable
    {
        private SafeFileHandle? _process;
        private SafeFileHandle? _job;

        internal int? ProcessId { get; private set; }

        internal bool HasProcessHandle => _process is { IsInvalid: false, IsClosed: false };

        internal bool IsObservedJobClosed => _job is { IsClosed: true };

        internal void ObserveThenThrow(SafeFileHandle process, SafeFileHandle job, uint processId)
        {
            _job = job;
            _process = Duplicate(process);
            ProcessId = checked((int)processId);
            throw failure;
        }

        internal bool WaitForObservedExit(TimeSpan timeout)
        {
            if (_process is null)
            {
                throw new InvalidOperationException("startup process was not observed");
            }

            var result = WaitForSingleObject(_process, checked((uint)Math.Max(1, timeout.TotalMilliseconds)));
            return result == 0;
        }

        internal void CleanupObservedFailure()
        {
            if (_process is not null)
            {
                TryTerminateProcess(_process);
            }

            _job?.Dispose();
            _job = null;
        }

        public void Dispose()
        {
            _process?.Dispose();
            _process = null;
            _job = null;
        }
    }

    private sealed class StartupAttributeList : IDisposable
    {
        private IntPtr _attributeList;
        private IntPtr _handles;
        private bool _initialized;

        internal StartupAttributeList(IReadOnlyList<IntPtr> handles)
        {
            if (handles.Count != 3)
            {
                throw new ArgumentException("exactly three standard handles are required", nameof(handles));
            }

            var attributeListSize = IntPtr.Zero;
            _ = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeListSize);
            if (attributeListSize == IntPtr.Zero)
            {
                throw new HostFailure("handle-list-failed");
            }

            try
            {
                _attributeList = Marshal.AllocHGlobal(attributeListSize);
                _handles = Marshal.AllocHGlobal(checked(IntPtr.Size * handles.Count));
                for (var index = 0; index < handles.Count; index++)
                {
                    Marshal.WriteIntPtr(_handles, checked(index * IntPtr.Size), handles[index]);
                }

                if (!InitializeProcThreadAttributeList(_attributeList, 1, 0, ref attributeListSize))
                {
                    throw new HostFailure("handle-list-failed");
                }

                _initialized = true;
                if (!UpdateProcThreadAttribute(_attributeList, 0, (IntPtr)ProcThreadAttributeHandleList, _handles, (IntPtr)(IntPtr.Size * handles.Count), IntPtr.Zero, IntPtr.Zero))
                {
                    throw new HostFailure("handle-list-failed");
                }
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        internal IntPtr Pointer => _attributeList;

        public void Dispose()
        {
            if (_attributeList != IntPtr.Zero)
            {
                if (_initialized)
                {
                    DeleteProcThreadAttributeList(_attributeList);
                }

                Marshal.FreeHGlobal(_attributeList);
                _attributeList = IntPtr.Zero;
                _initialized = false;
            }

            if (_handles != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_handles);
                _handles = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation { public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount; public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation { public JobObjectBasicLimitInformation BasicLimitInformation; public IoCounters IoInfo; public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit; public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed; }

    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInfoEx startupInfo, out ProcessInformation processInformation);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] private static partial SafeFileHandle CreateJobObjectW(IntPtr attributes, string? name);
    [LibraryImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool AssignProcessToJobObject(SafeFileHandle job, SafeFileHandle process);
    [LibraryImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool SetInformationJobObject(SafeFileHandle job, uint informationClass, ref JobObjectExtendedLimitInformation information, int informationLength);
    [LibraryImport("kernel32.dll", SetLastError = true)] private static partial uint ResumeThread(SafeFileHandle thread);
    [LibraryImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool DuplicateHandle(IntPtr sourceProcessHandle, SafeFileHandle sourceHandle, IntPtr targetProcessHandle, out SafeFileHandle targetHandle, uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);
    [LibraryImport("kernel32.dll")] private static partial IntPtr GetCurrentProcess();
    [LibraryImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool TerminateJobObject(SafeFileHandle job, uint exitCode);
    [LibraryImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool TerminateProcess(SafeFileHandle process, uint exitCode);
    [LibraryImport("kernel32.dll", SetLastError = true)] private static partial uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
}
