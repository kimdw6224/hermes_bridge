using HermesBridge.ServiceHost;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

if (args.Length > 0)
{
    return FixtureChild.Run(args);
}

var tests = new (string Name, Action Body)[]
{
    ("invalid-config", HostConfigRejectsInvalidInput),
    ("schema2-config", HostConfigAcceptsExactRuntimeBinding),
    ("runtime-binding-argv", RuntimeBindingCommandLineIsFixed),
    ("blocked-verifier", VerifierRejectsUnverifiedOutput),
    ("ready-parser", ReadyParserAcceptsOnlyExactGreeting),
    ("lifecycle", LifecycleKillsAfterGraceTimeout),
    ("native-lifecycle", NativeChildUsesPipesAndJob),
    ("native-handle-list", NativeChildCannotInheritSentinelHandle),
    ("native-startup-failure-cleanup", NativeChildCleansStartupFailure),
    ("malformed-ready", NativeChildRejectsMalformedReadiness),
    ("duplicate-ready", NativeChildRejectsDuplicateReadiness),
    ("delayed-duplicate-ready", NativeChildDetectsDelayedDuplicateReadiness),
    ("hung-ready-job-kill", NativeChildKillsHungReadiness),
    ("slow-ready-timeout", NativeChildRejectsSlowReadiness),
    ("service-exit-policy", ServiceExitPolicyPreservesRecovery),
    ("verifier-attach-cleanup", VerifierAttachFailureKillsProcess),
};

var failures = new List<string>();
foreach (var test in tests)
{
    try
    {
        test.Body();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception exception)
    {
        failures.Add(test.Name);
        Console.Error.WriteLine($"FAIL {test.Name}: {exception.Message}");
    }
}

return failures.Count == 0 ? 0 : 1;

static void HostConfigRejectsInvalidInput()
{
    var invalid = """{"schemaVersion":1,"profile":"gateway","releaseRoot":"C:\\release","manifestSha256":"abc"}""";
    AssertThrows(() => HostConfiguration.Parse(invalid));
}

static void HostConfigAcceptsExactRuntimeBinding()
{
    var bindingPath = "C:\\Program Files\\HermesWindowsBridgeEval-0123456789abcdef0123456789abcdef\\bindings\\gateway.json";
    var bindingSha = new string('a', 64);
    var configuration = HostConfiguration.Parse(JsonSerializer.Serialize(new
    {
        schemaVersion = 2,
        profile = "gateway",
        releaseRoot = "C:\\release",
        manifestSha256 = bindingSha,
        runtimeBindingPath = bindingPath,
        runtimeBindingSha256 = bindingSha,
    }));
    Assert(configuration.HasRuntimeBinding && configuration.RuntimeBindingPath == bindingPath && configuration.RuntimeBindingSha256 == bindingSha, "schema2 must retain the exact binding pair");
    var missingBindingHash = JsonSerializer.Serialize(new
    {
        schemaVersion = 2,
        profile = "gateway",
        releaseRoot = "C:\\release",
        manifestSha256 = bindingSha,
        runtimeBindingPath = bindingPath,
    });
    AssertThrows(() => HostConfiguration.Parse(missingBindingHash));
}

static void RuntimeBindingCommandLineIsFixed()
{
    var binding = new RuntimeBinding("C:\\Program Files\\HermesWindowsBridgeEval-0123456789abcdef0123456789abcdef\\bindings\\gateway.json", new string('b', 64));
    var command = ChildProcess.BuildCommandLine("C:\\release\\venv\\Scripts\\python.exe", ServiceProfile.Gateway, binding);
    Assert(command == $"\"C:\\release\\venv\\Scripts\\python.exe\" -I -B -m hermes_windows_bridge.service_child --profile gateway --runtime-binding \"{binding.BindingPath}\" --runtime-binding-sha256 {binding.Sha256}", "schema2 must append only the verified binding pair");
    Assert(ChildProcess.BuildCommandLine("C:\\release\\venv\\Scripts\\python.exe", ServiceProfile.Gateway, null) ==
        "\"C:\\release\\venv\\Scripts\\python.exe\" -I -B -m hermes_windows_bridge.service_child --profile gateway", "schema1 must preserve the legacy fixed child argv");
}

static void VerifierRejectsUnverifiedOutput()
{
    var output = """{"schemaVersion":1,"verified":false,"releaseRoot":"C:\\release","serviceExecutable":"C:\\release\\python.exe"}""";
    AssertThrows(() => ReleaseVerification.Parse(output, "C:\\release"));
}

static void ReadyParserAcceptsOnlyExactGreeting()
{
    ReadyProtocol.RequireExact("READY 1\n"u8.ToArray());
    AssertThrows(() => ReadyProtocol.RequireExact("READY 1\nextra"u8.ToArray()));
    AssertThrows(() => ReadyProtocol.RequireExact("READY 2\n"u8.ToArray()));
}

static void LifecycleKillsAfterGraceTimeout()
{
    var child = new FakeChild(exitsDuringGrace: false);
    ChildLifecycle.StopAsync(child, TimeSpan.Zero, CancellationToken.None).GetAwaiter().GetResult();
    Assert(child.StopWritten && child.StdinClosed && child.JobKilled, "stop timeout must close the job");
}

static void NativeChildUsesPipesAndJob()
{
    using var child = ChildProcess.StartFixtureAsync(Environment.ProcessPath!, "--fixture-child ready", AppContext.BaseDirectory, TimeSpan.FromSeconds(2), CancellationToken.None).GetAwaiter().GetResult();
    ChildLifecycle.StopAsync(child, TimeSpan.FromSeconds(2), CancellationToken.None).GetAwaiter().GetResult();
    Assert(child.WaitForExitAsync(TimeSpan.FromSeconds(1), CancellationToken.None).GetAwaiter().GetResult(), "child must exit after STOP");
}

static void NativeChildCannotInheritSentinelHandle()
{
    using var sentinel = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
    var sentinelHandle = sentinel.ClientSafePipeHandle.DangerousGetHandle().ToInt64();
    using var child = ChildProcess.StartFixtureAsync(Environment.ProcessPath!, $"--fixture-child sentinel {sentinelHandle}", AppContext.BaseDirectory, TimeSpan.FromSeconds(2), CancellationToken.None).GetAwaiter().GetResult();
    sentinel.DisposeLocalCopyOfClientHandle();
    child.SendStop();
    child.CloseStdin();
    Assert(child.WaitForExitAsync(TimeSpan.FromSeconds(1), CancellationToken.None).GetAwaiter().GetResult(), "stdio child must exit after STOP");
    using var reader = new StreamReader(sentinel);
    Assert(reader.ReadToEnd() == string.Empty, "child must not inherit an unrelated sentinel handle");
}

static void NativeChildCleansStartupFailure()
{
    var injectedFailure = new HostFailure("fixture-startup-failure");
    using var fault = new ChildProcess.StartupFixtureFault(injectedFailure);
    try
    {
        var failure = AssertHostFailure(() => ChildProcess.StartFixtureAsync(Environment.ProcessPath!, "--fixture-child ready", AppContext.BaseDirectory, TimeSpan.FromSeconds(2), CancellationToken.None, fault).GetAwaiter().GetResult());
        var sameFailure = ReferenceEquals(failure, injectedFailure);
        var hasProcessIdentity = fault.ProcessId is > 0;
        var hasProcessHandle = fault.HasProcessHandle;
        var processExited = hasProcessHandle && fault.WaitForObservedExit(TimeSpan.FromSeconds(2));
        var jobClosed = fault.IsObservedJobClosed;
        Console.WriteLine($"OBS native-startup-failure-cleanup sameFailure={sameFailure} processIdentity={hasProcessIdentity} processHandle={hasProcessHandle} processExited={processExited} jobClosed={jobClosed}");
        Assert(sameFailure, "injected startup failure instance must be preserved");
        Assert(hasProcessIdentity, "fault seam must retain the exact child process identity");
        Assert(hasProcessHandle, "fault seam must retain an owned observation handle");
        Assert(processExited, "post-job startup failure must terminate the observed child");
        Assert(jobClosed, "post-job startup failure must close the observed job owner");
    }
    finally
    {
        fault.CleanupObservedFailure();
    }
}

static void NativeChildRejectsMalformedReadiness()
{
    AssertThrows(() => ChildProcess.StartFixtureAsync(Environment.ProcessPath!, "--fixture-child malformed", AppContext.BaseDirectory, TimeSpan.FromSeconds(2), CancellationToken.None).GetAwaiter().GetResult());
}

static void NativeChildRejectsDuplicateReadiness()
{
    AssertThrows(() => ChildProcess.StartFixtureAsync(Environment.ProcessPath!, "--fixture-child duplicate", AppContext.BaseDirectory, TimeSpan.FromSeconds(2), CancellationToken.None).GetAwaiter().GetResult());
}

static void NativeChildDetectsDelayedDuplicateReadiness()
{
    using var child = ChildProcess.StartFixtureAsync(Environment.ProcessPath!, "--fixture-child delayedduplicate", AppContext.BaseDirectory, TimeSpan.FromSeconds(2), CancellationToken.None).GetAwaiter().GetResult();
    Thread.Sleep(300);
    Assert(child.HasProtocolViolation, "late stdout after READY must violate the protocol");
}

static void NativeChildKillsHungReadiness()
{
    var marker = Path.GetTempFileName();
    try
    {
        AssertThrows(() => ChildProcess.StartFixtureAsync(Environment.ProcessPath!, $"--fixture-child hang \"{marker}\"", AppContext.BaseDirectory, TimeSpan.FromMilliseconds(250), CancellationToken.None).GetAwaiter().GetResult());
        var processId = int.Parse(File.ReadAllText(marker));
        try
        {
            using var process = Process.GetProcessById(processId);
            Assert(process.HasExited, "hung child must be terminated with its job");
        }
        catch (ArgumentException)
        {
            // 종료된 process ID가 OS table에서 제거된 정상 경로입니다.
        }
    }
    finally
    {
        File.Delete(marker);
    }
}

static void NativeChildRejectsSlowReadiness()
{
    AssertThrows(() => ChildProcess.StartFixtureAsync(Environment.ProcessPath!, "--fixture-child slow", AppContext.BaseDirectory, TimeSpan.FromMilliseconds(250), CancellationToken.None).GetAwaiter().GetResult());
}

static void ServiceExitPolicyPreservesRecovery()
{
    Assert(!ServiceExitPolicy.ShouldReportStopped(ServiceTerminalOutcome.UnexpectedChildExit), "unexpected child exit must not report STOPPED");
    Assert(ServiceExitPolicy.ShouldReportStopped(ServiceTerminalOutcome.GracefulStop), "graceful stop must report STOPPED");
    Assert(ServiceExitPolicy.ShouldReportStopped(ServiceTerminalOutcome.ForcedStop), "forced stop must report STOPPED");
    Assert(ServiceExitPolicy.ProcessExitCode(ServiceTerminalOutcome.UnexpectedChildExit) == 1006, "unexpected child exit code must be fixed");
}

static void VerifierAttachFailureKillsProcess()
{
    var anchor = Path.Combine(Path.GetTempPath(), $"hermes-host-{Guid.NewGuid():N}");
    Directory.CreateDirectory(anchor);
    var pidPath = Path.Combine(anchor, "pid.txt");
    try
    {
        File.WriteAllText(Path.Combine(anchor, "verify-release.ps1"), "param([string]$ReleaseRoot,[string]$ManifestSha256)\n[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'pid.txt'), $PID)\nStart-Sleep -Seconds 30\n");
        ReleaseVerification.JobAttacherForTest = _ =>
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
            while (!File.Exists(pidPath) && DateTime.UtcNow < deadline)
            {
                Thread.Sleep(10);
            }

            throw new HostFailure("test-attach-failure");
        };
        var configuration = new HostConfiguration(1, ServiceProfile.Gateway, anchor, new string('a', 64), null, null);
        AssertThrows(() => ReleaseVerification.VerifyAsync(anchor, configuration, CancellationToken.None).GetAwaiter().GetResult());
        var processId = int.Parse(File.ReadAllText(pidPath));
        try
        {
            using var process = Process.GetProcessById(processId);
            Assert(process.HasExited, "verifier must be killed when job attachment fails");
        }
        catch (ArgumentException)
        {
            // 이미 process table에서 제거된 종료 경로입니다.
        }
    }
    finally
    {
        ReleaseVerification.JobAttacherForTest = null;
        Directory.Delete(anchor, recursive: true);
    }
}

static void AssertThrows(Action action)
{
    _ = AssertHostFailure(action);
}

static HostFailure AssertHostFailure(Action action)
{
    try
    {
        action();
    }
    catch (HostFailure failure)
    {
        return failure;
    }

    throw new InvalidOperationException("HostFailure was expected");
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

file sealed class FakeChild(bool exitsDuringGrace) : IManagedChild
{
    public bool StopWritten { get; private set; }
    public bool StdinClosed { get; private set; }
    public bool JobKilled { get; private set; }

    public void SendStop() => StopWritten = true;

    public void CloseStdin() => StdinClosed = true;

    public Task<bool> WaitForExitAsync(TimeSpan timeout, CancellationToken cancellationToken) => Task.FromResult(exitsDuringGrace);

    public void KillJob() => JobKilled = true;
}

file static class FixtureChild
{
    public static int Run(string[] arguments)
    {
        if (arguments.Length < 2 || arguments[0] != "--fixture-child")
        {
            return -1;
        }

        if (arguments[1] == "hang")
        {
            File.WriteAllText(arguments[2], Environment.ProcessId.ToString());
            Thread.Sleep(Timeout.Infinite);
            return 3;
        }

        if (arguments[1] == "delayedduplicate")
        {
            Console.Write("READY 1\n");
            Console.Out.Flush();
            Thread.Sleep(100);
            Console.Write("READY 1\n");
            Console.Out.Flush();
            Thread.Sleep(Timeout.Infinite);
            return 4;
        }

        if (arguments[1] == "slow")
        {
            Console.Write('R');
            Console.Out.Flush();
            Thread.Sleep(500);
            return 5;
        }

        if (arguments[1] == "sentinel")
        {
            Console.Write("READY 1\n");
            Console.Out.Flush();
            if (Console.ReadLine() == "STOP")
            {
                TryWriteSentinel(arguments[2]);
                return 0;
            }

            return 2;
        }

        Console.Write(arguments[1] == "ready" ? "READY 1\n" : arguments[1] == "duplicate" ? "READY 1\nREADY 1\n" : "BROKEN\n");
        Console.Out.Flush();
        if (arguments[1] != "ready")
        {
            return 0;
        }

        return Console.ReadLine() == "STOP" ? 0 : 2;
    }

    private static void TryWriteSentinel(string rawHandle)
    {
        try
        {
            using var handle = new SafeFileHandle(new IntPtr(long.Parse(rawHandle)), ownsHandle: false);
            using var stream = new FileStream(handle, FileAccess.Write, 1, isAsync: false);
            stream.Write("SENTINEL\n"u8);
        }
        catch (Exception)
        {
            // HANDLE_LIST에 없는 inheritable handle은 child에서 사용할 수 없어야 합니다.
        }
    }
}
