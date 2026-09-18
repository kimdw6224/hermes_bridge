using System.Runtime.InteropServices;

namespace HermesBridge.ServiceHost;

internal sealed class ScmServiceHost
{
    private const uint StartWaitHintMilliseconds = 120000;
    private const uint StopWaitHintMilliseconds = 15000;
    private readonly ServiceProfile _profile;
    private readonly AnchorContext _anchor;
    private readonly string _serviceName;
    private readonly ManualResetEventSlim _stopRequested = new(false);
    private readonly ScmNative.ServiceMain _serviceMain;
    private readonly ScmNative.HandlerEx _handler;
    private readonly Action<int> _terminateProcess;
    private IntPtr _statusHandle;
    private ChildProcess? _child;
    private uint _checkpoint;
    private int _finalExitCode;

    private ScmServiceHost(ServiceProfile profile, AnchorContext anchor, Action<int>? terminateProcess = null)
    {
        _profile = profile;
        _anchor = anchor;
        _serviceName = anchor.ExpectedServiceName(profile);
        _serviceMain = ServiceMain;
        _handler = HandleControl;
        _terminateProcess = terminateProcess ?? Environment.Exit;
    }

    public static int Run(ServiceProfile profile)
    {
        var host = new ScmServiceHost(profile, AnchorDirectory.Require(profile));
        var table = new[]
        {
            new ScmNative.ServiceTableEntry { ServiceName = host._serviceName, ServiceProc = host._serviceMain },
            new ScmNative.ServiceTableEntry(),
        };
        return ScmNative.StartServiceCtrlDispatcher(table) ? host._finalExitCode : Marshal.GetLastWin32Error();
    }

    private void ServiceMain(uint argumentCount, IntPtr arguments)
    {
        _statusHandle = ScmNative.RegisterServiceCtrlHandlerEx(_serviceName, _handler, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero)
        {
            return;
        }

        Report(ScmNative.ServiceStartPending, 0, 0, 0, StartWaitHintMilliseconds);
        using var startCancellation = new CancellationTokenSource();
        var startup = Task.Run(() => StartAsync(startCancellation.Token));
        while (!startup.IsCompleted)
        {
            if (_stopRequested.Wait(TimeSpan.FromSeconds(2)))
            {
                startCancellation.Cancel();
                break;
            }

            Report(ScmNative.ServiceStartPending, 0, 0, 0, StartWaitHintMilliseconds);
        }

        try
        {
            _child = startup.GetAwaiter().GetResult();
            if (_stopRequested.IsSet)
            {
                ReportStopped(StopChild() ? 1007u : 0u);
                return;
            }

            Report(ScmNative.ServiceRunning, ScmNative.ServiceAcceptStop | ScmNative.ServiceAcceptShutdown, 0, 0, 0);
            while (!_stopRequested.Wait(TimeSpan.FromMilliseconds(250)))
            {
                if (_child.HasProtocolViolation)
                {
                    _child.Dispose();
                    _child = null;
                    ReportStopped(1003);
                    return;
                }

                if (_child.WaitForExitAsync(TimeSpan.Zero, CancellationToken.None).GetAwaiter().GetResult())
                {
                    _child.Dispose();
                    _child = null;
                    TerminateUnexpectedChild();
                    return;
                }
            }

            ReportStopped(StopChild() ? 1007u : 0u);
        }
        catch (OperationCanceledException) when (_stopRequested.IsSet)
        {
            ReportStopped(0);
        }
        catch (HostFailure failure)
        {
            _child?.Dispose();
            ReportStopped(MapFailure(failure));
        }
        catch (Exception)
        {
            _child?.Dispose();
            ReportStopped(1001);
        }
    }

    private async Task<ChildProcess> StartAsync(CancellationToken cancellationToken)
    {
        HostManifest.Validate(_anchor, _profile);
        var configuration = HostConfiguration.Load(Path.Combine(_anchor.Directory, "host-config.json"));
        if (configuration.Profile != _profile)
        {
            throw new HostFailure("profile-mismatch");
        }

        if ((_anchor.ContextNonce is null) != !configuration.HasRuntimeBinding)
        {
            throw new HostFailure("runtime-binding-anchor-mismatch");
        }

        var binding = configuration.HasRuntimeBinding ? RuntimeBinding.Load(_anchor, configuration, _profile) : null;
        var verification = await ReleaseVerification.VerifyAsync(_anchor.Directory, configuration, cancellationToken);
        return await ChildProcess.StartAsync(verification, _profile, binding, cancellationToken);
    }

    private bool StopChild()
    {
        if (_child is null)
        {
            return false;
        }

        Report(ScmNative.ServiceStopPending, 0, 0, 0, StopWaitHintMilliseconds);
        try
        {
            return ChildLifecycle.StopAsync(_child, TimeSpan.FromSeconds(15), CancellationToken.None).GetAwaiter().GetResult();
        }
        finally
        {
            _child.Dispose();
            _child = null;
        }
    }

    private uint HandleControl(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control is ScmNative.ServiceControlStop or ScmNative.ServiceControlShutdown)
        {
            _stopRequested.Set();
        }

        return 0;
    }

    private void ReportStopped(uint serviceSpecificExitCode)
    {
        _finalExitCode = checked((int)serviceSpecificExitCode);
        if (serviceSpecificExitCode == 0)
        {
            Report(ScmNative.ServiceStopped, 0, 0, 0, 0);
            return;
        }

        Report(ScmNative.ServiceStopped, 0, ScmNative.ErrorServiceSpecificError, serviceSpecificExitCode, 0);
    }

    private void TerminateUnexpectedChild()
    {
        _finalExitCode = ServiceExitPolicy.ProcessExitCode(ServiceTerminalOutcome.UnexpectedChildExit);
        // 기본 SCM failure-actions 플래그는 STOPPED 종료를 실패로 보지 않으므로, 이 경로만 상태를 보고하지 않고 종료합니다.
        _terminateProcess(_finalExitCode);
    }

    private void Report(uint state, uint controlsAccepted, uint win32ExitCode, uint serviceSpecificExitCode, uint waitHint)
    {
        var status = new ScmNative.ServiceStatus
        {
            ServiceType = ScmNative.ServiceWin32OwnProcess,
            CurrentState = state,
            ControlsAccepted = controlsAccepted,
            Win32ExitCode = win32ExitCode,
            ServiceSpecificExitCode = serviceSpecificExitCode,
            CheckPoint = state is ScmNative.ServiceStartPending or ScmNative.ServiceStopPending ? ++_checkpoint : 0,
            WaitHint = waitHint,
        };
        if (!ScmNative.SetServiceStatus(_statusHandle, ref status))
        {
            _finalExitCode = 1001;
        }
    }

    private static uint MapFailure(HostFailure failure) => failure.Code switch
    {
        "release-verification-timeout" => 1002,
        "malformed-ready" or "child-not-ready" => 1003,
        "ready-timeout" or "ready-eof" => 1004,
        "child-start-failed" or "child-resume-failed" => 1005,
        _ => 1001,
    };
}
