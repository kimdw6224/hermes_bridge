namespace HermesBridge.ServiceHost;

internal enum ServiceTerminalOutcome
{
    GracefulStop,
    StartupFailure,
    ForcedStop,
    UnexpectedChildExit,
}

internal static class ServiceExitPolicy
{
    internal static bool ShouldReportStopped(ServiceTerminalOutcome outcome) => outcome != ServiceTerminalOutcome.UnexpectedChildExit;

    internal static int ProcessExitCode(ServiceTerminalOutcome outcome) => outcome switch
    {
        ServiceTerminalOutcome.GracefulStop => 0,
        ServiceTerminalOutcome.StartupFailure => 1001,
        ServiceTerminalOutcome.ForcedStop => 1007,
        ServiceTerminalOutcome.UnexpectedChildExit => 1006,
        _ => 1001,
    };
}
