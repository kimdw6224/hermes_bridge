namespace HermesBridge.ServiceHost;

using System.Runtime.ExceptionServices;

public interface IManagedChild
{
    void SendStop();
    void CloseStdin();
    Task<bool> WaitForExitAsync(TimeSpan timeout, CancellationToken cancellationToken);
    void KillJob();
}

public static class ChildLifecycle
{
    public static async Task<bool> StopAsync(IManagedChild child, TimeSpan gracePeriod, CancellationToken cancellationToken)
    {
        Exception? failure = null;
        try
        {
            child.SendStop();
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        try
        {
            child.CloseStdin();
        }
        catch (Exception exception)
        {
            failure ??= exception;
        }

        var exited = false;
        try
        {
            exited = await child.WaitForExitAsync(gracePeriod, CancellationToken.None);
        }
        catch (Exception exception)
        {
            failure ??= exception;
        }

        var forcedKill = !exited || failure is not null;
        if (forcedKill)
        {
            child.KillJob();
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }

        return forcedKill;
    }
}
