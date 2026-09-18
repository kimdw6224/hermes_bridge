namespace HermesBridge.ServiceHost;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 2 || args[0] != "--profile")
        {
            return 87;
        }

        try
        {
            return ScmServiceHost.Run(HostConfiguration.ParseProfile(args[1]));
        }
        catch (HostFailure)
        {
            return 87;
        }
    }
}
