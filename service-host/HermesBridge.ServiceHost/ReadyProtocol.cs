namespace HermesBridge.ServiceHost;

public static class ReadyProtocol
{
    private static ReadOnlySpan<byte> Greeting => "READY 1\n"u8;

    public static void RequireExact(byte[] value)
    {
        if (!value.AsSpan().SequenceEqual(Greeting))
        {
            throw new HostFailure("child-not-ready");
        }
    }
}
