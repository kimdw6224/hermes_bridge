namespace HermesBridge.ServiceHost;

public sealed class HostFailure(string code) : Exception(code)
{
    public string Code { get; } = code;
}
