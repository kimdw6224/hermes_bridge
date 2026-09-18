using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace HermesBridge.ServiceHost;

public sealed record RuntimeBinding(string BindingPath, string Sha256)
{
    private static readonly HashSet<string> RequiredProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion", "profile", "contextNonce", "configPath", "configSha256", "workerSid",
    };

    public static RuntimeBinding Load(AnchorContext anchor, HostConfiguration configuration, ServiceProfile profile)
    {
        if (!configuration.HasRuntimeBinding || anchor.ContextNonce is null || configuration.RuntimeBindingPath is null || configuration.RuntimeBindingSha256 is null)
        {
            throw new HostFailure("runtime-binding-required");
        }

        var expectedPath = System.IO.Path.GetFullPath(anchor.ExpectedRuntimeBindingPath(profile));
        if (!string.Equals(configuration.RuntimeBindingPath, expectedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new HostFailure("runtime-binding-path-mismatch");
        }

        AnchorDirectory.RequireProtectedFile(expectedPath, anchor.ProgramRoot);
        var bindingBytes = ReadBoundedFile(expectedPath);
        if (!string.Equals(HashBytes(bindingBytes), configuration.RuntimeBindingSha256, StringComparison.Ordinal))
        {
            throw new HostFailure("runtime-binding-digest-mismatch");
        }

        try
        {
            using var document = JsonDocument.Parse(bindingBytes);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new HostFailure("invalid-runtime-binding");
            }

            var names = root.EnumerateObject().Select(property => property.Name).ToArray();
            var workerSidText = root.GetProperty("workerSid").GetString();
            if (names.Length != RequiredProperties.Count || names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
                names.Any(name => !RequiredProperties.Contains(name)) || root.GetProperty("schemaVersion").GetInt32() != 1 ||
                !string.Equals(root.GetProperty("profile").GetString(), HostConfiguration.ToConfigValue(profile), StringComparison.Ordinal) ||
                !string.Equals(root.GetProperty("contextNonce").GetString(), anchor.ContextNonce, StringComparison.Ordinal) ||
                !string.Equals(System.IO.Path.GetFullPath(root.GetProperty("configPath").GetString() ?? string.Empty), anchor.ExpectedConfigPath, StringComparison.OrdinalIgnoreCase) ||
                !IsLowerHex(root.GetProperty("configSha256").GetString() ?? string.Empty) ||
                string.IsNullOrWhiteSpace(workerSidText))
            {
                throw new HostFailure("invalid-runtime-binding");
            }

            var workerSid = new SecurityIdentifier(workerSidText);
            if (workerSid.AccountDomainSid is null)
            {
                throw new HostFailure("invalid-runtime-binding");
            }
            var configPath = anchor.ExpectedConfigPath;
            AnchorDirectory.RequireProtectedFile(configPath, anchor.ExpectedProgramDataRoot);
            if (!string.Equals(HashBytes(ReadBoundedFile(configPath)), root.GetProperty("configSha256").GetString(), StringComparison.Ordinal))
            {
                throw new HostFailure("runtime-config-digest-mismatch");
            }

            return new RuntimeBinding(expectedPath, configuration.RuntimeBindingSha256);
        }
        catch (HostFailure)
        {
            throw;
        }
        catch (Exception)
        {
            throw new HostFailure("invalid-runtime-binding");
        }
    }

    private static bool IsLowerHex(string value) => value.Length == 64 && value.All(character =>
        (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'));

    private static byte[] ReadBoundedFile(string path)
    {
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > 64 * 1024)
        {
            throw new HostFailure("invalid-runtime-binding");
        }

        using var buffer = new MemoryStream(checked((int)stream.Length));
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static string HashBytes(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
