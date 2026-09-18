using System.Text.Json;

namespace HermesBridge.ServiceHost;

public enum ServiceProfile
{
    Gateway,
    Privileged,
}

public sealed record HostConfiguration(
    int SchemaVersion,
    ServiceProfile Profile,
    string ReleaseRoot,
    string ManifestSha256,
    string? RuntimeBindingPath,
    string? RuntimeBindingSha256)
{
    private static readonly HashSet<string> Schema1Properties = new(StringComparer.Ordinal)
    {
        "schemaVersion", "profile", "releaseRoot", "manifestSha256",
    };
    private static readonly HashSet<string> Schema2Properties = new(StringComparer.Ordinal)
    {
        "schemaVersion", "profile", "releaseRoot", "manifestSha256", "runtimeBindingPath", "runtimeBindingSha256",
    };

    public bool HasRuntimeBinding => SchemaVersion == 2;

    public static HostConfiguration Load(string path)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length > 64 * 1024)
        {
            throw new HostFailure("invalid-config");
        }

        return Parse(File.ReadAllText(path));
    }

    public static HostConfiguration Parse(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new HostFailure("invalid-config");
            }

            var schemaVersion = root.GetProperty("schemaVersion").GetInt32();
            var expectedProperties = schemaVersion switch
            {
                1 => Schema1Properties,
                2 => Schema2Properties,
                _ => throw new HostFailure("invalid-config"),
            };
            var names = root.EnumerateObject().Select(property => property.Name).ToArray();
            if (names.Length != expectedProperties.Count || names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
                names.Any(name => !expectedProperties.Contains(name)))
            {
                throw new HostFailure("invalid-config");
            }

            var profile = ParseProfile(root.GetProperty("profile").GetString());
            var releaseRoot = root.GetProperty("releaseRoot").GetString();
            var manifestSha256 = root.GetProperty("manifestSha256").GetString();
            if (string.IsNullOrWhiteSpace(releaseRoot) || !Path.IsPathFullyQualified(releaseRoot) ||
                string.IsNullOrWhiteSpace(manifestSha256) || !IsLowerHex(manifestSha256, 64))
            {
                throw new HostFailure("invalid-config");
            }

            var runtimeBindingPath = schemaVersion == 2 ? root.GetProperty("runtimeBindingPath").GetString() : null;
            var runtimeBindingSha256 = schemaVersion == 2 ? root.GetProperty("runtimeBindingSha256").GetString() : null;
            if (schemaVersion == 2 && (string.IsNullOrWhiteSpace(runtimeBindingPath) || !Path.IsPathFullyQualified(runtimeBindingPath) ||
                string.IsNullOrWhiteSpace(runtimeBindingSha256) || !IsLowerHex(runtimeBindingSha256, 64)))
            {
                throw new HostFailure("invalid-config");
            }

            return new HostConfiguration(
                schemaVersion,
                profile,
                Path.GetFullPath(releaseRoot),
                manifestSha256,
                runtimeBindingPath is null ? null : Path.GetFullPath(runtimeBindingPath),
                runtimeBindingSha256);
        }
        catch (HostFailure)
        {
            throw;
        }
        catch (JsonException)
        {
            throw new HostFailure("invalid-config");
        }
        catch (InvalidOperationException)
        {
            throw new HostFailure("invalid-config");
        }
        catch (ArgumentException)
        {
            throw new HostFailure("invalid-config");
        }
    }

    public static ServiceProfile ParseProfile(string? value) => value switch
    {
        "gateway" => ServiceProfile.Gateway,
        "privileged" => ServiceProfile.Privileged,
        _ => throw new HostFailure("invalid-profile"),
    };

    public static string ToConfigValue(ServiceProfile profile) => profile switch
    {
        ServiceProfile.Gateway => "gateway",
        ServiceProfile.Privileged => "privileged",
        _ => throw new HostFailure("invalid-profile"),
    };

    private static bool IsLowerHex(string value, int length) => value.Length == length && value.All(c =>
        (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
}
