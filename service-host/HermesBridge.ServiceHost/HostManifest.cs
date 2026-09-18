using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HermesBridge.ServiceHost;

public static class HostManifest
{
    private static readonly HashSet<string> RootProperties = new(StringComparer.Ordinal) { "schemaVersion", "hostDigest", "profile", "files" };
    private static readonly HashSet<string> FileProperties = new(StringComparer.Ordinal) { "relativePath", "sha256", "size" };

    public static void Validate(AnchorContext anchor, ServiceProfile profile)
    {
        var path = Path.Combine(anchor.Directory, "host-manifest.json");
        if (!File.Exists(path) || new FileInfo(path).Length > 4 * 1024 * 1024)
        {
            throw new HostFailure("invalid-host-manifest");
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            RequireExactProperties(root, RootProperties);
            var declaredDigest = root.GetProperty("hostDigest").GetString() ?? string.Empty;
            if (root.GetProperty("schemaVersion").GetInt32() != 1 || !IsLowerHex(declaredDigest) ||
                !string.Equals(declaredDigest, anchor.Digest, StringComparison.Ordinal) ||
                !string.Equals(root.GetProperty("profile").GetString(), HostConfiguration.ToConfigValue(profile), StringComparison.Ordinal))
            {
                throw new HostFailure("invalid-host-manifest");
            }

            var files = root.GetProperty("files").EnumerateArray().Select(item => ParseFile(item, anchor.Directory)).OrderBy(file => file.RelativePath, StringComparer.Ordinal).ToArray();
            if (files.Length == 0 || files.Select(file => file.RelativePath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != files.Length ||
                !files.SequenceEqual(files.OrderBy(file => file.RelativePath, StringComparer.Ordinal)))
            {
                throw new HostFailure("invalid-host-manifest");
            }

            var actualFiles = Directory.EnumerateFiles(anchor.Directory, "*", SearchOption.AllDirectories)
                .Select(path => ToRelativePath(anchor.Directory, path)).Where(path => path != "host-manifest.json")
                .OrderBy(path => path, StringComparer.Ordinal).ToArray();
            if (!actualFiles.SequenceEqual(files.Select(file => file.RelativePath), StringComparer.Ordinal))
            {
                throw new HostFailure("host-inventory-mismatch");
            }

            foreach (var file in files)
            {
                var fullPath = Path.Combine(anchor.Directory, file.RelativePath.Replace('/', Path.DirectorySeparatorChar));
                if (new FileInfo(fullPath).Length != file.Size || !string.Equals(HashFile(fullPath), file.Sha256, StringComparison.Ordinal))
                {
                    throw new HostFailure("host-inventory-mismatch");
                }
            }

            var canonical = string.Concat(files.Select(file => $"{file.RelativePath}|{file.Sha256}|{file.Size}\n"));
            if (!string.Equals(HashText(canonical), declaredDigest, StringComparison.Ordinal))
            {
                throw new HostFailure("host-digest-mismatch");
            }
        }
        catch (HostFailure)
        {
            throw;
        }
        catch (JsonException)
        {
            throw new HostFailure("invalid-host-manifest");
        }
        catch (InvalidOperationException)
        {
            throw new HostFailure("invalid-host-manifest");
        }
        catch (ArgumentException)
        {
            throw new HostFailure("invalid-host-manifest");
        }
    }

    private static HostFile ParseFile(JsonElement value, string anchor)
    {
        RequireExactProperties(value, FileProperties);
        var relativePath = value.GetProperty("relativePath").GetString() ?? string.Empty;
        var hash = value.GetProperty("sha256").GetString() ?? string.Empty;
        var size = value.GetProperty("size").GetInt64();
        if (!IsSafeRelativePath(relativePath) || !IsLowerHex(hash) || size < 0 || !File.Exists(Path.Combine(anchor, relativePath.Replace('/', Path.DirectorySeparatorChar))))
        {
            throw new HostFailure("invalid-host-manifest");
        }

        return new HostFile(relativePath, hash, size);
    }

    private static void RequireExactProperties(JsonElement value, HashSet<string> properties)
    {
        var names = value.EnumerateObject().Select(property => property.Name).ToArray();
        if (value.ValueKind != JsonValueKind.Object || names.Length != properties.Count || names.Distinct(StringComparer.Ordinal).Count() != names.Length || names.Any(name => !properties.Contains(name)))
        {
            throw new HostFailure("invalid-host-manifest");
        }
    }

    private static bool IsSafeRelativePath(string path) => !string.IsNullOrEmpty(path) && !Path.IsPathRooted(path) && !path.Contains('\\') &&
        !path.Contains(':') && !path.StartsWith('/') && !path.Split('/').Any(part => part is "" or "." or "..");

    private static string ToRelativePath(string anchor, string path) => Path.GetRelativePath(anchor, path).Replace(Path.DirectorySeparatorChar, '/');
    private static bool IsLowerHex(string value) => value.Length == 64 && value.All(character => (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'));
    private static string HashFile(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
    private static string HashText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    private sealed record HostFile(string RelativePath, string Sha256, long Size);
}
