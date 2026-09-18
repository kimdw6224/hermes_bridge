using System.Diagnostics;
using System.Text.Json;

namespace HermesBridge.ServiceHost;

public sealed record ReleaseVerification(string ReleaseRoot, string ServiceExecutable)
{
    private static readonly HashSet<string> RequiredProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion", "verified", "releaseRoot", "serviceExecutable",
    };
    internal static Func<Process, IDisposable>? JobAttacherForTest;

    public static ReleaseVerification Parse(string json, string expectedReleaseRoot)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Any(p => !RequiredProperties.Contains(p.Name)) ||
                root.EnumerateObject().Count() != RequiredProperties.Count || root.GetProperty("schemaVersion").GetInt32() != 1 ||
                !root.GetProperty("verified").GetBoolean())
            {
                throw new HostFailure("release-verification-failed");
            }

            var verifiedRoot = Path.GetFullPath(root.GetProperty("releaseRoot").GetString() ?? string.Empty);
            var expectedRoot = Path.GetFullPath(expectedReleaseRoot);
            var executable = Path.GetFullPath(root.GetProperty("serviceExecutable").GetString() ?? string.Empty);
            var expectedExecutable = Path.Combine(expectedRoot, "venv", "Scripts", "python.exe");
            if (!string.Equals(verifiedRoot, expectedRoot, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(executable, expectedExecutable, StringComparison.OrdinalIgnoreCase) || !File.Exists(executable))
            {
                throw new HostFailure("release-verification-failed");
            }

            return new ReleaseVerification(verifiedRoot, executable);
        }
        catch (HostFailure)
        {
            throw;
        }
        catch (Exception)
        {
            throw new HostFailure("release-verification-failed");
        }
    }

    public static async Task<ReleaseVerification> VerifyAsync(string anchorDirectory, HostConfiguration configuration, CancellationToken cancellationToken)
    {
        var verifier = Path.Combine(anchorDirectory, "verify-release.ps1");
        if (!File.Exists(verifier))
        {
            throw new HostFailure("verifier-missing");
        }

        var systemPowerShell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(systemPowerShell))
        {
            throw new HostFailure("powershell-missing");
        }

        using var process = new Process { StartInfo = BuildStartInfo(systemPowerShell, verifier, configuration) };
        if (!process.Start())
        {
            throw new HostFailure("verifier-start-failed");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(120));
        IDisposable? job = null;
        try
        {
            job = (JobAttacherForTest ?? VerificationJob.Attach)(process);
            var stdout = ReadBoundedAsync(process.StandardOutput, 16 * 1024, timeout.Token, () => TryKill(process));
            var stderr = ReadBoundedAsync(process.StandardError, 16 * 1024, timeout.Token, () => TryKill(process));
            await Task.WhenAll(process.WaitForExitAsync(timeout.Token), stdout, stderr);
            var output = stdout.Result;
            if (process.ExitCode != 0)
            {
                throw new HostFailure("release-verification-failed");
            }

            return Parse(output, configuration.ReleaseRoot);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            throw new HostFailure("release-verification-timeout");
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }
        finally
        {
            job?.Dispose();
            if (!process.HasExited)
            {
                TryKill(process);
            }
        }
    }

    private static ProcessStartInfo BuildStartInfo(string powerShell, string verifier, HostConfiguration configuration)
    {
        var result = new ProcessStartInfo(powerShell) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        result.ArgumentList.Add("-NoProfile");
        result.ArgumentList.Add("-NonInteractive");
        result.ArgumentList.Add("-File");
        result.ArgumentList.Add(verifier);
        result.ArgumentList.Add("-ReleaseRoot");
        result.ArgumentList.Add(configuration.ReleaseRoot);
        result.ArgumentList.Add("-ManifestSha256");
        result.ArgumentList.Add(configuration.ManifestSha256);
        return result;
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int limit, CancellationToken cancellationToken, Action overflow)
    {
        var buffer = new char[1024];
        var text = new System.Text.StringBuilder();
        while (true)
        {
            var read = await reader.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return text.ToString();
            }

            if (text.Length + read > limit)
            {
                overflow();
                throw new HostFailure("verifier-output-too-large");
            }

            text.Append(buffer, 0, read);
        }
    }

    private static void TryKill(Process process)
    {
        try { process.Kill(true); } catch (InvalidOperationException) { }
    }
}
