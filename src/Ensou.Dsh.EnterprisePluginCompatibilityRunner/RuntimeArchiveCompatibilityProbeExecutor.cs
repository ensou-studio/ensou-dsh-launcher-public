using System.Diagnostics;
using System.Security.Cryptography;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.EnterprisePluginCompatibilityRunner;

internal sealed class RuntimeArchiveCompatibilityProbeExecutor : ICompatibilityProbeExecutor
{
    internal const string InternalProbeSwitch = "--internal-compatibility-probe";
    private const int MaximumEvidenceBytes = 4 * 1024 * 1024;
    private readonly string _runnerPath;
    private readonly CompatibilityRunnerIdentity _runnerIdentity;
    private readonly TimeSpan _timeout;

    public RuntimeArchiveCompatibilityProbeExecutor(
        string runnerPath,
        CompatibilityRunnerIdentity runnerIdentity)
        : this(runnerPath, runnerIdentity, TimeSpan.FromHours(4))
    {
    }

    internal RuntimeArchiveCompatibilityProbeExecutor(
        string runnerPath,
        CompatibilityRunnerIdentity runnerIdentity,
        TimeSpan timeout)
    {
        _runnerPath = Path.GetFullPath(runnerPath);
        _runnerIdentity = runnerIdentity
            ?? throw new ArgumentNullException(nameof(runnerIdentity));
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromHours(4))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }
        _timeout = timeout;
    }

    public byte[] Execute(CompatibilityProbeContext context)
    {
        var workspace = Directory.CreateTempSubdirectory(
            "ensou-dsh-enterprise-plugin-compatibility-").FullName;
        try
        {
            PublisherPathGuard.RequireSafeExistingDirectory(workspace);
            using var runnerLock = PublisherSafeFile.OpenLockedRead(_runnerPath);
            var identity = PublisherSafeFile.GetIdentity(runnerLock);
            if (runnerLock.Length != _runnerIdentity.SizeBytes
                || !string.Equals(
                    PublisherSafeFile.HashAndRewind(runnerLock),
                    _runnerIdentity.Sha256,
                    StringComparison.Ordinal))
            {
                throw new IOException(
                    "The trusted compatibility runner identity changed before probe execution.");
            }

            var requestPath = Path.Combine(workspace, "request.v1.json");
            var outputPath = Path.Combine(workspace, "evidence.v1.json");
            var runWorkspace = Path.Combine(workspace, "run");
            Directory.CreateDirectory(runWorkspace);
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            WriteNew(
                requestPath,
                InternalCompatibilityProbe.SerializeRequest(
                    context,
                    runWorkspace,
                    nonce,
                    _runnerIdentity));
            using var requestLock = PublisherSafeFile.OpenLockedRead(requestPath);

            var startInfo = new ProcessStartInfo
            {
                FileName = _runnerPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = runWorkspace,
            };
            startInfo.ArgumentList.Add(InternalProbeSwitch);
            startInfo.ArgumentList.Add("--request");
            startInfo.ArgumentList.Add(requestPath);
            startInfo.ArgumentList.Add("--output");
            startInfo.ArgumentList.Add(outputPath);
            startInfo.ArgumentList.Add("--nonce");
            startInfo.ArgumentList.Add(nonce);
            startInfo.Environment.Clear();
            startInfo.Environment["SystemRoot"] = Environment.GetFolderPath(
                Environment.SpecialFolder.Windows);
            startInfo.Environment["WINDIR"] = Environment.GetFolderPath(
                Environment.SpecialFolder.Windows);
            startInfo.Environment["TEMP"] = runWorkspace;
            startInfo.Environment["TMP"] = runWorkspace;

            using var process = new Process { StartInfo = startInfo };
            if (!process.Start())
            {
                throw new InvalidOperationException(
                    "The trusted internal compatibility probe did not start.");
            }
            if (!process.WaitForExit(checked((int)_timeout.TotalMilliseconds)))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit();
                }
                catch
                {
                    // The bounded timeout remains authoritative.
                }
                throw new TimeoutException(
                    "The trusted internal compatibility probe exceeded its production timeout.");
            }
            if (process.ExitCode != 0)
            {
                throw new InvalidDataException(
                    $"The trusted internal compatibility probe failed with exit code {process.ExitCode}.");
            }

            PublisherSafeFile.RequireExpectedPathAndRegularFile(runnerLock, _runnerPath);
            if (PublisherSafeFile.GetIdentity(runnerLock) != identity
                || runnerLock.Length != _runnerIdentity.SizeBytes
                || !string.Equals(
                    PublisherSafeFile.HashAndRewind(runnerLock),
                    _runnerIdentity.Sha256,
                    StringComparison.Ordinal))
            {
                throw new IOException(
                    "The trusted compatibility runner identity changed during probe execution.");
            }
            using var evidence = PublisherSafeFile.OpenLockedRead(outputPath);
            if (evidence.Length is <= 0 or > MaximumEvidenceBytes)
            {
                throw new InvalidDataException(
                    "The trusted internal compatibility probe output size is invalid.");
            }
            var bytes = new byte[checked((int)evidence.Length)];
            evidence.ReadExactly(bytes);
            var parsed = PublisherRuntimeAdmissionJson.Parse<CompatibilityProbeEvidence>(
                bytes,
                "Trusted internal compatibility probe evidence");
            if (!string.Equals(parsed.Nonce, nonce, StringComparison.Ordinal)
                || !string.Equals(
                    parsed.RunnerSha256,
                    _runnerIdentity.Sha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The internal compatibility probe evidence is replayed or from another runner binary.");
            }
            return bytes;
        }
        finally
        {
            DeleteExactWorkspace(workspace);
        }
    }

    private static void WriteNew(string path, byte[] bytes)
    {
        using var output = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            64 * 1024,
            FileOptions.WriteThrough);
        output.Write(bytes);
        output.Flush(flushToDisk: true);
    }

    private static void DeleteExactWorkspace(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!Directory.Exists(fullPath))
        {
            return;
        }
        if (!Path.GetFileName(fullPath).StartsWith(
                "ensou-dsh-enterprise-plugin-compatibility-",
                StringComparison.Ordinal)
            || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                "Compatibility probe private workspace cleanup target is unsafe.");
        }
        Directory.Delete(fullPath, recursive: true);
    }
}
