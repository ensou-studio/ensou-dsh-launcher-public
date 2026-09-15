using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalCompiledTrustFingerprint
{
    public const int CurrentSchemaVersion = 2;
    private const int MaximumCanonicalBytes = 32 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 16,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    [JsonPropertyOrder(0)]
    public required int SchemaVersion { get; init; }

    [JsonPropertyOrder(1)]
    public required bool ProductionBuild { get; init; }

    [JsonPropertyOrder(2)]
    public required string ManifestOrigin { get; init; }

    [JsonPropertyOrder(3)]
    public required string ArtifactOrigin { get; init; }

    [JsonPropertyOrder(4)]
    public required string Product { get; init; }

    [JsonPropertyOrder(5)]
    public required string Environment { get; init; }

    [JsonPropertyOrder(6)]
    public required string Channel { get; init; }

    [JsonPropertyOrder(7)]
    public required string StartupStubVersion { get; init; }

    [JsonPropertyOrder(8)]
    public required string ReleaseKeyId { get; init; }

    [JsonPropertyOrder(9)]
    public required string ReleaseKeyX { get; init; }

    [JsonPropertyOrder(10)]
    public required string ReleaseKeyY { get; init; }

    [JsonPropertyOrder(11)]
    public required long CanonicalLowSFromSequence { get; init; }

    [JsonPropertyOrder(12)]
    public string? AuthenticodeSignerSha256Thumbprint { get; init; }

    public static PersonalCompiledTrustFingerprint Create(
        PersonalInstallerTrustConfiguration trust)
    {
        ArgumentNullException.ThrowIfNull(trust);
        if (trust.ReleasePolicy.TrustedKeys.Count != 1)
        {
            throw new InvalidOperationException(
                "Personal compiled trust must contain exactly one release key.");
        }
        var key = trust.ReleasePolicy.TrustedKeys[0];
        var value = new PersonalCompiledTrustFingerprint
        {
            SchemaVersion = CurrentSchemaVersion,
            ProductionBuild = trust.ProductionBuild,
            ManifestOrigin = trust.ManifestOrigin.AbsoluteUri,
            ArtifactOrigin = trust.ReleasePolicy.ArtifactOrigin.AbsoluteUri,
            Product = trust.ReleasePolicy.Product,
            Environment = trust.ReleasePolicy.Environment,
            Channel = trust.ReleasePolicy.Channel,
            StartupStubVersion = trust.ReleasePolicy.StartupStubVersion,
            ReleaseKeyId = key.KeyId,
            ReleaseKeyX = key.X,
            ReleaseKeyY = key.Y,
            CanonicalLowSFromSequence =
                trust.ReleasePolicy.CanonicalLowSFromSequence,
            AuthenticodeSignerSha256Thumbprint =
                trust.AuthenticodeSignerSha256Thumbprint,
        };
        value.Validate();
        return value;
    }

    public static PersonalCompiledTrustFingerprint ReadCompiled(Assembly assembly) =>
        Create(PersonalInstallerTrustConfiguration.ReadCompiled(assembly));

    public static PersonalCompiledTrustFingerprint ParseCanonical(
        ReadOnlySpan<byte> utf8)
    {
        if (utf8.IsEmpty || utf8.Length > MaximumCanonicalBytes)
        {
            throw new InvalidDataException(
                "Personal compiled trust fingerprint is empty or unbounded.");
        }
        using var document = JsonDocument.Parse(
            utf8.ToArray(),
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
        RejectDuplicateProperties(document.RootElement, "$");
        var value = JsonSerializer.Deserialize<PersonalCompiledTrustFingerprint>(
                utf8,
                JsonOptions)
            ?? throw new InvalidDataException(
                "Personal compiled trust fingerprint is empty.");
        value.Validate();
        var canonical = value.SerializeCanonical();
        try
        {
            if (!utf8.SequenceEqual(canonical))
            {
                throw new InvalidDataException(
                    "Personal compiled trust fingerprint is not strict canonical JSON.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
        return value;
    }

    public byte[] SerializeCanonical()
    {
        Validate();
        return JsonSerializer.SerializeToUtf8Bytes(this, JsonOptions);
    }

    public string ComputeSha256()
    {
        var canonical = SerializeCanonical();
        try
        {
            return Convert.ToHexStringLower(SHA256.HashData(canonical));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    public static void RequireMatches(
        PersonalCompiledTrustFingerprint expected,
        PersonalCompiledTrustFingerprint actual,
        string subject)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(actual);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        expected.Validate();
        actual.Validate();
        if (expected != actual)
        {
            throw new InvalidDataException(
                $"{subject} compiled Personal release trust does not match the Installer.");
        }
    }

    private void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion)
        {
            throw new InvalidDataException(
                "Personal compiled trust fingerprint schema is unsupported.");
        }
        var manifestOrigin = RequireCanonicalHttpsOrigin(ManifestOrigin, "manifest");
        var artifactOrigin = RequireCanonicalHttpsOrigin(ArtifactOrigin, "artifact");
        var policy = new PersonalReleaseTrustPolicy
        {
            Product = Product,
            Environment = Environment,
            Channel = Channel,
            ArtifactOrigin = artifactOrigin,
            StartupStubVersion = StartupStubVersion,
            CanonicalLowSFromSequence = CanonicalLowSFromSequence,
            TrustedKeys =
            [
                new PersonalReleasePublicKey(ReleaseKeyId, ReleaseKeyX, ReleaseKeyY),
            ],
        };
        policy.Validate();
        if (!string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(manifestOrigin.AbsoluteUri, ManifestOrigin, StringComparison.Ordinal)
            || !string.Equals(artifactOrigin.AbsoluteUri, ArtifactOrigin, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal compiled trust fingerprint identity is invalid.");
        }
        if (AuthenticodeSignerSha256Thumbprint is not null)
        {
            var normalized = PersonalAuthenticodeVerifier.RequireSha256Thumbprint(
                AuthenticodeSignerSha256Thumbprint);
            if (!string.Equals(
                    normalized,
                    AuthenticodeSignerSha256Thumbprint,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal compiled trust signer thumbprint is not canonical uppercase.");
            }
        }
        if (ProductionBuild && AuthenticodeSignerSha256Thumbprint is null)
        {
            throw new InvalidDataException(
                "Production Personal compiled trust has no signer identity.");
        }
    }

    private static Uri RequireCanonicalHttpsOrigin(string value, string label)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.Equals(uri.AbsolutePath, "/", StringComparison.Ordinal)
            || !uri.OriginalString.All(character =>
                char.IsAscii(character) && character > ' ' && character is not '"' and not '\\'))
        {
            throw new InvalidDataException(
                $"Personal compiled trust {label} origin is not canonical HTTPS.");
        }
        return uri;
    }

    private static void RejectDuplicateProperties(JsonElement element, string path)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        $"Personal compiled trust has duplicate property '{property.Name}' at {path}.");
                }
                RejectDuplicateProperties(property.Value, path + "." + property.Name);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicateProperties(item, $"{path}[{index++}]");
            }
        }
    }
}

public static class PersonalCompiledTrustProcessVerifier
{
    private const int MaximumOutputCharacters = 32 * 1024;

    public static PersonalTrustedExecutableLaunchLease
        AcquireExecutableLaunchLease(
            string executablePath,
            string expectedExecutableName,
            PersonalCompiledTrustFingerprint expected) =>
        AcquireExecutableLaunchLeaseAsync(
                executablePath,
                expectedExecutableName,
                expected,
                leaseAcquired: null)
            .GetAwaiter()
            .GetResult();

    internal static PersonalTrustedExecutableLaunchLease
        AcquireExecutableLaunchLeaseWithAdmission(
            string executablePath,
            string expectedExecutableName,
            PersonalCompiledTrustFingerprint expected,
            Action verifyWhileExecutableLocked)
    {
        ArgumentNullException.ThrowIfNull(verifyWhileExecutableLocked);
        return AcquireExecutableLaunchLeaseAsync(
                executablePath,
                expectedExecutableName,
                expected,
                verifyWhileExecutableLocked)
            .GetAwaiter()
            .GetResult();
    }

    public static PersonalCompiledTrustFingerprint RequireExecutable(
        string executablePath,
        string expectedExecutableName,
        PersonalCompiledTrustFingerprint expected) =>
        RequireExecutableAsync(
                executablePath,
                expectedExecutableName,
                expected,
                leaseAcquired: null)
            .GetAwaiter()
            .GetResult();

    internal static PersonalCompiledTrustFingerprint RequireExecutableForTests(
        string executablePath,
        string expectedExecutableName,
        PersonalCompiledTrustFingerprint expected,
        Action leaseAcquired) =>
        RequireExecutableAsync(
                executablePath,
                expectedExecutableName,
                expected,
                leaseAcquired)
            .GetAwaiter()
            .GetResult();

    private static async Task<PersonalCompiledTrustFingerprint> RequireExecutableAsync(
        string executablePath,
        string expectedExecutableName,
        PersonalCompiledTrustFingerprint expected,
        Action? leaseAcquired)
    {
        using var lease = await AcquireExecutableLaunchLeaseAsync(
                executablePath,
                expectedExecutableName,
                expected,
                leaseAcquired)
            .ConfigureAwait(false);
        return expected;
    }

    private static async Task<PersonalTrustedExecutableLaunchLease>
        AcquireExecutableLaunchLeaseAsync(
            string executablePath,
            string expectedExecutableName,
            PersonalCompiledTrustFingerprint expected,
            Action? leaseAcquired)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedExecutableName);
        ArgumentNullException.ThrowIfNull(expected);
        var path = Path.GetFullPath(executablePath);
        if (!string.Equals(
                Path.GetFileName(path),
                expectedExecutableName,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal compiled-trust probe executable name is unexpected.");
        }
        var executableLease = PersonalAuthenticodeVerifier
            .OpenTrustedExecutableForLaunch(path, expected);

        try
        {
            leaseAcquired?.Invoke();
            var startInfo = new ProcessStartInfo
            {
                FileName = path,
                WorkingDirectory = Path.GetDirectoryName(path)
                    ?? throw new InvalidDataException(
                        "Personal compiled-trust probe has no working directory."),
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = new UTF8Encoding(false, true),
                StandardErrorEncoding = new UTF8Encoding(false, true),
            };
            startInfo.ArgumentList.Add("--binary-self-check");
            startInfo.Environment[
                PersonalBinarySelfCheck.ProtocolEnvironmentVariable] =
                PersonalBinarySelfCheck.ProtocolValue;
            var startedProcess = executableLease.Start(startInfo);
            Process? ownedProcess = startedProcess;
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var stdoutTask = ReadBoundedAsync(
                    startedProcess.StandardOutput,
                    () => TryKill(startedProcess),
                    timeout.Token);
                var stderrTask = ReadBoundedAsync(
                    startedProcess.StandardError,
                    () => TryKill(startedProcess),
                    timeout.Token);
                try
                {
                    await Task.WhenAll(
                            startedProcess.WaitForExitAsync(timeout.Token),
                            stdoutTask,
                            stderrTask)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested)
                {
                    var timeoutFailure = new TimeoutException(
                        "Personal compiled-trust self-check timed out without UI interaction.");
                    RequireSelfCheckProcessTerminated(
                        executableLease,
                        ref ownedProcess,
                        startedProcess,
                        timeoutFailure);
                    throw timeoutFailure;
                }
                catch (Exception selfCheckFailure)
                {
                    RequireSelfCheckProcessTerminated(
                        executableLease,
                        ref ownedProcess,
                        startedProcess,
                        selfCheckFailure);
                    throw;
                }
                var stdout = await stdoutTask.ConfigureAwait(false);
                var stderr = await stderrTask.ConfigureAwait(false);
                if (startedProcess.ExitCode != 0)
                {
                    throw new InvalidDataException(
                        $"Personal compiled-trust self-check failed with exit {startedProcess.ExitCode}: {stderr}");
                }
                var utf8 = new UTF8Encoding(false, true).GetBytes(stdout);
                try
                {
                    var actual = PersonalCompiledTrustFingerprint.ParseCanonical(utf8);
                    PersonalCompiledTrustFingerprint.RequireMatches(
                        expected,
                        actual,
                        expectedExecutableName);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(utf8);
                }
            }
            finally
            {
                ownedProcess?.Dispose();
            }
            return executableLease;
        }
        catch (Exception acquisitionFailure)
        {
            try
            {
                executableLease.Dispose();
            }
            catch (Exception containmentFailure)
            {
                throw new InvalidOperationException(
                    "Personal compiled-trust admission failed while a rejected process remained retained.",
                    new AggregateException(
                        acquisitionFailure,
                        containmentFailure));
            }
            throw;
        }
    }

    internal static void RequireSelfCheckProcessTerminatedForTests(
        PersonalTrustedExecutableLaunchLease executableLease,
        ref Process? ownedProcess,
        Exception rejectionFailure,
        Func<Process, TimeSpan, bool> terminateRejectedProcess)
    {
        ArgumentNullException.ThrowIfNull(terminateRejectedProcess);
        var rejectedProcess = ownedProcess
            ?? throw new InvalidOperationException(
                "Personal self-check test has no owned process.");
        RequireSelfCheckProcessTerminated(
            executableLease,
            ref ownedProcess,
            rejectedProcess,
            rejectionFailure,
            terminateRejectedProcess);
    }

    private static void RequireSelfCheckProcessTerminated(
        PersonalTrustedExecutableLaunchLease executableLease,
        ref Process? ownedProcess,
        Process rejectedProcess,
        Exception rejectionFailure,
        Func<Process, TimeSpan, bool>? terminateRejectedProcess = null)
    {
        ArgumentNullException.ThrowIfNull(executableLease);
        ArgumentNullException.ThrowIfNull(rejectionFailure);
        try
        {
            executableLease.RequireRejectedProcessTerminated(
                rejectedProcess,
                rejectionFailure,
                terminateRejectedProcess);
        }
        finally
        {
            // The containment API either disposed the proven-exited process or
            // retained its exact handle and executable lock for a later retry.
            ownedProcess = null;
        }
    }

    private static async Task<string> ReadBoundedAsync(
        StreamReader reader,
        Action limitExceeded,
        CancellationToken cancellationToken)
    {
        var value = new StringBuilder();
        var buffer = new char[4 * 1024];
        while (true)
        {
            var read = await reader.ReadAsync(buffer, cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                return value.ToString();
            }
            if (value.Length + read > MaximumOutputCharacters)
            {
                limitExceeded();
                throw new InvalidDataException(
                    "Personal compiled-trust self-check output is unbounded.");
            }
            value.Append(buffer, 0, read);
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Preserve the original trust, bound, or timeout failure.
        }
    }
}
