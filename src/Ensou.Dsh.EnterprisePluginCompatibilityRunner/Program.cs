using System.Reflection;
using System.Security.Cryptography;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.EnterprisePluginCompatibilityRunner;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "Enterprise plugin compatibility production evidence requires Windows.");
            }
            if (args.Length > 0
                && string.Equals(
                    args[0],
                    RuntimeArchiveCompatibilityProbeExecutor.InternalProbeSwitch,
                    StringComparison.Ordinal))
            {
                var internalOptions = InternalCompatibilityProbeOptions.Parse(args);
                var internalIdentity = ResolveProductionIdentity();
                var internalRuntimeTrust = ResolveRuntimeAdmissionTrust();
                var internalPluginTrust = ResolvePluginAdmissionTrust();
                RequireIndependentTrusts(internalRuntimeTrust, internalPluginTrust);
                InternalCompatibilityProbe.Run(
                    internalOptions,
                    internalIdentity,
                    internalRuntimeTrust,
                    internalPluginTrust,
                    TimeProvider.System);
                return 0;
            }
            var options = CompatibilityRunnerOptions.Parse(args);
            var identity = ResolveProductionIdentity();
            var trust = ResolveRuntimeAdmissionTrust();
            var pluginTrust = ResolvePluginAdmissionTrust();
            RequireIndependentTrusts(trust, pluginTrust);
            EnterprisePluginCompatibilityRunner.Run(
                options,
                trust,
                pluginTrust,
                identity,
                new RuntimeArchiveCompatibilityProbeExecutor(
                    Environment.ProcessPath!,
                    identity),
                TimeProvider.System,
                Guid.NewGuid().ToString("D"));
            Console.WriteLine("Enterprise plugin compatibility receipt created.");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Enterprise plugin compatibility failed closed: {exception.Message}");
            return 1;
        }
    }

    private static CompatibilityRunnerIdentity ResolveProductionIdentity()
    {
        var assembly = typeof(Program).Assembly;
        var processPath = Environment.ProcessPath;
#pragma warning disable IL3000 // Empty Location is the required single-file identity signal.
        if (!string.IsNullOrEmpty(assembly.Location)
#pragma warning restore IL3000
            || string.IsNullOrWhiteSpace(processPath)
            || !string.Equals(
                Path.GetFileName(processPath),
                EnterprisePluginCompatibilityRunner.ProductionFileName,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Production compatibility evidence requires the exact self-contained single-file runner executable.");
        }
        using var stream = PublisherSafeFile.OpenLockedRead(processPath);
        return new CompatibilityRunnerIdentity(
            Path.GetFileName(processPath),
            stream.Length,
            PublisherSafeFile.HashAndRewind(stream));
    }

    private static PublisherRuntimeAdmissionTrust ResolveRuntimeAdmissionTrust()
    {
        const string keyIdName = "EnterpriseRuntimeAdmissionKeyId";
        const string keyXName = "EnterpriseRuntimeAdmissionKeyX";
        const string keyYName = "EnterpriseRuntimeAdmissionKeyY";
        var metadata = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToArray();
        string Require(string name)
        {
            var values = metadata
                .Where(value => string.Equals(value.Key, name, StringComparison.Ordinal))
                .Select(value => value.Value)
                .ToArray();
            if (values.Length != 1 || string.IsNullOrWhiteSpace(values[0]))
            {
                throw new InvalidDataException(
                    $"Compatibility runner assembly is missing exact {name} trust metadata.");
            }
            return values[0]!;
        }
        var trust = new PublisherRuntimeAdmissionTrust
        {
            KeyId = Require(keyIdName),
            X = Require(keyXName),
            Y = Require(keyYName),
        };
        trust.Validate();
        return trust;
    }

    private static PublisherPluginAdmissionTrust ResolvePluginAdmissionTrust()
    {
        var metadata = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToArray();
        string Require(string name)
        {
            var values = metadata
                .Where(value => string.Equals(value.Key, name, StringComparison.Ordinal))
                .Select(value => value.Value)
                .ToArray();
            if (values.Length != 1 || string.IsNullOrWhiteSpace(values[0]))
            {
                throw new InvalidDataException(
                    $"Compatibility runner assembly is missing exact {name} trust metadata.");
            }
            return values[0]!;
        }
        var trust = new PublisherPluginAdmissionTrust
        {
            KeyId = Require("EnterprisePluginAdmissionKeyId"),
            X = Require("EnterprisePluginAdmissionKeyX"),
            Y = Require("EnterprisePluginAdmissionKeyY"),
        };
        trust.Validate();
        return trust;
    }

    private static void RequireIndependentTrusts(
        PublisherRuntimeAdmissionTrust runtime,
        PublisherPluginAdmissionTrust plugin)
    {
        if (string.Equals(runtime.KeyId, plugin.KeyId, StringComparison.Ordinal)
            || (string.Equals(runtime.X, plugin.X, StringComparison.Ordinal)
                && string.Equals(runtime.Y, plugin.Y, StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Runtime and plugin-execution admission trust roots must be independent.");
        }
    }
}

internal sealed record InternalCompatibilityProbeOptions(
    string RequestPath,
    string OutputPath,
    string Nonce)
{
    public static InternalCompatibilityProbeOptions Parse(string[] args)
    {
        if (args.Length != 7
            || !string.Equals(
                args[0],
                RuntimeArchiveCompatibilityProbeExecutor.InternalProbeSwitch,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Internal compatibility probe requires the exact private request contract.");
        }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (args[index] is not "--request" and not "--output" and not "--nonce"
                || !values.TryAdd(args[index], args[index + 1])
                || string.IsNullOrWhiteSpace(args[index + 1]))
            {
                throw new ArgumentException(
                    "Internal compatibility probe argument is unknown, repeated, or empty.");
            }
        }
        string Require(string name) => values.TryGetValue(name, out var value)
            ? value
            : throw new ArgumentException($"Internal compatibility probe requires {name}.");
        return new InternalCompatibilityProbeOptions(
            Path.GetFullPath(Require("--request")),
            Path.GetFullPath(Require("--output")),
            Require("--nonce"));
    }
}

internal sealed record CompatibilityRunnerOptions(
    string LauncherReleaseId,
    string LauncherArchivePath,
    string LauncherArchiveSha256,
    string RuntimeReleaseId,
    string RuntimeArchivePath,
    string RuntimeArchiveSha256,
    string RuntimeSourceMetadataPath,
    string RuntimeSourceMetadataSha256,
    string RuntimeOrganizationAdmissionReceiptPath,
    string PluginPolicyArchivePath,
    string PluginPolicyArchiveSha256,
    string PluginPolicyMetadataPath,
    string PluginPolicyMetadataSha256,
    string PluginPolicyExecutionAdmissionReceiptPath,
    string OutputPath)
{
    public static CompatibilityRunnerOptions Parse(string[] args)
    {
        string[] names =
        [
            "--launcher-release-id", "--launcher-archive", "--launcher-sha256",
            "--runtime-release-id", "--runtime-archive", "--runtime-sha256",
            "--runtime-source-metadata", "--runtime-source-metadata-sha256",
            "--runtime-organization-admission-receipt",
            "--plugin-policy-archive", "--plugin-policy-archive-sha256",
            "--plugin-policy-metadata", "--plugin-policy-metadata-sha256", "--output",
            "--plugin-policy-execution-admission-receipt",
        ];
        if (args.Length != names.Length * 2)
        {
            throw new ArgumentException(
                "Compatibility runner requires the exact Launcher/runtime/policy tuple and a new output path.");
        }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (!names.Contains(args[index], StringComparer.Ordinal)
                || !values.TryAdd(args[index], args[index + 1])
                || string.IsNullOrWhiteSpace(args[index + 1]))
            {
                throw new ArgumentException(
                    "Compatibility runner argument is unknown, repeated, or empty.");
            }
        }
        string Require(string name) => values.TryGetValue(name, out var value)
            ? value
            : throw new ArgumentException($"Compatibility runner requires {name}.");
        return new CompatibilityRunnerOptions(
            Require("--launcher-release-id"),
            Path.GetFullPath(Require("--launcher-archive")),
            Require("--launcher-sha256"),
            Require("--runtime-release-id"),
            Path.GetFullPath(Require("--runtime-archive")),
            Require("--runtime-sha256"),
            Path.GetFullPath(Require("--runtime-source-metadata")),
            Require("--runtime-source-metadata-sha256"),
            Path.GetFullPath(Require("--runtime-organization-admission-receipt")),
            Path.GetFullPath(Require("--plugin-policy-archive")),
            Require("--plugin-policy-archive-sha256"),
            Path.GetFullPath(Require("--plugin-policy-metadata")),
            Require("--plugin-policy-metadata-sha256"),
            Path.GetFullPath(Require("--plugin-policy-execution-admission-receipt")),
            Path.GetFullPath(Require("--output")));
    }
}

internal sealed record CompatibilityRunnerIdentity(
    string FileName,
    long SizeBytes,
    string Sha256);
