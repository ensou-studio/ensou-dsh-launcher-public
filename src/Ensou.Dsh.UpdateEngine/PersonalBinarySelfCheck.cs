using System.Reflection;
using System.Security.Cryptography;

namespace Ensou.Dsh.UpdateEngine;

public static class PersonalBinarySelfCheck
{
    public const string FailureMarker =
        "ensou-personal-binary-self-check-failed-v1";
    public const string ProtocolEnvironmentVariable =
        "ENSOU_DSH_PERSONAL_BINARY_SELF_CHECK_PROTOCOL";
    public const string ProtocolValue =
        "ensou-personal-binary-self-check/v1";

    public static string RequireCurrentProcess(string expectedExecutableName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedExecutableName);
        if (!string.Equals(
                Path.GetFileName(expectedExecutableName),
                expectedExecutableName,
                StringComparison.Ordinal)
            || !string.Equals(
                Path.GetExtension(expectedExecutableName),
                ".exe",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal binary self-check expected executable name is invalid.");
        }
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "Unable to identify the current personal executable.");
        var absolutePath = Path.GetFullPath(processPath);
        if (!string.Equals(
                Path.GetFileName(absolutePath),
                expectedExecutableName,
                StringComparison.Ordinal)
            || !File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal binary self-check executable identity is invalid or linked.");
        }
        for (var current = new DirectoryInfo(Path.GetDirectoryName(absolutePath)!);
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal binary self-check path crosses a filesystem link.");
            }
        }
        PersonalPathGuard.RequireSingleLinkFile(absolutePath);
        PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(absolutePath);
        return absolutePath;
    }

    public static PersonalCompiledTrustFingerprint RequireCurrentProcessCompiledTrust(
        string expectedExecutableName,
        Assembly entryAssembly)
    {
        ArgumentNullException.ThrowIfNull(entryAssembly);
        RequireAndConsumeProtocol();
        return RequireCurrentRuntimeProcessCompiledTrust(
            expectedExecutableName,
            entryAssembly);
    }

    internal static PersonalCompiledTrustFingerprint RequireCurrentRuntimeProcessCompiledTrust(
        string expectedExecutableName,
        Assembly entryAssembly)
    {
        ArgumentNullException.ThrowIfNull(entryAssembly);
        if (!ReferenceEquals(Assembly.GetEntryAssembly(), entryAssembly))
        {
            throw new InvalidDataException(
                "Personal binary self-check did not receive its entry assembly.");
        }
        _ = RequireCurrentProcess(expectedExecutableName);
        var entryTrust = PersonalInstallerTrustConfiguration.ReadCompiled(entryAssembly);
        var engineTrust = PersonalInstallerTrustConfiguration.ReadCompiled(
            typeof(PersonalBinarySelfCheck).Assembly);
        PersonalAuthenticodeVerifier.RequireMatchingCompiledTrust(
            entryTrust,
            engineTrust);
        return PersonalCompiledTrustFingerprint.Create(entryTrust);
    }

    internal static void RequireAndConsumeProtocol()
    {
        var supplied = Environment.GetEnvironmentVariable(
            ProtocolEnvironmentVariable,
            EnvironmentVariableTarget.Process);
        Environment.SetEnvironmentVariable(
            ProtocolEnvironmentVariable,
            null,
            EnvironmentVariableTarget.Process);
        if (!string.Equals(supplied, ProtocolValue, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal binary self-check machine protocol is missing or invalid.");
        }
    }

    public static void WriteCanonicalCompiledTrust(
        PersonalCompiledTrustFingerprint fingerprint)
    {
        ArgumentNullException.ThrowIfNull(fingerprint);
        var bytes = fingerprint.SerializeCanonical();
        try
        {
            using var standardOutput = Console.OpenStandardOutput();
            if (!standardOutput.CanWrite)
            {
                throw new InvalidOperationException(
                    "Personal binary self-check requires a redirected machine output handle.");
            }
            standardOutput.Write(bytes);
            standardOutput.Flush();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
