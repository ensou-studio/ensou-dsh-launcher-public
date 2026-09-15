using System.Reflection;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

internal sealed record PublisherPluginCompatibilityRunnerTrust
{
    public required string Sha256 { get; init; }

    public void Validate()
    {
        if (!PublisherPluginPolicyMetadata.IsLowercaseSha256(Sha256))
        {
            throw new InvalidDataException(
                "Compiled plugin compatibility runner SHA-256 is invalid.");
        }
    }
}

internal static class PublisherPluginCompatibilityRunnerTrustResolver
{
    private const string Sha256Name = "EnterprisePluginCompatibilityRunnerSha256";

    public static PublisherPluginCompatibilityRunnerTrust ResolveProduction()
    {
        var values = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Where(value => string.Equals(value.Key, Sha256Name, StringComparison.Ordinal))
            .Select(value => value.Value)
            .ToArray();
        if (values.Length != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            throw new InvalidDataException(
                $"Production publisher assembly is missing exact {Sha256Name} trust metadata.");
        }
        var trust = new PublisherPluginCompatibilityRunnerTrust { Sha256 = values[0]! };
        trust.Validate();
        return trust;
    }
}
