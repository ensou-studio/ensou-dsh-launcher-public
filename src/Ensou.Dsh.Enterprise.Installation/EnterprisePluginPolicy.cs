using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

public static class EnterprisePluginPolicyContract
{
    public const int SchemaVersion = 1;
    public const string PolicyFileName = "plugin-policy.json";
    public const string SkillsEnvironmentVariable = "ENSOU_DSH_ENTERPRISE_SKILLS_ROOT";
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterprisePluginPolicyFile
{
    public required string Path { get; init; }

    public required string Sha256 { get; init; }

    public required long SizeBytes { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterprisePluginSkillPack
{
    public required string SkillId { get; init; }

    public required string Version { get; init; }

    public required string Root { get; init; }

    public required IReadOnlyList<EnterprisePluginPolicyFile> Files { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterprisePluginPolicyCompatibility
{
    public required IReadOnlyList<string> LauncherReleaseIds { get; init; }

    public required IReadOnlyList<string> RuntimeReleaseIds { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterprisePluginPolicy
{
    public required int SchemaVersion { get; init; }

    public required string PolicyId { get; init; }

    public required long Generation { get; init; }

    public required string SkillsRoot { get; init; }

    public required IReadOnlyList<EnterprisePluginSkillPack> SkillPacks { get; init; }

    public required EnterprisePluginPolicyCompatibility Compatibility { get; init; }

    public required bool Revoked { get; init; }

    public required bool Critical { get; init; }

    public static EnterprisePluginPolicy Parse(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.Length is <= 0 or > 4 * 1024 * 1024)
        {
            throw new InvalidDataException("Enterprise plugin policy size is invalid.");
        }

        try
        {
            using var document = JsonDocument.Parse(
                utf8Json.ToArray(),
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32,
                });
            RequireNoDuplicateProperties(document.RootElement);
            var policy = JsonSerializer.Deserialize<EnterprisePluginPolicy>(
                utf8Json,
                PluginPolicyJsonOptions)
                ?? throw new InvalidDataException("Enterprise plugin policy is empty.");
            ValidateContract(policy);
            return policy;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise plugin policy JSON is not the exact v1 contract.",
                exception);
        }
    }

    internal void RequireCompatible(string launcherReleaseId, string runtimeReleaseId)
    {
        EnterprisePathGuard.ValidateReleaseId(launcherReleaseId);
        EnterprisePathGuard.ValidateReleaseId(runtimeReleaseId);
        if (!Compatibility.LauncherReleaseIds.Contains(
                launcherReleaseId,
                StringComparer.Ordinal)
            || !Compatibility.RuntimeReleaseIds.Contains(
                runtimeReleaseId,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise plugin policy is incompatible with the selected Launcher/runtime tuple.");
        }
    }

    private static readonly JsonSerializerOptions PluginPolicyJsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };

    private static void ValidateContract(EnterprisePluginPolicy policy)
    {
        if (policy.SchemaVersion != EnterprisePluginPolicyContract.SchemaVersion
            || !Guid.TryParseExact(policy.PolicyId, "D", out var policyId)
            || !string.Equals(
                policyId.ToString("D"),
                policy.PolicyId,
                StringComparison.Ordinal)
            || policy.Generation is <= 0 or > 9_007_199_254_740_991L
            || policy.SkillPacks is null
            || policy.Compatibility is null)
        {
            throw new InvalidDataException("Enterprise plugin policy identity is invalid.");
        }

        ValidateRelativePath(policy.SkillsRoot, "skillsRoot");
        if (policy.SkillPacks.Count is <= 0 or > 256)
        {
            throw new InvalidDataException("Enterprise plugin policy skill-pack count is invalid.");
        }

        ValidateCompatibility(policy.Compatibility);
        var skillIds = new HashSet<string>(StringComparer.Ordinal);
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var totalFiles = 0;
        long totalBytes = 0;
        foreach (var skillPack in policy.SkillPacks)
        {
            if (skillPack is null
                || skillPack.Files is null
                || !skillIds.Add(skillPack.SkillId))
            {
                throw new InvalidDataException(
                    "Enterprise plugin policy contains duplicate or missing skill packs.");
            }
            EnterpriseReleaseSetValidator.ValidateToken(
                skillPack.SkillId,
                "skillId",
                64);
            EnterpriseReleaseSetValidator.ValidateToken(
                skillPack.Version,
                "skill version",
                64);
            ValidateRelativePath(skillPack.Root, "skill root");
            var expectedRoot = $"{policy.SkillsRoot}/{skillPack.SkillId}";
            if (!string.Equals(skillPack.Root, expectedRoot, StringComparison.Ordinal)
                || !roots.Add(skillPack.Root)
                || skillPack.Files.Count is <= 0 or > 10_000)
            {
                throw new InvalidDataException(
                    "Enterprise plugin policy skill root or file count is invalid.");
            }

            var hasSkillDefinition = false;
            foreach (var file in skillPack.Files)
            {
                if (file is null)
                {
                    throw new InvalidDataException(
                        "Enterprise plugin policy contains a missing file entry.");
                }
                ValidateRelativePath(file.Path, "skill file path");
                if (!IsSameOrDescendant(file.Path, skillPack.Root)
                    || string.Equals(file.Path, skillPack.Root, StringComparison.Ordinal)
                    || !allPaths.Add(file.Path)
                    || !EnterpriseHash.IsSha256(file.Sha256)
                    || file.SizeBytes is < 0 or > 64L * 1024 * 1024)
                {
                    throw new InvalidDataException(
                        "Enterprise plugin policy file metadata is invalid or duplicated.");
                }

                totalFiles = checked(totalFiles + 1);
                totalBytes = checked(totalBytes + file.SizeBytes);
                if (totalFiles > 10_000 || totalBytes > 512L * 1024 * 1024)
                {
                    throw new InvalidDataException(
                        "Enterprise plugin policy content exceeds its bounds.");
                }
                hasSkillDefinition |= string.Equals(
                    file.Path,
                    $"{skillPack.Root}/SKILL.md",
                    StringComparison.Ordinal);
            }

            if (!hasSkillDefinition)
            {
                throw new InvalidDataException(
                    "Every enterprise managed skill pack must contain its exact SKILL.md.");
            }
        }
    }

    private static void ValidateCompatibility(EnterprisePluginPolicyCompatibility compatibility)
    {
        ValidateReleaseIds(compatibility.LauncherReleaseIds, "Launcher");
        ValidateReleaseIds(compatibility.RuntimeReleaseIds, "runtime");
    }

    private static void ValidateReleaseIds(IReadOnlyList<string> values, string component)
    {
        if (values is null
            || values.Count is <= 0 or > 64
            || values.Distinct(StringComparer.Ordinal).Count() != values.Count
            || values.Distinct(StringComparer.OrdinalIgnoreCase).Count() != values.Count)
        {
            throw new InvalidDataException(
                $"Enterprise plugin policy {component} compatibility is invalid.");
        }
        foreach (var value in values)
        {
            EnterprisePathGuard.ValidateReleaseId(value);
        }
    }

    internal static void ValidateRelativePath(string value, string field)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 1024
            || value.Contains('\\')
            || value.Contains(':')
            || value.StartsWith("/", StringComparison.Ordinal)
            || value.EndsWith("/", StringComparison.Ordinal)
            || Path.IsPathFullyQualified(value))
        {
            throw new InvalidDataException($"Enterprise plugin policy {field} is not canonical.");
        }

        var segments = value.Split('/');
        if (segments.Length == 0)
        {
            throw new InvalidDataException($"Enterprise plugin policy {field} is empty.");
        }
        foreach (var segment in segments)
        {
            var firstName = segment.Split('.', 2)[0];
            if (string.IsNullOrEmpty(segment)
                || segment is "." or ".."
                || segment.EndsWith(' ')
                || segment.EndsWith('.')
                || segment.Any(character => !(char.IsAsciiLetterOrDigit(character)
                    || character is '@' or '+' or '_' or '.' or '-'))
                || segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
                || firstName.Equals("CON", StringComparison.OrdinalIgnoreCase)
                || firstName.Equals("PRN", StringComparison.OrdinalIgnoreCase)
                || firstName.Equals("AUX", StringComparison.OrdinalIgnoreCase)
                || firstName.Equals("NUL", StringComparison.OrdinalIgnoreCase)
                || (firstName.Length == 4
                    && firstName[..3].Equals("COM", StringComparison.OrdinalIgnoreCase)
                    && firstName[3] is >= '1' and <= '9')
                || (firstName.Length == 4
                    && firstName[..3].Equals("LPT", StringComparison.OrdinalIgnoreCase)
                    && firstName[3] is >= '1' and <= '9'))
            {
                throw new InvalidDataException(
                    $"Enterprise plugin policy {field} has an unsafe segment.");
            }
        }
    }

    private static bool IsSameOrDescendant(string candidate, string root) =>
        string.Equals(candidate, root, StringComparison.Ordinal)
        || candidate.StartsWith(root + "/", StringComparison.Ordinal);

    private static void RequireNoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        "Enterprise plugin policy contains duplicate JSON members.");
                }
                RequireNoDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                RequireNoDuplicateProperties(item);
            }
        }
    }
}

public sealed record EnterpriseActivePluginPolicy(
    string ReleaseId,
    string PolicyId,
    long Generation,
    bool Critical,
    string PolicyDirectory,
    string SkillsRoot,
    string PolicySha256,
    string SkillsTreeSha256)
{
    public void RequireLeaseBinding(
        string pluginPolicyId,
        long pluginPolicyGeneration,
        string pluginPolicySha256)
    {
        if (!string.Equals(PolicyId, pluginPolicyId, StringComparison.Ordinal)
            || Generation != pluginPolicyGeneration
            || !string.Equals(PolicySha256, pluginPolicySha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The active signed plugin policy identity, generation, or bytes do not match the verified authorization lease.");
        }
    }
}

internal static class EnterprisePluginPolicyInstallation
{
    public static EnterpriseActivePluginPolicy ValidateInstalled(
        string policyDirectory,
        string pluginRoot,
        string releaseId,
        string archiveSha256,
        string launcherReleaseId,
        string runtimeReleaseId,
        bool requireReceipt)
    {
        EnterprisePathGuard.ValidateReleaseId(releaseId);
        var normalizedDirectory = EnterprisePathGuard.NormalizeDirectory(policyDirectory);
        var normalizedPluginRoot = EnterprisePathGuard.NormalizeDirectory(pluginRoot);
        if (!EnterprisePathGuard.IsSameOrDescendant(
                normalizedDirectory,
                normalizedPluginRoot)
            || string.Equals(
                normalizedDirectory,
                normalizedPluginRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Enterprise plugin policy directory escaped its managed plugin root.");
        }

        EnterprisePathGuard.ValidateSafeTree(normalizedDirectory, normalizedPluginRoot);
        var policyPath = ResolveRelative(
            normalizedDirectory,
            EnterprisePluginPolicyContract.PolicyFileName);
        EnterprisePathGuard.ValidateExistingPathWithin(
            policyPath,
            normalizedPluginRoot,
            requireDirectory: false);
        var policyBytes = File.ReadAllBytes(policyPath);
        var policy = EnterprisePluginPolicy.Parse(policyBytes);
        policy.RequireCompatible(launcherReleaseId, runtimeReleaseId);
        if (policy.Revoked)
        {
            throw new InvalidDataException(
                policy.Critical
                    ? "The critical enterprise plugin policy is revoked."
                    : "The enterprise plugin policy is revoked.");
        }

        var skillsRoot = ResolveRelative(normalizedDirectory, policy.SkillsRoot);
        if (!Directory.Exists(skillsRoot))
        {
            throw new InvalidDataException(
                "Enterprise plugin policy skills root is missing.");
        }
        EnterprisePathGuard.ValidateExistingPathWithin(
            skillsRoot,
            normalizedPluginRoot,
            requireDirectory: true);

        var expectedFiles = policy.SkillPacks
            .SelectMany(skill => skill.Files)
            .ToDictionary(file => file.Path, StringComparer.OrdinalIgnoreCase);
        var actualFiles = Directory.EnumerateFiles(
                normalizedDirectory,
                "*",
                SearchOption.AllDirectories)
            .Select(path => new
            {
                FullPath = path,
                RelativePath = Path.GetRelativePath(normalizedDirectory, path)
                    .Replace('\\', '/'),
            })
            .Where(item => !IsReceipt(item.RelativePath)
                && !string.Equals(
                    item.RelativePath,
                    EnterprisePluginPolicyContract.PolicyFileName,
                    StringComparison.Ordinal))
            .ToArray();
        if (actualFiles.Length != expectedFiles.Count
            || actualFiles.Select(item => item.RelativePath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count() != actualFiles.Length)
        {
            throw new InvalidDataException(
                "Enterprise plugin policy tree contains missing, duplicate, or unexpected files.");
        }

        foreach (var actual in actualFiles)
        {
            if (!expectedFiles.TryGetValue(actual.RelativePath, out var expected)
                || (File.GetAttributes(actual.FullPath) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Enterprise plugin policy tree contains an unlisted file or filesystem link.");
            }
            var info = new FileInfo(actual.FullPath);
            if (info.Length != expected.SizeBytes
                || !string.Equals(
                    EnterpriseHash.ComputeFile(actual.FullPath),
                    expected.Sha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise plugin policy file size or SHA-256 changed.");
            }
        }

        var policySha256 = Convert.ToHexStringLower(SHA256.HashData(policyBytes));
        var skillsTreeSha256 = ComputeDeclaredTree(policy);
        if (requireReceipt)
        {
            var receiptPath = Path.Combine(
                normalizedDirectory,
                EnterpriseReleaseSetPointerStore.PluginReceiptFileName);
            EnterprisePathGuard.ValidateExistingPathWithin(
                receiptPath,
                normalizedPluginRoot,
                requireDirectory: false);
            var receipt = EnterprisePointerJson.Deserialize<EnterprisePluginPolicyReceipt>(
                File.ReadAllBytes(receiptPath));
            if (receipt.SchemaVersion != 2
                || !string.Equals(receipt.ReleaseId, releaseId, StringComparison.Ordinal)
                || !string.Equals(receipt.ArchiveSha256, archiveSha256, StringComparison.Ordinal)
                || !string.Equals(receipt.PolicySha256, policySha256, StringComparison.Ordinal)
                || !string.Equals(receipt.PolicyId, policy.PolicyId, StringComparison.Ordinal)
                || receipt.Generation != policy.Generation
                || !string.Equals(receipt.SkillsRoot, policy.SkillsRoot, StringComparison.Ordinal)
                || !string.Equals(
                    receipt.SkillsTreeSha256,
                    skillsTreeSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise plugin policy receipt is invalid.");
            }
        }

        return new EnterpriseActivePluginPolicy(
            releaseId,
            policy.PolicyId,
            policy.Generation,
            policy.Critical,
            normalizedDirectory,
            skillsRoot,
            policySha256,
            skillsTreeSha256);
    }

    public static string ComputeDeclaredTree(EnterprisePluginPolicy policy)
    {
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var file in policy.SkillPacks
                     .SelectMany(pack => pack.Files)
                     .OrderBy(file => file.Path, StringComparer.Ordinal))
        {
            Append(aggregate, file.Path);
            Append(aggregate, file.SizeBytes.ToString(
                System.Globalization.CultureInfo.InvariantCulture));
            Append(aggregate, file.Sha256);
        }
        return Convert.ToHexStringLower(aggregate.GetHashAndReset());
    }

    private static string ResolveRelative(string root, string relative)
    {
        EnterprisePluginPolicy.ValidateRelativePath(relative, "path");
        var combined = Path.GetFullPath(Path.Combine(
            root,
            relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!EnterprisePathGuard.IsSameOrDescendant(combined, root)
            || string.Equals(combined, root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Enterprise plugin policy path escaped its immutable directory.");
        }
        return combined;
    }

    private static bool IsReceipt(string relativePath) => relativePath is
        EnterpriseReleaseSetPointerStore.PluginReceiptFileName
        or EnterpriseTreeHash.ReceiptFileName;

    private static void Append(IncrementalHash hash, string value)
    {
        hash.AppendData(Encoding.UTF8.GetBytes(value));
        hash.AppendData([0]);
    }
}
