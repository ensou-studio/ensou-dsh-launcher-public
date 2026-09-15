using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalLegacyV1RuntimePointer(
    int SchemaVersion,
    string ReleaseId,
    string RuntimeDirectory,
    string? PreviousReleaseId,
    string? PreviousRuntimeDirectory,
    bool PendingHealthValidation,
    string? SnapshotDirectory,
    DateTimeOffset UpdatedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalLegacyV1LauncherPointer(
    int SchemaVersion,
    string LauncherDirectory,
    string? PreviousLauncherDirectory,
    DateTimeOffset UpdatedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalLegacyV1RuntimeReceipt(
    int SchemaVersion,
    string ReleaseId,
    string DshVersion,
    string ArtifactSha256,
    DateTimeOffset InstalledAtUtc);

public sealed record PersonalLegacyV1FallbackReference(
    string ReleaseId,
    string RuntimeDirectory,
    string LauncherExecutablePath);

/// <summary>
/// Reads the last healthy runtime-v1 tuple during the one-way transition to
/// release-set v2. It is used only while no v2 release has ever committed.
/// </summary>
public sealed class PersonalLegacyV1FallbackStore
{
    private const int MaximumLegacyStateBytes = 64 * 1024;
    private static readonly string[] PersonalChannels = ["stable", "pilot", "lab"];
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 32,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
    private readonly PersonalInstallationLayout _layout;

    public PersonalLegacyV1FallbackStore(PersonalInstallationLayout layout)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
    }

    internal async Task<PersonalLegacyV1FallbackReference?> TryReadAllowedAsync(
        CancellationToken cancellationToken = default)
    {
        var fallback = TryRead();
        if (fallback is null)
        {
            return null;
        }

        await using var admission = await AcquireNoCommittedV2ReleaseAsync(
                cancellationToken)
            .ConfigureAwait(false);
        return fallback;
    }

    public async Task<bool> TryStartLauncherAsync(
        IReadOnlyList<string> args,
        Func<ProcessStartInfo, Process?>? startProcess = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        var fallback = TryRead();
        if (fallback is null)
        {
            return false;
        }
        await using var admission = await AcquireNoCommittedV2ReleaseAsync(
                cancellationToken)
            .ConfigureAwait(false);
        if (args.Count == 1
            && string.Equals(args[0], "--self-check", StringComparison.Ordinal))
        {
            return true;
        }
        if (args.Count != 0)
        {
            throw new ArgumentException(
                "Personal legacy v1 fallback accepts no launch arguments.");
        }

        PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(
            fallback.LauncherExecutablePath);
        var startInfo = new ProcessStartInfo
        {
            FileName = fallback.LauncherExecutablePath,
            WorkingDirectory = Path.GetDirectoryName(fallback.LauncherExecutablePath)
                ?? throw new InvalidDataException(
                    "Personal legacy v1 Launcher has no working directory."),
            UseShellExecute = true,
        };
        var process = startProcess is null
            ? Process.Start(startInfo)
            : startProcess(startInfo);
        _ = process ?? throw new InvalidOperationException(
            "Personal legacy v1 Launcher did not start.");
        return true;
    }

    public PersonalLegacyV1FallbackReference? TryRead()
    {
        var runtimePointerExists = File.Exists(_layout.LegacyRuntimePointerPath);
        var launcherPointerExists = File.Exists(_layout.LegacyLauncherPointerPath);
        var colocatedLauncherExists = File.Exists(_layout.LegacyColocatedLauncherPath);
        if (!runtimePointerExists
            && !launcherPointerExists
            && !colocatedLauncherExists)
        {
            return null;
        }
        if (!runtimePointerExists
            || !launcherPointerExists && !colocatedLauncherExists)
        {
            throw new InvalidDataException(
                "Personal legacy v1 fallback is incomplete.");
        }

        RequireSafeFile(_layout.LegacyRuntimePointerPath, _layout.StateRoot);
        var launcherPath = ResolveLauncherPath(launcherPointerExists);

        var pointerBytes = ReadLockedBytes(_layout.LegacyRuntimePointerPath);
        try
        {
            RejectDuplicateProperties(pointerBytes, "legacy runtime pointer");
            var pointer = JsonSerializer.Deserialize<PersonalLegacyV1RuntimePointer>(
                pointerBytes,
                JsonOptions) ?? throw new InvalidDataException(
                    "Personal legacy v1 runtime pointer is empty.");
            ValidatePointer(pointer);
            ValidateRuntimeReceipt(pointer);
            return new PersonalLegacyV1FallbackReference(
                pointer.ReleaseId,
                pointer.RuntimeDirectory,
                launcherPath);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal legacy v1 runtime pointer JSON is invalid.",
                exception);
        }
    }

    private string ResolveLauncherPath(bool launcherPointerExists)
    {
        if (!launcherPointerExists)
        {
            RequireSafeFile(
                _layout.LegacyColocatedLauncherPath,
                _layout.ManagedRoot);
            PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(
                _layout.LegacyColocatedLauncherPath);
            return _layout.LegacyColocatedLauncherPath;
        }

        RequireSafeFile(_layout.LegacyLauncherPointerPath, _layout.StateRoot);
        var pointerBytes = ReadLockedBytes(_layout.LegacyLauncherPointerPath);
        try
        {
            RejectDuplicateProperties(pointerBytes, "legacy Launcher pointer");
            var pointer = JsonSerializer.Deserialize<PersonalLegacyV1LauncherPointer>(
                pointerBytes,
                JsonOptions) ?? throw new InvalidDataException(
                    "Personal legacy v1 Launcher pointer is empty.");
            if (pointer.SchemaVersion != 1
                || pointer.UpdatedAtUtc.Offset != TimeSpan.Zero)
            {
                throw new InvalidDataException(
                    "Personal legacy v1 Launcher pointer is invalid.");
            }
            var launcherDirectory = PersonalPathGuard.NormalizeDirectory(
                pointer.LauncherDirectory);
            if (!PersonalPathGuard.IsStrictDescendant(
                    launcherDirectory,
                    _layout.LegacyLauncherVersionsRoot))
            {
                throw new InvalidDataException(
                    "Personal legacy v1 Launcher escaped its managed version root.");
            }
            RejectReparseChain(
                launcherDirectory,
                _layout.LegacyLauncherVersionsRoot);
            var launcherPath = Path.Combine(
                launcherDirectory,
                PersonalInstallationLayout.LauncherExecutableName);
            RequireSafeFile(launcherPath, _layout.LegacyLauncherVersionsRoot);
            PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(launcherPath);
            return launcherPath;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal legacy v1 Launcher pointer JSON is invalid.",
                exception);
        }
    }

    private void ValidatePointer(PersonalLegacyV1RuntimePointer pointer)
    {
        PersonalReleaseSetValidator.ValidateReleaseId(
            pointer.ReleaseId,
            "legacy runtime releaseId");
        if (pointer.SchemaVersion != 1
            || pointer.PendingHealthValidation
            || pointer.UpdatedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Personal legacy v1 fallback is not a healthy canonical pointer.");
        }
        if (string.IsNullOrWhiteSpace(pointer.PreviousReleaseId)
            != string.IsNullOrWhiteSpace(pointer.PreviousRuntimeDirectory))
        {
            throw new InvalidDataException(
                "Personal legacy v1 previous-runtime tuple is incomplete.");
        }

        var expected = _layout.GetRuntimeDirectory(pointer.ReleaseId);
        var actual = PersonalPathGuard.NormalizeDirectory(pointer.RuntimeDirectory);
        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal legacy v1 runtime escaped its managed version root.");
        }
        RejectReparseChain(actual, _layout.RuntimeVersionsRoot);
    }

    private void ValidateRuntimeReceipt(PersonalLegacyV1RuntimePointer pointer)
    {
        var markerPath = Path.Combine(pointer.RuntimeDirectory, ".ensou-release.json");
        var nodePath = Path.Combine(pointer.RuntimeDirectory, "node.exe");
        var entryPath = Path.Combine(
            pointer.RuntimeDirectory,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "lib",
            "bin.js");
        RequireSafeFile(markerPath, pointer.RuntimeDirectory);
        RequireSafeFile(nodePath, pointer.RuntimeDirectory);
        RequireSafeFile(entryPath, pointer.RuntimeDirectory);

        var markerBytes = ReadLockedBytes(markerPath);
        try
        {
            RejectDuplicateProperties(markerBytes, "legacy runtime receipt");
            var receipt = JsonSerializer.Deserialize<PersonalLegacyV1RuntimeReceipt>(
                markerBytes,
                JsonOptions) ?? throw new InvalidDataException(
                    "Personal legacy v1 runtime receipt is empty.");
            if (receipt.SchemaVersion != 1
                || !string.Equals(
                    receipt.ReleaseId,
                    pointer.ReleaseId,
                    StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(receipt.DshVersion)
                || !PersonalReleaseSetValidator.IsSha256(receipt.ArtifactSha256)
                || receipt.InstalledAtUtc.Offset != TimeSpan.Zero)
            {
                throw new InvalidDataException(
                    "Personal legacy v1 runtime receipt does not match its pointer.");
            }
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal legacy v1 runtime receipt JSON is invalid.",
                exception);
        }
    }

    private async Task<PersonalReleaseSecurityStateReadLease>
        AcquireNoCommittedV2ReleaseAsync(
        CancellationToken cancellationToken)
    {
        InvalidDataException? lastIdentityFailure = null;
        foreach (var channel in PersonalChannels)
        {
            PersonalReleaseSecurityStateReadLease? read = null;
            var transferLease = false;
            try
            {
                read = await new PersonalReleaseSecurityStateStore(
                        _layout.UpdateSecurityStatePath,
                        new PersonalReleaseStateIdentity(
                            PersonalReleaseSetContract.Product,
                            PersonalReleaseSetContract.ProductionEnvironment,
                            channel),
                        _layout.UpdateSecurityWitnessPath)
                    .AcquireReadLeaseAsync(cancellationToken)
                    .ConfigureAwait(false);
                var state = read.State;
                if (state is null)
                {
                    if (HasResidualV2Installation())
                    {
                        throw new InvalidDataException(
                            "Personal legacy v1 fallback is forbidden while a release-set v2 installation footprint remains.");
                    }
                    transferLease = true;
                    return read;
                }
                if (state.LastCommittedReleaseSetId is not null)
                {
                    throw new InvalidDataException(
                        "Personal legacy v1 fallback is forbidden after a v2 release committed.");
                }
                transferLease = true;
                return read;
            }
            catch (InvalidDataException exception)
            {
                lastIdentityFailure = exception;
            }
            finally
            {
                if (!transferLease && read is not null)
                {
                    await read.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        throw new InvalidDataException(
            "Personal legacy v1 fallback could not authenticate the v2 transition state.",
            lastIdentityFailure);
    }

    private bool HasResidualV2Installation()
    {
        if (File.Exists(_layout.ReleaseSetPointerPath))
        {
            return true;
        }
        if (!Directory.Exists(_layout.ClientBundleVersionsRoot))
        {
            return false;
        }
        RejectReparseChain(
            _layout.ClientBundleVersionsRoot,
            _layout.ManagedRoot);
        foreach (var entry in Directory.EnumerateFileSystemEntries(
                     _layout.ClientBundleVersionsRoot,
                     "*",
                     SearchOption.TopDirectoryOnly))
        {
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal release-set v2 installation footprint contains a filesystem link.");
            }
            if (File.Exists(entry))
            {
                PersonalPathGuard.RequireSingleLinkFile(entry);
            }
            return true;
        }
        return false;
    }

    private static byte[] ReadLockedBytes(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length is <= 0 or > MaximumLegacyStateBytes)
        {
            throw new InvalidDataException(
                "Personal legacy v1 state size is invalid.");
        }
        using var output = new MemoryStream((int)stream.Length);
        stream.CopyTo(output);
        return output.ToArray();
    }

    private static void RequireSafeFile(string path, string managedRoot)
    {
        var absolute = PersonalPathGuard.NormalizeFilePath(path);
        var root = PersonalPathGuard.NormalizeDirectory(managedRoot);
        if (!PersonalPathGuard.IsStrictDescendant(absolute, root)
            || !File.Exists(absolute)
            || (File.GetAttributes(absolute) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal legacy v1 fallback file is missing, linked, or outside its root.");
        }
        RejectReparseChain(
            Path.GetDirectoryName(absolute)
                ?? throw new InvalidDataException(
                    "Personal legacy v1 fallback file has no parent."),
            root);
    }

    private static void RejectReparseChain(string directory, string managedRoot)
    {
        var root = PersonalPathGuard.NormalizeDirectory(managedRoot);
        for (var current = new DirectoryInfo(directory);;
             current = current.Parent
                 ?? throw new InvalidDataException(
                    "Personal legacy v1 path did not reach its managed root."))
        {
            if (!current.Exists
                || (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal legacy v1 path is missing or crosses a filesystem link.");
            }
            if (string.Equals(
                    Path.TrimEndingDirectorySeparator(current.FullName),
                    root,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }
    }

    private static void RejectDuplicateProperties(byte[] bytes, string field)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 32,
        });
        RejectDuplicateProperties(document.RootElement, field);
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
                        $"Personal {path} has duplicate property '{property.Name}'.");
                }
                RejectDuplicateProperties(property.Value, $"{path}.{property.Name}");
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
