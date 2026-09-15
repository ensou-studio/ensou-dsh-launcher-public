using System.Buffers;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalCompleteTreeFile
{
    public required string Path { get; init; }

    public required long SizeBytes { get; init; }

    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalCompleteTreeManifest
{
    public required int SchemaVersion { get; init; }

    public required string Component { get; init; }

    public required string ReleaseId { get; init; }

    public required IReadOnlyList<PersonalCompleteTreeFile> Files { get; init; }
}

public sealed record PersonalReleaseSetInstallationResult(
    PersonalInstalledReleaseSetPointer Pointer,
    PersonalHarnessHomeRecoveryState? HomeTransaction);

public sealed class PersonalReleaseArtifactInstaller
{
    public const string CompleteTreeEntryName = ".ensou-complete-tree.v1.json";
    private const int MaximumArchiveEntries = 250_000;
    private const int MaximumTreeManifestBytes = 16 * 1024 * 1024;
    private const long MaximumExpandedBytes = 16L * 1024 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 32,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    private readonly Action<int> _writerGuard;
    private readonly Action<int> _legacyEnrollmentGuard;

    public PersonalReleaseArtifactInstaller()
        : this(writerGuardForTesting: null)
    {
    }

    internal PersonalReleaseArtifactInstaller(Action<int>? writerGuardForTesting)
    {
        _writerGuard = writerGuardForTesting
            ?? PersonalHarnessWriterGuard.RequireAvailableLoopbackPort;
        _legacyEnrollmentGuard = writerGuardForTesting
            ?? PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort;
    }

    public static async Task<PersonalCompleteTreeManifest> VerifyCandidateArchiveAsync(
        string archivePath,
        string completeTreeManifestPath,
        string component,
        string releaseId,
        CancellationToken cancellationToken = default)
    {
        PersonalExecutablePathBudget.RequireArchiveVerification(component);
        var absoluteArchive = Path.GetFullPath(archivePath);
        var absoluteTree = Path.GetFullPath(completeTreeManifestPath);
        if (!File.Exists(absoluteArchive)
            || !File.Exists(absoluteTree)
            || (File.GetAttributes(absoluteArchive) & FileAttributes.ReparsePoint) != 0
            || (File.GetAttributes(absoluteTree) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal publisher candidate archive or complete tree is missing or linked.");
        }
        var expectedTreeBytes = await File.ReadAllBytesAsync(
            absoluteTree,
            cancellationToken).ConfigureAwait(false);
        await using var stream = new FileStream(
            absoluteArchive,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        var embeddedTreeBytes = await ReadTreeBytesAsync(archive, cancellationToken)
            .ConfigureAwait(false);
        if (!embeddedTreeBytes.AsSpan().SequenceEqual(expectedTreeBytes))
        {
            throw new InvalidDataException(
                "Personal publisher tree evidence is not the exact manifest embedded in its archive.");
        }
        var tree = ParseTree(embeddedTreeBytes, component, releaseId);
        var verificationRoot = Path.Combine(
            Path.GetTempPath(),
            "ensou-personal-candidate-verification",
            Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(verificationRoot);
            await ExtractAndVerifyAsync(
                archive,
                tree,
                embeddedTreeBytes,
                verificationRoot,
                progress: null,
                cancellationToken).ConfigureAwait(false);
            RequireEnsouClientSignatures(verificationRoot, component);
            return tree;
        }
        finally
        {
            if (Directory.Exists(verificationRoot))
            {
                DeleteTreeWithoutFollowingLinks(verificationRoot);
            }
            CryptographicOperations.ZeroMemory(expectedTreeBytes);
            CryptographicOperations.ZeroMemory(embeddedTreeBytes);
        }
    }

    public async Task<PersonalReleaseSetInstallationResult> InstallReleaseSetAsync(
        PersonalInstallationLayout layout,
        VerifiedPersonalReleaseSetManifest verified,
        string clientBundleArchivePath,
        string runtimeArchivePath,
        int loopbackPort,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(verified);
        PersonalExecutablePathBudget.RequireCandidate(layout, verified.Manifest);
        await using var operationLease =
            await PersonalManagedUpdateOperationLease.AcquireRequiredAsync(
                layout,
                cancellationToken).ConfigureAwait(false);
        if (!Directory.Exists(layout.ManagedRoot)
            || !File.Exists(layout.UpdateSecurityStatePath))
        {
            throw new InvalidDataException(
                "Personal managed installation disappeared before release installation.");
        }
        return await InstallReleaseSetUnderOperationLockAsync(
            layout,
            verified,
            new PersonalAcquiredReleaseSet(
                PersonalReleaseArtifactSource.Downloaded(clientBundleArchivePath),
                PersonalReleaseArtifactSource.Downloaded(runtimeArchivePath)),
            loopbackPort,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<PersonalReleaseSetInstallationResult> InstallDownloadedReleaseSetAsync(
        PersonalInstallationLayout layout,
        VerifiedPersonalReleaseSetManifest verified,
        string clientBundleArchivePath,
        string runtimeArchivePath,
        int loopbackPort,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default) =>
        await InstallAcquiredReleaseSetAsync(
            layout,
            verified,
            new PersonalAcquiredReleaseSet(
                PersonalReleaseArtifactSource.Downloaded(clientBundleArchivePath),
                PersonalReleaseArtifactSource.Downloaded(runtimeArchivePath)),
            loopbackPort,
            progress,
            cancellationToken).ConfigureAwait(false);

    public async Task<PersonalReleaseSetInstallationResult> InstallAcquiredReleaseSetAsync(
        PersonalInstallationLayout layout,
        VerifiedPersonalReleaseSetManifest verified,
        PersonalAcquiredReleaseSet acquired,
        int loopbackPort,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(verified);
        ArgumentNullException.ThrowIfNull(acquired);
        PersonalExecutablePathBudget.RequireCandidate(layout, verified.Manifest);
        acquired.ClientBundle.Validate(PersonalReleaseSetContract.ClientBundleComponent);
        acquired.Runtime.Validate(PersonalReleaseSetContract.RuntimeComponent);
        await using var operationLease =
            await PersonalManagedUpdateOperationLease.AcquireRequiredAsync(
                layout,
                cancellationToken).ConfigureAwait(false);
        if (!Directory.Exists(layout.ManagedRoot)
            || !File.Exists(layout.UpdateSecurityStatePath))
        {
            throw new InvalidDataException(
                "Personal managed installation disappeared before release installation.");
        }
        var sessions = new PersonalManagedUpdateSessionStore(layout);
        sessions.RequireMatches(
            verified.Manifest.ReleaseSetId,
            verified.CanonicalSignedManifestSha256,
            verified.Manifest.ClientBundle.Sha256,
            verified.Manifest.Runtime.Sha256);
        try
        {
            return await InstallReleaseSetUnderOperationLockAsync(
                layout,
                verified,
                acquired,
                loopbackPort,
                progress,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            sessions.Complete(
                verified.Manifest.ReleaseSetId,
                verified.CanonicalSignedManifestSha256,
                verified.Manifest.ClientBundle.Sha256,
                verified.Manifest.Runtime.Sha256);
        }
    }

    private async Task<PersonalReleaseSetInstallationResult>
        InstallReleaseSetUnderOperationLockAsync(
            PersonalInstallationLayout layout,
            VerifiedPersonalReleaseSetManifest verified,
            PersonalAcquiredReleaseSet acquired,
            int loopbackPort,
            IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        PersonalExecutablePathBudget.RequireCandidate(layout, verified.Manifest);
        layout.EnsureManagedRoots();
        var pointerStore = new PersonalReleaseSetPointerStore(layout);
        var installedAtStart = pointerStore.TryRead();
        var runtimeReleaseIdUnchanged = installedAtStart is not null
            && string.Equals(
                installedAtStart.Current.Runtime.ReleaseId,
                verified.Manifest.Runtime.ReleaseId,
                StringComparison.Ordinal);
        if (runtimeReleaseIdUnchanged
            && (installedAtStart!.Current.HealthState
                    != PersonalReleaseHealthStates.Healthy
                || acquired.Runtime.ReusedComponent is null
                || !PersonalReleaseSetPointerStore.InstalledComponentsMatch(
                    installedAtStart.Current.Runtime,
                    acquired.Runtime.ReusedComponent)
                || !InstalledComponentMatchesArtifact(
                    layout,
                    installedAtStart.Current.Runtime,
                    verified.Manifest.Runtime)))
        {
            throw new InvalidDataException(
                "Personal unchanged Runtime must reuse the exact authenticated active tuple.");
        }
        var authorizedReuse = await PersonalInstalledComponentReuseResolver.ResolveAsync(
            layout,
            verified,
            DateTimeOffset.UtcNow,
            cancellationToken).ConfigureAwait(false);
        RequireAcquiredSourceMatchesAuthorizedReuse(
            acquired.ClientBundle,
            authorizedReuse.ClientBundle,
            PersonalReleaseSetContract.ClientBundleComponent);
        RequireAcquiredSourceMatchesAuthorizedReuse(
            acquired.Runtime,
            authorizedReuse.Runtime,
            PersonalReleaseSetContract.RuntimeComponent);
        await InstallComponentSourceAsync(
            layout,
            verified,
            verified.Manifest.ClientBundle,
            acquired.ClientBundle,
            layout.GetClientBundleDirectory(verified.Manifest.ClientBundle.ReleaseId),
            progress is null ? null : new Progress<double>(value => progress.Report(value * 0.4)),
            cancellationToken).ConfigureAwait(false);
        await InstallComponentSourceAsync(
            layout,
            verified,
            verified.Manifest.Runtime,
            acquired.Runtime,
            layout.GetRuntimeDirectory(verified.Manifest.Runtime.ReleaseId),
            progress is null
                ? null
                : new Progress<double>(value => progress.Report(0.4 + value * 0.4)),
            cancellationToken).ConfigureAwait(false);

        var security = new PersonalReleaseSecurityStateStore(
            layout.UpdateSecurityStatePath,
            new PersonalReleaseStateIdentity(
                PersonalReleaseSetContract.Product,
                PersonalReleaseSetContract.ProductionEnvironment,
                verified.Manifest.Channel),
            layout.UpdateSecurityWitnessPath);
        await using var activationAdmission = await security
            .AcquireActivationAdmissionAsync(
                verified,
                DateTimeOffset.UtcNow,
                cancellationToken)
            .ConfigureAwait(false);
        if (runtimeReleaseIdUnchanged)
        {
            RequireNoHomeStartupStubCutover(verified.Manifest.StartupStub);
            var pointer = pointerStore.ActivatePendingWithoutHomeTransaction(verified);
            progress?.Report(1);
            return new PersonalReleaseSetInstallationResult(pointer, null);
        }
        using var homeLease = new PersonalHarnessHomeCoordinator(layout.HarnessHome)
            .AcquireLease(() => _legacyEnrollmentGuard(loopbackPort));
        homeLease.RequireMutationAdmission(layout.HarnessHome);
        var transaction = new PersonalHarnessHomeTransaction(
            layout.HarnessHome,
            layout.HarnessRecoveryRoot,
            timeProvider: null,
            moveGapHookForTesting: null,
            writerGuardForTesting: _writerGuard,
            homeLease: homeLease);
        var prepared = transaction.Prepare(verified.Manifest.ReleaseSetId, loopbackPort);
        try
        {
            var pointer = pointerStore.ActivatePending(verified, prepared.TransactionId);
            progress?.Report(1);
            return new PersonalReleaseSetInstallationResult(pointer, prepared);
        }
        catch
        {
            try
            {
                _ = transaction.Rollback(prepared.TransactionId, "activation-failed");
            }
            catch
            {
                // Preserve activation failure; active recovery state remains fail closed.
            }
            throw;
        }
    }

    private static bool InstalledComponentMatchesArtifact(
        PersonalInstallationLayout layout,
        PersonalInstalledComponentReference installed,
        PersonalReleaseArtifact artifact) =>
        string.Equals(installed.Component, artifact.Component, StringComparison.Ordinal)
        && string.Equals(installed.ReleaseId, artifact.ReleaseId, StringComparison.Ordinal)
        && string.Equals(
            installed.Directory,
            layout.GetRuntimeDirectory(artifact.ReleaseId),
            StringComparison.OrdinalIgnoreCase)
        && string.Equals(installed.ArchiveSha256, artifact.Sha256, StringComparison.Ordinal)
        && string.Equals(
            installed.CompleteTreeSha256,
            artifact.CompleteTreeSha256,
            StringComparison.Ordinal);

    internal const string NoHomeMinimumStartupStubVersion = "1.1.0";

    private static void RequireNoHomeStartupStubCutover(
        PersonalStartupStubCompatibility startupStub)
    {
        PersonalReleaseSetValidator.ValidateStartupStubRange(startupStub);
        if (PersonalReleaseVersion.Compare(
                startupStub.MinimumVersion,
                NoHomeMinimumStartupStubVersion) < 0)
        {
            throw new InvalidDataException(
                $"Personal Runtime-reused update requires Startup Stub {NoHomeMinimumStartupStubVersion} or later.");
        }
    }

    private async Task InstallComponentSourceAsync(
        PersonalInstallationLayout layout,
        VerifiedPersonalReleaseSetManifest verified,
        PersonalReleaseArtifact artifact,
        PersonalReleaseArtifactSource source,
        string finalDirectory,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        source.Validate(artifact.Component);
        if (source.ReusedComponent is not null)
        {
            progress?.Report(1);
            return;
        }
        PersonalInstalledComponentReuseResolver.RequireDownloadTargetAbsent(
            layout,
            artifact);
        await InstallComponentCoreAsync(
            layout,
            artifact,
            source.ArchivePath!,
            finalDirectory,
            progress,
            cancellationToken,
            allowExisting: false).ConfigureAwait(false);
    }

    private static void RequireAcquiredSourceMatchesAuthorizedReuse(
        PersonalReleaseArtifactSource source,
        PersonalInstalledComponentReference? authorized,
        string component)
    {
        source.Validate(component);
        if (source.ReusedComponent is null)
        {
            if (authorized is not null)
            {
                throw new InvalidDataException(
                    "Personal acquired source attempts to replace an authenticated reusable component.");
            }
            return;
        }
        if (authorized is null
            || !PersonalReleaseSetPointerStore.InstalledComponentsMatch(
                source.ReusedComponent,
                authorized))
        {
            throw new InvalidDataException(
                "Personal acquired source does not match authenticated component reuse.");
        }
    }

    public Task InstallComponentAsync(
        PersonalInstallationLayout layout,
        PersonalReleaseArtifact artifact,
        string archivePath,
        string finalDirectory,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default) =>
        InstallComponentCoreAsync(
            layout,
            artifact,
            archivePath,
            finalDirectory,
            progress,
            cancellationToken,
            allowExisting: true);

    private async Task InstallComponentCoreAsync(
        PersonalInstallationLayout layout,
        PersonalReleaseArtifact artifact,
        string archivePath,
        string finalDirectory,
        IProgress<double>? progress,
        CancellationToken cancellationToken,
        bool allowExisting)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(artifact);
        var absoluteArchive = Path.GetFullPath(archivePath);
        if (!File.Exists(absoluteArchive)
            || (File.GetAttributes(absoluteArchive) & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileNotFoundException(
                "Personal release archive is missing or linked.",
                absoluteArchive);
        }
        var expectedDirectory = artifact.Component switch
        {
            PersonalReleaseSetContract.ClientBundleComponent =>
                layout.GetClientBundleDirectory(artifact.ReleaseId),
            PersonalReleaseSetContract.RuntimeComponent =>
                layout.GetRuntimeDirectory(artifact.ReleaseId),
            _ => throw new InvalidDataException(
                "Personal release archive has an unknown component."),
        };
        if (!string.Equals(
                PersonalPathGuard.NormalizeDirectory(finalDirectory),
                expectedDirectory,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal release installation directory does not match its component tuple.");
        }
        if (Directory.Exists(expectedDirectory))
        {
            if (!allowExisting)
            {
                throw new InvalidDataException(
                    "Personal downloaded target collided with a component directory not authorized for reuse.");
            }
            ValidateExisting(layout, artifact, expectedDirectory);
            progress?.Report(1);
            return;
        }

        var versionRoot = Path.GetDirectoryName(expectedDirectory)
            ?? throw new InvalidDataException("Personal component directory has no version root.");
        PersonalPathGuard.EnsureDirectoryChain(layout.ManagedRoot, versionRoot);
        var staging = Path.Combine(
            versionRoot,
            $".{artifact.ReleaseId}.staging-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(staging);
            await using var archiveStream = new FileStream(
                absoluteArchive,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await VerifyArchiveDescriptorAsync(
                archiveStream,
                artifact,
                cancellationToken).ConfigureAwait(false);
            archiveStream.Position = 0;
            using var archive = new ZipArchive(
                archiveStream,
                ZipArchiveMode.Read,
                leaveOpen: true);
            var treeBytes = await ReadTreeBytesAsync(archive, cancellationToken)
                .ConfigureAwait(false);
            var treeSha256 = Convert.ToHexStringLower(SHA256.HashData(treeBytes));
            if (!string.Equals(
                    treeSha256,
                    artifact.CompleteTreeSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal artifact embedded complete-tree digest does not match its signature.");
            }
            var tree = ParseTree(treeBytes, artifact.Component, artifact.ReleaseId);
            await ExtractAndVerifyAsync(
                archive,
                tree,
                treeBytes,
                staging,
                progress,
                cancellationToken).ConfigureAwait(false);
            RequireEnsouClientSignatures(staging, artifact.Component);
            WriteReceipt(layout, artifact, staging, tree);
            PersonalPathGuard.ValidateSafeTree(staging, layout.ManagedRoot);
            Directory.Move(staging, expectedDirectory);
        }
        catch
        {
            if (Directory.Exists(staging))
            {
                DeleteTreeWithoutFollowingLinks(staging);
            }
            throw;
        }
    }

    internal static void VerifyInstalledComponentTree(
        string directory,
        string component,
        string releaseId,
        string expectedCompleteTreeSha256) =>
        VerifyInstalledComponentTree(
            directory,
            component,
            releaseId,
            expectedCompleteTreeSha256,
            CancellationToken.None);

    internal static void VerifyInstalledComponentTree(
        string directory,
        string component,
        string releaseId,
        string expectedCompleteTreeSha256,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var root = Path.GetFullPath(directory);
        var treePath = Path.Combine(root, CompleteTreeEntryName);
        if (!Directory.Exists(root)
            || !File.Exists(treePath)
            || (File.GetAttributes(treePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal installed component complete-tree evidence is missing or linked.");
        }
        var treeInfo = new FileInfo(treePath);
        if (treeInfo.Length is <= 0 or > MaximumTreeManifestBytes)
        {
            throw new InvalidDataException(
                "Personal installed component complete-tree evidence is unbounded.");
        }
        cancellationToken.ThrowIfCancellationRequested();
        var treeBytes = File.ReadAllBytes(treePath);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var actualTreeSha256 = Convert.ToHexStringLower(SHA256.HashData(treeBytes));
            if (!string.Equals(
                    actualTreeSha256,
                    expectedCompleteTreeSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal installed component complete-tree digest changed.");
            }
            var tree = ParseTree(treeBytes, component, releaseId);
            var expected = tree.Files.ToDictionary(file => file.Path, StringComparer.Ordinal);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            long totalBytes = 0;
            foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "Personal installed component contains a linked file.");
                }
                var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
                if (relative is CompleteTreeEntryName
                    or PersonalReleaseSetPointerStore.ReceiptFileName)
                {
                    continue;
                }
                if (!expected.TryGetValue(relative, out var expectedFile)
                    || !seen.Add(relative))
                {
                    throw new InvalidDataException(
                        "Personal installed component contains an unexpected file.");
                }
                var info = new FileInfo(path);
                using var stream = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    128 * 1024,
                    FileOptions.SequentialScan);
                var actualSha256 = ComputeSha256(stream, cancellationToken);
                if (info.Length != expectedFile.SizeBytes
                    || !string.Equals(
                        actualSha256,
                        expectedFile.Sha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Personal installed component differs from its complete tree.");
                }
                totalBytes = checked(totalBytes + info.Length);
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (seen.Count != expected.Count
                || expected.Keys.Except(seen, StringComparer.Ordinal).Any()
                || totalBytes != tree.Files.Sum(file => file.SizeBytes))
            {
                throw new InvalidDataException(
                    "Personal installed component is incomplete.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(treeBytes);
        }
    }

    internal static string ComputeSha256(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = stream.Read(buffer, 0, buffer.Length);
                cancellationToken.ThrowIfCancellationRequested();
                if (count == 0)
                {
                    break;
                }
                hash.AppendData(buffer, 0, count);
            }
            return Convert.ToHexStringLower(hash.GetHashAndReset());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    public static PersonalCompleteTreeManifest ParseTree(
        ReadOnlySpan<byte> json,
        string expectedComponent,
        string expectedReleaseId)
    {
        if (json.Length is <= 0 or > MaximumTreeManifestBytes)
        {
            throw new InvalidDataException(
                "Personal complete-tree manifest size is invalid.");
        }
        try
        {
            using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32,
            });
            RejectDuplicates(document.RootElement, "$");
            var tree = JsonSerializer.Deserialize<PersonalCompleteTreeManifest>(json, JsonOptions)
                ?? throw new InvalidDataException(
                    "Personal complete-tree manifest is empty.");
            ValidateTree(tree, expectedComponent, expectedReleaseId);
            return tree;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal complete-tree manifest JSON is invalid.",
                exception);
        }
    }

    private static async Task VerifyArchiveDescriptorAsync(
        FileStream stream,
        PersonalReleaseArtifact artifact,
        CancellationToken cancellationToken)
    {
        if (stream.Length != artifact.SizeBytes)
        {
            throw new InvalidDataException(
                "Personal release archive size changed before installation.");
        }
        var digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(
            stream,
            cancellationToken).ConfigureAwait(false));
        if (!string.Equals(digest, artifact.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal release archive hash changed before installation.");
        }
    }

    private static async Task<byte[]> ReadTreeBytesAsync(
        ZipArchive archive,
        CancellationToken cancellationToken)
    {
        if (archive.Entries.Count is <= 0 or > MaximumArchiveEntries)
        {
            throw new InvalidDataException(
                "Personal release archive entry count is invalid.");
        }
        var entries = archive.Entries.Where(entry => string.Equals(
            NormalizeArchivePath(entry.FullName),
            CompleteTreeEntryName,
            StringComparison.Ordinal)).ToArray();
        if (entries.Length != 1
            || entries[0].Length is <= 0 or > MaximumTreeManifestBytes)
        {
            throw new InvalidDataException(
                "Personal release archive must contain one bounded complete-tree manifest.");
        }
        await using var input = entries[0].Open();
        using var output = new MemoryStream(checked((int)entries[0].Length));
        await input.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
        return output.ToArray();
    }

    private static async Task ExtractAndVerifyAsync(
        ZipArchive archive,
        PersonalCompleteTreeManifest tree,
        byte[] treeBytes,
        string staging,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        var expected = tree.Files.ToDictionary(file => file.Path, StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var stagingRoot = Path.GetFullPath(staging) + Path.DirectorySeparatorChar;
        long extractedBytes = 0;
        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RejectLinkEntry(entry);
            var relative = NormalizeArchivePath(entry.FullName);
            if (relative.Length == 0 || string.IsNullOrEmpty(entry.Name))
            {
                continue;
            }
            if (string.Equals(relative, CompleteTreeEntryName, StringComparison.Ordinal))
            {
                var treePath = Path.Combine(staging, CompleteTreeEntryName);
                await File.WriteAllBytesAsync(treePath, treeBytes, cancellationToken)
                    .ConfigureAwait(false);
                continue;
            }
            if (!expected.TryGetValue(relative, out var expectedFile)
                || !seen.Add(relative))
            {
                throw new InvalidDataException(
                    "Personal release archive contains an unexpected or duplicate file.");
            }
            if (entry.Length != expectedFile.SizeBytes)
            {
                throw new InvalidDataException(
                    "Personal release archive entry size differs from its complete tree.");
            }
            var destination = Path.GetFullPath(Path.Combine(
                staging,
                relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!destination.StartsWith(stagingRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Personal release archive path escaped its staging root.");
            }
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            await using var input = entry.Open();
            await using var output = new FileStream(
                destination,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = GC.AllocateUninitializedArray<byte>(128 * 1024);
            long written = 0;
            while (true)
            {
                var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                written = checked(written + read);
                if (written > expectedFile.SizeBytes)
                {
                    throw new InvalidDataException(
                        "Personal release archive expanded beyond its signed file size.");
                }
                hash.AppendData(buffer.AsSpan(0, read));
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
            }
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            if (written != expectedFile.SizeBytes
                || !string.Equals(
                    Convert.ToHexStringLower(hash.GetHashAndReset()),
                    expectedFile.Sha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal release archive file failed complete-tree verification.");
            }
            extractedBytes = checked(extractedBytes + written);
            progress?.Report(tree.Files.Count == 0
                ? 1
                : (double)seen.Count / tree.Files.Count);
        }
        if (seen.Count != expected.Count
            || expected.Keys.Except(seen, StringComparer.Ordinal).Any()
            || extractedBytes != tree.Files.Sum(file => file.SizeBytes))
        {
            throw new InvalidDataException(
                "Personal release archive is missing complete-tree files.");
        }
    }

    private static void ValidateTree(
        PersonalCompleteTreeManifest tree,
        string expectedComponent,
        string expectedReleaseId)
    {
        if (tree.SchemaVersion != 1
            || !string.Equals(tree.Component, expectedComponent, StringComparison.Ordinal)
            || !string.Equals(tree.ReleaseId, expectedReleaseId, StringComparison.Ordinal)
            || tree.Files is null
            || tree.Files.Count is <= 0 or > MaximumArchiveEntries
            || tree.Files.Select(file => file.Path).Distinct(StringComparer.Ordinal).Count()
                != tree.Files.Count
            || !tree.Files.Select(file => file.Path).SequenceEqual(
                tree.Files.Select(file => file.Path).Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Personal complete-tree identity or ordering is invalid.");
        }
        long total = 0;
        foreach (var file in tree.Files)
        {
            if (!string.Equals(file.Path, NormalizeArchivePath(file.Path), StringComparison.Ordinal)
                || string.Equals(file.Path, CompleteTreeEntryName, StringComparison.Ordinal)
                || file.SizeBytes < 0
                || !PersonalReleaseSetValidator.IsSha256(file.Sha256))
            {
                throw new InvalidDataException(
                    "Personal complete-tree file descriptor is invalid.");
            }
            total = checked(total + file.SizeBytes);
            if (total > MaximumExpandedBytes)
            {
                throw new InvalidDataException(
                    "Personal complete-tree exceeds its expansion limit.");
            }
        }
        var required = expectedComponent == PersonalReleaseSetContract.ClientBundleComponent
            ? new[]
            {
                PersonalInstallationLayout.ClientBootstrapperExecutableName,
                PersonalInstallationLayout.LauncherExecutableName,
                PersonalInstallationLayout.MaintenanceExecutableName,
            }
            : new[] { "node.exe", "node_modules/@deepseek-ai/dsh/lib/bin.js" };
        if (required.Any(path => !tree.Files.Any(file => string.Equals(
            file.Path,
            path,
            StringComparison.Ordinal))))
        {
            throw new InvalidDataException(
                "Personal complete-tree is missing a required executable.");
        }
    }

    private static string NormalizeArchivePath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }
        var normalized = path.Replace('\\', '/').TrimEnd('/');
        if (normalized.StartsWith("/", StringComparison.Ordinal)
            || normalized.Contains(':', StringComparison.Ordinal)
            || normalized.Contains("//", StringComparison.Ordinal)
            || normalized.Split('/').Any(segment => segment is "" or "." or ".."))
        {
            throw new InvalidDataException("Personal archive path is not canonical.");
        }
        return normalized;
    }

    private static void RejectLinkEntry(ZipArchiveEntry entry)
    {
        var unixType = (entry.ExternalAttributes >> 16) & 0xF000;
        if (unixType is not (0 or 0x4000 or 0x8000))
        {
            throw new InvalidDataException(
                "Personal release archive must not contain links or special files.");
        }
    }

    private static void WriteReceipt(
        PersonalInstallationLayout layout,
        PersonalReleaseArtifact artifact,
        string staging,
        PersonalCompleteTreeManifest tree)
    {
        var primary = artifact.Component == PersonalReleaseSetContract.ClientBundleComponent
            ? PersonalInstallationLayout.ClientBootstrapperExecutableName
            : "node.exe";
        var secondary = artifact.Component == PersonalReleaseSetContract.ClientBundleComponent
            ? PersonalInstallationLayout.LauncherExecutableName
            : "node_modules/@deepseek-ai/dsh/lib/bin.js";
        var receipt = new PersonalReleaseComponentReceipt(
            1,
            artifact.Component,
            artifact.ReleaseId,
            artifact.Sha256,
            artifact.CompleteTreeSha256,
            primary,
            tree.Files.Single(file => file.Path == primary).Sha256,
            secondary,
            tree.Files.Single(file => file.Path == secondary).Sha256,
            DateTimeOffset.UtcNow);
        PersonalReleaseSetPointerStore.WriteComponentReceipt(
            staging,
            receipt,
            layout.ManagedRoot);
    }

    private static void ValidateExisting(
        PersonalInstallationLayout layout,
        PersonalReleaseArtifact artifact,
        string directory)
    {
        PersonalPathGuard.ValidateSafeTree(directory, layout.ManagedRoot);
        var receiptPath = Path.Combine(
            directory,
            PersonalReleaseSetPointerStore.ReceiptFileName);
        if (!File.Exists(receiptPath))
        {
            throw new InvalidDataException(
                "Existing personal release directory lacks an immutable receipt.");
        }
        var receipt = JsonSerializer.Deserialize<PersonalReleaseComponentReceipt>(
            File.ReadAllBytes(receiptPath),
            JsonOptions) ?? throw new InvalidDataException(
                "Existing personal component receipt is empty.");
        if (receipt.SchemaVersion != 1
            || !string.Equals(receipt.Component, artifact.Component, StringComparison.Ordinal)
            || !string.Equals(receipt.ReleaseId, artifact.ReleaseId, StringComparison.Ordinal)
            || !string.Equals(receipt.ArchiveSha256, artifact.Sha256, StringComparison.Ordinal)
            || !string.Equals(
                receipt.CompleteTreeSha256,
                artifact.CompleteTreeSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Existing personal release directory has a different immutable identity.");
        }
        VerifyInstalledComponentTree(
            directory,
            artifact.Component,
            artifact.ReleaseId,
            artifact.CompleteTreeSha256);
        RequireEnsouClientSignatures(directory, artifact.Component);
    }

    internal static void RequireEnsouClientSignatures(string directory, string component)
    {
        if (!string.Equals(
                component,
                PersonalReleaseSetContract.ClientBundleComponent,
                StringComparison.Ordinal))
        {
            return;
        }
        var executables = new[]
        {
            PersonalInstallationLayout.ClientBootstrapperExecutableName,
            PersonalInstallationLayout.LauncherExecutableName,
            PersonalInstallationLayout.MaintenanceExecutableName,
        };
        foreach (var executableName in executables)
        {
            PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(Path.Combine(
                directory,
                executableName));
        }

        var assembly = typeof(PersonalReleaseArtifactInstaller).Assembly;
        var production = assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Where(attribute => string.Equals(
                attribute.Key,
                "PersonalProductionBuild",
                StringComparison.Ordinal))
            .Select(attribute => attribute.Value)
            .ToArray();
        if (production.Length != 1
            || !bool.TryParse(production[0], out var productionBuild))
        {
            throw new InvalidOperationException(
                "Personal UpdateEngine has no unique production-build trust metadata.");
        }
        if (!productionBuild)
        {
            return;
        }
        var expected = PersonalCompiledTrustFingerprint.ReadCompiled(assembly);
        foreach (var executableName in executables)
        {
            _ = PersonalCompiledTrustProcessVerifier.RequireExecutable(
                Path.Combine(directory, executableName),
                executableName,
                expected);
        }
    }

    private static void RejectDuplicates(JsonElement element, string path)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        $"Personal complete-tree has duplicate property '{property.Name}' at {path}.");
                }
                RejectDuplicates(property.Value, $"{path}.{property.Name}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicates(item, $"{path}[{index++}]");
            }
        }
    }

    private static void DeleteTreeWithoutFollowingLinks(string directory)
    {
        var root = new DirectoryInfo(directory);
        if (!root.Exists)
        {
            return;
        }
        if ((root.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(root.FullName);
            return;
        }
        foreach (var entry in root.EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                if (entry is DirectoryInfo)
                {
                    Directory.Delete(entry.FullName);
                }
                else
                {
                    File.Delete(entry.FullName);
                }
            }
            else if (entry is DirectoryInfo child)
            {
                DeleteTreeWithoutFollowingLinks(child.FullName);
            }
            else
            {
                entry.Delete();
            }
        }
        root.Delete();
    }
}
