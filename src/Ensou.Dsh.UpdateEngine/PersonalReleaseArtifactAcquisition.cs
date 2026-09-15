using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

public sealed record PersonalReleaseArtifactSource(
    string? ArchivePath,
    PersonalInstalledComponentReference? ReusedComponent)
{
    public static PersonalReleaseArtifactSource Downloaded(string archivePath) =>
        new(Path.GetFullPath(archivePath), null);

    internal static PersonalReleaseArtifactSource Reused(
        PersonalInstalledComponentReference component) => new(null, component);

    internal void Validate(string expectedComponent)
    {
        var hasArchive = ArchivePath is not null;
        var hasReuse = ReusedComponent is not null;
        if (hasArchive == hasReuse
            || hasArchive && string.IsNullOrWhiteSpace(ArchivePath)
            || hasReuse && !string.Equals(
                ReusedComponent!.Component,
                expectedComponent,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal artifact source must select exactly one matching archive or authenticated installed component.");
        }
    }
}

public sealed record PersonalAcquiredReleaseSet(
    PersonalReleaseArtifactSource ClientBundle,
    PersonalReleaseArtifactSource Runtime);

/// <summary>
/// Acquires only the artifacts that are not already present in the authenticated
/// active Current/Previous tuple. Installed trees are never treated as a cache:
/// their pointer, protected acceptance identity, receipts, complete tree, and
/// client executable trust are all revalidated before a network request is made.
/// </summary>
public sealed class PersonalReleaseArtifactAcquisitionService(
    PersonalInstallationLayout layout,
    HttpClient httpClient,
    TimeProvider? timeProvider = null)
{
    private readonly PersonalInstallationLayout _layout = layout
        ?? throw new ArgumentNullException(nameof(layout));
    private readonly HttpClient _httpClient = httpClient
        ?? throw new ArgumentNullException(nameof(httpClient));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<PersonalAcquiredReleaseSet> AcquireAsync(
        VerifiedPersonalReleaseSetManifest verified,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verified);
        await using var operationLease =
            await PersonalManagedUpdateOperationLease.AcquireRequiredAsync(
                _layout,
                cancellationToken).ConfigureAwait(false);
        if (!Directory.Exists(_layout.ManagedRoot)
            || !File.Exists(_layout.UpdateSecurityStatePath))
        {
            throw new InvalidDataException(
                "Personal managed installation disappeared before artifact acquisition.");
        }
        _layout.EnsureManagedRoots();

        var reuse = await PersonalInstalledComponentReuseResolver.ResolveAsync(
            _layout,
            verified,
            _timeProvider.GetUtcNow(),
            cancellationToken).ConfigureAwait(false);

        var sessions = new PersonalManagedUpdateSessionStore(_layout);
        sessions.Begin(
            verified.Manifest.ReleaseSetId,
            verified.CanonicalSignedManifestSha256,
            verified.Manifest.ClientBundle.Sha256,
            verified.Manifest.Runtime.Sha256);

        var downloadCount = (reuse.ClientBundle is null ? 1 : 0)
            + (reuse.Runtime is null ? 1 : 0);
        var completedDownloads = 0;
        var downloader = new PersistentPartialDownloader(_httpClient);

        async Task<PersonalReleaseArtifactSource> AcquireComponentAsync(
            PersonalReleaseArtifact artifact,
            PersonalInstalledComponentReference? reused)
        {
            if (reused is not null)
            {
                progress?.Report(downloadCount == 0
                    ? 1
                    : (double)completedDownloads / downloadCount);
                return PersonalReleaseArtifactSource.Reused(reused);
            }

            var offset = downloadCount == 0
                ? 0
                : (double)completedDownloads / downloadCount;
            var weight = downloadCount == 0 ? 1 : 1d / downloadCount;
            var result = await downloader.DownloadAsync(
                new PersistentArtifactDownloadRequest(
                    artifact.Uri,
                    _layout.PartialCacheRoot,
                    artifact.SizeBytes,
                    artifact.Sha256,
                    ReadIdleTimeout: TimeSpan.FromSeconds(45)),
                progress is null
                    ? null
                    : new Progress<DownloadProgress>(value =>
                        progress.Report(offset + value.Fraction * weight)),
                cancellationToken).ConfigureAwait(false);
            completedDownloads++;
            progress?.Report((double)completedDownloads / downloadCount);
            return PersonalReleaseArtifactSource.Downloaded(result.ArtifactPath);
        }

        var client = await AcquireComponentAsync(
            verified.Manifest.ClientBundle,
            reuse.ClientBundle).ConfigureAwait(false);
        var runtime = await AcquireComponentAsync(
            verified.Manifest.Runtime,
            reuse.Runtime).ConfigureAwait(false);
        progress?.Report(1);
        return new PersonalAcquiredReleaseSet(client, runtime);
    }
}

internal sealed record PersonalReusableInstalledComponents(
    PersonalInstalledComponentReference? ClientBundle,
    PersonalInstalledComponentReference? Runtime);

internal static class PersonalInstalledComponentReuseResolver
{
    public static async Task<PersonalReusableInstalledComponents> ResolveAsync(
        PersonalInstallationLayout layout,
        VerifiedPersonalReleaseSetManifest verified,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(verified);
        RequireUtc(observedNowUtc);

        var security = CreateSecurityStore(layout, verified.Manifest.Channel);
        var state = await security.TryReadAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Personal artifact acquisition requires authenticated update state.");
        RequireAcceptedTarget(state, verified);

        var store = new PersonalReleaseSetPointerStore(layout);
        var pointer = store.TryRead();
        if (pointer is null)
        {
            RejectUnreferencedResidue(layout, verified.Manifest.ClientBundle);
            RejectUnreferencedResidue(layout, verified.Manifest.Runtime);
            return new PersonalReusableInstalledComponents(null, null);
        }
        RequirePointerIdentity(pointer, verified.Manifest.Channel);
        RequireAcceptedSource(state, pointer.Current);
        if (pointer.Previous is not null)
        {
            RequireAcceptedSource(state, pointer.Previous);
        }

        var client = FindExact(pointer, verified.Manifest.ClientBundle);
        var runtime = FindExact(pointer, verified.Manifest.Runtime);
        if (client is null)
        {
            RejectUnreferencedResidue(layout, verified.Manifest.ClientBundle);
        }
        if (runtime is null)
        {
            RejectUnreferencedResidue(layout, verified.Manifest.Runtime);
        }
        if (client is not null)
        {
            RequireFullComponentValidation(
                layout,
                client,
                verified.Manifest.ClientBundle);
        }
        if (runtime is not null)
        {
            RequireFullComponentValidation(
                layout,
                runtime,
                verified.Manifest.Runtime);
        }

        var after = store.ReadRequired();
        if (pointer != after)
        {
            throw new InvalidDataException(
                "Personal release pointer changed while resolving authenticated component reuse.");
        }
        return new PersonalReusableInstalledComponents(client, runtime);
    }

    public static async Task RequireAuthorizedSourceAsync(
        PersonalInstallationLayout layout,
        VerifiedPersonalReleaseSetManifest verified,
        PersonalReleaseArtifact artifact,
        PersonalInstalledComponentReference reused,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken)
    {
        var resolved = await ResolveAsync(
            layout,
            verified,
            observedNowUtc,
            cancellationToken).ConfigureAwait(false);
        var expected = string.Equals(
            artifact.Component,
            PersonalReleaseSetContract.ClientBundleComponent,
            StringComparison.Ordinal)
            ? resolved.ClientBundle
            : string.Equals(
                artifact.Component,
                PersonalReleaseSetContract.RuntimeComponent,
                StringComparison.Ordinal)
                ? resolved.Runtime
                : throw new InvalidDataException(
                    "Personal component reuse requested an unknown component.");
        if (expected is null || expected != reused)
        {
            throw new InvalidDataException(
                "Personal reused component is not the exact authenticated Current/Previous source.");
        }
    }

    public static void RequireDownloadTargetAbsent(
        PersonalInstallationLayout layout,
        PersonalReleaseArtifact artifact) =>
        RejectUnreferencedResidue(layout, artifact);

    private static PersonalReleaseSecurityStateStore CreateSecurityStore(
        PersonalInstallationLayout layout,
        string channel) => new(
            layout.UpdateSecurityStatePath,
            new PersonalReleaseStateIdentity(
                PersonalReleaseSetContract.Product,
                PersonalReleaseSetContract.ProductionEnvironment,
                channel),
            layout.UpdateSecurityWitnessPath);

    private static void RequirePointerIdentity(
        PersonalInstalledReleaseSetPointer pointer,
        string channel)
    {
        if (!string.Equals(pointer.Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                pointer.Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(pointer.Channel, channel, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal installed pointer is outside the authenticated target channel.");
        }
    }

    private static void RequireAcceptedTarget(
        PersonalReleaseSecurityState state,
        VerifiedPersonalReleaseSetManifest verified)
    {
        var accepted = state.AcceptedReleases.SingleOrDefault(value => string.Equals(
            value.ReleaseSetId,
            verified.Manifest.ReleaseSetId,
            StringComparison.Ordinal)) ?? throw new InvalidDataException(
                "Personal target release-set is not present in authenticated update state.");
        var manifest = verified.Manifest;
        if (accepted.Generation != manifest.Generation
            || accepted.Sequence != manifest.Sequence
            || !string.Equals(
                accepted.ManifestSha256,
                verified.CanonicalSignedManifestSha256,
                StringComparison.Ordinal)
            || !StartupStubMatches(accepted.StartupStub, manifest.StartupStub)
            || !ComponentMatches(accepted.ClientBundle, manifest.ClientBundle)
            || !ComponentMatches(accepted.Runtime, manifest.Runtime))
        {
            throw new InvalidDataException(
                "Personal target release-set differs from authenticated update state.");
        }
    }

    private static void RequireAcceptedSource(
        PersonalReleaseSecurityState state,
        PersonalInstalledReleaseSetReference source)
    {
        var accepted = state.AcceptedReleases.SingleOrDefault(value => string.Equals(
            value.ReleaseSetId,
            source.ReleaseSetId,
            StringComparison.Ordinal)) ?? throw new InvalidDataException(
                "Personal reuse source is not bound to authenticated signed metadata.");
        if (accepted.Generation != source.Generation
            || accepted.Sequence != source.Sequence
            || !string.Equals(accepted.ManifestSha256, source.ManifestSha256, StringComparison.Ordinal)
            || !StartupStubMatches(accepted.StartupStub, source.StartupStub)
            || !ComponentMatches(accepted.ClientBundle, source.ClientBundle)
            || !ComponentMatches(accepted.Runtime, source.Runtime))
        {
            throw new InvalidDataException(
                "Personal reuse source differs from authenticated signed metadata.");
        }
    }

    private static PersonalInstalledComponentReference? FindExact(
        PersonalInstalledReleaseSetPointer pointer,
        PersonalReleaseArtifact target)
    {
        foreach (var release in pointer.Previous is null
            ? new[] { pointer.Current }
            : new[] { pointer.Current, pointer.Previous })
        {
            var component = string.Equals(
                target.Component,
                PersonalReleaseSetContract.ClientBundleComponent,
                StringComparison.Ordinal)
                ? release.ClientBundle
                : string.Equals(
                    target.Component,
                    PersonalReleaseSetContract.RuntimeComponent,
                    StringComparison.Ordinal)
                    ? release.Runtime
                    : throw new InvalidDataException(
                        "Personal target contains an unknown component.");
            if (ComponentMatches(component, target))
            {
                return component;
            }
        }
        return null;
    }

    private static void RejectUnreferencedResidue(
        PersonalInstallationLayout layout,
        PersonalReleaseArtifact artifact)
    {
        var directory = string.Equals(
            artifact.Component,
            PersonalReleaseSetContract.ClientBundleComponent,
            StringComparison.Ordinal)
            ? layout.GetClientBundleDirectory(artifact.ReleaseId)
            : string.Equals(
                artifact.Component,
                PersonalReleaseSetContract.RuntimeComponent,
                StringComparison.Ordinal)
                ? layout.GetRuntimeDirectory(artifact.ReleaseId)
                : throw new InvalidDataException(
                    "Personal target contains an unknown component.");
        if (Directory.Exists(directory) || File.Exists(directory))
        {
            throw new InvalidDataException(
                "Personal target collides with an installed directory not authorized by active Current/Previous state.");
        }
    }

    private static void RequireFullComponentValidation(
        PersonalInstallationLayout layout,
        PersonalInstalledComponentReference component,
        PersonalReleaseArtifact artifact)
    {
        if (!ComponentMatches(component, artifact))
        {
            throw new InvalidDataException(
                "Personal installed reuse tuple differs from the signed target component.");
        }
        PersonalReleaseArtifactInstaller.VerifyInstalledComponentTree(
            component.Directory,
            component.Component,
            component.ReleaseId,
            component.CompleteTreeSha256);
        PersonalReleaseArtifactInstaller.RequireEnsouClientSignatures(
            component.Directory,
            component.Component);
        PersonalPathGuard.ValidateSafeTree(component.Directory, layout.ManagedRoot);
    }

    private static bool ComponentMatches(
        PersonalAcceptedComponentIdentity accepted,
        PersonalReleaseArtifact artifact) =>
        string.Equals(accepted.Component, artifact.Component, StringComparison.Ordinal)
        && string.Equals(accepted.ReleaseId, artifact.ReleaseId, StringComparison.Ordinal)
        && string.Equals(accepted.ArchiveSha256, artifact.Sha256, StringComparison.Ordinal)
        && string.Equals(
            accepted.CompleteTreeSha256,
            artifact.CompleteTreeSha256,
            StringComparison.Ordinal);

    private static bool ComponentMatches(
        PersonalAcceptedComponentIdentity accepted,
        PersonalInstalledComponentReference installed) =>
        string.Equals(accepted.Component, installed.Component, StringComparison.Ordinal)
        && string.Equals(accepted.ReleaseId, installed.ReleaseId, StringComparison.Ordinal)
        && string.Equals(
            accepted.ArchiveSha256,
            installed.ArchiveSha256,
            StringComparison.Ordinal)
        && string.Equals(
            accepted.CompleteTreeSha256,
            installed.CompleteTreeSha256,
            StringComparison.Ordinal);

    private static bool ComponentMatches(
        PersonalInstalledComponentReference installed,
        PersonalReleaseArtifact artifact) =>
        string.Equals(installed.Component, artifact.Component, StringComparison.Ordinal)
        && string.Equals(installed.ReleaseId, artifact.ReleaseId, StringComparison.Ordinal)
        && string.Equals(installed.ArchiveSha256, artifact.Sha256, StringComparison.Ordinal)
        && string.Equals(
            installed.CompleteTreeSha256,
            artifact.CompleteTreeSha256,
            StringComparison.Ordinal);

    private static bool StartupStubMatches(
        PersonalStartupStubCompatibility accepted,
        PersonalStartupStubCompatibility actual) =>
        accepted is not null
        && actual is not null
        && string.Equals(
            accepted.MinimumVersion,
            actual.MinimumVersion,
            StringComparison.Ordinal)
        && string.Equals(
            accepted.MaximumVersion,
            actual.MaximumVersion,
            StringComparison.Ordinal);

    private static void RequireUtc(DateTimeOffset value)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "Personal component reuse observation time must be UTC.");
        }
    }
}
