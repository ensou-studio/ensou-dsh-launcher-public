using System.Net;
using System.Net.Http;
using System.IO;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Launcher;

internal sealed record PersonalUpdateCheckOutcomeV2(
    string Title,
    string Detail,
    string AvailableVersion,
    bool UpdateAvailable,
    bool MustUpdate,
    VerifiedPersonalReleaseSetManifest Verified);

internal static class PersonalUpdateCoordinatorV2
{
    public static async Task<PersonalUpdateCheckOutcomeV2> CheckAsync(
        LauncherSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var layout = PersonalInstallationLayout.CreateDefault();
        var manifestUri = ValidateManifestUri(
            TrustedReleaseKeyProvider.GetPersonalManifestUri(settings));
        var policy = await TrustedReleaseKeyProvider.GetPersonalV2PolicyAsync(
            settings,
            cancellationToken).ConfigureAwait(false);
        RequireSameOrigin(manifestUri, policy.ArtifactOrigin, allowDifferentPath: true);
        using var client = CreateHttpClient(TimeSpan.FromSeconds(20));
        return await CheckAsync(
            settings,
            layout,
            manifestUri,
            policy,
            client,
            DateTimeOffset.UtcNow,
            cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<PersonalUpdateCheckOutcomeV2> CheckAsync(
        LauncherSettings settings,
        PersonalInstallationLayout layout,
        Uri manifestUri,
        PersonalReleaseTrustPolicy policy,
        HttpClient client,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(manifestUri);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(client);
        if (observedNowUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "Personal update observation time must be UTC.",
                nameof(observedNowUtc));
        }
        var installedAtStart = File.Exists(layout.ReleaseSetPointerPath);
        await using var operationLease =
            await PersonalManagedUpdateOperationLease.AcquireRequiredAsync(
                layout,
                cancellationToken).ConfigureAwait(false);
        if (installedAtStart
            && (!Directory.Exists(layout.ManagedRoot)
                || !File.Exists(layout.ReleaseSetPointerPath)))
        {
            throw new InvalidDataException(
                "Personal managed installation disappeared before update admission.");
        }
        manifestUri = ValidateManifestUri(manifestUri);
        RequireSameOrigin(manifestUri, policy.ArtifactOrigin, allowDifferentPath: true);
        using var response = await client.GetAsync(
            manifestUri,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        RequireEffectiveManifestUri(manifestUri, response);
        response.EnsureSuccessStatusCode();
        var bytes = await ReadLimitedAsync(
            response.Content,
            PersonalReleaseSetContract.MaximumManifestBytes,
            cancellationToken).ConfigureAwait(false);

        // This parse can only reject an unsupported local path. It does not admit an update;
        // signature and anti-rollback verification below remain mandatory. Reject before the
        // security store can advance or repair its durable copies for this candidate.
        PersonalExecutablePathBudget.RequireCandidate(layout, PersonalReleaseSetJson.Parse(bytes));

        var state = new PersonalReleaseSecurityStateStore(
            layout.UpdateSecurityStatePath,
            new PersonalReleaseStateIdentity(
                PersonalReleaseSetContract.Product,
                PersonalReleaseSetContract.ProductionEnvironment,
                settings.Channel),
            layout.UpdateSecurityWitnessPath);
        var admitted = await state.VerifyAndAcceptAsync(
            bytes,
            policy,
            observedNowUtc,
            cancellationToken).ConfigureAwait(false);
        PersonalExecutablePathBudget.RequireCandidate(layout, admitted.Verified.Manifest);
        var pointerStore = new PersonalReleaseSetPointerStore(layout);
        var pointer = pointerStore.TryRead();
        var current = pointer?.Current;
        var manifest = admitted.Verified.Manifest;
        var updateAvailable = current is null
            || manifest.Sequence > current.Sequence
            || !string.Equals(
                manifest.ReleaseSetId,
                current.ReleaseSetId,
                StringComparison.Ordinal);
        var exactRuntimeReuse = false;
        if (pointer is not null)
        {
            var reusable = await PersonalInstalledComponentReuseResolver.ResolveAsync(
                layout,
                admitted.Verified,
                observedNowUtc,
                cancellationToken).ConfigureAwait(false);
            exactRuntimeReuse = reusable.Runtime is not null
                && PersonalReleaseSetPointerStore.InstalledComponentsMatch(
                    pointer.Current.Runtime,
                    reusable.Runtime);
        }
        if (updateAvailable
            && exactRuntimeReuse
            && PersonalReleaseVersion.Compare(
                manifest.StartupStub.MinimumVersion,
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion) < 0)
        {
            throw new InvalidDataException(
                $"Runtime-reused Personal updates require Startup Stub {PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion} or later.");
        }
        if (pointer is not null
            && pointer.Current.HealthState == PersonalReleaseHealthStates.Healthy
            && pointer.Previous is not { HealthState: not PersonalReleaseHealthStates.Healthy }
            && (exactRuntimeReuse
                || new PersonalHarnessHomeTransaction(
                        layout.HarnessHome,
                        layout.HarnessRecoveryRoot)
                    .TryReadActive() is null))
        {
            _ = new PersonalManagedArtifactGarbageCollector(layout)
                .CollectTrustedUnderLease(
                    pointer,
                    pointerStore.ReadRequired,
                    observedNowUtc);
        }
        var mustUpdate = current is not null
            && (current.Sequence < manifest.MinAcceptedSequence
                || manifest.RevokedReleaseSetIds.Contains(
                    current.ReleaseSetId,
                    StringComparer.Ordinal));
        return new PersonalUpdateCheckOutcomeV2(
            updateAvailable ? "发现已签名更新" : "当前已是通道最新版本",
            updateAvailable
                ? $"已验证 release-set {manifest.ReleaseSetId}；将原子切换签名兼容组合，仅下载变化组件并复用未变组件。"
                : $"{manifest.Channel} 通道的双组件 release-set 已验证，本机无需更新。",
            manifest.Provenance.HarnessSourceTag,
            updateAvailable,
            mustUpdate,
            admitted.Verified);
    }

    public static async Task<PersonalAcquiredReleaseSet> DownloadAsync(
        LauncherSettings settings,
        PersonalUpdateCheckOutcomeV2 outcome,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(outcome);
        if (!outcome.UpdateAvailable)
        {
            throw new InvalidOperationException("No personal release-set download is required.");
        }
        var layout = PersonalInstallationLayout.CreateDefault();
        using var client = CreateHttpClient(TimeSpan.FromHours(2));
        return await DownloadAsync(
            layout,
            client,
            outcome,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<PersonalAcquiredReleaseSet> DownloadAsync(
        PersonalInstallationLayout layout,
        HttpClient client,
        PersonalUpdateCheckOutcomeV2 outcome,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(outcome);
        if (!outcome.UpdateAvailable)
        {
            throw new InvalidOperationException("No personal release-set download is required.");
        }
        return await new PersonalReleaseArtifactAcquisitionService(layout, client)
            .AcquireAsync(
                outcome.Verified,
                progress,
                cancellationToken).ConfigureAwait(false);
    }

    public static async Task<PersonalReleaseSetInstallationResult> StageAsync(
        LauncherSettings settings,
        PersonalUpdateCheckOutcomeV2 outcome,
        PersonalAcquiredReleaseSet download,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(outcome);
        ArgumentNullException.ThrowIfNull(download);
        var layout = PersonalInstallationLayout.CreateDefault();
        return await StageAsync(
            settings,
            layout,
            outcome,
            download,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<PersonalReleaseSetInstallationResult> StageAsync(
        LauncherSettings settings,
        PersonalInstallationLayout layout,
        PersonalUpdateCheckOutcomeV2 outcome,
        PersonalAcquiredReleaseSet download,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(outcome);
        ArgumentNullException.ThrowIfNull(download);
        if (!string.Equals(
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(settings.DshDataDirectory)),
                layout.HarnessHome,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal v2 update requires the certified default Harness home.");
        }
        return await new PersonalReleaseArtifactInstaller()
            .InstallAcquiredReleaseSetAsync(
                layout,
                outcome.Verified,
                download,
                settings.Port,
                progress,
                cancellationToken).ConfigureAwait(false);
    }

    private static HttpClient CreateHttpClient(TimeSpan timeout) => new(
        new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
        },
        disposeHandler: true)
    {
        Timeout = timeout,
    };

    private static Uri ValidateManifestUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidDataException("Personal release-set URL is invalid.");
        }
        var development = uri.Scheme == Uri.UriSchemeHttp
            && uri.IsLoopback
            && string.Equals(
                Environment.GetEnvironmentVariable("ENSOU_DSH_ALLOW_DEVELOPMENT_KEY"),
                "1",
                StringComparison.Ordinal);
        if (uri.Scheme != Uri.UriSchemeHttps && !development)
        {
            throw new InvalidDataException(
                "Personal release-set URL must use HTTPS outside explicit loopback development.");
        }
        return uri;
    }

    private static void RequireEffectiveManifestUri(
        Uri requested,
        HttpResponseMessage response)
    {
        var effective = response.RequestMessage?.RequestUri
            ?? throw new InvalidDataException(
                "Personal release-set response has no effective URI.");
        RequireSameOrigin(requested, effective, allowDifferentPath: false);
        if (!string.Equals(requested.AbsoluteUri, effective.AbsoluteUri, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal release-set request was redirected.");
        }
    }

    private static void RequireSameOrigin(
        Uri expected,
        Uri actual,
        bool allowDifferentPath)
    {
        if (!string.Equals(expected.Scheme, actual.Scheme, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(expected.IdnHost, actual.IdnHost, StringComparison.OrdinalIgnoreCase)
            || expected.Port != actual.Port
            || !allowDifferentPath
                && !string.Equals(
                    expected.AbsolutePath,
                    actual.AbsolutePath,
                    StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal release-set crossed its pinned update origin.");
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > maximumBytes)
        {
            throw new InvalidDataException("Personal release-set exceeds its size limit.");
        }
        await using var input = await content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = GC.AllocateUninitializedArray<byte>(16 * 1024);
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            if (output.Length + read > maximumBytes)
            {
                throw new InvalidDataException(
                    "Personal release-set exceeds its size limit.");
            }
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                .ConfigureAwait(false);
        }
        return output.ToArray();
    }
}
