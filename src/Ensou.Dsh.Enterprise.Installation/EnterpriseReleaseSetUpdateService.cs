using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Ensou.Dsh.Enterprise.Installation;

public sealed record EnterpriseReleaseUpdateOutcome(
    string State,
    string Message,
    EnterpriseReleaseSetPointer ActivePointer,
    bool RequiresBootstrapHealthCheck);

/// <summary>
/// Read-only result of a verified enterprise release-feed probe. A caller must
/// run the ordinary exclusive stage after <see cref="RequiresExclusiveStage"/>
/// is true; this probe never creates a lock, cache, receipt, or package tree.
/// </summary>
public sealed record EnterpriseReleaseUpdatePreflight(
    EnterpriseReleaseUpdateOutcome? TerminalOutcome,
    bool RequiresExclusiveStage)
{
    /// <summary>Creates a terminal, non-mutating probe result.</summary>
    public static EnterpriseReleaseUpdatePreflight Terminal(
        EnterpriseReleaseUpdateOutcome outcome) =>
        new(outcome ?? throw new ArgumentNullException(nameof(outcome)), false);

    /// <summary>Creates a result requiring the existing exclusive stage.</summary>
    public static EnterpriseReleaseUpdatePreflight RequiresStage() => new(null, true);
}

/// <summary>
/// The single startup entry point used by the enterprise Launcher. Keeping the
/// automatic check here makes it independently testable without starting WPF.
/// </summary>
public sealed class EnterpriseReleaseStartupCoordinator(
    EnterpriseInstallationLayout layout,
    Uri manifestUri,
    EnterpriseReleaseTrustPolicy trustPolicy,
    HttpClient httpClient,
    TimeProvider? timeProvider = null,
    int harnessPort = 3080)
{
    private readonly Action _requireNoPossibleHarnessWriter =
        () => EnterpriseHarnessProcessWriterGuard
            .RequireNoPossibleHarnessWriter(layout);
    private readonly Action<int> _requireQuiescentLoopbackPort =
        EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort;

    internal EnterpriseReleaseStartupCoordinator(
        EnterpriseInstallationLayout layout,
        Uri manifestUri,
        EnterpriseReleaseTrustPolicy trustPolicy,
        HttpClient httpClient,
        TimeProvider? timeProvider,
        int harnessPort,
        Action requireNoPossibleHarnessWriter,
        Action<int> requireQuiescentLoopbackPort)
        : this(
            layout,
            manifestUri,
            trustPolicy,
            httpClient,
            timeProvider,
            harnessPort)
    {
        _requireNoPossibleHarnessWriter = requireNoPossibleHarnessWriter
            ?? throw new ArgumentNullException(nameof(requireNoPossibleHarnessWriter));
        _requireQuiescentLoopbackPort = requireQuiescentLoopbackPort
            ?? throw new ArgumentNullException(nameof(requireQuiescentLoopbackPort));
    }

    public Task<EnterpriseReleaseUpdateOutcome> CheckOnEveryStartupAsync(
        CancellationToken cancellationToken = default) =>
        new EnterpriseReleaseSetUpdateService(
            layout,
            trustPolicy,
            httpClient,
            timeProvider,
            harnessPort,
            beforeLegacySqlitePointerActivationForTest: null,
            requireNoPossibleHarnessWriter: _requireNoPossibleHarnessWriter,
            requireQuiescentLoopbackPort: _requireQuiescentLoopbackPort)
        .CheckAndStageAsync(manifestUri, cancellationToken);

    /// <summary>
    /// Verifies whether the authenticated feed advertises a release-set change
    /// without entering the managed update critical section. It intentionally
    /// does not record feed state, recover transactions, download artifacts, or
    /// write update status; callers must use <see cref="CheckOnEveryStartupAsync"/>
    /// after separately obtaining runtime quiescence.
    /// </summary>
    public Task<EnterpriseReleaseUpdatePreflight> ProbeVerifiedReleaseAsync(
        CancellationToken cancellationToken = default) =>
        new EnterpriseReleaseSetUpdateService(
            layout,
            trustPolicy,
            httpClient,
            timeProvider,
            harnessPort)
        .ProbeVerifiedReleaseAsync(manifestUri, cancellationToken);
}

public sealed class EnterpriseReleaseSetUpdateService(
    EnterpriseInstallationLayout layout,
    EnterpriseReleaseTrustPolicy trustPolicy,
    HttpClient httpClient,
    TimeProvider? timeProvider = null,
    int harnessPort = 3080)
{
    private const int MaximumArchiveEntries = 200_000;
    private const long MaximumExpandedArchiveBytes = 8L * 1024 * 1024 * 1024;
    private readonly EnterpriseInstallationLayout _layout = layout
        ?? throw new ArgumentNullException(nameof(layout));
    private readonly EnterpriseReleaseTrustPolicy _trustPolicy = trustPolicy
        ?? throw new ArgumentNullException(nameof(trustPolicy));
    private readonly HttpClient _httpClient = httpClient
        ?? throw new ArgumentNullException(nameof(httpClient));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly int _harnessPort = harnessPort is >= 1 and <= 65535
        ? harnessPort
        : throw new ArgumentOutOfRangeException(nameof(harnessPort));
    private readonly Action _requireNoPossibleHarnessWriter =
        () => EnterpriseHarnessProcessWriterGuard
            .RequireNoPossibleHarnessWriter(layout);
    private readonly Action<int> _requireQuiescentLoopbackPort =
        EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort;
    private Action? _beforeLegacySqlitePointerActivationForTest;

    internal EnterpriseReleaseSetUpdateService(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseTrustPolicy trustPolicy,
        HttpClient httpClient,
        TimeProvider? timeProvider,
        int harnessPort,
        Action beforeLegacySqlitePointerActivationForTest)
        : this(
            layout,
            trustPolicy,
            httpClient,
            timeProvider,
            harnessPort,
            beforeLegacySqlitePointerActivationForTest,
            () => EnterpriseHarnessProcessWriterGuard
                .RequireNoPossibleHarnessWriter(layout),
            EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort)
    {
    }

    internal EnterpriseReleaseSetUpdateService(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseTrustPolicy trustPolicy,
        HttpClient httpClient,
        TimeProvider? timeProvider,
        int harnessPort,
        Action? beforeLegacySqlitePointerActivationForTest,
        Action requireNoPossibleHarnessWriter,
        Action<int> requireQuiescentLoopbackPort)
        : this(layout, trustPolicy, httpClient, timeProvider, harnessPort)
    {
        _beforeLegacySqlitePointerActivationForTest =
            beforeLegacySqlitePointerActivationForTest;
        _requireNoPossibleHarnessWriter = requireNoPossibleHarnessWriter
            ?? throw new ArgumentNullException(nameof(requireNoPossibleHarnessWriter));
        _requireQuiescentLoopbackPort = requireQuiescentLoopbackPort
            ?? throw new ArgumentNullException(nameof(requireQuiescentLoopbackPort));
    }

    public async Task<EnterpriseReleaseUpdateOutcome> CheckAndStageAsync(
        Uri manifestUri,
        CancellationToken cancellationToken = default)
    {
        RequireManifestUri(manifestUri);
        _trustPolicy.Validate();
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
            _layout,
            _requireNoPossibleHarnessWriter);
        _layout.EnsureUpdateOperationLockRoot();
        var compiledTrust = new EnterpriseCompiledReleaseTrust(manifestUri, _trustPolicy);
        if (File.Exists(_layout.ReleaseSetPointerPath))
        {
            _ = await new EnterpriseManagedArtifactGarbageCollector(
                    _layout,
                    compiledTrust,
                    _timeProvider)
                .CollectAsync(cancellationToken).ConfigureAwait(false);
        }
        await using var operationLease =
            await EnterpriseManagedUpdateOperationLease.AcquireRequiredAsync(
                _layout,
                cancellationToken).ConfigureAwait(false);
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
            _layout,
            _requireNoPossibleHarnessWriter);
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(_layout);
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
            _layout,
            _requireNoPossibleHarnessWriter);
        if (!Directory.Exists(_layout.ManagedRoot))
        {
            throw new InvalidDataException(
                "Enterprise managed installation disappeared before update admission.");
        }
        _layout.EnsureManagedRoots();
        compiledTrust.Validate(_layout);
        var pointerStore = new EnterpriseReleaseSetPointerStore(
            _layout,
            compiledTrust,
            _timeProvider);
        var feedStateStore = new EnterpriseReleaseFeedStateStore(
            _layout,
            _trustPolicy.ExpectedChannel,
            _timeProvider,
            _trustPolicy.MaximumOfflineGrace);
        var active = pointerStore.ReadRequired();
        var updateStatusExisted = File.Exists(_layout.UpdateStatusPath);
        var originalUpdateStatus = updateStatusExisted
            ? File.ReadAllBytes(_layout.UpdateStatusPath)
            : null;
        var homeTransaction = new EnterpriseHarnessHomeUpdateTransaction(
            _layout.HarnessHome,
            _layout.HarnessRecoveryRoot,
            _timeProvider,
            moveGapHookForTesting: null,
            requireQuiescentLoopbackPort: _requireQuiescentLoopbackPort,
            requireNoPossibleHarnessWriter: _requireNoPossibleHarnessWriter);
        var interruptedHome = homeTransaction.TryReadActiveState();
        if (interruptedHome is not null
            && active.Current.HealthState == EnterpriseReleaseHealthStates.Healthy)
        {
            if (interruptedHome.Status
                    == EnterpriseHarnessHomeUpdateTransaction.HealthPassedStatus
                && string.Equals(
                    interruptedHome.ReleaseSetId,
                    active.Current.ReleaseSetId,
                    StringComparison.Ordinal))
            {
                homeTransaction.FinalizeCommit(interruptedHome.TransactionId);
            }
            else
            {
                _ = homeTransaction.RecoverInterrupted();
            }
        }

        byte[] manifestBytes;
        try
        {
            using var manifestTimeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            manifestTimeout.CancelAfter(_trustPolicy.ManifestRequestTimeout);
            manifestBytes = await DownloadManifestAsync(
                manifestUri,
                manifestTimeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            !cancellationToken.IsCancellationRequested
            && IsAvailabilityFailure(exception))
        {
            return OfflineOutcome(active, feedStateStore);
        }

        EnterpriseReleaseSetManifest manifest;
        try
        {
            manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
            EnterpriseReleaseSetValidator.Verify(
                manifest,
                _trustPolicy,
                _timeProvider.GetUtcNow());
            if (manifest.Generation < active.Current.Generation
                || manifest.Sequence < active.Current.Sequence)
            {
                throw new InvalidDataException(
                    "Enterprise release-set is older than the active installation.");
            }
            _ = feedStateStore.RecordVerified(
                manifest,
                manifestBytes,
                manifestUri,
                active,
                _timeProvider.GetUtcNow());
        }
        catch (InvalidDataException exception)
        {
            if (feedStateStore.IsCurrentAllowedOffline(active.Current, out _))
            {
                EnterpriseReleaseStateFiles.WriteStatus(
                    _layout,
                    "security-rejected",
                    "更新元数据未通过安全校验；继续使用上次已验证的健康版本。",
                    active.Current,
                    mustUpdate: false);
                EnterpriseReleaseStateFiles.WriteReceipt(
                    _layout,
                    "manifest-rejected",
                    active.Current,
                    exception.GetType().Name);
                return new EnterpriseReleaseUpdateOutcome(
                    "security-rejected",
                    "更新元数据未通过安全校验；旧版本保持不变。",
                    active,
                    false);
            }
            EnterpriseReleaseStateFiles.WriteStatus(
                _layout,
                "blocked",
                "更新安全状态无法满足强制版本要求，已停止启动。",
                active.Current,
                mustUpdate: true);
            throw;
        }

        var mustUpdate = active.Current.Sequence < manifest.MinAcceptedSequence
            || manifest.RevokedReleaseSetIds.Contains(
                active.Current.ReleaseSetId,
                StringComparer.Ordinal);
        if (new EnterpriseReleaseHealthQuarantineStore(_layout)
            .IsRejected(manifest.ReleaseSetId))
        {
            if (!mustUpdate
                && feedStateStore.IsCurrentAllowedOffline(active.Current, out var reason))
            {
                EnterpriseReleaseStateFiles.WriteStatus(
                    _layout,
                    "health-rejected-old-allowed",
                    "该更新此前未通过启动自检；继续使用健康旧版本并等待管理员发布新序列。",
                    active.Current,
                    mustUpdate: false);
                EnterpriseReleaseStateFiles.WriteReceipt(
                    _layout,
                    "health-rejected-old-allowed",
                    active.Current,
                    manifest.ReleaseSetId);
                return new EnterpriseReleaseUpdateOutcome(
                    "health-rejected-old-allowed",
                    reason,
                    active,
                    false);
            }
            EnterpriseReleaseStateFiles.WriteStatus(
                _layout,
                "blocked",
                "强制更新版本此前未通过启动自检；管理员必须发布新的受信序列。",
                active.Current,
                mustUpdate: true);
            throw new InvalidOperationException(
                "The mandatory enterprise release was previously rejected by health verification.");
        }
        if (string.Equals(
                active.Current.ReleaseSetId,
                manifest.ReleaseSetId,
                StringComparison.Ordinal)
            && active.Current.Generation == manifest.Generation
            && active.Current.Sequence == manifest.Sequence
            && ActiveTupleMatchesManifest(active.Current, manifest)
            && string.Equals(
                feedStateStore.ReadAcceptedIdentityRequired(
                    active.Current,
                    compiledTrust).ManifestSha256,
                Convert.ToHexStringLower(SHA256.HashData(manifestBytes)),
                StringComparison.Ordinal)
            && active.Current.HealthState == EnterpriseReleaseHealthStates.Healthy)
        {
            EnterpriseReleaseStateFiles.WriteStatus(
                _layout,
                "up-to-date",
                "企业组件已是最新的受信版本。",
                active.Current,
                mustUpdate: false);
            return new EnterpriseReleaseUpdateOutcome(
                "up-to-date",
                "企业组件已是最新版本。",
                active,
                false);
        }

        EnterpriseReleaseStateFiles.WriteStatus(
            _layout,
            "downloading",
            "正在下载并验证企业更新包。",
            active.Current,
            mustUpdate);
        var operationDirectory = Path.Combine(
            _layout.PackageRoot,
            $".release-set-{Guid.NewGuid():N}");
        EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, operationDirectory);
        EnterpriseHarnessHomePreparedTransaction? preparedHome = null;
        try
        {
            foreach (var artifact in manifest.Artifacts)
            {
                if (TryReuseAuthorizedArtifact(active, manifest, artifact))
                {
                    continue;
                }
                var packagePath = Path.Combine(
                    operationDirectory,
                    $"{artifact.Component}-{artifact.ReleaseId}.zip");
                await DownloadArtifactAsync(
                    artifact,
                    packagePath,
                    cancellationToken).ConfigureAwait(false);
                await EnsureArtifactInstalledAsync(
                    artifact,
                    packagePath,
                    manifest.Launcher.ReleaseId,
                    manifest.Runtime.ReleaseId,
                    cancellationToken).ConfigureAwait(false);
            }

            if (!string.Equals(
                    active.Current.Runtime.ReleaseId,
                    manifest.Runtime.ReleaseId,
                    StringComparison.Ordinal))
            {
                EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
                    _layout,
                    _requireNoPossibleHarnessWriter);
                _requireQuiescentLoopbackPort(_harnessPort);
                EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
                    _layout,
                    _requireNoPossibleHarnessWriter);
                preparedHome = homeTransaction.Prepare(
                    manifest.ReleaseSetId,
                    _harnessPort,
                    () => EnterpriseLegacySqliteUpgradeGuard
                        .RequireJsonlOnlyHarnessHomeAndNoWriter(
                            _layout,
                            _requireNoPossibleHarnessWriter));
            }
            _beforeLegacySqlitePointerActivationForTest?.Invoke();
            EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
                _layout,
                _requireNoPossibleHarnessWriter);
            var pending = pointerStore.ActivatePending(manifest);
            EnterpriseReleaseStateFiles.WriteStatus(
                _layout,
                "pending-health",
                "更新已安装；下次启动将完成健康握手，失败会自动回退。",
                pending.Current,
                mustUpdate);
            return new EnterpriseReleaseUpdateOutcome(
                "pending-health",
                "更新已暂存并原子切换，等待 Bootstrapper 健康确认。",
                pending,
                true);
        }
        catch (Exception exception) when (
            EnterpriseLegacySqliteUpgradeGuard.IsBlockedFailure(exception))
        {
            try
            {
                if (preparedHome is not null)
                {
                    _ = homeTransaction.Rollback(
                        preparedHome.TransactionId,
                        "legacy-sqlite-admission-failed");
                }
                RestoreUpdateStatus(updateStatusExisted, originalUpdateStatus);
            }
            catch
            {
                throw new InvalidOperationException(
                    "DSH_LEGACY_SQLITE_UPDATE_ROLLBACK_FAILED：检测到旧版 DSH SQLite 风险，但无法确认更新状态已完整回退。请立即联系管理员。");
            }
            throw;
        }
        catch (Exception exception) when (
            (!cancellationToken.IsCancellationRequested && IsAvailabilityFailure(exception))
            || exception is InvalidDataException)
        {
            if (preparedHome is not null)
            {
                try
                {
                    _ = homeTransaction.Rollback(
                        preparedHome.TransactionId,
                        "activation-or-artifact-failed");
                }
                catch (Exception recoveryException)
                {
                    throw new InvalidOperationException(
                        "Enterprise update failed and the original Harness home could not be restored automatically.",
                        new AggregateException(exception, recoveryException));
                }
            }
            active = pointerStore.ReadRequired();
            if (feedStateStore.IsCurrentAllowedOffline(active.Current, out var reason))
            {
                EnterpriseReleaseStateFiles.WriteStatus(
                    _layout,
                    "download-failed-old-allowed",
                    "更新包未能完整验证；继续使用健康旧版本。",
                    active.Current,
                    mustUpdate: false);
                EnterpriseReleaseStateFiles.WriteReceipt(
                    _layout,
                    "artifact-rejected",
                    active.Current,
                    exception.GetType().Name);
                return new EnterpriseReleaseUpdateOutcome(
                    "download-failed-old-allowed",
                    reason,
                    active,
                    false);
            }
            EnterpriseReleaseStateFiles.WriteStatus(
                _layout,
                "blocked",
                "必须更新或当前版本已吊销，但新包未能完整验证。",
                active.Current,
                mustUpdate: true);
            throw new InvalidOperationException(
                "Enterprise update is mandatory, but the new release could not be verified.",
                exception);
        }
        finally
        {
            if (Directory.Exists(operationDirectory))
            {
                EnterprisePathGuard.DeleteDirectoryTree(
                    operationDirectory,
                    _layout.ManagedRoot);
            }
        }
    }

    /// <summary>
    /// Performs the read-only half of automatic update admission. This method
    /// must remain independent from <see cref="CheckAndStageAsync"/> because
    /// the latter intentionally obtains writer exclusion before doing any work.
    /// </summary>
    public async Task<EnterpriseReleaseUpdatePreflight> ProbeVerifiedReleaseAsync(
        Uri manifestUri,
        CancellationToken cancellationToken = default)
    {
        RequireManifestUri(manifestUri);
        _trustPolicy.Validate();
        if (!Directory.Exists(_layout.ManagedRoot))
        {
            throw new InvalidDataException(
                "Enterprise managed installation disappeared before update preflight.");
        }

        var compiledTrust = new EnterpriseCompiledReleaseTrust(manifestUri, _trustPolicy);
        compiledTrust.Validate(_layout);
        var pointerStore = new EnterpriseReleaseSetPointerStore(
            _layout,
            compiledTrust,
            _timeProvider);
        var feedStateStore = new EnterpriseReleaseFeedStateStore(
            _layout,
            _trustPolicy.ExpectedChannel,
            _timeProvider,
            _trustPolicy.MaximumOfflineGrace);
        var active = pointerStore.ReadRequired();

        byte[] manifestBytes;
        try
        {
            using var manifestTimeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            manifestTimeout.CancelAfter(_trustPolicy.ManifestRequestTimeout);
            manifestBytes = await DownloadManifestAsync(
                manifestUri,
                manifestTimeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            !cancellationToken.IsCancellationRequested
            && IsAvailabilityFailure(exception))
        {
            return EnterpriseReleaseUpdatePreflight.Terminal(
                ReadOnlyOfflineOutcome(active, feedStateStore));
        }

        EnterpriseReleaseSetManifest manifest;
        try
        {
            manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
            EnterpriseReleaseSetValidator.Verify(
                manifest,
                _trustPolicy,
                _timeProvider.GetUtcNow());
            if (manifest.Generation < active.Current.Generation
                || manifest.Sequence < active.Current.Sequence)
            {
                throw new InvalidDataException(
                    "Enterprise release-set is older than the active installation.");
            }
        }
        catch (InvalidDataException exception)
        {
            if (feedStateStore.IsCurrentAllowedOfflineReadOnly(active.Current, out _))
            {
                return EnterpriseReleaseUpdatePreflight.Terminal(new EnterpriseReleaseUpdateOutcome(
                    "security-rejected",
                    "更新元数据未通过安全校验；旧版本保持不变。",
                    active,
                    false));
            }
            throw new InvalidOperationException(
                "Enterprise release metadata failed verification while a mandatory update may apply.",
                exception);
        }

        var mustUpdate = active.Current.Sequence < manifest.MinAcceptedSequence
            || manifest.RevokedReleaseSetIds.Contains(
                active.Current.ReleaseSetId,
                StringComparer.Ordinal);
        if (new EnterpriseReleaseHealthQuarantineStore(_layout)
            .IsRejected(manifest.ReleaseSetId))
        {
            if (!mustUpdate
                && feedStateStore.IsCurrentAllowedOfflineReadOnly(active.Current, out var reason))
            {
                return EnterpriseReleaseUpdatePreflight.Terminal(new EnterpriseReleaseUpdateOutcome(
                    "health-rejected-old-allowed",
                    reason,
                    active,
                    false));
            }
            throw new InvalidOperationException(
                "The mandatory enterprise release was previously rejected by health verification.");
        }

        if (string.Equals(
                active.Current.ReleaseSetId,
                manifest.ReleaseSetId,
                StringComparison.Ordinal)
            && active.Current.Generation == manifest.Generation
            && active.Current.Sequence == manifest.Sequence
            && ActiveTupleMatchesManifest(active.Current, manifest)
            && string.Equals(
                feedStateStore.ReadAcceptedIdentityRequired(
                    active.Current,
                    compiledTrust).ManifestSha256,
                Convert.ToHexStringLower(SHA256.HashData(manifestBytes)),
                StringComparison.Ordinal)
            && active.Current.HealthState == EnterpriseReleaseHealthStates.Healthy)
        {
            return EnterpriseReleaseUpdatePreflight.Terminal(new EnterpriseReleaseUpdateOutcome(
                "up-to-date",
                "企业组件已是最新版本。",
                active,
                false));
        }

        return EnterpriseReleaseUpdatePreflight.RequiresStage();
    }

    private void RestoreUpdateStatus(bool existed, byte[]? original)
    {
        if (existed)
        {
            if (original is null)
            {
                throw new InvalidDataException(
                    "Enterprise update-status rollback snapshot is missing.");
            }
            EnterprisePathGuard.WriteFileAtomically(
                _layout.UpdateStatusPath,
                original,
                _layout.ManagedRoot);
            return;
        }

        if (Directory.Exists(_layout.UpdateStatusPath))
        {
            throw new InvalidDataException(
                "Enterprise update-status rollback path became a directory.");
        }
        if (!File.Exists(_layout.UpdateStatusPath))
        {
            return;
        }
        EnterprisePathGuard.ValidateExistingPathWithin(
            _layout.UpdateStatusPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        EnterpriseManagedGcPathSafety.RequireSingleLinkFile(
            _layout.UpdateStatusPath,
            _layout.ManagedRoot);
        File.Delete(_layout.UpdateStatusPath);
    }

    private EnterpriseReleaseUpdateOutcome OfflineOutcome(
        EnterpriseReleaseSetPointer active,
        EnterpriseReleaseFeedStateStore feedStateStore)
    {
        if (feedStateStore.IsCurrentAllowedOffline(active.Current, out var reason))
        {
            EnterpriseReleaseStateFiles.WriteStatus(
                _layout,
                "offline-last-known-good",
                reason,
                active.Current,
                mustUpdate: false);
            EnterpriseReleaseStateFiles.WriteReceipt(
                _layout,
                "offline-last-known-good",
                active.Current,
                null);
            return new EnterpriseReleaseUpdateOutcome(
                "offline-last-known-good",
                reason,
                active,
                false);
        }
        EnterpriseReleaseStateFiles.WriteStatus(
            _layout,
            "blocked",
            reason,
            active.Current,
            mustUpdate: true);
        throw new InvalidOperationException(
            $"Enterprise update check failed and offline use is forbidden: {reason}");
    }

    private EnterpriseReleaseUpdateOutcome ReadOnlyOfflineOutcome(
        EnterpriseReleaseSetPointer active,
        EnterpriseReleaseFeedStateStore feedStateStore)
    {
        if (feedStateStore.IsCurrentAllowedOfflineReadOnly(active.Current, out var reason))
        {
            return new EnterpriseReleaseUpdateOutcome(
                "offline-last-known-good",
                reason,
                active,
                false);
        }

        throw new InvalidOperationException(
            "Enterprise release metadata is unavailable and the current release is not eligible for offline use.");
    }

    private static bool ActiveTupleMatchesManifest(
        EnterpriseReleaseSetReference active,
        EnterpriseReleaseSetManifest manifest) =>
        active.MinAcceptedSequence == manifest.MinAcceptedSequence
        && active.StartupStub.MinimumProtocol == manifest.StartupStub.MinimumProtocol
        && active.StartupStub.MaximumProtocol == manifest.StartupStub.MaximumProtocol
        && ComponentMatches(active.Launcher, manifest.Launcher)
        && ComponentMatches(active.Runtime, manifest.Runtime)
        && (active.PluginPolicy is null
            ? manifest.PluginPolicy is null
            : manifest.PluginPolicy is not null
                && ComponentMatches(active.PluginPolicy, manifest.PluginPolicy));

    private static bool ComponentMatches(
        EnterpriseReleaseComponentPointer active,
        EnterpriseReleaseArtifact manifest) =>
        string.Equals(active.ReleaseId, manifest.ReleaseId, StringComparison.Ordinal)
        && string.Equals(active.ArchiveSha256, manifest.Sha256, StringComparison.Ordinal)
        && string.Equals(
            active.CompleteTreeSha256,
            manifest.CompleteTreeSha256,
            StringComparison.Ordinal);

    private bool TryReuseAuthorizedArtifact(
        EnterpriseReleaseSetPointer active,
        EnterpriseReleaseSetManifest manifest,
        EnterpriseReleaseArtifact artifact)
    {
        foreach (var release in EnumerateActiveReuseSources(active))
        {
            var installed = artifact.Component switch
            {
                EnterpriseReleaseSetContract.LauncherComponent => release.Launcher,
                EnterpriseReleaseSetContract.RuntimeComponent => release.Runtime,
                EnterpriseReleaseSetContract.PluginPolicyComponent => release.PluginPolicy,
                _ => throw new InvalidDataException(
                    "Unknown enterprise release component."),
            };
            if (installed is null || !ComponentMatches(installed, artifact))
            {
                continue;
            }

            var expectedDirectory = GetArtifactDirectory(artifact);
            if (!string.Equals(
                    EnterprisePathGuard.NormalizeDirectory(installed.Directory),
                    expectedDirectory,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Enterprise reusable component escaped its authenticated version directory.");
            }
            ValidateExistingImmutableArtifact(
                expectedDirectory,
                artifact,
                manifest.Launcher.ReleaseId,
                manifest.Runtime.ReleaseId);
            return true;
        }

        var targetDirectory = GetArtifactDirectory(artifact);
        if (Directory.Exists(targetDirectory) || File.Exists(targetDirectory))
        {
            throw new InvalidDataException(
                "Enterprise target collides with a version directory not authorized by active Current/Previous state.");
        }
        return false;
    }

    private static IEnumerable<EnterpriseReleaseSetReference> EnumerateActiveReuseSources(
        EnterpriseReleaseSetPointer active)
    {
        yield return active.Current;
        if (active.Previous is not null)
        {
            yield return active.Previous;
        }
    }

    private string GetArtifactDirectory(EnterpriseReleaseArtifact artifact) =>
        artifact.Component switch
        {
            EnterpriseReleaseSetContract.LauncherComponent =>
                _layout.GetLauncherVersionDirectory(artifact.ReleaseId),
            EnterpriseReleaseSetContract.RuntimeComponent =>
                _layout.GetRuntimeVersionDirectory(artifact.ReleaseId),
            EnterpriseReleaseSetContract.PluginPolicyComponent =>
                _layout.GetPluginPolicyVersionDirectory(artifact.ReleaseId),
            _ => throw new InvalidDataException("Unknown enterprise release component."),
        };

    private async Task<byte[]> DownloadManifestAsync(
        Uri manifestUri,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, manifestUri);
        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        RequireFinalOrigin(response, _trustPolicy.ManifestOrigin);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > 512 * 1024)
        {
            throw new InvalidDataException("Enterprise release manifest exceeds its size limit.");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(
            cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await ReadWithIdleTimeoutAsync(
                stream,
                buffer,
                _trustPolicy.ManifestRequestTimeout,
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            if (output.Length + read > 512 * 1024)
            {
                throw new InvalidDataException("Enterprise release manifest exceeds its size limit.");
            }
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private async Task DownloadArtifactAsync(
        EnterpriseReleaseArtifact artifact,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        var cache = GetPartialCachePaths(artifact);
        var safetyRestartUsed = false;
        while (true)
        {
            var cached = ReadPartialCache(artifact, cache);
            if (cached.Length == artifact.SizeBytes)
            {
                if (string.Equals(
                        EnterpriseHash.ComputeFile(cache.PartialPath),
                        artifact.Sha256,
                        StringComparison.Ordinal))
                {
                    ConsumeCompletedPartial(cache, destinationPath);
                    return;
                }

                ResetPartialCache(cache);
                if (safetyRestartUsed)
                {
                    throw new InvalidDataException(
                        "Enterprise cached artifact repeatedly failed SHA-256 verification.");
                }
                safetyRestartUsed = true;
                cached = EnterprisePartialCacheState.Empty;
            }

            var resume = cached.Length > 0 && cached.StrongETag is not null;
            using var request = new HttpRequestMessage(HttpMethod.Get, artifact.Uri);
            if (resume)
            {
                request.Headers.Range = new RangeHeaderValue(cached.Length, null);
                request.Headers.IfRange = new RangeConditionHeaderValue(
                    EntityTagHeaderValue.Parse(cached.StrongETag!));
            }

            using var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            try
            {
                RequireFinalOrigin(response, _trustPolicy.ArtifactOrigin);
            }
            catch (InvalidDataException)
            {
                ResetPartialCache(cache);
                throw;
            }

            var append = false;
            if (resume && response.StatusCode == HttpStatusCode.PartialContent)
            {
                if (!IsValidPartialResponse(response, artifact, cached))
                {
                    ResetPartialCache(cache);
                    if (safetyRestartUsed)
                    {
                        throw new InvalidDataException(
                            "Enterprise artifact server repeatedly returned an unsafe range response.");
                    }
                    safetyRestartUsed = true;
                    continue;
                }
                append = true;
            }
            else if (resume && response.StatusCode == HttpStatusCode.OK)
            {
                // If-Range permits a full 200 response when the validator changed, and some
                // static servers simply ignore Range. In both cases replace, never append.
                ResetPartialCache(cache);
                cached = EnterprisePartialCacheState.Empty;
            }
            else if (resume && response.StatusCode == HttpStatusCode.RequestedRangeNotSatisfiable)
            {
                ResetPartialCache(cache);
                if (safetyRestartUsed)
                {
                    throw new InvalidDataException(
                        "Enterprise artifact server repeatedly rejected the cached range.");
                }
                safetyRestartUsed = true;
                continue;
            }
            else
            {
                response.EnsureSuccessStatusCode();
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    ResetPartialCache(cache);
                    throw new InvalidDataException(
                        "Enterprise artifact server returned an unexpected success status.");
                }
            }

            var expectedResponseBytes = append
                ? artifact.SizeBytes - cached.Length
                : artifact.SizeBytes;
            if (response.Content.Headers.ContentLength is long contentLength
                && contentLength != expectedResponseBytes)
            {
                ResetPartialCache(cache);
                if (safetyRestartUsed)
                {
                    throw new InvalidDataException(
                        "Enterprise artifact Content-Length repeatedly disagreed with the signed size.");
                }
                safetyRestartUsed = true;
                continue;
            }

            var responseETag = ReadStrongETag(response);
            if (!append)
            {
                WritePartialCacheMetadata(cache, artifact, responseETag);
            }

            try
            {
                await AppendResponseToPartialAsync(
                    response,
                    cache.PartialPath,
                    append,
                    cached.Length,
                    artifact.SizeBytes,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidDataException)
            {
                ResetPartialCache(cache);
                throw;
            }

            if (new FileInfo(cache.PartialPath).Length != artifact.SizeBytes
                || !string.Equals(
                    EnterpriseHash.ComputeFile(cache.PartialPath),
                    artifact.Sha256,
                    StringComparison.Ordinal))
            {
                ResetPartialCache(cache);
                if (safetyRestartUsed)
                {
                    throw new InvalidDataException(
                        "Enterprise artifact repeatedly failed signed size or SHA-256 verification.");
                }
                safetyRestartUsed = true;
                continue;
            }

            ConsumeCompletedPartial(cache, destinationPath);
            return;
        }
    }

    private EnterprisePartialCachePaths GetPartialCachePaths(
        EnterpriseReleaseArtifact artifact)
    {
        var identity = string.Join(
            '\n',
            "ensou-dsh-enterprise-partial-v2",
            artifact.Component,
            artifact.ReleaseId,
            artifact.Uri.AbsoluteUri,
            artifact.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            artifact.Sha256);
        var key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
        return new EnterprisePartialCachePaths(
            EnterprisePathGuard.CombineExactChild(
                _layout.UpdatePartialCacheRoot,
                $"{key}.partial"),
            EnterprisePathGuard.CombineExactChild(
                _layout.UpdatePartialCacheRoot,
                $"{key}.partial.json"));
    }

    private EnterprisePartialCacheState ReadPartialCache(
        EnterpriseReleaseArtifact artifact,
        EnterprisePartialCachePaths cache)
    {
        var partialExists = File.Exists(cache.PartialPath);
        var metadataExists = File.Exists(cache.MetadataPath);
        if (!partialExists && !metadataExists)
        {
            return EnterprisePartialCacheState.Empty;
        }
        if (!partialExists || !metadataExists)
        {
            ResetPartialCache(cache);
            return EnterprisePartialCacheState.Empty;
        }

        EnterprisePathGuard.ValidateExistingPathWithin(
            cache.PartialPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        EnterprisePathGuard.ValidateExistingPathWithin(
            cache.MetadataPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        EnterpriseArtifactPartialCacheMetadata metadata;
        try
        {
            metadata = EnterprisePointerJson.Deserialize<EnterpriseArtifactPartialCacheMetadata>(
                File.ReadAllBytes(cache.MetadataPath));
        }
        catch (Exception exception) when (
            exception is JsonException or InvalidDataException or NotSupportedException)
        {
            ResetPartialCache(cache);
            return EnterprisePartialCacheState.Empty;
        }

        var length = new FileInfo(cache.PartialPath).Length;
        if (metadata.SchemaVersion != 1
            || !string.Equals(metadata.Component, artifact.Component, StringComparison.Ordinal)
            || !string.Equals(metadata.ReleaseId, artifact.ReleaseId, StringComparison.Ordinal)
            || !string.Equals(metadata.Uri, artifact.Uri.AbsoluteUri, StringComparison.Ordinal)
            || metadata.SizeBytes != artifact.SizeBytes
            || !string.Equals(metadata.Sha256, artifact.Sha256, StringComparison.Ordinal)
            || length <= 0
            || length > artifact.SizeBytes
            || !TryParseStrongETag(metadata.StrongETag, out _))
        {
            ResetPartialCache(cache);
            return EnterprisePartialCacheState.Empty;
        }

        return new EnterprisePartialCacheState(length, metadata.StrongETag);
    }

    private void WritePartialCacheMetadata(
        EnterprisePartialCachePaths cache,
        EnterpriseReleaseArtifact artifact,
        string? strongETag)
    {
        var metadata = new EnterpriseArtifactPartialCacheMetadata(
            1,
            artifact.Component,
            artifact.ReleaseId,
            artifact.Uri.AbsoluteUri,
            artifact.SizeBytes,
            artifact.Sha256,
            strongETag);
        EnterprisePathGuard.WriteFileAtomically(
            cache.MetadataPath,
            EnterprisePointerJson.Serialize(metadata),
            _layout.ManagedRoot);
    }

    private static bool IsValidPartialResponse(
        HttpResponseMessage response,
        EnterpriseReleaseArtifact artifact,
        EnterprisePartialCacheState cached)
    {
        var range = response.Content.Headers.ContentRange;
        return cached.StrongETag is not null
            && string.Equals(ReadStrongETag(response), cached.StrongETag, StringComparison.Ordinal)
            && range is not null
            && string.Equals(range.Unit, "bytes", StringComparison.OrdinalIgnoreCase)
            && range.From == cached.Length
            && range.To == artifact.SizeBytes - 1
            && range.Length == artifact.SizeBytes;
    }

    private static string? ReadStrongETag(HttpResponseMessage response) =>
        response.Headers.ETag is { IsWeak: false } value ? value.ToString() : null;

    private static bool TryParseStrongETag(
        string? value,
        out EntityTagHeaderValue? parsed)
    {
        if (EntityTagHeaderValue.TryParse(value, out parsed) && parsed is { IsWeak: false })
        {
            return true;
        }
        parsed = null;
        return false;
    }

    private async Task AppendResponseToPartialAsync(
        HttpResponseMessage response,
        string partialPath,
        bool append,
        long existingLength,
        long signedSize,
        CancellationToken cancellationToken)
    {
        await using var input = await response.Content.ReadAsStreamAsync(
            cancellationToken).ConfigureAwait(false);
        await using var output = new FileStream(
            partialPath,
            append ? FileMode.Append : FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        var buffer = new byte[128 * 1024];
        var total = append ? existingLength : 0;
        while (true)
        {
            var read = await ReadWithIdleTimeoutAsync(
                input,
                buffer,
                _trustPolicy.ArtifactReadIdleTimeout,
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            total = checked(total + read);
            if (total > signedSize)
            {
                throw new InvalidDataException("Enterprise artifact exceeded its signed size.");
            }
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                .ConfigureAwait(false);
        }
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        output.Flush(flushToDisk: true);
    }

    private void ConsumeCompletedPartial(
        EnterprisePartialCachePaths cache,
        string destinationPath)
    {
        EnterprisePathGuard.ValidateExistingPathWithin(
            cache.PartialPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        if (File.Exists(destinationPath))
        {
            throw new InvalidDataException("Enterprise artifact destination already exists.");
        }
        File.Move(cache.PartialPath, destinationPath);
        if (File.Exists(cache.MetadataPath))
        {
            EnterprisePathGuard.ValidateExistingPathWithin(
                cache.MetadataPath,
                _layout.ManagedRoot,
                requireDirectory: false);
            File.Delete(cache.MetadataPath);
        }
    }

    private void ResetPartialCache(EnterprisePartialCachePaths cache)
    {
        foreach (var path in new[] { cache.PartialPath, cache.MetadataPath })
        {
            if (!File.Exists(path))
            {
                continue;
            }
            EnterprisePathGuard.ValidateExistingPathWithin(
                path,
                _layout.ManagedRoot,
                requireDirectory: false);
            File.Delete(path);
        }
    }

    private async Task EnsureArtifactInstalledAsync(
        EnterpriseReleaseArtifact artifact,
        string archivePath,
        string launcherReleaseId,
        string runtimeReleaseId,
        CancellationToken cancellationToken)
    {
        var versionRoot = artifact.Component switch
        {
            EnterpriseReleaseSetContract.LauncherComponent => _layout.LauncherVersionsRoot,
            EnterpriseReleaseSetContract.RuntimeComponent => _layout.RuntimeVersionsRoot,
            EnterpriseReleaseSetContract.PluginPolicyComponent => _layout.PluginPolicyVersionsRoot,
            _ => throw new InvalidDataException("Unknown enterprise release component."),
        };
        var finalDirectory = EnterprisePathGuard.CombineExactChild(
            versionRoot,
            artifact.ReleaseId);
        if (Directory.Exists(finalDirectory) || File.Exists(finalDirectory))
        {
            throw new InvalidDataException(
                "Enterprise downloaded target collides with a version directory not authorized for reuse.");
        }

        var stagingDirectory = Path.Combine(
            versionRoot,
            $".{artifact.ReleaseId}.staging-{Guid.NewGuid():N}");
        EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, stagingDirectory);
        try
        {
            await ExtractArchiveSafelyAsync(
                archivePath,
                stagingDirectory,
                cancellationToken).ConfigureAwait(false);
            var (primary, secondary) = RequireComponentFiles(stagingDirectory, artifact.Component);
            if (artifact.Component == EnterpriseReleaseSetContract.LauncherComponent)
            {
                EnterpriseBuildProfileMarker.ReadAndValidate(
                    Path.Combine(
                        stagingDirectory,
                        EnterpriseInstallationLayout.BuildProfileMarkerFileName),
                    _layout.LayoutProfile);
                foreach (var executable in RequiredClientBundleExecutables(stagingDirectory))
                {
                    EnterpriseAuthenticodeVerifier.RequireTrustedSignature(executable, _layout);
                }
            }
            if (artifact.Component == EnterpriseReleaseSetContract.PluginPolicyComponent)
            {
                var pluginPolicy = EnterprisePluginPolicyInstallation.ValidateInstalled(
                    stagingDirectory,
                    _layout.PluginPolicyVersionsRoot,
                    artifact.ReleaseId,
                    artifact.Sha256,
                    launcherReleaseId,
                    runtimeReleaseId,
                    requireReceipt: false);
                var pluginReceipt = new EnterprisePluginPolicyReceipt(
                    2,
                    artifact.ReleaseId,
                    artifact.Sha256,
                    pluginPolicy.PolicySha256,
                    pluginPolicy.PolicyId,
                    pluginPolicy.Generation,
                    Path.GetRelativePath(
                            pluginPolicy.PolicyDirectory,
                            pluginPolicy.SkillsRoot)
                        .Replace('\\', '/'),
                    pluginPolicy.SkillsTreeSha256,
                    DateTimeOffset.UtcNow);
                EnterprisePathGuard.WriteFileAtomically(
                    Path.Combine(
                        stagingDirectory,
                        EnterpriseReleaseSetPointerStore.PluginReceiptFileName),
                    EnterprisePointerJson.Serialize(pluginReceipt),
                    _layout.ManagedRoot);
            }
            else
            {
                var receipt = new EnterpriseInstalledReleaseReceipt(
                    1,
                    artifact.ReleaseId,
                    artifact.Sha256,
                    EnterpriseHash.ComputeFile(primary),
                    secondary is null ? null : EnterpriseHash.ComputeFile(secondary),
                    DateTimeOffset.UtcNow);
                if (artifact.Component == EnterpriseReleaseSetContract.LauncherComponent)
                {
                    EnterpriseLauncherPointerStore.WriteReceipt(
                        stagingDirectory,
                        receipt,
                        _layout.ManagedRoot);
                }
                else
                {
                    EnterpriseRuntimePointerStore.WriteReceipt(
                        stagingDirectory,
                        receipt,
                        _layout.ManagedRoot);
                }
            }

            var runtimeManifestSha256 = artifact.Component
                == EnterpriseReleaseSetContract.RuntimeComponent
                ? EnterpriseRuntimeFileManifest.ValidateCompleteTree(stagingDirectory)
                : null;
            var completeTreeSha256 = EnterpriseTreeHash.Compute(stagingDirectory);
            if (!string.Equals(
                    completeTreeSha256,
                    artifact.CompleteTreeSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise extracted tree differs from the signed artifact identity.");
            }
            var v2Receipt = new EnterpriseReleaseArtifactReceiptV2(
                2,
                artifact.Component,
                artifact.ReleaseId,
                artifact.Sha256,
                artifact.CompleteTreeSha256,
                runtimeManifestSha256,
                DateTimeOffset.UtcNow);
            EnterprisePathGuard.WriteFileAtomically(
                Path.Combine(stagingDirectory, EnterpriseTreeHash.ReceiptFileName),
                EnterprisePointerJson.Serialize(v2Receipt),
                _layout.ManagedRoot);
            EnterprisePathGuard.ValidateSafeTree(stagingDirectory, _layout.ManagedRoot);

            try
            {
                Directory.Move(stagingDirectory, finalDirectory);
            }
            catch (IOException) when (Directory.Exists(finalDirectory))
            {
                throw new InvalidDataException(
                    "Enterprise component installation raced with an unauthorized version directory.");
            }
        }
        finally
        {
            if (Directory.Exists(stagingDirectory))
            {
                EnterprisePathGuard.DeleteDirectoryTree(stagingDirectory, _layout.ManagedRoot);
            }
        }
        ValidateExistingImmutableArtifact(
            finalDirectory,
            artifact,
            launcherReleaseId,
            runtimeReleaseId);
    }

    private void ValidateExistingImmutableArtifact(
        string directory,
        EnterpriseReleaseArtifact artifact,
        string launcherReleaseId,
        string runtimeReleaseId)
    {
        EnterprisePathGuard.ValidateSafeTree(directory, _layout.ManagedRoot);
        var receiptPath = Path.Combine(directory, EnterpriseTreeHash.ReceiptFileName);
        EnterprisePathGuard.ValidateExistingPathWithin(receiptPath, _layout.ManagedRoot, false);
        var receipt = EnterprisePointerJson.Deserialize<EnterpriseReleaseArtifactReceiptV2>(
            File.ReadAllBytes(receiptPath));
        if (receipt.SchemaVersion != 2
            || !string.Equals(receipt.Component, artifact.Component, StringComparison.Ordinal)
            || !string.Equals(receipt.ReleaseId, artifact.ReleaseId, StringComparison.Ordinal)
            || !string.Equals(receipt.ArchiveSha256, artifact.Sha256, StringComparison.Ordinal)
            || !string.Equals(
                receipt.TreeSha256,
                artifact.CompleteTreeSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                artifact.CompleteTreeSha256,
                EnterpriseTreeHash.Compute(directory),
                StringComparison.Ordinal)
            || (artifact.Component == EnterpriseReleaseSetContract.RuntimeComponent
                && !string.Equals(
                    receipt.RuntimeFilesManifestSha256,
                    EnterpriseRuntimeFileManifest.ValidateCompleteTree(directory),
                    StringComparison.Ordinal))
            || (artifact.Component != EnterpriseReleaseSetContract.RuntimeComponent
                && receipt.RuntimeFilesManifestSha256 is not null))
        {
            throw new InvalidDataException(
                "Enterprise immutable version directory conflicts with signed artifact.");
        }
        _ = RequireComponentFiles(directory, artifact.Component);
        if (artifact.Component == EnterpriseReleaseSetContract.LauncherComponent)
        {
            EnterpriseBuildProfileMarker.ReadAndValidate(
                Path.Combine(
                    directory,
                    EnterpriseInstallationLayout.BuildProfileMarkerFileName),
                _layout.LayoutProfile);
            foreach (var executable in RequiredClientBundleExecutables(directory))
            {
                EnterpriseAuthenticodeVerifier.RequireTrustedSignature(executable, _layout);
            }
        }
        if (artifact.Component == EnterpriseReleaseSetContract.PluginPolicyComponent)
        {
            _ = EnterprisePluginPolicyInstallation.ValidateInstalled(
                directory,
                _layout.PluginPolicyVersionsRoot,
                artifact.ReleaseId,
                artifact.Sha256,
                launcherReleaseId,
                runtimeReleaseId,
                requireReceipt: true);
        }
    }

    private static (string Primary, string? Secondary) RequireComponentFiles(
        string root,
        string component)
    {
        var primaryRelative = component switch
        {
            EnterpriseReleaseSetContract.LauncherComponent =>
                EnterpriseInstallationLayout.LauncherExecutableName,
            EnterpriseReleaseSetContract.RuntimeComponent => "node.exe",
            EnterpriseReleaseSetContract.PluginPolicyComponent => "plugin-policy.json",
            _ => throw new InvalidDataException("Unknown enterprise release component."),
        };
        var secondaryRelative = component == EnterpriseReleaseSetContract.RuntimeComponent
            ? "node_modules/@deepseek-ai/dsh/lib/bin.js"
            : null;
        var primary = ResolveArchiveOutput(root, primaryRelative);
        var secondary = secondaryRelative is null
            ? null
            : ResolveArchiveOutput(root, secondaryRelative);
        if (!File.Exists(primary) || (secondary is not null && !File.Exists(secondary)))
        {
            throw new InvalidDataException(
                $"Enterprise {component} archive is missing required files.");
        }
        if (component == EnterpriseReleaseSetContract.LauncherComponent)
        {
            _ = RequiredClientBundleExecutables(root);
        }
        return (primary, secondary);
    }

    private static IReadOnlyList<string> RequiredClientBundleExecutables(string root)
    {
        var required = new[]
        {
            EnterpriseInstallationLayout.LauncherExecutableName,
            EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
            EnterpriseInstallationLayout.MaintenanceExecutableName,
        }.Select(relative => ResolveArchiveOutput(root, relative)).ToArray();
        if (required.Any(path => !File.Exists(path)))
        {
            throw new InvalidDataException(
                "Enterprise client-bundle is missing Launcher, versioned Bootstrapper, or Maintenance.");
        }
        return required;
    }

    private async Task ExtractArchiveSafelyAsync(
        string archivePath,
        string destinationDirectory,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            archivePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        if (archive.Entries.Count is <= 0 or > MaximumArchiveEntries)
        {
            throw new InvalidDataException("Enterprise archive entry count is invalid.");
        }
        long expanded = 0;
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var normalized = ValidateArchiveEntry(entry);
            if (!paths.Add(normalized))
            {
                throw new InvalidDataException("Enterprise archive has duplicate paths.");
            }
            expanded = checked(expanded + entry.Length);
            if (expanded > MaximumExpandedArchiveBytes)
            {
                throw new InvalidDataException("Enterprise archive expands beyond its limit.");
            }
            var outputPath = ResolveArchiveOutput(destinationDirectory, normalized);
            if (normalized.EndsWith("/", StringComparison.Ordinal))
            {
                EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, outputPath);
                continue;
            }
            var parent = Path.GetDirectoryName(outputPath)
                ?? throw new InvalidDataException("Enterprise archive path has no parent.");
            EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, parent);
            await using var input = entry.Open();
            await using var output = new FileStream(
                outputPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            await input.CopyToAsync(output, 128 * 1024, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            if (output.Length != entry.Length)
            {
                throw new InvalidDataException("Enterprise archive entry length changed.");
            }
        }
    }

    private static string ValidateArchiveEntry(ZipArchiveEntry entry)
    {
        if ((entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0
            || ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
        {
            throw new InvalidDataException("Enterprise archive contains a filesystem link.");
        }
        var normalized = entry.FullName.Replace('\\', '/');
        if (string.IsNullOrWhiteSpace(normalized)
            || normalized.StartsWith("/", StringComparison.Ordinal)
            || normalized.Length > 1024)
        {
            throw new InvalidDataException("Enterprise archive entry path is invalid.");
        }
        var isDirectory = normalized.EndsWith("/", StringComparison.Ordinal);
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            throw new InvalidDataException("Enterprise archive path is empty.");
        }
        foreach (var segment in segments)
        {
            var firstName = segment.Split('.', 2)[0];
            if (segment is "." or ".."
                || segment.EndsWith(' ')
                || segment.EndsWith('.')
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
                throw new InvalidDataException("Enterprise archive has an unsafe path segment.");
            }
        }
        return string.Join('/', segments) + (isDirectory ? "/" : string.Empty);
    }

    private static string ResolveArchiveOutput(string root, string relative)
    {
        var normalizedRoot = EnterprisePathGuard.NormalizeDirectory(root);
        var combined = Path.GetFullPath(Path.Combine(
            normalizedRoot,
            relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!EnterprisePathGuard.IsSameOrDescendant(combined, normalizedRoot)
            || string.Equals(combined, normalizedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise archive escaped its destination.");
        }
        return combined;
    }

    private void RequireManifestUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.Equals(
                uri.GetLeftPart(UriPartial.Authority),
                _trustPolicy.ManifestOrigin.GetLeftPart(UriPartial.Authority),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise manifest URI is outside the pinned HTTPS origin.");
        }
    }

    private static void RequireFinalOrigin(HttpResponseMessage response, Uri expectedOrigin)
    {
        var finalUri = response.RequestMessage?.RequestUri
            ?? throw new HttpRequestException("Enterprise update response has no final URI.");
        if (!string.Equals(finalUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                finalUri.GetLeftPart(UriPartial.Authority),
                expectedOrigin.GetLeftPart(UriPartial.Authority),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise update redirect escaped its pinned origin.");
        }
    }

    private static bool IsAvailabilityFailure(Exception exception) =>
        exception is HttpRequestException
            or TaskCanceledException
            or TimeoutException
            or IOException;

    private static async Task<int> ReadWithIdleTimeoutAsync(
        Stream stream,
        Memory<byte> buffer,
        TimeSpan idleTimeout,
        CancellationToken cancellationToken)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        idle.CancelAfter(idleTimeout);
        return await stream.ReadAsync(buffer, idle.Token).ConfigureAwait(false);
    }
}

internal sealed record EnterpriseArtifactPartialCacheMetadata(
    int SchemaVersion,
    string Component,
    string ReleaseId,
    string Uri,
    long SizeBytes,
    string Sha256,
    string? StrongETag);

internal sealed record EnterprisePartialCachePaths(
    string PartialPath,
    string MetadataPath);

internal sealed record EnterprisePartialCacheState(long Length, string? StrongETag)
{
    public static EnterprisePartialCacheState Empty { get; } = new(0, null);
}
