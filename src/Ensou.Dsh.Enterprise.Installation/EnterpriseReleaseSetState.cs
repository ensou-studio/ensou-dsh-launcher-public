using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

public static class EnterpriseReleaseHealthStates
{
    public const string Pending = "pending";
    public const string Healthy = "healthy";
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseComponentPointer(
    string ReleaseId,
    string Directory,
    string ArchiveSha256,
    string CompleteTreeSha256);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseSetReference(
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    EnterpriseStartupStubCompatibility StartupStub,
    EnterpriseReleaseComponentPointer Launcher,
    EnterpriseReleaseComponentPointer Runtime,
    EnterpriseReleaseComponentPointer? PluginPolicy,
    string HealthState,
    string? HealthToken,
    DateTimeOffset ActivatedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseSetPointer(
    int SchemaVersion,
    string Product,
    string Environment,
    EnterpriseReleaseSetReference Current,
    EnterpriseReleaseSetReference? Previous,
    DateTimeOffset UpdatedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterprisePluginPolicyReceipt(
    int SchemaVersion,
    string ReleaseId,
    string ArchiveSha256,
    string PolicySha256,
    string PolicyId,
    long Generation,
    string SkillsRoot,
    string SkillsTreeSha256,
    DateTimeOffset InstalledAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseArtifactReceiptV2(
    int SchemaVersion,
    string Component,
    string ReleaseId,
    string ArchiveSha256,
    string TreeSha256,
    string? RuntimeFilesManifestSha256,
    DateTimeOffset InstalledAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseAcceptedReleaseIdentity(
    bool InstallerBootstrap,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    EnterpriseStartupStubCompatibility StartupStub,
    EnterpriseReleaseComponentPointer Launcher,
    EnterpriseReleaseComponentPointer Runtime,
    EnterpriseReleaseComponentPointer? PluginPolicy,
    string ManifestSha256,
    string? ExactManifestBase64,
    string? ManifestUri,
    DateTimeOffset VerifiedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseFeedState(
    int SchemaVersion,
    long StateRevision,
    string StateCommitId,
    string Product,
    string Environment,
    string Channel,
    long HighestGeneration,
    long HighestSequence,
    long MinAcceptedSequence,
    DateTimeOffset TrustedTimeUtc,
    IReadOnlyList<string> RevokedReleaseSetIds,
    IReadOnlyList<EnterpriseReleaseHealthFailure> FailedReleaseQuarantine,
    IReadOnlyList<EnterpriseAcceptedReleaseIdentity> AcceptedReleases,
    string LastManifestSha256,
    DateTimeOffset LastVerifiedAtUtc,
    DateTimeOffset LastManifestExpiresAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseUpdateStatus(
    int SchemaVersion,
    string State,
    string Message,
    string? ReleaseSetId,
    long? Sequence,
    bool MustUpdate,
    DateTimeOffset UpdatedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseUpdateReceipt(
    int SchemaVersion,
    string Event,
    string ReleaseSetId,
    long Sequence,
    string? Detail,
    DateTimeOffset RecordedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseHealthSignal(
    int SchemaVersion,
    string ReleaseSetId,
    string Token,
    int ProcessId,
    DateTimeOffset RecordedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseHealthFailure(
    string ReleaseSetId,
    long Generation,
    long Sequence,
    string ReasonCode,
    DateTimeOffset RecordedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleaseHealthQuarantine(
    int SchemaVersion,
    string Product,
    string Environment,
    IReadOnlyList<EnterpriseReleaseHealthFailure> Failures);

public sealed class EnterpriseReleaseSetPointerStore(
    EnterpriseInstallationLayout layout,
    EnterpriseCompiledReleaseTrust? compiledTrust = null,
    TimeProvider? timeProvider = null)
{
    internal const string PluginReceiptFileName = ".ensou-enterprise-plugin-policy.v2.json";
    private const int PointerSchemaVersion = 3;
    private const string PluginPolicyEntry = "plugin-policy.json";
    private readonly EnterpriseInstallationLayout _layout = layout
        ?? throw new ArgumentNullException(nameof(layout));
    private readonly EnterpriseCompiledReleaseTrust? _compiledTrust = compiledTrust;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public EnterpriseReleaseSetPointer? TryRead()
    {
        if (!File.Exists(_layout.ReleaseSetPointerPath))
        {
            return null;
        }
        EnterprisePathGuard.ValidateExistingPathWithin(
            _layout.ReleaseSetPointerPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        var pointer = EnterprisePointerJson.Deserialize<EnterpriseReleaseSetPointer>(
            File.ReadAllBytes(_layout.ReleaseSetPointerPath));
        Validate(pointer);
        EnterpriseReleaseFeedStateStore.RequirePointerBound(
            _layout,
            pointer,
            _compiledTrust,
            _timeProvider.GetUtcNow());
        return pointer;
    }

    public EnterpriseReleaseSetPointer ReadRequired() =>
        TryRead() ?? throw new InvalidDataException(
            "企业 release-set 尚未安装完成；请运行企业安装器进行修复。");

    public EnterpriseActivePluginPolicy ReadActivePluginPolicyRequired()
    {
        var pointer = ReadRequired();
        return ReadActivePluginPolicyRequired(pointer);
    }

    public EnterpriseActivePluginPolicy ReadActivePluginPolicyRequired(
        EnterpriseReleaseSetPointer pointer)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        var component = pointer.Current.PluginPolicy
            ?? throw new InvalidDataException(
                "The active enterprise release-set has no managed plugin policy.");
        return ValidatePluginComponent(
            component,
            pointer.Current.Launcher.ReleaseId,
            pointer.Current.Runtime.ReleaseId);
    }

    public void EnsureInstallerTargetAllowed(
        string launcherReleaseId,
        string runtimeReleaseId)
    {
        EnterprisePathGuard.ValidateReleaseId(launcherReleaseId);
        EnterprisePathGuard.ValidateReleaseId(runtimeReleaseId);
        var existing = TryReadInstallerIdentityOnly();
        if (existing is not null)
        {
            EnsureExistingInstallerTarget(
                existing,
                launcherReleaseId,
                runtimeReleaseId);
        }
        else if (HasOrphanedV2InstallationTrace(
            launcherReleaseId,
            runtimeReleaseId))
        {
            throw new InvalidDataException(
                "Enterprise v2 installation traces exist but the authenticated release pointer is missing; signed repair is required.");
        }
    }

    public EnterpriseReleaseSetPointer ActivateInitialHealthy(
        string launcherReleaseId,
        string runtimeReleaseId)
    {
        using var writer = EnterprisePointerWriter.Acquire();
        var existing = TryRead();
        if (existing is not null)
        {
            EnsureExistingInstallerTarget(existing, launcherReleaseId, runtimeReleaseId);
            return existing;
        }
        var launcher = new EnterpriseLauncherPointerStore(_layout).ReadRequired();
        var runtime = new EnterpriseRuntimePointerStore(_layout).ReadRequired();
        if (!string.Equals(launcher.ReleaseId, launcherReleaseId, StringComparison.Ordinal)
            || !string.Equals(runtime.ReleaseId, runtimeReleaseId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Initial enterprise release-set components do not match.");
        }

        var installIdentity = Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(
                    $"{launcherReleaseId}\n{runtimeReleaseId}")))[..32];
        var launcherArchiveSha256 = ReadArchiveSha256(
            launcher.LauncherDirectory,
            ".ensou-enterprise-launcher.json");
        var runtimeArchiveSha256 = ReadArchiveSha256(
            runtime.RuntimeDirectory,
            ".ensou-enterprise-runtime.json");
        var reference = new EnterpriseReleaseSetReference(
            $"install-{installIdentity}",
            0,
            0,
            0,
            new EnterpriseStartupStubCompatibility
            {
                MinimumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                MaximumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            },
            new EnterpriseReleaseComponentPointer(
                launcher.ReleaseId,
                launcher.LauncherDirectory,
                launcherArchiveSha256,
                ReadCompleteTreeSha256(
                    launcher.LauncherDirectory,
                    EnterpriseReleaseSetContract.LauncherComponent,
                    launcher.ReleaseId,
                    launcherArchiveSha256)),
            new EnterpriseReleaseComponentPointer(
                runtime.ReleaseId,
                runtime.RuntimeDirectory,
                runtimeArchiveSha256,
                ReadCompleteTreeSha256(
                    runtime.RuntimeDirectory,
                    EnterpriseReleaseSetContract.RuntimeComponent,
                    runtime.ReleaseId,
                    runtimeArchiveSha256)),
            null,
            EnterpriseReleaseHealthStates.Healthy,
            null,
            DateTimeOffset.UtcNow);
        var pointer = new EnterpriseReleaseSetPointer(
            PointerSchemaVersion,
            EnterpriseReleaseSetContract.Product,
            EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(_layout.IsDevelopmentE2E),
            reference,
            null,
            DateTimeOffset.UtcNow);
        Write(pointer);
        return pointer;
    }

    public EnterpriseReleaseSetPointer ActivatePending(EnterpriseReleaseSetManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        using var writer = EnterprisePointerWriter.Acquire();
        var current = ReadRequired();
        if (current.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
            || manifest.Generation < current.Current.Generation
            || manifest.Sequence <= current.Current.Sequence)
        {
            throw new InvalidDataException(
                "Enterprise release-set activation raced, rolled back, or is already pending.");
        }
        ValidatePluginPolicyTransition(current.Current, manifest);
        EnterpriseReleaseSetValidator.ValidateStartupStubCompatibility(
            manifest.StartupStub,
            EnterpriseReleaseSetContract.CurrentStartupStubProtocol);
        var token = EnterpriseBase64Url.Encode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var nextReference = new EnterpriseReleaseSetReference(
            manifest.ReleaseSetId,
            manifest.Generation,
            manifest.Sequence,
            manifest.MinAcceptedSequence,
            manifest.StartupStub,
            Component(manifest.Launcher, _layout.GetLauncherVersionDirectory(manifest.Launcher.ReleaseId)),
            Component(manifest.Runtime, _layout.GetRuntimeVersionDirectory(manifest.Runtime.ReleaseId)),
            manifest.PluginPolicy is null
                ? null
                : Component(
                    manifest.PluginPolicy,
                    _layout.GetPluginPolicyVersionDirectory(manifest.PluginPolicy.ReleaseId)),
            EnterpriseReleaseHealthStates.Pending,
            token,
            DateTimeOffset.UtcNow);
        var next = new EnterpriseReleaseSetPointer(
            PointerSchemaVersion,
            current.Product,
            current.Environment,
            nextReference,
            current.Current with
            {
                HealthState = EnterpriseReleaseHealthStates.Healthy,
                HealthToken = null,
            },
            DateTimeOffset.UtcNow);
        Validate(next);
        EnterpriseReleaseFeedStateStore.RequirePointerBound(
            _layout,
            next,
            _compiledTrust,
            _timeProvider.GetUtcNow());
        Write(next);
        EnterpriseReleaseStateFiles.WriteReceipt(
            _layout,
            "activated-pending-health",
            next.Current,
            null);
        return next;
    }

    public EnterpriseReleaseSetPointer MarkCurrentHealthy(string healthToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(healthToken);
        using var writer = EnterprisePointerWriter.Acquire();
        var pointer = ReadRequired();
        if (!string.Equals(pointer.Current.HealthState, EnterpriseReleaseHealthStates.Pending, StringComparison.Ordinal)
            || !string.Equals(pointer.Current.HealthToken, healthToken, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise release health token does not match pending activation.");
        }
        var healthy = pointer with
        {
            Current = pointer.Current with
            {
                HealthState = EnterpriseReleaseHealthStates.Healthy,
                HealthToken = null,
            },
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        };
        Write(healthy);
        EnterpriseReleaseStateFiles.WriteReceipt(_layout, "healthy", healthy.Current, null);
        EnterpriseReleaseStateFiles.WriteStatus(
            _layout,
            "healthy",
            "企业组件已更新并通过启动自检。",
            healthy.Current,
            mustUpdate: false);
        return healthy;
    }

    public EnterpriseReleaseSetPointer RollbackPending(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        using var writer = EnterprisePointerWriter.Acquire();
        var pointer = ReadRequired();
        if (!string.Equals(pointer.Current.HealthState, EnterpriseReleaseHealthStates.Pending, StringComparison.Ordinal)
            || pointer.Previous is null)
        {
            throw new InvalidOperationException("Enterprise release-set has no pending activation to roll back.");
        }

        var failed = pointer.Current;
        var rollback = pointer with
        {
            Current = pointer.Previous with
            {
                HealthState = EnterpriseReleaseHealthStates.Healthy,
                HealthToken = null,
            },
            Previous = null,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        };
        // Persist the rejection before restoring the old pointer. If the pointer
        // write is interrupted, the next Bootstrapper run sees the quarantine
        // and will not execute the already-failed candidate again.
        new EnterpriseReleaseHealthQuarantineStore(_layout)
            .RecordFailedUnderWriteLock(failed, reason);
        Write(rollback);
        EnterpriseReleaseStateFiles.WriteReceipt(_layout, "health-rollback", failed, reason);
        EnterpriseReleaseStateFiles.WriteStatus(
            _layout,
            "rolled-back",
            $"新版本启动自检失败，已回退到 {rollback.Current.ReleaseSetId}。",
            rollback.Current,
            mustUpdate: false);
        return rollback;
    }

    public void Validate(EnterpriseReleaseSetPointer pointer)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        if (pointer.SchemaVersion != PointerSchemaVersion
            || !string.Equals(pointer.Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                pointer.Environment,
                EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(_layout.IsDevelopmentE2E),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise release-set pointer identity is invalid.");
        }
        ValidateReference(pointer.Current, allowPending: true);
        if (pointer.Previous is not null)
        {
            ValidateReference(pointer.Previous, allowPending: false);
        }
    }

    private void ValidateReference(EnterpriseReleaseSetReference reference, bool allowPending)
    {
        EnterprisePathGuard.ValidateReleaseId(reference.ReleaseSetId);
        if (reference.StartupStub is null)
        {
            throw new InvalidDataException(
                "Enterprise release-set pointer has no Startup Stub protocol binding.");
        }
        EnterpriseReleaseSetValidator.ValidateStartupStubRange(reference.StartupStub);
        if (reference.Generation < 0
            || reference.Sequence < 0
            || reference.MinAcceptedSequence < 0
            || reference.MinAcceptedSequence > reference.Sequence
            || reference.ActivatedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Enterprise release-set pointer ordering is invalid.");
        }
        if (reference.HealthState == EnterpriseReleaseHealthStates.Pending)
        {
            if (!allowPending
                || reference.HealthToken is null
                || EnterpriseBase64Url.Decode(reference.HealthToken, "health token").Length != 32)
            {
                throw new InvalidDataException("Enterprise pending release health state is invalid.");
            }
        }
        else if (reference.HealthState != EnterpriseReleaseHealthStates.Healthy
            || reference.HealthToken is not null)
        {
            throw new InvalidDataException("Enterprise release health state is invalid.");
        }

        ValidateComponent(
            reference.Launcher,
            _layout.GetLauncherVersionDirectory(reference.Launcher.ReleaseId),
            ".ensou-enterprise-launcher.json",
            EnterpriseInstallationLayout.LauncherExecutableName,
            secondaryRelativePath: null);
        ValidateComponent(
            reference.Runtime,
            _layout.GetRuntimeVersionDirectory(reference.Runtime.ReleaseId),
            ".ensou-enterprise-runtime.json",
            "node.exe",
            "node_modules/@deepseek-ai/dsh/lib/bin.js");
        if (reference.PluginPolicy is not null)
        {
            _ = ValidatePluginComponent(
                reference.PluginPolicy,
                reference.Launcher.ReleaseId,
                reference.Runtime.ReleaseId);
        }
    }

    private void ValidateComponent(
        EnterpriseReleaseComponentPointer component,
        string expectedDirectory,
        string receiptFile,
        string primaryRelativePath,
        string? secondaryRelativePath)
    {
        if (!string.Equals(
                EnterprisePathGuard.NormalizeDirectory(component.Directory),
                expectedDirectory,
                StringComparison.OrdinalIgnoreCase)
            || !EnterpriseHash.IsSha256(component.ArchiveSha256)
            || !EnterpriseHash.IsSha256(component.CompleteTreeSha256))
        {
            throw new InvalidDataException("Enterprise release component pointer is invalid.");
        }
        EnterprisePathGuard.ValidateSafeTree(expectedDirectory, _layout.ManagedRoot);
        EnterpriseLauncherPointerStore.ValidateReceiptAndPrimaryFile(
            expectedDirectory,
            receiptFile,
            primaryRelativePath,
            secondaryRelativePath,
            component.ReleaseId,
            _layout.ManagedRoot);
        if (string.Equals(
                receiptFile,
                ".ensou-enterprise-launcher.json",
                StringComparison.Ordinal))
        {
            EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
                Path.Combine(expectedDirectory, primaryRelativePath),
                _layout);
        }
        if (!string.Equals(
                component.ArchiveSha256,
                ReadArchiveSha256(expectedDirectory, receiptFile),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise release component archive receipt changed.");
        }
        var expectedComponent = string.Equals(
            receiptFile,
            ".ensou-enterprise-launcher.json",
            StringComparison.Ordinal)
            ? EnterpriseReleaseSetContract.LauncherComponent
            : EnterpriseReleaseSetContract.RuntimeComponent;
        ValidateV2TreeReceiptIfPresent(
            expectedDirectory,
            component,
            expectedComponent);
    }

    private EnterpriseActivePluginPolicy ValidatePluginComponent(
        EnterpriseReleaseComponentPointer component,
        string launcherReleaseId,
        string runtimeReleaseId)
    {
        var expected = _layout.GetPluginPolicyVersionDirectory(component.ReleaseId);
        if (!string.Equals(
                EnterprisePathGuard.NormalizeDirectory(component.Directory),
                expected,
                StringComparison.OrdinalIgnoreCase)
            || !EnterpriseHash.IsSha256(component.ArchiveSha256)
            || !EnterpriseHash.IsSha256(component.CompleteTreeSha256))
        {
            throw new InvalidDataException("Enterprise plugin policy pointer is invalid.");
        }
        EnterprisePathGuard.ValidateSafeTree(expected, _layout.ManagedRoot);
        var policy = EnterprisePluginPolicyInstallation.ValidateInstalled(
            expected,
            _layout.PluginPolicyVersionsRoot,
            component.ReleaseId,
            component.ArchiveSha256,
            launcherReleaseId,
            runtimeReleaseId,
            requireReceipt: true);
        ValidateV2TreeReceiptIfPresent(
            expected,
            component,
            EnterpriseReleaseSetContract.PluginPolicyComponent);
        return policy;
    }

    private void ValidatePluginPolicyTransition(
        EnterpriseReleaseSetReference current,
        EnterpriseReleaseSetManifest candidate)
    {
        EnterpriseActivePluginPolicy? currentPolicy = current.PluginPolicy is null
            ? null
            : ValidatePluginComponent(
                current.PluginPolicy,
                current.Launcher.ReleaseId,
                current.Runtime.ReleaseId);
        if (candidate.PluginPolicy is null)
        {
            if (currentPolicy is not null)
            {
                throw new InvalidDataException(
                    "An enterprise release-set may not remove an active managed plugin policy.");
            }
            return;
        }

        var candidatePolicy = EnterprisePluginPolicyInstallation.ValidateInstalled(
            _layout.GetPluginPolicyVersionDirectory(candidate.PluginPolicy.ReleaseId),
            _layout.PluginPolicyVersionsRoot,
            candidate.PluginPolicy.ReleaseId,
            candidate.PluginPolicy.Sha256,
            candidate.Launcher.ReleaseId,
            candidate.Runtime.ReleaseId,
            requireReceipt: true);
        if (currentPolicy is null)
        {
            return;
        }

        if (candidatePolicy.Generation < currentPolicy.Generation
            || (candidatePolicy.Generation == currentPolicy.Generation
                && (!string.Equals(
                        candidatePolicy.PolicyId,
                        currentPolicy.PolicyId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        candidatePolicy.PolicySha256,
                        currentPolicy.PolicySha256,
                        StringComparison.Ordinal))))
        {
            throw new InvalidDataException(
                "Enterprise plugin policy generation rolled back or equivocated.");
        }
    }

    private void ValidateV2TreeReceiptIfPresent(
        string directory,
        EnterpriseReleaseComponentPointer component,
        string expectedComponent)
    {
        var path = Path.Combine(directory, EnterpriseTreeHash.ReceiptFileName);
        EnterprisePathGuard.ValidateExistingPathWithin(path, _layout.ManagedRoot, false);
        var receipt = EnterprisePointerJson.Deserialize<EnterpriseReleaseArtifactReceiptV2>(
            File.ReadAllBytes(path));
        if (receipt.SchemaVersion != 2
            || !string.Equals(receipt.Component, expectedComponent, StringComparison.Ordinal)
            || !string.Equals(receipt.ReleaseId, component.ReleaseId, StringComparison.Ordinal)
            || !string.Equals(receipt.ArchiveSha256, component.ArchiveSha256, StringComparison.Ordinal)
            || !string.Equals(
                receipt.TreeSha256,
                component.CompleteTreeSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise immutable artifact tree was modified.");
        }
        if (expectedComponent == EnterpriseReleaseSetContract.RuntimeComponent)
        {
            var validation = EnterpriseRuntimeFileManifest
                .ValidateCompleteTreeAndComputeTree(directory);
            if (!string.Equals(
                    component.CompleteTreeSha256,
                    validation.CompleteTreeSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException("Enterprise immutable artifact tree was modified.");
            }
            if (!EnterpriseHash.IsSha256(
                    receipt.RuntimeFilesManifestSha256 ?? string.Empty)
                || !string.Equals(
                    validation.RuntimeFilesManifestSha256,
                    receipt.RuntimeFilesManifestSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise runtime file-manifest binding is invalid.");
            }
        }
        else
        {
            if (!string.Equals(
                    component.CompleteTreeSha256,
                    EnterpriseTreeHash.Compute(directory),
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException("Enterprise immutable artifact tree was modified.");
            }
            if (receipt.RuntimeFilesManifestSha256 is not null)
            {
                throw new InvalidDataException(
                    "Enterprise non-runtime receipt contains a runtime manifest binding.");
            }
        }
    }

    private void Write(EnterpriseReleaseSetPointer pointer) =>
        EnterprisePathGuard.WriteFileAtomically(
            _layout.ReleaseSetPointerPath,
            EnterprisePointerJson.Serialize(pointer),
            _layout.ManagedRoot);

    private static void EnsureExistingInstallerTarget(
        EnterpriseReleaseSetPointer existing,
        string launcherReleaseId,
        string runtimeReleaseId)
    {
        if (!string.Equals(
                existing.Current.Launcher.ReleaseId,
                launcherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                existing.Current.Runtime.ReleaseId,
                runtimeReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Installed enterprise components may only advance through the signed release-set feed.");
        }
    }

    private EnterpriseReleaseSetPointer? TryReadInstallerIdentityOnly()
    {
        if (!File.Exists(_layout.ReleaseSetPointerPath))
        {
            return null;
        }
        EnterprisePathGuard.ValidateExistingPathWithin(
            _layout.ReleaseSetPointerPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        var pointer = EnterprisePointerJson.Deserialize<EnterpriseReleaseSetPointer>(
            File.ReadAllBytes(_layout.ReleaseSetPointerPath));
        if (pointer.SchemaVersion != PointerSchemaVersion
            || !string.Equals(pointer.Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                pointer.Environment,
                EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(_layout.IsDevelopmentE2E),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise release-set pointer identity is invalid during repair.");
        }
        EnterprisePathGuard.ValidateReleaseId(pointer.Current.ReleaseSetId);
        EnterprisePathGuard.ValidateReleaseId(pointer.Current.Launcher.ReleaseId);
        EnterprisePathGuard.ValidateReleaseId(pointer.Current.Runtime.ReleaseId);
        return pointer;
    }

    private bool HasOrphanedV2InstallationTrace(
        string installerLauncherReleaseId,
        string installerRuntimeReleaseId)
    {
        if (File.Exists(_layout.UpdateSecurityStatePath)
            || File.Exists(_layout.UpdateSecurityAnchorPath)
            || File.Exists(_layout.UpdateSecurityPendingAnchorPath)
            || File.Exists(_layout.UpdateSecurityWitnessPath)
            || File.Exists(_layout.UpdateStatusPath)
            || File.Exists(_layout.HealthQuarantinePath)
            || Directory.Exists(_layout.PluginPolicyVersionsRoot)
                && Directory.EnumerateFileSystemEntries(
                    _layout.PluginPolicyVersionsRoot,
                    "*",
                    SearchOption.TopDirectoryOnly).Any()
            || Directory.Exists(_layout.UpdateReceiptRoot)
                && Directory.EnumerateFiles(
                    _layout.UpdateReceiptRoot,
                    "*.json",
                    SearchOption.TopDirectoryOnly).Any())
        {
            return true;
        }
        return HasUnexpectedVersionDirectory(
                _layout.LauncherVersionsRoot,
                installerLauncherReleaseId)
            || HasUnexpectedVersionDirectory(
                _layout.RuntimeVersionsRoot,
                installerRuntimeReleaseId);
    }

    private bool HasUnexpectedVersionDirectory(string root, string expectedReleaseId)
    {
        if (!Directory.Exists(root))
        {
            return false;
        }
        EnterprisePathGuard.ValidateExistingPathWithin(
            root,
            _layout.ManagedRoot,
            requireDirectory: true);
        foreach (var directory in Directory.EnumerateDirectories(
            root,
            "*",
            SearchOption.TopDirectoryOnly))
        {
            EnterprisePathGuard.ValidateExistingPathWithin(
                directory,
                root,
                requireDirectory: true);
            if (!string.Equals(
                Path.GetFileName(directory),
                expectedReleaseId,
                StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    private static EnterpriseReleaseComponentPointer Component(
        EnterpriseReleaseArtifact artifact,
        string directory) => new(
            artifact.ReleaseId,
            directory,
            artifact.Sha256,
            artifact.CompleteTreeSha256);

    private static string ReadArchiveSha256(string directory, string receiptFile)
    {
        var receipt = EnterprisePointerJson.Deserialize<EnterpriseInstalledReleaseReceipt>(
            File.ReadAllBytes(Path.Combine(directory, receiptFile)));
        return receipt.ArchiveSha256;
    }

    private static string ReadCompleteTreeSha256(
        string directory,
        string component,
        string releaseId,
        string archiveSha256)
    {
        var receipt = EnterprisePointerJson.Deserialize<EnterpriseReleaseArtifactReceiptV2>(
            File.ReadAllBytes(Path.Combine(directory, EnterpriseTreeHash.ReceiptFileName)));
        var actual = EnterpriseTreeHash.Compute(directory);
        if (receipt.SchemaVersion != 2
            || !string.Equals(receipt.Component, component, StringComparison.Ordinal)
            || !string.Equals(receipt.ReleaseId, releaseId, StringComparison.Ordinal)
            || !string.Equals(receipt.ArchiveSha256, archiveSha256, StringComparison.Ordinal)
            || !EnterpriseHash.IsSha256(receipt.TreeSha256)
            || !string.Equals(receipt.TreeSha256, actual, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Initial enterprise component tree receipt is invalid.");
        }
        return actual;
    }
}

public sealed class EnterpriseReleaseHealthQuarantineStore(
    EnterpriseInstallationLayout layout)
{
    private const int MaximumFailures = 512;
    private readonly EnterpriseInstallationLayout _layout = layout
        ?? throw new ArgumentNullException(nameof(layout));

    public EnterpriseReleaseHealthQuarantine? TryRead()
    {
        if (!File.Exists(_layout.HealthQuarantinePath))
        {
            return null;
        }
        EnterprisePathGuard.ValidateExistingPathWithin(
            _layout.HealthQuarantinePath,
            _layout.ManagedRoot,
            requireDirectory: false);
        var quarantine = EnterprisePointerJson.Deserialize<EnterpriseReleaseHealthQuarantine>(
            File.ReadAllBytes(_layout.HealthQuarantinePath));
        Validate(quarantine);
        return quarantine;
    }

    public bool IsRejected(string releaseSetId)
    {
        EnterprisePathGuard.ValidateReleaseId(releaseSetId);
        var securityState = new EnterpriseReleaseSecurityStateProtection(_layout).TryRead();
        if (securityState is not null)
        {
            return securityState.FailedReleaseQuarantine.Any(failure => string.Equals(
                failure.ReleaseSetId,
                releaseSetId,
                StringComparison.Ordinal));
        }
        if (File.Exists(_layout.HealthQuarantinePath))
        {
            throw new InvalidDataException(
                "Enterprise plain health quarantine exists without authenticated security state.");
        }
        return false;
    }

    public void RecordFailed(EnterpriseReleaseSetReference failed, string reason)
    {
        using var writer = EnterprisePointerWriter.Acquire();
        RecordFailedUnderWriteLock(failed, reason);
    }

    internal void RecordFailedUnderWriteLock(
        EnterpriseReleaseSetReference failed,
        string reason)
    {
        ArgumentNullException.ThrowIfNull(failed);
        EnterprisePathGuard.ValidateReleaseId(failed.ReleaseSetId);
        var reasonCode = NormalizeReason(reason);
        var authenticated = EnterpriseReleaseFeedStateStore.RecordFailureUnderWriteLock(
            _layout,
            failed,
            reasonCode,
            DateTimeOffset.UtcNow);
        var next = new EnterpriseReleaseHealthQuarantine(
            2,
            EnterpriseReleaseSetContract.Product,
            EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(_layout.IsDevelopmentE2E),
            authenticated.FailedReleaseQuarantine);
        Validate(next);
        EnterprisePathGuard.WriteFileAtomically(
            _layout.HealthQuarantinePath,
            EnterprisePointerJson.Serialize(next),
            _layout.ManagedRoot);
    }

    private void Validate(EnterpriseReleaseHealthQuarantine quarantine)
    {
        if (quarantine.SchemaVersion != 2
            || !string.Equals(
                quarantine.Product,
                EnterpriseReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(
                quarantine.Environment,
                EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(_layout.IsDevelopmentE2E),
                StringComparison.Ordinal)
            || quarantine.Failures is null
            || quarantine.Failures.Count > MaximumFailures
            || quarantine.Failures.Any(failure => failure is null)
            || quarantine.Failures.Select(failure => failure.ReleaseSetId)
                .Distinct(StringComparer.Ordinal).Count() != quarantine.Failures.Count)
        {
            throw new InvalidDataException("Enterprise health quarantine is invalid.");
        }
        foreach (var failure in quarantine.Failures)
        {
            EnterprisePathGuard.ValidateReleaseId(failure.ReleaseSetId);
            if (failure.Generation <= 0
                || failure.Sequence <= 0
                || failure.RecordedAtUtc.Offset != TimeSpan.Zero
                || !string.Equals(
                    NormalizeReason(failure.ReasonCode),
                    failure.ReasonCode,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise health quarantine entry is invalid.");
            }
        }
    }

    private static string NormalizeReason(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        if (reason.Length > 256
            || reason.Any(character => char.IsControl(character)))
        {
            throw new InvalidDataException(
                "Enterprise health failure reason is invalid.");
        }
        return reason;
    }
}

public sealed class EnterpriseReleaseFeedStateStore
{
    internal const int SecurityStateSchemaVersion = 4;
    private const int MaximumAcceptedReleases = 4;
    private const int MaximumFailures = 512;
    private const int MaximumExactManifestBytes = 512 * 1024;
    private readonly EnterpriseInstallationLayout _layout;
    private readonly string _expectedChannel;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _maximumOfflineGrace;

    public EnterpriseReleaseFeedStateStore(
        EnterpriseInstallationLayout layout,
        string expectedChannel,
        TimeProvider? timeProvider = null,
        TimeSpan? maximumOfflineGrace = null)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        EnterpriseReleaseSetValidator.ValidateToken(
            expectedChannel,
            "expected channel",
            64);
        if (!EnterpriseReleaseSetContract.IsSupportedChannel(expectedChannel))
        {
            throw new ArgumentOutOfRangeException(nameof(expectedChannel));
        }
        _expectedChannel = expectedChannel;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _maximumOfflineGrace = maximumOfflineGrace ?? TimeSpan.FromDays(7);
        if (_maximumOfflineGrace < TimeSpan.FromHours(1)
            || _maximumOfflineGrace > TimeSpan.FromDays(14))
        {
            throw new ArgumentOutOfRangeException(nameof(maximumOfflineGrace));
        }
    }

    public EnterpriseReleaseFeedState? TryRead()
    {
        var state = new EnterpriseReleaseSecurityStateProtection(_layout).TryRead();
        if (state is not null)
        {
            ValidatePersistedState(_layout, state, _expectedChannel);
        }
        return state;
    }

    public EnterpriseReleaseFeedState RecordVerified(
        EnterpriseReleaseSetManifest manifest,
        ReadOnlySpan<byte> manifestBytes,
        Uri manifestUri,
        EnterpriseReleaseSetPointer activePointer,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(manifestUri);
        ArgumentNullException.ThrowIfNull(activePointer);
        RequireUtc(nowUtc, "manifest verification time");
        if (manifestBytes.Length is <= 0 or > MaximumExactManifestBytes)
        {
            throw new InvalidDataException(
                "Enterprise exact signed manifest size is invalid.");
        }
        var exactManifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
        if (!ManifestSemanticsMatch(manifest, exactManifest))
        {
            throw new InvalidDataException(
                "Enterprise parsed manifest does not match the exact bytes being admitted.");
        }
        manifest = exactManifest;
        if (!string.Equals(
                manifest.Channel,
                _expectedChannel,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise release-set channel does not match the subscribed feed state.");
        }
        RequireManifestUri(manifestUri);
        var digest = Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(manifestBytes));
        using var writer = EnterprisePointerWriter.Acquire();
        var previous = TryRead();
        if (previous is null)
        {
            if (activePointer.Previous is not null
                || activePointer.Current.Generation != 0
                || activePointer.Current.Sequence != 0
                || activePointer.Current.HealthState != EnterpriseReleaseHealthStates.Healthy)
            {
                throw new InvalidDataException(
                    "An updated enterprise installation lost its authenticated release security state.");
            }
        }
        else
        {
            _ = RequireAcceptedReference(previous, activePointer.Current);
            if (activePointer.Previous is not null)
            {
                _ = RequireAcceptedReference(previous, activePointer.Previous);
            }
        }

        var trustedNow = Max(
            Max(previous?.TrustedTimeUtc ?? nowUtc, nowUtc),
            manifest.IssuedAtUtc);
        if (trustedNow > manifest.ExpiresAtUtc)
        {
            throw new InvalidDataException(
                "Enterprise trusted time is beyond the signed manifest expiry.");
        }
        if (previous is not null)
        {
            if (manifest.Generation < previous.HighestGeneration
                || manifest.Sequence < previous.HighestSequence
                || manifest.MinAcceptedSequence < previous.MinAcceptedSequence
                || ((manifest.Sequence == previous.HighestSequence
                        || manifest.Generation < previous.HighestGeneration)
                    && !string.Equals(digest, previous.LastManifestSha256, StringComparison.Ordinal)))
            {
                throw new InvalidDataException(
                    "Enterprise release-set was rejected as rollback or equivocation.");
            }
            var reused = previous.AcceptedReleases.SingleOrDefault(candidate =>
                string.Equals(
                    candidate.ReleaseSetId,
                    manifest.ReleaseSetId,
                    StringComparison.Ordinal));
            if (reused is not null
                && !string.Equals(reused.ManifestSha256, digest, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise release-set identity was reused with different signed bytes.");
            }
        }

        var revoked = (previous?.RevokedReleaseSetIds ?? [])
            .Concat(manifest.RevokedReleaseSetIds)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (revoked.Length > 5_000)
        {
            throw new InvalidDataException("Enterprise persisted revocation set is too large.");
        }
        var accepted = (previous?.AcceptedReleases
                ?? [CreateInstallerBootstrapIdentity(activePointer.Current)])
            .Where(candidate => !string.Equals(
                candidate.ReleaseSetId,
                manifest.ReleaseSetId,
                StringComparison.Ordinal))
            .Append(CreateSignedIdentity(
                _layout,
                manifest,
                manifestBytes,
                manifestUri,
                digest,
                nowUtc))
            .OrderBy(candidate => candidate.Sequence)
            .ThenBy(candidate => candidate.ReleaseSetId, StringComparer.Ordinal)
            .ToArray();
        accepted = RetainAcceptedReleases(accepted, activePointer);
        var next = new EnterpriseReleaseFeedState(
            SecurityStateSchemaVersion,
            checked((previous?.StateRevision ?? 0) + 1),
            Guid.NewGuid().ToString("N"),
            manifest.Product,
            manifest.Environment,
            manifest.Channel,
            Math.Max(previous?.HighestGeneration ?? 0, manifest.Generation),
            Math.Max(previous?.HighestSequence ?? 0, manifest.Sequence),
            Math.Max(previous?.MinAcceptedSequence ?? 0, manifest.MinAcceptedSequence),
            trustedNow,
            revoked,
            previous?.FailedReleaseQuarantine.ToArray()
                ?? Array.Empty<EnterpriseReleaseHealthFailure>(),
            accepted,
            digest,
            trustedNow,
            manifest.ExpiresAtUtc);
        ValidatePersistedState(_layout, next, _expectedChannel);
        new EnterpriseReleaseSecurityStateProtection(_layout).Write(next);
        return next;
    }

    public bool IsCurrentAllowedOffline(EnterpriseReleaseSetReference current, out string reason)
    {
        ArgumentNullException.ThrowIfNull(current);
        var nowUtc = _timeProvider.GetUtcNow();
        RequireUtc(nowUtc, "observed time");
        using var writer = EnterprisePointerWriter.Acquire();
        var state = TryRead();
        if (state is null)
        {
            var initialDeadline = current.ActivatedAtUtc + _maximumOfflineGrace;
            if (current.Generation != 0
                || current.Sequence != 0
                || current.HealthState != EnterpriseReleaseHealthStates.Healthy
                || current.ActivatedAtUtc > nowUtc.AddMinutes(5))
            {
                reason = "已更新设备缺少受保护的更新安全状态，必须执行受信修复。";
                return false;
            }
            state = CreateInstallerBootstrapState(
                _layout,
                _expectedChannel,
                current,
                nowUtc);
            new EnterpriseReleaseSecurityStateProtection(_layout).Write(state);
            if (nowUtc > initialDeadline)
            {
                reason = "初装更新检查离线宽限已过期。";
                return false;
            }
            reason = $"尚无已验证更新状态；初装离线宽限至 {initialDeadline:O}。";
            return true;
        }
        _ = RequireAcceptedReference(state, current);
        var effectiveNow = Max(state.TrustedTimeUtc, nowUtc);
        if (effectiveNow > state.TrustedTimeUtc)
        {
            state = state with
            {
                StateRevision = checked(state.StateRevision + 1),
                StateCommitId = Guid.NewGuid().ToString("N"),
                TrustedTimeUtc = effectiveNow,
            };
            ValidatePersistedState(_layout, state, _expectedChannel);
            new EnterpriseReleaseSecurityStateProtection(_layout).Write(state);
        }
        if (current.Sequence < state.MinAcceptedSequence)
        {
            reason = "当前版本低于管理员强制最低序列。";
            return false;
        }
        if (state.RevokedReleaseSetIds.Contains(current.ReleaseSetId, StringComparer.Ordinal))
        {
            reason = "当前版本已被管理员吊销。";
            return false;
        }
        if (state.FailedReleaseQuarantine.Any(failure => string.Equals(
            failure.ReleaseSetId,
            current.ReleaseSetId,
            StringComparison.Ordinal)))
        {
            reason = "当前版本处于启动失败隔离区。";
            return false;
        }
        if (current.HealthState != EnterpriseReleaseHealthStates.Healthy)
        {
            reason = "当前版本尚未完成健康确认。";
            return false;
        }
        var verifiedDeadline = state.LastVerifiedAtUtc + _maximumOfflineGrace;
        var metadataDeadline = state.LastManifestExpiresAtUtc + _maximumOfflineGrace;
        var offlineDeadline = verifiedDeadline <= metadataDeadline
            ? verifiedDeadline
            : metadataDeadline;
        if (effectiveNow > offlineDeadline)
        {
            reason = "更新元数据离线宽限已过期，必须重新连接受信更新源。";
            return false;
        }
        reason = $"更新服务暂不可用；健康旧版本离线宽限至 {offlineDeadline:O}。";
        return true;
    }

    /// <summary>
    /// Evaluates the existing authenticated offline allowance without acquiring
    /// the pointer writer or advancing trusted time. Unlike
    /// <see cref="IsCurrentAllowedOffline"/>, a missing security state is not
    /// bootstrapped and therefore fails closed.
    /// </summary>
    internal bool IsCurrentAllowedOfflineReadOnly(
        EnterpriseReleaseSetReference current,
        out string reason)
    {
        ArgumentNullException.ThrowIfNull(current);
        var nowUtc = _timeProvider.GetUtcNow();
        RequireUtc(nowUtc, "observed time");
        var state = TryRead();
        if (state is null)
        {
            reason = "缺少受保护的更新安全状态，无法在只读检查中确认离线宽限。";
            return false;
        }

        _ = RequireAcceptedReference(state, current);
        var effectiveNow = Max(state.TrustedTimeUtc, nowUtc);
        if (current.Sequence < state.MinAcceptedSequence)
        {
            reason = "当前版本低于管理员强制最低序列。";
            return false;
        }
        if (state.RevokedReleaseSetIds.Contains(current.ReleaseSetId, StringComparer.Ordinal))
        {
            reason = "当前版本已被管理员吊销。";
            return false;
        }
        if (state.FailedReleaseQuarantine.Any(failure => string.Equals(
                failure.ReleaseSetId,
                current.ReleaseSetId,
                StringComparison.Ordinal)))
        {
            reason = "当前版本处于启动失败隔离区。";
            return false;
        }
        if (current.HealthState != EnterpriseReleaseHealthStates.Healthy)
        {
            reason = "当前版本尚未完成健康确认。";
            return false;
        }
        var verifiedDeadline = state.LastVerifiedAtUtc + _maximumOfflineGrace;
        var metadataDeadline = state.LastManifestExpiresAtUtc + _maximumOfflineGrace;
        var offlineDeadline = verifiedDeadline <= metadataDeadline
            ? verifiedDeadline
            : metadataDeadline;
        if (effectiveNow > offlineDeadline)
        {
            reason = "更新元数据离线宽限已过期，必须重新连接受信更新源。";
            return false;
        }
        reason = $"更新服务暂不可用；健康旧版本离线宽限至 {offlineDeadline:O}。";
        return true;
    }

    public EnterpriseAcceptedReleaseIdentity ReadAcceptedIdentityRequired(
        EnterpriseReleaseSetReference current,
        EnterpriseCompiledReleaseTrust? compiledTrust = null)
    {
        ArgumentNullException.ThrowIfNull(current);
        var state = TryRead()
            ?? throw new InvalidDataException(
                "Enterprise authenticated signed release-feed state is missing.");
        var accepted = RequireAcceptedReference(state, current);
        RequireExactSignedAuthorization(
            _layout,
            accepted,
            compiledTrust,
            _timeProvider.GetUtcNow());
        return accepted;
    }

    public void RequirePendingHealthAllowed(EnterpriseReleaseSetReference current)
    {
        ArgumentNullException.ThrowIfNull(current);
        using var writer = EnterprisePointerWriter.Acquire();
        var state = TryRead()
            ?? throw new InvalidDataException(
                "Enterprise pending release has no authenticated security state.");
        var accepted = RequireAcceptedReference(state, current);
        if (current.HealthState != EnterpriseReleaseHealthStates.Pending
            || accepted.InstallerBootstrap
            || current.Generation != state.HighestGeneration
            || current.Sequence != state.HighestSequence
            || !string.Equals(
                accepted.ManifestSha256,
                state.LastManifestSha256,
                StringComparison.Ordinal)
            || current.Sequence < state.MinAcceptedSequence
            || state.RevokedReleaseSetIds.Contains(
                current.ReleaseSetId,
                StringComparer.Ordinal)
            || state.FailedReleaseQuarantine.Any(failure => string.Equals(
                failure.ReleaseSetId,
                current.ReleaseSetId,
                StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Enterprise pending release is stale, revoked, quarantined, or not the latest signed candidate.");
        }
        var effectiveNow = Max(state.TrustedTimeUtc, _timeProvider.GetUtcNow());
        var exactManifest = EnterpriseReleaseSetManifest.Parse(
            DecodeExactManifest(accepted));
        if (effectiveNow > exactManifest.ExpiresAtUtc)
        {
            throw new InvalidDataException(
                "Enterprise pending release manifest expired before health verification.");
        }
        if (effectiveNow > state.TrustedTimeUtc)
        {
            var next = state with
            {
                StateRevision = checked(state.StateRevision + 1),
                StateCommitId = Guid.NewGuid().ToString("N"),
                TrustedTimeUtc = effectiveNow,
            };
            ValidatePersistedState(_layout, next, _expectedChannel);
            new EnterpriseReleaseSecurityStateProtection(_layout).Write(next);
        }
    }

    internal static void RequirePointerBound(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetPointer pointer,
        EnterpriseCompiledReleaseTrust? compiledTrust,
        DateTimeOffset observedNowUtc)
    {
        RequireUtc(observedNowUtc, "pointer observation time");
        var state = new EnterpriseReleaseSecurityStateProtection(layout).TryRead();
        if (state is null)
        {
            if (pointer.Previous is not null
                || pointer.Current.Generation != 0
                || pointer.Current.Sequence != 0
                || pointer.Current.HealthState != EnterpriseReleaseHealthStates.Healthy)
            {
                throw new InvalidDataException(
                    "Enterprise release pointer has no authenticated update security state.");
            }
            return;
        }
        ValidatePersistedState(layout, state, expectedChannel: null);
        var current = RequireAcceptedReference(state, pointer.Current);
        RequireExactSignedAuthorization(
            layout,
            current,
            compiledTrust,
            observedNowUtc);
        if (pointer.Previous is not null)
        {
            var previous = RequireAcceptedReference(state, pointer.Previous);
            RequireExactSignedAuthorization(
                layout,
                previous,
                compiledTrust,
                observedNowUtc);
        }
        // Pointer selection and executable-tree integrity are checked here.
        // Signed floor/revocation/quarantine admission stays in the startup and
        // Node-start gates so the updater can still inspect an old pointer and
        // replace it without executing the disallowed runtime.
    }

    internal static EnterpriseReleaseFeedState RecordFailureUnderWriteLock(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetReference failed,
        string reasonCode,
        DateTimeOffset observedNowUtc)
    {
        RequireUtc(observedNowUtc, "failure observation time");
        var protection = new EnterpriseReleaseSecurityStateProtection(layout);
        var state = protection.TryRead()
            ?? throw new InvalidDataException(
                "Enterprise release failure has no authenticated security state.");
        _ = RequireAcceptedReference(state, failed);
        var existing = state.FailedReleaseQuarantine.SingleOrDefault(candidate =>
            string.Equals(candidate.ReleaseSetId, failed.ReleaseSetId, StringComparison.Ordinal));
        if (existing is not null)
        {
            if (existing.Generation != failed.Generation
                || existing.Sequence != failed.Sequence)
            {
                throw new InvalidDataException(
                    "Enterprise failed release identity was reused with different ordering.");
            }
            return state;
        }
        if (state.FailedReleaseQuarantine.Count >= MaximumFailures)
        {
            throw new InvalidDataException(
                "Enterprise authenticated health quarantine is full.");
        }
        var next = state with
        {
            StateRevision = checked(state.StateRevision + 1),
            StateCommitId = Guid.NewGuid().ToString("N"),
            TrustedTimeUtc = Max(state.TrustedTimeUtc, observedNowUtc),
            FailedReleaseQuarantine = state.FailedReleaseQuarantine
                .Append(new EnterpriseReleaseHealthFailure(
                    failed.ReleaseSetId,
                    failed.Generation,
                    failed.Sequence,
                    reasonCode,
                    observedNowUtc))
                .ToArray(),
        };
        ValidatePersistedState(layout, next, expectedChannel: null);
        protection.Write(next);
        return next;
    }

    internal static void ValidatePersistedState(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseFeedState state,
        string? expectedChannel)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(state);
        if (state.SchemaVersion != SecurityStateSchemaVersion
            || state.StateRevision <= 0
            || !Guid.TryParseExact(state.StateCommitId, "N", out _)
            || !string.Equals(state.Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                state.Environment,
                EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(layout.IsDevelopmentE2E),
                StringComparison.Ordinal)
            || !EnterpriseReleaseSetContract.IsSupportedChannel(state.Channel)
            || expectedChannel is not null
                && !string.Equals(state.Channel, expectedChannel, StringComparison.Ordinal)
            || state.HighestGeneration < 0
            || state.HighestSequence < 0
            || state.MinAcceptedSequence < 0
            || state.MinAcceptedSequence > state.HighestSequence
            || state.TrustedTimeUtc.Offset != TimeSpan.Zero
            || state.LastVerifiedAtUtc.Offset != TimeSpan.Zero
            || state.LastManifestExpiresAtUtc.Offset != TimeSpan.Zero
            || state.TrustedTimeUtc < state.LastVerifiedAtUtc
            || !EnterpriseHash.IsSha256(state.LastManifestSha256)
            || state.RevokedReleaseSetIds is null
            || state.FailedReleaseQuarantine is null
            || state.AcceptedReleases is null
            || state.RevokedReleaseSetIds.Distinct(StringComparer.Ordinal).Count()
                != state.RevokedReleaseSetIds.Count
            || !state.RevokedReleaseSetIds.SequenceEqual(
                state.RevokedReleaseSetIds.Order(StringComparer.Ordinal),
                StringComparer.Ordinal)
            || state.FailedReleaseQuarantine.Count > MaximumFailures
            || state.FailedReleaseQuarantine.Select(failure => failure.ReleaseSetId)
                .Distinct(StringComparer.Ordinal).Count()
                != state.FailedReleaseQuarantine.Count
            || state.AcceptedReleases.Count is <= 0 or > MaximumAcceptedReleases
            || state.AcceptedReleases.Select(candidate => candidate.ReleaseSetId)
                .Distinct(StringComparer.Ordinal).Count() != state.AcceptedReleases.Count
            || state.AcceptedReleases.Select(candidate => candidate.Sequence)
                .Distinct().Count() != state.AcceptedReleases.Count)
        {
            throw new InvalidDataException("Enterprise release feed security state is invalid.");
        }
        foreach (var revoked in state.RevokedReleaseSetIds)
        {
            EnterprisePathGuard.ValidateReleaseId(revoked);
        }
        foreach (var failure in state.FailedReleaseQuarantine)
        {
            EnterprisePathGuard.ValidateReleaseId(failure.ReleaseSetId);
            if (failure.Generation <= 0
                || failure.Sequence <= 0
                || failure.Generation > state.HighestGeneration
                || failure.Sequence > state.HighestSequence
                || failure.RecordedAtUtc.Offset != TimeSpan.Zero
                || string.IsNullOrWhiteSpace(failure.ReasonCode)
                || failure.ReasonCode.Length > 256
                || failure.ReasonCode.Any(char.IsControl))
            {
                throw new InvalidDataException(
                    "Enterprise authenticated release quarantine is invalid.");
            }
        }
        foreach (var accepted in state.AcceptedReleases)
        {
            ValidateAcceptedIdentity(layout, accepted);
            if (accepted.Generation > state.HighestGeneration
                || accepted.Sequence > state.HighestSequence)
            {
                throw new InvalidDataException(
                    "Enterprise accepted release exceeds its authenticated high-water mark.");
            }
        }
        if (!state.AcceptedReleases.Any(candidate =>
                candidate.Generation == state.HighestGeneration
                && candidate.Sequence == state.HighestSequence
                && string.Equals(
                    candidate.ManifestSha256,
                    state.LastManifestSha256,
                    StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Enterprise latest manifest is absent from authenticated authorization records.");
        }
    }

    private static EnterpriseReleaseFeedState CreateInstallerBootstrapState(
        EnterpriseInstallationLayout layout,
        string channel,
        EnterpriseReleaseSetReference current,
        DateTimeOffset observedNowUtc)
    {
        var identity = CreateInstallerBootstrapIdentity(current);
        var state = new EnterpriseReleaseFeedState(
            SecurityStateSchemaVersion,
            1,
            Guid.NewGuid().ToString("N"),
            EnterpriseReleaseSetContract.Product,
            EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(layout.IsDevelopmentE2E),
            channel,
            0,
            0,
            0,
            Max(observedNowUtc, current.ActivatedAtUtc),
            [],
            [],
            [identity],
            identity.ManifestSha256,
            current.ActivatedAtUtc,
            current.ActivatedAtUtc);
        ValidatePersistedState(layout, state, channel);
        return state;
    }

    private static EnterpriseAcceptedReleaseIdentity CreateInstallerBootstrapIdentity(
        EnterpriseReleaseSetReference current)
    {
        var payload = string.Join(
            '\n',
            "enterprise-installer-bootstrap-v1",
            current.ReleaseSetId,
            current.Generation,
            current.Sequence,
            current.MinAcceptedSequence,
            current.StartupStub.MinimumProtocol,
            current.StartupStub.MaximumProtocol,
            current.Launcher.ReleaseId,
            current.Launcher.ArchiveSha256,
            current.Launcher.CompleteTreeSha256,
            current.Runtime.ReleaseId,
            current.Runtime.ArchiveSha256,
            current.Runtime.CompleteTreeSha256,
            current.PluginPolicy?.ReleaseId ?? string.Empty,
            current.PluginPolicy?.ArchiveSha256 ?? string.Empty,
            current.PluginPolicy?.CompleteTreeSha256 ?? string.Empty);
        return new EnterpriseAcceptedReleaseIdentity(
            true,
            current.ReleaseSetId,
            current.Generation,
            current.Sequence,
            current.MinAcceptedSequence,
            current.StartupStub,
            current.Launcher,
            current.Runtime,
            current.PluginPolicy,
            Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(payload))),
            null,
            null,
            current.ActivatedAtUtc);
    }

    private static EnterpriseAcceptedReleaseIdentity CreateSignedIdentity(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseSetManifest manifest,
        ReadOnlySpan<byte> exactBytes,
        Uri manifestUri,
        string digest,
        DateTimeOffset verifiedAtUtc) => new(
            false,
            manifest.ReleaseSetId,
            manifest.Generation,
            manifest.Sequence,
            manifest.MinAcceptedSequence,
            manifest.StartupStub,
            new EnterpriseReleaseComponentPointer(
                manifest.Launcher.ReleaseId,
                layout.GetLauncherVersionDirectory(manifest.Launcher.ReleaseId),
                manifest.Launcher.Sha256,
                manifest.Launcher.CompleteTreeSha256),
            new EnterpriseReleaseComponentPointer(
                manifest.Runtime.ReleaseId,
                layout.GetRuntimeVersionDirectory(manifest.Runtime.ReleaseId),
                manifest.Runtime.Sha256,
                manifest.Runtime.CompleteTreeSha256),
            manifest.PluginPolicy is null
                ? null
                : new EnterpriseReleaseComponentPointer(
                    manifest.PluginPolicy.ReleaseId,
                    layout.GetPluginPolicyVersionDirectory(manifest.PluginPolicy.ReleaseId),
                    manifest.PluginPolicy.Sha256,
                    manifest.PluginPolicy.CompleteTreeSha256),
            digest,
            Convert.ToBase64String(exactBytes),
            manifestUri.AbsoluteUri,
            verifiedAtUtc);

    private static EnterpriseAcceptedReleaseIdentity[] RetainAcceptedReleases(
        EnterpriseAcceptedReleaseIdentity[] candidates,
        EnterpriseReleaseSetPointer activePointer)
    {
        if (candidates.Length <= MaximumAcceptedReleases)
        {
            return candidates;
        }
        var retainedIds = new HashSet<string>(StringComparer.Ordinal)
        {
            activePointer.Current.ReleaseSetId,
            candidates[^1].ReleaseSetId,
        };
        if (activePointer.Previous is not null)
        {
            retainedIds.Add(activePointer.Previous.ReleaseSetId);
        }
        var retained = candidates
            .Where(candidate => retainedIds.Contains(candidate.ReleaseSetId))
            .Concat(candidates
                .Where(candidate => !retainedIds.Contains(candidate.ReleaseSetId))
                .TakeLast(MaximumAcceptedReleases - retainedIds.Count))
            .DistinctBy(candidate => candidate.ReleaseSetId, StringComparer.Ordinal)
            .OrderBy(candidate => candidate.Sequence)
            .ThenBy(candidate => candidate.ReleaseSetId, StringComparer.Ordinal)
            .ToArray();
        if (retained.Length > MaximumAcceptedReleases)
        {
            throw new InvalidDataException(
                "Enterprise accepted release retention exceeded its bound.");
        }
        return retained;
    }

    private static EnterpriseAcceptedReleaseIdentity RequireAcceptedReference(
        EnterpriseReleaseFeedState state,
        EnterpriseReleaseSetReference reference)
    {
        var accepted = state.AcceptedReleases.SingleOrDefault(candidate =>
            string.Equals(
                candidate.ReleaseSetId,
                reference.ReleaseSetId,
                StringComparison.Ordinal))
            ?? throw new InvalidDataException(
                "Enterprise pointer is not bound to authenticated signed metadata.");
        if (!ReferenceMatches(accepted, reference))
        {
            throw new InvalidDataException(
                "Enterprise pointer tuple differs from its authenticated authorization record.");
        }
        return accepted;
    }

    private static bool ReferenceMatches(
        EnterpriseAcceptedReleaseIdentity accepted,
        EnterpriseReleaseSetReference reference) =>
        accepted.Generation == reference.Generation
        && accepted.Sequence == reference.Sequence
        && accepted.MinAcceptedSequence == reference.MinAcceptedSequence
        && StartupStubMatches(accepted.StartupStub, reference.StartupStub)
        && ComponentMatches(accepted.Launcher, reference.Launcher)
        && ComponentMatches(accepted.Runtime, reference.Runtime)
        && NullableComponentMatches(accepted.PluginPolicy, reference.PluginPolicy);

    private static void RequireExactSignedAuthorization(
        EnterpriseInstallationLayout layout,
        EnterpriseAcceptedReleaseIdentity accepted,
        EnterpriseCompiledReleaseTrust? compiledTrust,
        DateTimeOffset observedNowUtc)
    {
        if (accepted.InstallerBootstrap)
        {
            if (accepted.Sequence != 0)
            {
                throw new InvalidDataException(
                    "Enterprise signed release cannot use installer-bootstrap authorization.");
            }
            return;
        }
        var exactBytes = DecodeExactManifest(accepted);
        var manifest = EnterpriseReleaseSetManifest.Parse(exactBytes);
        RequireManifestMatchesAccepted(manifest, accepted);
        if (compiledTrust is null)
        {
            return;
        }
        compiledTrust.Validate(layout);
        if (!string.Equals(
                accepted.ManifestUri,
                compiledTrust.ManifestUri.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise accepted manifest URI differs from compiled release trust.");
        }
        EnterpriseReleaseSetValidator.Verify(
            manifest,
            compiledTrust.Policy,
            accepted.VerifiedAtUtc);
        RequireUtc(observedNowUtc, nameof(observedNowUtc));
        // Signature validity is replayed at the durable original verification time.
        // Current temporal admission (trusted time, expiry, and offline grace) is
        // enforced separately by the launch gate before any controlled process starts.
    }

    private static void ValidateAcceptedIdentity(
        EnterpriseInstallationLayout layout,
        EnterpriseAcceptedReleaseIdentity accepted)
    {
        EnterprisePathGuard.ValidateReleaseId(accepted.ReleaseSetId);
        if (accepted.Generation < 0
            || accepted.Sequence < 0
            || accepted.MinAcceptedSequence < 0
            || accepted.MinAcceptedSequence > accepted.Sequence
            || accepted.StartupStub is null
            || !EnterpriseHash.IsSha256(accepted.ManifestSha256)
            || accepted.VerifiedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Enterprise accepted release authorization is invalid.");
        }
        EnterpriseReleaseSetValidator.ValidateStartupStubRange(accepted.StartupStub);
        ValidateAcceptedComponent(
            layout,
            accepted.Launcher,
            layout.GetLauncherVersionDirectory(accepted.Launcher.ReleaseId));
        ValidateAcceptedComponent(
            layout,
            accepted.Runtime,
            layout.GetRuntimeVersionDirectory(accepted.Runtime.ReleaseId));
        if (accepted.PluginPolicy is not null)
        {
            ValidateAcceptedComponent(
                layout,
                accepted.PluginPolicy,
                layout.GetPluginPolicyVersionDirectory(accepted.PluginPolicy.ReleaseId));
        }
        if (accepted.InstallerBootstrap)
        {
            if (accepted.Generation != 0
                || accepted.Sequence != 0
                || accepted.MinAcceptedSequence != 0
                || accepted.ExactManifestBase64 is not null
                || accepted.ManifestUri is not null)
            {
                throw new InvalidDataException(
                    "Enterprise installer-bootstrap authorization is invalid.");
            }
            return;
        }
        if (accepted.Generation <= 0
            || accepted.Sequence <= 0
            || string.IsNullOrWhiteSpace(accepted.ExactManifestBase64)
            || string.IsNullOrWhiteSpace(accepted.ManifestUri))
        {
            throw new InvalidDataException(
                "Enterprise signed release authorization is incomplete.");
        }
        RequireManifestUri(new Uri(accepted.ManifestUri, UriKind.Absolute));
        var exactBytes = DecodeExactManifest(accepted);
        var digest = Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(exactBytes));
        if (!string.Equals(digest, accepted.ManifestSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise exact signed manifest digest changed.");
        }
        RequireManifestMatchesAccepted(
            EnterpriseReleaseSetManifest.Parse(exactBytes),
            accepted);
    }

    private static void ValidateAcceptedComponent(
        EnterpriseInstallationLayout layout,
        EnterpriseReleaseComponentPointer component,
        string expectedDirectory)
    {
        EnterprisePathGuard.ValidateReleaseId(component.ReleaseId);
        if (!EnterpriseHash.IsSha256(component.ArchiveSha256)
            || !EnterpriseHash.IsSha256(component.CompleteTreeSha256)
            || !string.Equals(
                EnterprisePathGuard.NormalizeDirectory(component.Directory),
                expectedDirectory,
                StringComparison.OrdinalIgnoreCase)
            || !EnterprisePathGuard.IsSameOrDescendant(
                component.Directory,
                layout.ManagedRoot))
        {
            throw new InvalidDataException(
                "Enterprise accepted component authorization is invalid.");
        }
    }

    private static byte[] DecodeExactManifest(
        EnterpriseAcceptedReleaseIdentity accepted)
    {
        try
        {
            var bytes = Convert.FromBase64String(accepted.ExactManifestBase64!);
            if (bytes.Length is <= 0 or > MaximumExactManifestBytes
                || !string.Equals(
                    Convert.ToBase64String(bytes),
                    accepted.ExactManifestBase64,
                    StringComparison.Ordinal))
            {
                throw new FormatException();
            }
            return bytes;
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Enterprise exact signed manifest encoding is invalid.",
                exception);
        }
    }

    private static void RequireManifestMatchesAccepted(
        EnterpriseReleaseSetManifest manifest,
        EnterpriseAcceptedReleaseIdentity accepted)
    {
        if (!string.Equals(manifest.ReleaseSetId, accepted.ReleaseSetId, StringComparison.Ordinal)
            || manifest.Generation != accepted.Generation
            || manifest.Sequence != accepted.Sequence
            || manifest.MinAcceptedSequence != accepted.MinAcceptedSequence
            || !StartupStubMatches(manifest.StartupStub, accepted.StartupStub)
            || !ArtifactMatches(manifest.Launcher, accepted.Launcher)
            || !ArtifactMatches(manifest.Runtime, accepted.Runtime)
            || !NullableArtifactMatches(manifest.PluginPolicy, accepted.PluginPolicy))
        {
            throw new InvalidDataException(
                "Enterprise signed manifest does not match its accepted tuple.");
        }
    }

    private static bool ManifestSemanticsMatch(
        EnterpriseReleaseSetManifest left,
        EnterpriseReleaseSetManifest right) =>
        left.SchemaVersion == right.SchemaVersion
        && string.Equals(left.Product, right.Product, StringComparison.Ordinal)
        && string.Equals(left.Environment, right.Environment, StringComparison.Ordinal)
        && string.Equals(left.Channel, right.Channel, StringComparison.Ordinal)
        && string.Equals(left.ReleaseSetId, right.ReleaseSetId, StringComparison.Ordinal)
        && left.Generation == right.Generation
        && left.Sequence == right.Sequence
        && left.MinAcceptedSequence == right.MinAcceptedSequence
        && left.IssuedAtUtc == right.IssuedAtUtc
        && left.ExpiresAtUtc == right.ExpiresAtUtc
        && StartupStubMatches(left.StartupStub, right.StartupStub)
        && left.RevokedReleaseSetIds.SequenceEqual(right.RevokedReleaseSetIds, StringComparer.Ordinal)
        && left.Artifacts.Count == right.Artifacts.Count
        && left.Artifacts.Zip(right.Artifacts).All(pair => ArtifactSemanticsMatch(
            pair.First,
            pair.Second))
        && SignatureMatches(left.Signature, right.Signature);

    private static bool ArtifactSemanticsMatch(
        EnterpriseReleaseArtifact left,
        EnterpriseReleaseArtifact right) =>
        string.Equals(left.Component, right.Component, StringComparison.Ordinal)
        && string.Equals(left.ReleaseId, right.ReleaseId, StringComparison.Ordinal)
        && left.Uri == right.Uri
        && left.SizeBytes == right.SizeBytes
        && string.Equals(left.Sha256, right.Sha256, StringComparison.Ordinal)
        && string.Equals(
            left.CompleteTreeSha256,
            right.CompleteTreeSha256,
            StringComparison.Ordinal)
        && SignatureMatches(left.Signature, right.Signature);

    private static bool SignatureMatches(
        EnterpriseReleaseSignature left,
        EnterpriseReleaseSignature right) =>
        string.Equals(left.Algorithm, right.Algorithm, StringComparison.Ordinal)
        && string.Equals(left.KeyId, right.KeyId, StringComparison.Ordinal)
        && string.Equals(left.Value, right.Value, StringComparison.Ordinal);

    private static bool StartupStubMatches(
        EnterpriseStartupStubCompatibility left,
        EnterpriseStartupStubCompatibility right) =>
        left.MinimumProtocol == right.MinimumProtocol
        && left.MaximumProtocol == right.MaximumProtocol;

    private static bool ComponentMatches(
        EnterpriseReleaseComponentPointer left,
        EnterpriseReleaseComponentPointer right) =>
        string.Equals(left.ReleaseId, right.ReleaseId, StringComparison.Ordinal)
        && string.Equals(left.Directory, right.Directory, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.ArchiveSha256, right.ArchiveSha256, StringComparison.Ordinal)
        && string.Equals(
            left.CompleteTreeSha256,
            right.CompleteTreeSha256,
            StringComparison.Ordinal);

    private static bool NullableComponentMatches(
        EnterpriseReleaseComponentPointer? left,
        EnterpriseReleaseComponentPointer? right) => left is null
        ? right is null
        : right is not null && ComponentMatches(left, right);

    private static bool ArtifactMatches(
        EnterpriseReleaseArtifact artifact,
        EnterpriseReleaseComponentPointer component) =>
        string.Equals(artifact.ReleaseId, component.ReleaseId, StringComparison.Ordinal)
        && string.Equals(artifact.Sha256, component.ArchiveSha256, StringComparison.Ordinal)
        && string.Equals(
            artifact.CompleteTreeSha256,
            component.CompleteTreeSha256,
            StringComparison.Ordinal);

    private static bool NullableArtifactMatches(
        EnterpriseReleaseArtifact? artifact,
        EnterpriseReleaseComponentPointer? component) => artifact is null
        ? component is null
        : component is not null && ArtifactMatches(artifact, component);

    private static void RequireManifestUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidDataException(
                "Enterprise accepted manifest URI is invalid.");
        }
    }

    private static DateTimeOffset Max(DateTimeOffset left, DateTimeOffset right) =>
        left >= right ? left : right;

    private static void RequireUtc(DateTimeOffset value, string field)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException($"Enterprise {field} must be UTC.");
        }
    }
}

public sealed class EnterpriseReleaseHealthCoordinator(
    EnterpriseInstallationLayout layout,
    EnterpriseCompiledReleaseTrust? compiledTrust = null)
{
    private readonly EnterpriseInstallationLayout _layout = layout
        ?? throw new ArgumentNullException(nameof(layout));
    private readonly EnterpriseCompiledReleaseTrust? _compiledTrust = compiledTrust;

    public void WriteSignal(string healthToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(healthToken);
        var pointer = new EnterpriseReleaseSetPointerStore(
            _layout,
            _compiledTrust).ReadRequired();
        if (pointer.Current.HealthState != EnterpriseReleaseHealthStates.Pending
            || !string.Equals(pointer.Current.HealthToken, healthToken, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise health signal does not match active release.");
        }
        var signal = new EnterpriseReleaseHealthSignal(
            2,
            pointer.Current.ReleaseSetId,
            healthToken,
            Environment.ProcessId,
            DateTimeOffset.UtcNow);
        EnterprisePathGuard.WriteFileAtomically(
            GetSignalPath(healthToken),
            EnterprisePointerJson.Serialize(signal),
            _layout.ManagedRoot);
    }

    public EnterpriseReleaseSetPointer ConsumeSignalAndMarkHealthy(string healthToken)
    {
        var path = GetSignalPath(healthToken);
        EnterprisePathGuard.ValidateExistingPathWithin(path, _layout.ManagedRoot, false);
        var signal = EnterprisePointerJson.Deserialize<EnterpriseReleaseHealthSignal>(
            File.ReadAllBytes(path));
        var pointer = new EnterpriseReleaseSetPointerStore(
            _layout,
            _compiledTrust).ReadRequired();
        if (signal.SchemaVersion != 2
            || !string.Equals(signal.Token, healthToken, StringComparison.Ordinal)
            || !string.Equals(signal.ReleaseSetId, pointer.Current.ReleaseSetId, StringComparison.Ordinal)
            || signal.RecordedAtUtc < DateTimeOffset.UtcNow.AddMinutes(-5)
            || signal.RecordedAtUtc > DateTimeOffset.UtcNow.AddMinutes(1))
        {
            throw new InvalidDataException("Enterprise release health signal is invalid.");
        }
        var homeTransaction = new EnterpriseHarnessHomeUpdateTransaction(
            _layout.HarnessHome,
            _layout.HarnessRecoveryRoot);
        var activeHome = homeTransaction.TryReadActiveState();
        if (activeHome is not null)
        {
            if (!string.Equals(
                    activeHome.ReleaseSetId,
                    pointer.Current.ReleaseSetId,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Harness-home recovery generation does not match the pending release-set.");
            }
            homeTransaction.MarkHealthPassed(activeHome.TransactionId);
        }
        var healthy = new EnterpriseReleaseSetPointerStore(_layout, _compiledTrust)
            .MarkCurrentHealthy(healthToken);
        if (activeHome is not null)
        {
            homeTransaction.FinalizeCommit(activeHome.TransactionId);
        }
        File.Delete(path);
        return healthy;
    }

    public string GetSignalPath(string healthToken)
    {
        var bytes = EnterpriseBase64Url.Decode(healthToken, "health token");
        if (bytes.Length != 32)
        {
            throw new InvalidDataException("Enterprise health token length is invalid.");
        }
        var safeName = Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(bytes));
        return Path.Combine(_layout.HealthSignalRoot, $"{safeName}.json");
    }
}

public sealed record EnterpriseHealthProbeResult(bool Healthy, string Detail);

public sealed class EnterpriseBootstrapHealthGate(
    EnterpriseInstallationLayout layout,
    TimeSpan timeout,
    EnterpriseCompiledReleaseTrust? compiledTrust = null)
{
    public static TimeSpan ColdStartTimeout { get; } = TimeSpan.FromMinutes(5);

    private readonly EnterpriseInstallationLayout _layout = layout
        ?? throw new ArgumentNullException(nameof(layout));
    private readonly EnterpriseCompiledReleaseTrust? _compiledTrust = compiledTrust;
    private readonly TimeSpan _timeout = timeout is { } value
        && value >= TimeSpan.FromSeconds(1)
        && value <= TimeSpan.FromMinutes(5)
        ? value
        : throw new ArgumentOutOfRangeException(nameof(timeout));

    public async Task<EnterpriseReleaseSetPointer> RollbackPendingAsync(
        string reason,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        await using var operationLease =
            await EnterpriseManagedUpdateOperationLease.AcquireRequiredAsync(
                _layout,
                cancellationToken).ConfigureAwait(false);
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(_layout);
        var store = new EnterpriseReleaseSetPointerStore(_layout, _compiledTrust);
        var pointer = store.ReadRequired();
        if (pointer.Current.HealthState != EnterpriseReleaseHealthStates.Pending
            || pointer.Previous is null)
        {
            throw new InvalidOperationException(
                "Enterprise release-set has no pending activation to roll back.");
        }
        // Operator and failed-health rollback must restore the same Harness-home
        // generation before switching the release pointer back to the old tuple.
        RollbackPendingWithHome(store, reason);
        return store.ReadRequired();
    }

    public async Task<EnterpriseHealthProbeResult> EnsureHealthyAsync(
        Func<string, string, TimeSpan, CancellationToken, Task<int>> runProbeAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(runProbeAsync);
        await using var operationLease =
            await EnterpriseManagedUpdateOperationLease.AcquireRequiredAsync(
                _layout,
                cancellationToken).ConfigureAwait(false);
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(_layout);
        if (!Directory.Exists(_layout.ManagedRoot)
            || !File.Exists(_layout.ReleaseSetPointerPath))
        {
            throw new InvalidDataException(
                "Enterprise managed installation disappeared before health completion.");
        }
        var store = new EnterpriseReleaseSetPointerStore(_layout, _compiledTrust);
        var pointer = store.ReadRequired();
        if (pointer.Current.HealthState == EnterpriseReleaseHealthStates.Healthy)
        {
            return new EnterpriseHealthProbeResult(true, "active release already healthy");
        }
        if (new EnterpriseReleaseHealthQuarantineStore(_layout)
            .IsRejected(pointer.Current.ReleaseSetId))
        {
            RollbackPendingWithHome(
                store,
                "release-set was previously rejected by health verification");
            return new EnterpriseHealthProbeResult(
                false,
                "previously rejected release was rolled back without re-execution");
        }
        if (_compiledTrust is not null)
        {
            new EnterpriseReleaseFeedStateStore(
                _layout,
                _compiledTrust.Policy.ExpectedChannel)
                .RequirePendingHealthAllowed(pointer.Current);
        }
        var token = pointer.Current.HealthToken
            ?? throw new InvalidDataException("Pending release has no health token.");
        var launcherPath = Path.Combine(
            pointer.Current.Launcher.Directory,
            EnterpriseInstallationLayout.LauncherExecutableName);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_timeout);
        try
        {
            var exitCode = await runProbeAsync(
                launcherPath,
                token,
                _timeout,
                timeoutCts.Token).ConfigureAwait(false);
            if (exitCode != 0)
            {
                RollbackPendingWithHome(
                    store,
                    $"launcher self-check exited with code {exitCode}");
                return new EnterpriseHealthProbeResult(false, "launcher self-check failed; rolled back");
            }
            _ = new EnterpriseReleaseHealthCoordinator(_layout, _compiledTrust)
                .ConsumeSignalAndMarkHealthy(token);
            return new EnterpriseHealthProbeResult(true, "launcher health handshake completed");
        }
        catch (Exception exception) when (
            exception is OperationCanceledException
                or InvalidDataException
                or IOException
                or UnauthorizedAccessException)
        {
            try
            {
                RollbackPendingWithHome(
                    store,
                    $"launcher health handshake failed: {exception.GetType().Name}");
            }
            catch
            {
                // Preserve the original health failure. Bootstrapper remains fail closed.
            }
            return new EnterpriseHealthProbeResult(false, "launcher health handshake failed; rolled back");
        }
    }

    private void RollbackPendingWithHome(
        EnterpriseReleaseSetPointerStore store,
        string reason)
    {
        var pointer = store.ReadRequired();
        // The quarantine entry is the durable rollback intent. It must exist
        // before any Harness-home move so every interrupted phase resumes the
        // rollback instead of executing this candidate again.
        new EnterpriseReleaseHealthQuarantineStore(_layout)
            .RecordFailed(pointer.Current, reason);
        var homeTransaction = new EnterpriseHarnessHomeUpdateTransaction(
            _layout.HarnessHome,
            _layout.HarnessRecoveryRoot);
        var activeHome = homeTransaction.TryReadActiveState();
        if (activeHome is not null)
        {
            if (!string.Equals(
                    activeHome.ReleaseSetId,
                    pointer.Current.ReleaseSetId,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Harness-home recovery generation does not match the release being rolled back.");
            }
            _ = homeTransaction.Rollback(activeHome.TransactionId, "release-health-failed");
        }
        store.RollbackPending(reason);
    }
}

internal static class EnterpriseReleaseStateFiles
{
    public static void WriteReceipt(
        EnterpriseInstallationLayout layout,
        string eventName,
        EnterpriseReleaseSetReference reference,
        string? detail)
    {
        var receipt = new EnterpriseReleaseUpdateReceipt(
            2,
            eventName,
            reference.ReleaseSetId,
            reference.Sequence,
            detail,
            DateTimeOffset.UtcNow);
        var path = Path.Combine(
            layout.UpdateReceiptRoot,
            $"{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfffffffZ}-{Guid.NewGuid():N}.json");
        EnterprisePathGuard.WriteFileAtomically(
            path,
            EnterprisePointerJson.Serialize(receipt),
            layout.ManagedRoot);
    }

    public static void WriteStatus(
        EnterpriseInstallationLayout layout,
        string state,
        string message,
        EnterpriseReleaseSetReference? reference,
        bool mustUpdate)
    {
        var status = new EnterpriseReleaseUpdateStatus(
            2,
            state,
            message,
            reference?.ReleaseSetId,
            reference?.Sequence,
            mustUpdate,
            DateTimeOffset.UtcNow);
        EnterprisePathGuard.WriteFileAtomically(
            layout.UpdateStatusPath,
            EnterprisePointerJson.Serialize(status),
            layout.ManagedRoot);
    }

    public static EnterpriseReleaseUpdateStatus? TryReadStatus(
        EnterpriseInstallationLayout layout)
    {
        if (!File.Exists(layout.UpdateStatusPath))
        {
            return null;
        }
        EnterprisePathGuard.ValidateExistingPathWithin(
            layout.UpdateStatusPath,
            layout.ManagedRoot,
            false);
        var status = EnterprisePointerJson.Deserialize<EnterpriseReleaseUpdateStatus>(
            File.ReadAllBytes(layout.UpdateStatusPath));
        if (status.SchemaVersion != 2 || status.UpdatedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Enterprise update status is invalid.");
        }
        return status;
    }
}

public static class EnterpriseReleaseUpdateStatusReader
{
    public static EnterpriseReleaseUpdateStatus? TryRead(EnterpriseInstallationLayout layout) =>
        EnterpriseReleaseStateFiles.TryReadStatus(layout);
}

internal static class EnterpriseTreeHash
{
    public const string ReceiptFileName = ".ensou-enterprise-artifact.v2.json";

    public static string Compute(string root)
    {
        var normalizedRoot = EnterprisePathGuard.NormalizeDirectory(root);
        using var aggregate = System.Security.Cryptography.IncrementalHash.CreateHash(
            System.Security.Cryptography.HashAlgorithmName.SHA256);
        foreach (var path in Directory.EnumerateFiles(
                     normalizedRoot,
                     "*",
                     SearchOption.AllDirectories)
                 .Where(path => !IsInstallerReceipt(
                     Path.GetRelativePath(normalizedRoot, path).Replace('\\', '/')))
                 .OrderBy(path => Path.GetRelativePath(normalizedRoot, path)
                     .Replace('\\', '/'), StringComparer.Ordinal))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Enterprise immutable tree contains a filesystem link.");
            }
            var relative = Path.GetRelativePath(normalizedRoot, path).Replace('\\', '/');
            var relativeBytes = System.Text.Encoding.UTF8.GetBytes(relative);
            aggregate.AppendData(relativeBytes);
            aggregate.AppendData([0]);
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.SequentialScan);
            var hash = System.Security.Cryptography.SHA256.HashData(stream);
            aggregate.AppendData(hash);
            aggregate.AppendData([0]);
        }
        return Convert.ToHexStringLower(aggregate.GetHashAndReset());
    }

    internal static string ComputeFromFileHashes(
        IEnumerable<(string RelativePath, byte[] Sha256)> files)
    {
        ArgumentNullException.ThrowIfNull(files);
        using var aggregate = System.Security.Cryptography.IncrementalHash.CreateHash(
            System.Security.Cryptography.HashAlgorithmName.SHA256);
        foreach (var file in files
                     .Where(file => !IsInstallerReceipt(file.RelativePath))
                     .OrderBy(file => file.RelativePath, StringComparer.Ordinal))
        {
            if (file.Sha256.Length != 32)
            {
                throw new InvalidDataException(
                    "Enterprise immutable tree file hash is invalid.");
            }
            var relativeBytes = System.Text.Encoding.UTF8.GetBytes(file.RelativePath);
            aggregate.AppendData(relativeBytes);
            aggregate.AppendData([0]);
            aggregate.AppendData(file.Sha256);
            aggregate.AppendData([0]);
        }
        return Convert.ToHexStringLower(aggregate.GetHashAndReset());
    }

    internal static bool IsInstallerReceipt(string relativePath) =>
        relativePath is ".ensou-enterprise-launcher.json"
            or ".ensou-enterprise-runtime.json"
            or ".ensou-enterprise-plugin-policy.v2.json"
            or ReceiptFileName;
}
