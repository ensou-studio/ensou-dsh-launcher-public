using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

public static class PersonalReleaseHealthStates
{
    public const string Pending = "pending";
    public const string Healthy = "healthy";
}

internal enum PersonalReleaseHomeTransactionMode
{
    Required,
    NoneRuntimeReused,
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalInstalledComponentReference(
    string Component,
    string ReleaseId,
    string Directory,
    string ArchiveSha256,
    string CompleteTreeSha256);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalInstalledReleaseSetReference(
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    string ManifestSha256,
    PersonalStartupStubCompatibility StartupStub,
    PersonalInstalledComponentReference ClientBundle,
    PersonalInstalledComponentReference Runtime,
    string HealthState,
    string? HealthToken,
    string? HomeTransactionId,
    DateTimeOffset ActivatedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalInstalledReleaseSetPointer(
    int SchemaVersion,
    string Product,
    string Environment,
    string Channel,
    PersonalInstalledReleaseSetReference Current,
    PersonalInstalledReleaseSetReference? Previous,
    DateTimeOffset UpdatedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalReleaseComponentReceipt(
    int SchemaVersion,
    string Component,
    string ReleaseId,
    string ArchiveSha256,
    string CompleteTreeSha256,
    string PrimaryRelativePath,
    string PrimarySha256,
    string? SecondaryRelativePath,
    string? SecondarySha256,
    DateTimeOffset InstalledAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalReleaseHealthSignal(
    int SchemaVersion,
    string ReleaseSetId,
    string RuntimeReleaseId,
    string Token,
    int RuntimeProcessId,
    string CheckSummarySha256,
    string CandidateTreeSha256,
    long CandidateFileCount,
    long CandidateSizeBytes,
    DateTimeOffset RecordedAtUtc);

public sealed class PersonalReleaseSetPointerStore
{
    internal const string ReceiptFileName = ".ensou-personal-component.v1.json";
    internal const string NoHomeTransactionSentinel = "none-runtime-reused-v1";
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
    private readonly PersonalInstallationLayout _layout;

    public PersonalReleaseSetPointerStore(PersonalInstallationLayout layout)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
    }

    public PersonalInstalledReleaseSetPointer? TryRead() =>
        TryRead(CancellationToken.None);

    public PersonalInstalledReleaseSetPointer? TryRead(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!File.Exists(_layout.ReleaseSetPointerPath))
        {
            return null;
        }
        RequireSafeManagedFile(_layout.ReleaseSetPointerPath);
        cancellationToken.ThrowIfCancellationRequested();
        var pointer = JsonSerializer.Deserialize<PersonalInstalledReleaseSetPointer>(
            File.ReadAllBytes(_layout.ReleaseSetPointerPath),
            JsonOptions) ?? throw new InvalidDataException(
                "Personal release-set pointer is empty.");
        Validate(pointer, cancellationToken);
        return pointer;
    }

    public PersonalInstalledReleaseSetPointer ReadRequired() =>
        ReadRequired(CancellationToken.None);

    public PersonalInstalledReleaseSetPointer ReadRequired(
        CancellationToken cancellationToken) =>
        TryRead(cancellationToken) ?? throw new InvalidDataException(
            "Personal release-set is not installed.");

    public PersonalInstalledReleaseSetPointer ActivatePending(
        VerifiedPersonalReleaseSetManifest verified,
        string homeTransactionId)
        => ActivatePending(
            verified,
            homeTransactionId,
            allowSignedLegacyIdentityMigration: false);

    internal PersonalInstalledReleaseSetPointer ActivatePendingFromInstaller(
        VerifiedPersonalReleaseSetManifest verified,
        string homeTransactionId)
        => ActivatePending(
            verified,
            homeTransactionId,
            allowSignedLegacyIdentityMigration: true);

    private PersonalInstalledReleaseSetPointer ActivatePending(
        VerifiedPersonalReleaseSetManifest verified,
        string homeTransactionId,
        bool allowSignedLegacyIdentityMigration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(homeTransactionId);
        if (string.Equals(
                homeTransactionId,
                NoHomeTransactionSentinel,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Harness-home transaction id uses the reserved no-home sentinel.");
        }
        return ActivatePendingCore(
            verified,
            PersonalReleaseHomeTransactionMode.Required,
            homeTransactionId,
            allowSignedLegacyIdentityMigration);
    }

    internal PersonalInstalledReleaseSetPointer ActivatePendingWithoutHomeTransaction(
        VerifiedPersonalReleaseSetManifest verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        if (PersonalReleaseVersion.Compare(
                verified.Manifest.StartupStub.MinimumVersion,
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion) < 0)
        {
            throw new InvalidDataException(
                "Personal no-home activation is not fenced to a compatible Startup Stub.");
        }
        return ActivatePendingCore(
            verified,
            PersonalReleaseHomeTransactionMode.NoneRuntimeReused,
            NoHomeTransactionSentinel,
            allowSignedLegacyIdentityMigration: false);
    }

    private PersonalInstalledReleaseSetPointer ActivatePendingCore(
        VerifiedPersonalReleaseSetManifest verified,
        PersonalReleaseHomeTransactionMode homeTransactionMode,
        string? homeTransactionId,
        bool allowSignedLegacyIdentityMigration)
    {
        ArgumentNullException.ThrowIfNull(verified);
        if (homeTransactionMode == PersonalReleaseHomeTransactionMode.Required
                && (string.IsNullOrWhiteSpace(homeTransactionId)
                    || string.Equals(
                        homeTransactionId,
                        NoHomeTransactionSentinel,
                        StringComparison.Ordinal))
            || homeTransactionMode == PersonalReleaseHomeTransactionMode.NoneRuntimeReused
                && !string.Equals(
                    homeTransactionId,
                    NoHomeTransactionSentinel,
                    StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal release home-transaction mode is invalid.");
        }
        using var writer = AcquireWriter();
        var current = TryRead();
        if (current is not null
            && (current.Current.HealthState != PersonalReleaseHealthStates.Healthy
                || verified.Manifest.Generation < current.Current.Generation
                || verified.Manifest.Sequence <= current.Current.Sequence))
        {
            throw new InvalidDataException(
                "Personal release-set activation raced, rolled back, or is already pending.");
        }

        var manifest = verified.Manifest;
        var mayAdoptLegacyIdentity = allowSignedLegacyIdentityMigration
            && current is not null
            && PersonalReleaseVersion.Compare(
                manifest.StartupStub.MinimumVersion,
                PersonalInstallationIdentityStore.IdentityAwareStartupStubVersion) >= 0;
        _ = new PersonalInstallationIdentityStore(_layout)
            .GetOrCreateForActivation(current, mayAdoptLegacyIdentity);
        var token = PersonalReleaseBase64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var reference = new PersonalInstalledReleaseSetReference(
            manifest.ReleaseSetId,
            manifest.Generation,
            manifest.Sequence,
            manifest.MinAcceptedSequence,
            verified.CanonicalSignedManifestSha256,
            manifest.StartupStub,
            Component(
                manifest.ClientBundle,
                _layout.GetClientBundleDirectory(manifest.ClientBundle.ReleaseId)),
            Component(
                manifest.Runtime,
                _layout.GetRuntimeDirectory(manifest.Runtime.ReleaseId)),
            PersonalReleaseHealthStates.Pending,
            token,
            homeTransactionId,
            DateTimeOffset.UtcNow);
        var pointer = new PersonalInstalledReleaseSetPointer(
            3,
            manifest.Product,
            manifest.Environment,
            manifest.Channel,
            reference,
            current is null
                ? null
                : current.Current with
                {
                    HealthState = PersonalReleaseHealthStates.Healthy,
                    HealthToken = null,
                    HomeTransactionId = null,
                },
            DateTimeOffset.UtcNow);
        Validate(pointer);
        Write(pointer);
        return pointer;
    }

    public PersonalInstalledReleaseSetPointer MarkCurrentHealthy(string healthToken) =>
        MarkCurrentHealthy(healthToken, CancellationToken.None);

    public PersonalInstalledReleaseSetPointer MarkCurrentHealthy(
        string healthToken,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(healthToken);
        cancellationToken.ThrowIfCancellationRequested();
        using var writer = AcquireWriter();
        var pointer = ReadRequired(cancellationToken);
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Pending
            || !string.Equals(pointer.Current.HealthToken, healthToken, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal release health token does not match the pending activation.");
        }
        var healthy = pointer with
        {
            Current = pointer.Current with
            {
                HealthState = PersonalReleaseHealthStates.Healthy,
                HealthToken = null,
                HomeTransactionId = string.Equals(
                    pointer.Current.HomeTransactionId,
                    NoHomeTransactionSentinel,
                    StringComparison.Ordinal)
                    ? NoHomeTransactionSentinel
                    : null,
            },
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        };
        Validate(healthy, cancellationToken);
        Write(healthy);
        return healthy;
    }

    public PersonalInstalledReleaseSetPointer? RollbackPending() =>
        RollbackPending(CancellationToken.None);

    public PersonalInstalledReleaseSetPointer? RollbackPending(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var writer = AcquireWriter();
        var pointer = ReadRequired(cancellationToken);
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Pending)
        {
            throw new InvalidOperationException(
                "Personal release-set has no pending activation to roll back.");
        }
        if (pointer.Previous is null)
        {
            File.Delete(_layout.ReleaseSetPointerPath);
            return null;
        }
        var rollback = pointer with
        {
            Current = pointer.Previous with
            {
                HealthState = PersonalReleaseHealthStates.Healthy,
                HealthToken = null,
                HomeTransactionId = null,
            },
            Previous = null,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        };
        Validate(rollback, cancellationToken);
        Write(rollback);
        return rollback;
    }

    public void Validate(PersonalInstalledReleaseSetPointer pointer) =>
        Validate(pointer, CancellationToken.None);

    public void Validate(
        PersonalInstalledReleaseSetPointer pointer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        cancellationToken.ThrowIfCancellationRequested();
        if (pointer.SchemaVersion != 3
            || !string.Equals(
                pointer.Product,
                PersonalReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(
                pointer.Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || pointer.UpdatedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Personal release-set pointer identity is invalid.");
        }
        PersonalReleaseSetValidator.ValidateChannel(pointer.Channel);
        ValidateReference(
            pointer.Current,
            allowPending: true,
            allowHealthyNoHomeSentinel: true,
            cancellationToken);
        if (pointer.Previous is not null)
        {
            ValidateReference(
                pointer.Previous,
                allowPending: false,
                allowHealthyNoHomeSentinel: false,
                cancellationToken);
        }
        ValidateCurrentHomeTransactionMode(pointer);
    }

    internal static void WriteComponentReceipt(
        string directory,
        PersonalReleaseComponentReceipt receipt,
        string managedRoot)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(receipt, JsonOptions);
        WriteFileAtomically(
            Path.Combine(directory, ReceiptFileName),
            bytes,
            managedRoot);
    }

    private void ValidateReference(
        PersonalInstalledReleaseSetReference reference,
        bool allowPending,
        bool allowHealthyNoHomeSentinel,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        PersonalPathGuard.ValidateReleaseId(reference.ReleaseSetId);
        if (reference.Generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || reference.Sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || reference.MinAcceptedSequence < 0
            || reference.MinAcceptedSequence > reference.Sequence
            || !PersonalReleaseSetValidator.IsSha256(reference.ManifestSha256)
            || reference.StartupStub is null
            || reference.ActivatedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Personal release-set pointer ordering is invalid.");
        }
        PersonalReleaseSetValidator.ValidateStartupStubRange(reference.StartupStub);
        if (reference.HealthState == PersonalReleaseHealthStates.Pending)
        {
            if (!allowPending
                || reference.HealthToken is null
                || PersonalReleaseBase64Url.Decode(reference.HealthToken, "health token").Length != 32
                || string.IsNullOrWhiteSpace(reference.HomeTransactionId))
            {
                throw new InvalidDataException(
                    "Personal pending release health state is invalid.");
            }
        }
        else if (reference.HealthState != PersonalReleaseHealthStates.Healthy
            || reference.HealthToken is not null
            || reference.HomeTransactionId is not null
                && (!allowHealthyNoHomeSentinel
                    || !string.Equals(
                        reference.HomeTransactionId,
                        NoHomeTransactionSentinel,
                        StringComparison.Ordinal)))
        {
            throw new InvalidDataException("Personal release health state is invalid.");
        }

        ValidateComponent(
            reference.ClientBundle,
            PersonalReleaseSetContract.ClientBundleComponent,
            _layout.GetClientBundleDirectory(reference.ClientBundle.ReleaseId),
            PersonalInstallationLayout.ClientBootstrapperExecutableName,
            PersonalInstallationLayout.LauncherExecutableName,
            cancellationToken);
        ValidateComponent(
            reference.Runtime,
            PersonalReleaseSetContract.RuntimeComponent,
            _layout.GetRuntimeDirectory(reference.Runtime.ReleaseId),
            "node.exe",
            "node_modules/@deepseek-ai/dsh/lib/bin.js",
            cancellationToken);
    }

    private static void ValidateCurrentHomeTransactionMode(
        PersonalInstalledReleaseSetPointer pointer)
    {
        var current = pointer.Current;
        if (!string.Equals(
                current.HomeTransactionId,
                NoHomeTransactionSentinel,
                StringComparison.Ordinal))
        {
            return;
        }
        if (pointer.Previous is null
            || !InstalledComponentsMatch(current.Runtime, pointer.Previous.Runtime)
            || PersonalReleaseVersion.Compare(
                current.StartupStub.MinimumVersion,
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion) < 0)
        {
            throw new InvalidDataException(
                "Personal no-home activation requires the exact previous Runtime tuple and compatible Startup Stub.");
        }
    }

    internal static PersonalReleaseHomeTransactionMode GetPendingHomeTransactionMode(
        PersonalInstalledReleaseSetPointer pointer)
    {
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Pending)
        {
            throw new InvalidDataException(
                "Personal home-transaction mode is defined only for a pending release.");
        }
        return pointer.Current.HomeTransactionId is null
            ? throw new InvalidDataException(
                "Personal pending release has no home-transaction identity.")
            : string.Equals(
                pointer.Current.HomeTransactionId,
                NoHomeTransactionSentinel,
                StringComparison.Ordinal)
                ? PersonalReleaseHomeTransactionMode.NoneRuntimeReused
                : PersonalReleaseHomeTransactionMode.Required;
    }

    internal static bool InstalledComponentsMatch(
        PersonalInstalledComponentReference left,
        PersonalInstalledComponentReference right) =>
        string.Equals(left.Component, right.Component, StringComparison.Ordinal)
        && string.Equals(left.ReleaseId, right.ReleaseId, StringComparison.Ordinal)
        && string.Equals(left.Directory, right.Directory, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.ArchiveSha256, right.ArchiveSha256, StringComparison.Ordinal)
        && string.Equals(left.CompleteTreeSha256, right.CompleteTreeSha256, StringComparison.Ordinal);

    private void ValidateComponent(
        PersonalInstalledComponentReference component,
        string expectedComponent,
        string expectedDirectory,
        string primaryRelativePath,
        string secondaryRelativePath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.Equals(component.Component, expectedComponent, StringComparison.Ordinal)
            || !string.Equals(
                PersonalPathGuard.NormalizeDirectory(component.Directory),
                expectedDirectory,
                StringComparison.OrdinalIgnoreCase)
            || !PersonalReleaseSetValidator.IsSha256(component.ArchiveSha256)
            || !PersonalReleaseSetValidator.IsSha256(component.CompleteTreeSha256))
        {
            throw new InvalidDataException(
                "Personal installed component pointer is invalid.");
        }
        PersonalPathGuard.ValidateSafeTree(expectedDirectory, _layout.ManagedRoot);
        var receiptPath = Path.Combine(expectedDirectory, ReceiptFileName);
        RequireSafeManagedFile(receiptPath);
        var receipt = JsonSerializer.Deserialize<PersonalReleaseComponentReceipt>(
            File.ReadAllBytes(receiptPath),
            JsonOptions) ?? throw new InvalidDataException(
                "Personal installed component receipt is empty.");
        if (receipt.SchemaVersion != 1
            || !string.Equals(receipt.Component, expectedComponent, StringComparison.Ordinal)
            || !string.Equals(receipt.ReleaseId, component.ReleaseId, StringComparison.Ordinal)
            || !string.Equals(receipt.ArchiveSha256, component.ArchiveSha256, StringComparison.Ordinal)
            || !string.Equals(
                receipt.CompleteTreeSha256,
                component.CompleteTreeSha256,
                StringComparison.Ordinal)
            || !string.Equals(receipt.PrimaryRelativePath, primaryRelativePath, StringComparison.Ordinal)
            || !string.Equals(receipt.SecondaryRelativePath, secondaryRelativePath, StringComparison.Ordinal)
            || !PersonalReleaseSetValidator.IsSha256(receipt.PrimarySha256)
            || !PersonalReleaseSetValidator.IsSha256(receipt.SecondarySha256 ?? string.Empty))
        {
            throw new InvalidDataException(
                "Personal installed component receipt does not match its pointer.");
        }
        PersonalReleaseArtifactInstaller.VerifyInstalledComponentTree(
            expectedDirectory,
            expectedComponent,
            component.ReleaseId,
            component.CompleteTreeSha256,
            cancellationToken);
        RequireFileHash(
            expectedDirectory,
            primaryRelativePath,
            receipt.PrimarySha256,
            cancellationToken);
        RequireFileHash(
            expectedDirectory,
            secondaryRelativePath,
            receipt.SecondarySha256!,
            cancellationToken);
    }

    private static void RequireFileHash(
        string root,
        string relativePath,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var path = Path.GetFullPath(Path.Combine(root, relativePath));
        if (!PersonalPathGuard.IsStrictDescendant(path, root)
            || !File.Exists(path)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal installed component critical file is missing or unsafe.");
        }
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        var actual = PersonalReleaseArtifactInstaller.ComputeSha256(
            stream,
            cancellationToken);
        if (!string.Equals(actual, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal installed component critical file was modified.");
        }
    }

    private static PersonalInstalledComponentReference Component(
        PersonalReleaseArtifact artifact,
        string directory) => new(
            artifact.Component,
            artifact.ReleaseId,
            directory,
            artifact.Sha256,
            artifact.CompleteTreeSha256);

    private void Write(PersonalInstalledReleaseSetPointer pointer)
    {
        _layout.EnsureManagedRoots();
        WriteFileAtomically(
            _layout.ReleaseSetPointerPath,
            JsonSerializer.SerializeToUtf8Bytes(pointer, JsonOptions),
            _layout.ManagedRoot);
    }

    private void RequireSafeManagedFile(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath)
            || !PersonalPathGuard.IsStrictDescendant(fullPath, _layout.ManagedRoot)
            || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal managed state file is unsafe.");
        }
    }

    internal static void WriteFileAtomically(
        string path,
        ReadOnlySpan<byte> bytes,
        string managedRoot)
    {
        var fullPath = Path.GetFullPath(path);
        var root = PersonalPathGuard.NormalizeDirectory(managedRoot);
        if (!PersonalPathGuard.IsStrictDescendant(fullPath, root))
        {
            throw new InvalidDataException("Personal state write escaped its managed root.");
        }
        var parent = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidDataException("Personal state path has no parent.");
        PersonalPathGuard.EnsureDirectoryChain(root, parent);
        if (File.Exists(fullPath)
            && (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal state destination is a filesystem link.");
        }
        var temporary = Path.Combine(
            parent,
            $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var output = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporary, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private FileStream AcquireWriter()
    {
        _layout.EnsureManagedRoots();
        return new FileStream(
            Path.Combine(_layout.StateRoot, "personal-release-set-writer.lock"),
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
    }
}

internal enum PersonalNoHomeCommitStage
{
    PendingJournalWritten,
    PointerMarkedHealthy,
    SecurityCommitted,
    CommittedReceiptWritten,
}

public sealed class PersonalReleaseHealthCoordinator
{
    private readonly PersonalInstallationLayout _layout;
    private readonly Action<PersonalNoHomeCommitStage>? _noHomeCommitHook;
    private readonly PersonalHarnessHomeLease? _homeLease;

    public PersonalReleaseHealthCoordinator(PersonalInstallationLayout layout)
        : this(layout, noHomeCommitHook: null)
    {
    }

    public PersonalReleaseHealthCoordinator(
        PersonalInstallationLayout layout,
        PersonalHarnessHomeLease homeLease)
        : this(layout, noHomeCommitHook: null)
    {
        _homeLease = homeLease ?? throw new ArgumentNullException(nameof(homeLease));
    }

    internal PersonalReleaseHealthCoordinator(
        PersonalInstallationLayout layout,
        Action<PersonalNoHomeCommitStage>? noHomeCommitHook)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _noHomeCommitHook = noHomeCommitHook;
    }

    public void WriteSignal(
        string healthToken,
        int runtimeProcessId,
        string checkSummarySha256) =>
        WriteSignal(
            healthToken,
            runtimeProcessId,
            checkSummarySha256,
            CancellationToken.None);

    public void WriteSignal(
        string healthToken,
        int runtimeProcessId,
        string checkSummarySha256,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (runtimeProcessId <= 0
            || !PersonalReleaseSetValidator.IsSha256(checkSummarySha256))
        {
            throw new InvalidDataException(
                "Personal health signal runtime identity or check summary is invalid.");
        }
        var pointer = new PersonalReleaseSetPointerStore(_layout)
            .ReadRequired(cancellationToken);
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Pending
            || !string.Equals(pointer.Current.HealthToken, healthToken, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal health signal does not match the active release.");
        }
        var homeMode = PersonalReleaseSetPointerStore
            .GetPendingHomeTransactionMode(pointer);
        using var acquiredHomeLease = AcquireHomeAdmission(homeMode);
        var homeLease = _homeLease ?? acquiredHomeLease;
        if (homeMode == PersonalReleaseHomeTransactionMode.Required)
        {
            homeLease!.RequireCompletedHealthAttempt(
                pointer.Current.HomeTransactionId!, healthToken);
        }
        var evidence = homeMode == PersonalReleaseHomeTransactionMode.NoneRuntimeReused
            ? CreateNoHomeEvidence(pointer)
            : CreateTransactionalHomeEvidence(pointer, homeLease!);
        cancellationToken.ThrowIfCancellationRequested();
        var signal = new PersonalReleaseHealthSignal(
            2,
            pointer.Current.ReleaseSetId,
            pointer.Current.Runtime.ReleaseId,
            healthToken,
            runtimeProcessId,
            checkSummarySha256,
            evidence.TreeSha256,
            evidence.FileCount,
            evidence.SizeBytes,
            DateTimeOffset.UtcNow);
        PersonalReleaseSetPointerStore.WriteFileAtomically(
            GetSignalPath(healthToken),
            JsonSerializer.SerializeToUtf8Bytes(signal),
            _layout.ManagedRoot);
    }

    public PersonalInstalledReleaseSetPointer ConsumeSignalAndMarkHealthy(
        string healthToken) =>
        ConsumeSignalAndMarkHealthy(healthToken, CancellationToken.None);

    public PersonalInstalledReleaseSetPointer ConsumeSignalAndMarkHealthy(
        string healthToken,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var path = GetSignalPath(healthToken);
        if (!File.Exists(path)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal release health signal is missing or linked.");
        }
        var signal = JsonSerializer.Deserialize<PersonalReleaseHealthSignal>(
            File.ReadAllBytes(path)) ?? throw new InvalidDataException(
                "Personal release health signal is empty.");
        cancellationToken.ThrowIfCancellationRequested();
        var store = new PersonalReleaseSetPointerStore(_layout);
        var pointer = store.ReadRequired(cancellationToken);
        var homeMode = PersonalReleaseSetPointerStore
            .GetPendingHomeTransactionMode(pointer);
        using var acquiredHomeLease = AcquireHomeAdmission(homeMode);
        var homeLease = _homeLease ?? acquiredHomeLease;
        if (homeMode == PersonalReleaseHomeTransactionMode.Required)
        {
            homeLease!.RequireCompletedHealthAttempt(
                pointer.Current.HomeTransactionId!, healthToken);
        }
        if (signal.SchemaVersion != 2
            || !string.Equals(signal.Token, healthToken, StringComparison.Ordinal)
            || !string.Equals(
                signal.ReleaseSetId,
                pointer.Current.ReleaseSetId,
                StringComparison.Ordinal)
            || !string.Equals(
                signal.RuntimeReleaseId,
                pointer.Current.Runtime.ReleaseId,
                StringComparison.Ordinal)
            || signal.RuntimeProcessId <= 0
            || !PersonalReleaseSetValidator.IsSha256(signal.CheckSummarySha256)
            || !PersonalReleaseSetValidator.IsSha256(signal.CandidateTreeSha256)
            || signal.CandidateFileCount < 0
            || signal.CandidateSizeBytes < 0
            || signal.RecordedAtUtc < DateTimeOffset.UtcNow.AddMinutes(-5)
            || signal.RecordedAtUtc > DateTimeOffset.UtcNow.AddMinutes(1))
        {
            throw new InvalidDataException("Personal release health signal is invalid.");
        }
        PersonalHarnessHomeTransaction? transaction = null;
        PersonalHarnessHomeRecoveryState? active = null;
        PersonalNoHomeCommitStore? noHomeCommitStore = null;
        PersonalNoHomeCommitReceipt? noHomePrepared = null;
        if (homeMode == PersonalReleaseHomeTransactionMode.NoneRuntimeReused)
        {
            var expected = CreateNoHomeEvidence(pointer);
            if (!string.Equals(
                    expected.TreeSha256,
                    signal.CandidateTreeSha256,
                    StringComparison.Ordinal)
                || expected.FileCount != signal.CandidateFileCount
                || expected.SizeBytes != signal.CandidateSizeBytes)
            {
                throw new InvalidDataException(
                    "Personal no-home health evidence does not match the reused Runtime tuple.");
            }
            noHomeCommitStore = new PersonalNoHomeCommitStore(_layout);
            noHomePrepared = noHomeCommitStore.Prepare(pointer, healthToken);
            _noHomeCommitHook?.Invoke(
                PersonalNoHomeCommitStage.PendingJournalWritten);
        }
        else
        {
            cancellationToken.ThrowIfCancellationRequested();
            transaction = new PersonalHarnessHomeTransaction(
                _layout.HarnessHome,
                _layout.HarnessRecoveryRoot,
                homeLease!);
            active = transaction.TryReadActive()
                ?? throw new InvalidDataException(
                    "Personal pending release has no active Harness-home recovery generation.");
            if (!string.Equals(
                    active.ReleaseSetId,
                    pointer.Current.ReleaseSetId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    active.TransactionId,
                    pointer.Current.HomeTransactionId,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal Harness-home generation does not match the pending release.");
            }
            var candidate = transaction.VerifyCandidateReadable(active.TransactionId);
            cancellationToken.ThrowIfCancellationRequested();
            if (!string.Equals(
                    candidate.TreeSha256,
                    signal.CandidateTreeSha256,
                    StringComparison.Ordinal)
                || candidate.FileCount != signal.CandidateFileCount
                || candidate.SizeBytes != signal.CandidateSizeBytes)
            {
                throw new InvalidDataException(
                    "Personal health signal candidate Harness-home evidence does not match.");
            }
            transaction.MarkHealthPassed(active.TransactionId);
        }
        var healthy = store.MarkCurrentHealthy(healthToken, cancellationToken);
        if (noHomePrepared is not null)
        {
            _noHomeCommitHook?.Invoke(
                PersonalNoHomeCommitStage.PointerMarkedHealthy);
        }
        var security = new PersonalReleaseSecurityStateStore(
            _layout.UpdateSecurityStatePath,
            new PersonalReleaseStateIdentity(
                PersonalReleaseSetContract.Product,
                PersonalReleaseSetContract.ProductionEnvironment,
                healthy.Channel),
            _layout.UpdateSecurityWitnessPath);
        var committedState = security.RecordCommittedReleaseAsync(
                healthy.Current,
                cancellationToken)
            .GetAwaiter()
            .GetResult();
        if (noHomePrepared is not null)
        {
            _noHomeCommitHook?.Invoke(
                PersonalNoHomeCommitStage.SecurityCommitted);
        }
        _ = new PersonalInstallProvenanceStore(_layout, TimeProvider.System)
            .WriteFromSecurityState(committedState);
        if (transaction is not null && active is not null)
        {
            transaction.FinalizeCommit(active.TransactionId);
        }
        if (noHomeCommitStore is not null && noHomePrepared is not null)
        {
            _ = noHomeCommitStore.Commit(noHomePrepared, healthy);
            _noHomeCommitHook?.Invoke(
                PersonalNoHomeCommitStage.CommittedReceiptWritten);
        }
        File.Delete(path);
        return healthy;
    }

    private HomeHealthEvidence CreateTransactionalHomeEvidence(
        PersonalInstalledReleaseSetPointer pointer,
        PersonalHarnessHomeLease homeLease)
    {
        var transaction = new PersonalHarnessHomeTransaction(
            _layout.HarnessHome,
            _layout.HarnessRecoveryRoot,
            homeLease);
        var evidence = transaction.VerifyCandidateReadable(
            pointer.Current.HomeTransactionId
                ?? throw new InvalidDataException(
                    "Personal health signal has no Harness-home transaction."));
        return new HomeHealthEvidence(
            evidence.TreeSha256,
            evidence.FileCount,
            evidence.SizeBytes);
    }

    private PersonalHarnessHomeLease? AcquireHomeAdmission(
        PersonalReleaseHomeTransactionMode homeMode)
    {
        if (homeMode == PersonalReleaseHomeTransactionMode.NoneRuntimeReused)
        {
            return null;
        }
        if (_homeLease is not null)
        {
            _homeLease.RequireMutationAdmission(_layout.HarnessHome);
            return null;
        }
        var lease = new PersonalHarnessHomeCoordinator(_layout.HarnessHome)
            .AcquireLease(() => PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort(
                PersonalInstallMigrationService.DefaultLoopbackPort));
        try
        {
            lease.RequireMutationAdmission(_layout.HarnessHome);
            return lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    private static HomeHealthEvidence CreateNoHomeEvidence(
        PersonalInstalledReleaseSetPointer pointer)
    {
        if (pointer.Previous is null
            || !PersonalReleaseSetPointerStore.InstalledComponentsMatch(
                pointer.Current.Runtime,
                pointer.Previous.Runtime))
        {
            throw new InvalidDataException(
                "Personal no-home health has no exact reused Runtime tuple.");
        }
        var bytes = Encoding.UTF8.GetBytes(string.Join(
            '\n',
            "ensou-personal-no-home-health-evidence-v1",
            pointer.Current.ReleaseSetId,
            pointer.Current.ClientBundle.ReleaseId,
            pointer.Current.ClientBundle.ArchiveSha256,
            pointer.Current.Runtime.ReleaseId,
            pointer.Current.Runtime.ArchiveSha256,
            pointer.Previous.ReleaseSetId));
        try
        {
            return new HomeHealthEvidence(
                Convert.ToHexStringLower(SHA256.HashData(bytes)),
                0,
                0);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private sealed record HomeHealthEvidence(
        string TreeSha256,
        long FileCount,
        long SizeBytes);

    public string GetSignalPath(string healthToken)
    {
        var token = PersonalReleaseBase64Url.Decode(healthToken, "health token");
        if (token.Length != 32)
        {
            throw new InvalidDataException("Personal health token length is invalid.");
        }
        var name = Convert.ToHexStringLower(SHA256.HashData(token));
        return Path.Combine(_layout.HealthSignalRoot, $"{name}.json");
    }
}

public sealed record PersonalHealthProbeResult(bool Healthy, string Detail);

public static class PersonalHealthBudgetV1
{
    public const string OverallDeadlineArgument = "--health-overall-deadline";
    public const string ActiveDeadlineArgument = "--health-active-deadline";

    public static TimeSpan ActiveHealthEnvelope { get; } = TimeSpan.FromSeconds(600);
    public static TimeSpan OverallHealthEnvelope { get; } = TimeSpan.FromSeconds(765);
    public static TimeSpan FailureCleanupTimeout { get; } = TimeSpan.FromSeconds(120);
    public static TimeSpan OutputDrainTimeout { get; } = TimeSpan.FromSeconds(5);

    public static long CreateDeadlineTickCount64(TimeSpan timeout)
    {
        if (timeout < TimeSpan.FromSeconds(1)
            || timeout > OverallHealthEnvelope)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        return checked(
            Environment.TickCount64
            + checked((long)Math.Ceiling(timeout.TotalMilliseconds)));
    }

    public static long ConstrainDeadlineTickCount64(
        long outerDeadlineTickCount64,
        TimeSpan localTimeout)
    {
        _ = GetRemaining(outerDeadlineTickCount64, OverallHealthEnvelope);
        var localDeadline = CreateDeadlineTickCount64(localTimeout);
        return Math.Min(outerDeadlineTickCount64, localDeadline);
    }

    public static long ParseDeadlineTickCount64(
        string value,
        TimeSpan maximumRemaining)
    {
        if (!long.TryParse(
                value,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var deadline))
        {
            throw new ArgumentException("Personal health deadline is invalid.");
        }

        _ = GetRemaining(deadline, maximumRemaining);
        return deadline;
    }

    public static TimeSpan GetRemaining(
        long deadlineTickCount64,
        TimeSpan maximumRemaining)
    {
        if (maximumRemaining < TimeSpan.FromSeconds(1)
            || maximumRemaining > OverallHealthEnvelope)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRemaining));
        }

        var now = Environment.TickCount64;
        if (deadlineTickCount64 <= now)
        {
            throw new TimeoutException("Personal health deadline expired.");
        }
        var remainingMilliseconds = deadlineTickCount64 - now;

        var maximumMilliseconds = checked(
            (long)Math.Ceiling(maximumRemaining.TotalMilliseconds));
        if (remainingMilliseconds > maximumMilliseconds)
        {
            throw new InvalidDataException(
                "Personal health deadline exceeds its compiled maximum.");
        }

        return TimeSpan.FromMilliseconds(remainingMilliseconds);
    }

    public static CancellationTokenSource CreateCancellationUntil(
        long deadlineTickCount64,
        TimeSpan maximumRemaining,
        CancellationToken cancellationToken = default)
    {
        var remaining = GetRemaining(deadlineTickCount64, maximumRemaining);
        var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        source.CancelAfter(remaining);
        return source;
    }
}

public sealed class PersonalBootstrapHealthGate
{
    public static TimeSpan ColdStartTimeout { get; } =
        PersonalHealthBudgetV1.ActiveHealthEnvelope;
    private readonly PersonalInstallationLayout _layout;
    private readonly TimeSpan _timeout;
    private readonly Action<string, Exception?>? _diagnostic;
    private readonly long? _overallDeadlineTickCount64;

    public PersonalBootstrapHealthGate(
        PersonalInstallationLayout layout,
        TimeSpan? timeout = null)
        : this(layout, timeout, diagnostic: null)
    {
    }

    public PersonalBootstrapHealthGate(
        PersonalInstallationLayout layout,
        TimeSpan? timeout,
        Action<string, Exception?>? diagnostic)
        : this(layout, timeout, diagnostic, overallDeadlineTickCount64: null)
    {
    }

    public PersonalBootstrapHealthGate(
        PersonalInstallationLayout layout,
        TimeSpan? timeout,
        Action<string, Exception?>? diagnostic,
        long overallDeadlineTickCount64)
        : this(layout, timeout, diagnostic, (long?)overallDeadlineTickCount64)
    {
    }

    private PersonalBootstrapHealthGate(
        PersonalInstallationLayout layout,
        TimeSpan? timeout,
        Action<string, Exception?>? diagnostic,
        long? overallDeadlineTickCount64)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _timeout = timeout ?? ColdStartTimeout;
        _diagnostic = diagnostic;
        _overallDeadlineTickCount64 = overallDeadlineTickCount64;
        if (_timeout < TimeSpan.FromSeconds(1) || _timeout > ColdStartTimeout)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }
    }

    private void Mark(string phase, Exception? exception = null)
    {
        try { _diagnostic?.Invoke(phase, exception); }
        catch { /* Diagnostic observers cannot change health behavior. */ }
    }

    public async Task<PersonalHealthProbeResult> EnsureHealthyAsync(
        Func<string, string, TimeSpan, CancellationToken, Task<int>> runProbeAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(runProbeAsync);
        return await EnsureHealthyCoreAsync(
                async (path, token, deadline, innerCancellationToken) =>
                    await runProbeAsync(
                            path,
                            token,
                            PersonalHealthBudgetV1.GetRemaining(deadline, _timeout),
                            innerCancellationToken)
                        .ConfigureAwait(false),
                requireActiveInstallerTransaction: false,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<PersonalHealthProbeResult> EnsureHealthyBoundedAsync(
        Func<string, string, long, CancellationToken, Task<int>> runProbeAsync,
        CancellationToken cancellationToken = default) =>
        await EnsureHealthyCoreAsync(
                runProbeAsync,
                requireActiveInstallerTransaction: false,
                cancellationToken)
            .ConfigureAwait(false);

    public async Task<PersonalHealthProbeResult> EnsureInstallerHealthyAsync(
        Func<string, string, TimeSpan, CancellationToken, Task<int>> runProbeAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(runProbeAsync);
        return await EnsureHealthyCoreAsync(
                async (path, token, deadline, innerCancellationToken) =>
                    await runProbeAsync(
                            path,
                            token,
                            PersonalHealthBudgetV1.GetRemaining(deadline, _timeout),
                            innerCancellationToken)
                        .ConfigureAwait(false),
                requireActiveInstallerTransaction: true,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<PersonalHealthProbeResult> EnsureInstallerHealthyBoundedAsync(
        Func<string, string, long, CancellationToken, Task<int>> runProbeAsync,
        CancellationToken cancellationToken = default) =>
        await EnsureHealthyCoreAsync(
                runProbeAsync,
                requireActiveInstallerTransaction: true,
                cancellationToken)
            .ConfigureAwait(false);

    private async Task<PersonalHealthProbeResult> EnsureHealthyCoreAsync(
        Func<string, string, long, CancellationToken, Task<int>> runProbeAsync,
        bool requireActiveInstallerTransaction,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(runProbeAsync);
        var overallDeadline = _overallDeadlineTickCount64
            ?? PersonalHealthBudgetV1.CreateDeadlineTickCount64(
                PersonalHealthBudgetV1.OverallHealthEnvelope);
        using var overallTimeout = PersonalHealthBudgetV1.CreateCancellationUntil(
            overallDeadline,
            PersonalHealthBudgetV1.OverallHealthEnvelope,
            cancellationToken);
        var activeDeadline = PersonalHealthBudgetV1.ConstrainDeadlineTickCount64(
            overallDeadline,
            _timeout);
        using var activeTimeout = PersonalHealthBudgetV1.CreateCancellationUntil(
            activeDeadline,
            _timeout,
            overallTimeout.Token);
        Mark("gate_budget_armed");
        await using var activationLease =
            await PersonalManagedUpdateOperationLease.AcquireRequiredAsync(
                _layout,
                activeTimeout.Token)
            .ConfigureAwait(false);
        var store = new PersonalReleaseSetPointerStore(_layout);
        Mark("gate_pointer_begin");
        var pointer = store.ReadRequired(activeTimeout.Token);
        Mark("gate_pointer_end");
        if (requireActiveInstallerTransaction)
        {
            RequireActiveInstallerTransaction(pointer);
        }
        if (pointer.Current.HealthState == PersonalReleaseHealthStates.Healthy)
        {
            ReconcileHealthyHome(pointer, activeTimeout.Token);
            Mark("gate_healthy_pointer_begin");
            pointer = store.ReadRequired(activeTimeout.Token);
            Mark("gate_healthy_pointer_end");
            Mark("gate_security_begin");
            var decision = await CreateSecurityStore(pointer.Channel)
                .ValidateInstalledPointerAsync(
                    pointer,
                    DateTimeOffset.UtcNow,
                    activeTimeout.Token)
                .ConfigureAwait(false);
            Mark("gate_security_end");
            if (!decision.Allowed)
            {
                throw new InvalidDataException(decision.Reason);
            }
            return new PersonalHealthProbeResult(true, "active personal release is healthy");
        }
        var token = pointer.Current.HealthToken
            ?? throw new InvalidDataException("Pending personal release has no health token.");
        var bootstrapperPath = Path.Combine(
            pointer.Current.ClientBundle.Directory,
            PersonalInstallationLayout.ClientBootstrapperExecutableName);
        try
        {
            Mark("gate_security_begin");
            var decision = await CreateSecurityStore(pointer.Channel)
                .ValidateInstalledPointerAsync(
                    pointer,
                    DateTimeOffset.UtcNow,
                    activeTimeout.Token)
                .ConfigureAwait(false);
            Mark("gate_security_end");
            if (!decision.Allowed)
            {
                throw new InvalidDataException(decision.Reason);
            }
            Mark("gate_probe_begin");
            var exitCode = await runProbeAsync(
                bootstrapperPath,
                token,
                activeDeadline,
                activeTimeout.Token).ConfigureAwait(false);
            Mark("gate_probe_end");
            if (exitCode != 0)
            {
                Mark("gate_probe_nonzero");
                Mark("gate_rollback_begin");
                await RollbackPendingWithinBudgetAsync(
                        store,
                        pointer.Current,
                        "HEALTH_EXIT_NONZERO",
                        overallDeadline)
                    .ConfigureAwait(false);
                Mark("gate_rollback_end");
                return new PersonalHealthProbeResult(false, "candidate health process failed");
            }
            Mark("gate_signal_consume_begin");
            _ = new PersonalReleaseHealthCoordinator(_layout)
                .ConsumeSignalAndMarkHealthy(token, activeTimeout.Token);
            Mark("gate_signal_consume_end");
            return new PersonalHealthProbeResult(true, "personal health nonce was consumed");
        }
        catch (Exception exception) when (exception is OperationCanceledException
            or InvalidDataException
            or IOException
            or UnauthorizedAccessException
            or TimeoutException
            or System.ComponentModel.Win32Exception)
        {
            Mark("gate_exception", exception);
            if (activeTimeout.IsCancellationRequested) Mark("gate_budget_cancelled");
            if (cancellationToken.IsCancellationRequested) Mark("gate_caller_cancelled");
            try
            {
                Mark("gate_rollback_begin");
                await RollbackPendingWithinBudgetAsync(
                    store,
                    pointer.Current,
                    $"HEALTH_{exception.GetType().Name.ToUpperInvariant()}",
                    overallDeadline)
                    .ConfigureAwait(false);
                Mark("gate_rollback_end");
            }
            catch (Exception rollbackException)
            {
                Mark("gate_rollback_exception", rollbackException);
                // Preserve the original failure; the stable entry remains fail closed.
            }
            return new PersonalHealthProbeResult(
                false,
                $"personal health handshake failed ({exception.GetType().Name}: {exception.Message})");
        }
    }

    private void RequireActiveInstallerTransaction(
        PersonalInstalledReleaseSetPointer pointer)
    {
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Pending)
        {
            throw new InvalidDataException(
                "Personal Installer health command only accepts its pending release tuple.");
        }
        var transaction = new PersonalInstallMigrationJournalStore(
                _layout,
                TimeProvider.System)
            .TryRead()
            ?? throw new InvalidDataException(
                "Personal Installer health command has no active durable install transaction.");
        if (transaction.Status != PersonalInstallMigrationJournalState.ActiveStatus
            || transaction.Phase != PersonalInstallMigrationJournalState.AwaitingHealthPhase
            || !string.Equals(
                transaction.ReleaseSetId,
                pointer.Current.ReleaseSetId,
                StringComparison.Ordinal)
            || !string.Equals(
                transaction.ManifestSha256,
                pointer.Current.ManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                transaction.ClientBundleReleaseId,
                pointer.Current.ClientBundle.ReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                transaction.RuntimeReleaseId,
                pointer.Current.Runtime.ReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Installer health command does not match the active pending tuple.");
        }
    }

    private void ReconcileHealthyHome(
        PersonalInstalledReleaseSetPointer pointer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (IsHealthyNoHomeActivation(pointer))
        {
            ReconcileHealthyNoHome(pointer, cancellationToken);
            return;
        }
        var current = pointer.Current;
        var transaction = new PersonalHarnessHomeTransaction(
            _layout.HarnessHome,
            _layout.HarnessRecoveryRoot);
        var active = transaction.TryReadActive();
        if (active is null)
        {
            return;
        }
        using var homeLease = new PersonalHarnessHomeCoordinator(_layout.HarnessHome)
            .AcquireLease(() => PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort(
                PersonalInstallMigrationService.DefaultLoopbackPort));
        homeLease.RequireMutationAdmission(_layout.HarnessHome);
        transaction = new PersonalHarnessHomeTransaction(
            _layout.HarnessHome, _layout.HarnessRecoveryRoot, homeLease);
        active = transaction.TryReadActive();
        if (active is null)
        {
            return;
        }
        if (active.Status is PersonalHarnessHomeTransaction.HealthPassedStatus
                or PersonalHarnessHomeTransaction.CommittedStatus
            && string.Equals(active.ReleaseSetId, current.ReleaseSetId, StringComparison.Ordinal)
            && string.Equals(active.TransactionId, current.HomeTransactionId, StringComparison.Ordinal))
        {
            var refreshed = new PersonalReleaseSetPointerStore(_layout)
                .ReadRequired(cancellationToken);
            var committedState = CreateSecurityStore(refreshed.Channel)
                .RecordCommittedReleaseAsync(current, cancellationToken)
                .GetAwaiter()
                .GetResult();
            _ = new PersonalInstallProvenanceStore(_layout, TimeProvider.System)
                .WriteFromSecurityState(committedState);
            transaction.FinalizeCommit(active.TransactionId);
            return;
        }
        if (active.Status is PersonalHarnessHomeTransaction.PreparingStatus
            or PersonalHarnessHomeTransaction.PreparedStatus)
        {
            _ = transaction.Rollback(
                active.TransactionId,
                "interrupted-before-pointer-commit");
            return;
        }
        throw new InvalidDataException(
            "Healthy personal release has an inconsistent Harness-home transaction.");
    }

    private async Task RollbackPendingWithinBudgetAsync(
        PersonalReleaseSetPointerStore store,
        PersonalInstalledReleaseSetReference failed,
        string reasonCode,
        long overallDeadlineTickCount64)
    {
        var cleanupDeadline = PersonalHealthBudgetV1.ConstrainDeadlineTickCount64(
            overallDeadlineTickCount64,
            PersonalHealthBudgetV1.FailureCleanupTimeout);
        using var cleanupTimeout = PersonalHealthBudgetV1.CreateCancellationUntil(
            cleanupDeadline,
            PersonalHealthBudgetV1.FailureCleanupTimeout);
        await RollbackPendingAsync(
                store,
                failed,
                reasonCode,
                cleanupTimeout.Token)
            .ConfigureAwait(false);
    }

    private void ReconcileHealthyNoHome(
        PersonalInstalledReleaseSetPointer pointer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var commitStore = new PersonalNoHomeCommitStore(_layout);
        var prepared = commitStore.TryReadPending();
        PersonalNoHomeCommitReceipt receipt;
        var security = CreateSecurityStore(pointer.Channel);
        var state = security.TryReadAsync(cancellationToken).GetAwaiter().GetResult()
            ?? throw new InvalidDataException(
                "Personal no-home recovery has no authenticated update state.");
        if (!SecurityStateCommits(state, pointer.Current))
        {
            if (prepared is null)
            {
                throw new InvalidDataException(
                    "Personal no-home activation lost its pending commit journal.");
            }
            commitStore.RequirePreparedMatchesHealthy(prepared, pointer);
            state = security.RecordCommittedReleaseAsync(pointer.Current, cancellationToken)
                .GetAwaiter()
                .GetResult();
        }
        _ = new PersonalInstallProvenanceStore(_layout, TimeProvider.System)
            .WriteFromSecurityState(state);
        if (prepared is not null)
        {
            receipt = commitStore.Commit(prepared, pointer);
        }
        else
        {
            receipt = commitStore.ReadCommittedRequired(pointer);
        }
        File.Delete(commitStore.GetHealthSignalPath(receipt));
    }

    private static bool IsHealthyNoHomeActivation(
        PersonalInstalledReleaseSetPointer pointer) =>
        pointer.Current.HealthState == PersonalReleaseHealthStates.Healthy
        && string.Equals(
            pointer.Current.HomeTransactionId,
            PersonalReleaseSetPointerStore.NoHomeTransactionSentinel,
            StringComparison.Ordinal)
        && pointer.Previous is not null
        && PersonalReleaseSetPointerStore.InstalledComponentsMatch(
            pointer.Current.Runtime,
            pointer.Previous.Runtime)
        && PersonalReleaseVersion.Compare(
            pointer.Current.StartupStub.MinimumVersion,
            PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion) >= 0;

    private static bool SecurityStateCommits(
        PersonalReleaseSecurityState state,
        PersonalInstalledReleaseSetReference current) =>
        string.Equals(
            state.LastCommittedReleaseSetId,
            current.ReleaseSetId,
            StringComparison.Ordinal)
        && state.LastCommittedSequence == current.Sequence
        && string.Equals(
            state.LastCommittedManifestSha256,
            current.ManifestSha256,
            StringComparison.Ordinal);

    private async Task RollbackPendingAsync(
        PersonalReleaseSetPointerStore store,
        PersonalInstalledReleaseSetReference failed,
        string reasonCode,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var latest = store.ReadRequired(cancellationToken);
        if (latest.Current.HealthState != PersonalReleaseHealthStates.Pending
            || !string.Equals(
                latest.Current.ReleaseSetId,
                failed.ReleaseSetId,
                StringComparison.Ordinal)
            || !string.Equals(
                latest.Current.HealthToken,
                failed.HealthToken,
                StringComparison.Ordinal))
        {
            if (latest.Current.HealthState == PersonalReleaseHealthStates.Healthy
                && string.Equals(
                    latest.Current.ReleaseSetId,
                    failed.ReleaseSetId,
                    StringComparison.Ordinal))
            {
                return;
            }
            throw new InvalidDataException(
                "Personal pending release changed before rollback could commit.");
        }
        var homeMode = PersonalReleaseSetPointerStore
            .GetPendingHomeTransactionMode(latest);
        using var homeLease = homeMode == PersonalReleaseHomeTransactionMode.Required
            ? new PersonalHarnessHomeCoordinator(_layout.HarnessHome).AcquireLease(
                () => PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort(
                    PersonalInstallMigrationService.DefaultLoopbackPort))
            : null;
        homeLease?.RequireMutationAdmission(_layout.HarnessHome);
        if (homeMode == PersonalReleaseHomeTransactionMode.Required)
        {
            var transaction = new PersonalHarnessHomeTransaction(
                _layout.HarnessHome,
                _layout.HarnessRecoveryRoot,
                homeLease!);
            var active = transaction.TryReadActive();
            if (active is not null)
            {
                if (!string.Equals(
                        active.ReleaseSetId,
                        failed.ReleaseSetId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        active.TransactionId,
                        failed.HomeTransactionId,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Personal Harness-home recovery does not match the failed release.");
                }
                _ = transaction.Rollback(active.TransactionId, reasonCode);
            }
        }
        else
        {
            var healthToken = latest.Current.HealthToken
                ?? throw new InvalidDataException(
                    "Personal no-home rollback has no health token.");
            var noHomeCommit = new PersonalNoHomeCommitStore(_layout);
            noHomeCommit.AbortPending(latest, healthToken);
            File.Delete(new PersonalReleaseHealthCoordinator(_layout)
                .GetSignalPath(healthToken));
        }
        cancellationToken.ThrowIfCancellationRequested();
        _ = store.RollbackPending(cancellationToken);
        var failedState = await CreateSecurityStore(latest.Channel).RecordFailureAsync(
            failed.ReleaseSetId,
            failed.Generation,
            failed.Sequence,
            failed.ManifestSha256,
            reasonCode,
            DateTimeOffset.UtcNow,
            cancellationToken).ConfigureAwait(false);
        _ = new PersonalInstallProvenanceStore(_layout, TimeProvider.System)
            .WriteFromSecurityState(failedState);
    }

    private PersonalReleaseSecurityStateStore CreateSecurityStore(string channel) => new(
        _layout.UpdateSecurityStatePath,
        new PersonalReleaseStateIdentity(
            PersonalReleaseSetContract.Product,
            PersonalReleaseSetContract.ProductionEnvironment,
            channel),
        _layout.UpdateSecurityWitnessPath);

}

internal static class PersonalReleaseBase64Url
{
    public static string Encode(ReadOnlySpan<byte> value) => Convert.ToBase64String(value)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

    public static byte[] Decode(string value, string field)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Contains('=')
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '_'))
        {
            throw new InvalidDataException($"Personal {field} is not canonical base64url.");
        }
        try
        {
            var decoded = Convert.FromBase64String(
                value.Replace('-', '+').Replace('_', '/')
                + new string('=', (4 - value.Length % 4) % 4));
            if (!string.Equals(Encode(decoded), value, StringComparison.Ordinal))
            {
                CryptographicOperations.ZeroMemory(decoded);
                throw new InvalidDataException(
                    $"Personal {field} is not canonical base64url.");
            }
            return decoded;
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                $"Personal {field} is not valid base64url.",
                exception);
        }
    }
}
