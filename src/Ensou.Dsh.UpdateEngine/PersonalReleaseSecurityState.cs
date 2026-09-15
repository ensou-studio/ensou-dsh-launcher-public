using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

public sealed record PersonalReleaseStateIdentity(
    string Product,
    string Environment,
    string Channel)
{
    public void Validate()
    {
        if (!string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Personal release state product is invalid.");
        }
        PersonalReleaseSetValidator.ValidateToken(Environment, "state environment", 64);
        PersonalReleaseSetValidator.ValidateChannel(Channel);
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalFailedRelease
{
    public required string ReleaseSetId { get; init; }

    public required long Generation { get; init; }

    public required long Sequence { get; init; }

    public required string ReasonCode { get; init; }

    public required DateTimeOffset FailedAtUtc { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalAcceptedComponentIdentity
{
    public required string Component { get; init; }

    public required string ReleaseId { get; init; }

    public required string ArchiveSha256 { get; init; }

    public required string CompleteTreeSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalAcceptedReleaseIdentity
{
    public required string ReleaseSetId { get; init; }

    public required long Generation { get; init; }

    public required long Sequence { get; init; }

    public required string ManifestSha256 { get; init; }

    public required PersonalStartupStubCompatibility StartupStub { get; init; }

    public required PersonalAcceptedComponentIdentity ClientBundle { get; init; }

    public required PersonalAcceptedComponentIdentity Runtime { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalReleaseSecurityState
{
    public required int SchemaVersion { get; init; }

    public required long StateRevision { get; init; }

    public required string StateCommitId { get; init; }

    public required string Product { get; init; }

    public required string Environment { get; init; }

    public required string Channel { get; init; }

    public required long HighestGeneration { get; init; }

    public required long HighestSequence { get; init; }

    public required long MinAcceptedSequence { get; init; }

    public required DateTimeOffset TrustedTimeUtc { get; init; }

    public required string LastVerifiedManifestSha256 { get; init; }

    public required DateTimeOffset LastManifestExpiresAtUtc { get; init; }

    public required long LastManifestMaximumOfflineGraceSeconds { get; init; }

    public required IReadOnlyList<string> RevokedReleaseSetIds { get; init; }

    public required IReadOnlyList<PersonalFailedRelease> FailedReleaseQuarantine { get; init; }

    public required IReadOnlyList<PersonalAcceptedReleaseIdentity> AcceptedReleases { get; init; }

    public string? LastCommittedReleaseSetId { get; init; }

    public long? LastCommittedSequence { get; init; }

    public string? LastCommittedManifestSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalReleaseSecurityAnchor
{
    public required int SchemaVersion { get; init; }

    public required string Product { get; init; }

    public required string Environment { get; init; }

    public required string Channel { get; init; }

    public required long StateRevision { get; init; }

    public required string StateCommitId { get; init; }

    public required string StateSha256 { get; init; }
}

public sealed record PersonalReleaseAdmissionResult(
    VerifiedPersonalReleaseSetManifest Verified,
    PersonalReleaseSecurityState State,
    bool AlreadyAccepted);

public sealed record PersonalInstalledReleaseDecision(
    bool Allowed,
    string Reason,
    DateTimeOffset? OfflineDeadlineUtc);

public sealed class PersonalReleaseActivationAdmission : IAsyncDisposable
{
    private IDisposable? _lease;

    internal PersonalReleaseActivationAdmission(IDisposable lease)
    {
        _lease = lease;
    }

    public ValueTask DisposeAsync()
    {
        Interlocked.Exchange(ref _lease, null)?.Dispose();
        return ValueTask.CompletedTask;
    }
}

internal sealed class PersonalReleaseSecurityStateReadLease : IAsyncDisposable
{
    private IDisposable? _lease;

    public PersonalReleaseSecurityStateReadLease(
        PersonalReleaseSecurityState? state,
        IDisposable lease)
    {
        State = state;
        _lease = lease;
    }

    public PersonalReleaseSecurityState? State { get; }

    public ValueTask DisposeAsync()
    {
        Interlocked.Exchange(ref _lease, null)?.Dispose();
        return ValueTask.CompletedTask;
    }
}

internal interface IPersonalReleaseStateProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> optionalEntropy);

    byte[] Unprotect(ReadOnlySpan<byte> protectedBytes, ReadOnlySpan<byte> optionalEntropy);
}

internal sealed class WindowsDpapiPersonalReleaseStateProtector : IPersonalReleaseStateProtector
{
    public byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> optionalEntropy)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Personal release state protection requires Windows DPAPI.");
        }
        var plaintextBytes = plaintext.ToArray();
        var entropyBytes = optionalEntropy.ToArray();
        try
        {
            return ProtectedData.Protect(
                plaintextBytes,
                entropyBytes,
                DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(entropyBytes);
        }
    }

    public byte[] Unprotect(ReadOnlySpan<byte> protectedBytes, ReadOnlySpan<byte> optionalEntropy)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Personal release state protection requires Windows DPAPI.");
        }
        var ciphertextBytes = protectedBytes.ToArray();
        var entropyBytes = optionalEntropy.ToArray();
        try
        {
            return ProtectedData.Unprotect(
                ciphertextBytes,
                entropyBytes,
                DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertextBytes);
            CryptographicOperations.ZeroMemory(entropyBytes);
        }
    }
}

public sealed class PersonalReleaseSecurityStateStore
{
    private const int SchemaVersion = 5;
    private const int AnchorSchemaVersion = 1;
    private const int MaximumProtectedStateBytes = 2 * 1024 * 1024;
    private const int MaximumQuarantineEntries = 64;
    private const int MaximumAcceptedReleases = 64;
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

    private readonly string _statePath;
    private readonly string _managedRoot;
    private readonly PersonalReleaseStateIdentity _identity;
    private readonly IPersonalReleaseStateProtector _protector;
    private readonly byte[] _entropy;
    private readonly byte[] _anchorEntropy;
    private readonly byte[] _witnessEntropy;
    private readonly string _lockPath;
    private readonly string _anchorPath;
    private readonly string _pendingAnchorPath;
    private readonly string _witnessPath;
    private readonly PersonalV2MigrationFootprintStore _migrationFootprint;

    public PersonalReleaseSecurityStateStore(
        string statePath,
        PersonalReleaseStateIdentity identity,
        string witnessPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(witnessPath);
        _statePath = Path.GetFullPath(statePath);
        _managedRoot = Path.GetDirectoryName(_statePath)
            ?? throw new InvalidDataException("Personal release state path has no parent directory.");
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        _identity.Validate();
        _protector = new WindowsDpapiPersonalReleaseStateProtector();
        _entropy = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{_identity.Product}|{_identity.Environment}|{_identity.Channel}|personal-release-state-v2"));
        _anchorEntropy = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{_identity.Product}|{_identity.Environment}|{_identity.Channel}|personal-release-anchor-v1"));
        _witnessEntropy = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{_identity.Product}|{_identity.Environment}|{_identity.Channel}|personal-release-witness-v1"));
        _lockPath = _statePath + ".lock";
        _anchorPath = _statePath + ".anchor";
        _pendingAnchorPath = _statePath + ".anchor.pending";
        _witnessPath = Path.GetFullPath(witnessPath);
        if (string.Equals(_witnessPath, _statePath, StringComparison.OrdinalIgnoreCase)
            || string.Equals(_witnessPath, _anchorPath, StringComparison.OrdinalIgnoreCase)
            || string.Equals(_witnessPath, _pendingAnchorPath, StringComparison.OrdinalIgnoreCase)
            || PersonalPathGuard.IsSameOrDescendant(_witnessPath, _managedRoot))
        {
            throw new InvalidDataException(
                "Personal release witness must be outside the managed state directory.");
        }
        _migrationFootprint = new PersonalV2MigrationFootprintStore(
            _statePath,
            _witnessPath);
    }

    public async Task<PersonalReleaseSecurityState?> TryReadAsync(
        CancellationToken cancellationToken = default)
    {
        await using var read = await AcquireReadLeaseAsync(cancellationToken)
            .ConfigureAwait(false);
        return read.State;
    }

    internal async Task<PersonalReleaseSecurityState?> TryReadForPreflightAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureManagedPathIsSafe(allowMissingRoot: true);
        if (File.Exists(_pendingAnchorPath) || Directory.Exists(_pendingAnchorPath))
        {
            throw new InvalidDataException(
                "Personal release security state has an incomplete pending write.");
        }

        var stateExists = File.Exists(_statePath);
        var anchorExists = File.Exists(_anchorPath);
        var witnessExists = File.Exists(_witnessPath);
        if (!stateExists && !anchorExists && !witnessExists)
        {
            return null;
        }
        if (!stateExists || !anchorExists || !witnessExists)
        {
            throw new InvalidDataException(
                "Personal release high-water state, rollback anchor, or independent witness is missing.");
        }

        var state = await ReadStateFileAsync(cancellationToken).ConfigureAwait(false);
        var anchor = await ReadAnchorFileAsync(
                _anchorPath,
                _anchorEntropy,
                "rollback anchor",
                cancellationToken)
            .ConfigureAwait(false);
        var witness = await ReadAnchorFileAsync(
                _witnessPath,
                _witnessEntropy,
                "independent witness",
                cancellationToken)
            .ConfigureAwait(false);
        RequireMatchingAnchor(state, anchor);
        RequireMatchingAnchor(state, witness);
        return state;
    }

    internal async Task<PersonalReleaseSecurityStateReadLease> AcquireReadLeaseAsync(
        CancellationToken cancellationToken = default)
    {
        var lease = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var state = await ReadCoreAsync(cancellationToken).ConfigureAwait(false);
            return new PersonalReleaseSecurityStateReadLease(state, lease);
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    public async Task<PersonalReleaseAdmissionResult> VerifyAndAcceptAsync(
        ReadOnlyMemory<byte> signedManifest,
        PersonalReleaseTrustPolicy policy,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ValidateObservedTime(observedNowUtc);
        RequirePolicyIdentity(policy);

        using var lease = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        var previous = await ReadCoreAsync(cancellationToken).ConfigureAwait(false);
        var trustedNow = previous is null || observedNowUtc > previous.TrustedTimeUtc
            ? observedNowUtc
            : previous.TrustedTimeUtc;
        var verified = PersonalReleaseSetValidator.ParseAndVerify(
            signedManifest.Span,
            policy,
            trustedNow);
        var manifest = verified.Manifest;
        var alreadyAccepted = previous is not null
            && string.Equals(
                previous.LastVerifiedManifestSha256,
                verified.CanonicalSignedManifestSha256,
                StringComparison.Ordinal);

        ValidateAdvance(previous, verified);
        _migrationFootprint.EnsureEstablished(verified, trustedNow);
        var next = CreateNextState(previous, verified, trustedNow);
        await WriteCoreAsync(next, cancellationToken).ConfigureAwait(false);
        return new PersonalReleaseAdmissionResult(verified, next, alreadyAccepted);
    }

    internal void RequireValidProvenanceState(PersonalReleaseSecurityState state) =>
        ValidateState(state ?? throw new ArgumentNullException(nameof(state)));

    internal async Task<PersonalReleaseAdmissionResult> RestoreAfterCertifiedUninstallAndAcceptAsync(
        PersonalReleaseSecurityState preservedState,
        ReadOnlyMemory<byte> signedManifest,
        PersonalReleaseTrustPolicy policy,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(preservedState);
        ArgumentNullException.ThrowIfNull(policy);
        ValidateObservedTime(observedNowUtc);
        RequirePolicyIdentity(policy);
        ValidateState(preservedState);
        using var lease = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        EnsureManagedPathIsSafe(allowMissingRoot: true);
        var trustedNow = observedNowUtc > preservedState.TrustedTimeUtc
            ? observedNowUtc
            : preservedState.TrustedTimeUtc;
        var verified = PersonalReleaseSetValidator.ParseAndVerify(
            signedManifest.Span,
            policy,
            trustedNow);
        ValidateAdvance(preservedState, verified);
        if (File.Exists(_pendingAnchorPath)
            || File.Exists(_statePath)
            || File.Exists(_anchorPath))
        {
            var recovered = await ReadCoreAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException(
                    "Certified Personal reinstall security recovery is incomplete.");
            PersonalInstallProvenanceStore.RequireNotBehind(preservedState, recovered);
            if (recovered.HighestGeneration != verified.Manifest.Generation
                || recovered.HighestSequence != verified.Manifest.Sequence
                || !string.Equals(
                    recovered.LastVerifiedManifestSha256,
                    verified.CanonicalSignedManifestSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Certified Personal reinstall found unrelated authenticated state after an interrupted admission.");
            }
            return new PersonalReleaseAdmissionResult(
                verified,
                recovered,
                true);
        }
        if (File.Exists(_witnessPath))
        {
            var witness = await ReadAnchorFileAsync(
                    _witnessPath,
                    _witnessEntropy,
                    "preserved independent witness",
                    cancellationToken)
                .ConfigureAwait(false);
            RequireMatchingAnchor(preservedState, witness);
        }
        _migrationFootprint.EnsureEstablished(preservedState);
        var next = CreateNextState(preservedState, verified, trustedNow);
        await WriteCoreAsync(next, cancellationToken).ConfigureAwait(false);
        return new PersonalReleaseAdmissionResult(
            verified,
            next,
            string.Equals(
                preservedState.LastVerifiedManifestSha256,
                verified.CanonicalSignedManifestSha256,
                StringComparison.Ordinal));
    }

    public async Task<PersonalInstalledReleaseDecision> EvaluateInstalledReleaseAsync(
        string releaseSetId,
        long sequence,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken = default)
    {
        PersonalReleaseSetValidator.ValidateReleaseId(
            releaseSetId,
            "installed releaseSetId");
        if (sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger)
        {
            throw new InvalidDataException("Installed personal release sequence is invalid.");
        }
        ValidateObservedTime(observedNowUtc);
        using var lease = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        var state = await ReadCoreAsync(cancellationToken).ConfigureAwait(false);
        if (state is null)
        {
            return new PersonalInstalledReleaseDecision(
                false,
                "No authenticated personal update security state is installed.",
                null);
        }
        return EvaluateInstalledRelease(state, releaseSetId, sequence, observedNowUtc);
    }

    public Task<PersonalInstalledReleaseDecision> ValidateInstalledPointerAsync(
        PersonalInstalledReleaseSetPointer pointer,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken = default) =>
        ValidateInstalledPointerCoreAsync(
            pointer,
            startupStubVersion: null,
            observedNowUtc,
            cancellationToken);

    public Task<PersonalInstalledReleaseDecision> ValidateInstalledPointerForStartupStubAsync(
        PersonalInstalledReleaseSetPointer pointer,
        string startupStubVersion,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(startupStubVersion);
        return ValidateInstalledPointerCoreAsync(
            pointer,
            startupStubVersion,
            observedNowUtc,
            cancellationToken);
    }

    private async Task<PersonalInstalledReleaseDecision> ValidateInstalledPointerCoreAsync(
        PersonalInstalledReleaseSetPointer pointer,
        string? startupStubVersion,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        ValidateObservedTime(observedNowUtc);
        using var lease = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        var state = await ReadCoreAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "An installed personal release-set has no authenticated update state.");
        RequireAcceptedIdentity(state, pointer.Current);
        if (startupStubVersion is not null)
        {
            PersonalReleaseSetValidator.RequireStartupStubCompatible(
                pointer.Current.StartupStub,
                startupStubVersion);
        }
        if (pointer.Current.HealthState == PersonalReleaseHealthStates.Pending)
        {
            if (pointer.Current.Generation != state.HighestGeneration
                || pointer.Current.Sequence != state.HighestSequence
                || !string.Equals(
                    pointer.Current.ManifestSha256,
                    state.LastVerifiedManifestSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal pending release was superseded before health commit.");
            }
            if (pointer.Previous is null)
            {
                if (state.LastCommittedReleaseSetId is not null)
                {
                    throw new InvalidDataException(
                        "Personal pending release omitted the authenticated last committed release.");
                }
            }
            else
            {
                RequireAcceptedIdentity(state, pointer.Previous);
                RequireLastCommittedIdentity(state, pointer.Previous);
            }
        }
        else
        {
            RequireLastCommittedIdentity(state, pointer.Current);
        }
        return EvaluateInstalledRelease(
            state,
            pointer.Current.ReleaseSetId,
            pointer.Current.Sequence,
            observedNowUtc);
    }

    public async Task<PersonalReleaseActivationAdmission> AcquireActivationAdmissionAsync(
        VerifiedPersonalReleaseSetManifest verified,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verified);
        ValidateObservedTime(observedNowUtc);
        var lease = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var state = await ReadCoreAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException(
                    "Personal release activation requires authenticated update state.");
            var manifest = verified.Manifest;
            if (manifest.Generation != state.HighestGeneration
                || manifest.Sequence != state.HighestSequence
                || !string.Equals(
                    verified.CanonicalSignedManifestSha256,
                    state.LastVerifiedManifestSha256,
                    StringComparison.Ordinal)
                || observedNowUtc > manifest.ExpiresAtUtc
                || state.RevokedReleaseSetIds.Contains(
                    manifest.ReleaseSetId,
                    StringComparer.Ordinal)
                || state.FailedReleaseQuarantine.Any(failure => string.Equals(
                    failure.ReleaseSetId,
                    manifest.ReleaseSetId,
                    StringComparison.Ordinal)))
            {
                throw new InvalidDataException(
                    "Personal release is stale, expired, revoked, quarantined, or no longer the latest admitted candidate.");
            }
            var accepted = FindAcceptedIdentity(state, manifest.ReleaseSetId);
            RequireAcceptedIdentity(accepted, verified);
            return new PersonalReleaseActivationAdmission(lease);
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    public async Task<PersonalReleaseSecurityState> RecordCommittedReleaseAsync(
        PersonalInstalledReleaseSetReference release,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(release);
        using var lease = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        var current = await ReadCoreAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Personal release commit requires authenticated update state.");
        RequireAcceptedIdentity(current, release);
        var decision = EvaluateInstalledRelease(
            current,
            release.ReleaseSetId,
            release.Sequence,
            current.TrustedTimeUtc);
        if (!decision.Allowed)
        {
            throw new InvalidDataException(decision.Reason);
        }
        var next = current with
        {
            StateRevision = checked(current.StateRevision + 1),
            StateCommitId = Guid.NewGuid().ToString("N"),
            LastCommittedReleaseSetId = release.ReleaseSetId,
            LastCommittedSequence = release.Sequence,
            LastCommittedManifestSha256 = release.ManifestSha256,
        };
        ValidateState(next);
        await WriteCoreAsync(next, cancellationToken).ConfigureAwait(false);
        return next;
    }

    private static PersonalInstalledReleaseDecision EvaluateInstalledRelease(
        PersonalReleaseSecurityState state,
        string releaseSetId,
        long sequence,
        DateTimeOffset observedNowUtc)
    {
        if (sequence < state.MinAcceptedSequence)
        {
            return new PersonalInstalledReleaseDecision(
                false,
                "The installed personal release is below the signed minimum sequence.",
                null);
        }
        if (state.RevokedReleaseSetIds.Contains(releaseSetId, StringComparer.Ordinal))
        {
            return new PersonalInstalledReleaseDecision(
                false,
                "The installed personal release was revoked by signed metadata.",
                null);
        }
        if (state.FailedReleaseQuarantine.Any(failure => string.Equals(
            failure.ReleaseSetId,
            releaseSetId,
            StringComparison.Ordinal)))
        {
            return new PersonalInstalledReleaseDecision(
                false,
                "The installed personal release is in failed-health quarantine.",
                null);
        }
        var offlineGrace = TimeSpan.FromSeconds(
            state.LastManifestMaximumOfflineGraceSeconds);
        var metadataDeadline = state.LastManifestExpiresAtUtc + offlineGrace;
        var observationDeadline = state.TrustedTimeUtc + offlineGrace;
        var deadline = metadataDeadline <= observationDeadline
            ? metadataDeadline
            : observationDeadline;
        var effectiveNow = observedNowUtc >= state.TrustedTimeUtc
            ? observedNowUtc
            : state.TrustedTimeUtc;
        if (effectiveNow > deadline)
        {
            return new PersonalInstalledReleaseDecision(
                false,
                "Authenticated personal update metadata exceeded its offline grace.",
                deadline);
        }
        return new PersonalInstalledReleaseDecision(
            true,
            $"Installed personal release is allowed offline until {deadline:O}.",
            deadline);
    }

    public Task<PersonalReleaseSecurityState> RecordFailureAsync(
        VerifiedPersonalReleaseSetManifest verified,
        string reasonCode,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verified);
        return RecordFailureAsync(
            verified.Manifest.ReleaseSetId,
            verified.Manifest.Generation,
            verified.Manifest.Sequence,
            verified.CanonicalSignedManifestSha256,
            reasonCode,
            observedNowUtc,
            cancellationToken);
    }

    public async Task<PersonalReleaseSecurityState> RecordFailureAsync(
        string releaseSetId,
        long generation,
        long sequence,
        string canonicalSignedManifestSha256,
        string reasonCode,
        DateTimeOffset observedNowUtc,
        CancellationToken cancellationToken = default)
    {
        PersonalReleaseSetValidator.ValidateReleaseId(releaseSetId, "failed releaseSetId");
        if (generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || !PersonalReleaseSetValidator.IsSha256(canonicalSignedManifestSha256))
        {
            throw new InvalidDataException("Personal failed release identity is invalid.");
        }
        PersonalReleaseSetValidator.ValidateToken(reasonCode, "failure reason", 64);
        ValidateObservedTime(observedNowUtc);

        using var lease = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        var current = await ReadCoreAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Personal release failure cannot be recorded before the manifest is accepted.");
        var accepted = FindAcceptedIdentity(current, releaseSetId);
        if (generation != accepted.Generation
            || sequence != accepted.Sequence
            || !string.Equals(
                canonicalSignedManifestSha256,
                accepted.ManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal release failure does not match authenticated accepted metadata.");
        }

        var failedAtUtc = current.TrustedTimeUtc;
        var failures = current.FailedReleaseQuarantine
            .Where(failure => !string.Equals(
                failure.ReleaseSetId,
                releaseSetId,
                StringComparison.Ordinal))
            .Append(new PersonalFailedRelease
            {
                ReleaseSetId = releaseSetId,
                Generation = generation,
                Sequence = sequence,
                ReasonCode = reasonCode,
                FailedAtUtc = failedAtUtc,
            })
            .OrderBy(failure => failure.Generation)
            .ThenBy(failure => failure.Sequence)
            .ThenBy(failure => failure.ReleaseSetId, StringComparer.Ordinal)
            .TakeLast(MaximumQuarantineEntries)
            .ToArray();
        var next = current with
        {
            StateRevision = checked(current.StateRevision + 1),
            StateCommitId = Guid.NewGuid().ToString("N"),
            FailedReleaseQuarantine = failures,
        };
        ValidateState(next);
        await WriteCoreAsync(next, cancellationToken).ConfigureAwait(false);
        return next;
    }

    private void ValidateAdvance(
        PersonalReleaseSecurityState? previous,
        VerifiedPersonalReleaseSetManifest verified)
    {
        if (previous is null)
        {
            return;
        }

        var manifest = verified.Manifest;
        if (manifest.Generation < previous.HighestGeneration
            || manifest.Sequence < previous.HighestSequence
            || manifest.MinAcceptedSequence < previous.MinAcceptedSequence)
        {
            throw new InvalidDataException(
                "Personal release-set attempts to reduce a persisted anti-rollback floor.");
        }

        var sameDigest = string.Equals(
            previous.LastVerifiedManifestSha256,
            verified.CanonicalSignedManifestSha256,
            StringComparison.Ordinal);
        if (!sameDigest
            && (manifest.Generation <= previous.HighestGeneration
                || manifest.Sequence <= previous.HighestSequence))
        {
            throw new InvalidDataException(
                "Personal release-set reuses an accepted generation or sequence with different bytes.");
        }

        if (previous.RevokedReleaseSetIds.Except(
                manifest.RevokedReleaseSetIds,
                StringComparer.Ordinal).Any())
        {
            throw new InvalidDataException(
                "Personal release-set attempts to remove a cumulative revocation.");
        }

        if (previous.RevokedReleaseSetIds.Contains(
                manifest.ReleaseSetId,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException("Personal release-set was previously revoked.");
        }

        if (previous.FailedReleaseQuarantine.Any(failure => string.Equals(
                failure.ReleaseSetId,
                manifest.ReleaseSetId,
                StringComparison.Ordinal)))
        {
            throw new InvalidDataException("Personal release-set is in the local failed-release quarantine.");
        }
    }

    private PersonalReleaseSecurityState CreateNextState(
        PersonalReleaseSecurityState? previous,
        VerifiedPersonalReleaseSetManifest verified,
        DateTimeOffset trustedNow)
    {
        var manifest = verified.Manifest;
        var acceptedIdentity = CreateAcceptedIdentity(verified);
        var acceptedCandidates = (previous?.AcceptedReleases
                ?? Array.Empty<PersonalAcceptedReleaseIdentity>())
            .Where(release => !string.Equals(
                release.ReleaseSetId,
                acceptedIdentity.ReleaseSetId,
                StringComparison.Ordinal))
            .Append(acceptedIdentity)
            .OrderBy(release => release.Sequence)
            .ThenBy(release => release.ReleaseSetId, StringComparer.Ordinal)
            .ToArray();
        var committedIdentity = previous?.LastCommittedReleaseSetId is null
            ? null
            : acceptedCandidates.SingleOrDefault(release => string.Equals(
                release.ReleaseSetId,
                previous.LastCommittedReleaseSetId,
                StringComparison.Ordinal));
        PersonalAcceptedReleaseIdentity[] acceptedReleases;
        if (acceptedCandidates.Length <= MaximumAcceptedReleases)
        {
            acceptedReleases = acceptedCandidates;
        }
        else
        {
            var retained = acceptedCandidates
                .Where(release => committedIdentity is null || release != committedIdentity)
                .TakeLast(MaximumAcceptedReleases - (committedIdentity is null ? 0 : 1))
                .ToList();
            if (committedIdentity is not null)
            {
                retained.Add(committedIdentity);
            }
            acceptedReleases = retained
                .OrderBy(release => release.Sequence)
                .ThenBy(release => release.ReleaseSetId, StringComparer.Ordinal)
                .ToArray();
        }
        var nextTrustedTime = manifest.IssuedAtUtc > trustedNow
            ? manifest.IssuedAtUtc
            : trustedNow;
        var state = new PersonalReleaseSecurityState
        {
            SchemaVersion = SchemaVersion,
            StateRevision = checked((previous?.StateRevision ?? 0) + 1),
            StateCommitId = Guid.NewGuid().ToString("N"),
            Product = _identity.Product,
            Environment = _identity.Environment,
            Channel = _identity.Channel,
            HighestGeneration = Math.Max(previous?.HighestGeneration ?? 0, manifest.Generation),
            HighestSequence = Math.Max(previous?.HighestSequence ?? 0, manifest.Sequence),
            MinAcceptedSequence = Math.Max(
                previous?.MinAcceptedSequence ?? 0,
                manifest.MinAcceptedSequence),
            TrustedTimeUtc = nextTrustedTime,
            LastVerifiedManifestSha256 = verified.CanonicalSignedManifestSha256,
            LastManifestExpiresAtUtc = manifest.ExpiresAtUtc,
            LastManifestMaximumOfflineGraceSeconds = manifest.MaximumOfflineGraceSeconds,
            RevokedReleaseSetIds = manifest.RevokedReleaseSetIds.ToArray(),
            FailedReleaseQuarantine = previous?.FailedReleaseQuarantine.ToArray()
                ?? Array.Empty<PersonalFailedRelease>(),
            AcceptedReleases = acceptedReleases,
            LastCommittedReleaseSetId = previous?.LastCommittedReleaseSetId,
            LastCommittedSequence = previous?.LastCommittedSequence,
            LastCommittedManifestSha256 = previous?.LastCommittedManifestSha256,
        };
        ValidateState(state);
        return state;
    }

    private static PersonalAcceptedReleaseIdentity CreateAcceptedIdentity(
        VerifiedPersonalReleaseSetManifest verified) => new()
        {
            ReleaseSetId = verified.Manifest.ReleaseSetId,
            Generation = verified.Manifest.Generation,
            Sequence = verified.Manifest.Sequence,
            ManifestSha256 = verified.CanonicalSignedManifestSha256,
            StartupStub = verified.Manifest.StartupStub,
            ClientBundle = CreateAcceptedComponent(verified.Manifest.ClientBundle),
            Runtime = CreateAcceptedComponent(verified.Manifest.Runtime),
        };

    private static PersonalAcceptedComponentIdentity CreateAcceptedComponent(
        PersonalReleaseArtifact artifact) => new()
        {
            Component = artifact.Component,
            ReleaseId = artifact.ReleaseId,
            ArchiveSha256 = artifact.Sha256,
            CompleteTreeSha256 = artifact.CompleteTreeSha256,
        };

    private static PersonalAcceptedReleaseIdentity FindAcceptedIdentity(
        PersonalReleaseSecurityState state,
        string releaseSetId) => state.AcceptedReleases.SingleOrDefault(release =>
            string.Equals(release.ReleaseSetId, releaseSetId, StringComparison.Ordinal))
        ?? throw new InvalidDataException(
            "Personal installed release is not bound to authenticated signed metadata.");

    private static void RequireAcceptedIdentity(
        PersonalReleaseSecurityState state,
        PersonalInstalledReleaseSetReference release) => RequireAcceptedIdentity(
            FindAcceptedIdentity(state, release.ReleaseSetId),
            release);

    private static void RequireAcceptedIdentity(
        PersonalAcceptedReleaseIdentity accepted,
        PersonalInstalledReleaseSetReference release)
    {
        if (accepted.Generation != release.Generation
            || accepted.Sequence != release.Sequence
            || !string.Equals(
                accepted.ManifestSha256,
                release.ManifestSha256,
                StringComparison.Ordinal)
            || !StartupStubMatches(accepted.StartupStub, release.StartupStub)
            || !ComponentMatches(accepted.ClientBundle, release.ClientBundle)
            || !ComponentMatches(accepted.Runtime, release.Runtime))
        {
            throw new InvalidDataException(
                "Personal installed release tuple differs from authenticated signed metadata.");
        }
    }

    private static void RequireAcceptedIdentity(
        PersonalAcceptedReleaseIdentity accepted,
        VerifiedPersonalReleaseSetManifest verified)
    {
        var expected = CreateAcceptedIdentity(verified);
        if (accepted != expected)
        {
            throw new InvalidDataException(
                "Personal activation candidate differs from authenticated signed metadata.");
        }
    }

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

    private static bool StartupStubMatches(
        PersonalStartupStubCompatibility accepted,
        PersonalStartupStubCompatibility installed) =>
        accepted is not null
        && installed is not null
        && string.Equals(
            accepted.MinimumVersion,
            installed.MinimumVersion,
            StringComparison.Ordinal)
        && string.Equals(
            accepted.MaximumVersion,
            installed.MaximumVersion,
            StringComparison.Ordinal);

    private static void RequireLastCommittedIdentity(
        PersonalReleaseSecurityState state,
        PersonalInstalledReleaseSetReference release)
    {
        if (!string.Equals(
                state.LastCommittedReleaseSetId,
                release.ReleaseSetId,
                StringComparison.Ordinal)
            || state.LastCommittedSequence != release.Sequence
            || !string.Equals(
                state.LastCommittedManifestSha256,
                release.ManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal active pointer differs from the authenticated last committed release.");
        }
    }

    private async Task<PersonalReleaseSecurityState?> ReadCoreAsync(
        CancellationToken cancellationToken)
    {
        EnsureManagedPathIsSafe(allowMissingRoot: true);
        if (File.Exists(_pendingAnchorPath))
        {
            await RecoverPendingWriteAsync(cancellationToken).ConfigureAwait(false);
        }

        var stateExists = File.Exists(_statePath);
        var anchorExists = File.Exists(_anchorPath);
        var witnessExists = File.Exists(_witnessPath);
        if (!stateExists && !anchorExists && !witnessExists)
        {
            if (_migrationFootprint.TryRead() is not null)
            {
                throw new InvalidDataException(
                    "An authenticated personal v2 migration footprint exists but its update security state is missing.");
            }
            return null;
        }
        if (!stateExists || !anchorExists || !witnessExists)
        {
            throw new InvalidDataException(
                "Personal release high-water state, rollback anchor, or independent witness is missing.");
        }

        var state = await ReadStateFileAsync(cancellationToken).ConfigureAwait(false);
        var anchor = await ReadAnchorFileAsync(
                _anchorPath,
                _anchorEntropy,
                "rollback anchor",
                cancellationToken)
            .ConfigureAwait(false);
        var witness = await ReadAnchorFileAsync(
                _witnessPath,
                _witnessEntropy,
                "independent witness",
                cancellationToken)
            .ConfigureAwait(false);
        RequireMatchingAnchor(state, anchor);
        RequireMatchingAnchor(state, witness);
        _migrationFootprint.EnsureEstablished(state);
        return state;
    }

    private async Task RecoverPendingWriteAsync(CancellationToken cancellationToken)
    {
        var pending = await ReadAnchorFileAsync(
                _pendingAnchorPath,
                _anchorEntropy,
                "pending rollback anchor",
                cancellationToken)
            .ConfigureAwait(false);
        var state = File.Exists(_statePath)
            ? await ReadStateFileAsync(cancellationToken).ConfigureAwait(false)
            : null;
        var anchor = File.Exists(_anchorPath)
            ? await ReadAnchorFileAsync(
                _anchorPath,
                _anchorEntropy,
                "rollback anchor",
                cancellationToken).ConfigureAwait(false)
            : null;
        var witness = File.Exists(_witnessPath)
            ? await ReadAnchorFileAsync(
                _witnessPath,
                _witnessEntropy,
                "independent witness",
                cancellationToken).ConfigureAwait(false)
            : null;

        if (state is null && anchor is null && witness is null)
        {
            File.Delete(_pendingAnchorPath);
            return;
        }

        if (state is not null && AnchorMatchesState(pending, state))
        {
            if ((anchor is not null && anchor.StateRevision > pending.StateRevision)
                || (witness is not null && witness.StateRevision > pending.StateRevision))
            {
                throw new InvalidDataException(
                    "Personal release pending write is older than its rollback anchor.");
            }
            var pendingBytes = await File.ReadAllBytesAsync(_pendingAnchorPath, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                await WriteFileAtomicallyAsync(
                    _anchorPath,
                    pendingBytes,
                    cancellationToken).ConfigureAwait(false);
                var pendingPlaintext = JsonSerializer.SerializeToUtf8Bytes(pending, JsonOptions);
                byte[]? protectedWitness = null;
                try
                {
                    protectedWitness = _protector.Protect(
                        pendingPlaintext,
                        _witnessEntropy);
                    await WriteIndependentFileAtomicallyAsync(
                        _witnessPath,
                        protectedWitness,
                        cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pendingPlaintext);
                    if (protectedWitness is not null)
                    {
                        CryptographicOperations.ZeroMemory(protectedWitness);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pendingBytes);
            }
            File.Delete(_pendingAnchorPath);
            return;
        }

        if (state is not null
            && anchor is not null
            && AnchorMatchesState(anchor, state)
            && witness is not null
            && AnchorMatchesState(witness, state)
            && state.StateRevision < pending.StateRevision)
        {
            File.Delete(_pendingAnchorPath);
            return;
        }

        throw new InvalidDataException(
            "Personal release pending high-water transaction is inconsistent.");
    }

    private async Task<PersonalReleaseSecurityState> ReadStateFileAsync(
        CancellationToken cancellationToken)
    {
        var plaintext = await ReadProtectedFileAsync(
            _statePath,
            _entropy,
            "state",
            cancellationToken).ConfigureAwait(false);
        try
        {
            var state = JsonSerializer.Deserialize<PersonalReleaseSecurityState>(plaintext, JsonOptions)
                ?? throw new InvalidDataException("Personal release state is empty.");
            ValidateState(state);
            return state;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Personal release state JSON is invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private async Task<PersonalReleaseSecurityAnchor> ReadAnchorFileAsync(
        string path,
        byte[] entropy,
        string field,
        CancellationToken cancellationToken)
    {
        var plaintext = await ReadProtectedFileAsync(
            path,
            entropy,
            field,
            cancellationToken).ConfigureAwait(false);
        try
        {
            var anchor = JsonSerializer.Deserialize<PersonalReleaseSecurityAnchor>(plaintext, JsonOptions)
                ?? throw new InvalidDataException("Personal release rollback anchor is empty.");
            ValidateAnchor(anchor);
            return anchor;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Personal release rollback anchor JSON is invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private async Task<byte[]> ReadProtectedFileAsync(
        string path,
        byte[] entropy,
        string field,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(path);
        if (file.Length is <= 0 or > MaximumProtectedStateBytes)
        {
            throw new InvalidDataException($"Protected personal release {field} size is invalid.");
        }

        var protectedBytes = await File.ReadAllBytesAsync(path, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var plaintext = _protector.Unprotect(protectedBytes, entropy);
            if (plaintext.Length is <= 0 or > MaximumProtectedStateBytes)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new InvalidDataException(
                    $"Personal release {field} plaintext size is invalid.");
            }
            return plaintext;
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                $"Protected personal release {field} could not be authenticated for this Windows user.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private async Task WriteCoreAsync(
        PersonalReleaseSecurityState state,
        CancellationToken cancellationToken)
    {
        ValidateState(state);
        Directory.CreateDirectory(_managedRoot);
        EnsureManagedPathIsSafe(allowMissingRoot: false);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
        var anchor = CreateAnchor(state, plaintext);
        var anchorPlaintext = JsonSerializer.SerializeToUtf8Bytes(anchor, JsonOptions);
        byte[]? protectedState = null;
        byte[]? protectedAnchor = null;
        byte[]? protectedWitness = null;
        try
        {
            protectedState = _protector.Protect(plaintext, _entropy);
            protectedAnchor = _protector.Protect(anchorPlaintext, _anchorEntropy);
            protectedWitness = _protector.Protect(anchorPlaintext, _witnessEntropy);
            if (protectedState.Length is <= 0 or > MaximumProtectedStateBytes
                || protectedAnchor.Length is <= 0 or > MaximumProtectedStateBytes
                || protectedWitness.Length is <= 0 or > MaximumProtectedStateBytes)
            {
                throw new InvalidDataException(
                    "Protected personal release state or rollback anchor size is invalid.");
            }

            await WriteFileAtomicallyAsync(
                _pendingAnchorPath,
                protectedAnchor,
                cancellationToken).ConfigureAwait(false);
            await WriteFileAtomicallyAsync(
                _statePath,
                protectedState,
                cancellationToken).ConfigureAwait(false);
            await WriteFileAtomicallyAsync(
                _anchorPath,
                protectedAnchor,
                cancellationToken).ConfigureAwait(false);
            await WriteIndependentFileAtomicallyAsync(
                _witnessPath,
                protectedWitness,
                cancellationToken).ConfigureAwait(false);
            File.Delete(_pendingAnchorPath);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(anchorPlaintext);
            if (protectedState is not null)
            {
                CryptographicOperations.ZeroMemory(protectedState);
            }
            if (protectedAnchor is not null)
            {
                CryptographicOperations.ZeroMemory(protectedAnchor);
            }
            if (protectedWitness is not null)
            {
                CryptographicOperations.ZeroMemory(protectedWitness);
            }
        }
    }

    private async Task WriteFileAtomicallyAsync(
        string destinationPath,
        ReadOnlyMemory<byte> contents,
        CancellationToken cancellationToken)
    {
        var temporaryPath = Path.Combine(
            _managedRoot,
            $".{Path.GetFileName(destinationPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var output = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await output.WriteAsync(contents, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, destinationPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static async Task WriteIndependentFileAtomicallyAsync(
        string destinationPath,
        ReadOnlyMemory<byte> contents,
        CancellationToken cancellationToken)
    {
        var parent = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidDataException(
                "Personal release independent witness has no parent directory.");
        PersonalPathGuard.EnsureIndependentDirectory(parent);
        if (File.Exists(destinationPath)
            && (File.GetAttributes(destinationPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal release independent witness is a filesystem link.");
        }
        var temporaryPath = Path.Combine(
            parent,
            $".{Path.GetFileName(destinationPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var output = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await output.WriteAsync(contents, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, destinationPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private void ValidateState(PersonalReleaseSecurityState state)
    {
        if (state.SchemaVersion != SchemaVersion
            || state.StateRevision is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || !IsCommitId(state.StateCommitId)
            || !string.Equals(state.Product, _identity.Product, StringComparison.Ordinal)
            || !string.Equals(state.Environment, _identity.Environment, StringComparison.Ordinal)
            || !string.Equals(state.Channel, _identity.Channel, StringComparison.Ordinal)
            || state.HighestGeneration is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || state.HighestSequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || state.MinAcceptedSequence < 0
            || state.MinAcceptedSequence > state.HighestSequence
            || state.TrustedTimeUtc.Offset != TimeSpan.Zero
            || state.TrustedTimeUtc <= DateTimeOffset.UnixEpoch
            || state.LastManifestExpiresAtUtc.Offset != TimeSpan.Zero
            || state.LastManifestExpiresAtUtc <= DateTimeOffset.UnixEpoch
            || state.LastManifestMaximumOfflineGraceSeconds
                is < 3_600 or > 1_209_600
            || !PersonalReleaseSetValidator.IsSha256(state.LastVerifiedManifestSha256)
            || state.RevokedReleaseSetIds is null
            || state.FailedReleaseQuarantine is null
            || state.AcceptedReleases is null)
        {
            throw new InvalidDataException("Personal release security state is invalid.");
        }

        if (state.RevokedReleaseSetIds.Count > 1_000
            || state.RevokedReleaseSetIds.Distinct(StringComparer.Ordinal).Count()
                != state.RevokedReleaseSetIds.Count
            || !state.RevokedReleaseSetIds.SequenceEqual(
                state.RevokedReleaseSetIds.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException("Personal release state revocations are invalid.");
        }
        foreach (var revoked in state.RevokedReleaseSetIds)
        {
            PersonalReleaseSetValidator.ValidateReleaseId(revoked, "persisted revocation");
        }

        if (state.FailedReleaseQuarantine.Count > MaximumQuarantineEntries
            || state.FailedReleaseQuarantine.Select(failure => failure.ReleaseSetId)
                .Distinct(StringComparer.Ordinal).Count() != state.FailedReleaseQuarantine.Count)
        {
            throw new InvalidDataException("Personal release failed-release quarantine is invalid.");
        }
        foreach (var failure in state.FailedReleaseQuarantine)
        {
            PersonalReleaseSetValidator.ValidateReleaseId(failure.ReleaseSetId, "quarantine releaseSetId");
            PersonalReleaseSetValidator.ValidateToken(failure.ReasonCode, "quarantine reason", 64);
            if (failure.Generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
                || failure.Sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
                || failure.Generation > state.HighestGeneration
                || failure.Sequence > state.HighestSequence
                || failure.FailedAtUtc.Offset != TimeSpan.Zero
                || failure.FailedAtUtc <= DateTimeOffset.UnixEpoch)
            {
                throw new InvalidDataException("Personal release quarantine entry is invalid.");
            }
        }

        if (state.AcceptedReleases.Count is <= 0 or > MaximumAcceptedReleases
            || state.AcceptedReleases.Select(release => release.ReleaseSetId)
                .Distinct(StringComparer.Ordinal).Count() != state.AcceptedReleases.Count
            || state.AcceptedReleases.Select(release => release.Sequence)
                .Distinct().Count() != state.AcceptedReleases.Count
            || !state.AcceptedReleases.SequenceEqual(
                state.AcceptedReleases
                    .OrderBy(release => release.Sequence)
                    .ThenBy(release => release.ReleaseSetId, StringComparer.Ordinal)))
        {
            throw new InvalidDataException(
                "Personal accepted-release trust receipts are invalid.");
        }
        foreach (var accepted in state.AcceptedReleases)
        {
            ValidateAcceptedIdentity(accepted, state);
        }
        if (!state.AcceptedReleases.Any(release =>
                release.Generation == state.HighestGeneration
                && release.Sequence == state.HighestSequence
                && string.Equals(
                    release.ManifestSha256,
                    state.LastVerifiedManifestSha256,
                    StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Personal latest manifest is not represented by an authenticated trust receipt.");
        }

        var hasCommitted = state.LastCommittedReleaseSetId is not null
            || state.LastCommittedSequence is not null
            || state.LastCommittedManifestSha256 is not null;
        if (hasCommitted
            && (state.LastCommittedReleaseSetId is null
                || state.LastCommittedSequence is null
                || state.LastCommittedManifestSha256 is null
                || !state.AcceptedReleases.Any(release =>
                    string.Equals(
                        release.ReleaseSetId,
                        state.LastCommittedReleaseSetId,
                        StringComparison.Ordinal)
                    && release.Sequence == state.LastCommittedSequence
                    && string.Equals(
                        release.ManifestSha256,
                        state.LastCommittedManifestSha256,
                        StringComparison.Ordinal))))
        {
            throw new InvalidDataException(
                "Personal last committed release is not bound to accepted signed metadata.");
        }
    }

    private static void ValidateAcceptedIdentity(
        PersonalAcceptedReleaseIdentity accepted,
        PersonalReleaseSecurityState state)
    {
        PersonalReleaseSetValidator.ValidateReleaseId(
            accepted.ReleaseSetId,
            "accepted releaseSetId");
        if (accepted.Generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || accepted.Sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || accepted.Generation > state.HighestGeneration
            || accepted.Sequence > state.HighestSequence
            || !PersonalReleaseSetValidator.IsSha256(accepted.ManifestSha256)
            || accepted.StartupStub is null)
        {
            throw new InvalidDataException(
                "Personal accepted release ordering or digest is invalid.");
        }
        PersonalReleaseSetValidator.ValidateStartupStubRange(accepted.StartupStub);
        ValidateAcceptedComponent(
            accepted.ClientBundle,
            PersonalReleaseSetContract.ClientBundleComponent);
        ValidateAcceptedComponent(
            accepted.Runtime,
            PersonalReleaseSetContract.RuntimeComponent);
    }

    private static void ValidateAcceptedComponent(
        PersonalAcceptedComponentIdentity component,
        string expectedComponent)
    {
        if (!string.Equals(component.Component, expectedComponent, StringComparison.Ordinal)
            || !PersonalReleaseSetValidator.IsSha256(component.ArchiveSha256)
            || !PersonalReleaseSetValidator.IsSha256(component.CompleteTreeSha256))
        {
            throw new InvalidDataException(
                "Personal accepted component identity is invalid.");
        }
        PersonalReleaseSetValidator.ValidateReleaseId(
            component.ReleaseId,
            "accepted component releaseId");
    }

    private PersonalReleaseSecurityAnchor CreateAnchor(
        PersonalReleaseSecurityState state,
        ReadOnlySpan<byte> plaintext)
    {
        var anchor = new PersonalReleaseSecurityAnchor
        {
            SchemaVersion = AnchorSchemaVersion,
            Product = _identity.Product,
            Environment = _identity.Environment,
            Channel = _identity.Channel,
            StateRevision = state.StateRevision,
            StateCommitId = state.StateCommitId,
            StateSha256 = Convert.ToHexStringLower(SHA256.HashData(plaintext)),
        };
        ValidateAnchor(anchor);
        return anchor;
    }

    private void ValidateAnchor(PersonalReleaseSecurityAnchor anchor)
    {
        if (anchor.SchemaVersion != AnchorSchemaVersion
            || !string.Equals(anchor.Product, _identity.Product, StringComparison.Ordinal)
            || !string.Equals(anchor.Environment, _identity.Environment, StringComparison.Ordinal)
            || !string.Equals(anchor.Channel, _identity.Channel, StringComparison.Ordinal)
            || anchor.StateRevision is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || !IsCommitId(anchor.StateCommitId)
            || !PersonalReleaseSetValidator.IsSha256(anchor.StateSha256))
        {
            throw new InvalidDataException("Personal release rollback anchor is invalid.");
        }
    }

    private static bool AnchorMatchesState(
        PersonalReleaseSecurityAnchor anchor,
        PersonalReleaseSecurityState state)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
        try
        {
            return anchor.StateRevision == state.StateRevision
                && string.Equals(anchor.StateCommitId, state.StateCommitId, StringComparison.Ordinal)
                && string.Equals(
                    anchor.StateSha256,
                    Convert.ToHexStringLower(SHA256.HashData(plaintext)),
                    StringComparison.Ordinal);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static void RequireMatchingAnchor(
        PersonalReleaseSecurityState state,
        PersonalReleaseSecurityAnchor anchor)
    {
        if (!AnchorMatchesState(anchor, state))
        {
            throw new InvalidDataException(
                "Personal release high-water state was rolled back or differs from its anchor.");
        }
    }

    private static bool IsCommitId(string? value) => value is { Length: 32 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private void RequirePolicyIdentity(PersonalReleaseTrustPolicy policy)
    {
        if (!string.Equals(policy.Product, _identity.Product, StringComparison.Ordinal)
            || !string.Equals(policy.Environment, _identity.Environment, StringComparison.Ordinal)
            || !string.Equals(policy.Channel, _identity.Channel, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Personal release policy does not match the state identity.");
        }
    }

    private void EnsureManagedPathIsSafe(bool allowMissingRoot)
    {
        var root = new DirectoryInfo(_managedRoot);
        if (!root.Exists)
        {
            if (allowMissingRoot)
            {
                return;
            }
            throw new DirectoryNotFoundException("Personal release state root does not exist.");
        }
        if ((root.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal release state root must not be a filesystem link.");
        }
        if (File.Exists(_statePath)
            && (File.GetAttributes(_statePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal release state file must not be a filesystem link.");
        }
        foreach (var managedPath in new[] { _anchorPath, _pendingAnchorPath })
        {
            if (File.Exists(managedPath)
                && (File.GetAttributes(managedPath) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal release rollback anchor must not be a filesystem link.");
            }
        }
        var witnessParent = Path.GetDirectoryName(_witnessPath)
            ?? throw new InvalidDataException(
                "Personal release independent witness has no parent directory.");
        if (Directory.Exists(witnessParent))
        {
            for (var current = new DirectoryInfo(witnessParent);
                 current is not null;
                 current = current.Parent)
            {
                if (current.Exists
                    && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "Personal release independent witness path crosses a filesystem link.");
                }
            }
        }
        if (File.Exists(_witnessPath)
            && (File.GetAttributes(_witnessPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal release independent witness must not be a filesystem link.");
        }
    }

    private async Task<FileStream> AcquireLockAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_managedRoot);
        EnsureManagedPathIsSafe(allowMissingRoot: false);
        if (File.Exists(_lockPath)
            && (File.GetAttributes(_lockPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal release state lock must not be a filesystem link.");
        }

        var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (true)
        {
            try
            {
                return new FileStream(
                    _lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.WriteThrough);
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (IOException exception)
            {
                throw new TimeoutException(
                    "Timed out waiting for the personal release state writer.",
                    exception);
            }
        }
    }

    private static void ValidateObservedTime(DateTimeOffset observedNowUtc)
    {
        if (observedNowUtc.Offset != TimeSpan.Zero || observedNowUtc <= DateTimeOffset.UnixEpoch)
        {
            throw new InvalidDataException("Observed personal release time must be valid UTC.");
        }
    }

}
