using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

public interface IPersonalInstallerPayloadSource
{
    Stream OpenSignedReleaseManifest();

    Stream OpenStartupStub();

    Stream OpenClientBundleArchive();

    Stream OpenRuntimeArchive();
}

public sealed class PersonalEmbeddedInstallerPayloadSource : IPersonalInstallerPayloadSource
{
    public const string ResourcePrefix = "Ensou.Dsh.Personal.Installer.Payload.";
    public const string ManifestResourceName = ResourcePrefix + "release-set.v2.json";
    public const string StartupStubResourceName =
        ResourcePrefix + PersonalInstallationLayout.StartupStubExecutableName;
    public const string ClientBundleResourceName = ResourcePrefix + "client-bundle.zip";
    public const string RuntimeResourceName = ResourcePrefix + "runtime.zip";

    private static readonly string[] ExpectedResources =
    [
        ManifestResourceName,
        StartupStubResourceName,
        ClientBundleResourceName,
        RuntimeResourceName,
    ];

    private readonly Assembly _assembly;

    public PersonalEmbeddedInstallerPayloadSource(Assembly assembly)
    {
        _assembly = assembly ?? throw new ArgumentNullException(nameof(assembly));
        var actual = assembly.GetManifestResourceNames()
            .Where(name => name.StartsWith(ResourcePrefix, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!actual.SequenceEqual(ExpectedResources.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Installer must contain exactly one strict release manifest, Startup Stub, client bundle, and Runtime archive.");
        }
    }

    public Stream OpenSignedReleaseManifest() => Open(ManifestResourceName);

    public Stream OpenStartupStub() => Open(StartupStubResourceName);

    public Stream OpenClientBundleArchive() => Open(ClientBundleResourceName);

    public Stream OpenRuntimeArchive() => Open(RuntimeResourceName);

    private Stream Open(string name) => _assembly.GetManifestResourceStream(name)
        ?? throw new InvalidDataException($"Personal Installer payload resource is missing: {name}");
}

public sealed record PersonalInstallerTrustConfiguration(
    bool ProductionBuild,
    Uri ManifestOrigin,
    PersonalReleaseTrustPolicy ReleasePolicy,
    string? AuthenticodeSignerSha256Thumbprint)
{
    public static PersonalInstallerTrustConfiguration ReadCompiled(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        var metadata = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToDictionary(attribute => attribute.Key, attribute => attribute.Value, StringComparer.Ordinal);
        var productionValue = Require(metadata, "PersonalProductionBuild");
        if (!bool.TryParse(productionValue, out var production))
        {
            throw new InvalidDataException(
                "Personal Installer production-build metadata must be exactly true or false.");
        }

        var manifestOrigin = RequireCanonicalHttpsOrigin(
            Require(metadata, "PersonalManifestOrigin"),
            "manifest");
        var artifactOrigin = RequireCanonicalHttpsOrigin(
            Require(metadata, "PersonalArtifactOrigin"),
            "artifact");
        var policy = new PersonalReleaseTrustPolicy
        {
            Product = PersonalReleaseSetContract.Product,
            Environment = PersonalReleaseSetContract.ProductionEnvironment,
            Channel = Require(metadata, "PersonalChannel"),
            ArtifactOrigin = artifactOrigin,
            StartupStubVersion = Require(metadata, "PersonalStartupStubVersion"),
            CanonicalLowSFromSequence = RequirePositiveSafeInteger(
                metadata,
                "PersonalCanonicalLowSFromSequence"),
            TrustedKeys =
            [
                new PersonalReleasePublicKey(
                    Require(metadata, "PersonalReleaseKeyId"),
                    Require(metadata, "PersonalReleaseKeyX"),
                    Require(metadata, "PersonalReleaseKeyY")),
            ],
        };
        policy.Validate();
        string? signer = metadata.TryGetValue(
            "PersonalAuthenticodeSignerSha256Thumbprint",
            out var signerValue)
            && !string.IsNullOrWhiteSpace(signerValue)
                ? PersonalAuthenticodeVerifier.RequireSha256Thumbprint(signerValue)
                : null;
        if (production && signer is null)
        {
            throw new InvalidOperationException(
                "Production Personal Installer has no compiled Authenticode signer identity.");
        }
        return new PersonalInstallerTrustConfiguration(
            production,
            manifestOrigin,
            policy,
            signer);
    }

    private static string Require(
        IReadOnlyDictionary<string, string?> metadata,
        string key) => metadata.TryGetValue(key, out var value)
            && !string.IsNullOrWhiteSpace(value)
                ? value
                : throw new InvalidOperationException(
                    $"Personal Installer metadata '{key}' is not compiled into this build.");

    private static long RequirePositiveSafeInteger(
        IReadOnlyDictionary<string, string?> metadata,
        string key)
    {
        var value = Require(metadata, key);
        if (!long.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var parsed)
            || parsed is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger)
        {
            throw new InvalidOperationException(
                $"Personal Installer metadata '{key}' is not a positive safe integer.");
        }
        return parsed;
    }

    private static Uri RequireCanonicalHttpsOrigin(string value, string label)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.Equals(uri.AbsolutePath, "/", StringComparison.Ordinal)
            || !uri.OriginalString.All(character =>
                char.IsAscii(character) && character > ' ' && character is not '"' and not '\\'))
        {
            throw new InvalidDataException(
                $"Personal Installer {label} origin must be one canonical HTTPS origin.");
        }
        return uri;
    }
}

public sealed record PersonalInstallPreparationResult(
    string ReleaseSetId,
    string ManifestSha256,
    string StartupStubPath,
    string? LegacyQuarantinePath,
    bool LegacySettingsRequireReconfiguration,
    bool RequiresHealthValidation,
    bool AlreadyCompleted);

public sealed record PersonalInstallCompletionResult(
    string ReleaseSetId,
    string ManifestSha256,
    string StartupStubPath,
    string? LegacyQuarantinePath,
    bool LegacySettingsRequireReconfiguration);

internal enum PersonalInstallMigrationCheckpoint
{
    JournalCreated,
    PayloadStaged,
    LegacyAuthorizedBeforeMove,
    LegacyMovedBeforeJournal,
    LegacyQuarantined,
    SecurityAdmitted,
    ComponentsInstalled,
    StartupStubInstalled,
    PointerActivated,
    RegistrationInstalled,
    AwaitingHealth,
    Completed,
    HealthFailureMarked,
    FailedPointerRolledBack,
    FailureProvenanceWritten,
    FailedRootQuarantined,
    FailureRegistrationRestored,
    FailureJournalRetired,
}

public sealed class PersonalInstallMigrationService
{
    public const int DefaultLoopbackPort = 3080;

    private readonly PersonalInstallationLayout _layout;
    private readonly TimeProvider _timeProvider;
    private readonly Action _processGuard;
    private readonly Action<int> _harnessWriterGuard;
    private readonly Action<int> _legacyEnrollmentGuard;
    private readonly Func<string, PersonalWindowsRegistrationSnapshot> _registerShell;
    private readonly Action _removeShell;
    private readonly Action<PersonalInstallMigrationCheckpoint>? _checkpoint;

    public PersonalInstallMigrationService(PersonalInstallationLayout layout)
        : this(
            layout,
            TimeProvider.System,
            PersonalInstallerProcessGuard.RequireNoManagedClientProcesses,
            PersonalHarnessWriterGuard.RequireAvailableLoopbackPort,
            displayVersion => PersonalWindowsRegistration.Install(layout, displayVersion),
            () => PersonalWindowsRegistration.Remove(layout),
            null,
            PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort)
    {
    }

    public static PersonalInstallMigrationService CreateDevelopmentE2EWithoutShellRegistration(
        PersonalInstallationLayout layout,
        PersonalDevelopmentE2EInstallOptions options)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(options);
        options.RequireExactLayout(layout);
        return new PersonalInstallMigrationService(
            layout,
            TimeProvider.System,
            PersonalInstallerProcessGuard.RequireNoManagedClientProcesses,
            PersonalHarnessWriterGuard.RequireAvailableLoopbackPort,
            static _ => new PersonalWindowsRegistrationSnapshot(
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty),
            static () => { },
            null,
            PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort);
    }

    internal PersonalInstallMigrationService(
        PersonalInstallationLayout layout,
        TimeProvider timeProvider,
        Action processGuard,
        Action<int> harnessWriterGuard,
        Func<string, PersonalWindowsRegistrationSnapshot> registerShell,
        Action removeShell,
        Action<PersonalInstallMigrationCheckpoint>? checkpoint,
        Action<int>? legacyEnrollmentGuard = null)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _processGuard = processGuard ?? throw new ArgumentNullException(nameof(processGuard));
        _harnessWriterGuard = harnessWriterGuard
            ?? throw new ArgumentNullException(nameof(harnessWriterGuard));
        _legacyEnrollmentGuard = legacyEnrollmentGuard ?? harnessWriterGuard;
        _registerShell = registerShell ?? throw new ArgumentNullException(nameof(registerShell));
        _removeShell = removeShell ?? throw new ArgumentNullException(nameof(removeShell));
        _checkpoint = checkpoint;
    }

    public async Task<PersonalInstallPreparationResult> PrepareAsync(
        IPersonalInstallerPayloadSource payload,
        PersonalInstallerTrustConfiguration trust,
        PersonalInstallerExecutableLease installerExecutableLease,
        int loopbackPort = DefaultLoopbackPort,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(installerExecutableLease);
        using var retainedInstallerIdentity = installerExecutableLease.Retain();
        return await PrepareCoreAsync(
                payload,
                trust,
                loopbackPort,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal Task<PersonalInstallPreparationResult> PrepareForTestsAsync(
        IPersonalInstallerPayloadSource payload,
        PersonalInstallerTrustConfiguration trust,
        int loopbackPort = DefaultLoopbackPort,
        CancellationToken cancellationToken = default) => PrepareCoreAsync(
            payload,
            trust,
            loopbackPort,
            cancellationToken);

    private async Task<PersonalInstallPreparationResult> PrepareCoreAsync(
        IPersonalInstallerPayloadSource payload,
        PersonalInstallerTrustConfiguration trust,
        int loopbackPort,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(trust);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Personal installation and migration require Windows DPAPI and shell registration.");
        }
        if (loopbackPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(loopbackPort));
        }

        var manifestBytes = await ReadBoundedAsync(
            payload.OpenSignedReleaseManifest(),
            2 * 1024 * 1024,
            cancellationToken).ConfigureAwait(false);
        var observedNow = RequireUtc(_timeProvider.GetUtcNow());
        var rawManifestSha256 = Sha256(manifestBytes);

        await using var operationLease =
            await PersonalManagedUpdateOperationLease.AcquireRequiredAsync(
                _layout,
                cancellationToken).ConfigureAwait(false);
        _processGuard();
        var journal = new PersonalInstallMigrationJournalStore(_layout, _timeProvider);
        var provenanceStore = new PersonalInstallProvenanceStore(_layout, _timeProvider);
        var state = journal.TryRead();
        if (state is not null
            && state.Status == PersonalInstallMigrationJournalState.CompletedStatus)
        {
            await CertifyAndRetireJournalAsync(
                    journal,
                    provenanceStore,
                    state,
                    cancellationToken)
                .ConfigureAwait(false);
            state = null;
        }
        if (state is not null
            && state.Status == PersonalInstallMigrationJournalState.ActiveStatus
            && state.Phase == PersonalInstallMigrationJournalState.AwaitingHealthPhase
            && await HasDurableHealthFailureAsync(state, cancellationToken)
                .ConfigureAwait(false))
        {
            state = journal.MarkHealthFailed(state);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.HealthFailureMarked);
        }
        if (state is not null
            && state.Status == PersonalInstallMigrationJournalState.FailedStatus)
        {
            await FinalizeFailedTransactionAsync(journal, state, cancellationToken)
                .ConfigureAwait(false);
            state = null;
        }

        var provenance = provenanceStore.TryReadAndRepair();
        var footprint = new PersonalV2MigrationFootprintStore(
                _layout.UpdateSecurityStatePath,
                _layout.UpdateSecurityWitnessPath,
                _layout.V2MigrationFootprintPath)
            .TryRead();
        if (state is null)
        {
            RequireDurableInstallBoundary(provenance, footprint);
        }

        var effectiveNow = provenance is null
            ? observedNow
            : observedNow >= provenance.SecurityState.TrustedTimeUtc
                ? observedNow
                : provenance.SecurityState.TrustedTimeUtc;
        if (state is not null
            && PersonalInstallMigrationJournalState.PhaseIndex(state.Phase)
                >= PersonalInstallMigrationJournalState.PhaseIndex(
                    PersonalInstallMigrationJournalState.SecurityAdmittedPhase))
        {
            var admittedState = await CreateSecurityStore(state.Channel)
                .TryReadAsync(cancellationToken)
                .ConfigureAwait(false);
            if (admittedState is not null && admittedState.TrustedTimeUtc > effectiveNow)
            {
                effectiveNow = admittedState.TrustedTimeUtc;
            }
        }
        var verified = PersonalReleaseSetValidator.ParseAndVerify(
            manifestBytes,
            trust.ReleasePolicy,
            effectiveNow);

        // Reject unsupported execution paths before creating a new migration journal or payload.
        PersonalExecutablePathBudget.RequireInstallerCandidate(_layout, verified.Manifest, trust.ProductionBuild);

        if (state is null)
        {
            PersonalLegacyTreeIdentity? legacy = null;
            PersonalFileIdentity? previousStartupStub = null;
            string installMode;
            if (provenance is null)
            {
                EnsureQuarantineContainerIsEmptyOrAbsent();
                if (Directory.Exists(_layout.ManagedRoot))
                {
                    legacy = MeasureExactLegacyV1Footprint(_layout.ManagedRoot);
                    installMode = PersonalInstallMigrationJournalState.LegacyV1MigrationMode;
                }
                else if (File.Exists(_layout.ManagedRoot))
                {
                    throw new InvalidDataException(
                        "Personal managed root is unexpectedly a file.");
                }
                else
                {
                    installMode = PersonalInstallMigrationJournalState.CleanInstallMode;
                }
            }
            else
            {
                _ = provenanceStore.RequireCandidateAdvance(
                    provenance,
                    verified,
                    observedNow);
                if (Directory.Exists(_layout.ManagedRoot))
                {
                    var current = await ValidateExistingV2Async(
                            provenanceStore,
                            provenance,
                            trust.ReleasePolicy.StartupStubVersion,
                            cancellationToken)
                        .ConfigureAwait(false);
                    previousStartupStub = TryComputeSafeFileIdentity(
                        _layout.StartupStubPath);
                    installMode = string.Equals(
                            current.Current.ManifestSha256,
                            verified.CanonicalSignedManifestSha256,
                            StringComparison.Ordinal)
                        ? PersonalInstallMigrationJournalState.ExistingV2RepairMode
                        : PersonalInstallMigrationJournalState.ExistingV2UpgradeMode;
                }
                else if (File.Exists(_layout.ManagedRoot))
                {
                    throw new InvalidDataException(
                        "Personal managed root is unexpectedly a file.");
                }
                else
                {
                    installMode = PersonalInstallMigrationJournalState.CertifiedReinstallMode;
                }
            }
            var transactionId = Guid.NewGuid().ToString("N");
            var quarantinePath = legacy is null
                ? null
                : GetLegacyQuarantinePath(transactionId);
            if (quarantinePath is not null)
            {
                EnsureQuarantineContainerIsEmptyOrAbsent();
            }
            state = PersonalInstallMigrationJournalState.Create(
                _layout,
                transactionId,
                verified,
                rawManifestSha256,
                trust.ReleasePolicy.StartupStubVersion,
                installMode,
                previousStartupStub,
                quarantinePath,
                legacy,
                observedNow);
            journal.Write(state);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.JournalCreated);
        }
        RequirePayloadMatches(state, verified, rawManifestSha256, trust);

        if (state.Phase == PersonalInstallMigrationJournalState.AwaitingHealthPhase)
        {
            var installedPointer = await ValidateInstalledAsync(
                    state,
                    requireHealthy: false,
                    cancellationToken)
                .ConfigureAwait(false);
            _ = _registerShell(state.ReleaseSetId);
            if (installedPointer.Current.HealthState == PersonalReleaseHealthStates.Healthy)
            {
                state = await CertifyAndRetireJournalAsync(
                        journal,
                        provenanceStore,
                        state,
                        cancellationToken)
                    .ConfigureAwait(false);
                return Result(state, requiresHealth: false, alreadyCompleted: true);
            }
            return Result(state, requiresHealth: true, alreadyCompleted: false);
        }

        var staged = await StageAndVerifyPayloadAsync(
                payload,
                trust,
                verified,
                manifestBytes,
                rawManifestSha256,
                state,
                cancellationToken)
            .ConfigureAwait(false);
        if (state.Phase == PersonalInstallMigrationJournalState.CreatedPhase)
        {
            state = journal.RecordStagedPayload(state, staged.StartupStubSha256, staged.StartupStubSizeBytes);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.PayloadStaged);
        }
        else
        {
            RequireStagedStubMatches(state, staged);
        }

        state = EnsureLegacyQuarantined(journal, state);
        _layout.EnsureManagedRoots();
        RequireManagedRootOwnedByTransaction(state);

        var security = CreateSecurityStore(state.Channel);
        PersonalReleaseAdmissionResult admission;
        if (state.InstallMode == PersonalInstallMigrationJournalState.CertifiedReinstallMode
            && PersonalInstallMigrationJournalState.IsBefore(
                state.Phase,
                PersonalInstallMigrationJournalState.SecurityAdmittedPhase))
        {
            provenance ??= provenanceStore.TryReadAndRepair()
                ?? throw new InvalidDataException(
                    "Certified Personal reinstall lost both complete provenance witnesses.");
            admission = await security.RestoreAfterCertifiedUninstallAndAcceptAsync(
                    provenance.SecurityState,
                    manifestBytes,
                    trust.ReleasePolicy,
                    effectiveNow,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            admission = await security.VerifyAndAcceptAsync(
                    manifestBytes,
                    trust.ReleasePolicy,
                    effectiveNow,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        if (!string.Equals(
                admission.Verified.CanonicalSignedManifestSha256,
                state.ManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Installer security admission changed the embedded manifest identity.");
        }
        if (PersonalInstallMigrationJournalState.IsBefore(
                state.Phase,
                PersonalInstallMigrationJournalState.SecurityAdmittedPhase))
        {
            state = journal.Advance(
                state,
                PersonalInstallMigrationJournalState.SecurityAdmittedPhase);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.SecurityAdmitted);
        }

        var artifactInstaller = new PersonalReleaseArtifactInstaller();
        await artifactInstaller.InstallComponentAsync(
                _layout,
                verified.Manifest.ClientBundle,
                staged.ClientBundleArchivePath,
                _layout.GetClientBundleDirectory(verified.Manifest.ClientBundle.ReleaseId),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        await artifactInstaller.InstallComponentAsync(
                _layout,
                verified.Manifest.Runtime,
                staged.RuntimeArchivePath,
                _layout.GetRuntimeDirectory(verified.Manifest.Runtime.ReleaseId),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (PersonalInstallMigrationJournalState.IsBefore(
                state.Phase,
                PersonalInstallMigrationJournalState.ComponentsInstalledPhase))
        {
            state = journal.Advance(
                state,
                PersonalInstallMigrationJournalState.ComponentsInstalledPhase);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.ComponentsInstalled);
        }

        InstallStableStartupStub(staged, state);
        if (PersonalInstallMigrationJournalState.IsBefore(
                state.Phase,
                PersonalInstallMigrationJournalState.StartupStubInstalledPhase))
        {
            state = journal.Advance(
                state,
                PersonalInstallMigrationJournalState.StartupStubInstalledPhase);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.StartupStubInstalled);
        }

        var pointerStore = new PersonalReleaseSetPointerStore(_layout);
        var pointer = pointerStore.TryRead();
        if (pointer is null
            || !string.Equals(
                pointer.Current.ManifestSha256,
                state.ManifestSha256,
                StringComparison.Ordinal))
        {
            if (pointer?.Current.HealthState == PersonalReleaseHealthStates.Pending)
            {
                throw new InvalidDataException(
                    "Personal Installer cannot supersede an unrelated pending release.");
            }
            using var homeLease = new PersonalHarnessHomeCoordinator(_layout.HarnessHome)
                .AcquireLease(() => _legacyEnrollmentGuard(loopbackPort));
            homeLease.RequireMutationAdmission(_layout.HarnessHome);
            _harnessWriterGuard(loopbackPort);
            var home = new PersonalHarnessHomeTransaction(
                _layout.HarnessHome,
                _layout.HarnessRecoveryRoot,
                _timeProvider,
                null,
                _harnessWriterGuard,
                homeLease);
            var prepared = home.Prepare(verified.Manifest.ReleaseSetId, loopbackPort);
            await using var activationAdmission = await security
                .AcquireActivationAdmissionAsync(
                    verified,
                    effectiveNow,
                    cancellationToken)
                .ConfigureAwait(false);
            pointer = pointerStore.ActivatePendingFromInstaller(
                verified,
                prepared.TransactionId);
        }
        RequirePointerMatches(state, pointer);
        if (PersonalInstallMigrationJournalState.IsBefore(
                state.Phase,
                PersonalInstallMigrationJournalState.PointerActivatedPhase))
        {
            state = journal.Advance(
                state,
                PersonalInstallMigrationJournalState.PointerActivatedPhase);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.PointerActivated);
        }

        _ = _registerShell(state.ReleaseSetId);
        if (PersonalInstallMigrationJournalState.IsBefore(
                state.Phase,
                PersonalInstallMigrationJournalState.RegistrationInstalledPhase))
        {
            state = journal.Advance(
                state,
                PersonalInstallMigrationJournalState.RegistrationInstalledPhase);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.RegistrationInstalled);
        }
        if (PersonalInstallMigrationJournalState.IsBefore(
                state.Phase,
                PersonalInstallMigrationJournalState.AwaitingHealthPhase))
        {
            state = journal.Advance(
                state,
                PersonalInstallMigrationJournalState.AwaitingHealthPhase);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.AwaitingHealth);
        }
        if (pointer.Current.HealthState == PersonalReleaseHealthStates.Healthy)
        {
            state = await CertifyAndRetireJournalAsync(
                    journal,
                    provenanceStore,
                    state,
                    cancellationToken)
                .ConfigureAwait(false);
            return Result(state, requiresHealth: false, alreadyCompleted: true);
        }
        return Result(
            state,
            requiresHealth: pointer.Current.HealthState == PersonalReleaseHealthStates.Pending,
            alreadyCompleted: false);
    }

    public async Task<PersonalInstallCompletionResult> CompleteAfterHealthAsync(
        string releaseSetId,
        string manifestSha256,
        CancellationToken cancellationToken = default)
    {
        PersonalReleaseSetValidator.ValidateReleaseId(releaseSetId, "installed releaseSetId");
        if (!PersonalReleaseSetValidator.IsSha256(manifestSha256))
        {
            throw new InvalidDataException("Personal Installer completion manifest digest is invalid.");
        }
        await using var operationLease =
            await PersonalManagedUpdateOperationLease.AcquireRequiredAsync(
                _layout,
                cancellationToken).ConfigureAwait(false);
        var journal = new PersonalInstallMigrationJournalStore(_layout, _timeProvider);
        var state = journal.TryRead()
            ?? throw new InvalidDataException(
                "Personal Installer completion journal is missing.");
        if (!string.Equals(state.ReleaseSetId, releaseSetId, StringComparison.Ordinal)
            || !string.Equals(state.ManifestSha256, manifestSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Installer completion does not match its durable transaction.");
        }
        if (state.Status != PersonalInstallMigrationJournalState.CompletedStatus
            && state.Phase != PersonalInstallMigrationJournalState.AwaitingHealthPhase)
        {
            throw new InvalidDataException(
                "Personal Installer transaction has not reached its health boundary.");
        }
        state = await CertifyAndRetireJournalAsync(
                journal,
                new PersonalInstallProvenanceStore(_layout, _timeProvider),
                state,
                cancellationToken)
            .ConfigureAwait(false);
        return new PersonalInstallCompletionResult(
            state.ReleaseSetId,
            state.ManifestSha256,
            _layout.StartupStubPath,
            state.LegacyQuarantinePath,
            state.LegacyQuarantinePath is not null);
    }

    public async Task RollbackStableStubAfterFailureAsync(
        bool abandonPendingCandidate = false,
        CancellationToken cancellationToken = default)
    {
        await using var operationLease =
            await PersonalManagedUpdateOperationLease.AcquireRequiredAsync(
                _layout,
                cancellationToken).ConfigureAwait(false);
        var journal = new PersonalInstallMigrationJournalStore(_layout, _timeProvider);
        var state = journal.TryRead();
        if (state is null)
        {
            return;
        }
        if (abandonPendingCandidate
            && state.Status == PersonalInstallMigrationJournalState.ActiveStatus
            && state.Phase == PersonalInstallMigrationJournalState.AwaitingHealthPhase)
        {
            var pointer = new PersonalReleaseSetPointerStore(_layout).TryRead();
            if (pointer is not null
                && pointer.Current.HealthState == PersonalReleaseHealthStates.Healthy
                && PointerMatches(state, pointer.Current))
            {
                _ = await CertifyAndRetireJournalAsync(
                        journal,
                        new PersonalInstallProvenanceStore(_layout, _timeProvider),
                        state,
                        cancellationToken)
                    .ConfigureAwait(false);
                return;
            }
            state = journal.MarkHealthFailed(state);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.HealthFailureMarked);
        }
        if (state.Status == PersonalInstallMigrationJournalState.FailedStatus)
        {
            await FinalizeFailedTransactionAsync(journal, state, cancellationToken)
                .ConfigureAwait(false);
            return;
        }
        RestoreStableStubUnderLease(state);
    }

    private void RestoreStableStubUnderLease(
        PersonalInstallMigrationJournalState state)
    {
        if (PersonalInstallMigrationJournalState.IsBefore(
                state.Phase,
                PersonalInstallMigrationJournalState.StartupStubInstalledPhase))
        {
            return;
        }
        var current = TryComputeSafeFileIdentity(_layout.StartupStubPath);
        var installed = state.StartupStubSha256 is not null
            && state.StartupStubSizeBytes is not null
            ? new PersonalFileIdentity(
                state.StartupStubSha256,
                state.StartupStubSizeBytes.Value)
            : null;
        if (state.PreviousStartupStubSha256 is null)
        {
            if (current is null)
            {
                return;
            }
            if (installed is null || current != installed)
            {
                throw new InvalidDataException(
                    "Personal Installer cannot safely roll back an unexpected Startup Stub.");
            }
            File.Delete(_layout.StartupStubPath);
            return;
        }

        var previous = new PersonalFileIdentity(
            state.PreviousStartupStubSha256,
            state.PreviousStartupStubSizeBytes!.Value);
        if (current == previous)
        {
            if (state.StartupStubBackupPath is not null
                && File.Exists(state.StartupStubBackupPath))
            {
                RequireFileIdentity(
                    state.StartupStubBackupPath,
                    previous.SizeBytes,
                    previous.Sha256);
                File.Delete(state.StartupStubBackupPath);
            }
            return;
        }
        var backup = state.StartupStubBackupPath
            ?? throw new InvalidDataException(
                "Personal Installer rollback has no previous Startup Stub backup path.");
        RequireFileIdentity(backup, previous.SizeBytes, previous.Sha256);
        if (current is null)
        {
            File.Move(backup, _layout.StartupStubPath);
        }
        else
        {
            if (installed is null || current != installed)
            {
                throw new InvalidDataException(
                    "Personal Installer cannot replace an unexpected Startup Stub during rollback.");
            }
            File.Replace(backup, _layout.StartupStubPath, null, ignoreMetadataErrors: true);
        }
        RequireFileIdentity(
            _layout.StartupStubPath,
            previous.SizeBytes,
            previous.Sha256);
    }

    private async Task FinalizeFailedTransactionAsync(
        PersonalInstallMigrationJournalStore journal,
        PersonalInstallMigrationJournalState state,
        CancellationToken cancellationToken)
    {
        if (state.Status != PersonalInstallMigrationJournalState.FailedStatus)
        {
            throw new InvalidOperationException(
                "Personal Installer failure finalization requires a durable failed marker.");
        }
        using var homeLease = new PersonalHarnessHomeCoordinator(_layout.HarnessHome)
            .AcquireLease(() => _legacyEnrollmentGuard(DefaultLoopbackPort));
        homeLease.RequireMutationAdmission(_layout.HarnessHome);
        var pointerStore = new PersonalReleaseSetPointerStore(_layout);
        var pointer = pointerStore.TryRead();
        var security = CreateSecurityStore(state.Channel);
        PersonalReleaseSecurityState securityState;
        if (pointer is not null
            && pointer.Current.HealthState == PersonalReleaseHealthStates.Pending
            && PointerMatches(state, pointer.Current))
        {
            var home = new PersonalHarnessHomeTransaction(
                _layout.HarnessHome,
                _layout.HarnessRecoveryRoot,
                homeLease,
                _timeProvider);
            var activeHome = home.TryReadActive();
            if (activeHome is not null)
            {
                if (!string.Equals(
                        activeHome.ReleaseSetId,
                        state.ReleaseSetId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        activeHome.TransactionId,
                        pointer.Current.HomeTransactionId,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Personal failed Installer Harness-home transaction does not match its pending tuple.");
                }
                _ = home.Rollback(activeHome.TransactionId, "INSTALLER_HEALTH_FAILED");
            }
            pointer = pointerStore.RollbackPending();
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.FailedPointerRolledBack);
            var beforeFailure = await security.TryReadAsync(cancellationToken)
                .ConfigureAwait(false)
                ?? throw new InvalidDataException(
                    "Personal failed Installer has no admitted security state.");
            securityState = await security.RecordFailureAsync(
                    state.ReleaseSetId,
                    state.Generation,
                    state.Sequence,
                    state.ManifestSha256,
                    "INSTALLER_HEALTH_FAILED",
                    MaxUtc(
                        RequireUtc(_timeProvider.GetUtcNow()),
                        beforeFailure.TrustedTimeUtc),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            if (pointer is not null
                && pointer.Current.HealthState == PersonalReleaseHealthStates.Pending)
            {
                throw new InvalidDataException(
                    "Personal failed Installer cannot retire an unrelated pending tuple.");
            }
            if (Directory.Exists(_layout.ManagedRoot))
            {
                securityState = await security.TryReadAsync(cancellationToken)
                    .ConfigureAwait(false)
                    ?? throw new InvalidDataException(
                        "Personal failed Installer has no authenticated failure state.");
            }
            else
            {
                securityState = new PersonalInstallProvenanceStore(_layout, _timeProvider)
                    .TryReadAndRepair()?.SecurityState
                    ?? throw new InvalidDataException(
                        "Personal failed Installer lost both its managed state and complete provenance.");
            }
            if (!securityState.FailedReleaseQuarantine.Any(item =>
                    string.Equals(item.ReleaseSetId, state.ReleaseSetId, StringComparison.Ordinal)
                    && item.Generation == state.Generation
                    && item.Sequence == state.Sequence))
            {
                securityState = await security.RecordFailureAsync(
                        state.ReleaseSetId,
                        state.Generation,
                        state.Sequence,
                        state.ManifestSha256,
                        "INSTALLER_HEALTH_FAILED",
                        MaxUtc(
                            RequireUtc(_timeProvider.GetUtcNow()),
                            securityState.TrustedTimeUtc),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        var failure = securityState.FailedReleaseQuarantine.SingleOrDefault(item =>
            string.Equals(item.ReleaseSetId, state.ReleaseSetId, StringComparison.Ordinal));
        if (failure is null
            || failure.Generation != state.Generation
            || failure.Sequence != state.Sequence)
        {
            throw new InvalidDataException(
                "Personal failed Installer candidate was not durably quarantined.");
        }
        _ = new PersonalInstallProvenanceStore(_layout, _timeProvider)
            .WriteFromSecurityState(securityState);
        _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.FailureProvenanceWritten);

        if (pointer is null)
        {
            MoveFailedInstallToQuarantine(state);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.FailedRootQuarantined);
            _removeShell();
        }
        else if (state.PreviousStartupStubSha256 is not null)
        {
            RestoreStableStubUnderLease(state);
            _ = _registerShell(pointer.Current.ReleaseSetId);
        }
        else
        {
            _removeShell();
        }
        _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.FailureRegistrationRestored);
        journal.Delete();
        TryDeleteStaging(state);
        _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.FailureJournalRetired);
    }

    private async Task<bool> HasDurableHealthFailureAsync(
        PersonalInstallMigrationJournalState state,
        CancellationToken cancellationToken)
    {
        var pointer = new PersonalReleaseSetPointerStore(_layout).TryRead();
        if (pointer is not null && PointerMatches(state, pointer.Current))
        {
            return false;
        }
        PersonalReleaseSecurityState? securityState;
        if (Directory.Exists(_layout.ManagedRoot))
        {
            securityState = await CreateSecurityStore(state.Channel)
                .TryReadAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            securityState = new PersonalInstallProvenanceStore(_layout, _timeProvider)
                .TryReadAndRepair()?.SecurityState;
        }
        return securityState?.FailedReleaseQuarantine.Any(failure =>
            string.Equals(failure.ReleaseSetId, state.ReleaseSetId, StringComparison.Ordinal)
            && failure.Generation == state.Generation
            && failure.Sequence == state.Sequence) == true;
    }

    private void MoveFailedInstallToQuarantine(
        PersonalInstallMigrationJournalState state)
    {
        var parent = Path.GetDirectoryName(_layout.ManagedRoot)
            ?? throw new InvalidDataException("Personal managed root has no parent.");
        var container = Path.Combine(parent, "DshLauncherFailedInstallQuarantine");
        var target = Path.Combine(container, state.TransactionId);
        var managedExists = Directory.Exists(_layout.ManagedRoot);
        var quarantineExists = Directory.Exists(target);
        if (managedExists && quarantineExists || !managedExists && !quarantineExists)
        {
            throw new InvalidDataException(
                "Personal failed installation quarantine cannot reconcile its managed-root boundary.");
        }
        if (managedExists)
        {
            PersonalPathGuard.EnsureIndependentDirectory(container);
            Directory.Move(_layout.ManagedRoot, target);
        }
        RejectReparseAncestors(target);
    }

    private static bool PointerMatches(
        PersonalInstallMigrationJournalState state,
        PersonalInstalledReleaseSetReference reference) =>
        string.Equals(reference.ReleaseSetId, state.ReleaseSetId, StringComparison.Ordinal)
        && reference.Generation == state.Generation
        && reference.Sequence == state.Sequence
        && string.Equals(
            reference.ManifestSha256,
            state.ManifestSha256,
            StringComparison.Ordinal);

    private async Task<PersonalInstallMigrationJournalState> CertifyAndRetireJournalAsync(
        PersonalInstallMigrationJournalStore journal,
        PersonalInstallProvenanceStore provenanceStore,
        PersonalInstallMigrationJournalState state,
        CancellationToken cancellationToken)
    {
        _ = await ValidateInstalledAsync(state, requireHealthy: true, cancellationToken)
            .ConfigureAwait(false);
        _ = _registerShell(state.ReleaseSetId);
        var securityState = await CreateSecurityStore(state.Channel)
            .TryReadAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Healthy Personal installation has no authenticated release high-water state.");
        if (!string.Equals(
                securityState.LastCommittedReleaseSetId,
                state.ReleaseSetId,
                StringComparison.Ordinal)
            || !string.Equals(
                securityState.LastCommittedManifestSha256,
                state.ManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Healthy Personal installation is not the authenticated committed release.");
        }
        _ = provenanceStore.WriteFromSecurityState(securityState);
        if (state.Status != PersonalInstallMigrationJournalState.CompletedStatus)
        {
            state = journal.Advance(
                state,
                PersonalInstallMigrationJournalState.CompletedPhase,
                completed: true);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.Completed);
        }
        journal.Delete();
        TryDeleteStaging(state);
        return state;
    }

    private async Task<PersonalInstalledReleaseSetPointer> ValidateInstalledAsync(
        PersonalInstallMigrationJournalState state,
        bool requireHealthy,
        CancellationToken cancellationToken)
    {
        RequireStableStub(state);
        var pointer = new PersonalReleaseSetPointerStore(_layout).ReadRequired();
        RequirePointerMatches(state, pointer);
        if (requireHealthy && pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy)
        {
            throw new InvalidDataException(
                "Personal Installer release has not completed Startup Stub health validation.");
        }
        var security = CreateSecurityStore(state.Channel);
        var authenticated = await security.TryReadAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Personal installed release has no authenticated security state.");
        var decision = await security
            .ValidateInstalledPointerForStartupStubAsync(
                pointer,
                state.StartupStubVersion,
                MaxUtc(
                    RequireUtc(_timeProvider.GetUtcNow()),
                    authenticated.TrustedTimeUtc),
                cancellationToken)
            .ConfigureAwait(false);
        if (!decision.Allowed)
        {
            throw new InvalidDataException(decision.Reason);
        }
        return pointer;
    }

    private async Task<PersonalInstalledReleaseSetPointer> ValidateExistingV2Async(
        PersonalInstallProvenanceStore provenanceStore,
        PersonalInstallProvenance provenance,
        string startupStubVersion,
        CancellationToken cancellationToken)
    {
        var pointer = new PersonalReleaseSetPointerStore(_layout).ReadRequired();
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy)
        {
            throw new InvalidDataException(
                "Personal Installer will not supersede an existing pending release; start the Launcher to finish recovery first.");
        }
        var security = CreateSecurityStore(pointer.Channel);
        var currentState = await security.TryReadAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Existing Personal v2 installation has no authenticated release state.");
        var decision = await security.ValidateInstalledPointerForStartupStubAsync(
                pointer,
                startupStubVersion,
                MaxUtc(
                    RequireUtc(_timeProvider.GetUtcNow()),
                    currentState.TrustedTimeUtc),
                cancellationToken)
            .ConfigureAwait(false);
        if (!decision.Allowed)
        {
            throw new InvalidDataException(decision.Reason);
        }
        _ = provenanceStore.WriteFromSecurityState(currentState);
        var refreshed = provenanceStore.TryReadAndRepair()
            ?? throw new InvalidDataException(
                "Existing Personal v2 installation lost both provenance witnesses.");
        PersonalInstallProvenanceStore.RequireNotBehind(
            provenance.SecurityState,
            refreshed.SecurityState);
        return pointer;
    }

    private void RequireDurableInstallBoundary(
        PersonalInstallProvenance? provenance,
        PersonalV2MigrationFootprint? footprint)
    {
        if ((provenance is null) != (footprint is null))
        {
            throw new InvalidDataException(
                "Personal v2 migration evidence is incomplete; a separately authorized recovery package is required.");
        }
        if (provenance is not null)
        {
            PersonalInstallProvenanceStore.RequireMatchingFootprint(
                provenance,
                footprint!);
            return;
        }
        foreach (var path in new[]
        {
            _layout.UpdateSecurityWitnessPath,
            _layout.UpdateSecurityStatePath,
            _layout.UpdateSecurityStatePath + ".anchor",
            _layout.UpdateSecurityStatePath + ".anchor.pending",
            _layout.InstallationIdentityReceiptPath,
            _layout.InstallationIdentityProtectedPath,
        })
        {
            if (File.Exists(path) || Directory.Exists(path))
            {
                throw new InvalidDataException(
                    "Personal v2 security evidence exists without complete install provenance; recovery requires a separately authorized package.");
            }
        }
    }

    private PersonalInstallMigrationJournalState EnsureLegacyQuarantined(
        PersonalInstallMigrationJournalStore journal,
        PersonalInstallMigrationJournalState state)
    {
        if (!PersonalInstallMigrationJournalState.IsBefore(
                state.Phase,
                PersonalInstallMigrationJournalState.LegacyQuarantinedPhase))
        {
            if (state.LegacyQuarantinePath is not null)
            {
                RequireLegacyQuarantineIdentity(state);
            }
            return state;
        }
        if (state.InstallMode is PersonalInstallMigrationJournalState.ExistingV2UpgradeMode
            or PersonalInstallMigrationJournalState.ExistingV2RepairMode)
        {
            if (!Directory.Exists(_layout.ManagedRoot)
                || state.LegacyQuarantinePath is not null)
            {
                throw new InvalidDataException(
                    "Personal v2 upgrade lost its authenticated managed root.");
            }
            state = journal.Advance(
                state,
                PersonalInstallMigrationJournalState.LegacyQuarantinedPhase);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.LegacyQuarantined);
            return state;
        }
        if (state.LegacyQuarantinePath is null)
        {
            if (Directory.Exists(_layout.ManagedRoot) || File.Exists(_layout.ManagedRoot))
            {
                throw new InvalidDataException(
                    "Personal clean install root appeared after its durable plan was written.");
            }
            state = journal.Advance(
                state,
                PersonalInstallMigrationJournalState.LegacyQuarantinedPhase);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.LegacyQuarantined);
            return state;
        }

        var managedExists = Directory.Exists(_layout.ManagedRoot);
        var quarantineExists = Directory.Exists(state.LegacyQuarantinePath);
        if (managedExists && quarantineExists || !managedExists && !quarantineExists)
        {
            throw new InvalidDataException(
                "Personal legacy migration cannot reconcile its managed-root rename boundary.");
        }
        if (managedExists)
        {
            var identity = MeasureExactLegacyV1Footprint(_layout.ManagedRoot);
            RequireLegacyIdentity(state, identity);
            EnsureQuarantineContainer();
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.LegacyAuthorizedBeforeMove);
            Directory.Move(_layout.ManagedRoot, state.LegacyQuarantinePath);
            _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.LegacyMovedBeforeJournal);
        }
        RequireLegacyQuarantineIdentity(state);
        state = journal.Advance(
            state,
            PersonalInstallMigrationJournalState.LegacyQuarantinedPhase);
        _checkpoint?.Invoke(PersonalInstallMigrationCheckpoint.LegacyQuarantined);
        return state;
    }

    private async Task<PersonalStagedInstallerPayload> StageAndVerifyPayloadAsync(
        IPersonalInstallerPayloadSource payload,
        PersonalInstallerTrustConfiguration trust,
        VerifiedPersonalReleaseSetManifest verified,
        byte[] manifestBytes,
        string rawManifestSha256,
        PersonalInstallMigrationJournalState state,
        CancellationToken cancellationToken)
    {
        PersonalPathGuard.EnsureDirectoryChain(_layout.UpdateOperationLockRoot, state.StagingRoot);
        var manifestPath = Path.Combine(state.StagingRoot, "release-set.v2.json");
        var stubPath = Path.Combine(
            state.StagingRoot,
            PersonalInstallationLayout.StartupStubExecutableName);
        var clientPath = Path.Combine(state.StagingRoot, "client-bundle.zip");
        var runtimePath = Path.Combine(state.StagingRoot, "runtime.zip");
        await WriteOrValidateAsync(
                manifestPath,
                () => new MemoryStream(manifestBytes, writable: false),
                manifestBytes.LongLength,
                rawManifestSha256,
                2L * 1024 * 1024,
                cancellationToken)
            .ConfigureAwait(false);
        var stub = await WriteOrValidateUnknownAsync(
                stubPath,
                payload.OpenStartupStub,
                512L * 1024 * 1024,
                cancellationToken)
            .ConfigureAwait(false);
        await WriteOrValidateAsync(
                clientPath,
                payload.OpenClientBundleArchive,
                verified.Manifest.ClientBundle.SizeBytes,
                verified.Manifest.ClientBundle.Sha256,
                4L * 1024 * 1024 * 1024,
                cancellationToken)
            .ConfigureAwait(false);
        await WriteOrValidateAsync(
                runtimePath,
                payload.OpenRuntimeArchive,
                verified.Manifest.Runtime.SizeBytes,
                verified.Manifest.Runtime.Sha256,
                8L * 1024 * 1024 * 1024,
                cancellationToken)
            .ConfigureAwait(false);
        PersonalPathGuard.RequireSingleLinkFile(stubPath);
        PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(stubPath);
        if (trust.ProductionBuild)
        {
            _ = PersonalCompiledTrustProcessVerifier.RequireExecutable(
                stubPath,
                PersonalInstallationLayout.StartupStubExecutableName,
                PersonalCompiledTrustFingerprint.Create(trust));
        }

        var clientTree = await ExtractCompleteTreeAsync(
                clientPath,
                state.StagingRoot,
                "client-tree.json",
                cancellationToken)
            .ConfigureAwait(false);
        var runtimeTree = await ExtractCompleteTreeAsync(
                runtimePath,
                state.StagingRoot,
                "runtime-tree.json",
                cancellationToken)
            .ConfigureAwait(false);
        _ = await PersonalReleaseArtifactInstaller.VerifyCandidateArchiveAsync(
                clientPath,
                clientTree,
                PersonalReleaseSetContract.ClientBundleComponent,
                verified.Manifest.ClientBundle.ReleaseId,
                cancellationToken)
            .ConfigureAwait(false);
        _ = await PersonalReleaseArtifactInstaller.VerifyCandidateArchiveAsync(
                runtimePath,
                runtimeTree,
                PersonalReleaseSetContract.RuntimeComponent,
                verified.Manifest.Runtime.ReleaseId,
                cancellationToken)
            .ConfigureAwait(false);
        return new PersonalStagedInstallerPayload(
            stubPath,
            stub.Sha256,
            stub.SizeBytes,
            clientPath,
            runtimePath);
    }

    private static async Task<string> ExtractCompleteTreeAsync(
        string archivePath,
        string stagingRoot,
        string fileName,
        CancellationToken cancellationToken)
    {
        using var archive = ZipFile.OpenRead(archivePath);
        var entries = archive.Entries
            .Where(entry => string.Equals(
                entry.FullName,
                ".ensou-complete-tree.v1.json",
                StringComparison.Ordinal))
            .ToArray();
        if (entries.Length != 1 || entries[0].Length is <= 0 or > 64L * 1024 * 1024)
        {
            throw new InvalidDataException(
                "Personal Installer archive has no unique bounded complete-tree manifest.");
        }
        var path = Path.Combine(stagingRoot, fileName);
        var bytes = await ReadBoundedAsync(
                entries[0].Open(),
                64 * 1024 * 1024,
                cancellationToken)
            .ConfigureAwait(false);
        _ = await WriteOrValidateAsync(
                path,
                () => new MemoryStream(bytes, writable: false),
                bytes.LongLength,
                Sha256(bytes),
                64L * 1024 * 1024,
                cancellationToken)
            .ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(bytes);
        return path;
    }

    private void InstallStableStartupStub(
        PersonalStagedInstallerPayload staged,
        PersonalInstallMigrationJournalState state)
    {
        RequireStagedStubMatches(state, staged);
        if (File.Exists(_layout.StartupStubPath))
        {
            PersonalPathGuard.RequireSingleLinkFile(_layout.StartupStubPath);
            var current = ComputeFileIdentity(_layout.StartupStubPath);
            if (current == new PersonalFileIdentity(
                    staged.StartupStubSha256,
                    staged.StartupStubSizeBytes))
            {
                PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(
                    _layout.StartupStubPath);
                return;
            }
            RequirePreviousStartupStub(state, current);
        }
        else if (Directory.Exists(_layout.StartupStubPath))
        {
            throw new InvalidDataException(
                "Personal stable Startup Stub path is unexpectedly a directory.");
        }
        else if (state.PreviousStartupStubSha256 is not null
            && (state.StartupStubBackupPath is null
                || !File.Exists(state.StartupStubBackupPath)))
        {
            throw new InvalidDataException(
                "Personal previous Startup Stub disappeared before its durable replacement.");
        }

        if (state.StartupStubBackupPath is not null
            && File.Exists(state.StartupStubBackupPath))
        {
            RequireFileIdentity(
                state.StartupStubBackupPath,
                state.PreviousStartupStubSizeBytes!.Value,
                state.PreviousStartupStubSha256!);
            if (!File.Exists(_layout.StartupStubPath))
            {
                File.Move(state.StartupStubBackupPath, _layout.StartupStubPath);
            }
            else
            {
                var installed = ComputeFileIdentity(_layout.StartupStubPath);
                if (installed == new PersonalFileIdentity(
                        staged.StartupStubSha256,
                        staged.StartupStubSizeBytes))
                {
                    PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(
                        _layout.StartupStubPath);
                    return;
                }
                RequirePreviousStartupStub(state, installed);
                File.Delete(state.StartupStubBackupPath);
            }
        }

        var temporary = Path.Combine(
            _layout.ManagedRoot,
            $".{PersonalInstallationLayout.StartupStubExecutableName}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.Copy(staged.StartupStubPath, temporary, overwrite: false);
            PersonalPathGuard.RequireSingleLinkFile(temporary);
            RequireFileIdentity(temporary, staged.StartupStubSizeBytes, staged.StartupStubSha256);
            PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(temporary);
            if (File.Exists(_layout.StartupStubPath))
            {
                var backup = state.StartupStubBackupPath
                    ?? throw new InvalidDataException(
                        "Personal Startup Stub replacement has no durable backup path.");
                File.Replace(temporary, _layout.StartupStubPath, backup, ignoreMetadataErrors: true);
                RequireFileIdentity(
                    backup,
                    state.PreviousStartupStubSizeBytes!.Value,
                    state.PreviousStartupStubSha256!);
            }
            else
            {
                File.Move(temporary, _layout.StartupStubPath);
            }
            RequireStableStub(state);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static void RequirePreviousStartupStub(
        PersonalInstallMigrationJournalState state,
        PersonalFileIdentity actual)
    {
        if (state.PreviousStartupStubSha256 is null
            || state.PreviousStartupStubSizeBytes is null
            || actual != new PersonalFileIdentity(
                state.PreviousStartupStubSha256,
                state.PreviousStartupStubSizeBytes.Value))
        {
            throw new InvalidDataException(
                "Personal Startup Stub changed after its durable replacement plan was recorded.");
        }
    }

    private void RequireStableStub(PersonalInstallMigrationJournalState state)
    {
        if (state.StartupStubSha256 is null || state.StartupStubSizeBytes is null)
        {
            throw new InvalidDataException(
                "Personal Installer journal has no authenticated Startup Stub identity.");
        }
        RequireFileIdentity(
            _layout.StartupStubPath,
            state.StartupStubSizeBytes.Value,
            state.StartupStubSha256);
        PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(_layout.StartupStubPath);
    }

    private static void RequirePointerMatches(
        PersonalInstallMigrationJournalState state,
        PersonalInstalledReleaseSetPointer pointer)
    {
        if (!string.Equals(pointer.Current.ReleaseSetId, state.ReleaseSetId, StringComparison.Ordinal)
            || !string.Equals(pointer.Current.ManifestSha256, state.ManifestSha256, StringComparison.Ordinal)
            || !string.Equals(
                pointer.Current.ClientBundle.ReleaseId,
                state.ClientBundleReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                pointer.Current.ClientBundle.ArchiveSha256,
                state.ClientBundleArchiveSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                pointer.Current.Runtime.ReleaseId,
                state.RuntimeReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                pointer.Current.Runtime.ArchiveSha256,
                state.RuntimeArchiveSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal installed release does not match the durable Installer payload.");
        }
    }

    private void RequireFreshInstallBoundary()
    {
        foreach (var path in new[]
        {
            _layout.UpdateSecurityWitnessPath,
            _layout.V2MigrationFootprintPath,
            _layout.InstallationIdentityReceiptPath,
            _layout.InstallationIdentityProtectedPath,
        })
        {
            if (File.Exists(path) || Directory.Exists(path))
            {
                throw new InvalidDataException(
                    "Personal v2 security evidence already exists without its Installer journal; recovery requires a separately authorized repair package.");
            }
        }
        EnsureQuarantineContainerIsEmptyOrAbsent();
    }

    private PersonalLegacyTreeIdentity MeasureExactLegacyV1Footprint(string root)
    {
        var expected = new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            ["runtimes"] = true,
            ["snapshots"] = true,
            ["state"] = true,
            ["launcher.settings.json"] = false,
        };
        var entries = Directory.EnumerateFileSystemEntries(root, "*", SearchOption.TopDirectoryOnly)
            .ToArray();
        if (entries.Length != expected.Count)
        {
            throw new InvalidDataException(
                "Existing Personal managed root is not the exact supported v1 footprint.");
        }
        foreach (var entry in entries)
        {
            var name = Path.GetFileName(entry);
            if (!expected.TryGetValue(name, out var directory)
                || directory != Directory.Exists(entry)
                || !directory && !File.Exists(entry))
            {
                throw new InvalidDataException(
                    "Existing Personal managed root is not the exact supported v1 footprint.");
            }
        }
        var stateEntries = Directory.EnumerateFileSystemEntries(
                Path.Combine(root, "state"),
                "*",
                SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileName)
            .ToArray();
        if (stateEntries.Length != 1
            || !string.Equals(stateEntries[0], "runtime-current.json", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Existing Personal v1 state directory does not match the observed runtime-only footprint.");
        }
        return MeasureSafeTree(root);
    }

    private PersonalLegacyTreeIdentity MeasureSafeTree(string root)
    {
        var normalizedRoot = PersonalPathGuard.NormalizeDirectory(root);
        RejectReparseAncestors(normalizedRoot);
        if (!Directory.Exists(normalizedRoot)
            || (File.GetAttributes(normalizedRoot) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal legacy program root is missing or linked.");
        }
        var entries = Directory.EnumerateFileSystemEntries(
                normalizedRoot,
                "*",
                SearchOption.AllDirectories)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (entries.LongLength > 1_000_000)
        {
            throw new InvalidDataException("Personal legacy program tree is unbounded.");
        }
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long fileCount = 0;
        long sizeBytes = 0;
        foreach (var entry in entries)
        {
            var full = Path.GetFullPath(entry);
            if (!PersonalPathGuard.IsStrictDescendant(full, normalizedRoot)
                || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal legacy program tree contains a path escape or filesystem link.");
            }
            var relative = Path.GetRelativePath(normalizedRoot, full).Replace('\\', '/');
            if (relative.Length is <= 0 or > 32_768)
            {
                throw new InvalidDataException("Personal legacy relative path is unbounded.");
            }
            if (Directory.Exists(full))
            {
                AppendDigest(digest, $"D\0{relative}\n");
                continue;
            }
            if (!File.Exists(full))
            {
                throw new InvalidDataException(
                    "Personal legacy program tree contains an unsupported filesystem entry.");
            }
            PersonalPathGuard.RequireSingleLinkFile(full);
            var info = new FileInfo(full);
            fileCount = checked(fileCount + 1);
            sizeBytes = checked(sizeBytes + info.Length);
            if (sizeBytes > 2L * 1024 * 1024 * 1024 * 1024)
            {
                throw new InvalidDataException("Personal legacy program tree is unbounded.");
            }
            using var stream = new FileStream(
                full,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.SequentialScan);
            AppendDigest(digest, $"F\0{relative}\0{info.Length}\0");
            digest.AppendData(SHA256.HashData(stream));
            AppendDigest(digest, "\n");
        }
        return new PersonalLegacyTreeIdentity(
            Convert.ToHexStringLower(digest.GetHashAndReset()),
            fileCount,
            sizeBytes);
    }

    private void RequireLegacyQuarantineIdentity(PersonalInstallMigrationJournalState state)
    {
        if (state.LegacyQuarantinePath is null)
        {
            throw new InvalidDataException("Personal legacy quarantine identity is missing.");
        }
        RequireLegacyIdentity(state, MeasureSafeTree(state.LegacyQuarantinePath));
    }

    private static void RequireLegacyIdentity(
        PersonalInstallMigrationJournalState state,
        PersonalLegacyTreeIdentity actual)
    {
        if (!string.Equals(state.LegacyTreeSha256, actual.TreeSha256, StringComparison.Ordinal)
            || state.LegacyFileCount != actual.FileCount
            || state.LegacySizeBytes != actual.SizeBytes)
        {
            throw new InvalidDataException(
                "Personal legacy quarantine does not match the pre-migration tree identity.");
        }
    }

    private void EnsureQuarantineContainerIsEmptyOrAbsent()
    {
        var container = GetLegacyQuarantineContainer();
        if (!Directory.Exists(container))
        {
            if (File.Exists(container))
            {
                throw new InvalidDataException(
                    "Personal legacy quarantine container is unexpectedly a file.");
            }
            return;
        }
        RejectReparseAncestors(container);
        if (Directory.EnumerateFileSystemEntries(container).Any())
        {
            throw new InvalidDataException(
                "Personal legacy quarantine exists without a durable Installer journal.");
        }
    }

    private void EnsureQuarantineContainer()
    {
        var container = GetLegacyQuarantineContainer();
        PersonalPathGuard.EnsureIndependentDirectory(container);
        if (Directory.EnumerateFileSystemEntries(container).Any())
        {
            throw new InvalidDataException(
                "Personal legacy quarantine container is not empty before its first migration.");
        }
    }

    private string GetLegacyQuarantineContainer()
    {
        var parent = Path.GetDirectoryName(_layout.ManagedRoot)
            ?? throw new InvalidDataException("Personal managed root has no parent.");
        return Path.Combine(parent, "DshLauncherLegacyQuarantine");
    }

    private string GetLegacyQuarantinePath(string transactionId) =>
        Path.Combine(GetLegacyQuarantineContainer(), transactionId);

    private void RequireManagedRootOwnedByTransaction(PersonalInstallMigrationJournalState state)
    {
        if (!Directory.Exists(_layout.ManagedRoot)
            || state.LegacyQuarantinePath is not null
                && !Directory.Exists(state.LegacyQuarantinePath))
        {
            throw new InvalidDataException(
                "Personal Installer cannot prove ownership of its new managed root.");
        }
        RejectReparseAncestors(_layout.ManagedRoot);
    }

    private PersonalReleaseSecurityStateStore CreateSecurityStore(string channel) => new(
        _layout.UpdateSecurityStatePath,
        new PersonalReleaseStateIdentity(
            PersonalReleaseSetContract.Product,
            PersonalReleaseSetContract.ProductionEnvironment,
            channel),
        _layout.UpdateSecurityWitnessPath);

    private static void RequirePayloadMatches(
        PersonalInstallMigrationJournalState state,
        VerifiedPersonalReleaseSetManifest verified,
        string rawManifestSha256,
        PersonalInstallerTrustConfiguration trust)
    {
        var manifest = verified.Manifest;
        if (!string.Equals(state.ReleaseSetId, manifest.ReleaseSetId, StringComparison.Ordinal)
            || state.Generation != manifest.Generation
            || state.Sequence != manifest.Sequence
            || !string.Equals(
                state.ManifestSha256,
                verified.CanonicalSignedManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(state.RawManifestSha256, rawManifestSha256, StringComparison.Ordinal)
            || !string.Equals(state.Channel, manifest.Channel, StringComparison.Ordinal)
            || !string.Equals(
                state.StartupStubVersion,
                trust.ReleasePolicy.StartupStubVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                state.ClientBundleReleaseId,
                manifest.ClientBundle.ReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                state.ClientBundleArchiveSha256,
                manifest.ClientBundle.Sha256,
                StringComparison.Ordinal)
            || state.ClientBundleSizeBytes != manifest.ClientBundle.SizeBytes
            || !string.Equals(
                state.RuntimeReleaseId,
                manifest.Runtime.ReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                state.RuntimeArchiveSha256,
                manifest.Runtime.Sha256,
                StringComparison.Ordinal)
            || state.RuntimeSizeBytes != manifest.Runtime.SizeBytes)
        {
            throw new InvalidDataException(
                "Personal Installer payload does not match the durable install transaction.");
        }
    }

    private static void RequireStagedStubMatches(
        PersonalInstallMigrationJournalState state,
        PersonalStagedInstallerPayload staged)
    {
        if (state.StartupStubSha256 is null
            || state.StartupStubSizeBytes is null
            || !string.Equals(
                state.StartupStubSha256,
                staged.StartupStubSha256,
                StringComparison.Ordinal)
            || state.StartupStubSizeBytes != staged.StartupStubSizeBytes)
        {
            throw new InvalidDataException(
                "Personal Installer Startup Stub bytes changed across transaction recovery.");
        }
    }

    private static PersonalInstallPreparationResult Result(
        PersonalInstallMigrationJournalState state,
        bool requiresHealth,
        bool alreadyCompleted) => new(
            state.ReleaseSetId,
            state.ManifestSha256,
            state.ManagedRoot is { } root
                ? Path.Combine(root, PersonalInstallationLayout.StartupStubExecutableName)
                : throw new InvalidDataException("Personal Installer journal has no managed root."),
            state.LegacyQuarantinePath,
            state.LegacyQuarantinePath is not null,
            requiresHealth,
            alreadyCompleted);

    private static async Task<byte[]> ReadBoundedAsync(
        Stream source,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        await using (source.ConfigureAwait(false))
        {
            using var output = new MemoryStream();
            var buffer = new byte[32 * 1024];
            while (true)
            {
                var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                if (output.Length + read > maximumBytes)
                {
                    throw new InvalidDataException("Personal Installer manifest is unbounded.");
                }
                output.Write(buffer, 0, read);
            }
            if (output.Length == 0)
            {
                throw new InvalidDataException("Personal Installer manifest is empty.");
            }
            return output.ToArray();
        }
    }

    private static Task<PersonalFileIdentity> WriteOrValidateUnknownAsync(
        string path,
        Func<Stream> source,
        long maximumBytes,
        CancellationToken cancellationToken) => WriteOrValidateCoreAsync(
            path,
            source,
            null,
            null,
            maximumBytes,
            cancellationToken);

    private static Task<PersonalFileIdentity> WriteOrValidateAsync(
        string path,
        Func<Stream> source,
        long expectedBytes,
        string expectedSha256,
        long maximumBytes,
        CancellationToken cancellationToken) => WriteOrValidateCoreAsync(
            path,
            source,
            expectedBytes,
            expectedSha256,
            maximumBytes,
            cancellationToken);

    private static async Task<PersonalFileIdentity> WriteOrValidateCoreAsync(
        string path,
        Func<Stream> source,
        long? expectedBytes,
        string? expectedSha256,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        if (File.Exists(path))
        {
            PersonalPathGuard.RequireSingleLinkFile(path);
            var existing = ComputeFileIdentity(path);
            RequireExpected(existing, expectedBytes, expectedSha256, maximumBytes);
            await using var currentSource = source();
            var supplied = await ComputeStreamIdentityAsync(
                    currentSource,
                    maximumBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            RequireExpected(supplied, expectedBytes, expectedSha256, maximumBytes);
            if (supplied != existing)
            {
                throw new InvalidDataException(
                    "Personal Installer payload bytes changed across transaction recovery.");
            }
            return existing;
        }
        if (Directory.Exists(path))
        {
            throw new InvalidDataException(
                "Personal Installer staging file is unexpectedly a directory.");
        }
        var temporary = path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            await using var input = source();
            await using (var output = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             128 * 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                var buffer = new byte[128 * 1024];
                long total = 0;
                while (true)
                {
                    var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }
                    total = checked(total + read);
                    if (total > maximumBytes)
                    {
                        throw new InvalidDataException("Personal Installer payload entry is unbounded.");
                    }
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                        .ConfigureAwait(false);
                }
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            PersonalPathGuard.RequireSingleLinkFile(temporary);
            var identity = ComputeFileIdentity(temporary);
            RequireExpected(identity, expectedBytes, expectedSha256, maximumBytes);
            File.Move(temporary, path);
            PersonalPathGuard.RequireSingleLinkFile(path);
            return identity;
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static PersonalFileIdentity ComputeFileIdentity(string path)
    {
        var info = new FileInfo(path);
        if (info.Length <= 0)
        {
            throw new InvalidDataException("Personal Installer payload entry is empty.");
        }
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        return new PersonalFileIdentity(
            Convert.ToHexStringLower(SHA256.HashData(stream)),
            info.Length);
    }

    private static PersonalFileIdentity? TryComputeSafeFileIdentity(string path)
    {
        if (!File.Exists(path))
        {
            if (Directory.Exists(path))
            {
                throw new InvalidDataException(
                    "Personal Startup Stub path is unexpectedly a directory.");
            }
            return null;
        }
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal Startup Stub path must not be a filesystem link.");
        }
        PersonalPathGuard.RequireSingleLinkFile(path);
        return ComputeFileIdentity(path);
    }

    private static async Task<PersonalFileIdentity> ComputeStreamIdentityAsync(
        Stream stream,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            total = checked(total + read);
            if (total > maximumBytes)
            {
                throw new InvalidDataException(
                    "Personal Installer payload entry is unbounded.");
            }
            digest.AppendData(buffer, 0, read);
        }
        if (total <= 0)
        {
            throw new InvalidDataException("Personal Installer payload entry is empty.");
        }
        return new PersonalFileIdentity(
            Convert.ToHexStringLower(digest.GetHashAndReset()),
            total);
    }

    private static void RequireExpected(
        PersonalFileIdentity identity,
        long? expectedBytes,
        string? expectedSha256,
        long maximumBytes)
    {
        if (identity.SizeBytes <= 0
            || identity.SizeBytes > maximumBytes
            || expectedBytes is not null && identity.SizeBytes != expectedBytes
            || expectedSha256 is not null
                && !string.Equals(identity.Sha256, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Installer payload entry does not match its authenticated descriptor.");
        }
    }

    private static void RequireFileIdentity(string path, long sizeBytes, string sha256)
    {
        if (!File.Exists(path)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal installed file is missing or linked.");
        }
        PersonalPathGuard.RequireSingleLinkFile(path);
        RequireExpected(
            ComputeFileIdentity(path),
            sizeBytes,
            sha256,
            long.MaxValue);
    }

    private void TryDeleteStaging(PersonalInstallMigrationJournalState state)
    {
        if (!Directory.Exists(state.StagingRoot))
        {
            return;
        }
        if (!PersonalPathGuard.IsStrictDescendant(
                state.StagingRoot,
                _layout.UpdateOperationLockRoot))
        {
            throw new InvalidDataException("Personal Installer staging root escaped its lock root.");
        }
        DeleteTreeWithoutFollowingLinks(state.StagingRoot);
    }

    private static void DeleteTreeWithoutFollowingLinks(string root)
    {
        RejectReparseAncestors(root);
        foreach (var entry in Directory.EnumerateFileSystemEntries(
                     root,
                     "*",
                     SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal Installer staging cleanup encountered a filesystem link.");
            }
            if (File.Exists(entry))
            {
                PersonalPathGuard.RequireSingleLinkFile(entry);
            }
        }
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            File.Delete(file);
        }
        foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                     .OrderByDescending(path => path.Length))
        {
            Directory.Delete(directory);
        }
        Directory.Delete(root);
    }

    private static void RejectReparseAncestors(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path));
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal Installer path crosses a filesystem link.");
            }
        }
    }

    private static void AppendDigest(IncrementalHash digest, string value) =>
        digest.AppendData(Encoding.UTF8.GetBytes(value));

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static DateTimeOffset RequireUtc(DateTimeOffset value) =>
        value.Offset == TimeSpan.Zero && value > DateTimeOffset.UnixEpoch
            ? value
            : throw new InvalidDataException("Personal Installer time must be valid UTC.");

    private static DateTimeOffset MaxUtc(DateTimeOffset left, DateTimeOffset right) =>
        left >= right ? left : right;
}

public sealed record PersonalDevelopmentE2EInstallOptions(
    string ManagedRoot,
    string HarnessHome,
    string UpdateSecurityWitnessPath,
    bool NoShellRegistration)
{
    internal void RequireExactLayout(PersonalInstallationLayout layout)
    {
        if (!NoShellRegistration
            || !string.Equals(layout.ManagedRoot, ManagedRoot, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(layout.HarnessHome, HarnessHome, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                layout.UpdateSecurityWitnessPath,
                UpdateSecurityWitnessPath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal development E2E shell suppression requires the exact independently validated layout.");
        }
    }
}

internal static class PersonalInstallerProcessGuard
{
    private static readonly string[] ManagedProcessNames =
    [
        "Ensou.Dsh.Bootstrapper",
        "Ensou.Dsh.ClientBootstrapper",
        "Ensou.Dsh.Launcher",
        "Ensou.Dsh.Personal.Maintenance",
    ];

    public static void RequireNoManagedClientProcesses()
    {
        foreach (var name in ManagedProcessNames)
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                using (process)
                {
                    if (!process.HasExited && process.Id != Environment.ProcessId)
                    {
                        throw new InvalidOperationException(
                            "Close DeepSeek Harness Launcher before installing or migrating the Personal edition.");
                    }
                }
            }
        }
    }
}

internal sealed record PersonalFileIdentity(string Sha256, long SizeBytes);

internal sealed record PersonalStagedInstallerPayload(
    string StartupStubPath,
    string StartupStubSha256,
    long StartupStubSizeBytes,
    string ClientBundleArchivePath,
    string RuntimeArchivePath);

internal sealed record PersonalLegacyTreeIdentity(
    string TreeSha256,
    long FileCount,
    long SizeBytes);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalInstallMigrationJournalState
{
    public const int CurrentSchemaVersion = 1;
    public const string ActiveStatus = "active";
    public const string CompletedStatus = "completed";
    public const string FailedStatus = "failed-finalizing";
    public const string CreatedPhase = "created";
    public const string PayloadStagedPhase = "payload-staged";
    public const string LegacyQuarantinedPhase = "legacy-quarantined";
    public const string SecurityAdmittedPhase = "security-admitted";
    public const string ComponentsInstalledPhase = "components-installed";
    public const string StartupStubInstalledPhase = "startup-stub-installed";
    public const string PointerActivatedPhase = "pointer-activated";
    public const string RegistrationInstalledPhase = "registration-installed";
    public const string AwaitingHealthPhase = "awaiting-health";
    public const string CompletedPhase = "completed";
    public const string HealthFailedPhase = "health-failed";
    public const string CleanInstallMode = "clean-install";
    public const string LegacyV1MigrationMode = "legacy-v1-migration";
    public const string CertifiedReinstallMode = "certified-reinstall";
    public const string ExistingV2UpgradeMode = "existing-v2-upgrade";
    public const string ExistingV2RepairMode = "existing-v2-repair";

    private static readonly string[] OrderedPhases =
    [
        CreatedPhase,
        PayloadStagedPhase,
        LegacyQuarantinedPhase,
        SecurityAdmittedPhase,
        ComponentsInstalledPhase,
        StartupStubInstalledPhase,
        PointerActivatedPhase,
        RegistrationInstalledPhase,
        AwaitingHealthPhase,
        CompletedPhase,
        HealthFailedPhase,
    ];

    public required int SchemaVersion { get; init; }
    public required string Product { get; init; }
    public required string TransactionId { get; init; }
    public required string Status { get; init; }
    public required string Phase { get; init; }
    public required string ManagedRoot { get; init; }
    public required string StagingRoot { get; init; }
    public required string InstallMode { get; init; }
    public string? PreviousStartupStubSha256 { get; init; }
    public long? PreviousStartupStubSizeBytes { get; init; }
    public string? StartupStubBackupPath { get; init; }
    public string? LegacyQuarantinePath { get; init; }
    public string? LegacyTreeSha256 { get; init; }
    public long? LegacyFileCount { get; init; }
    public long? LegacySizeBytes { get; init; }
    public required string Channel { get; init; }
    public required string ReleaseSetId { get; init; }
    public required long Generation { get; init; }
    public required long Sequence { get; init; }
    public required string ManifestSha256 { get; init; }
    public required string RawManifestSha256 { get; init; }
    public required string StartupStubVersion { get; init; }
    public string? StartupStubSha256 { get; init; }
    public long? StartupStubSizeBytes { get; init; }
    public required string ClientBundleReleaseId { get; init; }
    public required string ClientBundleArchiveSha256 { get; init; }
    public required long ClientBundleSizeBytes { get; init; }
    public required string RuntimeReleaseId { get; init; }
    public required string RuntimeArchiveSha256 { get; init; }
    public required long RuntimeSizeBytes { get; init; }
    public required DateTimeOffset CreatedAtUtc { get; init; }
    public required DateTimeOffset UpdatedAtUtc { get; init; }

    public static PersonalInstallMigrationJournalState Create(
        PersonalInstallationLayout layout,
        string transactionId,
        VerifiedPersonalReleaseSetManifest verified,
        string rawManifestSha256,
        string startupStubVersion,
        string installMode,
        PersonalFileIdentity? previousStartupStub,
        string? quarantinePath,
        PersonalLegacyTreeIdentity? legacy,
        DateTimeOffset nowUtc) => new()
        {
            SchemaVersion = CurrentSchemaVersion,
            Product = "Ensou.Dsh.Personal.InstallMigration",
            TransactionId = transactionId,
            Status = ActiveStatus,
            Phase = CreatedPhase,
            ManagedRoot = layout.ManagedRoot,
            StagingRoot = Path.Combine(
                layout.UpdateOperationLockRoot,
                "personal-installer-staging",
                transactionId),
            InstallMode = installMode,
            PreviousStartupStubSha256 = previousStartupStub?.Sha256,
            PreviousStartupStubSizeBytes = previousStartupStub?.SizeBytes,
            StartupStubBackupPath = previousStartupStub is null
                ? null
                : Path.Combine(
                    layout.UpdateOperationLockRoot,
                    "personal-installer-staging",
                    transactionId,
                    "startup-stub.previous.exe"),
            LegacyQuarantinePath = quarantinePath,
            LegacyTreeSha256 = legacy?.TreeSha256,
            LegacyFileCount = legacy?.FileCount,
            LegacySizeBytes = legacy?.SizeBytes,
            Channel = verified.Manifest.Channel,
            ReleaseSetId = verified.Manifest.ReleaseSetId,
            Generation = verified.Manifest.Generation,
            Sequence = verified.Manifest.Sequence,
            ManifestSha256 = verified.CanonicalSignedManifestSha256,
            RawManifestSha256 = rawManifestSha256,
            StartupStubVersion = startupStubVersion,
            ClientBundleReleaseId = verified.Manifest.ClientBundle.ReleaseId,
            ClientBundleArchiveSha256 = verified.Manifest.ClientBundle.Sha256,
            ClientBundleSizeBytes = verified.Manifest.ClientBundle.SizeBytes,
            RuntimeReleaseId = verified.Manifest.Runtime.ReleaseId,
            RuntimeArchiveSha256 = verified.Manifest.Runtime.Sha256,
            RuntimeSizeBytes = verified.Manifest.Runtime.SizeBytes,
            CreatedAtUtc = nowUtc,
            UpdatedAtUtc = nowUtc,
        };

    public static bool IsBefore(string left, string right) =>
        Array.IndexOf(OrderedPhases, left) < Array.IndexOf(OrderedPhases, right);

    public static int PhaseIndex(string phase) => Array.IndexOf(OrderedPhases, phase);
}

internal sealed class PersonalInstallMigrationJournalStore
{
    private const int MaximumProtectedBytes = 2 * 1024 * 1024;
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
    private readonly TimeProvider _timeProvider;
    private readonly string _path;
    private readonly byte[] _entropy;

    public PersonalInstallMigrationJournalStore(
        PersonalInstallationLayout layout,
        TimeProvider timeProvider)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _path = Path.Combine(
            layout.UpdateOperationLockRoot,
            "personal-install-migration.v1.dpapi");
        _entropy = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
            '|',
            "Ensou.Dsh.Personal.InstallMigration.v1",
            layout.ManagedRoot,
            layout.HarnessHome)));
    }

    internal string JournalPath => _path;

    public PersonalInstallMigrationJournalState? TryRead()
    {
        _layout.EnsureUpdateOperationLockRoot();
        return ReadExisting();
    }

    internal PersonalInstallMigrationJournalState? TryReadForPreflight()
    {
        if (File.Exists(_layout.UpdateOperationLockRoot))
        {
            throw new InvalidDataException(
                "Personal Installer operation-lock root is unexpectedly a file.");
        }
        if (!Directory.Exists(_layout.UpdateOperationLockRoot))
        {
            return null;
        }
        for (var current = new DirectoryInfo(_layout.UpdateOperationLockRoot);
             current is not null;
             current = current.Parent)
        {
            if (current.Exists
                && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal Installer preflight journal path crosses a filesystem link.");
            }
        }
        return ReadExisting();
    }

    private PersonalInstallMigrationJournalState? ReadExisting()
    {
        if (!File.Exists(_path))
        {
            if (Directory.Exists(_path))
            {
                throw new InvalidDataException(
                    "Personal Installer journal path is unexpectedly a directory.");
            }
            return null;
        }
        PersonalPathGuard.RequireSingleLinkFile(_path);
        var protectedBytes = File.ReadAllBytes(_path);
        if (protectedBytes.Length is <= 0 or > MaximumProtectedBytes)
        {
            throw new InvalidDataException("Personal Installer journal is empty or unbounded.");
        }
        byte[]? plaintext = null;
        try
        {
            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                _entropy,
                DataProtectionScope.CurrentUser);
            RejectDuplicateProperties(plaintext);
            var state = JsonSerializer.Deserialize<PersonalInstallMigrationJournalState>(
                    plaintext,
                    JsonOptions)
                ?? throw new InvalidDataException("Personal Installer journal is empty.");
            Validate(state);
            return state;
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "Personal Installer journal is not valid for the current Windows user.",
                exception);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Personal Installer journal JSON is invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    public PersonalInstallMigrationJournalState RecordStagedPayload(
        PersonalInstallMigrationJournalState state,
        string stubSha256,
        long stubSizeBytes)
    {
        if (state.Phase != PersonalInstallMigrationJournalState.CreatedPhase)
        {
            throw new InvalidOperationException(
                "Personal Installer payload identity can only be recorded once.");
        }
        var next = state with
        {
            Phase = PersonalInstallMigrationJournalState.PayloadStagedPhase,
            StartupStubSha256 = stubSha256,
            StartupStubSizeBytes = stubSizeBytes,
            UpdatedAtUtc = MonotonicNow(state),
        };
        Write(next);
        return next;
    }

    public PersonalInstallMigrationJournalState Advance(
        PersonalInstallMigrationJournalState state,
        string phase,
        bool completed = false)
    {
        var currentIndex = PersonalInstallMigrationJournalState.PhaseIndex(state.Phase);
        var nextIndex = PersonalInstallMigrationJournalState.PhaseIndex(phase);
        if (currentIndex < 0 || nextIndex != currentIndex + 1)
        {
            throw new InvalidOperationException(
                "Personal Installer journal phases must advance exactly once in order.");
        }
        if (completed != (phase == PersonalInstallMigrationJournalState.CompletedPhase))
        {
            throw new InvalidOperationException(
                "Personal Installer completion status does not match its phase.");
        }
        var next = state with
        {
            Phase = phase,
            Status = completed
                ? PersonalInstallMigrationJournalState.CompletedStatus
                : PersonalInstallMigrationJournalState.ActiveStatus,
            UpdatedAtUtc = MonotonicNow(state),
        };
        Write(next);
        return next;
    }

    public PersonalInstallMigrationJournalState MarkHealthFailed(
        PersonalInstallMigrationJournalState state)
    {
        if (state.Status == PersonalInstallMigrationJournalState.FailedStatus
            && state.Phase == PersonalInstallMigrationJournalState.HealthFailedPhase)
        {
            return state;
        }
        if (state.Status != PersonalInstallMigrationJournalState.ActiveStatus
            || state.Phase != PersonalInstallMigrationJournalState.AwaitingHealthPhase)
        {
            throw new InvalidOperationException(
                "Personal Installer health failure can only finalize an awaiting transaction.");
        }
        var next = state with
        {
            Status = PersonalInstallMigrationJournalState.FailedStatus,
            Phase = PersonalInstallMigrationJournalState.HealthFailedPhase,
            UpdatedAtUtc = MonotonicNow(state),
        };
        Write(next);
        return next;
    }

    public void Write(PersonalInstallMigrationJournalState state)
    {
        Validate(state);
        _layout.EnsureUpdateOperationLockRoot();
        if (File.Exists(_path))
        {
            PersonalPathGuard.RequireSingleLinkFile(_path);
        }
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
        byte[]? protectedBytes = null;
        var temporary = Path.Combine(
            _layout.UpdateOperationLockRoot,
            $".personal-install-migration.{Guid.NewGuid():N}.tmp");
        try
        {
            protectedBytes = ProtectedData.Protect(
                plaintext,
                _entropy,
                DataProtectionScope.CurrentUser);
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       16 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(protectedBytes);
                stream.Flush(flushToDisk: true);
            }
            PersonalPathGuard.RequireSingleLinkFile(temporary);
            File.Move(temporary, _path, overwrite: true);
            PersonalPathGuard.RequireSingleLinkFile(_path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    public void Delete()
    {
        _layout.EnsureUpdateOperationLockRoot();
        if (Directory.Exists(_path))
        {
            throw new InvalidDataException(
                "Personal Installer journal path is unexpectedly a directory.");
        }
        if (!File.Exists(_path))
        {
            return;
        }
        PersonalPathGuard.RequireSingleLinkFile(_path);
        File.Delete(_path);
    }

    private void Validate(PersonalInstallMigrationJournalState state)
    {
        var phaseIndex = PersonalInstallMigrationJournalState.PhaseIndex(state.Phase);
        if (state.SchemaVersion != PersonalInstallMigrationJournalState.CurrentSchemaVersion
            || !string.Equals(
                state.Product,
                "Ensou.Dsh.Personal.InstallMigration",
                StringComparison.Ordinal)
            || state.TransactionId.Length != 32
            || !state.TransactionId.All(character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f')
            || phaseIndex < 0
            || state.Status is not PersonalInstallMigrationJournalState.ActiveStatus
                and not PersonalInstallMigrationJournalState.CompletedStatus
                and not PersonalInstallMigrationJournalState.FailedStatus
            || (state.Status == PersonalInstallMigrationJournalState.CompletedStatus)
                != (state.Phase == PersonalInstallMigrationJournalState.CompletedPhase)
            || (state.Status == PersonalInstallMigrationJournalState.FailedStatus)
                != (state.Phase == PersonalInstallMigrationJournalState.HealthFailedPhase)
            || !string.Equals(state.ManagedRoot, _layout.ManagedRoot, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                state.StagingRoot,
                Path.Combine(
                    _layout.UpdateOperationLockRoot,
                    "personal-installer-staging",
                    state.TransactionId),
                StringComparison.OrdinalIgnoreCase)
            || !PersonalPathGuard.IsStrictDescendant(
                state.StagingRoot,
                _layout.UpdateOperationLockRoot)
            || state.InstallMode is not PersonalInstallMigrationJournalState.CleanInstallMode
                and not PersonalInstallMigrationJournalState.LegacyV1MigrationMode
                and not PersonalInstallMigrationJournalState.CertifiedReinstallMode
                and not PersonalInstallMigrationJournalState.ExistingV2UpgradeMode
                and not PersonalInstallMigrationJournalState.ExistingV2RepairMode
            || !PersonalReleaseSetValidator.IsSha256(state.ManifestSha256)
            || !PersonalReleaseSetValidator.IsSha256(state.RawManifestSha256)
            || !PersonalReleaseSetValidator.IsSha256(state.ClientBundleArchiveSha256)
            || !PersonalReleaseSetValidator.IsSha256(state.RuntimeArchiveSha256)
            || state.ClientBundleSizeBytes <= 0
            || state.RuntimeSizeBytes <= 0
            || state.Generation is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || state.Sequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || state.CreatedAtUtc.Offset != TimeSpan.Zero
            || state.UpdatedAtUtc.Offset != TimeSpan.Zero
            || state.UpdatedAtUtc < state.CreatedAtUtc)
        {
            throw new InvalidDataException("Personal Installer journal identity is invalid.");
        }
        PersonalReleaseSetValidator.ValidateChannel(state.Channel);
        PersonalReleaseSetValidator.ValidateReleaseId(state.ReleaseSetId, "journal releaseSetId");
        PersonalReleaseSetValidator.ValidateReleaseId(
            state.ClientBundleReleaseId,
            "journal client releaseId");
        PersonalReleaseSetValidator.ValidateReleaseId(
            state.RuntimeReleaseId,
            "journal runtime releaseId");
        PersonalReleaseVersion.Compare(state.StartupStubVersion, state.StartupStubVersion);
        var hasLegacy = state.LegacyQuarantinePath is not null;
        if ((state.InstallMode == PersonalInstallMigrationJournalState.LegacyV1MigrationMode)
                != hasLegacy
            || hasLegacy
            != (state.LegacyTreeSha256 is not null
                && state.LegacyFileCount is not null
                && state.LegacySizeBytes is not null)
            || hasLegacy && (!PersonalReleaseSetValidator.IsSha256(state.LegacyTreeSha256)
                || state.LegacyFileCount < 0
                || state.LegacySizeBytes < 0)
            || state.LegacyQuarantinePath is not null
                && !string.Equals(
                    state.LegacyQuarantinePath,
                    Path.Combine(
                        Path.GetDirectoryName(_layout.ManagedRoot)!,
                        "DshLauncherLegacyQuarantine",
                        state.TransactionId),
                    StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal Installer legacy quarantine identity is invalid.");
        }
        var hasPreviousStub = state.PreviousStartupStubSha256 is not null
            || state.PreviousStartupStubSizeBytes is not null
            || state.StartupStubBackupPath is not null;
        if (hasPreviousStub
            && (state.PreviousStartupStubSha256 is null
                || state.PreviousStartupStubSizeBytes is null
                || state.StartupStubBackupPath is null
                || !PersonalReleaseSetValidator.IsSha256(
                    state.PreviousStartupStubSha256)
                || state.PreviousStartupStubSizeBytes <= 0
                || !string.Equals(
                    state.StartupStubBackupPath,
                    Path.Combine(state.StagingRoot, "startup-stub.previous.exe"),
                    StringComparison.OrdinalIgnoreCase))
            || state.InstallMode is not PersonalInstallMigrationJournalState.ExistingV2UpgradeMode
                and not PersonalInstallMigrationJournalState.ExistingV2RepairMode
                && hasPreviousStub)
        {
            throw new InvalidDataException(
                "Personal Installer previous Startup Stub identity is invalid.");
        }
        var payloadStaged = phaseIndex >= PersonalInstallMigrationJournalState.PhaseIndex(
            PersonalInstallMigrationJournalState.PayloadStagedPhase);
        if (payloadStaged
            != (state.StartupStubSha256 is not null && state.StartupStubSizeBytes is not null)
            || payloadStaged && (!PersonalReleaseSetValidator.IsSha256(state.StartupStubSha256)
                || state.StartupStubSizeBytes <= 0))
        {
            throw new InvalidDataException(
                "Personal Installer Startup Stub journal identity is invalid.");
        }
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> bytes)
    {
        using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 32,
        });
        RejectDuplicateProperties(document.RootElement, "$journal");
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
                        $"Personal Installer journal contains duplicate property at {path}.");
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

    private static DateTimeOffset RequireUtc(DateTimeOffset value) =>
        value.Offset == TimeSpan.Zero && value > DateTimeOffset.UnixEpoch
            ? value
            : throw new InvalidDataException("Personal Installer journal time must be valid UTC.");

    private DateTimeOffset MonotonicNow(PersonalInstallMigrationJournalState state)
    {
        var observed = RequireUtc(_timeProvider.GetUtcNow());
        return observed >= state.UpdatedAtUtc ? observed : state.UpdatedAtUtc;
    }
}
