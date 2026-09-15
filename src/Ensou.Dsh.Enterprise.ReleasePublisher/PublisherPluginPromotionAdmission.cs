using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

internal sealed record PublisherPluginPromotionPaths(
    string ArchivePath,
    string MetadataPath,
    string CompatibilityReceiptPath,
    string ReservationPath,
    string LedgerPath);

internal sealed record PublisherPluginPromotionSnapshot(
    PublisherPluginPromotionPaths Paths,
    string ArtifactSourcePath,
    string MetadataSourcePath,
    string CompatibilityReceiptSourcePath,
    string ReservationSourcePath,
    string LedgerSourcePath,
    string OrganizationAdmissionReceiptSourcePath,
    string JournalAuthorizationSourcePath,
    PublisherStagedInputFile Handoff,
    PublisherStagedInputFile CompatibilityReceipt,
    PublisherStagedInputFile Reservation,
    PublisherStagedInputFile Ledger,
    PublisherStagedInputFile OrganizationAdmissionReceipt,
    PublisherStagedInputFile? JournalAuthorization);

internal static class PublisherPluginPromotionAdmission
{
    internal const int MaximumHandoffBytes = 4 * 1024 * 1024;
    private const int MaximumEvidenceBytes = 1024 * 1024;
    private const long MaximumJavascriptInteger = 9_007_199_254_740_991;
    private static readonly TimeSpan MaximumReceiptAge = TimeSpan.FromHours(168);
    private static readonly TimeSpan MaximumCompatibilityRunDuration = TimeSpan.FromHours(4);
    private static readonly JsonSerializerOptions StrictJson = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
    private static readonly string[] RequiredObservations =
    [
        "launcherBinarySelfCheck",
        "runtimeHealth",
        "pluginPolicyInstalled",
        "pluginCommandExecuted",
        "managedPolicyEnforced",
        "startupUpdateCheck",
        "rollbackRestoredPreviousRuntime",
        "conversationHistoryPreserved",
        "workspacePreserved",
    ];

    public static PublisherPluginPromotionPaths Discover(byte[] handoffBytes)
    {
        using var document = ParseStrictDocument(
            handoffBytes,
            MaximumHandoffBytes,
            "Plugin promotion handoff");
        var root = document.RootElement;
        RequireProperties(
            root,
            "Plugin promotion handoff",
            "schemaVersion",
            "handoffType",
            "targetEnvironment",
            "promotionStatus",
            "signingStatus",
            "productionSignaturePresent",
            "policy",
            "compatibility",
            "digests",
            "publisherInputTemplate",
            "inputs",
            "harnessCompatibility",
            "generationAdmission",
            "verification",
            "signing");
        var template = root.GetProperty("publisherInputTemplate");
        var harness = root.GetProperty("harnessCompatibility");
        var generation = root.GetProperty("generationAdmission");
        return new PublisherPluginPromotionPaths(
            RequireAbsolutePath(template, "filePath", "Plugin promotion archive path"),
            RequireAbsolutePath(template, "policyMetadataPath", "Plugin promotion metadata path"),
            RequireAbsolutePath(harness, "path", "Plugin compatibility receipt path"),
            RequireAbsolutePath(generation, "reservationPath", "Plugin reservation path"),
            RequireAbsolutePath(generation, "ledgerPath", "Plugin generation ledger path"));
    }

    public static void ValidateProduction(
        PublisherSnapshotArtifact artifact,
        EnterprisePluginPolicyArchiveInspection inspection,
        PublisherPluginPolicyMetadata metadata,
        PublisherSnapshotArtifact launcher,
        PublisherSnapshotArtifact runtime,
        PublisherPluginAdmissionTrust admissionTrust,
        PublisherPluginCompatibilityRunnerTrust runnerTrust,
        DateTimeOffset now)
    {
        var snapshot = artifact.PluginPromotion
            ?? throw new InvalidDataException(
                "Production plugin-policy publication requires a snapshotted promotion handoff.");
        RequireProductionReleaseId(launcher.Input.ReleaseId, "Launcher");
        RequireProductionReleaseId(runtime.Input.ReleaseId, "Runtime");
        RequireProductionReleaseId(artifact.Input.ReleaseId, "Plugin-policy");

        var handoffBytes = snapshot.Handoff.ReadAllBytes(MaximumHandoffBytes);
        using var handoffDocument = ParseStrictDocument(
            handoffBytes,
            MaximumHandoffBytes,
            "Plugin promotion handoff");
        RequireHandoffShape(handoffDocument.RootElement);
        var handoff = Deserialize<PublisherPluginPromotionHandoff>(
            handoffBytes,
            "Plugin promotion handoff");

        RequireSameFileName(snapshot.Paths.ArchivePath, snapshot.ArtifactSourcePath, "handoff archive");
        RequireSameFileName(snapshot.Paths.MetadataPath, snapshot.MetadataSourcePath, "handoff metadata");
        RequireSameFileName(
            snapshot.Paths.CompatibilityReceiptPath,
            snapshot.CompatibilityReceiptSourcePath,
            "compatibility receipt");
        RequireSameFileName(
            snapshot.Paths.ReservationPath,
            snapshot.ReservationSourcePath,
            "generation reservation");
        RequireSameFileName(snapshot.Paths.LedgerPath, snapshot.LedgerSourcePath, "generation ledger");
        RequireExactHandoff(
            handoff,
            artifact,
            snapshot,
            inspection,
            metadata,
            launcher.Input.ReleaseId,
            runtime.Input.ReleaseId);

        var receiptBytes = snapshot.CompatibilityReceipt.ReadAllBytes(MaximumEvidenceBytes);
        using var receiptDocument = ParseStrictDocument(
            receiptBytes,
            MaximumEvidenceBytes,
            "Plugin compatibility receipt");
        RequireReceiptShape(receiptDocument.RootElement);
        var receipt = Deserialize<PublisherPluginCompatibilityReceipt>(
            receiptBytes,
            "Plugin compatibility receipt");
        RequireExactReceipt(
            receipt,
            handoff,
            snapshot,
            inspection,
            launcher,
            runtime,
            runnerTrust,
            now);

        var ledgerBytes = snapshot.Ledger.ReadAllBytes(MaximumEvidenceBytes);
        using var ledgerDocument = ParseStrictDocument(
            ledgerBytes,
            MaximumEvidenceBytes,
            "Plugin generation ledger");
        var ledger = ParseLedgerState(ledgerDocument.RootElement, ledgerBytes);

        var reservationBytes = snapshot.Reservation.ReadAllBytes(MaximumEvidenceBytes);
        using var reservationDocument = ParseStrictDocument(
            reservationBytes,
            MaximumEvidenceBytes,
            "Plugin generation reservation");
        RequireReservationShape(reservationDocument.RootElement);
        var reservation = Deserialize<PublisherPluginGenerationReservation>(
            reservationBytes,
            "Plugin generation reservation");
        RequireExactGenerationAdmission(
            handoff,
            snapshot,
            ledger,
            reservation,
            inspection,
            artifact.Input.ReleaseId,
            artifact.Input.PluginGenerationLedgerNamespace!,
            now);
        var organizationAdmission = PublisherPluginOrganizationAdmissionReceipt.Parse(
            snapshot.OrganizationAdmissionReceipt.ReadAllBytes(MaximumEvidenceBytes));
        organizationAdmission.Verify(
            artifact,
            snapshot,
            inspection,
            launcher,
            runtime,
            receipt,
            handoff,
            ledger,
            admissionTrust,
            now);
    }

    private static void RequireExactHandoff(
        PublisherPluginPromotionHandoff handoff,
        PublisherSnapshotArtifact artifact,
        PublisherPluginPromotionSnapshot snapshot,
        EnterprisePluginPolicyArchiveInspection inspection,
        PublisherPluginPolicyMetadata metadata,
        string launcherReleaseId,
        string runtimeReleaseId)
    {
        if (handoff.SchemaVersion != 2
            || !string.Equals(
                handoff.HandoffType,
                "managed-plugin-policy-publisher-input-template",
                StringComparison.Ordinal)
            || !string.Equals(
                handoff.TargetEnvironment,
                "production-release-candidate",
                StringComparison.Ordinal)
            || !string.Equals(
                handoff.PromotionStatus,
                "UNSIGNED_PUBLISHER_REVIEW_REQUIRED",
                StringComparison.Ordinal)
            || !string.Equals(handoff.SigningStatus, "UNSIGNED_CANDIDATE", StringComparison.Ordinal)
            || handoff.ProductionSignaturePresent
            || handoff.Policy is null
            || !string.Equals(handoff.Policy.PolicyId, inspection.PolicyId, StringComparison.Ordinal)
            || handoff.Policy.Generation != inspection.Generation
            || handoff.Policy.Generation is <= 0 or > MaximumJavascriptInteger
            || handoff.Policy.Critical != inspection.Critical
            || handoff.Policy.Revoked
            || !string.Equals(
                handoff.Policy.RawPolicyFileName,
                EnterprisePluginPolicyContract.PolicyFileName,
                StringComparison.Ordinal)
            || handoff.Policy.RawPolicySizeBytes != inspection.PolicySizeBytes
            || !string.Equals(
                handoff.Policy.RawPolicySha256,
                inspection.PolicySha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Plugin promotion handoff identity or unsigned production state is invalid.");
        }
        if (handoff.Compatibility is null
            || handoff.Compatibility.LauncherReleaseIds is null
            || handoff.Compatibility.RuntimeReleaseIds is null
            || !handoff.Compatibility.LauncherReleaseIds.SequenceEqual(
                inspection.LauncherReleaseIds,
                StringComparer.Ordinal)
            || !handoff.Compatibility.RuntimeReleaseIds.SequenceEqual(
                inspection.RuntimeReleaseIds,
                StringComparer.Ordinal)
            || !handoff.Compatibility.LauncherReleaseIds.Contains(
                launcherReleaseId,
                StringComparer.Ordinal)
            || !handoff.Compatibility.RuntimeReleaseIds.Contains(
                runtimeReleaseId,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Plugin promotion handoff compatibility does not exactly match the validated policy or include the selected Launcher/runtime tuple.");
        }
        if (handoff.Digests is null
            || !string.Equals(handoff.Digests.ArchiveSha256, artifact.File.Sha256, StringComparison.Ordinal)
            || handoff.Digests.ArchiveSizeBytes != artifact.File.Length
            || artifact.PolicyMetadata is null
            || !string.Equals(
                handoff.Digests.MetadataSha256,
                artifact.PolicyMetadata.Sha256,
                StringComparison.Ordinal)
            || handoff.Digests.MetadataSizeBytes != artifact.PolicyMetadata.Length
            || !string.Equals(
                handoff.Digests.RawPolicySha256,
                inspection.PolicySha256,
                StringComparison.Ordinal)
            || handoff.Digests.RawPolicySizeBytes != inspection.PolicySizeBytes)
        {
            throw new InvalidDataException(
                "Plugin promotion handoff digests do not match the immutable candidate snapshot.");
        }
        var template = handoff.PublisherInputTemplate;
        if (template is null
            || !template.TemplateOnly
            || template.DirectlyConsumable
            || !string.Equals(
                template.Component,
                EnterpriseReleaseSetContract.PluginPolicyComponent,
                StringComparison.Ordinal)
            || !string.Equals(template.FilePath, snapshot.Paths.ArchivePath, StringComparison.Ordinal)
            || !string.Equals(
                template.PolicyMetadataPath,
                snapshot.Paths.MetadataPath,
                StringComparison.Ordinal)
            || !string.Equals(template.FileName, Path.GetFileName(snapshot.ArtifactSourcePath), StringComparison.Ordinal)
            || !string.Equals(
                template.MetadataFileName,
                Path.GetFileName(snapshot.MetadataSourcePath),
                StringComparison.Ordinal)
            || !string.Equals(
                template.SigningStatusRequired,
                "UNSIGNED_CANDIDATE",
                StringComparison.Ordinal)
            || template.ReleaseId is not null
            || template.Uri is not null
            || !template.RequiresReleasePublisherId
            || !template.RequiresHttpsUri
            || !template.RequiresIndependentPublisherRevalidation)
        {
            throw new InvalidDataException(
                "Plugin promotion publisherInputTemplate is directly consumable or incomplete.");
        }
        if (artifact.Input.Uri.Scheme != Uri.UriSchemeHttps
            || string.IsNullOrWhiteSpace(artifact.Input.ReleaseId))
        {
            throw new InvalidDataException(
                "Publisher config must independently supply plugin releaseId and HTTPS URI.");
        }
        RequireExactInputs(handoff.Inputs, metadata.Inputs);
        RequireVerification(handoff.Verification);
        if (metadata.Inputs.Any(input => !string.Equals(
                input.Source.Commit,
                handoff.Verification.HeadCommit,
                StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Plugin promotion verification HEAD differs from policy input source commits.");
        }
        if (IsSameOrDescendant(
                snapshot.CompatibilityReceiptSourcePath,
                handoff.Verification.RepositoryRoot)
            || IsSameOrDescendant(
                snapshot.LedgerSourcePath,
                handoff.Verification.RepositoryRoot)
            || IsSameOrDescendant(
                snapshot.ReservationSourcePath,
                handoff.Verification.RepositoryRoot)
            || IsSameOrDescendant(
                snapshot.OrganizationAdmissionReceiptSourcePath,
                handoff.Verification.RepositoryRoot))
        {
            throw new InvalidDataException(
                "Production plugin receipt and generation admission state must be external to the plugin source repository.");
        }
        if (handoff.Signing is null
            || !string.Equals(handoff.Signing.Status, "UNSIGNED_CANDIDATE", StringComparison.Ordinal)
            || handoff.Signing.PrivateKeyUsed
            || string.IsNullOrWhiteSpace(handoff.Signing.SignerActionRequired))
        {
            throw new InvalidDataException("Plugin promotion signing handoff is invalid.");
        }
    }

    private static void RequireExactReceipt(
        PublisherPluginCompatibilityReceipt receipt,
        PublisherPluginPromotionHandoff handoff,
        PublisherPluginPromotionSnapshot snapshot,
        EnterprisePluginPolicyArchiveInspection inspection,
        PublisherSnapshotArtifact launcher,
        PublisherSnapshotArtifact runtime,
        PublisherPluginCompatibilityRunnerTrust runnerTrust,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(runnerTrust);
        runnerTrust.Validate();
        var producerId = ParseCanonicalUuid(receipt.Producer?.TestRunId, "receipt producer testRunId");
        var started = ParseCanonicalUtc(receipt.StartedAtUtc, "receipt startedAtUtc");
        var observed = ParseCanonicalUtc(receipt.ObservedAtUtc, "receipt observedAtUtc");
        if (started > observed
            || observed - started > MaximumCompatibilityRunDuration
            || observed > now.AddMinutes(5)
            || now - observed > MaximumReceiptAge)
        {
            throw new InvalidDataException(
                "Plugin compatibility receipt timing is invalid, future-dated, or older than 168 hours.");
        }
        if (receipt.SchemaVersion != 1
            || !string.Equals(
                receipt.ReceiptType,
                "managed-plugin-harness-compatibility",
                StringComparison.Ordinal)
            || receipt.Producer is null
            || !string.Equals(
                receipt.Producer.Component,
                "Ensou.Dsh.EnterprisePluginCompatibilityRunner",
                StringComparison.Ordinal)
            || !string.Equals(receipt.Producer.TestRunId, producerId, StringComparison.Ordinal)
            || !string.Equals(
                receipt.Producer.FileName,
                "Ensou.Dsh.EnterprisePluginCompatibilityRunner.exe",
                StringComparison.Ordinal)
            || receipt.Producer.SizeBytes <= 0
            || !string.Equals(
                receipt.Producer.Sha256,
                runnerTrust.Sha256,
                StringComparison.Ordinal)
            || !string.Equals(receipt.Result, "PASS", StringComparison.Ordinal)
            || !string.Equals(
                receipt.LauncherReleaseId,
                launcher.Input.ReleaseId,
                StringComparison.Ordinal)
            || receipt.LauncherArtifact is null
            || !string.Equals(
                receipt.LauncherArtifact.FileName,
                Path.GetFileName(launcher.Input.FilePath),
                StringComparison.Ordinal)
            || receipt.LauncherArtifact.SizeBytes != launcher.File.Length
            || !string.Equals(
                receipt.LauncherArtifact.Sha256,
                launcher.File.Sha256,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.RuntimeReleaseId,
                runtime.Input.ReleaseId,
                StringComparison.Ordinal)
            || receipt.RuntimeArtifact is null
            || !string.Equals(
                receipt.RuntimeArtifact.FileName,
                Path.GetFileName(runtime.Input.FilePath),
                StringComparison.Ordinal)
            || receipt.RuntimeArtifact.SizeBytes != runtime.File.Length
            || !string.Equals(
                receipt.RuntimeArtifact.Sha256,
                runtime.File.Sha256,
                StringComparison.Ordinal)
            || runtime.SourceRuntimeMetadata is null
            || !string.Equals(
                receipt.RuntimeArtifact.SourceMetadataSha256,
                runtime.SourceRuntimeMetadata.Sha256,
                StringComparison.Ordinal)
            || !string.Equals(receipt.HarnessSourceTag, "dsh-v0.1.2-rc.1", StringComparison.Ordinal)
            || receipt.Policy is null
            || !string.Equals(receipt.Policy.PolicyId, inspection.PolicyId, StringComparison.Ordinal)
            || receipt.Policy.Generation != inspection.Generation
            || !string.Equals(receipt.Policy.ArchiveSha256, inspection.ArchiveSha256, StringComparison.Ordinal)
            || handoff.Digests is null
            || !string.Equals(
                receipt.Policy.MetadataSha256,
                handoff.Digests.MetadataSha256,
                StringComparison.Ordinal)
            || !string.Equals(receipt.Policy.RawPolicySha256, inspection.PolicySha256, StringComparison.Ordinal)
            || !PublisherPluginPolicyMetadata.IsLowercaseSha256(
                receipt.Policy.ExecutionAdmissionReceiptSha256))
        {
            throw new InvalidDataException(
                "Plugin compatibility receipt does not bind the exact production candidate tuple.");
        }
        RequireCompletePluginObservations(receipt.Plugins, inspection.SkillPacks);
        if (receipt.Observations is null || receipt.Observations.Count != RequiredObservations.Length)
        {
            throw new InvalidDataException(
                "Plugin compatibility receipt observations are incomplete or unexpected.");
        }
        foreach (var name in RequiredObservations)
        {
            if (!receipt.Observations.TryGetValue(name, out var status)
                || !string.Equals(status, "PASS", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Plugin compatibility receipt observation is not PASS: {name}.");
            }
        }
        var harness = handoff.HarnessCompatibility;
        if (harness is null
            || !string.Equals(harness.Status, "EXTERNAL_RECEIPT_VALIDATED", StringComparison.Ordinal)
            || !PathEquals(harness.Path, snapshot.Paths.CompatibilityReceiptPath)
            || !string.Equals(
                harness.Sha256,
                snapshot.CompatibilityReceipt.Sha256,
                StringComparison.Ordinal)
            || harness.SizeBytes != snapshot.CompatibilityReceipt.Length
            || !string.Equals(harness.ObservedAtUtc, receipt.ObservedAtUtc, StringComparison.Ordinal)
            || !string.Equals(harness.TestRunId, receipt.Producer.TestRunId, StringComparison.Ordinal)
            || !string.Equals(harness.HarnessSourceTag, receipt.HarnessSourceTag, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Plugin promotion handoff compatibility evidence differs from the receipt snapshot.");
        }

    }

    private static void RequireCompletePluginObservations(
        IReadOnlyList<PublisherPluginCompatibilityPluginObservation>? actual,
        IReadOnlyList<EnterprisePluginSkillPackInspection> expected)
    {
        if (actual is null
            || actual.Count != expected.Count
            || actual.Count is <= 0 or > 256
            || actual.Select(value => value.SkillId)
                .Distinct(StringComparer.Ordinal)
                .Count() != actual.Count)
        {
            throw new InvalidDataException(
                "Plugin compatibility receipt does not cover every managed skill pack exactly once.");
        }
        var ordered = actual.OrderBy(value => value.SkillId, StringComparer.Ordinal).ToArray();
        for (var index = 0; index < expected.Count; index++)
        {
            var observation = ordered[index];
            var skill = expected[index];
            if (!string.Equals(observation.SkillId, skill.SkillId, StringComparison.Ordinal)
                || !string.Equals(observation.Version, skill.Version, StringComparison.Ordinal)
                || !string.Equals(observation.Root, skill.Root, StringComparison.Ordinal)
                || !string.Equals(
                    observation.DeclaredTreeSha256,
                    skill.DeclaredTreeSha256,
                    StringComparison.Ordinal)
                || !string.Equals(observation.CommandExecuted, "PASS", StringComparison.Ordinal)
                || !string.Equals(
                    observation.ManagedPolicyEnforced,
                    "PASS",
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Plugin compatibility receipt skill observation is incomplete or drifted: {skill.SkillId}.");
            }
        }
    }

    private static void RequireExactGenerationAdmission(
        PublisherPluginPromotionHandoff handoff,
        PublisherPluginPromotionSnapshot snapshot,
        PublisherPluginGenerationLedgerState ledger,
        PublisherPluginGenerationReservation reservation,
        EnterprisePluginPolicyArchiveInspection inspection,
        string pluginReleaseId,
        string trustedLedgerNamespace,
        DateTimeOffset now)
    {
        var generation = handoff.GenerationAdmission
            ?? throw new InvalidDataException("Plugin generation admission is missing.");
        if (ledger.SchemaVersion != 2
            || !string.Equals(ledger.PolicyId, inspection.PolicyId, StringComparison.Ordinal)
            || ledger.HighestPromotedGeneration < 0
            || ledger.HighestPromotedGeneration > MaximumJavascriptInteger
            || ledger.HighestPromotedGeneration > inspection.Generation
            || generation.ObservedHighestPromotedGeneration < 0
            || generation.ObservedHighestPromotedGeneration >= inspection.Generation
            || !PublisherPluginPolicyMetadata.IsLowercaseSha256(generation.LedgerSha256)
            || generation.CandidateGeneration != inspection.Generation
            || !PathEquals(generation.LedgerPath, snapshot.Paths.LedgerPath))
        {
            throw new InvalidDataException(
                "Plugin generation ledger does not prove a monotonic candidate generation.");
        }
        if (ledger.SchemaVersion == 2
            && (!string.Equals(
                    ledger.Namespace,
                    trustedLedgerNamespace,
                    StringComparison.Ordinal)
                || (ledger.HighestPromotedGeneration == 0
                    && ledger.HighestPromotedCandidate is not null)
                || (ledger.HighestPromotedGeneration > 0
                    && (ledger.HighestPromotedCandidate is null
                        || ledger.HighestPromotedCandidate.Generation
                            != ledger.HighestPromotedGeneration))))
        {
            throw new InvalidDataException(
                "Plugin generation ledger v2 namespace or highest candidate is invalid.");
        }
        if (ledger.HighestPromotedCandidate is not null)
        {
            var previous = ledger.HighestPromotedCandidate;
            RequireProductionReleaseId(previous.PluginReleaseId, "Prior plugin-policy");
            if (!PublisherPluginPolicyMetadata.IsLowercaseSha256(previous.ArchiveSha256)
                || !PublisherPluginPolicyMetadata.IsLowercaseSha256(previous.MetadataSha256)
                || !PublisherPluginPolicyMetadata.IsLowercaseSha256(previous.RawPolicySha256)
                || !PublisherPluginPolicyMetadata.IsLowercaseSha256(
                    previous.PromotionHandoffSha256)
                || !PublisherPluginPolicyMetadata.IsLowercaseSha256(
                    previous.CompatibilityReceiptSha256)
                || !PublisherPluginPolicyMetadata.IsLowercaseSha256(previous.ReservationSha256)
                || !PublisherPluginPolicyMetadata.IsLowercaseSha256(
                    previous.OrganizationAdmissionReceiptSha256)
                || ParseCanonicalUtc(
                    previous.FirstPublishedAtUtc,
                    "generation ledger firstPublishedAtUtc") > now.AddMinutes(5))
            {
                throw new InvalidDataException(
                    "Plugin generation ledger prior candidate identity is invalid.");
            }
        }
        if (ledger.HighestPromotedGeneration < inspection.Generation)
        {
            if (ledger.HighestPromotedGeneration != generation.ObservedHighestPromotedGeneration
                || !string.Equals(
                    generation.LedgerSha256,
                    snapshot.Ledger.Sha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Plugin generation handoff does not bind the current pre-promotion ledger bytes.");
            }
        }
        else
        {
            var candidate = ledger.HighestPromotedCandidate;
            if (candidate is null
                || !string.Equals(candidate.PluginReleaseId, pluginReleaseId, StringComparison.Ordinal)
                || !string.Equals(candidate.ArchiveSha256, inspection.ArchiveSha256, StringComparison.Ordinal)
                || handoff.Digests is null
                || !string.Equals(
                    candidate.MetadataSha256,
                    handoff.Digests.MetadataSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    candidate.RawPolicySha256,
                    inspection.PolicySha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    candidate.PromotionHandoffSha256,
                    snapshot.Handoff.Sha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    candidate.CompatibilityReceiptSha256,
                    snapshot.CompatibilityReceipt.Sha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    candidate.ReservationSha256,
                    snapshot.Reservation.Sha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    candidate.OrganizationAdmissionReceiptSha256,
                    snapshot.OrganizationAdmissionReceipt.Sha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Plugin generation replay differs from the exact previously promoted candidate.");
            }
        }
        var expectedClaimedReservationPath = Path.Combine(
            Path.GetDirectoryName(snapshot.Paths.LedgerPath)
                ?? throw new InvalidDataException("Plugin generation ledger has no parent."),
            $"{Path.GetFileName(snapshot.Paths.LedgerPath)}.reservations.v1",
            $"managed-plugin-policy-{inspection.PolicyId}-g{inspection.Generation}.reservation.json");
        var expectedSourceReservationPath = Path.Combine(
            Path.GetDirectoryName(snapshot.LedgerSourcePath)
                ?? throw new InvalidDataException("Trusted plugin generation ledger has no parent."),
            $"{Path.GetFileName(snapshot.LedgerSourcePath)}.reservations.v1",
            $"managed-plugin-policy-{inspection.PolicyId}-g{inspection.Generation}.reservation.json");
        if (!PathEquals(expectedClaimedReservationPath, snapshot.Paths.ReservationPath)
            || !PathEquals(expectedSourceReservationPath, snapshot.ReservationSourcePath)
            || !PathEquals(generation.ReservationPath, snapshot.Paths.ReservationPath)
            || !string.Equals(
                generation.ReservationSha256,
                snapshot.Reservation.Sha256,
                StringComparison.Ordinal)
            || generation.ReservationSizeBytes != snapshot.Reservation.Length
            || !string.Equals(
                generation.Decision,
                "EXCLUSIVELY_RESERVED_UNSIGNED_CANDIDATE",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Plugin generation reservation path, bytes, or decision is invalid.");
        }
        var created = ParseCanonicalUtc(reservation.CreatedAtUtc, "reservation createdAtUtc");
        if (created > now.AddMinutes(5) || now - created > MaximumReceiptAge
            || reservation.SchemaVersion != 1
            || !string.Equals(
                reservation.ReservationType,
                "managed-plugin-policy-generation",
                StringComparison.Ordinal)
            || !string.Equals(
                reservation.ReservationStatus,
                "EXCLUSIVE_UNSIGNED_CANDIDATE_RESERVATION",
                StringComparison.Ordinal)
            || !string.Equals(reservation.PolicyId, inspection.PolicyId, StringComparison.Ordinal)
            || reservation.Generation != inspection.Generation
            || !string.Equals(
                reservation.TargetEnvironment,
                "production-release-candidate",
                StringComparison.Ordinal)
            || reservation.Digests is null
            || !string.Equals(
                reservation.Digests.ArchiveSha256,
                inspection.ArchiveSha256,
                StringComparison.Ordinal)
            || artifactMetadataDigestMismatch(reservation.Digests.MetadataSha256, handoff)
            || !string.Equals(
                reservation.Digests.RawPolicySha256,
                inspection.PolicySha256,
                StringComparison.Ordinal)
            || !string.Equals(
                reservation.HarnessCompatibilityReceiptSha256,
                snapshot.CompatibilityReceipt.Sha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Plugin generation reservation does not bind the exact fresh production tuple.");
        }

        static bool artifactMetadataDigestMismatch(
            string? digest,
            PublisherPluginPromotionHandoff value) =>
            value.Digests is null
            || !string.Equals(digest, value.Digests.MetadataSha256, StringComparison.Ordinal);
    }

    private static void RequireExactInputs(
        IReadOnlyList<PublisherPluginHandoffInput>? handoffInputs,
        IReadOnlyList<PublisherPluginPolicyInput> metadataInputs)
    {
        if (handoffInputs is null || handoffInputs.Count != metadataInputs.Count)
        {
            throw new InvalidDataException(
                "Plugin promotion input provenance count differs from policy metadata.");
        }
        for (var index = 0; index < metadataInputs.Count; index++)
        {
            var actual = handoffInputs[index];
            var expected = metadataInputs[index];
            if (!string.Equals(actual.Kind, expected.Kind, StringComparison.Ordinal)
                || !string.Equals(actual.Id, expected.Id, StringComparison.Ordinal)
                || !string.Equals(actual.Version, expected.Version, StringComparison.Ordinal)
                || !SameInputFile(actual.Artifact, expected.Artifact)
                || !SameInputFile(actual.Metadata, expected.Metadata)
                || actual.Source is null
                || !string.Equals(actual.Source.Commit, expected.Source.Commit, StringComparison.Ordinal)
                || !string.Equals(actual.Source.Tree, expected.Source.Tree, StringComparison.Ordinal)
                || !string.Equals(actual.Source.BuilderBlob, expected.Source.BuilderBlob, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Plugin promotion input provenance differs from policy metadata.");
            }
        }

        static bool SameInputFile(
            PublisherPluginHandoffInputFile? actual,
            PublisherPluginPolicyInputFile expected) =>
            actual is not null
            && string.Equals(actual.FileName, expected.FileName, StringComparison.Ordinal)
            && actual.SizeBytes == expected.SizeBytes
            && string.Equals(actual.Sha256, expected.Sha256, StringComparison.Ordinal);
    }

    private static void RequireVerification(PublisherPluginPromotionVerification? verification)
    {
        if (verification is null
            || !string.Equals(
                verification.Status,
                "UNSIGNED_CANDIDATE_CONTRACTS_VERIFIED",
                StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(verification.RepositoryRoot)
            || !Path.IsPathFullyQualified(verification.RepositoryRoot)
            || !PublisherPluginPolicyMetadata.IsGitObjectId(verification.HeadCommit)
            || !verification.RepositoryClean
            || !verification.RelevantSourcePathsClean
            || verification.WorkingTreeOverrideUsed
            || !string.Equals(
                verification.SkillArtifactVerification,
                "VERIFIED_BY_TEST_MANAGED_ARTIFACT",
                StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(verification.PolicyTest))
        {
            throw new InvalidDataException("Plugin promotion verification state is invalid.");
        }
        RequireScript(verification.PolicyTestScript, "policy test script");
        RequireScript(verification.PolicyBuilderScript, "policy builder script");
        RequireScript(verification.HandoffScript, "handoff script");
        RequireScript(verification.SkillArtifactTestScript, "skill artifact test script");
        RequireScript(verification.CompatibilityReceiptTestScript, "compatibility receipt test script");
        RequireScript(verification.GenerationReservationScript, "generation reservation script");
        foreach (var script in new[]
        {
            verification.PolicyTestScript,
            verification.PolicyBuilderScript,
            verification.HandoffScript,
            verification.SkillArtifactTestScript,
            verification.CompatibilityReceiptTestScript,
            verification.GenerationReservationScript,
        })
        {
            if (!IsSameOrDescendant(script.Path, verification.RepositoryRoot))
            {
                throw new InvalidDataException(
                    "Plugin promotion verifier script path is outside the reviewed repository root.");
            }
        }
    }

    private static void RequireScript(PublisherPluginPromotionScript? script, string label)
    {
        if (script is null
            || string.IsNullOrWhiteSpace(script.Path)
            || !Path.IsPathFullyQualified(script.Path)
            || !PublisherPluginPolicyMetadata.IsLowercaseSha256(script.Sha256))
        {
            throw new InvalidDataException($"Plugin promotion {label} evidence is invalid.");
        }
    }

    private static void RequireHandoffShape(JsonElement root)
    {
        RequireProperties(root, "Plugin promotion handoff",
            "schemaVersion", "handoffType", "targetEnvironment", "promotionStatus",
            "signingStatus", "productionSignaturePresent", "policy", "compatibility",
            "digests", "publisherInputTemplate", "inputs", "harnessCompatibility",
            "generationAdmission", "verification", "signing");
        RequireProperties(root.GetProperty("policy"), "Plugin promotion policy",
            "policyId", "generation", "critical", "revoked", "rawPolicyFileName",
            "rawPolicySizeBytes", "rawPolicySha256");
        RequireProperties(root.GetProperty("compatibility"), "Plugin promotion compatibility",
            "launcherReleaseIds", "runtimeReleaseIds");
        RequireProperties(root.GetProperty("digests"), "Plugin promotion digests",
            "archiveSha256", "archiveSizeBytes", "metadataSha256", "metadataSizeBytes",
            "rawPolicySha256", "rawPolicySizeBytes");
        RequireProperties(root.GetProperty("publisherInputTemplate"), "Plugin publisher template",
            "templateOnly", "directlyConsumable", "component", "filePath",
            "policyMetadataPath", "fileName", "metadataFileName", "signingStatusRequired",
            "releaseId", "uri", "requiresReleasePublisherId", "requiresHttpsUri",
            "requiresIndependentPublisherRevalidation");
        var inputs = root.GetProperty("inputs");
        if (inputs.ValueKind != JsonValueKind.Array || inputs.GetArrayLength() is <= 0 or > 256)
        {
            throw new InvalidDataException("Plugin promotion inputs are invalid.");
        }
        foreach (var input in inputs.EnumerateArray())
        {
            RequireProperties(input, "Plugin promotion input",
                "kind", "id", "version", "artifact", "metadata", "source");
            RequireProperties(input.GetProperty("artifact"), "Plugin promotion input artifact",
                "fileName", "sizeBytes", "sha256");
            RequireProperties(input.GetProperty("metadata"), "Plugin promotion input metadata",
                "fileName", "sizeBytes", "sha256");
            RequireProperties(input.GetProperty("source"), "Plugin promotion input source",
                "commit", "tree", "builderBlob");
        }
        RequireProperties(root.GetProperty("harnessCompatibility"), "Plugin harness compatibility",
            "status", "path", "sha256", "sizeBytes", "observedAtUtc", "testRunId",
            "harnessSourceTag");
        RequireProperties(root.GetProperty("generationAdmission"), "Plugin generation admission",
            "ledgerPath", "ledgerSha256", "observedHighestPromotedGeneration",
            "candidateGeneration", "reservationPath", "reservationSha256",
            "reservationSizeBytes", "decision");
        var verification = root.GetProperty("verification");
        RequireProperties(verification, "Plugin promotion verification",
            "status", "repositoryRoot", "headCommit", "repositoryClean",
            "relevantSourcePathsClean", "workingTreeOverrideUsed", "policyTestScript",
            "policyBuilderScript", "handoffScript", "skillArtifactTestScript",
            "compatibilityReceiptTestScript", "generationReservationScript",
            "skillArtifactVerification", "policyTest");
        foreach (var name in new[]
        {
            "policyTestScript", "policyBuilderScript", "handoffScript",
            "skillArtifactTestScript", "compatibilityReceiptTestScript",
            "generationReservationScript",
        })
        {
            RequireProperties(verification.GetProperty(name), $"Plugin promotion {name}",
                "path", "sha256");
        }
        RequireProperties(root.GetProperty("signing"), "Plugin promotion signing",
            "status", "privateKeyUsed", "signerActionRequired");
    }

    private static void RequireReceiptShape(JsonElement root)
    {
        RequireProperties(root, "Plugin compatibility receipt",
            "schemaVersion", "receiptType", "producer", "result", "startedAtUtc", "observedAtUtc",
            "launcherReleaseId", "launcherArtifact", "runtimeReleaseId", "runtimeArtifact",
            "harnessSourceTag", "policy", "plugins", "observations");
        RequireProperties(root.GetProperty("producer"), "Plugin compatibility producer",
            "component", "testRunId", "fileName", "sizeBytes", "sha256");
        RequireProperties(root.GetProperty("policy"), "Plugin compatibility policy",
            "policyId", "generation", "archiveSha256", "metadataSha256",
            "rawPolicySha256", "executionAdmissionReceiptSha256");
        RequireProperties(root.GetProperty("launcherArtifact"), "Plugin compatibility Launcher artifact",
            "fileName", "sizeBytes", "sha256");
        RequireProperties(root.GetProperty("runtimeArtifact"), "Plugin compatibility runtime artifact",
            "fileName", "sizeBytes", "sha256", "sourceMetadataSha256");
        var plugins = root.GetProperty("plugins");
        if (plugins.ValueKind != JsonValueKind.Array || plugins.GetArrayLength() is <= 0 or > 256)
        {
            throw new InvalidDataException("Plugin compatibility skill observations are invalid.");
        }
        foreach (var plugin in plugins.EnumerateArray())
        {
            RequireProperties(plugin, "Plugin compatibility skill observation",
                "skillId", "version", "root", "declaredTreeSha256",
                "commandExecuted", "managedPolicyEnforced");
        }
        RequireProperties(root.GetProperty("observations"), "Plugin compatibility observations",
            RequiredObservations);
    }

    private static void RequireReservationShape(JsonElement root)
    {
        RequireProperties(root, "Plugin generation reservation",
            "schemaVersion", "reservationType", "reservationStatus", "policyId",
            "generation", "targetEnvironment", "digests",
            "harnessCompatibilityReceiptSha256", "createdAtUtc");
        RequireProperties(root.GetProperty("digests"), "Plugin reservation digests",
            "archiveSha256", "metadataSha256", "rawPolicySha256");
    }

    private static PublisherPluginGenerationLedgerState ParseLedgerState(
        JsonElement root,
        byte[] bytes)
    {
        var schemaVersion = root.GetProperty("schemaVersion").GetInt32();
        if (schemaVersion == 1)
        {
            RequireProperties(root, "Plugin generation ledger",
                "schemaVersion", "policyId", "highestPromotedGeneration");
            var ledger = Deserialize<PublisherPluginGenerationLedgerV1>(
                bytes,
                "Plugin generation ledger v1");
            return new PublisherPluginGenerationLedgerState(
                ledger.SchemaVersion,
                null,
                ledger.PolicyId,
                ledger.HighestPromotedGeneration,
                null);
        }
        if (schemaVersion == 2)
        {
            RequireProperties(root, "Plugin generation ledger",
                "schemaVersion", "ledgerType", "namespace", "policyId",
                "highestPromotedGeneration", "highestPromotedCandidate");
            if (root.GetProperty("highestPromotedCandidate").ValueKind != JsonValueKind.Null)
            {
                RequireProperties(
                    root.GetProperty("highestPromotedCandidate"),
                    "Plugin generation ledger highest candidate",
                    "generation", "pluginReleaseId", "archiveSha256", "metadataSha256",
                    "rawPolicySha256", "promotionHandoffSha256",
                    "compatibilityReceiptSha256", "reservationSha256",
                    "organizationAdmissionReceiptSha256", "firstPublishedAtUtc");
            }
            var ledger = Deserialize<PublisherPluginGenerationLedgerV2>(
                bytes,
                "Plugin generation ledger v2");
            if (!string.Equals(
                ledger.LedgerType,
                "managed-plugin-policy-generation",
                StringComparison.Ordinal))
            {
                throw new InvalidDataException("Plugin generation ledger v2 type is invalid.");
            }
            return new PublisherPluginGenerationLedgerState(
                ledger.SchemaVersion,
                ledger.Namespace,
                ledger.PolicyId,
                ledger.HighestPromotedGeneration,
                ledger.HighestPromotedCandidate);
        }
        throw new InvalidDataException("Plugin generation ledger schema version is unsupported.");
    }

    internal static PublisherPluginGenerationLedgerState ParseLedgerState(byte[] bytes)
    {
        using var document = ParseStrictDocument(
            bytes,
            MaximumEvidenceBytes,
            "Plugin generation ledger");
        return ParseLedgerState(document.RootElement, bytes);
    }

    private static JsonDocument ParseStrictDocument(byte[] bytes, int maximumBytes, string label)
    {
        if (bytes.Length is <= 0 || bytes.Length > maximumBytes)
        {
            throw new InvalidDataException($"{label} size is invalid.");
        }
        try
        {
            _ = new UTF8Encoding(false, true).GetString(bytes);
            var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32,
            });
            RequireNoDuplicateMembers(document.RootElement, label);
            return document;
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException)
        {
            throw new InvalidDataException($"{label} is not strict UTF-8 JSON.", exception);
        }
    }

    private static T Deserialize<T>(byte[] bytes, string label)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(bytes, StrictJson)
                ?? throw new InvalidDataException($"{label} is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"{label} does not match its exact schema.", exception);
        }
    }

    private static void RequireProperties(JsonElement element, string label, params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.EnumerateObject().Select(value => value.Name).SequenceEqual(
                expected,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException($"{label} properties are absent, reordered, or unexpected.");
        }
    }

    private static void RequireNoDuplicateMembers(JsonElement element, string label)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException($"{label} contains duplicate JSON members.");
                }
                RequireNoDuplicateMembers(property.Value, label);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                RequireNoDuplicateMembers(item, label);
            }
        }
    }

    private static string RequireAbsolutePath(JsonElement owner, string property, string label)
    {
        var value = owner.GetProperty(property).GetString();
        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathFullyQualified(value))
        {
            throw new InvalidDataException($"{label} must be absolute.");
        }
        return Path.GetFullPath(value);
    }

    private static void RequireSameFileName(string claimed, string actual, string label)
    {
        if (!string.Equals(
            Path.GetFileName(claimed),
            Path.GetFileName(actual),
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Plugin promotion {label} filename differs from the portable publisher input.");
        }
    }

    private static bool PathEquals(string first, string second) =>
        Path.GetFullPath(first).Equals(Path.GetFullPath(second), StringComparison.OrdinalIgnoreCase);

    private static bool IsSameOrDescendant(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return fullPath.Equals(fullRoot, StringComparison.OrdinalIgnoreCase)
            || fullPath.StartsWith(
                fullRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
    }

    private static string ParseCanonicalUuid(string? value, string label)
    {
        if (!Guid.TryParseExact(value, "D", out var parsed)
            || !string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Plugin {label} is not a canonical UUID.");
        }
        return parsed.ToString("D");
    }

    private static DateTimeOffset ParseCanonicalUtc(string? value, string label)
    {
        if (value is null
            || !DateTimeOffset.TryParseExact(
                value,
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed)
            || !string.Equals(
                value,
                parsed.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Plugin {label} is not canonical whole-second UTC.");
        }
        return parsed;
    }

    private static void RequireProductionReleaseId(string value, string component)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 128
            || !char.IsAsciiLetterOrDigit(value[0])
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '+' and not '-'))
        {
            throw new InvalidDataException($"{component} production release ID is unsafe.");
        }
        var lower = value.ToLowerInvariant();
        string[] rejected =
        [
            "placeholder", "example", "fixture", "dummy", "fake", "mock", "sample",
            "unknown", "todo", "test", "localhost", "development", "e2e", "staging",
            "preview", "local",
        ];
        if (rejected.Any(lower.Contains)
            || lower.Equals("exact", StringComparison.Ordinal)
            || lower.Contains("exact-", StringComparison.Ordinal)
            || lower.Contains("exact_", StringComparison.Ordinal)
            || lower.Contains("exact.", StringComparison.Ordinal)
            || lower.Contains("cicontract", StringComparison.Ordinal)
            || lower.Contains("ci-contract", StringComparison.Ordinal)
            || lower.Contains("ci_contract", StringComparison.Ordinal)
            || lower.Contains("ci.contract", StringComparison.Ordinal)
            || ContainsDelimitedToken(lower, "dev"))
        {
            throw new InvalidDataException($"{component} release ID is not production immutable.");
        }

        static bool ContainsDelimitedToken(string source, string token)
        {
            for (var index = 0; index <= source.Length - token.Length; index++)
            {
                if (!source.AsSpan(index, token.Length).SequenceEqual(token.AsSpan()))
                {
                    continue;
                }
                var before = index == 0 || source[index - 1] is '-' or '_' or '.';
                var after = index + token.Length == source.Length
                    || source[index + token.Length] is '-' or '_' or '.';
                if (before && after)
                {
                    return true;
                }
            }
            return false;
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginOrganizationAdmissionReceipt
{
    public const int CurrentSchemaVersion = 1;
    public const string CurrentReceiptType = "ensou-dsh-plugin-organization-admission";
    public const string AdmittedDecision = "admitted";
    public const string LedgerTypeNamespace = "managed-plugin-policy-generation";

    public required int SchemaVersion { get; init; }
    public required string ReceiptType { get; init; }
    public required string Decision { get; init; }
    public required long ReviewedAtUnixSeconds { get; init; }
    public required string CompatibilityTestRunId { get; init; }
    public required string PolicyId { get; init; }
    public required long Generation { get; init; }
    public required bool Critical { get; init; }
    public required string PluginReleaseId { get; init; }
    public required string ArchiveSha256 { get; init; }
    public required long ArchiveSizeBytes { get; init; }
    public required string MetadataSha256 { get; init; }
    public required long MetadataSizeBytes { get; init; }
    public required string RawPolicySha256 { get; init; }
    public required long RawPolicySizeBytes { get; init; }
    public required string LauncherReleaseId { get; init; }
    public required string LauncherArchiveSha256 { get; init; }
    public required long LauncherArchiveSizeBytes { get; init; }
    public required string RuntimeReleaseId { get; init; }
    public required string RuntimeArchiveSha256 { get; init; }
    public required long RuntimeArchiveSizeBytes { get; init; }
    public required string RuntimeSourceMetadataSha256 { get; init; }
    public required string HarnessSourceTag { get; init; }
    public required string CompatibilityReceiptSha256 { get; init; }
    public required long CompatibilityReceiptSizeBytes { get; init; }
    public required string CompatibilityObservedAtUtc { get; init; }
    public required string PromotionHandoffSha256 { get; init; }
    public required long PromotionHandoffSizeBytes { get; init; }
    public required string ReservationSha256 { get; init; }
    public required long ReservationSizeBytes { get; init; }
    public required string GenerationLedgerNamespace { get; init; }
    public required string GenerationLedgerPathSha256 { get; init; }
    public required string GenerationLedgerSha256 { get; init; }
    public required long ObservedHighestPromotedGeneration { get; init; }
    public required EnterpriseReleaseSignature Signature { get; init; }

    public static PublisherPluginOrganizationAdmissionReceipt Parse(byte[] bytes) =>
        PublisherRuntimeAdmissionJson.Parse<PublisherPluginOrganizationAdmissionReceipt>(
            bytes,
            "Plugin organization admission receipt");

    public void Verify(
        PublisherSnapshotArtifact plugin,
        PublisherPluginPromotionSnapshot promotion,
        EnterprisePluginPolicyArchiveInspection inspection,
        PublisherSnapshotArtifact launcher,
        PublisherSnapshotArtifact runtime,
        PublisherPluginCompatibilityReceipt compatibilityReceipt,
        PublisherPluginPromotionHandoff handoff,
        PublisherPluginGenerationLedgerState ledger,
        PublisherPluginAdmissionTrust trust,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(trust);
        if (Signature is null
            || !string.Equals(
                Signature.Algorithm,
                EnterpriseReleaseSetContract.SignatureAlgorithm,
                StringComparison.Ordinal)
            || !string.Equals(Signature.KeyId, trust.KeyId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Plugin organization admission signature identity is invalid.");
        }
        trust.Validate();
        var signature = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            Signature.Value,
            "plugin organization admission signature",
            64);
        using (var verifier = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                    trust.X,
                    "plugin organization admission key x",
                    32),
                Y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                    trust.Y,
                    "plugin organization admission key y",
                    32),
            },
        }))
        {
            if (!verifier.VerifyData(
                    PublisherPluginOrganizationAdmissionCanonicalJson.Payload(this),
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new InvalidDataException(
                    "Plugin organization admission signature verification failed.");
            }
        }

        var reviewedAt = DateTimeOffset.FromUnixTimeSeconds(ReviewedAtUnixSeconds);
        var metadata = plugin.PolicyMetadata
            ?? throw new InvalidDataException("Plugin policy metadata snapshot is missing.");
        var runtimeMetadata = runtime.SourceRuntimeMetadata
            ?? throw new InvalidDataException("Runtime source metadata snapshot is missing.");
        var generationAdmission = handoff.GenerationAdmission
            ?? throw new InvalidDataException("Plugin handoff generation admission is missing.");
        var compatibilityProducer = compatibilityReceipt.Producer
            ?? throw new InvalidDataException("Plugin compatibility producer is missing.");
        if (SchemaVersion != CurrentSchemaVersion
            || !string.Equals(ReceiptType, CurrentReceiptType, StringComparison.Ordinal)
            || !string.Equals(Decision, AdmittedDecision, StringComparison.Ordinal)
            || reviewedAt > now.AddMinutes(5)
            || now - reviewedAt > TimeSpan.FromHours(168)
            || !string.Equals(
                CompatibilityTestRunId,
                compatibilityProducer.TestRunId,
                StringComparison.Ordinal)
            || !string.Equals(PolicyId, inspection.PolicyId, StringComparison.Ordinal)
            || Generation != inspection.Generation
            || Critical != inspection.Critical
            || !string.Equals(PluginReleaseId, plugin.Input.ReleaseId, StringComparison.Ordinal)
            || !string.Equals(ArchiveSha256, plugin.File.Sha256, StringComparison.Ordinal)
            || ArchiveSizeBytes != plugin.File.Length
            || !string.Equals(MetadataSha256, metadata.Sha256, StringComparison.Ordinal)
            || MetadataSizeBytes != metadata.Length
            || !string.Equals(RawPolicySha256, inspection.PolicySha256, StringComparison.Ordinal)
            || RawPolicySizeBytes != inspection.PolicySizeBytes
            || !string.Equals(LauncherReleaseId, launcher.Input.ReleaseId, StringComparison.Ordinal)
            || !string.Equals(LauncherArchiveSha256, launcher.File.Sha256, StringComparison.Ordinal)
            || LauncherArchiveSizeBytes != launcher.File.Length
            || !string.Equals(RuntimeReleaseId, runtime.Input.ReleaseId, StringComparison.Ordinal)
            || !string.Equals(RuntimeArchiveSha256, runtime.File.Sha256, StringComparison.Ordinal)
            || RuntimeArchiveSizeBytes != runtime.File.Length
            || !string.Equals(
                RuntimeSourceMetadataSha256,
                runtimeMetadata.Sha256,
                StringComparison.Ordinal)
            || !string.Equals(HarnessSourceTag, "dsh-v0.1.2-rc.1", StringComparison.Ordinal)
            || !string.Equals(
                CompatibilityReceiptSha256,
                promotion.CompatibilityReceipt.Sha256,
                StringComparison.Ordinal)
            || CompatibilityReceiptSizeBytes != promotion.CompatibilityReceipt.Length
            || !string.Equals(
                CompatibilityObservedAtUtc,
                compatibilityReceipt.ObservedAtUtc,
                StringComparison.Ordinal)
            || !string.Equals(
                PromotionHandoffSha256,
                promotion.Handoff.Sha256,
                StringComparison.Ordinal)
            || PromotionHandoffSizeBytes != promotion.Handoff.Length
            || !string.Equals(
                ReservationSha256,
                promotion.Reservation.Sha256,
                StringComparison.Ordinal)
            || ReservationSizeBytes != promotion.Reservation.Length
            || !string.Equals(
                GenerationLedgerNamespace,
                plugin.Input.PluginGenerationLedgerNamespace,
                StringComparison.Ordinal)
            || !string.Equals(
                GenerationLedgerPathSha256,
                ComputeLedgerPathSha256(promotion.LedgerSourcePath),
                StringComparison.Ordinal)
            || !string.Equals(
                GenerationLedgerSha256,
                generationAdmission.LedgerSha256,
                StringComparison.Ordinal)
            || ObservedHighestPromotedGeneration
                != generationAdmission.ObservedHighestPromotedGeneration)
        {
            throw new InvalidDataException(
                "Plugin organization admission receipt does not bind the exact admitted release tuple.");
        }
        if (ledger.HighestPromotedGeneration < inspection.Generation
            && (!string.Equals(
                    GenerationLedgerSha256,
                    promotion.Ledger.Sha256,
                    StringComparison.Ordinal)
                || ObservedHighestPromotedGeneration != ledger.HighestPromotedGeneration))
        {
            throw new InvalidDataException(
                "Plugin organization admission does not bind the current pre-promotion ledger.");
        }
    }

    public static string ComputeLedgerPathSha256(string path)
    {
        var canonical = Path.GetFullPath(path)
            .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar)
            .ToUpperInvariant();
        return Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes("ensou-dsh-plugin-ledger-path-v1\n" + canonical)));
    }
}

internal static class PublisherPluginOrganizationAdmissionCanonicalJson
{
    public static byte[] Payload(PublisherPluginOrganizationAdmissionReceipt receipt)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", receipt.SchemaVersion);
            writer.WriteString("receiptType", receipt.ReceiptType);
            writer.WriteString("decision", receipt.Decision);
            writer.WriteNumber("reviewedAtUnixSeconds", receipt.ReviewedAtUnixSeconds);
            writer.WriteString("compatibilityTestRunId", receipt.CompatibilityTestRunId);
            writer.WriteString("policyId", receipt.PolicyId);
            writer.WriteNumber("generation", receipt.Generation);
            writer.WriteBoolean("critical", receipt.Critical);
            writer.WriteString("pluginReleaseId", receipt.PluginReleaseId);
            writer.WriteString("archiveSha256", receipt.ArchiveSha256);
            writer.WriteNumber("archiveSizeBytes", receipt.ArchiveSizeBytes);
            writer.WriteString("metadataSha256", receipt.MetadataSha256);
            writer.WriteNumber("metadataSizeBytes", receipt.MetadataSizeBytes);
            writer.WriteString("rawPolicySha256", receipt.RawPolicySha256);
            writer.WriteNumber("rawPolicySizeBytes", receipt.RawPolicySizeBytes);
            writer.WriteString("launcherReleaseId", receipt.LauncherReleaseId);
            writer.WriteString("launcherArchiveSha256", receipt.LauncherArchiveSha256);
            writer.WriteNumber("launcherArchiveSizeBytes", receipt.LauncherArchiveSizeBytes);
            writer.WriteString("runtimeReleaseId", receipt.RuntimeReleaseId);
            writer.WriteString("runtimeArchiveSha256", receipt.RuntimeArchiveSha256);
            writer.WriteNumber("runtimeArchiveSizeBytes", receipt.RuntimeArchiveSizeBytes);
            writer.WriteString("runtimeSourceMetadataSha256", receipt.RuntimeSourceMetadataSha256);
            writer.WriteString("harnessSourceTag", receipt.HarnessSourceTag);
            writer.WriteString("compatibilityReceiptSha256", receipt.CompatibilityReceiptSha256);
            writer.WriteNumber("compatibilityReceiptSizeBytes", receipt.CompatibilityReceiptSizeBytes);
            writer.WriteString("compatibilityObservedAtUtc", receipt.CompatibilityObservedAtUtc);
            writer.WriteString("promotionHandoffSha256", receipt.PromotionHandoffSha256);
            writer.WriteNumber("promotionHandoffSizeBytes", receipt.PromotionHandoffSizeBytes);
            writer.WriteString("reservationSha256", receipt.ReservationSha256);
            writer.WriteNumber("reservationSizeBytes", receipt.ReservationSizeBytes);
            writer.WriteString("generationLedgerNamespace", receipt.GenerationLedgerNamespace);
            writer.WriteString("generationLedgerPathSha256", receipt.GenerationLedgerPathSha256);
            writer.WriteString("generationLedgerSha256", receipt.GenerationLedgerSha256);
            writer.WriteNumber(
                "observedHighestPromotedGeneration",
                receipt.ObservedHighestPromotedGeneration);
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPromotionHandoff
{
    public required int SchemaVersion { get; init; }
    public required string HandoffType { get; init; }
    public required string TargetEnvironment { get; init; }
    public required string PromotionStatus { get; init; }
    public required string SigningStatus { get; init; }
    public required bool ProductionSignaturePresent { get; init; }
    public required PublisherPluginHandoffPolicy Policy { get; init; }
    public required PublisherPluginHandoffCompatibility Compatibility { get; init; }
    public required PublisherPluginHandoffDigests Digests { get; init; }
    public required PublisherPluginInputTemplate PublisherInputTemplate { get; init; }
    public required IReadOnlyList<PublisherPluginHandoffInput> Inputs { get; init; }
    public required PublisherPluginHarnessCompatibility HarnessCompatibility { get; init; }
    public required PublisherPluginGenerationAdmission GenerationAdmission { get; init; }
    public required PublisherPluginPromotionVerification Verification { get; init; }
    public required PublisherPluginPromotionSigning Signing { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginHandoffPolicy
{
    public required string PolicyId { get; init; }
    public required long Generation { get; init; }
    public required bool Critical { get; init; }
    public required bool Revoked { get; init; }
    public required string RawPolicyFileName { get; init; }
    public required long RawPolicySizeBytes { get; init; }
    public required string RawPolicySha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginHandoffCompatibility
{
    public required IReadOnlyList<string> LauncherReleaseIds { get; init; }
    public required IReadOnlyList<string> RuntimeReleaseIds { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginHandoffDigests
{
    public required string ArchiveSha256 { get; init; }
    public required long ArchiveSizeBytes { get; init; }
    public required string MetadataSha256 { get; init; }
    public required long MetadataSizeBytes { get; init; }
    public required string RawPolicySha256 { get; init; }
    public required long RawPolicySizeBytes { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginInputTemplate
{
    public required bool TemplateOnly { get; init; }
    public required bool DirectlyConsumable { get; init; }
    public required string Component { get; init; }
    public required string FilePath { get; init; }
    public required string PolicyMetadataPath { get; init; }
    public required string FileName { get; init; }
    public required string MetadataFileName { get; init; }
    public required string SigningStatusRequired { get; init; }
    public string? ReleaseId { get; init; }
    public string? Uri { get; init; }
    public required bool RequiresReleasePublisherId { get; init; }
    public required bool RequiresHttpsUri { get; init; }
    public required bool RequiresIndependentPublisherRevalidation { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginHandoffInput
{
    public required string Kind { get; init; }
    public required string Id { get; init; }
    public required string Version { get; init; }
    public required PublisherPluginHandoffInputFile Artifact { get; init; }
    public required PublisherPluginHandoffInputFile Metadata { get; init; }
    public required PublisherPluginHandoffSource Source { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginHandoffInputFile
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginHandoffSource
{
    public required string Commit { get; init; }
    public required string Tree { get; init; }
    public required string BuilderBlob { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginHarnessCompatibility
{
    public required string Status { get; init; }
    public required string Path { get; init; }
    public required string Sha256 { get; init; }
    public required long SizeBytes { get; init; }
    public required string ObservedAtUtc { get; init; }
    public required string TestRunId { get; init; }
    public required string HarnessSourceTag { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginGenerationAdmission
{
    public required string LedgerPath { get; init; }
    public required string LedgerSha256 { get; init; }
    public required long ObservedHighestPromotedGeneration { get; init; }
    public required long CandidateGeneration { get; init; }
    public required string ReservationPath { get; init; }
    public required string ReservationSha256 { get; init; }
    public required long ReservationSizeBytes { get; init; }
    public required string Decision { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPromotionVerification
{
    public required string Status { get; init; }
    public required string RepositoryRoot { get; init; }
    public required string HeadCommit { get; init; }
    public required bool RepositoryClean { get; init; }
    public required bool RelevantSourcePathsClean { get; init; }
    public required bool WorkingTreeOverrideUsed { get; init; }
    public required PublisherPluginPromotionScript PolicyTestScript { get; init; }
    public required PublisherPluginPromotionScript PolicyBuilderScript { get; init; }
    public required PublisherPluginPromotionScript HandoffScript { get; init; }
    public required PublisherPluginPromotionScript SkillArtifactTestScript { get; init; }
    public required PublisherPluginPromotionScript CompatibilityReceiptTestScript { get; init; }
    public required PublisherPluginPromotionScript GenerationReservationScript { get; init; }
    public required string SkillArtifactVerification { get; init; }
    public required string PolicyTest { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPromotionScript
{
    public required string Path { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginPromotionSigning
{
    public required string Status { get; init; }
    public required bool PrivateKeyUsed { get; init; }
    public required string SignerActionRequired { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginCompatibilityReceipt
{
    public required int SchemaVersion { get; init; }
    public required string ReceiptType { get; init; }
    public required PublisherPluginReceiptProducer Producer { get; init; }
    public required string Result { get; init; }
    public required string StartedAtUtc { get; init; }
    public required string ObservedAtUtc { get; init; }
    public required string LauncherReleaseId { get; init; }
    public required PublisherPluginCompatibilityArtifact LauncherArtifact { get; init; }
    public required string RuntimeReleaseId { get; init; }
    public required PublisherPluginCompatibilityRuntimeArtifact RuntimeArtifact { get; init; }
    public required string HarnessSourceTag { get; init; }
    public required PublisherPluginReceiptPolicy Policy { get; init; }
    public required IReadOnlyList<PublisherPluginCompatibilityPluginObservation> Plugins { get; init; }
    public required IReadOnlyDictionary<string, string> Observations { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginCompatibilityArtifact
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginCompatibilityRuntimeArtifact
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
    public required string SourceMetadataSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginReceiptProducer
{
    public required string Component { get; init; }
    public required string TestRunId { get; init; }
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginCompatibilityPluginObservation
{
    public required string SkillId { get; init; }
    public required string Version { get; init; }
    public required string Root { get; init; }
    public required string DeclaredTreeSha256 { get; init; }
    public required string CommandExecuted { get; init; }
    public required string ManagedPolicyEnforced { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginReceiptPolicy
{
    public required string PolicyId { get; init; }
    public required long Generation { get; init; }
    public required string ArchiveSha256 { get; init; }
    public required string MetadataSha256 { get; init; }
    public required string RawPolicySha256 { get; init; }
    public required string ExecutionAdmissionReceiptSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginGenerationLedgerV1
{
    public required int SchemaVersion { get; init; }
    public required string PolicyId { get; init; }
    public required long HighestPromotedGeneration { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginGenerationLedgerV2
{
    public required int SchemaVersion { get; init; }
    public required string LedgerType { get; init; }
    public required string Namespace { get; init; }
    public required string PolicyId { get; init; }
    public required long HighestPromotedGeneration { get; init; }
    public PublisherPluginGenerationCandidate? HighestPromotedCandidate { get; init; }
}

internal sealed record PublisherPluginGenerationLedgerState(
    int SchemaVersion,
    string? Namespace,
    string PolicyId,
    long HighestPromotedGeneration,
    PublisherPluginGenerationCandidate? HighestPromotedCandidate);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginGenerationCandidate
{
    public required long Generation { get; init; }
    public required string PluginReleaseId { get; init; }
    public required string ArchiveSha256 { get; init; }
    public required string MetadataSha256 { get; init; }
    public required string RawPolicySha256 { get; init; }
    public required string PromotionHandoffSha256 { get; init; }
    public required string CompatibilityReceiptSha256 { get; init; }
    public required string ReservationSha256 { get; init; }
    public required string OrganizationAdmissionReceiptSha256 { get; init; }
    public required string FirstPublishedAtUtc { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginGenerationReservation
{
    public required int SchemaVersion { get; init; }
    public required string ReservationType { get; init; }
    public required string ReservationStatus { get; init; }
    public required string PolicyId { get; init; }
    public required long Generation { get; init; }
    public required string TargetEnvironment { get; init; }
    public required PublisherPluginReservationDigests Digests { get; init; }
    public required string HarnessCompatibilityReceiptSha256 { get; init; }
    public required string CreatedAtUtc { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherPluginReservationDigests
{
    public required string ArchiveSha256 { get; init; }
    public required string MetadataSha256 { get; init; }
    public required string RawPolicySha256 { get; init; }
}
