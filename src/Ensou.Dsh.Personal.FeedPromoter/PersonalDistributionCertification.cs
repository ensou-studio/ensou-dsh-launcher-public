using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.FeedPromoter;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalProductionGateCompiledTrust
{
    public required int SchemaVersion { get; init; }
    public required bool ProductionBuild { get; init; }
    public required string ManifestOrigin { get; init; }
    public required string ArtifactOrigin { get; init; }
    public required string Product { get; init; }
    public required string Environment { get; init; }
    public required string Channel { get; init; }
    public required string StartupStubVersion { get; init; }
    public required string ReleaseKeyId { get; init; }
    public required string ReleaseKeyX { get; init; }
    public required string ReleaseKeyY { get; init; }
    public required long CanonicalLowSFromSequence { get; init; }
    public string? AuthenticodeSignerSha256Thumbprint { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalProductionGateExecutable
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
    public required string AuthenticodeStatus { get; init; }
    public required string SignatureType { get; init; }
    public required string SignerSha256Thumbprint { get; init; }
    public required bool Timestamped { get; init; }
    public required string CompiledTrustSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalProductionGateArtifact
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalProductionGatePayload
{
    public required PersonalProductionGateArtifact Manifest { get; init; }
    public required PersonalProductionGateArtifact StartupStub { get; init; }
    public required PersonalProductionGateArtifact ClientBundle { get; init; }
    public required PersonalProductionGateArtifact Runtime { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalProductionGateEvidence
{
    public const string EvidenceTypeValue =
        "ensou-dsh-personal-production-artifact-gate";
    private const int MaximumBytes = 512 * 1024;
    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";
    private static readonly JsonSerializerOptions CompactJson = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 16,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    public required int SchemaVersion { get; init; }
    public required string EvidenceType { get; init; }
    public required string Product { get; init; }
    public required string ReleaseSetId { get; init; }
    public required bool ProductionDistributionGate { get; init; }
    public required PersonalProductionGateCompiledTrust CompiledTrust { get; init; }
    public required string CompiledTrustSha256 { get; init; }
    public required PersonalProductionGateExecutable Installer { get; init; }
    public required IReadOnlyList<PersonalProductionGateExecutable> ClientExecutables { get; init; }
    public required PersonalProductionGateArtifact ClientBundle { get; init; }
    public required PersonalProductionGatePayload Payload { get; init; }
    public required string ValidatedAtUtc { get; init; }

    [JsonIgnore]
    public DateTimeOffset ParsedValidatedAtUtc => DateTimeOffset.ParseExact(
        ValidatedAtUtc,
        TimestampFormat,
        CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    public static PersonalProductionGateEvidence ParseCanonical(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > MaximumBytes)
        {
            throw new InvalidDataException(
                "Personal production gate evidence size is invalid.");
        }
        try
        {
            PersonalFeedJson.RequireNoDuplicateMembers(json);
            var value = JsonSerializer.Deserialize<PersonalProductionGateEvidence>(
                    json,
                    CompactJson)
                ?? throw new InvalidDataException(
                    "Personal production gate evidence is empty.");
            var canonical = JsonSerializer.SerializeToUtf8Bytes(value, CompactJson);
            if (!json.SequenceEqual(canonical))
            {
                throw new InvalidDataException(
                    "Personal production gate evidence must use strict compact canonical JSON.");
            }
            return value;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal production gate evidence JSON is invalid.",
                exception);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Personal production gate evidence timestamp is invalid.",
                exception);
        }
    }

    internal byte[] SerializeCanonical() =>
        JsonSerializer.SerializeToUtf8Bytes(this, CompactJson);

    internal static string ComputeCompiledTrustSha256(
        PersonalProductionGateCompiledTrust compiledTrust) =>
        PersonalFeedJson.Sha256(
            JsonSerializer.SerializeToUtf8Bytes(compiledTrust, CompactJson));

    public void Verify(
        PersonalFeedTrustConfiguration trust,
        PersonalReleaseSetManifest stable,
        string stableManifestSha256,
        long stableManifestSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(stable);
        trust.Validate();
        var expectedClientNames = new[]
        {
            "Ensou.Dsh.Bootstrapper.exe",
            "Ensou.Dsh.ClientBootstrapper.exe",
            "Ensou.Dsh.Launcher.exe",
            "Ensou.Dsh.Personal.Maintenance.exe",
        };
        var stableClient = stable.ClientBundle;
        var stableRuntime = stable.Runtime;
        var compiledBytes = JsonSerializer.SerializeToUtf8Bytes(CompiledTrust, CompactJson);
        string compiledSha256;
        try
        {
            compiledSha256 = PersonalFeedJson.Sha256(compiledBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(compiledBytes);
        }
        if (SchemaVersion != 1
            || !string.Equals(EvidenceType, EvidenceTypeValue, StringComparison.Ordinal)
            || !string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, stable.ReleaseSetId, StringComparison.Ordinal)
            || !ProductionDistributionGate
            || CompiledTrust is null
            || CompiledTrust.SchemaVersion != 2
            || !CompiledTrust.ProductionBuild
            || !string.Equals(CompiledTrust.Product, trust.Product, StringComparison.Ordinal)
            || !string.Equals(CompiledTrust.Environment, trust.Environment, StringComparison.Ordinal)
            || !string.Equals(CompiledTrust.Channel, "stable", StringComparison.Ordinal)
            || !string.Equals(
                CompiledTrust.ManifestOrigin,
                trust.ManifestOrigin.AbsoluteUri,
                StringComparison.Ordinal)
            || !string.Equals(
                CompiledTrust.ArtifactOrigin,
                trust.ArtifactOrigin.AbsoluteUri,
                StringComparison.Ordinal)
            || !string.Equals(
                CompiledTrust.StartupStubVersion,
                trust.CertifiedStartupStubVersion,
                StringComparison.Ordinal)
            || CompiledTrust.CanonicalLowSFromSequence
                != trust.CanonicalLowSFromSequence
            || !trust.ReleaseKeys.Any(key =>
                string.Equals(key.KeyId, CompiledTrust.ReleaseKeyId, StringComparison.Ordinal)
                && string.Equals(key.X, CompiledTrust.ReleaseKeyX, StringComparison.Ordinal)
                && string.Equals(key.Y, CompiledTrust.ReleaseKeyY, StringComparison.Ordinal))
            || stable.Signature is null
            || !string.Equals(
                stable.Signature.KeyId,
                CompiledTrust.ReleaseKeyId,
                StringComparison.Ordinal)
            || !string.Equals(
                CompiledTrust.AuthenticodeSignerSha256Thumbprint,
                trust.ExpectedAuthenticodeSignerSha256Thumbprint,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(CompiledTrustSha256, compiledSha256, StringComparison.Ordinal)
            || Installer is null
            || ClientExecutables is null
            || ClientExecutables.Count != expectedClientNames.Length
            || !ClientExecutables.Select(item => item.FileName)
                .SequenceEqual(expectedClientNames, StringComparer.Ordinal)
            || ClientExecutables.Any(item => !ValidExecutable(item, trust, compiledSha256))
            || !ValidExecutable(Installer, trust, compiledSha256)
            || !string.Equals(
                Installer.FileName,
                PersonalCertifiedInstaller.OfficialFileName,
                StringComparison.Ordinal)
            || !ValidArtifact(ClientBundle, "client-bundle.zip")
            || Payload is null
            || !ValidArtifact(Payload.Manifest, "release-set.v2.json")
            || !ValidArtifact(Payload.StartupStub, "Ensou.Dsh.Bootstrapper.exe")
            || !ValidArtifact(Payload.ClientBundle, "client-bundle.zip")
            || !ValidArtifact(Payload.Runtime, "runtime.zip")
            || Payload.Manifest.SizeBytes != stableManifestSizeBytes
            || !string.Equals(Payload.Manifest.Sha256, stableManifestSha256, StringComparison.Ordinal)
            || Payload.StartupStub.SizeBytes != ClientExecutables[0].SizeBytes
            || !string.Equals(
                Payload.StartupStub.Sha256,
                ClientExecutables[0].Sha256,
                StringComparison.Ordinal)
            || ClientBundle.SizeBytes != Payload.ClientBundle.SizeBytes
            || !string.Equals(ClientBundle.Sha256, Payload.ClientBundle.Sha256, StringComparison.Ordinal)
            || ClientBundle.SizeBytes != stableClient.SizeBytes
            || !string.Equals(ClientBundle.Sha256, stableClient.Sha256, StringComparison.Ordinal)
            || Payload.Runtime.SizeBytes != stableRuntime.SizeBytes
            || !string.Equals(Payload.Runtime.Sha256, stableRuntime.Sha256, StringComparison.Ordinal)
            || ParsedValidatedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Personal production gate evidence does not bind the exact trusted Stable distribution closure.");
        }
    }

    public PersonalCertifiedInstaller ToCertifiedInstaller() => new()
    {
        FileName = Installer.FileName,
        SizeBytes = Installer.SizeBytes,
        Sha256 = Installer.Sha256,
        AuthenticodeStatus = Installer.AuthenticodeStatus,
        SignatureType = Installer.SignatureType,
        SignerSha256Thumbprint = Installer.SignerSha256Thumbprint,
        Timestamped = Installer.Timestamped,
    };

    private static bool ValidExecutable(
        PersonalProductionGateExecutable value,
        PersonalFeedTrustConfiguration trust,
        string compiledTrustSha256) =>
        value is not null
        && value.FileName == Path.GetFileName(value.FileName)
        && value.SizeBytes > 0
        && PersonalReleaseSetValidator.IsSha256(value.Sha256)
        && string.Equals(value.AuthenticodeStatus, "Valid", StringComparison.Ordinal)
        && string.Equals(value.SignatureType, "Authenticode", StringComparison.Ordinal)
        && string.Equals(
            value.SignerSha256Thumbprint,
            trust.ExpectedAuthenticodeSignerSha256Thumbprint,
            StringComparison.OrdinalIgnoreCase)
        && value.Timestamped
        && string.Equals(
            value.CompiledTrustSha256,
            compiledTrustSha256,
            StringComparison.Ordinal);

    private static bool ValidArtifact(
        PersonalProductionGateArtifact value,
        string expectedFileName) =>
        value is not null
        && string.Equals(value.FileName, expectedFileName, StringComparison.Ordinal)
        && value.SizeBytes > 0
        && PersonalReleaseSetValidator.IsSha256(value.Sha256);
}

internal sealed record PersonalProductionGateEvidenceSnapshot(
    byte[] RawBytes,
    string RawSha256,
    PersonalProductionGateEvidence Evidence)
{
    public static PersonalProductionGateEvidenceSnapshot Read(string path)
    {
        var bytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            path,
            512 * 1024,
            "Personal production gate evidence");
        return new PersonalProductionGateEvidenceSnapshot(
            bytes,
            PersonalFeedJson.Sha256(bytes),
            PersonalProductionGateEvidence.ParseCanonical(bytes));
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalProductionGateEvidenceReference
{
    public required string EvidenceType { get; init; }
    public required string ReleaseSetId { get; init; }
    public required long EvidenceSizeBytes { get; init; }
    public required string EvidenceSha256 { get; init; }
    public required string CompiledTrustSha256 { get; init; }
    public required DateTimeOffset ValidatedAtUtc { get; init; }

    internal static PersonalProductionGateEvidenceReference Create(
        PersonalProductionGateEvidenceSnapshot snapshot) => new()
    {
        EvidenceType = snapshot.Evidence.EvidenceType,
        ReleaseSetId = snapshot.Evidence.ReleaseSetId,
        EvidenceSizeBytes = snapshot.RawBytes.LongLength,
        EvidenceSha256 = snapshot.RawSha256,
        CompiledTrustSha256 = snapshot.Evidence.CompiledTrustSha256,
        ValidatedAtUtc = snapshot.Evidence.ParsedValidatedAtUtc,
    };

    internal void RequireExact(
        PersonalProductionGateEvidenceSnapshot snapshot,
        DateTimeOffset approvedAtUtc)
    {
        if (!string.Equals(
                EvidenceType,
                PersonalProductionGateEvidence.EvidenceTypeValue,
                StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, snapshot.Evidence.ReleaseSetId, StringComparison.Ordinal)
            || EvidenceSizeBytes != snapshot.RawBytes.LongLength
            || EvidenceSizeBytes is <= 0 or > 512 * 1024
            || !string.Equals(EvidenceSha256, snapshot.RawSha256, StringComparison.Ordinal)
            || !PersonalReleaseSetValidator.IsSha256(EvidenceSha256)
            || !string.Equals(
                CompiledTrustSha256,
                snapshot.Evidence.CompiledTrustSha256,
                StringComparison.Ordinal)
            || !PersonalReleaseSetValidator.IsSha256(CompiledTrustSha256)
            || ValidatedAtUtc.Offset != TimeSpan.Zero
            || ValidatedAtUtc != snapshot.Evidence.ParsedValidatedAtUtc
            || ValidatedAtUtc > approvedAtUtc)
        {
            throw new InvalidDataException(
                "Personal receipt does not reference the exact production gate evidence bytes.");
        }
    }
}

public sealed record PersonalDistributionCertificationOptions(
    string TrustPolicyPath,
    string PilotManifestPath,
    string StableManifestPath,
    string ProductionGateEvidencePath,
    string ExternalPilotFeedEvidencePath,
    string CleanDeviceLifecyclePath,
    string TwoUpdateUpgradeLifecyclePath,
    string FailureRecoveryLifecyclePath,
    string OutputReceiptPath);

public sealed record PersonalDistributionPreflightOptions(
    string TrustPolicyPath,
    string PilotManifestPath,
    string StableManifestPath,
    string ProductionGateEvidencePath,
    string ExternalPilotFeedEvidencePath,
    string CleanDeviceLifecyclePath,
    string TwoUpdateUpgradeLifecyclePath,
    string FailureRecoveryLifecyclePath);

public sealed record PersonalDistributionPreflightResult(
    string ReleaseSetId,
    string PilotManifestSha256,
    string StableManifestSha256,
    string LauncherRepositoryCommit,
    string HarnessSourceTag,
    string HarnessSourceCommit,
    string ManifestOrigin,
    string ArtifactOrigin,
    string ReleaseKeyId,
    string AuthenticodeSignerSha256Thumbprint,
    long ReceiptPreviewSizeBytes,
    string ReceiptPreviewSha256,
    string InstallerSha256,
    string ProductionGateEvidenceSha256)
{
    public bool DistributionReceiptCreated => false;
}

public sealed record PersonalDistributionCertificationResult(
    string OutputReceiptPath,
    string ReleaseSetId,
    long ReceiptSizeBytes,
    string ReceiptSha256,
    string InstallerSha256,
    string ProductionGateEvidenceSha256);

public sealed class PersonalDistributionReceiptProducer(
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public PersonalDistributionPreflightResult Preflight(
        PersonalDistributionPreflightOptions options)
    {
        var validated = Validate(options);
        return new PersonalDistributionPreflightResult(
            validated.Receipt.ReleaseSetId,
            validated.PilotManifestSha256,
            validated.StableManifestSha256,
            validated.Provenance.LauncherRepositoryCommit,
            validated.Provenance.HarnessSourceTag,
            validated.Provenance.HarnessSourceCommit,
            validated.ManifestOrigin,
            validated.ArtifactOrigin,
            validated.ReleaseKeyId,
            validated.AuthenticodeSignerSha256Thumbprint,
            validated.ReceiptBytes.LongLength,
            PersonalFeedJson.Sha256(validated.ReceiptBytes),
            validated.Receipt.Installer.Sha256,
            validated.Gate.RawSha256);
    }

    public PersonalDistributionCertificationResult Produce(
        PersonalDistributionCertificationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var validated = Validate(new PersonalDistributionPreflightOptions(
            options.TrustPolicyPath,
            options.PilotManifestPath,
            options.StableManifestPath,
            options.ProductionGateEvidencePath,
            options.ExternalPilotFeedEvidencePath,
            options.CleanDeviceLifecyclePath,
            options.TwoUpdateUpgradeLifecyclePath,
            options.FailureRecoveryLifecyclePath));
        var outputPath = RequireNewOutputPath(options.OutputReceiptPath);
        PersonalFeedPathGuard.WriteNewDurable(outputPath, validated.ReceiptBytes);
        var readBack = PersonalFeedPathGuard.ReadBoundedRegularFile(
            outputPath,
            512 * 1024,
            "Personal certified distribution receipt output");
        _ = PersonalCertifiedDistributionReceipt.Parse(readBack);
        if (!validated.ReceiptBytes.AsSpan().SequenceEqual(readBack))
        {
            throw new IOException(
                "Personal certified distribution receipt changed after create-only write.");
        }
        return new PersonalDistributionCertificationResult(
            outputPath,
            validated.Receipt.ReleaseSetId,
            validated.ReceiptBytes.LongLength,
            PersonalFeedJson.Sha256(validated.ReceiptBytes),
            validated.Receipt.Installer.Sha256,
            validated.Gate.RawSha256);
    }

    private ValidatedDistribution Validate(PersonalDistributionPreflightOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var trustBytes = LinuxNative.ReadRootOwnedRegularFile(
            options.TrustPolicyPath,
            256 * 1024,
            "Personal feed trust policy");
        var trust = PersonalFeedTrustConfiguration.Parse(trustBytes);
        var observedNow = RequireUtc(_timeProvider.GetUtcNow());
        var pilotBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            options.PilotManifestPath,
            2 * 1024 * 1024,
            "Personal Pilot manifest");
        var stableBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            options.StableManifestPath,
            2 * 1024 * 1024,
            "Personal Stable manifest");
        var pilot = PersonalReleaseSetValidator.ParseAndVerify(
            pilotBytes,
            trust.ToReleasePolicy("pilot"),
            observedNow);
        var stable = PersonalReleaseSetValidator.ParseAndVerify(
            stableBytes,
            trust.ToReleasePolicy("stable"),
            observedNow);
        var pilotSha256 = PersonalFeedJson.Sha256(pilotBytes);
        var stableSha256 = PersonalFeedJson.Sha256(stableBytes);
        if (!string.Equals(
                pilot.CanonicalSignedManifestSha256,
                pilotSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                stable.CanonicalSignedManifestSha256,
                stableSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal certification manifests must be their exact canonical signed bytes.");
        }
        PersonalFeedPromoter.RequireStableMatchesPilot(
            pilot.Manifest,
            stable.Manifest);

        var gate = PersonalProductionGateEvidenceSnapshot.Read(
            options.ProductionGateEvidencePath);
        gate.Evidence.Verify(
            trust,
            stable.Manifest,
            stableSha256,
            stableBytes.LongLength);
        var feedBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            options.ExternalPilotFeedEvidencePath,
            128 * 1024,
            "Personal external Pilot feed evidence");
        var feed = PersonalCertifiedFeedEvidence.ParseCanonical(feedBytes);
        var lifecycle = new PersonalLifecycleEvidenceSet(
            PersonalLifecycleEvidenceSnapshot.Read(
                options.CleanDeviceLifecyclePath,
                "clean-device lifecycle evidence receipt"),
            PersonalLifecycleEvidenceSnapshot.Read(
                options.TwoUpdateUpgradeLifecyclePath,
                "two-update upgrade lifecycle evidence receipt"),
            PersonalLifecycleEvidenceSnapshot.Read(
                options.FailureRecoveryLifecyclePath,
                "failure-recovery lifecycle evidence receipt"));
        var matrix = new PersonalCertifiedTestMatrix
        {
            CleanDeviceLifecycle = CreateReference(lifecycle.CleanDevice),
            TwoUpdateUpgradeLifecycle = CreateReference(lifecycle.TwoUpdateUpgrade),
            FailureRecoveryLifecycle = CreateReference(lifecycle.FailureRecovery),
        };
        var receipt = new PersonalCertifiedDistributionReceipt
        {
            SchemaVersion = 2,
            Product = PersonalReleaseSetContract.Product,
            SourceChannel = "pilot",
            TargetChannel = "stable",
            ReleaseSetId = stable.Manifest.ReleaseSetId,
            PilotManifestSha256 = pilotSha256,
            StableManifestSha256 = stableSha256,
            Artifacts = PersonalFeedArtifactReceipt.FromManifest(stable.Manifest),
            Installer = gate.Evidence.ToCertifiedInstaller(),
            ProductionGateEvidence = PersonalProductionGateEvidenceReference.Create(gate),
            Feed = feed,
            Certification = matrix,
            ApprovedAtUtc = observedNow,
            DistributionAuthorized = true,
        };
        receipt.Verify(
            pilot.Manifest,
            pilotSha256,
            stable.Manifest,
            stableSha256,
            trust,
            lifecycle,
            gate);
        var receiptBytes = receipt.SerializeCanonical();
        return new ValidatedDistribution(
            receipt,
            receiptBytes,
            pilotSha256,
            stableSha256,
            stable.Manifest.Provenance,
            trust.ManifestOrigin.AbsoluteUri,
            trust.ArtifactOrigin.AbsoluteUri,
            gate.Evidence.CompiledTrust.ReleaseKeyId,
            trust.ExpectedAuthenticodeSignerSha256Thumbprint,
            gate);
    }

    private static PersonalLifecycleEvidenceReference CreateReference(
        PersonalLifecycleEvidenceSnapshot snapshot) => new()
    {
        Kind = snapshot.Receipt.Kind,
        TestRunId = snapshot.Receipt.TestRunId,
        ReceiptSizeBytes = snapshot.RawBytes.LongLength,
        ReceiptSha256 = snapshot.RawSha256,
        CompletedAtUtc = snapshot.Receipt.CompletedAtUtc,
    };

    private static string RequireNewOutputPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException(
                "Personal certified receipt output path must be absolute.");
        }
        var full = Path.GetFullPath(path);
        PersonalFeedPathGuard.RequireSafeFileName(
            Path.GetFileName(full),
            "Personal certified receipt file name");
        _ = PersonalFeedPathGuard.RequireExistingDirectory(
            Path.GetDirectoryName(full)
                ?? throw new InvalidDataException(
                    "Personal certified receipt output has no parent."),
            "Personal certified receipt output directory");
        if (File.Exists(full) || Directory.Exists(full))
        {
            throw new IOException(
                "Personal certified distribution receipt output is create-only.");
        }
        return full;
    }

    private static DateTimeOffset RequireUtc(DateTimeOffset value) =>
        value.Offset == TimeSpan.Zero
            ? value
            : throw new InvalidDataException(
                "Personal distribution certification clock must be UTC.");

    private sealed record ValidatedDistribution(
        PersonalCertifiedDistributionReceipt Receipt,
        byte[] ReceiptBytes,
        string PilotManifestSha256,
        string StableManifestSha256,
        PersonalReleaseProvenance Provenance,
        string ManifestOrigin,
        string ArtifactOrigin,
        string ReleaseKeyId,
        string AuthenticodeSignerSha256Thumbprint,
        PersonalProductionGateEvidenceSnapshot Gate);
}
