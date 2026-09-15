using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.Enterprise.ReleasePublisherTests;

internal static class WindowsPilotEvidenceTrustTests
{
    public static Task RunAsync()
    {
        using var evidenceSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attackerSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = CreateTrust(evidenceSigner, "pilot-evidence-2026-01");
        var body = Encoding.UTF8.GetBytes(
            "{\"schemaVersion\":2,\"pilotDecision\":\"ADMIT\",\"gates\":21}");
        var envelope = CreateEnvelope(evidenceSigner, trust.KeyId, body);
        var envelopeBytes = JsonSerializer.SerializeToUtf8Bytes(
            envelope,
            PublisherWindowsPilotEvidenceJson.Options);

        var verified = PublisherWindowsPilotEvidenceVerifier.Verify(
            envelopeBytes,
            body,
            trust);
        AssertEqual(Convert.ToHexStringLower(SHA256.HashData(body)), verified.BodySha256);
        AssertEqual(trust.KeyId, verified.KeyId);

        var forgedPass = Encoding.UTF8.GetBytes(
            "{\"schemaVersion\":2,\"pilotDecision\":\"ADMIT\",\"gates\":22}");
        AssertThrows<InvalidDataException>(() =>
            PublisherWindowsPilotEvidenceVerifier.Verify(
                envelopeBytes,
                forgedPass,
                trust));

        var attackerEnvelope = CreateEnvelope(attackerSigner, "attacker-key", body);
        AssertThrows<InvalidDataException>(() =>
            PublisherWindowsPilotEvidenceVerifier.Verify(
                JsonSerializer.SerializeToUtf8Bytes(
                    attackerEnvelope,
                    PublisherWindowsPilotEvidenceJson.Options),
                body,
                trust));

        var selfSelectedKey = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(envelope)[..^1]
            + ",\"publicKey\":{\"x\":\"attacker\",\"y\":\"attacker\"}}");
        AssertThrows<InvalidDataException>(() =>
            PublisherWindowsPilotEvidenceVerifier.Verify(
                selfSelectedKey,
                body,
                trust));

        var evidenceParameters = evidenceSigner.ExportParameters(false);
        AssertThrows<InvalidDataException>(() => trust.RequireIndependentFrom(
            ("release-signing-key",
                PublisherRuntimeAdmissionEncoding.EncodeBase64Url(evidenceParameters.Q.X!),
                PublisherRuntimeAdmissionEncoding.EncodeBase64Url(evidenceParameters.Q.Y!),
                "release-signing")));

        return Task.CompletedTask;
    }

    private static PublisherWindowsPilotEvidenceEnvelope CreateEnvelope(
        ECDsa signer,
        string keyId,
        byte[] body)
    {
        var unsigned = new PublisherWindowsPilotEvidenceEnvelope
        {
            SchemaVersion = PublisherWindowsPilotEvidenceEnvelope.CurrentSchemaVersion,
            EvidenceType = PublisherWindowsPilotEvidenceEnvelope.CurrentEvidenceType,
            Body = new PublisherWindowsPilotEvidenceBodyBinding
            {
                SchemaVersion = PublisherWindowsPilotEvidenceEnvelope.CurrentSchemaVersion,
                EvidenceType = PublisherWindowsPilotEvidenceEnvelope.CurrentBodyEvidenceType,
                SizeBytes = body.Length,
                Sha256 = Convert.ToHexStringLower(SHA256.HashData(body)),
            },
            Attestation = new EnterpriseReleaseSignature
            {
                Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                KeyId = keyId,
                Value = EnterpriseBase64Url.Encode(new byte[64]),
            },
        };
        return unsigned with
        {
            Attestation = new EnterpriseReleaseSignature
            {
                Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                KeyId = keyId,
                Value = EnterpriseBase64Url.Encode(signer.SignData(
                    PublisherWindowsPilotEvidenceCanonicalPayload.Create(unsigned),
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            },
        };
    }

    private static PublisherWindowsPilotEvidenceTrust CreateTrust(
        ECDsa signer,
        string keyId)
    {
        var parameters = signer.ExportParameters(false);
        return new PublisherWindowsPilotEvidenceTrust
        {
            KeyId = keyId,
            X = EnterpriseBase64Url.Encode(parameters.Q.X!),
            Y = EnterpriseBase64Url.Encode(parameters.Q.Y!),
        };
    }

    private static void AssertThrows<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static void AssertEqual(string expected, string actual)
    {
        if (!string.Equals(expected, actual, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Expected '{expected}', actual '{actual}'.");
        }
    }
}
