using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public sealed record EnterpriseBindingReceipt(
    string BindingId,
    string InstallationId,
    string DeviceKeyThumbprint,
    string EmployeeAuthorizationId,
    string LeaseId,
    EnterpriseAuthorizationEpochState EpochState,
    DateTimeOffset ServerTimeUtc,
    DateTimeOffset LeaseExpiresAtUtc,
    string AuthorizationLeaseSha256)
{
    public override string ToString() => "Enterprise binding receipt [REDACTED]";
}

public sealed record EnterprisePersistedBindingCredential(
    string RefreshToken,
    string AuthorizationLease,
    EnterpriseBindingReceipt Receipt)
{
    public override string ToString() =>
        "Enterprise persisted binding credential [REDACTED]";
}

public sealed class EnterpriseBindingCredentialStore
{
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new EnterpriseWholeSecondUtcDateTimeOffsetConverter() },
    };

    private readonly EnterpriseManagedPaths _paths;
    private readonly EnterpriseProtectedArtifactStore _protectedStore;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public EnterpriseBindingCredentialStore(
        EnterpriseManagedPaths paths,
        EnterpriseProtectedArtifactStore protectedStore)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _protectedStore = protectedStore ?? throw new ArgumentNullException(nameof(protectedStore));
    }

    public async Task<EnterpriseBindingReceipt> CommitOrConfirmAsync(
        EnterpriseDeviceBindingCompleteResponse response,
        EnterpriseVerifiedAuthorizationLease verifiedLease,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(verifiedLease);
        ValidateResponseConsistency(response, verifiedLease);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (File.Exists(_paths.Resolve(EnterpriseManagedArtifact.RefreshTokenDpapi)))
            {
                EnterprisePersistedBindingCredential existing;
                try
                {
                    existing = await ReadCommittedCoreAsync(cancellationToken)
                        .ConfigureAwait(false)
                        ?? throw new InvalidDataException(
                            "Enterprise protected binding commit disappeared during recovery.");
                }
                catch (Exception exception)
                {
                    throw new EnterpriseBindingRecoveryRequiredException(exception);
                }

                ValidateExistingCommit(existing, response, verifiedLease);
                return existing.Receipt;
            }

            return await CommitNewCoreAsync(response, verifiedLease, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<EnterpriseBindingReceipt> CommitNewCoreAsync(
        EnterpriseDeviceBindingCompleteResponse response,
        EnterpriseVerifiedAuthorizationLease verifiedLease,
        CancellationToken cancellationToken)
    {
        byte[]? leaseBytes = null;
        byte[]? receiptBytes = null;
        byte[]? protectedCommitBytes = null;
        byte[]? leaseHash = null;
        byte[]? receiptHash = null;
        var committed = false;
        try
        {
            leaseBytes = JsonSerializer.SerializeToUtf8Bytes(
                new AuthorizationLeaseCacheDocument
                {
                    SchemaVersion = 1,
                    AuthorizationLease = response.AuthorizationLease,
                },
                StrictJson);
            leaseHash = SHA256.HashData(leaseBytes);
            var leaseHashText = EnterpriseBindingValidation.Base64UrlEncode(leaseHash);
            var claims = verifiedLease.Claims;
            var receiptDocument = new BindingReceiptDocument
            {
                SchemaVersion = 1,
                BindingId = claims.BindingId,
                InstallationId = claims.InstallationId,
                DeviceKeyThumbprint = claims.DeviceKeyThumbprint,
                EmployeeAuthorizationId = claims.Subject,
                LeaseId = claims.LeaseId,
                AuthorizationEpoch = claims.AuthorizationEpoch,
                EntitlementEpoch = claims.EntitlementEpoch,
                BindingEpoch = claims.BindingEpoch,
                ApiAllocationId = claims.ApiAllocationId,
                AllocationEpoch = claims.AllocationEpoch,
                ApiProfileId = claims.ApiProfileId,
                ApiProfileVersion = claims.ApiProfileVersion,
                PluginPolicyId = claims.PluginPolicyId,
                PluginPolicyGeneration = claims.PluginPolicyGeneration,
                PluginPolicySha256 = claims.PluginPolicySha256,
                RolloutChannel = claims.RolloutChannel,
                ServerTimeUtc = response.ServerTimeUtc,
                LeaseExpiresAtUtc = response.LeaseExpiresAtUtc,
                AuthorizationLeaseSha256 = leaseHashText,
            };
            receiptBytes = JsonSerializer.SerializeToUtf8Bytes(receiptDocument, StrictJson);
            receiptHash = SHA256.HashData(receiptBytes);
            protectedCommitBytes = JsonSerializer.SerializeToUtf8Bytes(
                new ProtectedBindingCommitDocument
                {
                    SchemaVersion = 1,
                    BindingId = claims.BindingId,
                    InstallationId = claims.InstallationId,
                    DeviceKeyThumbprint = claims.DeviceKeyThumbprint,
                    RefreshToken = response.RefreshToken,
                    AuthorizationLeaseSha256 = leaseHashText,
                    BindingReceiptSha256 = EnterpriseBindingValidation.Base64UrlEncode(receiptHash),
                },
                StrictJson);

            await WriteProjectionIfAbsentOrExactAsync(
                    EnterpriseManagedArtifact.AuthorizationLease,
                    leaseBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            await WriteProjectionIfAbsentOrExactAsync(
                    EnterpriseManagedArtifact.DeviceBindingReceipt,
                    receiptBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            await _protectedStore.WriteNewAsync(
                    EnterpriseManagedArtifact.RefreshTokenDpapi,
                    protectedCommitBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            committed = true;
            return ToReceipt(receiptDocument);
        }
        catch (Exception exception) when (!committed)
        {
            throw new EnterpriseBindingRecoveryRequiredException(exception);
        }
        finally
        {
            Zero(leaseBytes);
            Zero(receiptBytes);
            Zero(protectedCommitBytes);
            Zero(leaseHash);
            Zero(receiptHash);
        }
    }

    public async Task<EnterprisePersistedBindingCredential?> ReadCommittedAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var hasProtectedCommit = File.Exists(
                _paths.Resolve(EnterpriseManagedArtifact.RefreshTokenDpapi));
            var hasLease = File.Exists(
                _paths.Resolve(EnterpriseManagedArtifact.AuthorizationLease));
            var hasReceipt = File.Exists(
                _paths.Resolve(EnterpriseManagedArtifact.DeviceBindingReceipt));
            if (!hasProtectedCommit)
            {
                if (hasLease || hasReceipt)
                {
                    throw new EnterpriseBindingRecoveryRequiredException(
                        new InvalidDataException(
                            "Enterprise binding projections exist without a protected commit."));
                }

                return null;
            }

            try
            {
                return await ReadCommittedCoreAsync(cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidDataException(
                        "Enterprise protected binding commit disappeared during read.");
            }
            catch (EnterpriseBindingRecoveryRequiredException)
            {
                throw;
            }
            catch (Exception exception)
            {
                throw new EnterpriseBindingRecoveryRequiredException(exception);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<EnterpriseBindingReceipt> RotateOrConfirmAsync(
        EnterpriseDeviceBindingCompleteResponse response,
        EnterpriseVerifiedAuthorizationLease verifiedLease,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(verifiedLease);
        ValidateResponseConsistency(response, verifiedLease);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var existing = await ReadCommittedCoreAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new EnterpriseBindingRecoveryRequiredException(
                    new InvalidDataException(
                        "Enterprise refresh cannot rotate an absent binding credential."));
            if (IsExactCommittedResponse(existing, response))
            {
                ValidateExistingCommit(existing, response, verifiedLease);
                return existing.Receipt;
            }

            ValidateRotation(existing, response, verifiedLease);
            return await CommitRotationCoreAsync(response, verifiedLease, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (EnterpriseBindingRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new EnterpriseBindingRecoveryRequiredException(exception);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<EnterpriseBindingReceipt> CommitRotationCoreAsync(
        EnterpriseDeviceBindingCompleteResponse response,
        EnterpriseVerifiedAuthorizationLease verifiedLease,
        CancellationToken cancellationToken)
    {
        byte[]? leaseBytes = null;
        byte[]? receiptBytes = null;
        byte[]? protectedCommitBytes = null;
        byte[]? leaseHash = null;
        byte[]? receiptHash = null;
        try
        {
            var leaseDocument = new AuthorizationLeaseCacheDocument
            {
                SchemaVersion = 1,
                AuthorizationLease = response.AuthorizationLease,
            };
            leaseBytes = JsonSerializer.SerializeToUtf8Bytes(leaseDocument, StrictJson);
            leaseHash = SHA256.HashData(leaseBytes);
            var receiptDocument = CreateReceiptDocument(
                response,
                verifiedLease.Claims,
                EnterpriseBindingValidation.Base64UrlEncode(leaseHash));
            receiptBytes = JsonSerializer.SerializeToUtf8Bytes(receiptDocument, StrictJson);
            receiptHash = SHA256.HashData(receiptBytes);
            protectedCommitBytes = JsonSerializer.SerializeToUtf8Bytes(
                new ProtectedBindingCommitDocument
                {
                    SchemaVersion = 2,
                    BindingId = receiptDocument.BindingId,
                    InstallationId = receiptDocument.InstallationId,
                    DeviceKeyThumbprint = receiptDocument.DeviceKeyThumbprint,
                    RefreshToken = response.RefreshToken,
                    AuthorizationLeaseSha256 = receiptDocument.AuthorizationLeaseSha256,
                    BindingReceiptSha256 = EnterpriseBindingValidation.Base64UrlEncode(receiptHash),
                    AuthorizationLease = response.AuthorizationLease,
                    BindingReceipt = receiptDocument,
                },
                StrictJson);

            // The DPAPI document is the single authoritative rotation commit. Projections are
            // intentionally written afterwards and can be reconstructed after a process crash.
            await _protectedStore.WriteAsync(
                    EnterpriseManagedArtifact.RefreshTokenDpapi,
                    protectedCommitBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            await WriteProjectionExactOrReplaceAsync(
                    EnterpriseManagedArtifact.AuthorizationLease,
                    leaseBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            await WriteProjectionExactOrReplaceAsync(
                    EnterpriseManagedArtifact.DeviceBindingReceipt,
                    receiptBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            return ToReceipt(receiptDocument);
        }
        finally
        {
            Zero(leaseBytes);
            Zero(receiptBytes);
            Zero(protectedCommitBytes);
            Zero(leaseHash);
            Zero(receiptHash);
        }
    }

    private async Task<EnterprisePersistedBindingCredential?> ReadCommittedCoreAsync(
        CancellationToken cancellationToken)
    {
        var protectedBytes = await _protectedStore.ReadAsync(
                EnterpriseManagedArtifact.RefreshTokenDpapi,
                cancellationToken)
            .ConfigureAwait(false);
        if (protectedBytes is null)
        {
            return null;
        }

        byte[]? leaseBytes = null;
        byte[]? receiptBytes = null;
        byte[]? computedLeaseHash = null;
        byte[]? computedReceiptHash = null;
        byte[]? expectedLeaseHash = null;
        byte[]? expectedReceiptHash = null;
        try
        {
            var protectedCommit = DeserializeExact<ProtectedBindingCommitDocument>(
                protectedBytes,
                "protected binding commit");
            AuthorizationLeaseCacheDocument leaseDocument;
            BindingReceiptDocument receiptDocument;
            if (protectedCommit.SchemaVersion == 2)
            {
                if (protectedCommit.AuthorizationLease is null
                    || protectedCommit.BindingReceipt is null)
                {
                    throw new InvalidDataException(
                        "Enterprise rotated credential is missing its authoritative projections.");
                }

                leaseDocument = new AuthorizationLeaseCacheDocument
                {
                    SchemaVersion = 1,
                    AuthorizationLease = protectedCommit.AuthorizationLease,
                };
                receiptDocument = protectedCommit.BindingReceipt;
                leaseBytes = JsonSerializer.SerializeToUtf8Bytes(leaseDocument, StrictJson);
                receiptBytes = JsonSerializer.SerializeToUtf8Bytes(receiptDocument, StrictJson);
            }
            else
            {
                leaseBytes = await EnterpriseLocalStateSecurity.ReadBoundedAsync(
                        _paths.Resolve(EnterpriseManagedArtifact.AuthorizationLease),
                        _paths.ManagedRoot,
                        cancellationToken)
                    .ConfigureAwait(false);
                receiptBytes = await EnterpriseLocalStateSecurity.ReadBoundedAsync(
                        _paths.Resolve(EnterpriseManagedArtifact.DeviceBindingReceipt),
                        _paths.ManagedRoot,
                        cancellationToken)
                    .ConfigureAwait(false);
                leaseDocument = DeserializeExact<AuthorizationLeaseCacheDocument>(
                    leaseBytes,
                    "authorization lease cache");
                receiptDocument = DeserializeExact<BindingReceiptDocument>(
                    receiptBytes,
                    "binding receipt");
            }

            ValidateDocuments(protectedCommit, leaseDocument, receiptDocument);

            computedLeaseHash = SHA256.HashData(leaseBytes);
            computedReceiptHash = SHA256.HashData(receiptBytes);
            expectedLeaseHash = EnterpriseBindingValidation.Base64UrlDecode(
                protectedCommit.AuthorizationLeaseSha256,
                "protected_commit.authorization_lease_sha256",
                32);
            expectedReceiptHash = EnterpriseBindingValidation.Base64UrlDecode(
                protectedCommit.BindingReceiptSha256,
                "protected_commit.binding_receipt_sha256",
                32);
            if (expectedLeaseHash.Length != 32
                || expectedReceiptHash.Length != 32
                || !CryptographicOperations.FixedTimeEquals(computedLeaseHash, expectedLeaseHash)
                || !CryptographicOperations.FixedTimeEquals(computedReceiptHash, expectedReceiptHash))
            {
                throw new InvalidDataException(
                    "Enterprise binding credential projections do not match the protected commit.");
            }

            if (protectedCommit.SchemaVersion == 2)
            {
                await WriteProjectionExactOrReplaceAsync(
                        EnterpriseManagedArtifact.AuthorizationLease,
                        leaseBytes,
                        cancellationToken)
                    .ConfigureAwait(false);
                await WriteProjectionExactOrReplaceAsync(
                        EnterpriseManagedArtifact.DeviceBindingReceipt,
                        receiptBytes,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            return new EnterprisePersistedBindingCredential(
                protectedCommit.RefreshToken,
                leaseDocument.AuthorizationLease,
                ToReceipt(receiptDocument));
        }
        finally
        {
            Zero(protectedBytes);
            Zero(leaseBytes);
            Zero(receiptBytes);
            Zero(computedLeaseHash);
            Zero(computedReceiptHash);
            Zero(expectedLeaseHash);
            Zero(expectedReceiptHash);
        }
    }

    public void DeleteBindingArtifacts()
    {
        _gate.Wait();
        try
        {
            DeleteBindingArtifactsCore();
        }
        finally
        {
            _gate.Release();
        }
    }

    private void DeleteBindingArtifactsCore()
    {
        List<Exception>? failures = null;
        foreach (var artifact in new[]
        {
            EnterpriseManagedArtifact.AuthorizationLease,
            EnterpriseManagedArtifact.DeviceBindingReceipt,
            EnterpriseManagedArtifact.RefreshTokenDpapi,
        })
        {
            try
            {
                if (artifact == EnterpriseManagedArtifact.RefreshTokenDpapi)
                {
                    _protectedStore.Delete(artifact);
                }
                else
                {
                    DeletePlainProjection(artifact);
                }
            }
            catch (Exception exception)
            {
                failures ??= [];
                failures.Add(exception);
            }
        }

        if (failures is not null)
        {
            throw new AggregateException(
                "One or more enterprise binding artifacts could not be deleted.",
                failures);
        }
    }

    private static void ValidateExistingCommit(
        EnterprisePersistedBindingCredential existing,
        EnterpriseDeviceBindingCompleteResponse response,
        EnterpriseVerifiedAuthorizationLease verifiedLease)
    {
        var claims = verifiedLease.Claims;
        var receipt = existing.Receipt;
        var existingRefreshToken = EnterpriseBindingValidation.Base64UrlDecode(
            existing.RefreshToken,
            "existing_binding.refresh_token",
            32);
        var replayedRefreshToken = EnterpriseBindingValidation.Base64UrlDecode(
            response.RefreshToken,
            "replayed_binding.refresh_token",
            32);
        try
        {
            if (existingRefreshToken.Length != 32
                || replayedRefreshToken.Length != 32
                || !CryptographicOperations.FixedTimeEquals(
                    existingRefreshToken,
                    replayedRefreshToken)
                || !string.Equals(
                    existing.AuthorizationLease,
                    response.AuthorizationLease,
                    StringComparison.Ordinal)
                || !string.Equals(receipt.BindingId, claims.BindingId, StringComparison.Ordinal)
                || !string.Equals(
                    receipt.InstallationId,
                    claims.InstallationId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    receipt.DeviceKeyThumbprint,
                    claims.DeviceKeyThumbprint,
                    StringComparison.Ordinal)
                || !string.Equals(
                    receipt.EmployeeAuthorizationId,
                    claims.Subject,
                    StringComparison.Ordinal)
                || !string.Equals(receipt.LeaseId, claims.LeaseId, StringComparison.Ordinal)
                || receipt.EpochState != claims.ToEpochState()
                || receipt.ServerTimeUtc != claims.IssuedAtUtc
                || receipt.LeaseExpiresAtUtc != claims.ExpiresAtUtc)
            {
                throw new EnterpriseBindingRecoveryRequiredException(
                    new InvalidDataException(
                        "Committed enterprise binding differs from the verified idempotent replay."));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(existingRefreshToken);
            CryptographicOperations.ZeroMemory(replayedRefreshToken);
        }
    }

    private static void ValidateResponseConsistency(
        EnterpriseDeviceBindingCompleteResponse response,
        EnterpriseVerifiedAuthorizationLease verifiedLease)
    {
        var claims = verifiedLease.Claims;
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            response.RefreshToken,
            nameof(response.RefreshToken),
            32);
        if (!string.Equals(response.BindingId, claims.BindingId, StringComparison.Ordinal)
            || !string.Equals(
                response.AuthorizationLease,
                verifiedLease.Envelope.CompactJws,
                StringComparison.Ordinal)
            || response.ServerTimeUtc != claims.IssuedAtUtc
            || response.LeaseExpiresAtUtc != claims.ExpiresAtUtc)
        {
            throw new InvalidDataException(
                "Enterprise binding response does not match its verified authorization lease.");
        }
    }

    private static bool IsExactCommittedResponse(
        EnterprisePersistedBindingCredential existing,
        EnterpriseDeviceBindingCompleteResponse response) =>
        string.Equals(existing.AuthorizationLease, response.AuthorizationLease, StringComparison.Ordinal)
        && FixedTimeTokenEquals(existing.RefreshToken, response.RefreshToken);

    private static void ValidateRotation(
        EnterprisePersistedBindingCredential existing,
        EnterpriseDeviceBindingCompleteResponse response,
        EnterpriseVerifiedAuthorizationLease verifiedLease)
    {
        var current = existing.Receipt;
        var claims = verifiedLease.Claims;
        if (!string.Equals(current.BindingId, claims.BindingId, StringComparison.Ordinal)
            || !string.Equals(current.InstallationId, claims.InstallationId, StringComparison.Ordinal)
            || !string.Equals(
                current.DeviceKeyThumbprint,
                claims.DeviceKeyThumbprint,
                StringComparison.Ordinal)
            || !string.Equals(
                current.EmployeeAuthorizationId,
                claims.Subject,
                StringComparison.Ordinal)
            || response.ServerTimeUtc < current.ServerTimeUtc
            || claims.AuthorizationEpoch < current.EpochState.AuthorizationEpoch
            || claims.EntitlementEpoch < current.EpochState.EntitlementEpoch
            || claims.BindingEpoch < current.EpochState.BindingEpoch
            || FixedTimeTokenEquals(existing.RefreshToken, response.RefreshToken))
        {
            throw new InvalidDataException(
                "Enterprise refresh attempted an identity, epoch, time, or token-rotation rollback.");
        }
    }

    private static bool FixedTimeTokenEquals(string left, string right)
    {
        var leftBytes = EnterpriseBindingValidation.Base64UrlDecode(left, "left_refresh_token", 32);
        var rightBytes = EnterpriseBindingValidation.Base64UrlDecode(right, "right_refresh_token", 32);
        try
        {
            return leftBytes.Length == 32
                && rightBytes.Length == 32
                && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static void ValidateDocuments(
        ProtectedBindingCommitDocument protectedCommit,
        AuthorizationLeaseCacheDocument lease,
        BindingReceiptDocument receipt)
    {
        if (protectedCommit.SchemaVersion is not 1 and not 2
            || lease.SchemaVersion != 1
            || receipt.SchemaVersion != 1)
        {
            throw new InvalidDataException(
                "Enterprise binding credential schema version is unsupported.");
        }

        EnterpriseBindingValidation.CanonicalizeUuid(
            protectedCommit.BindingId,
            "protected_commit.binding_id");
        EnterpriseBindingValidation.CanonicalizeUuid(
            protectedCommit.InstallationId,
            "protected_commit.installation_id");
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            protectedCommit.DeviceKeyThumbprint,
            "protected_commit.device_key_thumbprint",
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            protectedCommit.RefreshToken,
            "protected_commit.refresh_token",
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            protectedCommit.AuthorizationLeaseSha256,
            "protected_commit.authorization_lease_sha256",
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            protectedCommit.BindingReceiptSha256,
            "protected_commit.binding_receipt_sha256",
            32);
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            receipt.AuthorizationLeaseSha256,
            "binding_receipt.authorization_lease_sha256",
            32);
        _ = EnterpriseSignedLeaseEnvelopeParser.Parse(lease.AuthorizationLease);

        if (!string.Equals(protectedCommit.BindingId, receipt.BindingId, StringComparison.Ordinal)
            || !string.Equals(
                protectedCommit.InstallationId,
                receipt.InstallationId,
                StringComparison.Ordinal)
            || !string.Equals(
                protectedCommit.DeviceKeyThumbprint,
                receipt.DeviceKeyThumbprint,
                StringComparison.Ordinal)
            || !string.Equals(
                protectedCommit.AuthorizationLeaseSha256,
                receipt.AuthorizationLeaseSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise binding credential documents are not mutually consistent.");
        }

        ValidateReceipt(receipt);
        if (protectedCommit.SchemaVersion == 1
            && (protectedCommit.AuthorizationLease is not null
                || protectedCommit.BindingReceipt is not null)
            || protectedCommit.SchemaVersion == 2
                && (!string.Equals(
                        protectedCommit.AuthorizationLease,
                        lease.AuthorizationLease,
                        StringComparison.Ordinal)
                    || protectedCommit.BindingReceipt is null))
        {
            throw new InvalidDataException(
                "Enterprise protected binding commit has invalid versioned projections.");
        }
    }

    private static BindingReceiptDocument CreateReceiptDocument(
        EnterpriseDeviceBindingCompleteResponse response,
        EnterpriseAuthorizationLeaseClaims claims,
        string leaseHashText) => new()
    {
        SchemaVersion = 1,
        BindingId = claims.BindingId,
        InstallationId = claims.InstallationId,
        DeviceKeyThumbprint = claims.DeviceKeyThumbprint,
        EmployeeAuthorizationId = claims.Subject,
        LeaseId = claims.LeaseId,
        AuthorizationEpoch = claims.AuthorizationEpoch,
        EntitlementEpoch = claims.EntitlementEpoch,
        BindingEpoch = claims.BindingEpoch,
        ApiAllocationId = claims.ApiAllocationId,
        AllocationEpoch = claims.AllocationEpoch,
        ApiProfileId = claims.ApiProfileId,
        ApiProfileVersion = claims.ApiProfileVersion,
        PluginPolicyId = claims.PluginPolicyId,
        PluginPolicyGeneration = claims.PluginPolicyGeneration,
        PluginPolicySha256 = claims.PluginPolicySha256,
        RolloutChannel = claims.RolloutChannel,
        ServerTimeUtc = response.ServerTimeUtc,
        LeaseExpiresAtUtc = response.LeaseExpiresAtUtc,
        AuthorizationLeaseSha256 = leaseHashText,
    };

    private static void ValidateReceipt(BindingReceiptDocument receipt)
    {
        EnterpriseBindingValidation.CanonicalizeUuid(receipt.BindingId, "binding_receipt.binding_id");
        EnterpriseBindingValidation.CanonicalizeUuid(
            receipt.InstallationId,
            "binding_receipt.installation_id");
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            receipt.DeviceKeyThumbprint,
            "binding_receipt.device_key_thumbprint",
            32);
        EnterpriseBindingValidation.CanonicalizeUuid(
            receipt.EmployeeAuthorizationId,
            "binding_receipt.employee_authorization_id");
        EnterpriseBindingValidation.CanonicalizeUuid(receipt.LeaseId, "binding_receipt.lease_id");
        EnterpriseBindingValidation.CanonicalizeUuid(
            receipt.ApiAllocationId,
            "binding_receipt.api_allocation_id");
        EnterpriseBindingValidation.CanonicalizeUuid(
            receipt.ApiProfileId,
            "binding_receipt.api_profile_id");
        EnterpriseBindingValidation.CanonicalizeUuid(
            receipt.PluginPolicyId,
            "binding_receipt.plugin_policy_id");
        EnterpriseBindingValidation.ValidateCanonicalLowercaseSha256(
            receipt.PluginPolicySha256,
            "binding_receipt.plugin_policy_sha256");
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            receipt.ServerTimeUtc,
            "binding_receipt.server_time");
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            receipt.LeaseExpiresAtUtc,
            "binding_receipt.lease_expires_at");
        if (receipt.AuthorizationEpoch <= 0
            || receipt.EntitlementEpoch <= 0
            || receipt.BindingEpoch <= 0
            || receipt.AllocationEpoch <= 0
            || receipt.ApiProfileVersion <= 0
            || receipt.PluginPolicyGeneration <= 0
            || receipt.RolloutChannel is not "LAB" and not "PILOT" and not "STABLE")
        {
            throw new InvalidDataException(
                "Enterprise binding receipt contains invalid epoch or policy state.");
        }
    }

    private static EnterpriseBindingReceipt ToReceipt(BindingReceiptDocument document) => new(
        document.BindingId,
        document.InstallationId,
        document.DeviceKeyThumbprint,
        document.EmployeeAuthorizationId,
        document.LeaseId,
        new EnterpriseAuthorizationEpochState(
            document.AuthorizationEpoch,
            document.EntitlementEpoch,
            document.BindingEpoch,
            document.ApiAllocationId,
            document.AllocationEpoch,
            document.ApiProfileId,
            document.ApiProfileVersion,
            document.PluginPolicyId,
            document.PluginPolicyGeneration,
            document.PluginPolicySha256,
            document.RolloutChannel),
        document.ServerTimeUtc,
        document.LeaseExpiresAtUtc,
        document.AuthorizationLeaseSha256);

    private static T DeserializeExact<T>(byte[] bytes, string description)
    {
        EnterpriseStrictJson.ValidateNoDuplicateProperties(bytes);
        return JsonSerializer.Deserialize<T>(bytes, StrictJson)
            ?? throw new InvalidDataException($"Enterprise {description} is empty.");
    }

    private void DeletePlainProjection(EnterpriseManagedArtifact artifact) =>
        EnterpriseLocalStateSecurity.DeleteExactFile(
            _paths.Resolve(artifact),
            _paths.ManagedRoot);

    private async Task WriteProjectionIfAbsentOrExactAsync(
        EnterpriseManagedArtifact artifact,
        ReadOnlyMemory<byte> expectedBytes,
        CancellationToken cancellationToken)
    {
        var path = _paths.Resolve(artifact);
        if (!File.Exists(path))
        {
            await EnterpriseLocalStateSecurity.WriteAtomicAsync(
                    path,
                    _paths.ManagedRoot,
                    expectedBytes,
                    overwrite: false,
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        var existingBytes = await EnterpriseLocalStateSecurity.ReadBoundedAsync(
                path,
                _paths.ManagedRoot,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (existingBytes.Length != expectedBytes.Length
                || !CryptographicOperations.FixedTimeEquals(
                    existingBytes,
                    expectedBytes.Span))
            {
                throw new InvalidDataException(
                    "Existing enterprise binding projection differs from the verified server replay.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(existingBytes);
        }
    }

    private async Task WriteProjectionExactOrReplaceAsync(
        EnterpriseManagedArtifact artifact,
        ReadOnlyMemory<byte> expectedBytes,
        CancellationToken cancellationToken)
    {
        var path = _paths.Resolve(artifact);
        if (File.Exists(path))
        {
            var existingBytes = await EnterpriseLocalStateSecurity.ReadBoundedAsync(
                    path,
                    _paths.ManagedRoot,
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                if (existingBytes.Length == expectedBytes.Length
                    && CryptographicOperations.FixedTimeEquals(
                        existingBytes,
                        expectedBytes.Span))
                {
                    return;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(existingBytes);
            }
        }

        await EnterpriseLocalStateSecurity.WriteAtomicAsync(
                path,
                _paths.ManagedRoot,
                expectedBytes,
                overwrite: true,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private sealed class AuthorizationLeaseCacheDocument
    {
        [JsonPropertyName("schema_version")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("authorization_lease")]
        public required string AuthorizationLease { get; init; }
    }

    private sealed class ProtectedBindingCommitDocument
    {
        [JsonPropertyName("schema_version")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("binding_id")]
        public required string BindingId { get; init; }

        [JsonPropertyName("installation_id")]
        public required string InstallationId { get; init; }

        [JsonPropertyName("device_key_thumbprint")]
        public required string DeviceKeyThumbprint { get; init; }

        [JsonPropertyName("refresh_token")]
        public required string RefreshToken { get; init; }

        [JsonPropertyName("authorization_lease_sha256")]
        public required string AuthorizationLeaseSha256 { get; init; }

        [JsonPropertyName("binding_receipt_sha256")]
        public required string BindingReceiptSha256 { get; init; }

        [JsonPropertyName("authorization_lease")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? AuthorizationLease { get; init; }

        [JsonPropertyName("binding_receipt")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public BindingReceiptDocument? BindingReceipt { get; init; }
    }

    private sealed class BindingReceiptDocument
    {
        [JsonPropertyName("schema_version")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("binding_id")]
        public required string BindingId { get; init; }

        [JsonPropertyName("installation_id")]
        public required string InstallationId { get; init; }

        [JsonPropertyName("device_key_thumbprint")]
        public required string DeviceKeyThumbprint { get; init; }

        [JsonPropertyName("employee_authorization_id")]
        public required string EmployeeAuthorizationId { get; init; }

        [JsonPropertyName("lease_id")]
        public required string LeaseId { get; init; }

        [JsonPropertyName("auth_epoch")]
        public required long AuthorizationEpoch { get; init; }

        [JsonPropertyName("entitlement_epoch")]
        public required long EntitlementEpoch { get; init; }

        [JsonPropertyName("binding_epoch")]
        public required long BindingEpoch { get; init; }

        [JsonPropertyName("api_allocation_id")]
        public required string ApiAllocationId { get; init; }

        [JsonPropertyName("allocation_epoch")]
        public required long AllocationEpoch { get; init; }

        [JsonPropertyName("api_profile_id")]
        public required string ApiProfileId { get; init; }

        [JsonPropertyName("api_profile_version")]
        public required long ApiProfileVersion { get; init; }

        [JsonPropertyName("plugin_policy_id")]
        public required string PluginPolicyId { get; init; }

        [JsonPropertyName("plugin_policy_generation")]
        public required long PluginPolicyGeneration { get; init; }

        [JsonPropertyName("plugin_policy_sha256")]
        public required string PluginPolicySha256 { get; init; }

        [JsonPropertyName("rollout_channel")]
        public required string RolloutChannel { get; init; }

        [JsonPropertyName("server_time")]
        public required DateTimeOffset ServerTimeUtc { get; init; }

        [JsonPropertyName("lease_expires_at")]
        public required DateTimeOffset LeaseExpiresAtUtc { get; init; }

        [JsonPropertyName("authorization_lease_sha256")]
        public required string AuthorizationLeaseSha256 { get; init; }
    }
}
