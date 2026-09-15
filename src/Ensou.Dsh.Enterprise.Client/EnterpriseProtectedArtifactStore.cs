using System.Security.Cryptography;
using System.Text;

namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterpriseProtectedArtifactStore
{
    private readonly EnterpriseManagedPaths _paths;
    private readonly string _entropyIdentity;

    public EnterpriseProtectedArtifactStore(EnterpriseManagedPaths paths)
        : this(paths, EnterpriseProductIdentity.AppUserModelId)
    {
    }

    public EnterpriseProtectedArtifactStore(
        EnterpriseManagedPaths paths,
        string entropyIdentity)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        EnterpriseBindingValidation.ValidateBoundedText(
            entropyIdentity,
            nameof(entropyIdentity),
            1,
            128);
        _entropyIdentity = entropyIdentity;
    }

    public async Task WriteAsync(
        EnterpriseManagedArtifact artifact,
        ReadOnlyMemory<byte> plaintext,
        CancellationToken cancellationToken = default)
    {
        await WriteCoreAsync(
                artifact,
                plaintext,
                overwrite: true,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task WriteNewAsync(
        EnterpriseManagedArtifact artifact,
        ReadOnlyMemory<byte> plaintext,
        CancellationToken cancellationToken = default)
    {
        await WriteCoreAsync(
                artifact,
                plaintext,
                overwrite: false,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task WriteCoreAsync(
        EnterpriseManagedArtifact artifact,
        ReadOnlyMemory<byte> plaintext,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        ValidateProtectedArtifact(artifact);
        if (plaintext.IsEmpty)
        {
            throw new ArgumentException("Protected enterprise artifact must not be empty.", nameof(plaintext));
        }

        var plaintextBytes = plaintext.ToArray();
        byte[]? protectedBytes = null;
        try
        {
            protectedBytes = ProtectedData.Protect(
                plaintextBytes,
                CreateEntropy(artifact),
                DataProtectionScope.CurrentUser);
            await EnterpriseLocalStateSecurity.WriteAtomicAsync(
                    _paths.Resolve(artifact),
                    _paths.ManagedRoot,
                    protectedBytes,
                    overwrite,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
    }

    public async Task<byte[]?> ReadAsync(
        EnterpriseManagedArtifact artifact,
        CancellationToken cancellationToken = default)
    {
        ValidateProtectedArtifact(artifact);
        var path = _paths.Resolve(artifact);
        if (!File.Exists(path))
        {
            return null;
        }

        var protectedBytes = await EnterpriseLocalStateSecurity.ReadBoundedAsync(
                path,
                _paths.ManagedRoot,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return ProtectedData.Unprotect(
                protectedBytes,
                CreateEntropy(artifact),
                DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException exception)
        {
            throw new CryptographicException(
                "Enterprise protected state could not be authenticated for this Windows user.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    public void Delete(EnterpriseManagedArtifact artifact)
    {
        ValidateProtectedArtifact(artifact);
        EnterpriseLocalStateSecurity.DeleteExactFile(
            _paths.Resolve(artifact),
            _paths.ManagedRoot);
    }

    private byte[] CreateEntropy(EnterpriseManagedArtifact artifact) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{_entropyIdentity}|{artifact}|v1"));

    private static void ValidateProtectedArtifact(EnterpriseManagedArtifact artifact)
    {
        if (artifact is not EnterpriseManagedArtifact.RefreshTokenDpapi
            and not EnterpriseManagedArtifact.EnrollmentSessionDpapi
            and not EnterpriseManagedArtifact.PendingBindingTransactionDpapi
            and not EnterpriseManagedArtifact.PendingRefreshTransactionDpapi
            and not EnterpriseManagedArtifact.PendingUpdateReceiptTransactionDpapi
            and not EnterpriseManagedArtifact.ResetBarrierDpapi
            and not EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi)
        {
            throw new ArgumentOutOfRangeException(
                nameof(artifact),
                artifact,
                "Only fixed enterprise credential artifacts may use DPAPI storage.");
        }
    }
}
