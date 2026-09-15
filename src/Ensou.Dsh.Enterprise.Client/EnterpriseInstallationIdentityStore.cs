using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Client;

public sealed record EnterpriseInstallationIdentity(
    Guid InstallId,
    DateTimeOffset CreatedAtUtc);

public sealed class EnterpriseInstallationIdentityStore
{
    private const int CurrentSchemaVersion = 1;

    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly EnterpriseManagedPaths _paths;
    private readonly TimeProvider _timeProvider;

    public EnterpriseInstallationIdentityStore(
        EnterpriseManagedPaths paths,
        TimeProvider? timeProvider = null)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<EnterpriseInstallationIdentity> GetOrCreateAsync(
        CancellationToken cancellationToken = default)
    {
        if (File.Exists(_paths.InstallationIdentityPath))
        {
            return await ReadAsync(cancellationToken).ConfigureAwait(false);
        }

        var identity = new EnterpriseInstallationIdentity(
            Guid.NewGuid(),
            _timeProvider.GetUtcNow());
        var document = new InstallationIdentityDocument(
            CurrentSchemaVersion,
            identity.InstallId.ToString("D"),
            identity.CreatedAtUtc);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(document, StrictJson);

        try
        {
            await EnterpriseLocalStateSecurity.WriteAtomicAsync(
                    _paths.InstallationIdentityPath,
                    _paths.ManagedRoot,
                    bytes,
                    overwrite: false,
                    cancellationToken)
                .ConfigureAwait(false);
            return identity;
        }
        catch (IOException) when (File.Exists(_paths.InstallationIdentityPath))
        {
            return await ReadAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<EnterpriseInstallationIdentity> ReadAsync(
        CancellationToken cancellationToken)
    {
        var bytes = await EnterpriseLocalStateSecurity.ReadBoundedAsync(
                _paths.InstallationIdentityPath,
                _paths.ManagedRoot,
                cancellationToken)
            .ConfigureAwait(false);
        var document = JsonSerializer.Deserialize<InstallationIdentityDocument>(bytes, StrictJson)
            ?? throw new InvalidDataException("Enterprise installation identity is empty.");

        if (document.SchemaVersion != CurrentSchemaVersion
            || !Guid.TryParseExact(document.InstallId, "D", out var installId)
            || installId == Guid.Empty
            || document.CreatedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Enterprise installation identity is invalid.");
        }

        return new EnterpriseInstallationIdentity(installId, document.CreatedAtUtc);
    }

    private sealed record InstallationIdentityDocument(
        [property: JsonPropertyName("schema_version")] int SchemaVersion,
        [property: JsonPropertyName("install_id")] string InstallId,
        [property: JsonPropertyName("created_at_utc")] DateTimeOffset CreatedAtUtc);
}
