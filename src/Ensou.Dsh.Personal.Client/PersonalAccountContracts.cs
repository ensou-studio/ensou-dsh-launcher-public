namespace Ensou.Dsh.Personal.Client;

public sealed record PersonalDevicePublicKey(string X, string Y);

/// <summary>Signs SHA-256/ES256 with a device key; implementations must not export private keys.</summary>
public interface IPersonalDeviceProofKey
{
    PersonalDevicePublicKey ReadPublicKey();
    byte[] Sign(ReadOnlySpan<byte> signingInput);
}

/// <summary>Online personal-account operations for one installation.</summary>
public interface IPersonalAccountClient
{
    Task<PersonalEmailChallenge> RequestEmailAsync(string email, CancellationToken cancellationToken = default);
    Task<PersonalAccountSession> SignInAsync(PersonalEmailChallenge challenge, string code,
        CancellationToken cancellationToken = default);
    Task<PersonalAccountAccess> ValidateAccessAsync(PersonalAccountSession session,
        CancellationToken cancellationToken = default);
    Task<PersonalAccountSession> RefreshAsync(PersonalAccountSession session,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Durable session storage. SaveAsync must atomically replace any prior session;
/// a failed SaveAsync must not leave a partial or mixed session readable.
/// </summary>
public interface IPersonalAccountSessionStore
{
    Task<PersonalAccountSession?> LoadAsync(CancellationToken cancellationToken = default);
    Task SaveAsync(PersonalAccountSession session, CancellationToken cancellationToken = default);
    Task ClearAsync(CancellationToken cancellationToken = default);
}

public enum PersonalAccountFailure
{
    Denied,
    RateLimited,
    Unavailable,
    InvalidResponse,
    ReauthenticationRequired,
    Busy,
}

public sealed class PersonalAccountException(PersonalAccountFailure failure)
    : Exception("Personal account operation could not be completed.")
{
    public PersonalAccountFailure Failure { get; } = failure;
}

public sealed class PersonalEmailChallenge
{
    internal PersonalEmailChallenge(string challengeId) => ChallengeId = challengeId;
    public string ChallengeId { get; }
    public override string ToString() => "PersonalEmailChallenge { Redacted }";
}

/// <summary>Online account credentials, not an offline runtime lease or a model API token.</summary>
public sealed class PersonalAccountSession
{
    internal PersonalAccountSession(Uri origin, string sessionId, string accountId, string installationId,
        string accessToken, string refreshToken, DateTimeOffset issuedAtUtc,
        DateTimeOffset accessExpiresAtUtc, DateTimeOffset refreshExpiresAtUtc)
    {
        Origin = origin;
        SessionId = sessionId;
        AccountId = accountId;
        InstallationId = installationId;
        AccessToken = accessToken;
        RefreshToken = refreshToken;
        IssuedAtUtc = issuedAtUtc;
        AccessExpiresAtUtc = accessExpiresAtUtc;
        RefreshExpiresAtUtc = refreshExpiresAtUtc;
    }
    public Uri Origin { get; }
    public string SessionId { get; }
    public string AccountId { get; }
    public string InstallationId { get; }
    public string AccessToken { get; }
    public string RefreshToken { get; }
    public DateTimeOffset IssuedAtUtc { get; }
    public DateTimeOffset AccessExpiresAtUtc { get; }
    public DateTimeOffset RefreshExpiresAtUtc { get; }
    public override string ToString() => "PersonalAccountSession { Redacted }";
}

public sealed record PersonalAccountAccess(DateTimeOffset CheckedAtUtc, DateTimeOffset AccessExpiresAtUtc);

public static class PersonalAccountRoutes
{
    public const string Nonce = "/v1/personal/device-proofs/nonce";
    public const string EmailRequest = "/v1/personal/email/request";
    public const string SignIn = "/v1/personal/sessions/sign-in";
    public const string Access = "/v1/personal/sessions/access";
    public const string Refresh = "/v1/personal/sessions/refresh";
}
