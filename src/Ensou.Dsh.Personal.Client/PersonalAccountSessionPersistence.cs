namespace Ensou.Dsh.Personal.Client;

internal static class PersonalAccountSessionPersistence
{
    public static PersonalAccountSession RestoreValidated(
        Uri expectedOrigin,
        string expectedInstallationId,
        string origin,
        string sessionId,
        string accountId,
        string installationId,
        string accessToken,
        string refreshToken,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset accessExpiresAtUtc,
        DateTimeOffset refreshExpiresAtUtc)
    {
        var canonicalExpectedOrigin = PersonalAccountFormat.RequireOrigin(expectedOrigin);
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var parsedOrigin))
        {
            throw InvalidState();
        }

        var canonicalOrigin = PersonalAccountFormat.RequireOrigin(parsedOrigin);
        var canonicalExpectedInstallationId = PersonalAccountFormat.RequireUuid(expectedInstallationId);
        var canonicalInstallationId = PersonalAccountFormat.RequireUuid(installationId);
        var canonicalSessionId = PersonalAccountFormat.RequireUuid(sessionId);
        if (!Guid.TryParseExact(accountId, "D", out var parsedAccountId)
            || parsedAccountId == Guid.Empty
            || !string.Equals(parsedAccountId.ToString("D"), accountId, StringComparison.Ordinal)
            || canonicalOrigin != canonicalExpectedOrigin
            || !string.Equals(origin, canonicalOrigin.AbsoluteUri, StringComparison.Ordinal)
            || !string.Equals(
                canonicalInstallationId,
                canonicalExpectedInstallationId,
                StringComparison.Ordinal))
        {
            throw InvalidState();
        }

        PersonalAccountFormat.RequireToken(accessToken, "psa_");
        PersonalAccountFormat.RequireToken(refreshToken, "psr_");
        var accessLifetime = accessExpiresAtUtc - issuedAtUtc;
        var refreshLifetime = refreshExpiresAtUtc - issuedAtUtc;
        if (issuedAtUtc.Offset != TimeSpan.Zero
            || accessExpiresAtUtc.Offset != TimeSpan.Zero
            || refreshExpiresAtUtc.Offset != TimeSpan.Zero
            || accessLifetime < TimeSpan.FromMinutes(1)
            || accessLifetime > TimeSpan.FromMinutes(15)
            || refreshLifetime < TimeSpan.FromHours(1)
            || refreshLifetime > TimeSpan.FromDays(30))
        {
            throw InvalidState();
        }

        return new PersonalAccountSession(
            canonicalOrigin,
            canonicalSessionId,
            accountId,
            canonicalInstallationId,
            accessToken,
            refreshToken,
            issuedAtUtc,
            accessExpiresAtUtc,
            refreshExpiresAtUtc);
    }

    private static InvalidDataException InvalidState() =>
        new("Personal account session state is invalid.");
}
