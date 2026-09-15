using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Ensou.Dsh.Host;

internal sealed record DshBrowserSession(
    int ProcessId,
    Uri LaunchUri,
    string CookieHeader)
{
    public override string ToString() =>
        $"DshBrowserSession {{ ProcessId = {ProcessId}, credentials = redacted }}";
}

internal static class DshBrowserAuthentication
{
    private const string AnnouncementPrefix = "dsh web: ";
    private const string CookiePrefix = "dsh-auth-";
    private static readonly Regex TokenRedaction = new(
        @"([?&]token=)[^\s)]+",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>
    /// Returns null for unrelated output and fails loud for a malformed line that claims
    /// to be the DSH readiness announcement.
    /// </summary>
    internal static Uri? ParseLaunchAnnouncement(string line, Uri expectedWebUiUri)
    {
        ArgumentNullException.ThrowIfNull(line);
        ArgumentNullException.ThrowIfNull(expectedWebUiUri);
        if (!line.StartsWith(AnnouncementPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        var candidate = line[AnnouncementPrefix.Length..];
        if (candidate.Length == 0
            || candidate.Any(char.IsWhiteSpace)
            || !Uri.TryCreate(candidate, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            || !string.Equals(uri.Host, "127.0.0.1", StringComparison.Ordinal)
            || uri.Port != expectedWebUiUri.Port
            || uri.AbsolutePath != "/"
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidDataException(
                "DSH emitted a malformed browser authentication readiness URL.");
        }

        const string queryPrefix = "?token=";
        if (!uri.Query.StartsWith(queryPrefix, StringComparison.Ordinal)
            || uri.Query.Length != queryPrefix.Length + 43)
        {
            throw new InvalidDataException(
                "DSH emitted a browser readiness URL with a malformed token query.");
        }

        var token = uri.Query[queryPrefix.Length..];
        if (!IsCanonicalBase64Url32(token))
        {
            throw new InvalidDataException(
                "DSH emitted a browser readiness URL with a noncanonical token.");
        }

        var expected = $"{expectedWebUiUri.GetLeftPart(UriPartial.Authority)}/?token={token}";
        if (!string.Equals(candidate, expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "DSH emitted a browser readiness URL outside the configured loopback authority.");
        }

        return uri;
    }

    internal static string RedactTokens(string line) =>
        TokenRedaction.Replace(line, "$1<redacted>");

    internal static async Task<DshBrowserSession> ExchangeAsync(
        HttpClient httpClient,
        Uri launchUri,
        Uri expectedWebUiUri,
        int processId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(launchUri);
        ArgumentNullException.ThrowIfNull(expectedWebUiUri);
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(processId));
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, launchUri);
        using var response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.SeeOther
            || response.Headers.Location?.OriginalString != "/"
            || !HasExactSingleHeader(response, "Cache-Control", "no-store")
            || !HasExactSingleHeader(response, "Referrer-Policy", "no-referrer"))
        {
            throw new InvalidDataException(
                "DSH browser token exchange did not return the required clean-root redirect.");
        }

        if (!response.Headers.TryGetValues("Set-Cookie", out var setCookieValues))
        {
            throw new InvalidDataException("DSH browser token exchange omitted its session cookie.");
        }

        var values = setCookieValues.ToArray();
        if (values.Length != 1)
        {
            throw new InvalidDataException(
                "DSH browser token exchange returned an ambiguous session cookie set.");
        }

        var cookieHeader = ValidateSessionCookie(values[0], expectedWebUiUri);
        return new DshBrowserSession(processId, launchUri, cookieHeader);
    }

    internal static void ApplyCookie(HttpRequestMessage request, DshBrowserSession session)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(session);
        if (!request.Headers.TryAddWithoutValidation("Cookie", session.CookieHeader))
        {
            throw new InvalidOperationException("The DSH browser session cookie could not be attached.");
        }
    }

    private static bool HasExactSingleHeader(
        HttpResponseMessage response,
        string name,
        string expected)
    {
        if (!response.Headers.TryGetValues(name, out var values))
        {
            return false;
        }

        var materialized = values.ToArray();
        return materialized.Length == 1
            && string.Equals(materialized[0], expected, StringComparison.Ordinal);
    }

    private static string ValidateSessionCookie(string setCookie, Uri expectedWebUiUri)
    {
        var segments = setCookie.Split(';');
        if (segments.Length != 6
            || !segments[1].StartsWith(" Max-Age=", StringComparison.Ordinal)
            || !long.TryParse(
                segments[1][" Max-Age=".Length..],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var maxAge)
            || maxAge <= 0
            || segments[2] != " Path=/"
            || !segments[3].StartsWith(" Expires=", StringComparison.Ordinal)
            || !DateTimeOffset.TryParseExact(
                segments[3][" Expires=".Length..],
                "R",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out _)
            || segments[4] != " HttpOnly"
            || segments[5] != " SameSite=Strict")
        {
            throw new InvalidDataException(
                "DSH browser token exchange returned unexpected cookie attributes.");
        }

        var separator = segments[0].IndexOf('=');
        if (separator <= 0 || separator == segments[0].Length - 1)
        {
            throw new InvalidDataException("DSH browser token exchange returned a malformed cookie.");
        }

        var expectedName = CookiePrefix + EncodeBase64Url(SHA256.HashData(
            Encoding.UTF8.GetBytes(NormalizedAuthority(expectedWebUiUri))));
        var name = segments[0][..separator];
        var value = segments[0][(separator + 1)..];
        var valueParts = value.Split('.');
        if (!string.Equals(name, expectedName, StringComparison.Ordinal)
            || valueParts.Length != 3
            || valueParts[0] != "v1"
            || !IsCanonicalBase64Url(valueParts[1], maximumDecodedBytes: 2048)
            || valueParts[2].Length != 43
            || !IsCanonicalBase64Url32(valueParts[2]))
        {
            throw new InvalidDataException(
                "DSH browser token exchange returned a malformed signed cookie value.");
        }

        return segments[0];
    }

    private static string NormalizedAuthority(Uri uri) => uri.IsDefaultPort
        ? uri.Host.ToLowerInvariant()
        : $"{uri.Host.ToLowerInvariant()}:{uri.Port.ToString(CultureInfo.InvariantCulture)}";

    private static bool IsCanonicalBase64Url32(string value)
    {
        if (value.Length != 43 || !IsCanonicalBase64Url(value, maximumDecodedBytes: 32))
        {
            return false;
        }

        try
        {
            var decoded = Convert.FromBase64String(
                value.Replace('-', '+').Replace('_', '/') + "=");
            return decoded.Length == 32
                && string.Equals(EncodeBase64Url(decoded), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsCanonicalBase64Url(string value, int maximumDecodedBytes)
    {
        if (value.Length == 0
            || value.Length > checked(maximumDecodedBytes * 2)
            || value.Length % 4 == 1
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_')))
        {
            return false;
        }

        try
        {
            var padding = new string('=', (4 - value.Length % 4) % 4);
            var decoded = Convert.FromBase64String(
                value.Replace('-', '+').Replace('_', '/') + padding);
            return decoded.Length <= maximumDecodedBytes
                && string.Equals(EncodeBase64Url(decoded), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
