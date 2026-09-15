using System.Security.Cryptography;
using System.Text;

namespace Ensou.Dsh.Personal.Client;

public static class PersonalAccountFormat
{
    private const string AllowedLocalSpecialCharacters = "!#$%&'*+-/=?^_`{|}~";

    public static string CanonicalizeEmail(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 254 || value != value.Trim())
            throw InvalidArgument();

        var separator = value.IndexOf('@');
        if (separator <= 0 || separator != value.LastIndexOf('@') || separator > 64)
            throw InvalidArgument();

        var local = value.AsSpan(0, separator);
        var domain = value.AsSpan(separator + 1);
        if (!IsValidLocal(local) || !IsValidDomain(domain))
            throw InvalidArgument();

        return string.Concat(local, "@", domain.ToString().ToLowerInvariant());
    }

    public static Uri RequireOrigin(Uri value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.IsAbsoluteUri
            || !string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !value.IsDefaultPort
            || value.Port != 443
            || value.AbsolutePath != "/"
            || value.Query.Length != 0
            || value.Fragment.Length != 0
            || value.UserInfo.Length != 0
            || value.HostNameType != UriHostNameType.Dns
            || value.IsLoopback
            || value.Host.EndsWith(".", StringComparison.Ordinal)
            || value.Host.Length == 0
            || value.OriginalString.Any(static c => c > 127 || char.IsControl(c)))
            throw InvalidArgument();

        var host = value.Host.ToLowerInvariant();
        if (host.Any(static c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '.'))
            throw InvalidArgument();
        return new Uri($"https://{host}/", UriKind.Absolute);
    }

    public static string RequireUuid(string value)
    {
        if (value is null || value.Length != 36 || !Guid.TryParseExact(value, "D", out var id)
            || !string.Equals(id.ToString("D"), value, StringComparison.Ordinal)
            || value[14] != '4' || value[19] is not ('8' or '9' or 'a' or 'b'))
            throw InvalidArgument();
        return value;
    }

    public static string RequireToken(string value, string prefix)
    {
        ArgumentNullException.ThrowIfNull(prefix);
        if (value is null || prefix.Length == 0 || value.Length != prefix.Length + 43
            || !value.StartsWith(prefix, StringComparison.Ordinal))
            throw InvalidArgument();
        RequireBase64Url(value[prefix.Length..], 32);
        return value;
    }

    public static string RequireBase64Url(string value, int decodedBytes)
    {
        if (value is null || decodedBytes is < 1 or > 1024
            || value.Length != checked((decodedBytes * 8 + 5) / 6)
            || value.Contains('='))
            throw InvalidArgument();
        if (value.Any(static c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_'))
            throw InvalidArgument();

        byte[]? bytes = null;
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            padded += (value.Length % 4) switch
            {
                0 => string.Empty,
                2 => "==",
                3 => "=",
                _ => throw InvalidArgument(),
            };
            bytes = Convert.FromBase64String(padded);
            if (bytes.Length != decodedBytes || Encode(bytes) != value)
                throw InvalidArgument();
            return value;
        }
        catch (FormatException)
        {
            throw InvalidArgument();
        }
        finally
        {
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static string HashToken(string value, string prefix)
    {
        RequireToken(value, prefix);
        var bytes = Encoding.ASCII.GetBytes(value);
        byte[]? digest = null;
        try
        {
            digest = SHA256.HashData(bytes);
            return Encode(digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (digest is not null) CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static bool IsValidLocal(ReadOnlySpan<char> local)
    {
        if (local.IsEmpty || local[0] == '.' || local[^1] == '.') return false;
        var previousWasDot = false;
        foreach (var character in local)
        {
            if (character > 0x7f || char.IsControl(character)) return false;
            if (character == '.')
            {
                if (previousWasDot) return false;
                previousWasDot = true;
                continue;
            }
            previousWasDot = false;
            if (!char.IsAsciiLetterOrDigit(character)
                && !AllowedLocalSpecialCharacters.Contains(character, StringComparison.Ordinal)) return false;
        }
        return true;
    }

    private static bool IsValidDomain(ReadOnlySpan<char> domain)
    {
        if (domain.IsEmpty || domain.Length > 253 || domain[0] == '.' || domain[^1] == '.') return false;
        foreach (var label in domain.ToString().Split('.'))
        {
            if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-') return false;
            if (label.Any(static c => c > 0x7f || (!char.IsAsciiLetterOrDigit(c) && c != '-'))) return false;
        }
        return true;
    }

    private static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static ArgumentException InvalidArgument() =>
        new("The personal account value is invalid.");
}
