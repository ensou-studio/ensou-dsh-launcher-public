namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterpriseControlPlaneOptions
{
    public EnterpriseControlPlaneOptions(Uri apiOrigin, Uri authorizationOrigin)
    {
        ApiOrigin = ValidateOrigin(apiOrigin, nameof(apiOrigin));
        AuthorizationOrigin = ValidateOrigin(authorizationOrigin, nameof(authorizationOrigin));
    }

    public Uri ApiOrigin { get; }

    public Uri AuthorizationOrigin { get; }

    public bool IsAllowedAuthorizationUrl(Uri value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.IsAbsoluteUri
            && string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && string.IsNullOrEmpty(value.UserInfo)
            && string.Equals(value.Host, AuthorizationOrigin.Host, StringComparison.OrdinalIgnoreCase)
            && value.Port == AuthorizationOrigin.Port;
    }

    private static Uri ValidateOrigin(Uri value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (!value.IsAbsoluteUri
            || !string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(value.UserInfo)
            || !string.IsNullOrEmpty(value.Query)
            || !string.IsNullOrEmpty(value.Fragment)
            || value.AbsolutePath != "/")
        {
            throw new ArgumentException(
                "Enterprise origins must be HTTPS origins without credentials, paths, queries, or fragments.",
                parameterName);
        }

        return new UriBuilder(Uri.UriSchemeHttps, value.Host, value.Port).Uri;
    }
}
