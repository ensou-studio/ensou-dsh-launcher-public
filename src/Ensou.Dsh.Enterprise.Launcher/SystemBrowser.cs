using System.Diagnostics;
using Ensou.Dsh.Enterprise.Client;

namespace Ensou.Dsh.Enterprise.Launcher;

internal sealed class SystemBrowser : IEnterpriseSystemBrowser
{
    public void Open(Uri authorizationUrl)
    {
        ArgumentNullException.ThrowIfNull(authorizationUrl);
        if (!authorizationUrl.IsAbsoluteUri
            || !string.Equals(
                authorizationUrl.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(authorizationUrl.UserInfo))
        {
            throw new InvalidOperationException(
                "Enterprise authorization requires a clean absolute HTTPS URL.");
        }

        _ = Process.Start(new ProcessStartInfo
        {
            FileName = authorizationUrl.AbsoluteUri,
            UseShellExecute = true,
        }) ?? throw new InvalidOperationException(
            "Windows did not start the enterprise authorization browser.");
    }
}
