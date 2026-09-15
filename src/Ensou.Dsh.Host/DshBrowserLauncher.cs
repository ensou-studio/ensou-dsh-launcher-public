using System.Diagnostics;

namespace Ensou.Dsh.Host;

public static class DshBrowserLauncher
{
    internal const string FailureMessage =
        "Windows 无法打开 DSH WebUI。请检查默认浏览器设置后重试。";

    public static void Open(Uri browserLaunchUri) =>
        Open(browserLaunchUri, Process.Start);

    internal static void Open(
        Uri browserLaunchUri,
        Func<ProcessStartInfo, Process?> startProcess)
    {
        ArgumentNullException.ThrowIfNull(browserLaunchUri);
        ArgumentNullException.ThrowIfNull(startProcess);
        try
        {
            ValidateLaunchUri(browserLaunchUri);
            using var launched = startProcess(new ProcessStartInfo
            {
                FileName = browserLaunchUri.AbsoluteUri,
                UseShellExecute = true,
            });
        }
        catch (Exception)
        {
            // Shell exceptions may include ProcessStartInfo.FileName. Never let
            // the token-bearing launch URL cross into UI or diagnostics.
            throw new InvalidOperationException(FailureMessage);
        }
    }

    private static void ValidateLaunchUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            || !string.Equals(uri.Host, "127.0.0.1", StringComparison.Ordinal)
            || uri.AbsolutePath != "/"
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException(FailureMessage);
        }

        if (string.IsNullOrEmpty(uri.Query))
        {
            return;
        }

        var cleanRoot = new Uri($"{uri.GetLeftPart(UriPartial.Authority)}/");
        _ = DshBrowserAuthentication.ParseLaunchAnnouncement(
                $"dsh web: {uri.AbsoluteUri}",
                cleanRoot)
            ?? throw new InvalidOperationException(FailureMessage);
    }
}
