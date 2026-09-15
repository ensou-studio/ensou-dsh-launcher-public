using System.IO;
using System.Net.Http;
using System.Reflection;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Launcher;

internal static class UpdateCoordinator
{
    public static async Task<UpdateCheckOutcome> CheckAsync(
        LauncherSettings settings,
        string? installedReleaseId,
        string installedDshVersion,
        CancellationToken cancellationToken = default)
    {
        var manifestUri = ValidateManifestUri(settings.ManifestUrl);
        using var client = CreateHttpClient(TimeSpan.FromSeconds(20));
        using var response = await client.GetAsync(
            manifestUri,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        response.EnsureSuccessStatusCode();

        var manifestBytes = await ReadLimitedAsync(
            response.Content,
            ReleaseManifestJson.MaximumManifestBytes,
            cancellationToken);
        var parsed = ReleaseManifestJson.ParseAndValidate(manifestBytes);
        var keyId = parsed.Signature?.KeyId
            ?? throw new InvalidDataException("更新清单缺少签名 keyId。");
        var publicKeyPem = await TrustedReleaseKeyProvider.GetPublicKeyPemAsync(
            keyId,
            settings,
            cancellationToken);
        var verified = ReleaseManifestSignature.ParseAndVerify(manifestBytes, publicKeyPem, keyId);
        var manifest = verified.Manifest;

        var expectedChannel = ParseChannel(settings.Channel);
        if (manifest.Channel != expectedChannel)
        {
            throw new InvalidDataException(
                $"更新清单属于 {manifest.Channel}，但本机配置为 {expectedChannel}。");
        }

        var launcherVersion = GetLauncherVersion();
        if (ReleaseStateComparer.CompareVersionStrings(launcherVersion, manifest.LauncherVersion) < 0)
        {
            throw new InvalidOperationException(
                $"此 DSH 运行时要求 Launcher {manifest.LauncherVersion} 或更高版本；" +
                $"本机为 {launcherVersion}。请先更新 Launcher。");
        }

        var bootstrapperVersion = GetBootstrapperVersion();
        if (ReleaseStateComparer.CompareVersionStrings(
                bootstrapperVersion,
                manifest.MinimumBootstrapperVersion) < 0)
        {
            throw new InvalidOperationException(
                $"此版本要求 Bootstrapper {manifest.MinimumBootstrapperVersion} 或更高版本；" +
                $"本机为 {bootstrapperVersion}。请联系管理员更新客户端。");
        }

        var updateAvailable = IsNewerOrMissing(
            manifest.ReleaseId,
            manifest.DshVersion,
            installedReleaseId,
            installedDshVersion);

        return new UpdateCheckOutcome(
            Title: updateAvailable ? "发现可用更新" : "当前已是通道最新版本",
            Detail: updateAvailable
                ? $"已验证 {manifest.ReleaseId} 的 ES256 签名，可以安全下载。"
                : $"{manifest.Channel} 通道清单签名有效，本机无需更新。",
            AvailableVersion: manifest.DshVersion,
            UpdateAvailable: updateAvailable,
            ReleaseId: manifest.ReleaseId,
            ArtifactUrl: manifest.Artifact.Url,
            ArtifactFileName: manifest.Artifact.FileName,
            ArtifactSizeBytes: manifest.Artifact.SizeBytes,
            ArtifactSha256: manifest.Artifact.Sha256);
    }

    public static async Task<string> DownloadAsync(
        LauncherSettings settings,
        UpdateCheckOutcome outcome,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (!outcome.UpdateAvailable)
        {
            throw new InvalidOperationException("当前没有需要下载的更新。");
        }

        Directory.CreateDirectory(settings.PackageDirectory);
        var finalPath = Path.Combine(settings.PackageDirectory, outcome.ArtifactFileName);
        var partialPath = finalPath + ".partial";

        if (File.Exists(finalPath))
        {
            var existing = await Sha256Verifier.VerifyFileAsync(
                finalPath,
                outcome.ArtifactSha256,
                outcome.ArtifactSizeBytes,
                cancellationToken);
            if (existing.IsMatch)
            {
                progress?.Report(1);
                return finalPath;
            }

            File.Delete(finalPath);
        }

        using var client = CreateHttpClient(TimeSpan.FromHours(2));
        var downloader = new ResumableDownloader(client);
        var downloadProgress = progress is null
            ? null
            : new Progress<DownloadProgress>(value => progress.Report(value.Fraction));
        await downloader.DownloadAsync(
            new ResumableDownloadRequest(
                new Uri(outcome.ArtifactUrl, UriKind.Absolute),
                partialPath,
                outcome.ArtifactSizeBytes),
            downloadProgress,
            cancellationToken);

        var verification = await Sha256Verifier.VerifyFileAsync(
            partialPath,
            outcome.ArtifactSha256,
            outcome.ArtifactSizeBytes,
            cancellationToken);
        if (!verification.IsMatch)
        {
            File.Delete(partialPath);
            throw new InvalidDataException(
                $"更新包校验失败。期望 {verification.ExpectedSha256}，实际 {verification.ActualSha256}。");
        }

        File.Move(partialPath, finalPath, overwrite: true);
        progress?.Report(1);
        return finalPath;
    }

    private static HttpClient CreateHttpClient(TimeSpan timeout)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = System.Net.DecompressionMethods.None
        };
        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = timeout
        };
    }

    private static Uri ValidateManifestUri(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidDataException("更新清单地址无效。");
        }

        var isLoopbackDevelopment = uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;
        if (uri.Scheme != Uri.UriSchemeHttps && !isLoopbackDevelopment)
        {
            throw new InvalidDataException("更新清单必须使用 HTTPS（本机回环开发服务除外）。");
        }

        return uri;
    }

    private static ReleaseChannel ParseChannel(string value) => value.Trim().ToLowerInvariant() switch
    {
        "lab" => ReleaseChannel.Lab,
        "pilot" => ReleaseChannel.Pilot,
        "stable" => ReleaseChannel.Stable,
        _ => throw new InvalidDataException($"未知更新通道：{value}")
    };

    private static string GetLauncherVersion()
    {
        var assembly = typeof(UpdateCoordinator).Assembly;
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
            .Split('+', 2)[0];
        return string.IsNullOrWhiteSpace(informationalVersion)
            ? assembly.GetName().Version?.ToString(3) ?? "1.0.0"
            : informationalVersion;
    }

    private static string GetBootstrapperVersion()
    {
        var bootstrapperPath = Path.Combine(AppContext.BaseDirectory, "Ensou.Dsh.Bootstrapper.exe");
        if (File.Exists(bootstrapperPath))
        {
            var productVersion = System.Diagnostics.FileVersionInfo
                .GetVersionInfo(bootstrapperPath)
                .ProductVersion?
                .Split('+', 2)[0];
            if (!string.IsNullOrWhiteSpace(productVersion))
            {
                return productVersion;
            }
        }

        // Development builds keep the two projects in separate output folders but version them together.
        return GetLauncherVersion();
    }

    private static bool IsNewerOrMissing(
        string availableReleaseId,
        string availableVersion,
        string? installedReleaseId,
        string installedVersion)
    {
        if (installedVersion is "未安装" or "未知" or "无法识别")
        {
            return true;
        }

        var versionComparison = ReleaseStateComparer.CompareVersionStrings(
            availableVersion,
            installedVersion);
        return versionComparison > 0 ||
            (versionComparison == 0 &&
                !string.Equals(availableReleaseId, installedReleaseId, StringComparison.Ordinal));
    }

    private static async Task<byte[]> ReadLimitedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > maximumBytes)
        {
            throw new InvalidDataException("更新清单超过允许大小。");
        }

        await using var input = await content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = GC.AllocateUninitializedArray<byte>(16 * 1024);
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }

            if (output.Length + read > maximumBytes)
            {
                throw new InvalidDataException("更新清单超过允许大小。");
            }

            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }

        return output.ToArray();
    }
}
