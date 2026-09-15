using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

public enum PersistentDownloadStatus
{
    AlreadyComplete,
    Downloaded,
    Resumed,
}

public sealed record PersistentArtifactDownloadRequest(
    Uri Url,
    string CacheDirectory,
    long ExpectedSizeBytes,
    string ExpectedSha256,
    int BufferSize = 128 * 1024,
    TimeSpan? ReadIdleTimeout = null);

public sealed record PersistentArtifactDownloadResult(
    PersistentDownloadStatus Status,
    string ArtifactPath,
    long InitialBytes,
    long FinalBytes,
    string? EntityTag);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersistentPartialMetadata
{
    public required int SchemaVersion { get; init; }

    public required string Url { get; init; }

    public required long ExpectedSizeBytes { get; init; }

    public required string ExpectedSha256 { get; init; }

    public string? StrongEntityTag { get; init; }

    public required DateTimeOffset UpdatedAtUtc { get; init; }
}

public sealed class PersistentPartialDownloader(HttpClient httpClient)
{
    private const int MetadataSchemaVersion = 1;
    private const int MaximumMetadataBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 16,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    private readonly HttpClient _httpClient = httpClient
        ?? throw new ArgumentNullException(nameof(httpClient));

    public async Task<PersistentArtifactDownloadResult> DownloadAsync(
        PersistentArtifactDownloadRequest request,
        IProgress<DownloadProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateRequest(request);
        var cacheRoot = Path.GetFullPath(request.CacheDirectory);
        Directory.CreateDirectory(cacheRoot);
        RejectReparsePoint(cacheRoot, "cache root");

        var baseName = request.ExpectedSha256;
        var completePath = Path.Combine(cacheRoot, baseName + ".complete");
        var partialPath = Path.Combine(cacheRoot, baseName + ".partial");
        var metadataPath = Path.Combine(cacheRoot, baseName + ".partial.json");
        RejectExistingReparsePoint(completePath);
        RejectExistingReparsePoint(partialPath);
        RejectExistingReparsePoint(metadataPath);

        using var lease = await AcquireLockAsync(
            cacheRoot,
            request.ExpectedSha256,
            cancellationToken).ConfigureAwait(false);
        if (File.Exists(completePath))
        {
            var verification = await Sha256Verifier.VerifyFileAsync(
                completePath,
                request.ExpectedSha256,
                request.ExpectedSizeBytes,
                cancellationToken).ConfigureAwait(false);
            if (verification.IsMatch)
            {
                return new PersistentArtifactDownloadResult(
                    PersistentDownloadStatus.AlreadyComplete,
                    completePath,
                    request.ExpectedSizeBytes,
                    request.ExpectedSizeBytes,
                    null);
            }
            File.Delete(completePath);
        }

        var metadata = await TryReadMetadataAsync(metadataPath, cancellationToken)
            .ConfigureAwait(false);
        if (!MetadataMatches(metadata, request))
        {
            ResetPartial(partialPath, metadataPath);
            metadata = null;
        }

        var existingLength = File.Exists(partialPath) ? new FileInfo(partialPath).Length : 0;
        if (existingLength > request.ExpectedSizeBytes)
        {
            ResetPartial(partialPath, metadataPath);
            metadata = null;
            existingLength = 0;
        }

        if (existingLength == request.ExpectedSizeBytes)
        {
            var completed = await TryPromoteCompletedPartialAsync(
                partialPath,
                metadataPath,
                completePath,
                request,
                cancellationToken).ConfigureAwait(false);
            if (completed)
            {
                return new PersistentArtifactDownloadResult(
                    PersistentDownloadStatus.AlreadyComplete,
                    completePath,
                    existingLength,
                    existingLength,
                    metadata?.StrongEntityTag);
            }
            metadata = null;
            existingLength = 0;
        }

        if (existingLength > 0 && ParseStrongEntityTag(metadata?.StrongEntityTag) is null)
        {
            ResetPartial(partialPath, metadataPath);
            metadata = null;
            existingLength = 0;
        }

        var initialLength = existingLength;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var message = new HttpRequestMessage(HttpMethod.Get, request.Url);
            message.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue("identity"));
            var resumeTag = ParseStrongEntityTag(metadata?.StrongEntityTag);
            if (existingLength > 0 && resumeTag is not null)
            {
                message.Headers.Range = new RangeHeaderValue(existingLength, null);
                message.Headers.IfRange = new RangeConditionHeaderValue(resumeTag);
            }

            using var response = await _httpClient.SendAsync(
                message,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            RequireSameOriginResponse(request.Url, response);
            if (existingLength > 0
                && response.StatusCode is HttpStatusCode.RequestedRangeNotSatisfiable
                    or HttpStatusCode.PreconditionFailed)
            {
                ResetPartial(partialPath, metadataPath);
                metadata = null;
                existingLength = 0;
                if (attempt == 0)
                {
                    continue;
                }
            }

            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentEncoding.Count != 0)
            {
                throw new InvalidDataException(
                    "Persistent artifact downloads do not accept content encoding.");
            }

            var responseTag = GetStrongEntityTag(response.Headers.ETag);
            var append = response.StatusCode == HttpStatusCode.PartialContent && existingLength > 0;
            if (response.StatusCode == HttpStatusCode.PartialContent)
            {
                if (!append || resumeTag is null || responseTag is null
                    || !string.Equals(
                        resumeTag.ToString(),
                        responseTag,
                        StringComparison.Ordinal))
                {
                    ResetPartial(partialPath, metadataPath);
                    throw new InvalidDataException(
                        "Partial response did not preserve the strong ETag used by If-Range.");
                }
                ValidatePartialResponse(response, existingLength, request.ExpectedSizeBytes);
            }
            else if (response.StatusCode == HttpStatusCode.OK)
            {
                append = false;
                existingLength = 0;
                ValidateFullResponse(response, request.ExpectedSizeBytes);
            }
            else
            {
                throw new HttpRequestException(
                    $"Download endpoint returned unsupported success status {(int)response.StatusCode}.",
                    null,
                    response.StatusCode);
            }

            metadata = new PersistentPartialMetadata
            {
                SchemaVersion = MetadataSchemaVersion,
                Url = request.Url.AbsoluteUri,
                ExpectedSizeBytes = request.ExpectedSizeBytes,
                ExpectedSha256 = request.ExpectedSha256,
                StrongEntityTag = responseTag,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
            };
            await WriteMetadataAtomicallyAsync(metadataPath, metadata, cancellationToken)
                .ConfigureAwait(false);

            var writeOffset = append ? existingLength : 0;
            var transferred = 0L;
            await using (var output = new FileStream(
                partialPath,
                FileMode.OpenOrCreate,
                FileAccess.Write,
                FileShare.Read,
                request.BufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                if (!append)
                {
                    output.SetLength(0);
                }
                else if (output.Length != writeOffset)
                {
                    throw new IOException(
                        "Persistent partial file length changed while the download was starting.");
                }

                output.Position = writeOffset;
                await using var input = await response.Content.ReadAsStreamAsync(cancellationToken)
                    .ConfigureAwait(false);
                var buffer = GC.AllocateUninitializedArray<byte>(request.BufferSize);
                while (true)
                {
                    var read = await ReadWithIdleTimeoutAsync(
                        input,
                        buffer,
                        request.ReadIdleTimeout ?? TimeSpan.FromSeconds(30),
                        cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                        .ConfigureAwait(false);
                    transferred += read;
                    var total = writeOffset + transferred;
                    if (total > request.ExpectedSizeBytes)
                    {
                        output.SetLength(0);
                        File.Delete(metadataPath);
                        throw new InvalidDataException(
                            "Persistent artifact download exceeded the signed size.");
                    }
                    progress?.Report(new DownloadProgress(
                        total,
                        transferred,
                        request.ExpectedSizeBytes));
                }
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            var finalLength = writeOffset + transferred;
            if (finalLength != request.ExpectedSizeBytes)
            {
                throw new EndOfStreamException(
                    $"Persistent artifact download ended at {finalLength} bytes; "
                    + $"expected {request.ExpectedSizeBytes}. The validated partial was retained.");
            }

            var promoted = await TryPromoteCompletedPartialAsync(
                partialPath,
                metadataPath,
                completePath,
                request,
                cancellationToken).ConfigureAwait(false);
            if (!promoted)
            {
                throw new InvalidDataException(
                    "Persistent artifact download failed the signed SHA-256 verification.");
            }

            return new PersistentArtifactDownloadResult(
                append ? PersistentDownloadStatus.Resumed : PersistentDownloadStatus.Downloaded,
                completePath,
                initialLength,
                finalLength,
                responseTag);
        }

        throw new HttpRequestException(
            "Persistent artifact server rejected the local partial and a clean retry failed.");
    }

    private static void RequireSameOriginResponse(
        Uri requestedUri,
        HttpResponseMessage response)
    {
        var effectiveUri = response.RequestMessage?.RequestUri
            ?? throw new InvalidDataException(
                "Persistent artifact response does not identify its effective URI.");
        if (!string.Equals(requestedUri.Scheme, effectiveUri.Scheme, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(requestedUri.IdnHost, effectiveUri.IdnHost, StringComparison.OrdinalIgnoreCase)
            || requestedUri.Port != effectiveUri.Port)
        {
            throw new InvalidDataException(
                "Persistent artifact download crossed the signed HTTPS origin.");
        }
    }

    private static async Task<bool> TryPromoteCompletedPartialAsync(
        string partialPath,
        string metadataPath,
        string completePath,
        PersistentArtifactDownloadRequest request,
        CancellationToken cancellationToken)
    {
        var verification = await Sha256Verifier.VerifyFileAsync(
            partialPath,
            request.ExpectedSha256,
            request.ExpectedSizeBytes,
            cancellationToken).ConfigureAwait(false);
        if (!verification.IsMatch)
        {
            ResetPartial(partialPath, metadataPath);
            return false;
        }
        File.Move(partialPath, completePath, overwrite: true);
        File.Delete(metadataPath);
        return true;
    }

    private static async Task<PersistentPartialMetadata?> TryReadMetadataAsync(
        string path,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return null;
        }
        var file = new FileInfo(path);
        if (file.Length is <= 0 or > MaximumMetadataBytes)
        {
            File.Delete(path);
            return null;
        }
        try
        {
            return JsonSerializer.Deserialize<PersistentPartialMetadata>(
                await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false),
                JsonOptions);
        }
        catch (JsonException)
        {
            File.Delete(path);
            return null;
        }
    }

    private static bool MetadataMatches(
        PersistentPartialMetadata? metadata,
        PersistentArtifactDownloadRequest request) =>
        metadata is not null
        && metadata.SchemaVersion == MetadataSchemaVersion
        && string.Equals(metadata.Url, request.Url.AbsoluteUri, StringComparison.Ordinal)
        && metadata.ExpectedSizeBytes == request.ExpectedSizeBytes
        && string.Equals(metadata.ExpectedSha256, request.ExpectedSha256, StringComparison.Ordinal)
        && metadata.UpdatedAtUtc.Offset == TimeSpan.Zero
        && metadata.UpdatedAtUtc > DateTimeOffset.UnixEpoch
        && (metadata.StrongEntityTag is null
            || ParseStrongEntityTag(metadata.StrongEntityTag) is not null);

    private static async Task WriteMetadataAtomicallyAsync(
        string path,
        PersistentPartialMetadata metadata,
        CancellationToken cancellationToken)
    {
        var temporaryPath = path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(metadata, JsonOptions);
            await using (var output = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static async Task<int> ReadWithIdleTimeoutAsync(
        Stream input,
        Memory<byte> buffer,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeoutCancellation.CancelAfter(timeout);
        try
        {
            return await input.ReadAsync(buffer, timeoutCancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("Persistent artifact download exceeded the read-idle timeout.");
        }
    }

    private static EntityTagHeaderValue? ParseStrongEntityTag(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !EntityTagHeaderValue.TryParse(value, out var tag)
            || tag.IsWeak)
        {
            return null;
        }
        return tag;
    }

    private static string? GetStrongEntityTag(EntityTagHeaderValue? tag) =>
        tag is null || tag.IsWeak ? null : tag.ToString();

    private static void ValidatePartialResponse(
        HttpResponseMessage response,
        long expectedStart,
        long expectedTotal)
    {
        var range = response.Content.Headers.ContentRange;
        if (range?.From != expectedStart
            || range.To is null
            || range.To < expectedStart
            || range.To >= expectedTotal
            || range.Length != expectedTotal)
        {
            throw new InvalidDataException(
                "Partial response Content-Range does not match the signed artifact.");
        }
        var contentLength = response.Content.Headers.ContentLength;
        if (contentLength is not null && contentLength != range.To.Value - expectedStart + 1)
        {
            throw new InvalidDataException("Partial response length does not match Content-Range.");
        }
    }

    private static void ValidateFullResponse(HttpResponseMessage response, long expectedTotal)
    {
        var contentLength = response.Content.Headers.ContentLength;
        if (contentLength is not null && contentLength != expectedTotal)
        {
            throw new InvalidDataException(
                "Full response length does not match the signed artifact size.");
        }
    }

    private static void ResetPartial(string partialPath, string metadataPath)
    {
        if (File.Exists(partialPath))
        {
            File.Delete(partialPath);
        }
        if (File.Exists(metadataPath))
        {
            File.Delete(metadataPath);
        }
    }

    private static void ValidateRequest(PersistentArtifactDownloadRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Url);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.CacheDirectory);
        if (!request.Url.IsAbsoluteUri
            || !string.Equals(request.Url.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(request.Url.UserInfo)
            || !string.IsNullOrEmpty(request.Url.Fragment)
            || !string.IsNullOrEmpty(request.Url.Query))
        {
            throw new ArgumentException(
                "Persistent artifact URL must be absolute HTTPS without user info, query, or fragment.",
                nameof(request));
        }
        if (request.ExpectedSizeBytes <= 0
            || request.ExpectedSizeBytes > 8L * 1024 * 1024 * 1024
            || !PersonalReleaseSetValidator.IsSha256(request.ExpectedSha256))
        {
            throw new ArgumentException(
                "Persistent artifact signed size or SHA-256 is invalid.",
                nameof(request));
        }
        if (request.BufferSize is < 4 * 1024 or > 4 * 1024 * 1024
            || request.ReadIdleTimeout is { } timeout
                && (timeout < TimeSpan.FromSeconds(1) || timeout > TimeSpan.FromMinutes(2)))
        {
            throw new ArgumentException(
                "Persistent artifact download buffer or read-idle timeout is invalid.",
                nameof(request));
        }
    }

    private static void RejectReparsePoint(string path, string field)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"Persistent artifact {field} must not be a filesystem link.");
        }
    }

    private static void RejectExistingReparsePoint(string path)
    {
        if ((File.Exists(path) || Directory.Exists(path))
            && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Persistent artifact cache entries must not be filesystem links.");
        }
    }

    private static async Task<FileStream> AcquireLockAsync(
        string cacheRoot,
        string sha256,
        CancellationToken cancellationToken)
    {
        var lockPath = Path.Combine(cacheRoot, "." + sha256 + ".lock");
        RejectExistingReparsePoint(lockPath);
        var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (true)
        {
            try
            {
                return new FileStream(
                    lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.WriteThrough);
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (IOException exception)
            {
                throw new TimeoutException(
                    "Timed out waiting for the persistent artifact cache writer.",
                    exception);
            }
        }
    }
}
