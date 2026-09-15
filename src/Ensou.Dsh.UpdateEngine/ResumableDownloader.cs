using System.Net;
using System.Net.Http.Headers;

namespace Ensou.Dsh.UpdateEngine;

public enum ResumableDownloadStatus
{
    AlreadyComplete,
    Downloaded,
    Resumed,
}

public sealed record ResumableDownloadRequest(
    Uri Url,
    string PartialFilePath,
    long ExpectedSizeBytes,
    int BufferSize = 128 * 1024);

public sealed record DownloadProgress(
    long BytesPresent,
    long BytesTransferredThisAttempt,
    long TotalBytes)
{
    public double Fraction => TotalBytes == 0 ? 0 : (double)BytesPresent / TotalBytes;
}

public sealed record ResumableDownloadResult(
    ResumableDownloadStatus Status,
    string PartialFilePath,
    long InitialBytes,
    long FinalBytes,
    HttpStatusCode? StatusCode);

public sealed class ResumableDownloader
{
    private readonly HttpClient _httpClient;

    public ResumableDownloader(HttpClient httpClient)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    }

    /// <summary>
    /// Downloads into a caller-owned partial file. Cancellation and short responses retain valid
    /// received bytes so a later call can resume. Hash verification and final-file promotion are
    /// intentionally separate operations.
    /// </summary>
    public async Task<ResumableDownloadResult> DownloadAsync(
        ResumableDownloadRequest request,
        IProgress<DownloadProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateRequest(request);
        var partialPath = Path.GetFullPath(request.PartialFilePath);
        var directory = Path.GetDirectoryName(partialPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var existingLength = File.Exists(partialPath) ? new FileInfo(partialPath).Length : 0;
        if (existingLength > request.ExpectedSizeBytes)
        {
            ResetPartialFile(partialPath);
            existingLength = 0;
        }

        var initialLength = existingLength;
        if (existingLength == request.ExpectedSizeBytes)
        {
            return new ResumableDownloadResult(
                ResumableDownloadStatus.AlreadyComplete,
                partialPath,
                initialLength,
                existingLength,
                null);
        }

        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var message = new HttpRequestMessage(HttpMethod.Get, request.Url);
            message.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue("identity"));
            if (existingLength > 0)
            {
                message.Headers.Range = new RangeHeaderValue(existingLength, null);
            }

            using var response = await _httpClient.SendAsync(
                    message,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.RequestedRangeNotSatisfiable && existingLength > 0)
            {
                var serverLength = response.Content.Headers.ContentRange?.Length;
                if (existingLength == request.ExpectedSizeBytes &&
                    (serverLength is null || serverLength == request.ExpectedSizeBytes))
                {
                    return new ResumableDownloadResult(
                        ResumableDownloadStatus.AlreadyComplete,
                        partialPath,
                        initialLength,
                        existingLength,
                        response.StatusCode);
                }

                ResetPartialFile(partialPath);
                existingLength = 0;
                if (attempt == 0)
                {
                    continue;
                }
            }

            response.EnsureSuccessStatusCode();
            var append = response.StatusCode == HttpStatusCode.PartialContent && existingLength > 0;
            if (response.StatusCode == HttpStatusCode.PartialContent)
            {
                ValidatePartialResponse(response, existingLength, request.ExpectedSizeBytes);
            }
            else if (response.StatusCode == HttpStatusCode.OK)
            {
                if (existingLength > 0)
                {
                    existingLength = 0;
                }

                ValidateFullResponse(response, request.ExpectedSizeBytes);
            }
            else
            {
                throw new HttpRequestException(
                    $"Download endpoint returned unsupported success status {(int)response.StatusCode}.",
                    null,
                    response.StatusCode);
            }

            var transferred = 0L;
            var writeOffset = append ? existingLength : 0;
            await using var output = new FileStream(
                partialPath,
                FileMode.OpenOrCreate,
                FileAccess.Write,
                FileShare.Read,
                request.BufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            if (!append)
            {
                output.SetLength(0);
            }
            else if (output.Length != writeOffset)
            {
                throw new IOException("Partial file length changed while the download was starting.");
            }

            output.Position = writeOffset;
            await using var input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var buffer = GC.AllocateUninitializedArray<byte>(request.BufferSize);
            while (true)
            {
                var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                transferred += read;
                var total = writeOffset + transferred;
                if (total > request.ExpectedSizeBytes)
                {
                    output.SetLength(0);
                    throw new InvalidDataException("Download exceeded the signed artifact size.");
                }

                progress?.Report(new DownloadProgress(total, transferred, request.ExpectedSizeBytes));
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            var finalLength = writeOffset + transferred;
            if (finalLength != request.ExpectedSizeBytes)
            {
                throw new EndOfStreamException(
                    $"Download ended at {finalLength} bytes; expected {request.ExpectedSizeBytes}. " +
                    "The partial file was retained for a later resume.");
            }

            return new ResumableDownloadResult(
                append ? ResumableDownloadStatus.Resumed : ResumableDownloadStatus.Downloaded,
                partialPath,
                initialLength,
                finalLength,
                response.StatusCode);
        }

        throw new HttpRequestException("Server rejected the local partial file and a clean retry failed.");
    }

    private static void ValidateRequest(ResumableDownloadRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Url);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.PartialFilePath);
        if (!request.Url.IsAbsoluteUri ||
            (request.Url.Scheme != Uri.UriSchemeHttps && request.Url.Scheme != Uri.UriSchemeHttp))
        {
            throw new ArgumentException("Download URL must be absolute HTTP or HTTPS.", nameof(request));
        }

        if (request.ExpectedSizeBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Expected size must be positive.");
        }

        if (request.BufferSize is < 4096 or > 4 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Buffer size must be between 4 KiB and 4 MiB.");
        }
    }

    private static void ValidatePartialResponse(
        HttpResponseMessage response,
        long expectedStart,
        long expectedTotal)
    {
        var range = response.Content.Headers.ContentRange;
        if (range?.From != expectedStart ||
            range.To is null ||
            range.To < expectedStart ||
            range.To >= expectedTotal ||
            range.Length != expectedTotal)
        {
            throw new InvalidDataException("Server returned a Content-Range that does not match the signed artifact.");
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
            throw new InvalidDataException("Full response length does not match the signed artifact size.");
        }
    }

    private static void ResetPartialFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
        stream.SetLength(0);
    }
}
