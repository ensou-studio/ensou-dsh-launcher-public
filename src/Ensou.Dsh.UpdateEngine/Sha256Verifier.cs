using System.Security.Cryptography;

namespace Ensou.Dsh.UpdateEngine;

public sealed record Sha256VerificationResult(
    bool IsMatch,
    string ExpectedSha256,
    string ActualSha256,
    long ActualSizeBytes);

public static class Sha256Verifier
{
    public static async Task<Sha256VerificationResult> VerifyFileAsync(
        string filePath,
        string expectedSha256,
        long? expectedSizeBytes = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        var expectedBytes = ParseExpectedHash(expectedSha256);
        if (expectedSizeBytes is <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedSizeBytes),
                "Expected size must be positive when supplied.");
        }

        await using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        var actualSize = stream.Length;
        var actualBytes = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        var sizeMatches = expectedSizeBytes is null || actualSize == expectedSizeBytes.Value;
        var hashMatches = CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);

        return new Sha256VerificationResult(
            sizeMatches && hashMatches,
            Convert.ToHexStringLower(expectedBytes),
            Convert.ToHexStringLower(actualBytes),
            actualSize);
    }

    public static async Task<string> ComputeFileHashAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        await using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexStringLower(
            await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
    }

    private static byte[] ParseExpectedHash(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length != 64)
        {
            throw new ArgumentException("SHA-256 must contain exactly 64 hexadecimal characters.", nameof(value));
        }

        try
        {
            var bytes = Convert.FromHexString(value);
            if (bytes.Length != 32)
            {
                throw new ArgumentException("SHA-256 must decode to exactly 32 bytes.", nameof(value));
            }

            return bytes;
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("SHA-256 contains non-hexadecimal characters.", nameof(value), exception);
        }
    }
}
