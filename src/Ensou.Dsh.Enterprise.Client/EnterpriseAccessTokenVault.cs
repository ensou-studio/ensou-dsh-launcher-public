using System.Security.Cryptography;

namespace Ensou.Dsh.Enterprise.Client;

public interface IEnterpriseAccessTokenVault
{
    void Install(
        string bindingId,
        string accessToken,
        DateTimeOffset expiresAtUtc);

    bool HasUsableToken(
        string bindingId,
        DateTimeOffset nowUtc);

    EnterpriseAccessTokenLease Acquire(DateTimeOffset nowUtc);

    void Clear();
}

public sealed class EnterpriseAccessTokenLease : IDisposable
{
    private char[]? _token;

    internal EnterpriseAccessTokenLease(
        string bindingId,
        char[] token,
        DateTimeOffset expiresAtUtc)
    {
        BindingId = bindingId;
        _token = token;
        ExpiresAtUtc = expiresAtUtc;
    }

    public string BindingId { get; }

    public DateTimeOffset ExpiresAtUtc { get; }

    internal string Materialize() => new(
        _token ?? throw new ObjectDisposedException(nameof(EnterpriseAccessTokenLease)));

    public void Dispose()
    {
        if (_token is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(_token.AsSpan()));
        _token = null;
    }

    public override string ToString() => "Enterprise access token lease [REDACTED]";
}

public sealed class EnterpriseAccessTokenVault : IEnterpriseAccessTokenVault, IDisposable
{
    private readonly object _gate = new();
    private char[]? _token;
    private string? _bindingId;
    private DateTimeOffset _expiresAtUtc;
    private bool _disposed;

    public void Install(
        string bindingId,
        string accessToken,
        DateTimeOffset expiresAtUtc)
    {
        EnterpriseBindingValidation.CanonicalizeUuid(bindingId, nameof(bindingId));
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            expiresAtUtc,
            nameof(expiresAtUtc));
        if (accessToken.Length is < 32 or > 4096
            || accessToken.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '.' and not '_' and not '~'))
        {
            throw new InvalidDataException(
                "Enterprise access token is not a bounded bearer token.");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var copy = accessToken.ToCharArray();
            ClearCore();
            _token = copy;
            _bindingId = bindingId;
            _expiresAtUtc = expiresAtUtc;
        }
    }

    public bool HasUsableToken(string bindingId, DateTimeOffset nowUtc)
    {
        if (nowUtc.Offset != TimeSpan.Zero)
        {
            return false;
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _token is { Length: >= 32 }
                && string.Equals(_bindingId, bindingId, StringComparison.Ordinal)
                && nowUtc < _expiresAtUtc;
        }
    }

    public EnterpriseAccessTokenLease Acquire(DateTimeOffset nowUtc)
    {
        if (nowUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Enterprise access-token acquisition requires UTC time.");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_token is not { Length: >= 32 }
                || _bindingId is null
                || nowUtc >= _expiresAtUtc)
            {
                ClearCore();
                throw new EnterpriseAccessTokenUnavailableException();
            }

            return new EnterpriseAccessTokenLease(
                _bindingId,
                (char[])_token.Clone(),
                _expiresAtUtc);
        }
    }

    public void Clear()
    {
        if (_disposed)
        {
            return;
        }

        lock (_gate)
        {
            ClearCore();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            ClearCore();
            _disposed = true;
        }
    }

    private void ClearCore()
    {
        if (_token is not null)
        {
            CryptographicOperations.ZeroMemory(
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(_token.AsSpan()));
            _token = null;
        }

        _bindingId = null;
        _expiresAtUtc = default;
    }
}

public sealed class EnterpriseAccessTokenUnavailableException()
    : InvalidOperationException("No usable enterprise access token is available.");
