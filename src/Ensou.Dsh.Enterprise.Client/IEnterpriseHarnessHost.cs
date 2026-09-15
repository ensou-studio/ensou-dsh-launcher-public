namespace Ensou.Dsh.Enterprise.Client;

public interface IEnterpriseHarnessHost : IAsyncDisposable
{
    Uri WebUiUri { get; }

    Task EnsureStartedAsync(CancellationToken cancellationToken = default);

    Task OpenWebUiAsync(CancellationToken cancellationToken = default);

    Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default);

    Task StopOwnedProcessAsync(CancellationToken cancellationToken = default);
}
