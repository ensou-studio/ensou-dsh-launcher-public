using System.Security.Cryptography;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public interface IEnterpriseResetExecutor
{
    EnterpriseResetBarrier? ReadBarrier();

    void PersistBarrier(EnterpriseResetBarrier barrier);

    void ClearBarrier();

    void Execute(EnterpriseResetScope scope);
}

public sealed class EnterpriseResetExecutor : IEnterpriseResetExecutor
{
    private readonly EnterpriseManagedPaths _paths;
    private readonly IEnterpriseDeviceProofKeyStore _deviceKeyStore;
    private readonly EnterpriseResetBarrierStore _barrierStore;

    public EnterpriseResetExecutor(
        EnterpriseManagedPaths paths,
        IEnterpriseDeviceProofKeyStore deviceKeyStore,
        EnterpriseProtectedArtifactStore? protectedStore = null)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _deviceKeyStore = deviceKeyStore ?? throw new ArgumentNullException(nameof(deviceKeyStore));
        _barrierStore = new EnterpriseResetBarrierStore(
            protectedStore ?? new EnterpriseProtectedArtifactStore(paths));
    }

    public EnterpriseResetBarrier? ReadBarrier() => _barrierStore.Read();

    public void PersistBarrier(EnterpriseResetBarrier barrier) => _barrierStore.Write(barrier);

    public void ClearBarrier() => _barrierStore.Delete();

    public void Execute(EnterpriseResetScope scope)
    {
        var plan = EnterpriseResetPlanner.Create(scope, _paths);
        List<Exception>? failures = null;
        foreach (var artifact in plan.ExactFiles)
        {
            try
            {
                EnterpriseLocalStateSecurity.DeleteExactFile(
                    _paths.Resolve(artifact),
                    _paths.ManagedRoot);
            }
            catch (Exception exception)
            {
                (failures ??= []).Add(new IOException(
                    $"Enterprise reset could not remove {artifact}.",
                    exception));
            }
        }

        // Keep the device proof key until every exact file has been removed. If one
        // file is temporarily locked, the locked authorization session can retry the
        // same idempotent allowlist without losing the key for the remaining binding.
        if (failures is null && plan.DeleteDeviceProofKey)
        {
            try
            {
                _deviceKeyStore.DeleteForSecurityReset();
            }
            catch (Exception exception)
            {
                (failures ??= []).Add(new CryptographicException(
                    "Enterprise reset could not remove the device proof key.",
                    exception));
            }
        }

        if (failures is not null)
        {
            throw new AggregateException(
                "Enterprise reset was incomplete and must be retried while the client remains locked.",
                failures);
        }
    }
}
