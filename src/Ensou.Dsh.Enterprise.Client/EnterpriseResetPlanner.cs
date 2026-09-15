using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterpriseResetPlan
{
    internal EnterpriseResetPlan(
        EnterpriseResetScope scope,
        EnterpriseManagedArtifact[] exactFiles,
        bool deleteDeviceProofKey)
    {
        Scope = scope;
        ExactFiles = Array.AsReadOnly(exactFiles);
        DeleteDeviceProofKey = deleteDeviceProofKey;
    }

    public EnterpriseResetScope Scope { get; }

    public IReadOnlyList<EnterpriseManagedArtifact> ExactFiles { get; }

    public bool DeleteDeviceProofKey { get; }
}

public static class EnterpriseResetPlanner
{
    public static EnterpriseResetPlan Create(
        EnterpriseResetScope scope,
        EnterpriseManagedPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        var exactFiles = scope switch
        {
            EnterpriseResetScope.None => Array.Empty<EnterpriseManagedArtifact>(),
            EnterpriseResetScope.ManagedConfig =>
            [
                EnterpriseManagedArtifact.AuthorizationLease,
                EnterpriseManagedArtifact.ApiAllocationCache,
                EnterpriseManagedArtifact.PluginPolicyCache,
            ],
            EnterpriseResetScope.SecurityCredentials =>
            [
                EnterpriseManagedArtifact.AuthorizationLease,
                EnterpriseManagedArtifact.ApiAllocationCache,
                EnterpriseManagedArtifact.PluginPolicyCache,
                EnterpriseManagedArtifact.DeviceBindingReceipt,
                EnterpriseManagedArtifact.RefreshTokenDpapi,
                EnterpriseManagedArtifact.EnrollmentSessionDpapi,
                EnterpriseManagedArtifact.PendingBindingTransactionDpapi,
                EnterpriseManagedArtifact.PendingRefreshTransactionDpapi,
                EnterpriseManagedArtifact.PendingUpdateReceiptTransactionDpapi,
                EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi,
            ],
            _ => throw new ArgumentOutOfRangeException(nameof(scope), scope, "Unknown reset scope."),
        };

        foreach (var artifact in exactFiles)
        {
            _ = paths.Resolve(artifact);
        }

        return new EnterpriseResetPlan(
            scope,
            exactFiles,
            deleteDeviceProofKey: scope == EnterpriseResetScope.SecurityCredentials);
    }
}
