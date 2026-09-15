using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterpriseControlPlaneException(EnterpriseApiError error)
    : Exception($"Enterprise control plane denied the request: {error.Code} ({error.RequestId}).")
{
    public EnterpriseApiError Error { get; } = error;
}
