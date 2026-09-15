using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterpriseAccessDeniedException(EnterpriseAccessDecision decision)
    : InvalidOperationException(CreateMessage(decision))
{
    public EnterpriseAccessDecision Decision { get; } = decision;

    private static string CreateMessage(EnterpriseAccessDecision decision) =>
        $"Enterprise Harness access is blocked in state {decision.ClientState}" +
        (string.IsNullOrWhiteSpace(decision.ErrorCode)
            ? "."
            : $" ({decision.ErrorCode}).");
}
