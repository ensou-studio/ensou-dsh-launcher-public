namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterpriseBindingRecoveryRequiredException : Exception
{
    public EnterpriseBindingRecoveryRequiredException(Exception innerException)
        : base(
            "设备绑定结果需要安全恢复；请保持本机数据不变并重试，无法恢复时联系管理员。",
            innerException)
    {
    }
}
