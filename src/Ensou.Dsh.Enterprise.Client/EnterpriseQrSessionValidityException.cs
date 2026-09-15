namespace Ensou.Dsh.Enterprise.Client;

public enum EnterpriseQrSessionValidityReason
{
    Expired,
    ExceedsLocalMaximum,
}

/// <summary>
/// Local diagnostic evidence only, not a server error or proof of clock skew.
/// Kept inside InvalidDataException to preserve the response-rejection contract.
/// </summary>
public sealed class EnterpriseQrSessionValidityException : Exception
{
    internal EnterpriseQrSessionValidityException(EnterpriseQrSessionValidityReason reason)
        : base(reason switch
        {
            EnterpriseQrSessionValidityReason.Expired =>
                "Enterprise QR session has expired according to the local clock.",
            EnterpriseQrSessionValidityReason.ExceedsLocalMaximum =>
                "Enterprise QR session validity exceeds the local maximum.",
            _ => throw new ArgumentOutOfRangeException(nameof(reason)),
        })
    {
        Reason = reason;
    }

    public EnterpriseQrSessionValidityReason Reason { get; }

    public string UserTitle => "无法安全确认企业登录有效期";

    public string UserMessage => Reason == EnterpriseQrSessionValidityReason.Expired
        ? "按本机时间，本次登录已过期，请重新扫码。若反复出现，可能是电脑或服务器时间不同步，也可能是登录响应异常；请联系管理员。"
        : "服务返回的登录有效期超出本机允许范围，已停止登录。可能是电脑或服务器时间不同步，也可能是登录响应异常；请联系管理员检查，确认后重新扫码。";
}
