namespace Ensou.Dsh.Enterprise.Contracts;

public enum EmployeeAuthorizationState
{
    Unknown = 0,
    PreRegistered = 1,
    Active = 2,
    Suspended = 3,
    Revoked = 4,
}

public enum DeviceBindingState
{
    Unbound = 0,
    Pending = 1,
    Active = 2,
    RevokedReplaced = 3,
    RevokedAdmin = 4,
    RevokedEmployee = 5,
    QuarantinedCompromise = 6,
}

public enum ApiAllocationState
{
    Unknown = 0,
    Unassigned = 1,
    Active = 2,
    Suspended = 3,
    Revoked = 4,
}

public enum EnterpriseClientState
{
    QrRequired = 0,
    Binding = 1,
    Ready = 2,
    OfflineGrace = 3,
    LeaseExpiredLocked = 4,
    AccountLocked = 5,
    DeviceRevokedResetRequired = 6,
    ApiDisabled = 7,
    UpdateRequired = 8,
    SecurityQuarantined = 9,
}

public enum ControlPlaneConnectivity
{
    Unknown = 0,
    Available = 1,
    Unavailable = 2,
}

public enum EnterpriseResetScope
{
    None = 0,
    ManagedConfig = 1,
    SecurityCredentials = 2,
}

public static class EnterpriseResetScopeContract
{
    public static string ToWireValue(EnterpriseResetScope scope) => scope switch
    {
        EnterpriseResetScope.None => "NONE",
        EnterpriseResetScope.ManagedConfig => "MANAGED_CONFIG",
        EnterpriseResetScope.SecurityCredentials => "SECURITY_CREDENTIALS",
        _ => throw new ArgumentOutOfRangeException(nameof(scope), scope, "Unknown reset scope."),
    };

    public static EnterpriseResetScope ParseWireValue(string value) => value switch
    {
        "NONE" => EnterpriseResetScope.None,
        "MANAGED_CONFIG" => EnterpriseResetScope.ManagedConfig,
        "SECURITY_CREDENTIALS" => EnterpriseResetScope.SecurityCredentials,
        _ => throw new FormatException("Unknown enterprise reset scope."),
    };
}

public enum EnterpriseEnrollmentAuthorizationMethod
{
    WeCom,
    AdminInvite,
}

public static class EnterpriseEnrollmentAuthorizationMethodContract
{
    public static string ToWireValue(EnterpriseEnrollmentAuthorizationMethod method) => method switch
    {
        EnterpriseEnrollmentAuthorizationMethod.WeCom => "WECOM",
        EnterpriseEnrollmentAuthorizationMethod.AdminInvite => "ADMIN_INVITE",
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, "Unknown enrollment authorization method."),
    };

    public static EnterpriseEnrollmentAuthorizationMethod ParseWireValue(string value) => value switch
    {
        "WECOM" => EnterpriseEnrollmentAuthorizationMethod.WeCom,
        "ADMIN_INVITE" => EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
        _ => throw new FormatException("Unknown enrollment authorization method."),
    };
}

public enum QrSessionState
{
    Issued = 0,
    CallbackVerified = 1,
    EligibilityVerified = 2,
    Approved = 3,
    Consumed = 4,
    Expired = 5,
    Cancelled = 6,
    DeniedNotPreregistered = 7,
    DeniedEmployeeSuspended = 8,
    DeniedEmployeeRevoked = 9,
    DeniedAlreadyBound = 10,
    DeniedEnterpriseMemberRequired = 11,
    DeniedEntitlementMissing = 12,
    DeniedUserRejected = 13,
}

public static class QrSessionStateContract
{
    public static string ToWireValue(QrSessionState state) => state switch
    {
        QrSessionState.Issued => "ISSUED",
        QrSessionState.CallbackVerified => "CALLBACK_VERIFIED",
        QrSessionState.EligibilityVerified => "ELIGIBILITY_VERIFIED",
        QrSessionState.Approved => "APPROVED",
        QrSessionState.Consumed => "CONSUMED",
        QrSessionState.Expired => "EXPIRED",
        QrSessionState.Cancelled => "CANCELLED",
        QrSessionState.DeniedNotPreregistered => "DENIED_NOT_PREREGISTERED",
        QrSessionState.DeniedEmployeeSuspended => "DENIED_EMPLOYEE_SUSPENDED",
        QrSessionState.DeniedEmployeeRevoked => "DENIED_EMPLOYEE_REVOKED",
        QrSessionState.DeniedAlreadyBound => "DENIED_ALREADY_BOUND",
        QrSessionState.DeniedEnterpriseMemberRequired => "DENIED_ENTERPRISE_MEMBER_REQUIRED",
        QrSessionState.DeniedEntitlementMissing => "DENIED_ENTITLEMENT_MISSING",
        QrSessionState.DeniedUserRejected => "DENIED_USER_REJECTED",
        _ => throw new ArgumentOutOfRangeException(nameof(state), state, "Unknown QR state."),
    };

    public static QrSessionState ParseWireValue(string value) => value switch
    {
        "ISSUED" => QrSessionState.Issued,
        "CALLBACK_VERIFIED" => QrSessionState.CallbackVerified,
        "ELIGIBILITY_VERIFIED" => QrSessionState.EligibilityVerified,
        "APPROVED" => QrSessionState.Approved,
        "CONSUMED" => QrSessionState.Consumed,
        "EXPIRED" => QrSessionState.Expired,
        "CANCELLED" => QrSessionState.Cancelled,
        "DENIED_NOT_PREREGISTERED" => QrSessionState.DeniedNotPreregistered,
        "DENIED_EMPLOYEE_SUSPENDED" => QrSessionState.DeniedEmployeeSuspended,
        "DENIED_EMPLOYEE_REVOKED" => QrSessionState.DeniedEmployeeRevoked,
        "DENIED_ALREADY_BOUND" => QrSessionState.DeniedAlreadyBound,
        "DENIED_ENTERPRISE_MEMBER_REQUIRED" => QrSessionState.DeniedEnterpriseMemberRequired,
        "DENIED_ENTITLEMENT_MISSING" => QrSessionState.DeniedEntitlementMissing,
        "DENIED_USER_REJECTED" => QrSessionState.DeniedUserRejected,
        _ => throw new FormatException("Unknown QR session state."),
    };
}

public static class EnterpriseClientStateContract
{
    public static string ToWireValue(EnterpriseClientState state) => state switch
    {
        EnterpriseClientState.QrRequired => "QR_REQUIRED",
        EnterpriseClientState.Binding => "BINDING",
        EnterpriseClientState.Ready => "READY",
        EnterpriseClientState.OfflineGrace => "OFFLINE_GRACE",
        EnterpriseClientState.LeaseExpiredLocked => "LEASE_EXPIRED_LOCKED",
        EnterpriseClientState.AccountLocked => "ACCOUNT_LOCKED",
        EnterpriseClientState.DeviceRevokedResetRequired => "DEVICE_REVOKED_RESET_REQUIRED",
        EnterpriseClientState.ApiDisabled => "API_DISABLED",
        EnterpriseClientState.UpdateRequired => "UPDATE_REQUIRED",
        EnterpriseClientState.SecurityQuarantined => "SECURITY_QUARANTINED",
        _ => throw new ArgumentOutOfRangeException(nameof(state), state, "Unknown client state."),
    };

    public static EnterpriseClientState ParseWireValue(string value) => value switch
    {
        "QR_REQUIRED" => EnterpriseClientState.QrRequired,
        "BINDING" => EnterpriseClientState.Binding,
        "READY" => EnterpriseClientState.Ready,
        "OFFLINE_GRACE" => EnterpriseClientState.OfflineGrace,
        "LEASE_EXPIRED_LOCKED" => EnterpriseClientState.LeaseExpiredLocked,
        "ACCOUNT_LOCKED" => EnterpriseClientState.AccountLocked,
        "DEVICE_REVOKED_RESET_REQUIRED" => EnterpriseClientState.DeviceRevokedResetRequired,
        "API_DISABLED" => EnterpriseClientState.ApiDisabled,
        "UPDATE_REQUIRED" => EnterpriseClientState.UpdateRequired,
        "SECURITY_QUARANTINED" => EnterpriseClientState.SecurityQuarantined,
        _ => throw new FormatException("Unknown enterprise client state."),
    };
}
