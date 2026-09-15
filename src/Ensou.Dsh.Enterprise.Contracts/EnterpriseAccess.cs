namespace Ensou.Dsh.Enterprise.Contracts;

public sealed record EnterpriseAccessSnapshot
{
    public required EmployeeAuthorizationState Employee { get; init; }

    public required DeviceBindingState Device { get; init; }

    public required ApiAllocationState ApiAllocation { get; init; }

    public required ControlPlaneConnectivity ControlPlane { get; init; }

    public required bool LeaseSignatureValid { get; init; }

    public required bool AuthorizationEpochMatches { get; init; }

    public required bool ClockTrusted { get; init; }

    public required DateTimeOffset TrustedTimeFloorUtc { get; init; }

    public required DateTimeOffset LeaseIssuedAtUtc { get; init; }

    public DateTimeOffset? LeaseExpiresAtUtc { get; init; }

    public string? PluginPolicyId { get; init; }

    public long? PluginPolicyGeneration { get; init; }

    public string? PluginPolicySha256 { get; init; }

    public string? RuntimeProfile { get; init; }

    public string? ApiProvider { get; init; }

    public bool ClientUpdateRequired { get; init; }

    public bool RuntimeUpdateRequired { get; init; }

    public bool CriticalPluginUpdateRequired { get; init; }
}

public sealed record EnterpriseAccessDecision(
    EnterpriseClientState ClientState,
    bool MayStartHarness,
    bool MayCallManagedApi,
    EnterpriseResetScope ResetScope,
    string? ErrorCode);

public static class EnterpriseAccessEvaluator
{
    public static EnterpriseAccessDecision Evaluate(
        EnterpriseAccessSnapshot snapshot,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        if (!Enum.IsDefined(snapshot.Employee)
            || !Enum.IsDefined(snapshot.Device)
            || !Enum.IsDefined(snapshot.ApiAllocation)
            || !Enum.IsDefined(snapshot.ControlPlane))
        {
            return Deny(
                EnterpriseClientState.SecurityQuarantined,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.ControlPlaneUnavailable);
        }

        if (snapshot.ApiAllocation == ApiAllocationState.Unknown
            && snapshot.Device is not DeviceBindingState.Unbound
                and not DeviceBindingState.Pending)
        {
            return Deny(
                EnterpriseClientState.SecurityQuarantined,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.ControlPlaneUnavailable);
        }

        if (snapshot.Device == DeviceBindingState.QuarantinedCompromise)
        {
            return Deny(
                EnterpriseClientState.SecurityQuarantined,
                EnterpriseResetScope.SecurityCredentials,
                EnterpriseErrorCodes.DeviceSecurityQuarantined);
        }

        if (snapshot.Employee == EmployeeAuthorizationState.Revoked)
        {
            return Deny(
                EnterpriseClientState.AccountLocked,
                snapshot.Device == DeviceBindingState.Unbound
                    ? EnterpriseResetScope.None
                    : EnterpriseResetScope.SecurityCredentials,
                EnterpriseErrorCodes.EmployeeRevoked);
        }

        if (IsRevoked(snapshot.Device))
        {
            return Deny(
                EnterpriseClientState.DeviceRevokedResetRequired,
                EnterpriseResetScope.SecurityCredentials,
                EnterpriseErrorCodes.DeviceBindingRevoked);
        }

        if (snapshot.Employee == EmployeeAuthorizationState.Suspended)
        {
            return Deny(
                EnterpriseClientState.AccountLocked,
                snapshot.Device == DeviceBindingState.Unbound
                    ? EnterpriseResetScope.None
                    : EnterpriseResetScope.ManagedConfig,
                EnterpriseErrorCodes.EmployeeSuspended);
        }

        if (snapshot.Device == DeviceBindingState.Pending)
        {
            return Deny(EnterpriseClientState.Binding, EnterpriseResetScope.None, errorCode: null);
        }

        if (snapshot.Device == DeviceBindingState.Unbound
            && snapshot.Employee is EmployeeAuthorizationState.Unknown
                or EmployeeAuthorizationState.PreRegistered)
        {
            return Deny(EnterpriseClientState.QrRequired, EnterpriseResetScope.None, errorCode: null);
        }

        if (snapshot.Employee != EmployeeAuthorizationState.Active
            || snapshot.Device != DeviceBindingState.Active)
        {
            return Deny(
                EnterpriseClientState.SecurityQuarantined,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.ControlPlaneUnavailable);
        }

        if (!snapshot.LeaseSignatureValid)
        {
            return Deny(
                EnterpriseClientState.SecurityQuarantined,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.LeaseSignatureInvalid);
        }

        if (!snapshot.AuthorizationEpochMatches)
        {
            return Deny(
                EnterpriseClientState.SecurityQuarantined,
                EnterpriseResetScope.SecurityCredentials,
                EnterpriseErrorCodes.AuthorizationEpochMismatch);
        }

        if (!HasTrustedUtcClock(snapshot, nowUtc))
        {
            return Deny(
                EnterpriseClientState.SecurityQuarantined,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.ClockUntrusted);
        }

        var trustedFloorUtc = snapshot.TrustedTimeFloorUtc > snapshot.LeaseIssuedAtUtc
            ? snapshot.TrustedTimeFloorUtc
            : snapshot.LeaseIssuedAtUtc;
        if (nowUtc < trustedFloorUtc)
        {
            return Deny(
                EnterpriseClientState.SecurityQuarantined,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.ClockRollbackDetected);
        }

        if (snapshot.ApiAllocation != ApiAllocationState.Active)
        {
            var code = snapshot.ApiAllocation == ApiAllocationState.Unassigned
                ? EnterpriseErrorCodes.ApiProfileUnassigned
                : EnterpriseErrorCodes.ApiProfileDisabled;
            return Deny(
                EnterpriseClientState.ApiDisabled,
                EnterpriseResetScope.ManagedConfig,
                code);
        }

        // Authorization failures take precedence over an update hold. A pending
        // update must never hide an expired lease or unknown authorization state.
        if (snapshot.LeaseExpiresAtUtc is null
            || snapshot.LeaseExpiresAtUtc <= snapshot.LeaseIssuedAtUtc
            || snapshot.LeaseExpiresAtUtc <= nowUtc)
        {
            return Deny(
                EnterpriseClientState.LeaseExpiredLocked,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.LeaseExpired);
        }

        if (snapshot.ControlPlane is not ControlPlaneConnectivity.Available
            and not ControlPlaneConnectivity.Unavailable)
        {
            return Deny(
                EnterpriseClientState.SecurityQuarantined,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.ControlPlaneUnavailable);
        }

        if (snapshot.ClientUpdateRequired)
        {
            return Deny(
                EnterpriseClientState.UpdateRequired,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.ClientUpdateRequired);
        }

        if (snapshot.RuntimeUpdateRequired)
        {
            return Deny(
                EnterpriseClientState.UpdateRequired,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.RuntimeUpdateRequired);
        }

        if (snapshot.CriticalPluginUpdateRequired)
        {
            return Deny(
                EnterpriseClientState.UpdateRequired,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.CriticalPluginUpdateRequired);
        }

        if (snapshot.PluginPolicyId is not { } pluginPolicyId
            || !Guid.TryParseExact(pluginPolicyId, "D", out var parsedPluginPolicyId)
            || !string.Equals(
                parsedPluginPolicyId.ToString("D"),
                pluginPolicyId,
                StringComparison.Ordinal)
            || snapshot.PluginPolicyGeneration is not { } pluginPolicyGeneration
            || pluginPolicyGeneration <= 0
            || !IsLowercaseSha256(snapshot.PluginPolicySha256))
        {
            return Deny(
                EnterpriseClientState.UpdateRequired,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.CriticalPluginUpdateRequired);
        }

        if (snapshot.ControlPlane == ControlPlaneConnectivity.Unavailable)
        {
            return new EnterpriseAccessDecision(
                EnterpriseClientState.OfflineGrace,
                MayStartHarness: true,
                MayCallManagedApi: false,
                EnterpriseResetScope.None,
                EnterpriseErrorCodes.ControlPlaneUnavailable);
        }

        return new EnterpriseAccessDecision(
            EnterpriseClientState.Ready,
            MayStartHarness: true,
            MayCallManagedApi: true,
            EnterpriseResetScope.None,
            ErrorCode: null);
    }

    private static bool IsLowercaseSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character => char.IsAsciiDigit(character)
            || character is >= 'a' and <= 'f');

    private static bool IsRevoked(DeviceBindingState state) => state is
        DeviceBindingState.RevokedReplaced
        or DeviceBindingState.RevokedAdmin
        or DeviceBindingState.RevokedEmployee;

    private static bool HasTrustedUtcClock(
        EnterpriseAccessSnapshot snapshot,
        DateTimeOffset nowUtc) => snapshot.ClockTrusted
        && nowUtc.Offset == TimeSpan.Zero
        && snapshot.TrustedTimeFloorUtc.Offset == TimeSpan.Zero
        && snapshot.LeaseIssuedAtUtc.Offset == TimeSpan.Zero
        && (snapshot.LeaseExpiresAtUtc is null
            || snapshot.LeaseExpiresAtUtc.Value.Offset == TimeSpan.Zero);

    private static EnterpriseAccessDecision Deny(
        EnterpriseClientState state,
        EnterpriseResetScope resetScope,
        string? errorCode) => new(
            state,
            MayStartHarness: false,
            MayCallManagedApi: false,
            resetScope,
            errorCode);
}
