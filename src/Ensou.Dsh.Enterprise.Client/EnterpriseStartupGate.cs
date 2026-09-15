using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterpriseStartupGate(TimeProvider timeProvider)
{
    private readonly TimeProvider _timeProvider = timeProvider
        ?? throw new ArgumentNullException(nameof(timeProvider));

    public EnterpriseAccessDecision Evaluate(EnterpriseAccessSnapshot snapshot) =>
        EnterpriseAccessEvaluator.Evaluate(snapshot, _timeProvider.GetUtcNow());

    internal DateTimeOffset GetUtcNow() => _timeProvider.GetUtcNow();

    internal long GetTimestamp() => _timeProvider.GetTimestamp();

    internal TimeSpan GetElapsedTime(long startingTimestamp) =>
        _timeProvider.GetElapsedTime(startingTimestamp);

    internal ITimer CreateTimer(TimerCallback callback, object? state) =>
        _timeProvider.CreateTimer(
            callback,
            state,
            Timeout.InfiniteTimeSpan,
            Timeout.InfiniteTimeSpan);

    public static EnterpriseAccessSnapshot CreateEnrollmentRequiredSnapshot()
    {
        var placeholderTime = DateTimeOffset.UnixEpoch;
        return new EnterpriseAccessSnapshot
        {
            Employee = EmployeeAuthorizationState.Unknown,
            Device = DeviceBindingState.Unbound,
            ApiAllocation = ApiAllocationState.Unknown,
            ControlPlane = ControlPlaneConnectivity.Unknown,
            LeaseSignatureValid = false,
            AuthorizationEpochMatches = false,
            ClockTrusted = false,
            TrustedTimeFloorUtc = placeholderTime,
            LeaseIssuedAtUtc = placeholderTime,
            LeaseExpiresAtUtc = null,
        };
    }

    public static EnterpriseAccessSnapshot CreateEnrollmentPendingSnapshot()
    {
        var snapshot = CreateEnrollmentRequiredSnapshot();
        return snapshot with { Device = DeviceBindingState.Pending };
    }

    public static EnterpriseAccessSnapshot CreateEnrollmentAccountLockedSnapshot(
        EmployeeAuthorizationState employeeState)
    {
        if (employeeState is not EmployeeAuthorizationState.Suspended
            and not EmployeeAuthorizationState.Revoked)
        {
            throw new ArgumentOutOfRangeException(
                nameof(employeeState),
                employeeState,
                "Enrollment account lock requires a suspended or revoked employee state.");
        }

        return CreateEnrollmentRequiredSnapshot() with { Employee = employeeState };
    }
}
