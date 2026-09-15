using System.Diagnostics;
using System.Reflection;
using Ensou.Dsh.Host;

namespace Ensou.Dsh.CoreTests;

internal static partial class Program
{
    private static async Task ManagedUpdateExactExitDefersLeasedChannelAsync()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var process = Process.GetCurrentProcess();
        using var job = WindowsJobObject.CreateKillOnClose();
        using var channel = DshRuntimeUpdateChannel.Create(static _ => true);
        await using var service = new DshHostService(CreateCandidateHealthOptions());
        AttachManagedUpdateChannelForLifetimeTest(service, process, channel);
        SetManagedUpdateChannelLeaseForLifetimeTest(service, process);

        service.HandleOwnedProcessExitedForTest(process, job, static _ => { });
        AssertTrue(HasManagedUpdateChannelForLifetimeTest(service, process));

        SetManagedUpdateChannelLeaseForLifetimeTest(service, null);
        DisposeManagedUpdateChannelForLifetimeTest(service, process, deferWhileManagedStop: false);
        AssertFalse(HasManagedUpdateChannelForLifetimeTest(service, process));
    }

    private static async Task ManagedUpdateNormalExitClosesUnleasedChannelAsync()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var process = Process.GetCurrentProcess();
        using var job = WindowsJobObject.CreateKillOnClose();
        using var channel = DshRuntimeUpdateChannel.Create(static _ => true);
        await using var service = new DshHostService(CreateCandidateHealthOptions());
        AttachManagedUpdateChannelForLifetimeTest(service, process, channel);

        service.HandleOwnedProcessExitedForTest(process, job, static _ => { });
        AssertFalse(HasManagedUpdateChannelForLifetimeTest(service, process));
    }

    private static async Task ManagedUpdateOldExitCannotRetainOrClearNewChannelAsync()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var oldProcess = Process.GetProcessById(Environment.ProcessId);
        using var currentProcess = Process.GetCurrentProcess();
        using var oldJob = WindowsJobObject.CreateKillOnClose();
        using var channel = DshRuntimeUpdateChannel.Create(static _ => true);
        await using var service = new DshHostService(CreateCandidateHealthOptions());
        AttachManagedUpdateChannelForLifetimeTest(service, currentProcess, channel);
        SetManagedUpdateChannelLeaseForLifetimeTest(service, currentProcess);

        service.HandleOwnedProcessExitedForTest(oldProcess, oldJob, static _ => { });
        AssertTrue(HasManagedUpdateChannelForLifetimeTest(service, currentProcess));

        SetManagedUpdateChannelLeaseForLifetimeTest(service, null);
        DisposeManagedUpdateChannelForLifetimeTest(service, oldProcess, deferWhileManagedStop: false);
        AssertTrue(HasManagedUpdateChannelForLifetimeTest(service, currentProcess));
        DisposeManagedUpdateChannelForLifetimeTest(service, currentProcess, deferWhileManagedStop: false);
    }

    private static async Task ManagedUpdateLeaseReleaseRequiresExactProcessAsync()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var exactProcess = Process.GetCurrentProcess();
        using var wrongProcess = Process.GetProcessById(Environment.ProcessId);
        using var channel = DshRuntimeUpdateChannel.Create(static _ => true);
        await using var service = new DshHostService(CreateCandidateHealthOptions());
        AttachManagedUpdateChannelForLifetimeTest(service, exactProcess, channel);
        SetManagedUpdateChannelLeaseForLifetimeTest(service, exactProcess);

        ReleaseManagedUpdateChannelLeaseForLifetimeTest(service, wrongProcess, keepChannel: true);
        AssertTrue(HasManagedUpdateChannelLeaseForLifetimeTest(service, exactProcess));
        AssertTrue(HasManagedUpdateChannelForLifetimeTest(service, exactProcess));

        ReleaseManagedUpdateChannelLeaseForLifetimeTest(service, exactProcess, keepChannel: true);
        AssertFalse(HasManagedUpdateChannelLeaseForLifetimeTest(service, exactProcess));
        AssertTrue(HasManagedUpdateChannelForLifetimeTest(service, exactProcess));
        DisposeManagedUpdateChannelForLifetimeTest(service, exactProcess, deferWhileManagedStop: false);
        AssertFalse(HasManagedUpdateChannelForLifetimeTest(service, exactProcess));
    }

    private static void AttachManagedUpdateChannelForLifetimeTest(
        DshHostService service,
        Process process,
        DshRuntimeUpdateChannel channel)
    {
        var bindingType = typeof(DshHostService).GetNestedType(
            "RuntimeUpdateChannelBinding",
            BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Runtime update binding type is unavailable.");
        var binding = Activator.CreateInstance(bindingType, process, channel)
            ?? throw new InvalidOperationException("Runtime update binding could not be created.");
        RuntimeUpdateChannelField().SetValue(service, binding);
    }

    private static bool HasManagedUpdateChannelForLifetimeTest(
        DshHostService service,
        Process process)
    {
        var binding = RuntimeUpdateChannelField().GetValue(service);
        if (binding is null) return false;
        var boundProcess = binding.GetType().GetProperty("Process")?.GetValue(binding);
        return ReferenceEquals(boundProcess, process);
    }

    private static void SetManagedUpdateChannelLeaseForLifetimeTest(
        DshHostService service,
        Process? process) =>
        typeof(DshHostService).GetField(
            "_managedUpdateChannelLeaseProcess",
            BindingFlags.Instance | BindingFlags.NonPublic)!
        .SetValue(service, process);

    private static bool HasManagedUpdateChannelLeaseForLifetimeTest(
        DshHostService service,
        Process process) =>
        ReferenceEquals(
            typeof(DshHostService).GetField(
                "_managedUpdateChannelLeaseProcess",
                BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(service),
            process);

    private static void ReleaseManagedUpdateChannelLeaseForLifetimeTest(
        DshHostService service,
        Process process,
        bool keepChannel) =>
        typeof(DshHostService).GetMethod(
            "ReleaseManagedUpdateChannelLease",
            BindingFlags.Instance | BindingFlags.NonPublic)!
        .Invoke(service, new object[] { process, keepChannel });

    private static void DisposeManagedUpdateChannelForLifetimeTest(
        DshHostService service,
        Process process,
        bool deferWhileManagedStop) =>
        typeof(DshHostService).GetMethod(
            "DisposeRuntimeUpdateChannel",
            BindingFlags.Instance | BindingFlags.NonPublic)!
        .Invoke(service, new object[] { process, deferWhileManagedStop });

    private static FieldInfo RuntimeUpdateChannelField() =>
        typeof(DshHostService).GetField(
            "_runtimeUpdateChannel",
            BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("Runtime update channel field is unavailable.");
}
