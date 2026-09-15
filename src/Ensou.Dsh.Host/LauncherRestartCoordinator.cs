using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Ensou.Dsh.Contracts;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Host;

internal sealed record LauncherRestartAttempt(
    LauncherRestartHandoffLease? Handoff,
    string? Failure,
    LauncherRestartParentOwnership ParentOwnership)
{
    internal bool ReadyForParentExit => Handoff is not null;

    internal bool ParentOwnershipProven =>
        ParentOwnership is LauncherRestartParentOwnership.Retained
            or LauncherRestartParentOwnership.Recovered;
}

internal enum LauncherRestartParentOwnership
{
    Retained,
    Recovered,
    Transferred,
    Unproven,
}

internal sealed record LauncherRestartOwnershipResult(
    LauncherRestartParentOwnership ParentOwnership,
    string? Failure)
{
    internal bool ParentOwnershipProven =>
        ParentOwnership is LauncherRestartParentOwnership.Retained
            or LauncherRestartParentOwnership.Recovered;
}

internal sealed record LauncherRestartIncomingHandoff(
    Mutex Singleton,
    LauncherRestartReceiverLease Receiver);

internal enum LauncherRestartReceiverOutcome
{
    ParentExited,
    AbortRequested,
}

internal enum LauncherRestartRollbackOutcome
{
    ParentExited,
    RollbackOwned,
}

internal sealed class LauncherRestartReceiverProcessRetainedException
    : InvalidOperationException
{
    internal LauncherRestartReceiverProcessRetainedException(
        Process retainedProcess,
        Exception innerException)
        : base(
            "Launcher restart receiver was rejected but its exact process handle remains retained for containment.",
            innerException)
    {
        RetainedProcess = retainedProcess
            ?? throw new ArgumentNullException(nameof(retainedProcess));
    }

    internal Process RetainedProcess { get; }
}

internal sealed class LauncherRestartHandoffLease : IDisposable
{
    private readonly EventWaitHandle _cancellationEvent;
    private readonly EventWaitHandle _releasedEvent;
    private readonly EventWaitHandle _rollbackOwnedEvent;
    private readonly Process _receiverProcess;
    private readonly LauncherProcessWaitHandle _receiverExit;
    private readonly Func<TimeSpan, bool> _tryReacquireSingleton;
    private readonly TimeSpan _cancellationGrace;
    private readonly Action<Process> _terminateReceiver;
    private readonly Func<Process, TimeSpan, bool> _waitForReceiverExit;
    private bool _completed;
    private bool _disposed;

    internal LauncherRestartHandoffLease(
        EventWaitHandle cancellationEvent,
        EventWaitHandle releasedEvent,
        EventWaitHandle rollbackOwnedEvent,
        Process receiverProcess,
        LauncherProcessWaitHandle receiverExit,
        Func<TimeSpan, bool> tryReacquireSingleton,
        TimeSpan cancellationGrace,
        Action<Process> terminateReceiver,
        Func<Process, TimeSpan, bool> waitForReceiverExit)
    {
        _cancellationEvent = cancellationEvent;
        _releasedEvent = releasedEvent;
        _rollbackOwnedEvent = rollbackOwnedEvent;
        _receiverProcess = receiverProcess;
        _receiverExit = receiverExit;
        _tryReacquireSingleton = tryReacquireSingleton;
        _cancellationGrace = cancellationGrace;
        _terminateReceiver = terminateReceiver;
        _waitForReceiverExit = waitForReceiverExit;
    }

    internal void Commit()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _completed = true;
    }

    internal LauncherRestartOwnershipResult CancelAndReacquire()
    {
        if (_completed)
        {
            return new LauncherRestartOwnershipResult(
                LauncherRestartParentOwnership.Transferred,
                null);
        }

        var result = LauncherRestartCoordinator.CancelAndRecoverParentOwnership(
            _cancellationEvent,
            _releasedEvent,
            _rollbackOwnedEvent,
            _receiverProcess,
            _receiverExit,
            _tryReacquireSingleton,
            _cancellationGrace,
            _terminateReceiver,
            _waitForReceiverExit);
        _completed = true;
        return result;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (!_completed)
        {
            _ = CancelAndReacquire();
        }

        _receiverExit.Dispose();
        _receiverProcess.Dispose();
        _rollbackOwnedEvent.Dispose();
        _releasedEvent.Dispose();
        _cancellationEvent.Dispose();
        _disposed = true;
    }
}

internal sealed class LauncherRestartReceiverLease : IDisposable
{
    private readonly PersonalLauncherRestartHandoffCommand _command;
    private readonly Process _parentProcess;
    private readonly LauncherProcessWaitHandle _parentExit;
    private readonly EventWaitHandle _ready;
    private readonly EventWaitHandle _commit;
    private readonly EventWaitHandle _commitAcknowledged;
    private readonly EventWaitHandle _cancellation;
    private readonly EventWaitHandle _failure;
    private readonly EventWaitHandle _released;
    private readonly EventWaitHandle _rollbackOwned;
    private readonly NamedPipeClientStream _controlPipe;
    private bool _readySignalled;
    private bool _waitStarted;
    private bool _disposed;

    internal int ParentProcessId => _command.ParentProcessId;

    internal LauncherRestartReceiverLease(
        PersonalLauncherRestartHandoffCommand command,
        Process parentProcess,
        EventWaitHandle ready,
        EventWaitHandle commit,
        EventWaitHandle commitAcknowledged,
        EventWaitHandle cancellation,
        EventWaitHandle failure,
        EventWaitHandle released,
        EventWaitHandle rollbackOwned,
        NamedPipeClientStream controlPipe)
    {
        _command = command;
        _parentProcess = parentProcess;
        _parentExit = new LauncherProcessWaitHandle(parentProcess);
        _ready = ready;
        _commit = commit;
        _commitAcknowledged = commitAcknowledged;
        _cancellation = cancellation;
        _failure = failure;
        _released = released;
        _rollbackOwned = rollbackOwned;
        _controlPipe = controlPipe;
    }

    internal void MarkReady()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_readySignalled)
        {
            throw new InvalidOperationException(
                "Launcher restart receiver readiness was already signalled.");
        }

        _ready.Set();
        _readySignalled = true;
    }

    internal async Task<LauncherRestartReceiverOutcome> WaitForParentExitAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_readySignalled)
        {
            throw new InvalidOperationException(
                "Launcher restart receiver cannot wait before local readiness.");
        }
        if (_waitStarted)
        {
            throw new InvalidOperationException(
                "Launcher restart receiver wait was already started.");
        }
        _waitStarted = true;

        var decision = await Task.Run(() => WaitHandle.WaitAny(
            [_parentExit, _cancellation, _commit]));
        if (decision == 0)
        {
            return LauncherRestartReceiverOutcome.ParentExited;
        }
        if (decision == 1)
        {
            return LauncherRestartReceiverOutcome.AbortRequested;
        }
        if (decision != 2)
        {
            throw new InvalidOperationException(
                "Launcher restart receiver returned an invalid decision.");
        }

        _commitAcknowledged.Set();
        var committedDecision = await Task.Run(() => WaitHandle.WaitAny(
            [_parentExit, _cancellation]));
        return committedDecision switch
        {
            0 => LauncherRestartReceiverOutcome.ParentExited,
            1 => LauncherRestartReceiverOutcome.AbortRequested,
            _ => throw new InvalidOperationException(
                "Launcher restart receiver returned an invalid committed decision."),
        };
    }

    internal void SignalReleased()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _released.Set();
    }

    internal async Task<LauncherRestartRollbackOutcome>
        WaitForRollbackOwnedOrParentExitAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var decision = await Task.Run(() => WaitHandle.WaitAny(
            [_parentExit, _rollbackOwned]));
        return decision switch
        {
            0 => LauncherRestartRollbackOutcome.ParentExited,
            1 => LauncherRestartRollbackOutcome.RollbackOwned,
            _ => throw new InvalidOperationException(
                "Launcher restart rollback returned an invalid decision."),
        };
    }

    internal void TrySignalFailure()
    {
        try
        {
            _failure.Set();
        }
        catch
        {
            _command.TrySignalFailure();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _controlPipe.Dispose();
        _rollbackOwned.Dispose();
        _released.Dispose();
        _failure.Dispose();
        _cancellation.Dispose();
        _commitAcknowledged.Dispose();
        _commit.Dispose();
        _ready.Dispose();
        _parentExit.Dispose();
        _parentProcess.Dispose();
        _disposed = true;
    }
}

internal static class LauncherRestartCoordinator
{
    internal const int MaximumFailureLength = 512;
    private static readonly TimeSpan MonitorPollInterval =
        TimeSpan.FromMilliseconds(25);

    internal static TimeSpan DefaultHandoffTimeout { get; } =
        TimeSpan.FromMinutes(3);

    // A Personal installed restart first traverses the stable bootstrapper's
    // bounded health envelope, then this receiver handoff. Keep the allowance
    // explicit and bounded rather than allowing callers to make the initial
    // receiver connection unbounded.
    internal static TimeSpan MaximumReceiverConnectionTimeout { get; } =
        TimeSpan.FromSeconds(945);

    internal static TimeSpan DefaultCancellationGrace { get; } =
        TimeSpan.FromSeconds(5);

    [SupportedOSPlatform("windows")]
    internal static async Task<LauncherRestartAttempt> TryStartAsync(
        Func<string> resolveExecutablePath,
        Func<Task> prepareForRestartAsync,
        Func<ProcessStartInfo, Process?> startProcess,
        Action releaseSingleton,
        Func<TimeSpan, bool> tryReacquireSingleton,
        int parentProcessId,
        TimeSpan? handoffTimeout = null,
        TimeSpan? receiverConnectionTimeout = null,
        Action<Process>? validateReceiverProcess = null,
        Action? abortReleasedForTest = null,
        TimeSpan? cancellationGrace = null,
        Action<Process>? terminateReceiver = null,
        Func<Process, TimeSpan, bool>? waitForReceiverExit = null,
        bool backgroundStartup = false,
        LauncherRestartHandoffScope handoffScope = LauncherRestartHandoffScope.Personal)
    {
        EventWaitHandle? cancellation = null;
        EventWaitHandle? released = null;
        EventWaitHandle? rollbackOwned = null;
        Process? starterProcess = null;
        Process? receiverProcess = null;
        LauncherProcessWaitHandle? receiverExit = null;
        var childStarted = false;
        var singletonReleased = false;
        try
        {
            ArgumentNullException.ThrowIfNull(resolveExecutablePath);
            ArgumentNullException.ThrowIfNull(prepareForRestartAsync);
            ArgumentNullException.ThrowIfNull(startProcess);
            ArgumentNullException.ThrowIfNull(releaseSingleton);
            ArgumentNullException.ThrowIfNull(tryReacquireSingleton);

            var timeout = ValidateTimeout(handoffTimeout);
            var connectionTimeout = ValidateReceiverConnectionTimeout(
                receiverConnectionTimeout,
                timeout);
            var abortGrace = ValidateCancellationGrace(cancellationGrace);
            terminateReceiver ??= TerminateReceiver;
            waitForReceiverExit ??= WaitForReceiverExit;
            var executablePath = resolveExecutablePath();
            if (string.IsNullOrWhiteSpace(executablePath))
            {
                throw new InvalidOperationException(
                    "无法确定 Launcher 可执行文件路径。");
            }

            var command = PersonalLauncherRestartHandoffCommand.Create(
                parentProcessId,
                backgroundStartup,
                handoffScope);
            using var armed = CreateNewEvent(command.ArmedEventName);
            using var owned = CreateNewEvent(command.OwnedEventName);
            using var ready = CreateNewEvent(command.ReadyEventName);
            using var commit = CreateNewEvent(command.CommitEventName);
            using var commitAcknowledged = CreateNewEvent(
                command.CommitAcknowledgedEventName);
            cancellation = CreateNewEvent(command.CancellationEventName);
            released = CreateNewEvent(command.ReleasedEventName);
            rollbackOwned = CreateNewEvent(command.RollbackOwnedEventName);
            using var failure = CreateNewEvent(command.FailureEventName);
            using var controlPipe = CreateControlPipe(command.PipeName);

            var startInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                WorkingDirectory = Path.GetDirectoryName(executablePath)
                    ?? AppContext.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = backgroundStartup
                    ? ProcessWindowStyle.Hidden
                    : ProcessWindowStyle.Normal,
            };
            foreach (var argument in command.ToArguments())
            {
                startInfo.ArgumentList.Add(argument);
            }

            var launchStartedUtc = DateTime.UtcNow;
            var parentSessionId = Process.GetCurrentProcess().SessionId;
            starterProcess = startProcess(startInfo)
                ?? throw new InvalidOperationException(
                    "Launcher 重启进程未能启动。");
            childStarted = true;

            await WaitForReceiverConnectionAsync(
                controlPipe,
                failure,
                starterProcess,
                connectionTimeout);
            receiverProcess = OpenReceiverProcess(
                controlPipe,
                parentProcessId,
                parentSessionId,
                launchStartedUtc);
            // Retain the OS-bound receiver handle before image admission. A
            // rejected image may already have been terminated by the validator;
            // cleanup must not lose that exact handle and infer ownership from
            // the starter PID instead.
            validateReceiverProcess?.Invoke(receiverProcess);
            if (receiverProcess.HasExited)
            {
                throw new InvalidOperationException(
                    "Launcher restart handoff receiver exited during identity validation.");
            }
            receiverExit = new LauncherProcessWaitHandle(
                receiverProcess);

            await RequireStageAsync(
                failure,
                armed,
                receiverExit,
                receiverProcess,
                timeout,
                "替代 Launcher 拒绝了重启交接。",
                "替代 Launcher 未在期限内准备重启交接。");

            releaseSingleton();
            singletonReleased = true;

            await RequireStageAsync(
                failure,
                owned,
                receiverExit,
                receiverProcess,
                timeout,
                "替代 Launcher 未能取得单实例所有权。",
                "替代 Launcher 取得单实例所有权超时。");

            await RequireStageAsync(
                failure,
                ready,
                receiverExit,
                receiverProcess,
                timeout,
                "替代 Launcher 本地初始化失败。",
                "替代 Launcher 本地初始化超时。");
            await PrepareWhileMonitoringAsync(
                prepareForRestartAsync,
                failure,
                receiverProcess);

            ThrowIfReceiverUnavailable(failure, receiverProcess);
            commit.Set();
            await RequireStageAsync(
                failure,
                commitAcknowledged,
                receiverExit,
                receiverProcess,
                timeout,
                "替代 Launcher 未能确认安全退出决策。",
                "替代 Launcher 确认安全退出决策超时。");

            var lease = new LauncherRestartHandoffLease(
                cancellation,
                released,
                rollbackOwned,
                receiverProcess,
                receiverExit,
                tryReacquireSingleton,
                abortGrace,
                terminateReceiver,
                waitForReceiverExit);
            cancellation = null;
            released = null;
            rollbackOwned = null;
            receiverProcess = null;
            receiverExit = null;
            return new LauncherRestartAttempt(
                lease,
                null,
                LauncherRestartParentOwnership.Transferred);
        }
        catch (Exception exception)
        {
            var parentOwnership = singletonReleased
                ? LauncherRestartParentOwnership.Unproven
                : LauncherRestartParentOwnership.Retained;
            string? ownershipFailure = null;
            if (childStarted && cancellation is not null)
            {
                TrySet(cancellation);
            }

            if (!singletonReleased
                && childStarted)
            {
                if (receiverProcess is null
                    && exception is LauncherRestartReceiverProcessRetainedException retained)
                {
                    // The validation boundary explicitly retained this exact
                    // pipe-bound process handle so cleanup can target it even
                    // though OpenReceiverProcess did not return normally.
                    receiverProcess = retained.RetainedProcess;
                }
                var processToTerminate = receiverProcess ?? starterProcess;
                if (receiverProcess is null && starterProcess is not null)
                {
                    try
                    {
                        if (starterProcess.HasExited)
                        {
                            // Before the pipe binds a trusted receiver, an exited
                            // starter cannot prove that it left no descendants.
                            // Do not target a recycled or unrelated PID and do not
                            // admit another retry from this uncertain state.
                            processToTerminate = null;
                            parentOwnership = LauncherRestartParentOwnership.Unproven;
                            ownershipFailure =
                                "重启转发进程已退出，无法确认其子进程树已清理。";
                        }
                    }
                    catch (Exception cleanupInspectionFailure)
                    {
                        processToTerminate = null;
                        parentOwnership = LauncherRestartParentOwnership.Unproven;
                        ownershipFailure = NormalizeFailure(
                            cleanupInspectionFailure);
                    }
                }
                if (processToTerminate is not null)
                {
                    ownershipFailure = TerminateAndConfirmPreHandoffProcess(
                        processToTerminate,
                        ValidateCancellationGrace(cancellationGrace),
                        terminateReceiver ?? TerminateReceiver,
                        waitForReceiverExit ?? WaitForReceiverExit);
                    if (!string.IsNullOrWhiteSpace(ownershipFailure))
                    {
                        // A stale starter or forwarder can outlive this parent
                        // even while the parent still owns the singleton. Do
                        // not let that uncertain tree be followed by a retry.
                        parentOwnership = LauncherRestartParentOwnership.Unproven;
                    }
                }
            }
            else if (singletonReleased
                && cancellation is not null
                && released is not null
                && rollbackOwned is not null
                && receiverProcess is not null
                && receiverExit is not null)
            {
                var ownership = CancelAndRecoverParentOwnership(
                    cancellation,
                    released,
                    rollbackOwned,
                    receiverProcess,
                    receiverExit,
                    tryReacquireSingleton,
                    ValidateCancellationGrace(cancellationGrace),
                    terminateReceiver ?? TerminateReceiver,
                    waitForReceiverExit ?? WaitForReceiverExit,
                    abortReleasedForTest);
                parentOwnership = ownership.ParentOwnership;
                ownershipFailure = ownership.Failure;
            }

            var failure = NormalizeFailure(exception);
            if (!string.IsNullOrWhiteSpace(ownershipFailure))
            {
                failure = NormalizeFailure(new InvalidOperationException(
                    $"{failure} {ownershipFailure}"));
            }
            return new LauncherRestartAttempt(
                null,
                failure,
                parentOwnership);
        }
        finally
        {
            receiverExit?.Dispose();
            receiverProcess?.Dispose();
            starterProcess?.Dispose();
            rollbackOwned?.Dispose();
            released?.Dispose();
            cancellation?.Dispose();
        }
    }

    [SupportedOSPlatform("windows")]
    internal static LauncherRestartIncomingHandoff AcceptHandoff(
        PersonalLauncherRestartHandoffCommand command,
        string singletonMutexName,
        TimeSpan? handoffTimeout = null,
        Action? ownershipAcquired = null)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentException.ThrowIfNullOrWhiteSpace(singletonMutexName);
        var timeout = ValidateTimeout(handoffTimeout);
        if (command.ParentProcessId == Environment.ProcessId)
        {
            throw new InvalidOperationException(
                "Launcher restart parent cannot be the replacement process.");
        }

        Process? parent = null;
        Mutex? singleton = null;
        EventWaitHandle? ready = null;
        EventWaitHandle? commit = null;
        EventWaitHandle? commitAcknowledged = null;
        EventWaitHandle? cancellation = null;
        EventWaitHandle? failure = null;
        EventWaitHandle? released = null;
        EventWaitHandle? rollbackOwned = null;
        NamedPipeClientStream? controlPipe = null;
        var ownsSingleton = false;
        try
        {
            parent = Process.GetProcessById(command.ParentProcessId);
            if (parent.HasExited)
            {
                throw new InvalidOperationException(
                    "Launcher restart parent exited before handoff preparation.");
            }

            singleton = Mutex.OpenExisting(singletonMutexName);
            using var armed = EventWaitHandle.OpenExisting(
                command.ArmedEventName);
            using var owned = EventWaitHandle.OpenExisting(
                command.OwnedEventName);
            ready = EventWaitHandle.OpenExisting(command.ReadyEventName);
            commit = EventWaitHandle.OpenExisting(command.CommitEventName);
            commitAcknowledged = EventWaitHandle.OpenExisting(
                command.CommitAcknowledgedEventName);
            cancellation = EventWaitHandle.OpenExisting(
                command.CancellationEventName);
            failure = EventWaitHandle.OpenExisting(command.FailureEventName);
            released = EventWaitHandle.OpenExisting(command.ReleasedEventName);
            rollbackOwned = EventWaitHandle.OpenExisting(
                command.RollbackOwnedEventName);
            controlPipe = new NamedPipeClientStream(
                ".",
                command.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            controlPipe.Connect(checked((int)timeout.TotalMilliseconds));
            armed.Set();
            var mutexResult = WaitForMutexOrCancellation(
                singleton,
                cancellation,
                timeout);
            if (mutexResult == HandoffSignal.Second)
            {
                throw new OperationCanceledException(
                    "Launcher restart handoff was cancelled before ownership transfer.");
            }
            if (mutexResult == HandoffSignal.Timeout)
            {
                throw new TimeoutException(
                    "Launcher restart handoff timed out waiting for singleton ownership.");
            }
            ownsSingleton = true;

            owned.Set();
            ownershipAcquired?.Invoke();

            var receiver = new LauncherRestartReceiverLease(
                command,
                parent,
                ready,
                commit,
                commitAcknowledged,
                cancellation,
                failure,
                released,
                rollbackOwned,
                controlPipe);
            var accepted = new LauncherRestartIncomingHandoff(
                singleton,
                receiver);

            parent = null;
            singleton = null;
            ready = null;
            commit = null;
            commitAcknowledged = null;
            cancellation = null;
            failure = null;
            released = null;
            rollbackOwned = null;
            controlPipe = null;
            ownsSingleton = false;
            return accepted;
        }
        catch
        {
            if (ownsSingleton)
            {
                TryRelease(singleton);
            }
            TrySet(failure);
            command.TrySignalFailure();
            throw;
        }
        finally
        {
            controlPipe?.Dispose();
            rollbackOwned?.Dispose();
            released?.Dispose();
            failure?.Dispose();
            cancellation?.Dispose();
            commitAcknowledged?.Dispose();
            commit?.Dispose();
            ready?.Dispose();
            singleton?.Dispose();
            parent?.Dispose();
        }
    }

    internal static string NormalizeFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var source = string.IsNullOrWhiteSpace(exception.Message)
            ? "Launcher 重启失败。"
            : exception.Message;
        var normalized = new StringBuilder(
            Math.Min(source.Length, MaximumFailureLength));
        foreach (var character in source)
        {
            if (normalized.Length == MaximumFailureLength)
            {
                break;
            }
            normalized.Append(char.IsControl(character) ? ' ' : character);
        }
        var result = normalized.ToString().Trim();
        return string.IsNullOrWhiteSpace(result)
            ? "Launcher 重启失败。"
            : result;
    }

    private static TimeSpan ValidateTimeout(TimeSpan? handoffTimeout)
    {
        var timeout = handoffTimeout ?? DefaultHandoffTimeout;
        if (timeout < TimeSpan.FromSeconds(1)
            || timeout > DefaultHandoffTimeout)
        {
            throw new ArgumentOutOfRangeException(nameof(handoffTimeout));
        }

        return timeout;
    }

    private static TimeSpan ValidateReceiverConnectionTimeout(
        TimeSpan? receiverConnectionTimeout,
        TimeSpan handoffTimeout)
    {
        var timeout = receiverConnectionTimeout ?? handoffTimeout;
        if (timeout < TimeSpan.FromSeconds(1)
            || timeout > MaximumReceiverConnectionTimeout)
        {
            throw new ArgumentOutOfRangeException(
                nameof(receiverConnectionTimeout));
        }

        return timeout;
    }

    private static TimeSpan ValidateCancellationGrace(
        TimeSpan? cancellationGrace)
    {
        var grace = cancellationGrace ?? DefaultCancellationGrace;
        if (grace <= TimeSpan.Zero || grace > DefaultCancellationGrace)
        {
            throw new ArgumentOutOfRangeException(nameof(cancellationGrace));
        }

        return grace;
    }

    internal static LauncherRestartOwnershipResult
        CancelAndRecoverParentOwnership(
            EventWaitHandle cancellation,
            EventWaitHandle released,
            EventWaitHandle rollbackOwned,
            Process receiverProcess,
            LauncherProcessWaitHandle receiverExit,
            Func<TimeSpan, bool> tryReacquireSingleton,
            TimeSpan cancellationGrace,
            Action<Process> terminateReceiver,
            Func<Process, TimeSpan, bool> waitForReceiverExit,
            Action? releasedObserved = null)
    {
        TrySet(cancellation);

        // Cancellation is already a known failure. Do not reuse the normal
        // three-minute handoff phase timeout here or the old UI can appear
        // frozen. Give a cooperative receiver one short grace period to
        // release, then contain only the pipe-bound, validated final process.
        // Exit confirmation and singleton reacquisition each use that same
        // short, injectable bound, so a known cancellation never falls back
        // to any three-minute normal-stage wait.
        HandoffSignal releaseState;
        try
        {
            releaseState = WaitForSignal(
                released,
                receiverExit,
                cancellationGrace);
        }
        catch (Exception exception)
        {
            return OwnershipUnproven(exception);
        }
        if (releaseState == HandoffSignal.First)
        {
            try
            {
                releasedObserved?.Invoke();
            }
            catch (Exception exception)
            {
                return OwnershipUnproven(exception);
            }
        }
        else if (releaseState == HandoffSignal.Timeout)
        {
            try
            {
                terminateReceiver(receiverProcess);
            }
            catch (Exception exception)
            {
                return OwnershipUnproven(new InvalidOperationException(
                    "Launcher 重启取消后无法终止已验证的替代进程。",
                    exception));
            }

            bool receiverExited;
            try
            {
                receiverExited = waitForReceiverExit(
                    receiverProcess,
                    cancellationGrace);
            }
            catch (Exception exception)
            {
                return OwnershipUnproven(new InvalidOperationException(
                    "Launcher 重启取消后无法确认替代进程已退出。",
                    exception));
            }
            bool receiverExitConfirmed;
            try
            {
                receiverExitConfirmed = receiverExited
                    && receiverProcess.HasExited;
            }
            catch (Exception exception)
            {
                return OwnershipUnproven(new InvalidOperationException(
                    "Launcher 重启取消后无法确认替代进程已退出。",
                    exception));
            }
            if (!receiverExitConfirmed)
            {
                return OwnershipUnproven(new TimeoutException(
                    "Launcher 重启取消后未能确认替代进程已退出。"));
            }
        }

        bool ownershipRecovered;
        try
        {
            ownershipRecovered = tryReacquireSingleton(cancellationGrace);
        }
        catch (Exception exception)
        {
            return OwnershipUnproven(new InvalidOperationException(
                "Launcher 重启取消后重新取得单实例所有权失败。",
                exception));
        }
        if (!ownershipRecovered)
        {
            return OwnershipUnproven(new TimeoutException(
                "Launcher 重启取消后未能重新取得单实例所有权。"));
        }

        try
        {
            if (!receiverProcess.HasExited)
            {
                TrySet(rollbackOwned);
            }
        }
        catch
        {
            // Parent ownership is already positively proven. The receiver
            // observes parent exit if this best-effort rollback ACK is lost.
        }
        return new LauncherRestartOwnershipResult(
            LauncherRestartParentOwnership.Recovered,
            null);
    }

    private static LauncherRestartOwnershipResult OwnershipUnproven(
        Exception exception) =>
        new(
            LauncherRestartParentOwnership.Unproven,
            NormalizeFailure(exception));

    private static string? TerminateAndConfirmPreHandoffProcess(
        Process process,
        TimeSpan cleanupGrace,
        Action<Process> terminateProcess,
        Func<Process, TimeSpan, bool> waitForProcessExit)
    {
        try
        {
            terminateProcess(process);
            if (!waitForProcessExit(process, cleanupGrace))
            {
                throw new TimeoutException(
                    "重启转发进程取消后未在宽限期内退出。");
            }

            return null;
        }
        catch (Exception exception)
        {
            return NormalizeFailure(new InvalidOperationException(
                "重启转发进程取消后的进程树清理未获确认。",
                exception));
        }
    }

    private static void TerminateReceiver(Process receiverProcess)
    {
        if (!receiverProcess.HasExited)
        {
            receiverProcess.Kill(entireProcessTree: true);
        }
    }

    private static bool WaitForReceiverExit(
        Process receiverProcess,
        TimeSpan timeout) =>
        receiverProcess.HasExited
        || (receiverProcess.WaitForExit(checked((int)timeout.TotalMilliseconds))
            && receiverProcess.HasExited);

    private static EventWaitHandle CreateNewEvent(string name)
    {
        var result = new EventWaitHandle(
            initialState: false,
            EventResetMode.ManualReset,
            name,
            out var createdNew);
        if (createdNew)
        {
            return result;
        }

        result.Dispose();
        throw new InvalidOperationException(
            "Launcher restart handoff event already exists.");
    }

    [SupportedOSPlatform("windows")]
    private static NamedPipeServerStream CreateControlPipe(string pipeName) =>
        new(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

    private static async Task WaitForReceiverConnectionAsync(
        NamedPipeServerStream controlPipe,
        EventWaitHandle failure,
        Process starterProcess,
        TimeSpan timeout)
    {
        using var timeoutCancellation = new CancellationTokenSource(timeout);
        var connection = controlPipe.WaitForConnectionAsync(
            timeoutCancellation.Token);
        while (!connection.IsCompleted)
        {
            if (failure.WaitOne(0))
            {
                timeoutCancellation.Cancel();
                await ObserveCancellationAsync(connection);
                throw new InvalidOperationException(
                    "替代 Launcher 拒绝了重启交接。");
            }
            if (starterProcess.HasExited)
            {
                timeoutCancellation.Cancel();
                await ObserveCancellationAsync(connection);
                throw new InvalidOperationException(
                    "Launcher 重启转发进程在最终 Launcher 建链前退出。");
            }

            await Task.WhenAny(
                connection,
                Task.Delay(MonitorPollInterval));
        }

        try
        {
            await connection;
        }
        catch (OperationCanceledException)
            when (timeoutCancellation.IsCancellationRequested)
        {
            if (failure.WaitOne(0))
            {
                throw new InvalidOperationException(
                    "替代 Launcher 拒绝了重启交接。");
            }

            throw new TimeoutException(
                "替代 Launcher 未在期限内连接重启交接控制通道。");
        }

        if (failure.WaitOne(0))
        {
            throw new InvalidOperationException(
                "替代 Launcher 拒绝了重启交接。");
        }
    }

    private static async Task ObserveCancellationAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
            // Expected after the parent rejects a failed receiver connection.
        }
    }

    [SupportedOSPlatform("windows")]
    private static Process OpenReceiverProcess(
        NamedPipeServerStream controlPipe,
        int parentProcessId,
        int parentSessionId,
        DateTime launchStartedUtc)
    {
        if (!GetNamedPipeClientProcessId(
                controlPipe.SafePipeHandle,
                out var receiverProcessId))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        if (receiverProcessId == 0
            || receiverProcessId > int.MaxValue
            || receiverProcessId == (uint)parentProcessId)
        {
            throw new InvalidOperationException(
                "Launcher restart handoff receiver identity is invalid.");
        }

        var process = Process.GetProcessById((int)receiverProcessId);
        try
        {
            var creationTimeUtc = process.StartTime.ToUniversalTime();
            if (process.Id != (int)receiverProcessId
                || process.SessionId != parentSessionId
                || creationTimeUtc < launchStartedUtc.AddSeconds(-2)
                || creationTimeUtc > DateTime.UtcNow.AddSeconds(2)
                || process.HasExited)
            {
                throw new InvalidOperationException(
                    "Launcher restart handoff receiver process identity is stale or cross-session.");
            }

            return process;
        }
        catch (Exception validationFailure)
        {
            DisposeReceiverAfterValidationFailure(
                process,
                validationFailure);
            throw;
        }
    }

    internal static void DisposeReceiverAfterValidationFailureForTests(
        Process process,
        Exception validationFailure) =>
        DisposeReceiverAfterValidationFailure(process, validationFailure);

    private static void DisposeReceiverAfterValidationFailure(
        Process process,
        Exception validationFailure)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(validationFailure);
        if (validationFailure
                is LauncherRestartReceiverProcessRetainedException retained
            && ReferenceEquals(retained.RetainedProcess, process))
        {
            return;
        }
        process.Dispose();
    }

    private static async Task RequireStageAsync(
        EventWaitHandle failure,
        EventWaitHandle stage,
        LauncherProcessWaitHandle receiverExit,
        Process receiverProcess,
        TimeSpan timeout,
        string failureMessage,
        string timeoutMessage)
    {
        var result = await Task.Run(() =>
            WaitForStage(failure, stage, receiverExit, timeout));
        if (result == HandoffStage.Stage)
        {
            ThrowIfReceiverUnavailable(failure, receiverProcess);
            return;
        }

        throw new InvalidOperationException(result switch
        {
            HandoffStage.Failure => failureMessage,
            HandoffStage.ReceiverExited =>
                "替代 Launcher 在重启交接期间意外退出。",
            HandoffStage.Timeout => timeoutMessage,
            _ => "Launcher restart handoff returned an invalid wait result.",
        });
    }

    private static HandoffStage WaitForStage(
        WaitHandle failure,
        WaitHandle stage,
        WaitHandle receiverExit,
        TimeSpan timeout) =>
        WaitHandle.WaitAny([failure, stage, receiverExit], timeout) switch
        {
            0 => HandoffStage.Failure,
            1 => HandoffStage.Stage,
            2 => HandoffStage.ReceiverExited,
            WaitHandle.WaitTimeout => HandoffStage.Timeout,
            _ => throw new InvalidOperationException(
                "Launcher restart handoff returned an invalid wait result."),
        };

    private static async Task PrepareWhileMonitoringAsync(
        Func<Task> prepareForRestartAsync,
        EventWaitHandle failure,
        Process receiverProcess)
    {
        var preparation = Task.Run(prepareForRestartAsync);
        while (!preparation.IsCompleted)
        {
            try
            {
                ThrowIfReceiverUnavailable(failure, receiverProcess);
            }
            catch
            {
                ObserveBackgroundFault(preparation);
                throw;
            }

            await Task.WhenAny(
                preparation,
                Task.Delay(MonitorPollInterval));
        }

        await preparation;
        ThrowIfReceiverUnavailable(failure, receiverProcess);
    }

    private static void ObserveBackgroundFault(Task task)
    {
        _ = task.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted
                | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private static void ThrowIfReceiverUnavailable(
        EventWaitHandle failure,
        Process receiverProcess)
    {
        if (failure.WaitOne(0))
        {
            throw new InvalidOperationException(
                "替代 Launcher 拒绝了重启交接。");
        }
        if (receiverProcess.HasExited)
        {
            throw new InvalidOperationException(
                "替代 Launcher 在重启交接期间意外退出。");
        }
    }

    private static HandoffSignal WaitForSignal(
        WaitHandle first,
        WaitHandle second,
        TimeSpan timeout) =>
        WaitHandle.WaitAny([first, second], timeout) switch
        {
            0 => HandoffSignal.First,
            1 => HandoffSignal.Second,
            WaitHandle.WaitTimeout => HandoffSignal.Timeout,
            _ => throw new InvalidOperationException(
                "Launcher restart handoff returned an invalid wait result."),
        };

    private static HandoffSignal WaitForMutexOrCancellation(
        Mutex singleton,
        EventWaitHandle cancellation,
        TimeSpan timeout)
    {
        try
        {
            return WaitForSignal(singleton, cancellation, timeout);
        }
        catch (AbandonedMutexException exception)
            when (exception.MutexIndex == 0)
        {
            return HandoffSignal.First;
        }
    }

    private static void TrySet(EventWaitHandle? waitHandle)
    {
        try
        {
            waitHandle?.Set();
        }
        catch
        {
            // A best-effort signal must not replace the original failure.
        }
    }

    private static void TryRelease(Mutex? mutex)
    {
        try
        {
            mutex?.ReleaseMutex();
        }
        catch
        {
            // The owning process may be terminating. The kernel will abandon
            // the mutex if this thread can no longer release it normally.
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(
        SafePipeHandle pipe,
        out uint clientProcessId);

    private enum HandoffSignal
    {
        First,
        Second,
        Timeout,
    }

    private enum HandoffStage
    {
        Failure,
        Stage,
        ReceiverExited,
        Timeout,
    }
}

internal sealed class LauncherProcessWaitHandle : WaitHandle
{
    internal LauncherProcessWaitHandle(Process process)
    {
        SafeWaitHandle = new SafeWaitHandle(
            process.Handle,
            ownsHandle: false);
    }
}
