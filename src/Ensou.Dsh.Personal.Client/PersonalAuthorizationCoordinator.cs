using System.Runtime.ExceptionServices;

namespace Ensou.Dsh.Personal.Client;

/// <summary>
/// Serializes one installation's authorization transitions. It never treats a
/// locally stored session as authority: every open/start path checks online.
/// </summary>
public sealed class PersonalAuthorizationCoordinator
{
    private static readonly TimeSpan RefreshLeadTime = TimeSpan.FromMinutes(2);
    private readonly IPersonalAccountClient _client;
    private readonly IPersonalAccountSessionStore _store;
    private readonly Func<CancellationToken, Task> _stopOwnedRuntime;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _operation = new(1, 1);
    private volatile bool _stopRequired;
    private long _lastAccessDeadlineTimestamp;
    private string? _lastAccessDeadlineIdentity;

    public PersonalAuthorizationCoordinator(IPersonalAccountClient client, IPersonalAccountSessionStore store,
        Func<CancellationToken, Task> stopOwnedRuntime, TimeProvider? clock = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _stopOwnedRuntime = stopOwnedRuntime ?? throw new ArgumentNullException(nameof(stopOwnedRuntime));
        _clock = clock ?? TimeProvider.System;
    }

    public Task<PersonalEmailChallenge> RequestEmailAsync(string email, CancellationToken cancellationToken = default) =>
        RunExclusiveAsync(token => _client.RequestEmailAsync(email, token), cancellationToken);

    public Task SignInAsync(PersonalEmailChallenge challenge, string code,
        CancellationToken cancellationToken = default) =>
        RunExclusiveAsync(async token =>
        {
            var priorStopFailure = await InvalidateAndStopAsync().ConfigureAwait(false);
            if (priorStopFailure is not null) ExceptionDispatchInfo.Capture(priorStopFailure).Throw();
            token.ThrowIfCancellationRequested();
            try
            {
                var session = await _client.SignInAsync(challenge, code, token).ConfigureAwait(false);
                await _store.SaveAsync(session, token).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                var cleanupFailure = await ClearAfterFailedAuthorizationAsync().ConfigureAwait(false);
                ThrowPreferred(cleanupFailure, exception);
                throw;
            }
        }, cancellationToken);

    public Task EnsureAuthorizedAsync(CancellationToken cancellationToken = default) =>
        RunExclusiveAsync(EnsureAuthorizedCoreAsync, cancellationToken);

    public Task SignOutAsync(CancellationToken cancellationToken = default) =>
        RunExclusiveAsync(SignOutCoreAsync, cancellationToken);

    public Task CheckRuntimeAuthorizationAsync(CancellationToken cancellationToken = default) =>
        CheckRuntimeAuthorizationAsyncCore(cancellationToken);

    private Task EnsureAuthorizedCoreAsync(CancellationToken cancellationToken) =>
        EnsureAuthorizedCoreAsync(cancellationToken, clearAfterFailure: true);

    private async Task EnsureAuthorizedCoreAsync(CancellationToken cancellationToken, bool clearAfterFailure)
    {
        await ResolvePendingStopAsync().ConfigureAwait(false);
        var session = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (session is null) throw Reauthenticate();

        if (session.AccessExpiresAtUtc <= _clock.GetUtcNow().Add(RefreshLeadTime))
        {
            // Do not leave a refresh credential available after submitting it.
            await _store.ClearAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                var refreshed = await _client.RefreshAsync(session, cancellationToken).ConfigureAwait(false);
                await _store.SaveAsync(refreshed, cancellationToken).ConfigureAwait(false);
                var access = await _client.ValidateAccessAsync(refreshed, cancellationToken).ConfigureAwait(false);
                RecordAccessDeadline(refreshed, access);
                return;
            }
            catch (Exception exception)
            {
                if (!clearAfterFailure) throw;
                var cleanupFailure = await ClearAfterFailedAuthorizationAsync().ConfigureAwait(false);
                ThrowPreferred(cleanupFailure, exception);
                throw;
            }
        }

        try
        {
            var access = await _client.ValidateAccessAsync(session, cancellationToken).ConfigureAwait(false);
            RecordAccessDeadline(session, access);
        }
        catch (Exception exception)
        {
            if (!clearAfterFailure) throw;
            var cleanupFailure = await ClearAfterFailedAuthorizationAsync().ConfigureAwait(false);
            ThrowPreferred(cleanupFailure, exception);
            throw;
        }
    }

    private async Task SignOutCoreAsync(CancellationToken cancellationToken)
    {
        var failure = await InvalidateAndStopAsync().ConfigureAwait(false);
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private async Task CheckRuntimeAuthorizationAsyncCore(CancellationToken cancellationToken)
    {
        if (!await _operation.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            if (IsLastAccessDeadlineExpired()) await StopForExpiredBusyCheckAsync(cancellationToken).ConfigureAwait(false);
            throw Busy();
        }
        try { await CheckRuntimeAuthorizationCoreAsync(cancellationToken).ConfigureAwait(false); }
        finally { _operation.Release(); }
    }

    private async Task CheckRuntimeAuthorizationCoreAsync(CancellationToken cancellationToken)
    {
        if (_stopRequired)
        {
            await ResolvePendingStopAsync().ConfigureAwait(false);
        }

        try
        {
            await EnsureAuthorizedCoreAsync(cancellationToken, clearAfterFailure: false).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            var remediationFailure = await InvalidateAndStopAsync().ConfigureAwait(false);
            ThrowPreferred(remediationFailure, exception);
            throw;
        }
    }

    private async Task ResolvePendingStopAsync()
    {
        if (!_stopRequired) return;
        var pendingStopFailure = await InvalidateAndStopAsync().ConfigureAwait(false);
        if (pendingStopFailure is not null) ExceptionDispatchInfo.Capture(pendingStopFailure).Throw();
        throw Reauthenticate();
    }

    private async Task<Exception?> InvalidateAndStopAsync()
    {
        Exception? failure = null;
        var cleared = true;
        ForgetAccessDeadline();
        try { await _store.ClearAsync(CancellationToken.None).ConfigureAwait(false); }
        catch (Exception exception)
        {
            cleared = false;
            failure = exception;
        }

        try
        {
            await _stopOwnedRuntime(CancellationToken.None).ConfigureAwait(false);
            _stopRequired = !cleared;
        }
        catch (Exception exception)
        {
            _stopRequired = true;
            failure ??= exception;
        }
        return failure;
    }

    private async Task<Exception?> ClearAfterFailedAuthorizationAsync()
    {
        ForgetAccessDeadline();
        try
        {
            await _store.ClearAsync(CancellationToken.None).ConfigureAwait(false);
            return null;
        }
        catch (Exception exception)
        {
            _stopRequired = true;
            return exception;
        }
    }

    private void RecordAccessDeadline(PersonalAccountSession session, PersonalAccountAccess access)
    {
        var serverWindow = access.AccessExpiresAtUtc - access.CheckedAtUtc;
        var localRemaining = access.AccessExpiresAtUtc - _clock.GetUtcNow();
        var now = _clock.GetTimestamp();
        if (serverWindow <= TimeSpan.Zero || localRemaining <= TimeSpan.Zero) throw Reauthenticate();
        var identity = string.Concat(session.SessionId, ":", session.AccessExpiresAtUtc.UtcTicks);
        if (string.Equals(identity, _lastAccessDeadlineIdentity, StringComparison.Ordinal))
        {
            if (Volatile.Read(ref _lastAccessDeadlineTimestamp) > now) return;
            throw Reauthenticate();
        }

        var boundedRemaining = TimeSpan.FromMinutes(15);
        if (serverWindow < boundedRemaining) boundedRemaining = serverWindow;
        if (localRemaining < boundedRemaining) boundedRemaining = localRemaining;
        var duration = checked((long)(boundedRemaining.TotalSeconds * _clock.TimestampFrequency));
        var deadline = now > long.MaxValue - duration ? long.MaxValue : now + duration;
        _lastAccessDeadlineIdentity = identity;
        Volatile.Write(ref _lastAccessDeadlineTimestamp, deadline);
    }

    private void ForgetAccessDeadline()
    {
        _lastAccessDeadlineIdentity = null;
        Volatile.Write(ref _lastAccessDeadlineTimestamp, 0);
    }

    private bool IsLastAccessDeadlineExpired() =>
        Volatile.Read(ref _lastAccessDeadlineTimestamp) <= _clock.GetTimestamp();

    private async Task StopForExpiredBusyCheckAsync(CancellationToken cancellationToken)
    {
        try { await _stopOwnedRuntime(CancellationToken.None).ConfigureAwait(false); }
        catch
        {
            _stopRequired = true;
            throw;
        }
    }

    private async Task<T> RunExclusiveAsync<T>(Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        if (!await _operation.WaitAsync(0, cancellationToken).ConfigureAwait(false)) throw Busy();
        try { return await operation(cancellationToken).ConfigureAwait(false); }
        finally { _operation.Release(); }
    }

    private async Task RunExclusiveAsync(Func<CancellationToken, Task> operation,
        CancellationToken cancellationToken)
    {
        if (!await _operation.WaitAsync(0, cancellationToken).ConfigureAwait(false)) throw Busy();
        try { await operation(cancellationToken).ConfigureAwait(false); }
        finally { _operation.Release(); }
    }

    private static void ThrowPreferred(Exception? remediationFailure, Exception originalFailure)
    {
        if (remediationFailure is not null) ExceptionDispatchInfo.Capture(remediationFailure).Throw();
        ExceptionDispatchInfo.Capture(originalFailure).Throw();
    }

    private static PersonalAccountException Reauthenticate() =>
        new(PersonalAccountFailure.ReauthenticationRequired);
    private static PersonalAccountException Busy() => new(PersonalAccountFailure.Busy);
}
