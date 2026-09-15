using Ensou.Dsh.Personal.Client;

namespace Ensou.Dsh.Personal.ClientTests;

internal static class PersonalAuthorizationCoordinatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 9, 0, 0, 0, TimeSpan.Zero);

    internal static async Task RunAsync()
    {
        Func<Task>[] tests =
        [
            SignInStopsOldRuntimeAndPersistsNewSessionAsync,
            SignInDoesNotSucceedWhenPersistenceFailsAsync,
            FailedCleanupBlocksSubsequentEnsureAsync,
            EnsureClearsBeforeRefreshAndValidatesAfterSaveAsync,
            RefreshFailureLeavesNoReusableSessionAsync,
            RefreshCancellationLeavesNoReusableSessionAsync,
            EnsureAlwaysChecksOnlineAsync,
            RuntimeCheckUsesRefreshFlowAsync,
            RuntimeCheckFailureStopsAndRetriesStopAsync,
            PendingStopBlocksEnsureAsync,
            ExpiredAccessResponseInvalidatesAndStopsAsync,
            SameSessionValidationCannotExtendExpiredDeadlineAsync,
            BusyRefreshBeforePriorDeadlineDoesNotStopAsync,
            CancellationAfterCleanupDoesNotPreserveOldSessionAsync,
            SignOutStopsWithNoStoredSessionAsync,
            BusyOperationDoesNotQueueAsync,
            ExpiredDeadlineBusyCheckStopsRuntimeAsync,
        ];
        foreach (var test in tests)
        {
            try
            {
                await test().ConfigureAwait(false);
                Console.WriteLine($"PASS personal-coordinator {test.Method.Name}");
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine($"FAIL personal-coordinator {test.Method.Name}: {exception.GetType().Name}");
                throw;
            }
        }
    }

    private static async Task SignInStopsOldRuntimeAndPersistsNewSessionAsync()
    {
        var events = new List<string>();
        var store = new FakeStore(events) { Stored = Session() };
        var client = new FakeClient(events) { SignInResult = Session(accessMarker: 'c', refreshMarker: 'd') };
        var coordinator = NewCoordinator(client, store, events);

        await coordinator.SignInAsync(Challenge(), "123456").ConfigureAwait(false);

        RequireEvents(events, "clear", "stop", "sign-in", "save");
        Require(store.Stored?.AccessToken == client.SignInResult.AccessToken);
    }

    private static async Task SignInDoesNotSucceedWhenPersistenceFailsAsync()
    {
        var events = new List<string>();
        var store = new FakeStore(events)
        {
            Stored = Session(),
            SaveFailure = new InvalidOperationException(),
            SaveWritesThenThrows = true,
        };
        var client = new FakeClient(events) { SignInResult = Session(accessMarker: 'c', refreshMarker: 'd') };
        var coordinator = NewCoordinator(client, store, events);

        await ExpectExceptionAsync<InvalidOperationException>(
            () => coordinator.SignInAsync(Challenge(), "123456")).ConfigureAwait(false);

        RequireEvents(events, "clear", "stop", "sign-in", "save", "clear");
        Require(store.Stored is null);
    }

    private static async Task FailedCleanupBlocksSubsequentEnsureAsync()
    {
        var events = new List<string>();
        var session = Session(accessExpiry: Now.AddMinutes(5));
        var store = new FakeStore(events) { Stored = session, ClearFailuresRemaining = 1 };
        var client = new FakeClient(events)
        {
            AccessFailure = new PersonalAccountException(PersonalAccountFailure.Denied),
        };
        var coordinator = NewCoordinator(client, store, events);

        await ExpectExceptionAsync<InvalidOperationException>(
            () => coordinator.EnsureAuthorizedAsync()).ConfigureAwait(false);
        RequireEvents(events, "load", "validate", "clear");

        events.Clear();
        await ExpectFailureAsync(
            () => coordinator.EnsureAuthorizedAsync(), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
        RequireEvents(events, "clear", "stop");
    }

    private static async Task EnsureClearsBeforeRefreshAndValidatesAfterSaveAsync()
    {
        var events = new List<string>();
        var clock = new MutableClock(Now);
        var initial = Session(accessExpiry: Now.AddMinutes(1));
        var refreshed = Session(accessMarker: 'c', refreshMarker: 'd', accessExpiry: Now.AddMinutes(5));
        var store = new FakeStore(events) { Stored = initial };
        var client = new FakeClient(events)
        {
            RefreshResult = refreshed,
            AccessResult = new PersonalAccountAccess(Now, refreshed.AccessExpiresAtUtc),
        };
        var coordinator = NewCoordinator(client, store, events, clock);

        await coordinator.EnsureAuthorizedAsync().ConfigureAwait(false);

        RequireEvents(events, "load", "clear", "refresh", "save", "validate");
        Require(store.Stored?.RefreshToken == refreshed.RefreshToken);
    }

    private static async Task RefreshFailureLeavesNoReusableSessionAsync()
    {
        var events = new List<string>();
        var clock = new MutableClock(Now);
        var store = new FakeStore(events) { Stored = Session(accessExpiry: Now.AddMinutes(1)) };
        var client = new FakeClient(events)
        {
            RefreshFailure = new PersonalAccountException(PersonalAccountFailure.ReauthenticationRequired),
        };
        var coordinator = NewCoordinator(client, store, events, clock);

        await ExpectFailureAsync(
            () => coordinator.EnsureAuthorizedAsync(), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);

        RequireEvents(events, "load", "clear", "refresh", "clear");
        Require(store.Stored is null);

        events.Clear();
        await ExpectFailureAsync(
            () => coordinator.EnsureAuthorizedAsync(), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
        RequireEvents(events, "load");
    }

    private static async Task RefreshCancellationLeavesNoReusableSessionAsync()
    {
        var events = new List<string>();
        var store = new FakeStore(events) { Stored = Session(accessExpiry: Now.AddMinutes(1)) };
        var client = new FakeClient(events) { RefreshFailure = new OperationCanceledException() };
        var coordinator = NewCoordinator(client, store, events, new MutableClock(Now));

        await ExpectExceptionAsync<OperationCanceledException>(
            () => coordinator.EnsureAuthorizedAsync()).ConfigureAwait(false);

        RequireEvents(events, "load", "clear", "refresh", "clear");
        Require(store.Stored is null);
    }

    private static async Task EnsureAlwaysChecksOnlineAsync()
    {
        var events = new List<string>();
        var session = Session(accessExpiry: Now.AddMinutes(10));
        var store = new FakeStore(events) { Stored = session };
        var client = new FakeClient(events)
        {
            AccessResult = new PersonalAccountAccess(Now, session.AccessExpiresAtUtc),
        };
        var coordinator = NewCoordinator(client, store, events);

        await coordinator.EnsureAuthorizedAsync().ConfigureAwait(false);
        await coordinator.EnsureAuthorizedAsync().ConfigureAwait(false);

        RequireEvents(events, "load", "validate", "load", "validate");
    }

    private static async Task RuntimeCheckUsesRefreshFlowAsync()
    {
        var events = new List<string>();
        var clock = new MutableClock(Now);
        var initial = Session(accessExpiry: Now.AddMinutes(1));
        var refreshed = Session(accessMarker: 'c', refreshMarker: 'd', accessExpiry: Now.AddMinutes(5));
        var store = new FakeStore(events) { Stored = initial };
        var client = new FakeClient(events)
        {
            RefreshResult = refreshed,
            AccessResult = new PersonalAccountAccess(Now, refreshed.AccessExpiresAtUtc),
        };
        var coordinator = NewCoordinator(client, store, events, clock);

        await coordinator.CheckRuntimeAuthorizationAsync().ConfigureAwait(false);

        RequireEvents(events, "load", "clear", "refresh", "save", "validate");
    }

    private static async Task RuntimeCheckFailureStopsAndRetriesStopAsync()
    {
        var events = new List<string>();
        var store = new FakeStore(events) { Stored = Session(accessExpiry: Now.AddMinutes(10)) };
        var client = new FakeClient(events)
        {
            AccessFailure = new PersonalAccountException(PersonalAccountFailure.Denied),
        };
        var stopAttempts = 0;
        var coordinator = NewCoordinator(client, store, events, stop: _ =>
        {
            events.Add("stop");
            stopAttempts++;
            return stopAttempts == 1 ? Task.FromException(new InvalidOperationException()) : Task.CompletedTask;
        });

        await ExpectExceptionAsync<InvalidOperationException>(
            () => coordinator.CheckRuntimeAuthorizationAsync()).ConfigureAwait(false);
        RequireEvents(events, "load", "validate", "clear", "stop");

        events.Clear();
        await ExpectFailureAsync(
            () => coordinator.CheckRuntimeAuthorizationAsync(), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
        RequireEvents(events, "clear", "stop");
    }

    private static async Task PendingStopBlocksEnsureAsync()
    {
        var events = new List<string>();
        var store = new FakeStore(events) { Stored = Session(accessExpiry: Now.AddMinutes(10)) };
        var client = new FakeClient(events)
        {
            AccessFailure = new PersonalAccountException(PersonalAccountFailure.Denied),
        };
        var stopAttempts = 0;
        var coordinator = NewCoordinator(client, store, events, stop: _ =>
        {
            events.Add("stop");
            stopAttempts++;
            return stopAttempts == 1 ? Task.FromException(new InvalidOperationException()) : Task.CompletedTask;
        });

        await ExpectExceptionAsync<InvalidOperationException>(
            () => coordinator.CheckRuntimeAuthorizationAsync()).ConfigureAwait(false);
        events.Clear();

        await ExpectFailureAsync(
            () => coordinator.EnsureAuthorizedAsync(), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
        RequireEvents(events, "clear", "stop");
    }

    private static async Task ExpiredAccessResponseInvalidatesAndStopsAsync()
    {
        var events = new List<string>();
        var session = Session(accessExpiry: Now.AddMinutes(5));
        var client = new FakeClient(events)
        {
            AccessResult = new PersonalAccountAccess(Now, Now),
        };
        var coordinator = NewCoordinator(client, new FakeStore(events) { Stored = session }, events);

        await ExpectFailureAsync(
            () => coordinator.CheckRuntimeAuthorizationAsync(), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
        RequireEvents(events, "load", "validate", "clear", "stop");
    }

    private static async Task SameSessionValidationCannotExtendExpiredDeadlineAsync()
    {
        var events = new List<string>();
        var clock = new MutableClock(Now);
        var session = Session(accessExpiry: Now.AddMinutes(5));
        var client = new FakeClient(events)
        {
            AccessResult = new PersonalAccountAccess(Now, Now.AddSeconds(1)),
        };
        var coordinator = NewCoordinator(client, new FakeStore(events) { Stored = session }, events, clock);
        await coordinator.CheckRuntimeAuthorizationAsync().ConfigureAwait(false);

        events.Clear();
        clock.Advance(TimeSpan.FromSeconds(2));
        await ExpectFailureAsync(
            () => coordinator.CheckRuntimeAuthorizationAsync(), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
        RequireEvents(events, "load", "validate", "clear", "stop");
    }

    private static async Task BusyRefreshBeforePriorDeadlineDoesNotStopAsync()
    {
        var events = new List<string>();
        var clock = new MutableClock(Now);
        var initial = Session(accessExpiry: Now.AddMinutes(3));
        var store = new FakeStore(events) { Stored = initial };
        var client = new FakeClient(events)
        {
            AccessResult = new PersonalAccountAccess(Now, initial.AccessExpiresAtUtc),
        };
        var coordinator = NewCoordinator(client, store, events, clock);
        await coordinator.CheckRuntimeAuthorizationAsync().ConfigureAwait(false);

        clock.Advance(TimeSpan.FromMinutes(2));
        var refreshStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseRefresh = new TaskCompletionSource<PersonalAccountSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.RefreshOverride = async _ =>
        {
            refreshStarted.TrySetResult(true);
            return await releaseRefresh.Task.ConfigureAwait(false);
        };
        var refresh = coordinator.EnsureAuthorizedAsync();
        await refreshStarted.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);

        await ExpectFailureAsync(
            () => coordinator.CheckRuntimeAuthorizationAsync(), PersonalAccountFailure.Busy).ConfigureAwait(false);
        Require(events.Count(static entry => entry == "stop") == 0);

        var refreshed = Session(accessMarker: 'c', refreshMarker: 'd', accessExpiry: Now.AddMinutes(5));
        client.AccessResult = new PersonalAccountAccess(clock.GetUtcNow(), refreshed.AccessExpiresAtUtc);
        releaseRefresh.TrySetResult(refreshed);
        await refresh.ConfigureAwait(false);
    }

    private static async Task CancellationAfterCleanupDoesNotPreserveOldSessionAsync()
    {
        var events = new List<string>();
        var store = new FakeStore(events) { Stored = Session() };
        using var cancellation = new CancellationTokenSource();
        var stopUsedCancelableToken = true;
        var coordinator = NewCoordinator(new FakeClient(events), store, events, stop: token =>
        {
            events.Add("stop");
            stopUsedCancelableToken = token.CanBeCanceled;
            cancellation.Cancel();
            return Task.CompletedTask;
        });

        await ExpectExceptionAsync<OperationCanceledException>(
            () => coordinator.SignInAsync(Challenge(), "123456", cancellation.Token)).ConfigureAwait(false);

        RequireEvents(events, "clear", "stop");
        Require(store.Stored is null && store.ClearTokens.All(static token => !token.CanBeCanceled) && !stopUsedCancelableToken);
    }

    private static async Task SignOutStopsWithNoStoredSessionAsync()
    {
        var events = new List<string>();
        var coordinator = NewCoordinator(new FakeClient(events), new FakeStore(events), events);

        await coordinator.SignOutAsync().ConfigureAwait(false);

        RequireEvents(events, "clear", "stop");
    }

    private static async Task BusyOperationDoesNotQueueAsync()
    {
        var events = new List<string>();
        var requestStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseRequest = new TaskCompletionSource<PersonalEmailChallenge>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new FakeClient(events)
        {
            RequestOverride = async _ =>
            {
                requestStarted.TrySetResult(true);
                return await releaseRequest.Task.ConfigureAwait(false);
            },
        };
        var coordinator = NewCoordinator(client, new FakeStore(events), events);
        var first = coordinator.RequestEmailAsync("member@example.test");
        await requestStarted.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);

        await ExpectFailureAsync(
            () => coordinator.RequestEmailAsync("member@example.test"), PersonalAccountFailure.Busy).ConfigureAwait(false);
        RequireEvents(events, "request");

        releaseRequest.TrySetResult(Challenge());
        await first.ConfigureAwait(false);
    }

    private static async Task ExpiredDeadlineBusyCheckStopsRuntimeAsync()
    {
        var events = new List<string>();
        var clock = new MutableClock(Now);
        var session = Session(accessExpiry: Now.AddMinutes(5));
        var client = new FakeClient(events)
        {
            AccessResult = new PersonalAccountAccess(Now, Now.AddSeconds(1)),
        };
        var coordinator = NewCoordinator(client, new FakeStore(events) { Stored = session }, events, clock);
        await coordinator.CheckRuntimeAuthorizationAsync().ConfigureAwait(false);
        clock.Advance(TimeSpan.FromMilliseconds(500));
        await coordinator.CheckRuntimeAuthorizationAsync().ConfigureAwait(false);

        var requestStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseRequest = new TaskCompletionSource<PersonalEmailChallenge>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.RequestOverride = async _ =>
        {
            requestStarted.TrySetResult(true);
            return await releaseRequest.Task.ConfigureAwait(false);
        };
        var inFlight = coordinator.RequestEmailAsync("member@example.test");
        await requestStarted.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        clock.Advance(TimeSpan.FromSeconds(1));

        await ExpectFailureAsync(
            () => coordinator.CheckRuntimeAuthorizationAsync(), PersonalAccountFailure.Busy).ConfigureAwait(false);
        Require(events.Count(static entry => entry == "stop") == 1);

        releaseRequest.TrySetResult(Challenge());
        await inFlight.ConfigureAwait(false);
    }

    private static PersonalAuthorizationCoordinator NewCoordinator(FakeClient client, FakeStore store,
        List<string> events, TimeProvider? clock = null, Func<CancellationToken, Task>? stop = null) =>
        // Session fixtures have a fixed epoch; do not depend on the machine clock.
        new(client, store, stop ?? (_ =>
        {
            events.Add("stop");
            return Task.CompletedTask;
        }), clock ?? new MutableClock(Now));

    private static PersonalEmailChallenge Challenge() => new("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");

    private static PersonalAccountSession Session(char accessMarker = 'a', char refreshMarker = 'b',
        DateTimeOffset? accessExpiry = null) =>
        new(new Uri("https://personal.example.test/"), "33333333-3333-4333-8333-333333333333",
            "22222222-2222-4222-8222-222222222222", "11111111-1111-4111-8111-111111111111",
            "psa_" + new string(accessMarker, 43), "psr_" + new string(refreshMarker, 43), Now,
            accessExpiry ?? Now.AddMinutes(5), Now.AddDays(7));

    private static async Task ExpectFailureAsync(Func<Task> action, PersonalAccountFailure expected)
    {
        try { await action().ConfigureAwait(false); }
        catch (PersonalAccountException exception) when (exception.Failure == expected) { return; }
        throw new InvalidOperationException();
    }

    private static async Task ExpectExceptionAsync<TException>(Func<Task> action) where TException : Exception
    {
        try { await action().ConfigureAwait(false); }
        catch (TException) { return; }
        throw new InvalidOperationException();
    }

    private static void RequireEvents(IEnumerable<string> actual, params string[] expected)
    {
        if (!actual.SequenceEqual(expected, StringComparer.Ordinal)) throw new InvalidOperationException();
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException();
    }

    private sealed class MutableClock(DateTimeOffset now) : TimeProvider
    {
        private long _timestamp = now.UtcTicks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow() => now;
        public override long GetTimestamp() => _timestamp;
        public void Advance(TimeSpan elapsed)
        {
            now += elapsed;
            _timestamp += elapsed.Ticks;
        }
    }

    private sealed class FakeClient(List<string> events) : IPersonalAccountClient
    {
        public PersonalAccountSession SignInResult { get; init; } = Session(accessMarker: 'c', refreshMarker: 'd');
        public PersonalAccountSession RefreshResult { get; init; } = Session(accessMarker: 'c', refreshMarker: 'd');
        public PersonalAccountAccess AccessResult { get; set; } = new(Now, Now.AddMinutes(5));
        public Exception? RefreshFailure { get; init; }
        public Exception? AccessFailure { get; init; }
        public Func<CancellationToken, Task<PersonalEmailChallenge>>? RequestOverride { get; set; }
        public Func<CancellationToken, Task<PersonalAccountSession>>? RefreshOverride { get; set; }

        public Task<PersonalEmailChallenge> RequestEmailAsync(string email, CancellationToken cancellationToken = default)
        {
            events.Add("request");
            return RequestOverride?.Invoke(cancellationToken) ?? Task.FromResult(Challenge());
        }

        public Task<PersonalAccountSession> SignInAsync(PersonalEmailChallenge challenge, string code,
            CancellationToken cancellationToken = default)
        {
            events.Add("sign-in");
            return Task.FromResult(SignInResult);
        }

        public Task<PersonalAccountAccess> ValidateAccessAsync(PersonalAccountSession session,
            CancellationToken cancellationToken = default)
        {
            events.Add("validate");
            return AccessFailure is null ? Task.FromResult(AccessResult) : Task.FromException<PersonalAccountAccess>(AccessFailure);
        }

        public Task<PersonalAccountSession> RefreshAsync(PersonalAccountSession session,
            CancellationToken cancellationToken = default)
        {
            events.Add("refresh");
            if (RefreshOverride is not null) return RefreshOverride(cancellationToken);
            return RefreshFailure is null ? Task.FromResult(RefreshResult) : Task.FromException<PersonalAccountSession>(RefreshFailure);
        }
    }

    private sealed class FakeStore(List<string> events) : IPersonalAccountSessionStore
    {
        public PersonalAccountSession? Stored { get; set; }
        public Exception? SaveFailure { get; init; }
        public bool SaveWritesThenThrows { get; init; }
        public int ClearFailuresRemaining { get; set; }
        public List<CancellationToken> ClearTokens { get; } = [];

        public Task<PersonalAccountSession?> LoadAsync(CancellationToken cancellationToken = default)
        {
            events.Add("load");
            return Task.FromResult(Stored);
        }

        public Task SaveAsync(PersonalAccountSession session, CancellationToken cancellationToken = default)
        {
            events.Add("save");
            if (SaveFailure is not null && SaveWritesThenThrows) Stored = session;
            if (SaveFailure is not null) return Task.FromException(SaveFailure);
            Stored = session;
            return Task.CompletedTask;
        }

        public Task ClearAsync(CancellationToken cancellationToken = default)
        {
            events.Add("clear");
            ClearTokens.Add(cancellationToken);
            if (ClearFailuresRemaining > 0)
            {
                ClearFailuresRemaining--;
                return Task.FromException(new InvalidOperationException());
            }
            Stored = null;
            return Task.CompletedTask;
        }
    }
}
