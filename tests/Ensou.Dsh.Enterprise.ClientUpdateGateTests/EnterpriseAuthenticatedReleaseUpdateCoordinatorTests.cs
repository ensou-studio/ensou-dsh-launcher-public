using System.Net;
using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ClientUpdateGateTests;

internal static class EnterpriseAuthenticatedReleaseUpdateCoordinatorTests
{
    public static async Task MappingAsync()
    {
        await AssertSafeDowngradeAsync(
            ReadySnapshot(),
            new EnterpriseUpdateFeedAuthorizationDeniedException(
                HttpStatusCode.Forbidden,
                tokenCleared: false),
            EnterpriseAuthenticatedReleaseUpdateDisposition.ContinueVerifiedStable,
            EnterpriseAuthenticatedReleaseUpdateFailureKind.Forbidden);
        await AssertSafeDowngradeAsync(
            UpdateRequiredSnapshot(),
            new EnterpriseUpdateFeedAuthorizationDeniedException(
                HttpStatusCode.Forbidden,
                tokenCleared: false),
            EnterpriseAuthenticatedReleaseUpdateDisposition.UpdateRemainsLocked,
            EnterpriseAuthenticatedReleaseUpdateFailureKind.Forbidden);
        await AssertSafeDowngradeAsync(
            ReadySnapshot(),
            new EnterpriseUpdateFeedUnavailableException(HttpStatusCode.ServiceUnavailable),
            EnterpriseAuthenticatedReleaseUpdateDisposition.ContinueVerifiedStable,
            EnterpriseAuthenticatedReleaseUpdateFailureKind.FeedUnavailable);
        await AssertSafeDowngradeAsync(
            UpdateRequiredSnapshot(),
            new EnterpriseUpdateFeedProtocolException("invalid private response"),
            EnterpriseAuthenticatedReleaseUpdateDisposition.UpdateRemainsLocked,
            EnterpriseAuthenticatedReleaseUpdateFailureKind.Protocol);
    }

    public static async Task FactoryCountAsync()
    {
        await using var session = CreateSession(ReadySnapshot());
        var factoryCalls = 0;
        var checkCalls = 0;
        var restartCalls = 0;
        var shutdownCalls = 0;
        var handlers = new List<DisposalTrackingHandler>();
        var coordinator = new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            session,
            () =>
            {
                factoryCalls++;
                var handler = new DisposalTrackingHandler();
                handlers.Add(handler);
                return new HttpClient(handler);
            },
            (client, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                checkCalls++;
                return Task.FromResult(Outcome(requiresBootstrapHealthCheck: false));
            },
            () => { restartCalls++; return Task.CompletedTask; },
            () => shutdownCalls++);

        var skipped = await coordinator.CheckAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: false,
            session.CurrentDecision);
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.NotEligible,
            skipped.Disposition);
        AssertEqual(0, factoryCalls);

        var first = await coordinator.CheckAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: true,
            session.CurrentDecision);
        var second = await coordinator.CheckAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: true,
            session.CurrentDecision);

        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.Completed,
            first.Disposition);
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.Completed,
            second.Disposition);
        AssertEqual(2, factoryCalls);
        AssertEqual(2, checkCalls);
        AssertEqual(2, handlers.Count);
        AssertTrue(handlers.All(handler => handler.Disposed));
        AssertEqual(0, restartCalls);
        AssertEqual(0, shutdownCalls);

        await using var restartSession = CreateSession(ReadySnapshot());
        var callbackOrder = new List<string>();
        var restartHandler = new DisposalTrackingHandler();
        var restartCoordinator = new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            restartSession,
            () => new HttpClient(restartHandler),
            (_, _) => Task.FromResult(Outcome(requiresBootstrapHealthCheck: true)),
            () => { callbackOrder.Add("restart-through-stable-bootstrapper"); return Task.CompletedTask; },
            () => callbackOrder.Add("shutdown"));
        var restarting = await restartCoordinator.CheckAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: true,
            restartSession.CurrentDecision);
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.Restarting,
            restarting.Disposition);
        AssertEqual(2, callbackOrder.Count);
        AssertEqual("restart-through-stable-bootstrapper", callbackOrder[0]);
        AssertEqual("shutdown", callbackOrder[1]);
        AssertTrue(restartHandler.Disposed);

        await using var gatedSession = CreateSession(ReadySnapshot());
        var callbackGate = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var gatedShutdownCalls = 0;
        var gatedCoordinator = new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            gatedSession,
            () => new HttpClient(new DisposalTrackingHandler()),
            (_, _) => Task.FromResult(Outcome(requiresBootstrapHealthCheck: true)),
            async () => await callbackGate.Task.ConfigureAwait(false),
            () => gatedShutdownCalls++);
        var gatedRun = gatedCoordinator.CheckAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: true,
            gatedSession.CurrentDecision);
        await Task.Delay(25);
        AssertEqual(0, gatedShutdownCalls);
        callbackGate.SetResult(null);
        var gatedResult = await gatedRun;
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.Restarting,
            gatedResult.Disposition);
        AssertEqual(1, gatedShutdownCalls);

        await using var failedSession = CreateSession(ReadySnapshot());
        var failedShutdownCalls = 0;
        var failedCoordinator = new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            failedSession,
            () => new HttpClient(new DisposalTrackingHandler()),
            (_, _) => Task.FromResult(Outcome(requiresBootstrapHealthCheck: true)),
            async () => throw new InvalidOperationException("async restart failed"),
            () => failedShutdownCalls++);
        await AssertThrowsAsync<InvalidOperationException>(() =>
            failedCoordinator.CheckAfterFreshAuthorizationAsync(
                freshAuthorizationCompleted: true,
                failedSession.CurrentDecision));
        AssertEqual(0, failedShutdownCalls);
    }

    public static async Task SessionLockAsync()
    {
        var initial = ReadySnapshot();
        await using var session = CreateSession(initial);
        var disposalHandler = new DisposalTrackingHandler();
        var coordinator = new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            session,
            () => new HttpClient(disposalHandler),
            (_, _) => Task.FromException<EnterpriseReleaseUpdateOutcome>(
                new EnterpriseUpdateFeedAuthorizationDeniedException(
                    HttpStatusCode.Unauthorized,
                    tokenCleared: true)),
            async () => throw new InvalidOperationException("Restart was not expected."),
            () => throw new InvalidOperationException("Shutdown was not expected."));

        var result = await coordinator.CheckAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: true,
            session.CurrentDecision);

        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.SessionLocked,
            result.Disposition);
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateFailureKind.Unauthorized,
            result.FailureKind);
        AssertTrue(disposalHandler.Disposed);
        AssertEqual(
            ControlPlaneConnectivity.Unknown,
            session.CurrentAccessSnapshot.ControlPlane);
        AssertEqual(initial.Employee, session.CurrentAccessSnapshot.Employee);
        AssertEqual(initial.Device, session.CurrentAccessSnapshot.Device);
        AssertEqual(initial.ApiAllocation, session.CurrentAccessSnapshot.ApiAllocation);
        AssertFalse(session.CurrentDecision.MayStartHarness);
        AssertFalse(session.CurrentDecision.MayCallManagedApi);
        await AssertThrowsAsync<EnterpriseAccessDeniedException>(
            () => session.EnsureStartedAsync());
        await AssertThrowsAsync<EnterpriseAccessDeniedException>(async () =>
        {
            _ = await session.EnsureManagedApiAllowedAsync();
        });

        await using var missingTokenSession = CreateSession(ReadySnapshot());
        var missingTokenCoordinator =
            new EnterpriseAuthenticatedReleaseUpdateCoordinator(
                missingTokenSession,
                () => new HttpClient(new DisposalTrackingHandler()),
                (_, _) => Task.FromException<EnterpriseReleaseUpdateOutcome>(
                    new EnterpriseAccessTokenUnavailableException()),
                async () => throw new InvalidOperationException("Restart was not expected."),
                () => throw new InvalidOperationException("Shutdown was not expected."));
        var missingTokenResult = await missingTokenCoordinator
            .CheckAfterFreshAuthorizationAsync(
                freshAuthorizationCompleted: true,
                missingTokenSession.CurrentDecision);
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.SessionLocked,
            missingTokenResult.Disposition);
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateFailureKind.AccessTokenUnavailable,
            missingTokenResult.FailureKind);
        AssertEqual(
            ControlPlaneConnectivity.Unknown,
            missingTokenSession.CurrentAccessSnapshot.ControlPlane);
        AssertFalse(missingTokenSession.CurrentDecision.MayStartHarness);
        AssertFalse(missingTokenSession.CurrentDecision.MayCallManagedApi);
    }

    public static async Task PreflightAsync()
    {
        await using var session = CreateSession(ReadySnapshot());
        var factoryCalls = 0;
        var stageCalls = 0;
        var probeCalls = 0;
        var coordinator = new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            session,
            () =>
            {
                factoryCalls++;
                return new HttpClient(new DisposalTrackingHandler());
            },
            (_, _) =>
            {
                stageCalls++;
                return Task.FromResult(Outcome(requiresBootstrapHealthCheck: false));
            },
            async () => throw new InvalidOperationException("Restart was not expected."),
            () => throw new InvalidOperationException("Shutdown was not expected."),
            (_, _) =>
            {
                probeCalls++;
                return Task.FromResult(EnterpriseReleaseUpdatePreflight.RequiresStage());
            });

        var skipped = await coordinator.ProbeAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: false,
            session.CurrentDecision);
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.NotEligible,
            skipped.Disposition);
        AssertEqual(0, factoryCalls);

        var changed = await coordinator.ProbeAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: true,
            session.CurrentDecision);
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.RequiresExclusiveStage,
            changed.Disposition);
        AssertEqual(1, factoryCalls);
        AssertEqual(1, probeCalls);
        AssertEqual(0, stageCalls);
        AssertTrue(await coordinator.IsStillAdmittedAsync(
            freshAuthorizationCompleted: true,
            session.CurrentDecision));

        await using var noUpdateSession = CreateSession(ReadySnapshot());
        var noUpdateStageCalls = 0;
        var noUpdateCoordinator = new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            noUpdateSession,
            () => new HttpClient(new DisposalTrackingHandler()),
            (_, _) =>
            {
                noUpdateStageCalls++;
                return Task.FromResult(Outcome(requiresBootstrapHealthCheck: false));
            },
            async () => throw new InvalidOperationException("Restart was not expected."),
            () => throw new InvalidOperationException("Shutdown was not expected."),
            (_, _) => Task.FromResult(EnterpriseReleaseUpdatePreflight.Terminal(
                Outcome(requiresBootstrapHealthCheck: false))));
        var noUpdate = await noUpdateCoordinator.ProbeAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: true,
            noUpdateSession.CurrentDecision);
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.Completed,
            noUpdate.Disposition);
        AssertEqual(0, noUpdateStageCalls);

        await using var deniedSession = CreateSession(ReadySnapshot());
        var deniedStageCalls = 0;
        var deniedCoordinator = new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            deniedSession,
            () => new HttpClient(new DisposalTrackingHandler()),
            (_, _) =>
            {
                deniedStageCalls++;
                return Task.FromResult(Outcome(requiresBootstrapHealthCheck: false));
            },
            async () => throw new InvalidOperationException("Restart was not expected."),
            () => throw new InvalidOperationException("Shutdown was not expected."),
            (_, _) => Task.FromException<EnterpriseReleaseUpdatePreflight>(
                new EnterpriseUpdateFeedAuthorizationDeniedException(
                    HttpStatusCode.Unauthorized,
                    tokenCleared: true)));
        var denied = await deniedCoordinator.ProbeAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: true,
            deniedSession.CurrentDecision);
        AssertEqual(
            EnterpriseAuthenticatedReleaseUpdateDisposition.SessionLocked,
            denied.Disposition);
        AssertEqual(0, deniedStageCalls);
        AssertFalse(await deniedCoordinator.IsStillAdmittedAsync(
            freshAuthorizationCompleted: true,
            deniedSession.CurrentDecision));
    }

    public static async Task AutomaticPipelineAsync()
    {
        await using (var session = CreateSession(ReadySnapshot()))
        {
            var drains = 0;
            var stages = 0;
            var restores = 0;
            var updates = CreateAutomaticTestUpdates(
                session,
                () => Task.FromResult(EnterpriseReleaseUpdatePreflight.Terminal(
                    Outcome(requiresBootstrapHealthCheck: false))),
                () =>
                {
                    stages++;
                    return Task.FromResult(Outcome(requiresBootstrapHealthCheck: false));
                });
            var automatic = new EnterpriseAutomaticReleaseUpdateCoordinator(
                updates,
                (_, _) =>
                {
                    drains++;
                    return Task.FromResult(
                        EnterpriseManagedRuntimeDrainDisposition.StoppedExactRuntime);
                },
                () => throw new InvalidOperationException("Loopback guard was not expected."),
                _ =>
                {
                    restores++;
                    return Task.CompletedTask;
                });

            var result = await automatic.RunAsync(true, session.CurrentDecision);
            AssertEqual(EnterpriseAuthenticatedReleaseUpdateDisposition.Completed, result.Disposition);
            AssertEqual(0, drains);
            AssertEqual(0, stages);
            AssertEqual(0, restores);
        }

        await using (var session = CreateSession(ReadySnapshot()))
        {
            var drains = 0;
            var stages = 0;
            var updates = CreateAutomaticTestUpdates(
                session,
                async () =>
                {
                    await session.ApplyAccessAsync(
                        session.CurrentAccessSnapshot with
                        {
                            Employee = EmployeeAuthorizationState.Revoked,
                        });
                    return EnterpriseReleaseUpdatePreflight.RequiresStage();
                },
                () =>
                {
                    stages++;
                    return Task.FromResult(Outcome(requiresBootstrapHealthCheck: false));
                });
            var automatic = new EnterpriseAutomaticReleaseUpdateCoordinator(
                updates,
                (_, _) =>
                {
                    drains++;
                    return Task.FromResult(
                        EnterpriseManagedRuntimeDrainDisposition.StoppedExactRuntime);
                },
                () => throw new InvalidOperationException("Loopback guard was not expected."),
                _ => Task.CompletedTask);

            var result = await automatic.RunAsync(true, session.CurrentDecision);
            AssertEqual(EnterpriseAuthenticatedReleaseUpdateDisposition.NotEligible, result.Disposition);
            AssertEqual(0, drains);
            AssertEqual(0, stages);
        }

        await using (var session = CreateSession(ReadySnapshot()))
        {
            var stages = 0;
            var restores = 0;
            var updates = CreateAutomaticTestUpdates(
                session,
                () => Task.FromResult(EnterpriseReleaseUpdatePreflight.RequiresStage()),
                () =>
                {
                    stages++;
                    return Task.FromResult(Outcome(requiresBootstrapHealthCheck: false));
                });
            var automatic = new EnterpriseAutomaticReleaseUpdateCoordinator(
                updates,
                (_, _) => Task.FromException<EnterpriseManagedRuntimeDrainDisposition>(
                    new InvalidOperationException("drain failed")),
                () => throw new InvalidOperationException("Loopback guard was not expected."),
                _ =>
                {
                    restores++;
                    return Task.CompletedTask;
                });

            await AssertThrowsAsync<InvalidOperationException>(() =>
                automatic.RunAsync(true, session.CurrentDecision));
            AssertEqual(0, stages);
            AssertEqual(0, restores);
        }

        await using (var session = CreateSession(ReadySnapshot()))
        {
            var stages = 0;
            var restores = 0;
            var operationId = Guid.NewGuid();
            var updates = CreateAutomaticTestUpdates(
                session,
                () => Task.FromResult(EnterpriseReleaseUpdatePreflight.RequiresStage()),
                () =>
                {
                    stages++;
                    return Task.FromResult(Outcome(requiresBootstrapHealthCheck: false));
                });
            var automatic = new EnterpriseAutomaticReleaseUpdateCoordinator(
                updates,
                (_, _) => Task.FromException<EnterpriseManagedRuntimeDrainDisposition>(
                    new EnterpriseManagedRuntimeStoppedException(
                        operationId,
                        new InvalidOperationException("post-exit drain failure"))),
                () => throw new InvalidOperationException("Loopback guard was not expected."),
                _ =>
                {
                    restores++;
                    return Task.CompletedTask;
                });

            var failure = await AssertThrowsAndReturnAsync<
                EnterpriseManagedRuntimeStoppedException>(() =>
                automatic.RunAsync(true, session.CurrentDecision));
            AssertEqual(operationId, failure.OperationId);
            AssertEqual(0, stages);
            AssertEqual(1, restores);
        }

        await using (var session = CreateSession(ReadySnapshot()))
        {
            var restores = 0;
            var updates = CreateAutomaticTestUpdates(
                session,
                () => Task.FromResult(EnterpriseReleaseUpdatePreflight.RequiresStage()),
                () => Task.FromException<EnterpriseReleaseUpdateOutcome>(
                    new InvalidOperationException("stage failed")));
            var automatic = new EnterpriseAutomaticReleaseUpdateCoordinator(
                updates,
                (_, _) => Task.FromResult(
                    EnterpriseManagedRuntimeDrainDisposition.NoRuntimeToStop),
                static () => { },
                _ =>
                {
                    restores++;
                    return Task.CompletedTask;
                });

            await AssertThrowsAsync<InvalidOperationException>(() =>
                automatic.RunAsync(true, session.CurrentDecision));
            AssertEqual(0, restores);
        }

        await using (var session = CreateSession(ReadySnapshot()))
        {
            var restores = 0;
            var updates = CreateAutomaticTestUpdates(
                session,
                () => Task.FromResult(EnterpriseReleaseUpdatePreflight.RequiresStage()),
                () => Task.FromException<EnterpriseReleaseUpdateOutcome>(
                    new InvalidOperationException("stage failed")));
            var automatic = new EnterpriseAutomaticReleaseUpdateCoordinator(
                updates,
                (_, _) => Task.FromResult(
                    EnterpriseManagedRuntimeDrainDisposition.StoppedExactRuntime),
                static () => { },
                _ =>
                {
                    restores++;
                    return Task.CompletedTask;
                });

            await AssertThrowsAsync<InvalidOperationException>(() =>
                automatic.RunAsync(true, session.CurrentDecision));
            AssertEqual(1, restores);
        }

        await using (var session = CreateSession(ReadySnapshot()))
        {
            var restores = 0;
            var restarts = 0;
            var shutdowns = 0;
            var updates = CreateAutomaticTestUpdates(
                session,
                () => Task.FromResult(EnterpriseReleaseUpdatePreflight.RequiresStage()),
                () => Task.FromResult(Outcome(requiresBootstrapHealthCheck: true)),
                () => { restarts++; return Task.CompletedTask; },
                () => shutdowns++);
            var automatic = new EnterpriseAutomaticReleaseUpdateCoordinator(
                updates,
                (_, _) => Task.FromResult(
                    EnterpriseManagedRuntimeDrainDisposition.StoppedExactRuntime),
                static () => { },
                _ =>
                {
                    restores++;
                    return Task.CompletedTask;
                });

            var result = await automatic.RunAsync(true, session.CurrentDecision);
            AssertEqual(EnterpriseAuthenticatedReleaseUpdateDisposition.Restarting, result.Disposition);
            AssertEqual(1, restarts);
            AssertEqual(1, shutdowns);
            AssertEqual(0, restores);
        }

        var host = new FakeHarnessHost();
        await using (var session = new EnterpriseHarnessSession(
                         new EnterpriseStartupGate(TimeProvider.System),
                         host,
                         ReadySnapshot()))
        {
            var stages = 0;
            var updates = CreateAutomaticTestUpdates(
                session,
                () => Task.FromResult(EnterpriseReleaseUpdatePreflight.RequiresStage()),
                () =>
                {
                    stages++;
                    return Task.FromResult(Outcome(requiresBootstrapHealthCheck: false));
                });
            var automatic = new EnterpriseAutomaticReleaseUpdateCoordinator(
                updates,
                async (_, _) =>
                {
                    await session.ApplyAccessAsync(
                        session.CurrentAccessSnapshot with
                        {
                            Employee = EmployeeAuthorizationState.Revoked,
                        });
                    return EnterpriseManagedRuntimeDrainDisposition.StoppedExactRuntime;
                },
                static () => { },
                async cancellationToken =>
                {
                    _ = await session.EnsureStartedAsync(cancellationToken);
                });

            await AssertThrowsAsync<EnterpriseAccessDeniedException>(() =>
                automatic.RunAsync(true, session.CurrentDecision));
            AssertEqual(0, stages);
            AssertEqual(0, host.EnsureStartedCalls);
        }
    }

    private static EnterpriseAuthenticatedReleaseUpdateCoordinator
        CreateAutomaticTestUpdates(
            EnterpriseHarnessSession session,
            Func<Task<EnterpriseReleaseUpdatePreflight>> probe,
            Func<Task<EnterpriseReleaseUpdateOutcome>> stage,
            Func<Task>? restart = null,
            Action? shutdown = null) =>
        new(
            session,
            () => new HttpClient(new DisposalTrackingHandler()),
            (_, _) => stage(),
            restart ?? (() => Task.CompletedTask),
            shutdown ?? (() => { }),
            (_, _) => probe());

    private static async Task AssertSafeDowngradeAsync(
        EnterpriseAccessSnapshot snapshot,
        Exception exception,
        EnterpriseAuthenticatedReleaseUpdateDisposition expectedDisposition,
        EnterpriseAuthenticatedReleaseUpdateFailureKind expectedFailure)
    {
        await using var session = CreateSession(snapshot);
        var factoryCalls = 0;
        var coordinator = new EnterpriseAuthenticatedReleaseUpdateCoordinator(
            session,
            () =>
            {
                factoryCalls++;
                return new HttpClient(new DisposalTrackingHandler());
            },
            (_, _) => Task.FromException<EnterpriseReleaseUpdateOutcome>(exception),
            async () => throw new InvalidOperationException("Restart was not expected."),
            () => throw new InvalidOperationException("Shutdown was not expected."));

        var result = await coordinator.CheckAfterFreshAuthorizationAsync(
            freshAuthorizationCompleted: true,
            session.CurrentDecision);

        AssertEqual(expectedDisposition, result.Disposition);
        AssertEqual(expectedFailure, result.FailureKind);
        AssertEqual(1, factoryCalls);
        AssertEqual(snapshot.ControlPlane, session.CurrentAccessSnapshot.ControlPlane);
        AssertEqual(
            snapshot.ClientUpdateRequired,
            session.CurrentAccessSnapshot.ClientUpdateRequired);
        if (expectedDisposition
            == EnterpriseAuthenticatedReleaseUpdateDisposition.ContinueVerifiedStable)
        {
            AssertTrue(session.CurrentDecision.MayStartHarness);
            AssertTrue(session.CurrentDecision.MayCallManagedApi);
        }
        else
        {
            AssertFalse(session.CurrentDecision.MayStartHarness);
            AssertFalse(session.CurrentDecision.MayCallManagedApi);
        }
    }

    private static EnterpriseHarnessSession CreateSession(
        EnterpriseAccessSnapshot snapshot) => new(
        new EnterpriseStartupGate(TimeProvider.System),
        new FakeHarnessHost(),
        snapshot);

    private static EnterpriseAccessSnapshot ReadySnapshot()
    {
        var now = DateTimeOffset.UtcNow;
        return new EnterpriseAccessSnapshot
        {
            Employee = EmployeeAuthorizationState.Active,
            Device = DeviceBindingState.Active,
            ApiAllocation = ApiAllocationState.Active,
            ControlPlane = ControlPlaneConnectivity.Available,
            LeaseSignatureValid = true,
            AuthorizationEpochMatches = true,
            ClockTrusted = true,
            TrustedTimeFloorUtc = now.AddMinutes(-10),
            LeaseIssuedAtUtc = now.AddMinutes(-5),
            LeaseExpiresAtUtc = now.AddMinutes(30),
            PluginPolicyId = "01234567-89ab-4cde-8fab-0123456789ab",
            PluginPolicyGeneration = 1,
            PluginPolicySha256 =
                "1111111111111111111111111111111111111111111111111111111111111111",
        };
    }

    private static EnterpriseAccessSnapshot UpdateRequiredSnapshot() =>
        ReadySnapshot() with { ClientUpdateRequired = true };

    private static EnterpriseReleaseUpdateOutcome Outcome(
        bool requiresBootstrapHealthCheck) => new(
        "up-to-date",
        "Enterprise components are current.",
        ActivePointer: null!,
        requiresBootstrapHealthCheck);

    private static async Task AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static async Task<TException> AssertThrowsAndReturnAsync<TException>(
        Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertTrue(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void AssertFalse(bool condition) => AssertTrue(!condition);

    private static void AssertEqual<T>(T expected, T actual)
        where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException(
                $"Expected '{expected}', actual '{actual}'.");
        }
    }

    private sealed class DisposalTrackingHandler : HttpMessageHandler
    {
        public bool Disposed { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No HTTP request was expected.");

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class FakeHarnessHost : IEnterpriseHarnessHost
    {
        public Uri WebUiUri { get; } = new("http://127.0.0.1:3080/");

        public int EnsureStartedCalls { get; private set; }

        public Task EnsureStartedAsync(CancellationToken cancellationToken = default)
        {
            EnsureStartedCalls++;
            return Task.CompletedTask;
        }

        public Task OpenWebUiAsync(CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task StopOwnedProcessAsync(CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
