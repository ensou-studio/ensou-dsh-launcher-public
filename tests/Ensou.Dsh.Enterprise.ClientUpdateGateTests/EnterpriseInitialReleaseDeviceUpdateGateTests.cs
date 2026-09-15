using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ClientUpdateGateTests;

internal static class EnterpriseInitialReleaseDeviceUpdateGateTests
{
    // These callback fakes verify product ordering only. They do not represent
    // signed feed, filesystem, health-process, or production runtime evidence.
    private const string BindingId = "22222222-3333-4444-8555-666666666666";
    private const string PolicyId = "01234567-89ab-4cde-8fab-0123456789ab";
    private const string OtherPolicyId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    private const string NonCanonicalBindingId = "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE";
    private const string PolicySha256 =
        "1111111111111111111111111111111111111111111111111111111111111111";
    private const string OtherSha256 =
        "2222222222222222222222222222222222222222222222222222222222222222";
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-09-14T12:00:00Z");

    internal static async Task RunAsync()
    {
        await InitialReleaseOrdersStagePolicyHealthAndInnerAsync().ConfigureAwait(false);
        await PendingInitialReleaseResumesWithoutRestagingAsync().ConfigureAwait(false);
        await InvalidAuthorizationAndBindingDoNotStageAsync().ConfigureAwait(false);
        await InvalidPolicyStopsBeforeHealthAsync().ConfigureAwait(false);
        await FailedOrInexactHealthNeverReachesInnerAsync().ConfigureAwait(false);
        await CancellationNeverReachesInnerAsync().ConfigureAwait(false);
        await InstalledAndOrdinaryPendingReleasesDelegateWithoutInitialStageAsync()
            .ConfigureAwait(false);
    }

    private static async Task InitialReleaseOrdersStagePolicyHealthAndInnerAsync()
    {
        var harness = new GateHarness(InitialPointer());
        var authorized = ReadyDirectSnapshot();
        var deniedByInner = authorized with { ClientUpdateRequired = true };
        harness.Inner.Result = deniedByInner;
        var gate = harness.CreateGate();

        var result = await gate.EvaluateBeforeReadyAsync(authorized, BindingId)
            .ConfigureAwait(false);

        AssertSame(deniedByInner, result);
        AssertSame(authorized, harness.Inner.LastSnapshot);
        AssertEqual(BindingId, harness.Inner.LastBindingId);
        AssertTrue(gate.RequiresLauncherRestart);
        AssertSequence(
            harness.Calls,
            "pointer", "stage", "pointer", "policy", "health", "pointer", "policy", "inner");

        harness.Calls.Clear();
        var secondInnerResult = authorized with { RuntimeUpdateRequired = true };
        harness.Inner.Result = secondInnerResult;
        var second = await gate.EvaluateBeforeReadyAsync(authorized, BindingId)
            .ConfigureAwait(false);

        AssertSame(secondInnerResult, second);
        AssertEqual(1, harness.StageCalls);
        AssertEqual(1, harness.HealthCalls);
        AssertEqual(2, harness.Inner.Calls);
        AssertTrue(gate.RequiresLauncherRestart);
        AssertSequence(harness.Calls, "pointer", "inner");
    }

    private static async Task PendingInitialReleaseResumesWithoutRestagingAsync()
    {
        var harness = new GateHarness(PendingPointer(InitialPointer()));
        var authorized = ReadyDirectSnapshot();
        var gate = harness.CreateGate();

        var result = await gate.EvaluateBeforeReadyAsync(authorized, BindingId)
            .ConfigureAwait(false);

        AssertSame(authorized, result);
        AssertEqual(0, harness.StageCalls);
        AssertEqual(1, harness.HealthCalls);
        AssertEqual(1, harness.Inner.Calls);
        AssertTrue(gate.RequiresLauncherRestart);
        AssertSequence(
            harness.Calls,
            "pointer", "pointer", "policy", "health", "pointer", "policy", "inner");
    }

    private static async Task InvalidAuthorizationAndBindingDoNotStageAsync()
    {
        var invalidSnapshots = new[]
        {
            ReadyDirectSnapshot() with { RuntimeProfile = "enterprise-managed" },
            ReadyDirectSnapshot() with { ApiProvider = "not-deepseek" },
            ReadyDirectSnapshot() with { ControlPlane = ControlPlaneConnectivity.Unavailable },
            ReadyDirectSnapshot() with { LeaseSignatureValid = false },
            ReadyDirectSnapshot() with { AuthorizationEpochMatches = false },
            ReadyDirectSnapshot() with { ClockTrusted = false },
            ReadyDirectSnapshot() with { LeaseExpiresAtUtc = Now },
            ReadyDirectSnapshot() with { PluginPolicyId = null },
            ReadyDirectSnapshot() with { PluginPolicyGeneration = null },
            ReadyDirectSnapshot() with { PluginPolicySha256 = null },
        };

        foreach (var invalid in invalidSnapshots)
        {
            var harness = new GateHarness(InitialPointer());
            var gate = harness.CreateGate();
            await AssertThrowsAsync<InvalidDataException>(() =>
                    gate.EvaluateBeforeReadyAsync(invalid, BindingId))
                .ConfigureAwait(false);
            AssertEqual(0, harness.StageCalls);
            AssertEqual(0, harness.PolicyCalls);
            AssertEqual(0, harness.HealthCalls);
            AssertEqual(0, harness.Inner.Calls);
            AssertFalse(gate.RequiresLauncherRestart);
        }

        var noncanonical = new GateHarness(InitialPointer());
        var noncanonicalGate = noncanonical.CreateGate();
        await AssertThrowsAsync<InvalidDataException>(() =>
                noncanonicalGate.EvaluateBeforeReadyAsync(
                    ReadyDirectSnapshot(),
                    NonCanonicalBindingId))
            .ConfigureAwait(false);
        AssertEqual(0, noncanonical.PointerReads);
        AssertEqual(0, noncanonical.StageCalls);
        AssertEqual(0, noncanonical.Inner.Calls);
    }

    private static async Task InvalidPolicyStopsBeforeHealthAsync()
    {
        var invalidPolicies = new[]
        {
            MatchingPolicy() with { PolicyId = OtherPolicyId },
            MatchingPolicy() with { Generation = 2 },
            MatchingPolicy() with { PolicySha256 = OtherSha256 },
        };
        foreach (var invalidPolicy in invalidPolicies)
        {
            var harness = new GateHarness(InitialPointer())
            {
                Policy = invalidPolicy,
            };
            var gate = harness.CreateGate();

            await AssertThrowsAsync<InvalidDataException>(() =>
                    gate.EvaluateBeforeReadyAsync(ReadyDirectSnapshot(), BindingId))
                .ConfigureAwait(false);

            AssertEqual(1, harness.StageCalls);
            AssertEqual(1, harness.PolicyCalls);
            AssertEqual(0, harness.HealthCalls);
            AssertEqual(0, harness.Inner.Calls);
            AssertTrue(gate.RequiresLauncherRestart);
            AssertSequence(harness.Calls, "pointer", "stage", "pointer", "policy");
        }
    }

    private static async Task FailedOrInexactHealthNeverReachesInnerAsync()
    {
        await AssertHealthRefusalAsync(static (_, _) => Task.CompletedTask)
            .ConfigureAwait(false);

        await AssertHealthRefusalAsync((harness, _) =>
        {
            var wrongRelease = HealthyPointer(harness.Pointer);
            harness.Pointer = wrongRelease with
            {
                Current = wrongRelease.Current with
                {
                    ReleaseSetId = "signed-initial-other",
                },
            };
            return Task.CompletedTask;
        }).ConfigureAwait(false);

        await AssertHealthRefusalAsync((harness, _) =>
        {
            harness.Pointer = InitialPointer();
            return Task.CompletedTask;
        }).ConfigureAwait(false);

        var failed = new GateHarness(InitialPointer())
        {
            HealthBehavior = static (_, _) =>
                Task.FromException(new IOException("synthetic health failure")),
        };
        var failedGate = failed.CreateGate();
        await AssertThrowsAsync<IOException>(() =>
                failedGate.EvaluateBeforeReadyAsync(ReadyDirectSnapshot(), BindingId))
            .ConfigureAwait(false);
        AssertEqual(1, failed.HealthCalls);
        AssertEqual(0, failed.Inner.Calls);
        AssertTrue(failedGate.RequiresLauncherRestart);
    }

    private static async Task AssertHealthRefusalAsync(
        Func<GateHarness, CancellationToken, Task> healthBehavior)
    {
        var harness = new GateHarness(InitialPointer())
        {
            HealthBehavior = healthBehavior,
        };
        var gate = harness.CreateGate();

        await AssertThrowsAsync<InvalidDataException>(() =>
                gate.EvaluateBeforeReadyAsync(ReadyDirectSnapshot(), BindingId))
            .ConfigureAwait(false);

        AssertEqual(1, harness.StageCalls);
        AssertEqual(1, harness.HealthCalls);
        AssertEqual(0, harness.Inner.Calls);
        AssertTrue(gate.RequiresLauncherRestart);
    }

    private static async Task CancellationNeverReachesInnerAsync()
    {
        using (var beforeCancellation = new CancellationTokenSource())
        {
            beforeCancellation.Cancel();
            var before = new GateHarness(InitialPointer());
            await AssertThrowsAsync<OperationCanceledException>(() =>
                    before.CreateGate().EvaluateBeforeReadyAsync(
                        ReadyDirectSnapshot(), BindingId, beforeCancellation.Token))
                .ConfigureAwait(false);
            AssertEqual(0, before.PointerReads);
            AssertEqual(0, before.StageCalls);
            AssertEqual(0, before.Inner.Calls);
        }

        using (var duringStageCancellation = new CancellationTokenSource())
        {
            var duringStage = new GateHarness(InitialPointer())
            {
                StageBehavior = (harness, _) =>
                {
                    harness.Pointer = PendingPointer(harness.Pointer);
                    duringStageCancellation.Cancel();
                    return Task.CompletedTask;
                },
            };
            var gate = duringStage.CreateGate();
            await AssertThrowsAsync<OperationCanceledException>(() =>
                    gate.EvaluateBeforeReadyAsync(
                        ReadyDirectSnapshot(), BindingId, duringStageCancellation.Token))
                .ConfigureAwait(false);
            AssertEqual(1, duringStage.StageCalls);
            AssertEqual(0, duringStage.PolicyCalls);
            AssertEqual(0, duringStage.HealthCalls);
            AssertEqual(0, duringStage.Inner.Calls);
            AssertTrue(gate.RequiresLauncherRestart);
        }

        using var duringHealthCancellation = new CancellationTokenSource();
        var duringHealth = new GateHarness(InitialPointer())
        {
            HealthBehavior = (harness, _) =>
            {
                harness.Pointer = HealthyPointer(harness.Pointer);
                duringHealthCancellation.Cancel();
                return Task.FromException(
                    new OperationCanceledException(duringHealthCancellation.Token));
            },
        };
        var healthGate = duringHealth.CreateGate();
        await AssertThrowsAsync<OperationCanceledException>(() =>
                healthGate.EvaluateBeforeReadyAsync(
                    ReadyDirectSnapshot(), BindingId, duringHealthCancellation.Token))
            .ConfigureAwait(false);
        AssertEqual(1, duringHealth.HealthCalls);
        AssertEqual(0, duringHealth.Inner.Calls);
        AssertTrue(healthGate.RequiresLauncherRestart);

        duringHealth.Calls.Clear();
        var retried = await healthGate.EvaluateBeforeReadyAsync(
                ReadyDirectSnapshot(), BindingId)
            .ConfigureAwait(false);
        AssertSame(duringHealth.Inner.LastSnapshot, retried);
        AssertEqual(1, duringHealth.StageCalls);
        AssertEqual(1, duringHealth.HealthCalls);
        AssertEqual(1, duringHealth.Inner.Calls);
        AssertTrue(healthGate.RequiresLauncherRestart);
        AssertSequence(duringHealth.Calls, "pointer", "inner");
    }

    private static async Task InstalledAndOrdinaryPendingReleasesDelegateWithoutInitialStageAsync()
    {
        var initial = InitialPointer();
        var installed = HealthyPointer(PendingPointer(initial));
        var ordinaryPending = PendingPointer(installed, generation: 2, sequence: 2);

        foreach (var pointer in new[] { installed, ordinaryPending })
        {
            var harness = new GateHarness(pointer);
            var authorized = ReadyDirectSnapshot();
            var innerResult = authorized with { CriticalPluginUpdateRequired = true };
            harness.Inner.Result = innerResult;
            var gate = harness.CreateGate();

            var result = await gate.EvaluateBeforeReadyAsync(authorized, BindingId)
                .ConfigureAwait(false);

            AssertSame(innerResult, result);
            AssertEqual(0, harness.StageCalls);
            AssertEqual(0, harness.PolicyCalls);
            AssertEqual(0, harness.HealthCalls);
            AssertEqual(1, harness.Inner.Calls);
            AssertFalse(gate.RequiresLauncherRestart);
            AssertSequence(harness.Calls, "pointer", "inner");
        }
    }

    private static EnterpriseReleaseSetPointer InitialPointer()
    {
        var current = new EnterpriseReleaseSetReference(
            "installer-bootstrap",
            0,
            0,
            0,
            StartupStub(),
            Component("launcher-bootstrap"),
            Component("runtime-bootstrap"),
            null,
            EnterpriseReleaseHealthStates.Healthy,
            null,
            Now.AddMinutes(-10));
        return new EnterpriseReleaseSetPointer(
            EnterpriseReleaseSetContract.SchemaVersion,
            EnterpriseReleaseSetContract.Product,
            EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
            current,
            null,
            Now.AddMinutes(-10));
    }

    private static EnterpriseReleaseSetPointer PendingPointer(
        EnterpriseReleaseSetPointer before,
        long generation = 1,
        long sequence = 1)
    {
        var current = new EnterpriseReleaseSetReference(
            $"signed-initial-{generation}",
            generation,
            sequence,
            0,
            StartupStub(),
            Component($"launcher-{generation}"),
            Component($"runtime-{generation}"),
            Component($"plugin-{generation}"),
            EnterpriseReleaseHealthStates.Pending,
            $"health-token-{generation}",
            Now.AddMinutes(-1));
        return before with
        {
            Current = current,
            Previous = before.Current,
            UpdatedAtUtc = Now.AddMinutes(-1),
        };
    }

    private static EnterpriseReleaseSetPointer HealthyPointer(
        EnterpriseReleaseSetPointer pending) => pending with
    {
        Current = pending.Current with
        {
            HealthState = EnterpriseReleaseHealthStates.Healthy,
            HealthToken = null,
        },
        UpdatedAtUtc = Now,
    };

    private static EnterpriseStartupStubCompatibility StartupStub() => new()
    {
        MinimumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
        MaximumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
    };

    private static EnterpriseReleaseComponentPointer Component(string releaseId) => new(
        releaseId,
        $@"C:\fixture\{releaseId}",
        PolicySha256,
        OtherSha256);

    private static EnterpriseActivePluginPolicy MatchingPolicy() => new(
        "plugin-1",
        PolicyId,
        1,
        false,
        @"C:\fixture\plugin-1",
        @"C:\fixture\plugin-1\skills",
        PolicySha256,
        OtherSha256);

    private static EnterpriseAccessSnapshot ReadyDirectSnapshot() => new()
    {
        Employee = EmployeeAuthorizationState.Active,
        Device = DeviceBindingState.Active,
        ApiAllocation = ApiAllocationState.Active,
        ControlPlane = ControlPlaneConnectivity.Available,
        LeaseSignatureValid = true,
        AuthorizationEpochMatches = true,
        ClockTrusted = true,
        TrustedTimeFloorUtc = Now.AddMinutes(-2),
        LeaseIssuedAtUtc = Now.AddMinutes(-1),
        LeaseExpiresAtUtc = Now.AddMinutes(5),
        PluginPolicyId = PolicyId,
        PluginPolicyGeneration = 1,
        PluginPolicySha256 = PolicySha256,
        RuntimeProfile = "enterprise-direct-local",
        ApiProvider = "deepseek",
    };

    private static async Task AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertSequence(IReadOnlyList<string> actual, params string[] expected)
    {
        if (!actual.SequenceEqual(expected, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                $"Expected calls '{string.Join(",", expected)}', actual '{string.Join(",", actual)}'.");
        }
    }

    private static void AssertSame(object? expected, object? actual)
    {
        if (!ReferenceEquals(expected, actual))
        {
            throw new InvalidOperationException("Expected the exact same object reference.");
        }
    }

    private static void AssertTrue(bool value)
    {
        if (!value) throw new InvalidOperationException("Expected true.");
    }

    private static void AssertFalse(bool value)
    {
        if (value) throw new InvalidOperationException("Expected false.");
    }

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', actual '{actual}'.");
        }
    }

    private sealed class GateHarness
    {
        internal GateHarness(EnterpriseReleaseSetPointer pointer)
        {
            Pointer = pointer;
        }

        internal EnterpriseReleaseSetPointer Pointer { get; set; }
        internal EnterpriseActivePluginPolicy Policy { get; init; } = MatchingPolicy();
        internal FakeGate Inner { get; } = new();
        internal List<string> Calls { get; } = [];
        internal int PointerReads { get; private set; }
        internal int StageCalls { get; private set; }
        internal int PolicyCalls { get; private set; }
        internal int HealthCalls { get; private set; }
        internal Func<GateHarness, CancellationToken, Task>? StageBehavior { get; init; }
        internal Func<GateHarness, CancellationToken, Task>? HealthBehavior { get; init; }

        internal EnterpriseInitialReleaseDeviceUpdateGate CreateGate()
        {
            Inner.Observe = () => Calls.Add("inner");
            return new EnterpriseInitialReleaseDeviceUpdateGate(
                Inner,
                ReadPointer,
                StageAsync,
                ReadPolicy,
                CompleteHealthAsync,
                new FixedTimeProvider(Now));
        }

        private EnterpriseReleaseSetPointer ReadPointer()
        {
            PointerReads++;
            Calls.Add("pointer");
            return Pointer;
        }

        private async Task StageAsync(CancellationToken cancellationToken)
        {
            StageCalls++;
            Calls.Add("stage");
            if (StageBehavior is not null)
            {
                await StageBehavior(this, cancellationToken).ConfigureAwait(false);
                return;
            }
            cancellationToken.ThrowIfCancellationRequested();
            Pointer = PendingPointer(Pointer);
        }

        private EnterpriseActivePluginPolicy ReadPolicy(EnterpriseReleaseSetPointer pointer)
        {
            AssertSame(Pointer, pointer);
            PolicyCalls++;
            Calls.Add("policy");
            return Policy;
        }

        private async Task CompleteHealthAsync(CancellationToken cancellationToken)
        {
            HealthCalls++;
            Calls.Add("health");
            if (HealthBehavior is not null)
            {
                await HealthBehavior(this, cancellationToken).ConfigureAwait(false);
                return;
            }
            cancellationToken.ThrowIfCancellationRequested();
            Pointer = HealthyPointer(Pointer);
        }
    }

    private sealed class FakeGate : IEnterpriseDeviceUpdateGate
    {
        internal int Calls { get; private set; }
        internal EnterpriseAccessSnapshot? Result { get; set; }
        internal EnterpriseAccessSnapshot? LastSnapshot { get; private set; }
        internal string? LastBindingId { get; private set; }
        internal Action? Observe { get; set; }

        public Task<EnterpriseAccessSnapshot> EvaluateBeforeReadyAsync(
            EnterpriseAccessSnapshot authorizedSnapshot,
            string bindingId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            LastSnapshot = authorizedSnapshot;
            LastBindingId = bindingId;
            Observe?.Invoke();
            return Task.FromResult(Result ?? authorizedSnapshot);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset nowUtc) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => nowUtc;
    }
}
