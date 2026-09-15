using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Launcher;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class PersonalDevelopmentLiveUpdateArgumentsTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases { get; } =
    [
        ("personal live-update arguments require one exact-cased pair", ExactPairAsync),
        ("personal live-update arguments require compiled development and isolated layout", DevelopmentAdmissionAsync),
        ("personal live-update configuration requires a bounded ordinary pinned file", FileAdmissionAsync),
        ("personal live-update configuration read lease blocks mutation and re-reads pinned bytes", RetainedLeaseAsync),
        ("personal live-update recovery observation is explicit and evidence-bound", RecoveryObservationAsync),
        ("personal live-update recovery observation rejects incomplete and mismatched evidence", RecoveryEvidenceRejectedAsync),
        ("personal live-update arguments reject hard links when the host permits link creation", HardLinkAsync),
    ];

    internal static IReadOnlyList<(string Name, Func<Task> Run)> NonConditionalCases { get; } =
        Cases.Take(Cases.Count - 1).ToArray();

    internal static async Task<int> RunAsync()
    {
        var failures = 0;
        var skipped = 0;
        foreach (var test in Cases)
        {
            try
            {
                await test.Run().ConfigureAwait(false);
                Console.WriteLine($"PASS {test.Name}");
            }
            catch (ConditionalTestSkippedException exception)
            {
                skipped++;
                Console.WriteLine($"SKIP {test.Name}: {exception.Message}");
            }
            catch (Exception exception)
            {
                failures++;
                Console.Error.WriteLine($"FAIL {test.Name}: {exception}");
            }
        }
        Console.WriteLine(
            $"RESULT {Cases.Count - failures - skipped}/{Cases.Count} passed, {skipped} skipped");
        return failures == 0 ? 0 : 1;
    }

    private static Task ExactPairAsync() => WithFixtureAsync("exact-pair", fixture =>
    {
        var bytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":1}");
        fixture.WriteConfiguration(bytes);
        var sha256 = Sha256(bytes);

        RequireThrows<ArgumentException>(() => Parse(
            fixture,
            [PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument, fixture.ConfigurationPath]));
        RequireThrows<ArgumentException>(() => Parse(
            fixture,
            [PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument, sha256]));
        RequireThrows<ArgumentException>(() => Parse(
            fixture,
            [PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument]));
        RequireThrows<ArgumentException>(() => Parse(
            fixture,
            [PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument]));
        RequireThrows<ArgumentException>(() => Parse(
            fixture,
            [
                PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
                fixture.ConfigurationPath,
                PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
                fixture.ConfigurationPath,
                PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
                sha256,
            ]));
        RequireThrows<ArgumentException>(() => Parse(
            fixture,
            [
                PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
                fixture.ConfigurationPath,
                PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
                sha256,
                PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
                sha256,
            ]));
        var wrongCase = PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument.ToUpperInvariant();
        Require(PersonalDevelopmentLiveUpdateArguments.IsIntent([wrongCase]));
        RequireThrows<ArgumentException>(() => Parse(
            fixture,
            [
                wrongCase,
                fixture.ConfigurationPath,
                PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
                sha256,
            ]));
        RequireThrows<ArgumentException>(() => Parse(
            fixture,
            [
                PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
                fixture.ConfigurationPath,
                PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
                sha256.ToUpperInvariant(),
            ]));
        RequireThrows<ArgumentException>(() => Parse(
            fixture,
            [
                PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
                fixture.ConfigurationPath,
                PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
                new string('a', 63),
            ]));
        var wrongShaCase =
            PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument.ToUpperInvariant();
        Require(PersonalDevelopmentLiveUpdateArguments.IsIntent([wrongShaCase]));
        RequireThrows<ArgumentException>(() => Parse(
            fixture,
            [
                PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
                fixture.ConfigurationPath,
                wrongShaCase,
                sha256,
            ]));

        var absent = PersonalDevelopmentLiveUpdateArguments.ParseAndStrip(
            ["--background-startup"],
            developmentE2ECompiled: true,
            fixture.LayoutArguments,
            out var absentCommand);
        Require(absent is null);
        RequireSequence(["--background-startup"], absentCommand);

        var original = new[]
        {
            "--background-startup",
            PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
            fixture.ConfigurationPath,
            PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
            sha256,
        };
        using var parsed = Parse(fixture, original, out var command);
        RequireSequence(["--background-startup"], command);
        RequireSequence(original[1..], parsed.ToArguments());
        using var roundTrip = Parse(
            fixture,
            ["--background-startup", .. parsed.ToArguments()],
            out var roundTripCommand);
        RequireSequence(["--background-startup"], roundTripCommand);
        RequireEqual(parsed.ConfigurationPath, roundTrip.ConfigurationPath);
        RequireEqual(parsed.ConfigurationSha256, roundTrip.ConfigurationSha256);
    });

    private static Task DevelopmentAdmissionAsync() => WithFixtureAsync(
        "development-admission",
        fixture =>
        {
            var bytes = Encoding.UTF8.GetBytes("{}");
            fixture.WriteConfiguration(bytes);
            var arguments = fixture.ArgumentsFor(bytes);
            RequireThrows<InvalidOperationException>(() =>
                PersonalDevelopmentLiveUpdateArguments.ParseAndStrip(
                    arguments,
                    developmentE2ECompiled: false,
                    fixture.LayoutArguments,
                    out _));
            RequireThrows<ArgumentException>(() =>
                PersonalDevelopmentLiveUpdateArguments.ParseAndStrip(
                    arguments,
                    developmentE2ECompiled: true,
                    layoutArgs: null,
                    out _));
        });

    private static Task FileAdmissionAsync() => WithFixtureAsync("file-admission", fixture =>
    {
        var bytes = Encoding.UTF8.GetBytes("{\"value\":1}");
        fixture.WriteConfiguration(bytes);
        using (var valid = Parse(fixture, fixture.ArgumentsFor(bytes), out var command))
        {
            Require(command.Length == 0);
            RequireSequence(bytes, valid.ReadPinnedConfigurationBytes());
        }

        RequireThrows<InvalidDataException>(() => Parse(
            fixture,
            [
                PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
                "relative-live-update.json",
                PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
                Sha256(bytes),
            ]));

        var directoryPath = Path.Combine(fixture.Root, "configuration-directory");
        Directory.CreateDirectory(directoryPath);
        RequireThrows<InvalidDataException>(() => Parse(
            fixture,
            [
                PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
                directoryPath,
                PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
                Sha256(bytes),
            ]));

        fixture.WriteConfiguration(new byte[(64 * 1024) + 1]);
        RequireThrows<InvalidDataException>(() => Parse(
            fixture,
            fixture.ArgumentsFor(new byte[(64 * 1024) + 1])));

        fixture.WriteConfiguration(bytes);
        var wrongSha256 = new string('0', 64);
        if (string.Equals(wrongSha256, Sha256(bytes), StringComparison.Ordinal))
        {
            wrongSha256 = new string('1', 64);
        }
        RequireThrows<InvalidDataException>(() => Parse(
            fixture,
            [
                PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
                fixture.ConfigurationPath,
                PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
                wrongSha256,
            ]));
    });

    private static Task RetainedLeaseAsync() => WithFixtureAsync("retained-lease", fixture =>
    {
        var pinned = Encoding.UTF8.GetBytes("{\"pinned\":true}");
        fixture.WriteConfiguration(pinned);
        using var arguments = Parse(fixture, fixture.ArgumentsFor(pinned));
        RequireSequence(pinned, arguments.ReadPinnedConfigurationBytes());
        RequireThrowsAny<IOException, UnauthorizedAccessException>(() =>
            File.WriteAllBytes(
                fixture.ConfigurationPath,
                Encoding.UTF8.GetBytes("{\"mutated\":true}")));
        RequireSequence(pinned, arguments.ReadPinnedConfigurationBytes());

        arguments.Dispose();
        var replacement = Encoding.UTF8.GetBytes("{\"afterDispose\":true}");
        File.WriteAllBytes(fixture.ConfigurationPath, replacement);
        RequireSequence(replacement, File.ReadAllBytes(fixture.ConfigurationPath));
    });

    private static Task RecoveryObservationAsync() => WithFixtureAsync(
        "recovery-observation",
        fixture =>
        {
            using (var disabledArguments = fixture.CreateContext(
                       observeFailureRecovery: false,
                       out var disabled))
            {
                Require(!disabled.RequireRestoredBaselineObservation(
                    CreatePointer(
                        sequence: 99,
                        healthState: PersonalReleaseHealthStates.Pending)));
            }

            using var arguments = fixture.CreateContext(
                observeFailureRecovery: true,
                out var context);
            var baseline = CreatePointer(
                sequence: context.InitialSequence,
                healthState: PersonalReleaseHealthStates.Healthy);
            Require(!context.RequireRestoredBaselineObservation(baseline));

            context.RecordPhase("baseline-runtime-owned", processId: 1001);
            context.RecordPhase("stage-begin", processId: 2002);
            context.RecordPhase("stage-authenticated-complete", processId: 2002);
            Require(context.RequireRestoredBaselineObservation(baseline));
            context.RecordPhase("rollback-baseline-runtime-owned", processId: 3003);
            RequireThrows<IOException>(() =>
                context.RecordPhase("rollback-baseline-runtime-owned", processId: 3003));
            RequireThrows<InvalidDataException>(() =>
                context.RequireRestoredBaselineObservation(
                    CreatePointer(context.TargetSequence, PersonalReleaseHealthStates.Healthy)));
            RequireThrows<InvalidDataException>(() =>
                context.RequireRestoredBaselineObservation(
                    CreatePointer(context.InitialSequence, PersonalReleaseHealthStates.Pending)));
            RequireThrows<InvalidDataException>(() =>
                context.RequireRestoredBaselineObservation(
                    baseline with { Previous = baseline.Current }));
        });

    private static Task RecoveryEvidenceRejectedAsync() => WithFixtureAsync(
        "recovery-evidence-rejected",
        fixture =>
        {
            using (var incompleteArguments = fixture.CreateContext(
                       observeFailureRecovery: true,
                       out var incomplete))
            {
                incomplete.RecordPhase("stage-begin", processId: 2002);
                RequireThrows<InvalidDataException>(() =>
                    incomplete.RequireRestoredBaselineObservation(CreatePointer(
                        incomplete.InitialSequence,
                        PersonalReleaseHealthStates.Healthy)));
            }

            fixture.ResetObserverRoot();
            using var arguments = fixture.CreateContext(
                observeFailureRecovery: true,
                out var mismatched);
            mismatched.RecordPhase("baseline-runtime-owned", processId: 1001);
            fixture.WriteObserver(
                "stage-begin",
                processId: 2002,
                runId: new string('f', 32),
                observedAtUtc: DateTimeOffset.UtcNow);
            mismatched.RecordPhase("stage-authenticated-complete", processId: 2002);
            RequireThrows<InvalidDataException>(() =>
                mismatched.RequireRestoredBaselineObservation(CreatePointer(
                    mismatched.InitialSequence,
                    PersonalReleaseHealthStates.Healthy)));

            var observedAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            foreach (var invalid in new[]
            {
                (BaselinePid: 2002, StagePid: 2002, EndPid: 2002, Begin: observedAt, End: observedAt),
                (BaselinePid: 1001, StagePid: 2002, EndPid: 2003, Begin: observedAt, End: observedAt),
                (BaselinePid: 0, StagePid: 2002, EndPid: 2002, Begin: observedAt, End: observedAt),
                (BaselinePid: 1001, StagePid: 2002, EndPid: 2002, Begin: observedAt, End: DateTimeOffset.UtcNow.AddMinutes(1)),
                (BaselinePid: 1001, StagePid: 2002, EndPid: 2002, Begin: observedAt, End: observedAt.AddSeconds(-1)),
                (BaselinePid: 1001, StagePid: 2002, EndPid: 2002, Begin: observedAt.ToOffset(TimeSpan.FromHours(9)), End: observedAt),
            })
            {
                fixture.ResetObserverRoot();
                fixture.WriteObserver("baseline-runtime-owned", invalid.BaselinePid,
                    mismatched.RunId, observedAt.AddSeconds(-2));
                fixture.WriteObserver("stage-begin", invalid.StagePid,
                    mismatched.RunId, invalid.Begin);
                fixture.WriteObserver("stage-authenticated-complete", invalid.EndPid,
                    mismatched.RunId, invalid.End);
                RequireThrows<InvalidDataException>(() =>
                    mismatched.RequireRestoredBaselineObservation(CreatePointer(
                        mismatched.InitialSequence,
                        PersonalReleaseHealthStates.Healthy)));
            }
        });

    private static Task HardLinkAsync() => WithFixtureAsync("hard-link", fixture =>
    {
        var bytes = Encoding.UTF8.GetBytes("{\"linked\":true}");
        fixture.WriteConfiguration(bytes);
        var linkPath = Path.Combine(fixture.Root, "configuration-hard-link.json");
        if (!CreateHardLinkW(linkPath, fixture.ConfigurationPath, IntPtr.Zero))
        {
            var error = Marshal.GetLastPInvokeError();
            // This case is explicitly conditional only for hosts that deny hard-link creation.
            if (error is 5 or 1314)
            {
                throw new ConditionalTestSkippedException(
                    $"host denied hard-link creation (Win32 {error})");
            }
            throw new Win32Exception(error, "Could not create the test hard link.");
        }
        RequireThrows<InvalidDataException>(() => Parse(
            fixture,
            fixture.ArgumentsFor(bytes)));
    });

    private static PersonalDevelopmentLiveUpdateArguments Parse(
        Fixture fixture,
        IReadOnlyList<string> arguments) =>
        Parse(fixture, arguments, out _);

    private static PersonalDevelopmentLiveUpdateArguments Parse(
        Fixture fixture,
        IReadOnlyList<string> arguments,
        out string[] commandArguments) =>
        PersonalDevelopmentLiveUpdateArguments.ParseAndStrip(
            arguments,
            developmentE2ECompiled: true,
            fixture.LayoutArguments,
            out commandArguments)
        ?? throw new InvalidOperationException(
            "Expected one Personal development live-update argument envelope.");

    private static PersonalInstalledReleaseSetPointer CreatePointer(
        long sequence,
        string healthState)
    {
        var component = new PersonalInstalledComponentReference(
            PersonalReleaseSetContract.ClientBundleComponent,
            "fixture-client",
            "fixture-directory",
            new string('a', 64),
            new string('b', 64));
        var current = new PersonalInstalledReleaseSetReference(
            "fixture-release-set",
            1,
            sequence,
            1,
            new string('c', 64),
            new PersonalStartupStubCompatibility
            {
                MinimumVersion = "1.0.0",
                MaximumVersion = "1.0.0",
            },
            component,
            component with { Component = PersonalReleaseSetContract.RuntimeComponent },
            healthState,
            null,
            null,
            DateTimeOffset.UtcNow);
        return new PersonalInstalledReleaseSetPointer(
            3,
            PersonalReleaseSetContract.Product,
            PersonalReleaseSetContract.ProductionEnvironment,
            "stable",
            current,
            null,
            DateTimeOffset.UtcNow);
    }

    private static async Task WithFixtureAsync(string name, Action<Fixture> test)
    {
        using var fixture = new Fixture(name);
        test(fixture);
        await Task.CompletedTask;
    }

    private static string Sha256(byte[] bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException(
                "Personal development live-update argument assertion failed.");
        }
    }

    private static void RequireEqual<T>(T expected, T actual)
        where T : IEquatable<T>
    {
        if (!expected.Equals(actual))
        {
            throw new InvalidOperationException(
                $"Expected '{expected}', got '{actual}'.");
        }
    }

    private static void RequireSequence<T>(
        IEnumerable<T> expected,
        IEnumerable<T> actual)
    {
        if (!expected.SequenceEqual(actual))
        {
            throw new InvalidOperationException(
                "Personal development live-update argument sequence differed.");
        }
    }

    private static void RequireThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException(
            $"Expected {typeof(TException).Name}.");
    }

    private static void RequireThrowsAny<TFirst, TSecond>(Action action)
        where TFirst : Exception
        where TSecond : Exception
    {
        try
        {
            action();
        }
        catch (Exception exception) when (exception is TFirst or TSecond)
        {
            return;
        }
        throw new InvalidOperationException(
            $"Expected {typeof(TFirst).Name} or {typeof(TSecond).Name}.");
    }

    private sealed class Fixture : IDisposable
    {
        private static readonly string AllowedRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(Path.Combine(
                Path.GetTempPath(),
                "ensou-personal-live-update-argument-tests")));

        internal Fixture(string name)
        {
            Root = Path.GetFullPath(Path.Combine(
                AllowedRoot,
                $"{name}-q-{Guid.NewGuid():N}"));
            if (!Root.StartsWith(
                    AllowedRoot + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase)
                || Directory.Exists(Root)
                || File.Exists(Root))
            {
                throw new InvalidOperationException(
                    "Personal live-update test root escaped its isolated temporary boundary.");
            }
            Directory.CreateDirectory(Root);
            ConfigurationPath = Path.Combine(Root, "live-update.json");
            LayoutArguments = PersonalDevelopmentE2ELayoutArguments.Create(
                Path.Combine(Root, "managed"),
                Path.Combine(Root, "home"),
                Path.Combine(Root, "witness", "security.dpapi"));
        }

        internal string Root { get; }

        internal string ConfigurationPath { get; }

        internal PersonalDevelopmentE2ELayoutArguments LayoutArguments { get; }

        internal string ObserverRoot => Path.Combine(Root, "observer");

        internal void WriteConfiguration(byte[] bytes) =>
            File.WriteAllBytes(ConfigurationPath, bytes);

        internal string[] ArgumentsFor(byte[] bytes) =>
        [
            PersonalDevelopmentLiveUpdateArguments.ConfigurationArgument,
            ConfigurationPath,
            PersonalDevelopmentLiveUpdateArguments.ConfigurationSha256Argument,
            Sha256(bytes),
        ];

        internal PersonalDevelopmentLiveUpdateArguments CreateContext(
            bool observeFailureRecovery,
            out PersonalDevelopmentLiveUpdateContext context)
        {
            using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var configuration = new
            {
                schemaVersion = 1,
                runId = Guid.NewGuid().ToString("N"),
                managedRoot = LayoutArguments.Layout.ManagedRoot,
                harnessHome = LayoutArguments.Layout.HarnessHome,
                updateSecurityWitnessPath = LayoutArguments.Layout.UpdateSecurityWitnessPath,
                manifestUri = "https://updates.example.test/v2/channels/stable/release-set.v2.json",
                loopbackPort = 60081,
                expectedTlsCertificateDerSha256 = new string('d', 64),
                trustedPolicy = new PersonalReleaseTrustPolicy
                {
                    Product = PersonalReleaseSetContract.Product,
                    Environment = PersonalReleaseSetContract.ProductionEnvironment,
                    Channel = "stable",
                    ArtifactOrigin = new Uri("https://updates.example.test/"),
                    StartupStubVersion = "1.0.0",
                    TrustedKeys =
                    [
                        PersonalReleaseSetSigner.ExportPublicKey("fixture-key", signingKey),
                    ],
                },
                observerRoot = ObserverRoot,
                runtimePort = 60082,
                initialSequence = 1,
                targetSequence = 2,
                failFirstReceiverBeforeReady = false,
                observeFailureRecovery,
            };
            var bytes = JsonSerializer.SerializeToUtf8Bytes(
                configuration,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            WriteConfiguration(bytes);
            var arguments = Parse(this, ArgumentsFor(bytes));
            context = PersonalDevelopmentLiveUpdateContext.Create(arguments, LayoutArguments);
            return arguments;
        }

        internal void ResetObserverRoot()
        {
            if (Directory.Exists(ObserverRoot))
            {
                Directory.Delete(ObserverRoot, recursive: true);
            }
        }

        internal void WriteObserver(
            string phase,
            int processId,
            string runId,
            DateTimeOffset observedAtUtc)
        {
            Directory.CreateDirectory(ObserverRoot);
            File.WriteAllBytes(
                Path.Combine(ObserverRoot, $"{phase}.json"),
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    pid = processId,
                    timeUtc = observedAtUtc,
                    runId,
                    phase,
                }, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        }

        public void Dispose()
        {
            var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Root));
            if (!normalized.StartsWith(
                    AllowedRoot + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Personal live-update test cleanup escaped its isolated temporary boundary.");
            }
            if (Directory.Exists(normalized))
            {
                Directory.Delete(normalized, recursive: true);
            }
        }
    }

    private sealed class ConditionalTestSkippedException(string message)
        : Exception(message);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);
}
