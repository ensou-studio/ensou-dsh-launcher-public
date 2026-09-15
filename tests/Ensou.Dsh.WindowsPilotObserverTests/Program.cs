using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using Ensou.Dsh.WindowsPilotObserver;

namespace Ensou.Dsh.WindowsPilotObserverTests;

internal static class Program
{
    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "ensou-windows-pilot-observer-tests",
        Guid.NewGuid().ToString("N"));

    public static int Main()
    {
        Directory.CreateDirectory(TempRoot);
        var tests = new (string Name, Action Run)[]
        {
            ("strict plan accepts the exact contract", StrictPlanAcceptsExactContract),
            ("strict plan rejects unknown duplicate and reordered content", StrictPlanRejectsAmbiguity),
            ("decision state is sticky and duration is monotonic", DecisionIsSticky),
            ("medium unelevated administrator-account tokens are accepted", MediumUnelevatedTokenPolicy),
            ("medium-plus integrity RID 0x2100 is rejected", MediumPlusIntegrityIsRejected),
            ("only native x64 Windows workstations are accepted", PlatformPolicyIsExact),
            ("preflight time is excluded and boundary gaps are strict", TimingBoundaryIsGapFree),
            ("candidate binding requires exact stable bytes", CandidateBindingRequiresExactBytes),
            ("external recording binds fixed bytes process identity and challenges", ExternalRecordingIsBound),
            ("hash-chain evidence is create-only and verifiable", EvidenceChainIsCreateOnly),
            ("privacy removes titles and account paths", PrivacyRemovesSensitiveValues),
            ("short console and error windows are unexpected", SuspiciousWindowsFailPolicy),
            ("only candidate recorder and suspicious evidence is persistent", EvidenceRelevanceIsNarrow),
            ("relevant zero creation times are unusable", ZeroCreationTimesAreRejected),
            ("eligible summaries enforce every runtime admission invariant", EligibleSummaryVerifierIsFailClosed),
            ("summary schema conditionally gates eligible evidence", SummarySchemaGatesEligibility),
            ("fixture is build-only and never launched by tests", FixtureIsBuildOnly),
        };
        var failures = 0;
        try
        {
            foreach (var test in tests)
            {
                try
                {
                    Console.WriteLine($"RUN {test.Name}");
                    test.Run();
                    Console.WriteLine($"PASS {test.Name}");
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.Error.WriteLine($"FAIL {test.Name}: {exception}");
                }
            }
        }
        finally
        {
            if (Directory.Exists(TempRoot))
            {
                Directory.Delete(TempRoot, recursive: true);
            }
        }
        Console.WriteLine($"{tests.Length - failures}/{tests.Length} Windows Pilot Observer tests passed.");
        return failures == 0 ? 0 : 1;
    }

    private static void StrictPlanAcceptsExactContract()
    {
        var fixture = CreatePlanFixture("strict-valid");
        var raw = JsonSerializer.SerializeToUtf8Bytes(fixture.Plan, ObservationContract.JsonOptions);
        var parsed = ObservationContract.ParsePlan(raw);
        AssertEqual(ObservationContract.PlanType, parsed.PlanType);
        AssertEqual(900, parsed.MinimumObservationSeconds);
        AssertSequenceEqual(ObservationContract.CandidateRoles, parsed.Candidate.Files.Select(static item => item.Role));
        AssertSequenceEqual(ObservationContract.RequiredActions, parsed.RequiredActions);
    }

    private static void StrictPlanRejectsAmbiguity()
    {
        var fixture = CreatePlanFixture("strict-reject");
        var json = JsonSerializer.Serialize(fixture.Plan, ObservationContract.JsonOptions);
        AssertThrows<InvalidDataException>(() => ObservationContract.ParsePlan(
            Encoding.UTF8.GetBytes(json.Replace(
                "\"schemaVersion\":1",
                "\"schemaVersion\":1,\"schemaVersion\":1",
                StringComparison.Ordinal))));
        AssertThrows<JsonException>(() => ObservationContract.ParsePlan(
            Encoding.UTF8.GetBytes(json.Replace(
                "\"planType\":",
                "\"unknown\":true,\"planType\":",
                StringComparison.Ordinal))));

        var reordered = fixture.Plan.Candidate.Files.Reverse().ToArray();
        var invalid = CopyPlan(fixture.Plan, fixture.Plan.Candidate.WithFiles(reordered));
        AssertThrows<InvalidDataException>(() => ObservationContract.ParsePlan(
            JsonSerializer.SerializeToUtf8Bytes(invalid, ObservationContract.JsonOptions)));
    }

    private static void DecisionIsSticky()
    {
        var eligible = new ObservationDecision();
        foreach (var action in ObservationContract.RequiredActions)
        {
            eligible.CompleteAction(action);
        }
        eligible.Finalize(900_000, 900);
        AssertEqual("ELIGIBLE_FOR_REVIEW", eligible.ToContractValue());

        var shortRun = new ObservationDecision();
        shortRun.Finalize(899_999, 900);
        AssertEqual("BLOCKED", shortRun.ToContractValue());
        shortRun.Fail("UNEXPECTED_WINDOW");
        shortRun.Block("SYSTEM_SUSPEND");
        AssertEqual("FAIL", shortRun.ToContractValue());
        AssertTrue(shortRun.ReasonCodes.Contains("OBSERVATION_DURATION_INSUFFICIENT", StringComparer.Ordinal));
    }

    private static void MediumUnelevatedTokenPolicy()
    {
        AssertTrue(ExecutionIdentityPolicy.IsAccepted(
            ProcessTokenElevationType.Default,
            ExecutionIdentityPolicy.MediumIntegrityRid));
        AssertTrue(ExecutionIdentityPolicy.IsAccepted(
            ProcessTokenElevationType.Limited,
            ExecutionIdentityPolicy.MediumIntegrityRid));
        AssertFalse(ExecutionIdentityPolicy.IsAccepted(
            ProcessTokenElevationType.Full,
            ExecutionIdentityPolicy.MediumIntegrityRid));
    }

    private static void MediumPlusIntegrityIsRejected()
    {
        AssertFalse(ExecutionIdentityPolicy.IsAccepted(
            ProcessTokenElevationType.Limited,
            0x2100));
    }

    private static void PlatformPolicyIsExact()
    {
        AssertTrue(PlatformEvidence.IsSupported(
            10, 0, 19045, 1, Architecture.X64, Architecture.X64, 0x0000, 0x8664));
        AssertTrue(PlatformEvidence.IsSupported(
            10, 0, 26100, 1, Architecture.X64, Architecture.X64, 0x0000, 0x8664));
        AssertFalse(PlatformEvidence.IsSupported(
            10, 0, 20348, 3, Architecture.X64, Architecture.X64, 0x0000, 0x8664));
        AssertFalse(PlatformEvidence.IsSupported(
            10, 0, 19045, 1, Architecture.X64, Architecture.X64, 0x014c, 0x8664));
        AssertFalse(PlatformEvidence.IsSupported(
            10, 0, 26100, 1, Architecture.X64, Architecture.Arm64, 0x0000, 0xaa64));
        AssertFalse(PlatformEvidence.IsSupported(
            10, 0, 19045, 1, Architecture.X86, Architecture.X64, 0x014c, 0x8664));
    }

    private static void TimingBoundaryIsGapFree()
    {
        const long expensivePreflightCompletedAt = 125_000;
        var start = ObservationTiming.BeginAfterPreflight(expensivePreflightCompletedAt);
        AssertEqual(0L, ObservationTiming.Elapsed(start, expensivePreflightCompletedAt));
        AssertEqual(900_000L, ObservationTiming.Elapsed(start, expensivePreflightCompletedAt + 900_000));
        AssertTrue(ObservationTiming.IsLightweightGapAccepted(1000, 1750));
        AssertFalse(ObservationTiming.IsLightweightGapAccepted(1000, 1751));
        AssertTrue(ObservationTiming.IsFullGapAccepted(1000, 2000));
        AssertFalse(ObservationTiming.IsFullGapAccepted(1000, 2001));
    }

    private static void CandidateBindingRequiresExactBytes()
    {
        var fixture = CreatePlanFixture("binding");
        var tracker = new CandidateBindingTracker(fixture.Plan.Candidate);
        tracker.VerifyRequiredAtStart();
        var observed = tracker.ObserveNewlyAvailable();
        AssertEqual(
            ObservationContract.CandidateRoles.Length
            - fixture.Plan.Candidate.Files.Count(static item => item.RequiredAtStart),
            observed.Length);
        AssertEqual(ObservationContract.CandidateRoles.Length, tracker.VerifyAllAtEnd().Length);

        File.AppendAllText(fixture.Plan.Candidate.Files[2].Path, "tamper");
        var exception = AssertThrows<CandidateBindingException>(() => tracker.VerifyAllAtEnd());
        AssertEqual("CANDIDATE_HASH_MISMATCH", exception.ReasonCode);
    }

    private static void EvidenceChainIsCreateOnly()
    {
        var root = Path.Combine(TempRoot, "evidence");
        var runId = Guid.NewGuid().ToString("D");
        EvidenceLogCompletion completion;
        using (var store = new EvidenceSessionStore(runId, root))
        {
            store.Append("first", 0, new { value = "one" });
            store.Append("second", 250, new { normalizedPath = @"C:\pilot" });
            completion = store.CompleteLog();
        }
        AssertEqual(2L, completion.RecordCount);
        AssertEqual(64, completion.TerminalRecordSha256.Length);
        var previous = new string('0', 64);
        foreach (var line in File.ReadLines(completion.Path))
        {
            using var document = JsonDocument.Parse(line);
            var rootElement = document.RootElement;
            AssertEqual(previous, rootElement.GetProperty("previousSha256").GetString()!);
            var computed = EvidenceSessionStore.ComputeRecordHash(
                previous,
                rootElement.GetProperty("sequence").GetInt64(),
                rootElement.GetProperty("observedAtUtc").GetString()!,
                rootElement.GetProperty("monotonicMilliseconds").GetInt64(),
                rootElement.GetProperty("eventType").GetString()!,
                rootElement.GetProperty("data"));
            previous = rootElement.GetProperty("recordSha256").GetString()!;
            AssertEqual(computed, previous);
        }
        AssertEqual(completion.TerminalRecordSha256, previous);
        AssertThrows<IOException>(() => new EvidenceSessionStore(runId, root).Dispose());
    }

    private static void ExternalRecordingIsBound()
    {
        var fixture = CreatePlanFixture("recording");
        var monitor = new ExternalRecordingMonitor(fixture.Plan.Recording);
        var recorder = new ProcessObservation(
            400,
            1,
            123456789,
            "recorder.exe",
            fixture.Plan.Recording.RecorderExecutablePath,
            fixture.Plan.Recording.RecorderExecutableSha256,
            false);
        var snapshot = new DesktopSnapshot([recorder], []);
        monitor.Begin(snapshot);
        AssertTrue(monitor.IsContinuous(snapshot));
        AssertFalse(monitor.IsContinuous(new DesktopSnapshot(
            [recorder with { CreationTimeUtcFileTime = 123456790 }],
            [])));
        var endChallenge = monitor.IssueEndChallenge();
        AssertTrue(endChallenge.StartsWith("ENSOU-END-", StringComparison.Ordinal));
        File.WriteAllText(fixture.Plan.Recording.OutputPath, "fixed external recording bytes");
        var completion = monitor.Complete(900_000);
        AssertEqual(900_000L, completion.CoverageMilliseconds);
        AssertEqual(64, completion.Sha256.Length);
        AssertEqual(64, completion.StartChallengeSha256.Length);
        AssertEqual(64, completion.EndChallengeSha256.Length);
        AssertFalse(completion.AudioCaptured);
    }

    private static void PrivacyRemovesSensitiveValues()
    {
        const string title = "secret customer workspace - Application Error";
        var titleHash = ObservationPrivacy.HashSensitiveText(title);
        AssertEqual(64, titleHash.Length);
        AssertFalse(titleHash.Contains("secret", StringComparison.OrdinalIgnoreCase));
        AssertEqual("application-error", ObservationPrivacy.ClassifyTitle(title));

        var privatePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "private",
            "file.exe");
        var normalized = ObservationPrivacy.NormalizePrivatePath(privatePath);
        AssertFalse(normalized.Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase));
        AssertTrue(normalized.StartsWith("<user-profile>", StringComparison.Ordinal));

        var forbidden = JsonSerializer.SerializeToElement(new { commandLine = "--api-key secret" });
        AssertThrows<InvalidDataException>(() => ObservationPrivacy.AssertSafePayload(forbidden));
    }

    private static void SuspiciousWindowsFailPolicy()
    {
        var fixture = CreatePlanFixture("windows");
        var baseline = new WindowObservation(
            1,
            100,
            10,
            "explorer.exe",
            "CabinetWClass",
            ObservationPrivacy.HashSensitiveText("baseline"),
            8,
            "other",
            true);
        var policy = new WindowAdmissionPolicy([baseline], fixture.Plan, 999);
        AssertEqual(WindowAdmissionResult.Allowed, policy.Evaluate(baseline, false));

        var console = new WindowObservation(
            2,
            101,
            11,
            "cmd.exe",
            "ConsoleWindowClass",
            ObservationPrivacy.HashSensitiveText("console"),
            7,
            "other",
            true);
        AssertEqual(WindowAdmissionResult.Unexpected, policy.Evaluate(console, true));
        var dirtyBaselinePolicy = new WindowAdmissionPolicy([console], fixture.Plan, 999);
        AssertEqual(WindowAdmissionResult.Unexpected, dirtyBaselinePolicy.Evaluate(console, true));

        var error = console with
        {
            WindowHandle = 3,
            ProcessImageName = "dotnet.exe",
            ClassName = "#32770",
            TitleCategory = "application-error",
        };
        AssertEqual(WindowAdmissionResult.Unexpected, policy.Evaluate(error, false));

        var launcher = console with
        {
            WindowHandle = 4,
            ProcessImageName = Path.GetFileName(fixture.Plan.Candidate.Files[2].Path),
            ClassName = "Chrome_WidgetWin_1",
            ExecutablePath = @"C:\Other\launcher.exe",
        };
        AssertEqual(WindowAdmissionResult.Unexpected, policy.Evaluate(launcher, false));
        AssertEqual(
            WindowAdmissionResult.Blocked,
            policy.Evaluate(launcher with { ExecutablePath = null }, false));
        var exactLauncher = launcher with
        {
            WindowHandle = 5,
            ExecutablePath = fixture.Plan.Candidate.Files[2].Path,
        };
        AssertEqual(WindowAdmissionResult.Allowed, policy.Evaluate(exactLauncher, false));
        var serialized = JsonSerializer.Serialize(exactLauncher, ObservationContract.JsonOptions);
        AssertFalse(serialized.Contains(exactLauncher.ExecutablePath!, StringComparison.OrdinalIgnoreCase));
    }

    private static void EvidenceRelevanceIsNarrow()
    {
        var fixture = CreatePlanFixture("relevance");
        var policy = new EvidenceRelevancePolicy(fixture.Plan);
        var ordinary = new ProcessObservation(
            10, 1, 100, "notepad.exe", @"C:\Windows\System32\notepad.exe", null, false);
        var descendant = ordinary with
        {
            ProcessId = 11,
            CreationTimeUtcFileTime = 101,
            ImageName = "helper.exe",
            CandidateRelated = true,
        };
        var recorder = ordinary with
        {
            ProcessId = 12,
            CreationTimeUtcFileTime = 102,
            ImageName = "recorder.exe",
            ExecutablePath = fixture.Plan.Recording.RecorderExecutablePath,
        };
        var suspicious = ordinary with
        {
            ProcessId = 13,
            CreationTimeUtcFileTime = 103,
            ImageName = "werfault.exe",
            ExecutablePath = null,
        };
        AssertFalse(policy.IsRelevant(ordinary));
        AssertTrue(policy.IsRelevant(descendant));
        AssertTrue(policy.IsRelevant(recorder));
        AssertTrue(policy.IsRelevant(suspicious));

        var ordinaryWindow = new WindowObservation(
            1, ordinary.ProcessId, ordinary.CreationTimeUtcFileTime, ordinary.ImageName,
            "Notepad", ObservationPrivacy.HashSensitiveText("ordinary"), 8, "other", true);
        AssertFalse(policy.IsRelevant(ordinaryWindow, ordinary));
        AssertTrue(policy.IsRelevant(
            ordinaryWindow with { ProcessImageName = "cmd.exe", ClassName = "ConsoleWindowClass" },
            null));
    }

    private static void ZeroCreationTimesAreRejected()
    {
        var process = new ProcessObservation(50, 1, 0, "cmd.exe", null, null, false);
        var window = new WindowObservation(
            5, 50, 0, "cmd.exe", "ConsoleWindowClass",
            ObservationPrivacy.HashSensitiveText("console"), 7, "other", true);
        AssertFalse(EvidenceRelevancePolicy.HasUsableCreationTime(process));
        AssertFalse(EvidenceRelevancePolicy.HasUsableCreationTime(window));
        AssertTrue(EvidenceRelevancePolicy.HasUsableCreationTime(
            process with { CreationTimeUtcFileTime = 1 }));
    }

    private static void EligibleSummaryVerifierIsFailClosed()
    {
        var fixture = CreatePlanFixture("summary-verifier");
        var valid = CreateEligibleSummary(fixture.Plan);
        ObservationSummaryVerifier.Validate(valid, fixture.Plan);

        AssertThrows<InvalidDataException>(() => ObservationSummaryVerifier.Validate(
            valid with { MonotonicDurationMilliseconds = 899_999 }, fixture.Plan));
        AssertThrows<InvalidDataException>(() => ObservationSummaryVerifier.Validate(
            valid with { Actions = valid.Actions[..^1] }, fixture.Plan));
        AssertThrows<InvalidDataException>(() => ObservationSummaryVerifier.Validate(
            valid with
            {
                Candidate = valid.Candidate with
                {
                    Files = valid.Candidate.Files.Select((item, index) =>
                        index == 0 ? item with { Observed = false } : item).ToArray(),
                },
            }, fixture.Plan));
        AssertThrows<InvalidDataException>(() => ObservationSummaryVerifier.Validate(
            valid with { Sampling = valid.Sampling with { LostEventCount = 1 } }, fixture.Plan));
        AssertThrows<InvalidDataException>(() => ObservationSummaryVerifier.Validate(
            valid with { Recording = valid.Recording with { SizeBytes = 0 } }, fixture.Plan));
        AssertThrows<InvalidDataException>(() => ObservationSummaryVerifier.Validate(
            valid with
            {
                UnexpectedWindows =
                [
                    new UnexpectedWindowSummary(
                        "cmd.exe", "ConsoleWindowClass", new string('f', 64), "other", 1),
                ],
            }, fixture.Plan));
        AssertThrows<InvalidDataException>(() => ObservationSummaryVerifier.Validate(
            valid with { Platform = valid.Platform with { Workstation = false } }, fixture.Plan));
    }

    private static void SummarySchemaGatesEligibility()
    {
        var schemaPath = Path.Combine(
            Directory.GetCurrentDirectory(),
            "release",
            "schemas",
            "windows-pilot-observation-summary-v1.schema.json");
        using var schema = JsonDocument.Parse(File.ReadAllBytes(schemaPath));
        var root = schema.RootElement;
        var definitions = root.GetProperty("$defs");
        AssertEqual(
            8192,
            definitions.GetProperty("executionIdentity")
                .GetProperty("properties")
                .GetProperty("integrityRid")
                .GetProperty("const")
                .GetInt32());
        var platform = definitions.GetProperty("platform");
        AssertFalse(platform.GetProperty("additionalProperties").GetBoolean());
        AssertEqual(
            "x64",
            platform.GetProperty("properties")
                .GetProperty("processArchitecture")
                .GetProperty("const")
                .GetString()!);
        AssertFalse(platform.GetProperty("properties")
            .GetProperty("wowOrEmulated")
            .GetProperty("const")
            .GetBoolean());

        var eligibleConditional = root.GetProperty("allOf")
            .EnumerateArray()
            .Single(item => item.GetProperty("if")
                .GetProperty("properties")
                .GetProperty("verdict")
                .GetProperty("const")
                .GetString() == "ELIGIBLE_FOR_REVIEW");
        var properties = eligibleConditional.GetProperty("then").GetProperty("properties");
        AssertEqual(900_000L, properties.GetProperty("monotonicDurationMilliseconds")
            .GetProperty("minimum").GetInt64());
        AssertEqual(0, properties.GetProperty("reasonCodes").GetProperty("maxItems").GetInt32());
        AssertEqual(9, properties.GetProperty("actions").GetProperty("minItems").GetInt32());
        AssertEqual(0, properties.GetProperty("unexpectedWindows").GetProperty("maxItems").GetInt32());
        var eligibleCandidateItems = properties.GetProperty("candidate")
            .GetProperty("allOf")[1]
            .GetProperty("properties")
            .GetProperty("files")
            .GetProperty("prefixItems")
            .EnumerateArray()
            .ToArray();
        AssertEqual(ObservationContract.CandidateRoles.Length, eligibleCandidateItems.Length);
        foreach (var item in eligibleCandidateItems)
        {
            AssertEqual(1, item.GetProperty("properties")
                .GetProperty("sizeBytes")
                .GetProperty("minimum")
                .GetInt32());
            AssertTrue(item.GetProperty("properties")
                .GetProperty("observed")
                .GetProperty("const")
                .GetBoolean());
        }
    }

    private static void FixtureIsBuildOnly()
    {
        var fixtureProject = Path.Combine(
            Directory.GetCurrentDirectory(),
            "tests",
            "Ensou.Dsh.WindowsPilotObserverFixture",
            "Ensou.Dsh.WindowsPilotObserverFixture.csproj");
        AssertTrue(File.Exists(fixtureProject));
    }

    private static PlanFixture CreatePlanFixture(string name)
    {
        var root = Path.Combine(TempRoot, name + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var files = new List<CandidateFilePlan>();
        for (var index = 0; index < ObservationContract.CandidateRoles.Length; index++)
        {
            var role = ObservationContract.CandidateRoles[index];
            var path = Path.Combine(root, $"{index:D2}-{role}.exe");
            File.WriteAllText(path, $"candidate-{role}");
            files.Add(new CandidateFilePlan
            {
                Role = role,
                Path = path,
                Sha256 = ObservationContract.Sha256File(path),
                RequiredAtStart = index < 2,
            });
        }
        var recorder = Path.Combine(root, "recorder.exe");
        File.WriteAllText(recorder, "recorder");
        var plan = new ObservationPlan
        {
            SchemaVersion = 1,
            PlanType = ObservationContract.PlanType,
            Edition = "personal",
            TestRunId = Guid.NewGuid().ToString("D"),
            MinimumObservationSeconds = 900,
            ExpectedObserverSha256 = new string('a', 64),
            Recording = new RecordingPlan
            {
                RecorderExecutablePath = recorder,
                RecorderExecutableSha256 = ObservationContract.Sha256File(recorder),
                OutputPath = Path.Combine(root, "capture.mp4"),
                MediaType = "video/mp4",
                AudioCaptured = false,
            },
            Candidate = new CandidatePlan
            {
                ReleaseSetId = "personal-stable-1",
                Generation = 1,
                Sequence = 1,
                LauncherRepositoryCommit = new string('b', 40),
                HarnessSourceTag = "v1.0.0",
                HarnessSourceCommit = new string('c', 40),
                Files = files.ToArray(),
            },
            RequiredActions = ObservationContract.RequiredActions.ToArray(),
            AllowedVisibleImageNames = ["msedge.exe"],
        };
        return new PlanFixture(root, plan);
    }

    private static ObservationSummary CreateEligibleSummary(ObservationPlan plan) => new()
    {
        StandaloneAdmissionEvidence = false,
        TestRunId = plan.TestRunId,
        Edition = plan.Edition,
        Verdict = "ELIGIBLE_FOR_REVIEW",
        ReasonCodes = [],
        PlanSha256 = new string('d', 64),
        ObserverExecutableSha256 = plan.ExpectedObserverSha256,
        StartedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-15).ToString("O"),
        CompletedAtUtc = DateTimeOffset.UtcNow.ToString("O"),
        MonotonicDurationMilliseconds = 900_000,
        Sampling = new SamplingSummary(250, 1000, 3600, 900, 1000, 0),
        ExecutionIdentity = new ExecutionIdentitySummary("limited", 0x2000, "deny-only"),
        Platform = new PlatformEvidence(
            10, 0, 19045, 1, Architecture.X64, Architecture.X64, 0x0000, 0x8664).ToSummary(),
        Candidate = new CandidateSummary(
            plan.Candidate.ReleaseSetId,
            plan.Candidate.Generation,
            plan.Candidate.Sequence,
            plan.Candidate.LauncherRepositoryCommit,
            plan.Candidate.HarnessSourceTag,
            plan.Candidate.HarnessSourceCommit,
            plan.Candidate.Files.Select(item => new CandidateFileSummary(
                item.Role,
                item.Sha256,
                new FileInfo(item.Path).Length,
                true)).ToArray()),
        Actions = ObservationContract.RequiredActions.Select((action, index) =>
            new CompletedActionSummary(action, (index + 1) * 1000L)).ToArray(),
        Recording = new RecordingSummary(
            "video/mp4", 1024, new string('e', 64), 900_000, false,
            new string('1', 64), new string('2', 64)),
        EvidenceLog = new EvidenceLogSummary(
            "application/x-ndjson", 1024, new string('3', 64), new string('4', 64), 10),
        UnexpectedWindows = [],
    };

    private static ObservationPlan CopyPlan(ObservationPlan source, CandidatePlan candidate) => new()
    {
        SchemaVersion = source.SchemaVersion,
        PlanType = source.PlanType,
        Edition = source.Edition,
        TestRunId = source.TestRunId,
        MinimumObservationSeconds = source.MinimumObservationSeconds,
        ExpectedObserverSha256 = source.ExpectedObserverSha256,
        Recording = source.Recording,
        Candidate = candidate,
        RequiredActions = source.RequiredActions,
        AllowedVisibleImageNames = source.AllowedVisibleImageNames,
    };

    private static CandidatePlan WithFiles(this CandidatePlan source, CandidateFilePlan[] files) => new()
    {
        ReleaseSetId = source.ReleaseSetId,
        Generation = source.Generation,
        Sequence = source.Sequence,
        LauncherRepositoryCommit = source.LauncherRepositoryCommit,
        HarnessSourceTag = source.HarnessSourceTag,
        HarnessSourceCommit = source.HarnessSourceCommit,
        Files = files,
    };

    private sealed record PlanFixture(string Root, ObservationPlan Plan);

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
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
        }
    }

    private static void AssertSequenceEqual<T>(IEnumerable<T> expected, IEnumerable<T> actual)
    {
        if (!expected.SequenceEqual(actual))
        {
            throw new InvalidOperationException("Sequences differ.");
        }
    }

    private static TException AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }
}
