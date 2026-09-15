using System.ComponentModel;
using System.Text.Json;

namespace Ensou.Dsh.WindowsPilotObserver;

public sealed record ObservationCompletion(
    string Verdict,
    string EvidenceDirectory,
    string SummaryPath,
    string EvidenceLogPath);

public sealed class ObservationEngine : IDisposable
{
    private readonly object sync = new();
    private readonly ObservationPlan plan;
    private readonly string planSha256;
    private readonly string observerSha256;
    private readonly ExecutionIdentityEvidence executionIdentity;
    private readonly PlatformEvidence platform;
    private readonly IDesktopProbe probe;
    private readonly IMonotonicClock clock;
    private readonly EvidenceSessionStore evidence;
    private readonly CandidateBindingTracker candidateBinding;
    private readonly ExternalRecordingMonitor recording;
    private readonly EvidenceRelevancePolicy relevance;
    private readonly ObservationDecision decision = new();
    private readonly Dictionary<string, ProcessObservation> knownProcesses = new(StringComparer.Ordinal);
    private readonly HashSet<string> knownWindows = new(StringComparer.Ordinal);
    private readonly HashSet<string> identityFailures = new(StringComparer.Ordinal);
    private readonly List<CompletedActionSummary> completedActions = [];
    private readonly List<UnexpectedWindowSummary> unexpectedWindows = [];
    private readonly HashSet<string> candidateImageNames;
    private readonly Dictionary<string, CandidateFilePlan> candidateFilesByPath;
    private System.Threading.Timer? timer;
    private WindowsEventHookCollector? eventHooks;
    private WindowAdmissionPolicy? windowPolicy;
    private int samplingGate;
    private long lightweightCount;
    private long fullCount;
    private long maximumFullGap;
    private long lostEventCount;
    private bool recordingInterruptionRecorded;
    private long lastLightweightAt;
    private long lastFullAt;
    private long startedAtMilliseconds;
    private long endedAtMilliseconds;
    private DateTimeOffset startedAtUtc;
    private DateTimeOffset? completedAtUtc;
    private int actionIndex;
    private bool started;
    private bool ended;
    private bool finalized;

    public ObservationEngine(
        ObservationPlan plan,
        ReadOnlySpan<byte> rawPlan,
        string? evidenceRoot = null,
        IDesktopProbe? probe = null,
        IMonotonicClock? clock = null,
        string? observerExecutablePath = null,
        ExecutionIdentityEvidence? executionIdentity = null,
        PlatformEvidence? platformEvidence = null)
    {
        this.plan = plan;
        planSha256 = ObservationContract.Sha256Hex(rawPlan);
        observerExecutablePath ??= Environment.ProcessPath
            ?? throw new InvalidOperationException("Observer executable path is unavailable.");
        observerSha256 = ObservationContract.Sha256File(observerExecutablePath);
        if (!string.Equals(observerSha256, plan.ExpectedObserverSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Observer executable bytes do not match the observation plan.");
        }
        this.executionIdentity = executionIdentity ?? ExecutionIdentityPolicy.CaptureCurrent();
        if (!ExecutionIdentityPolicy.IsAccepted(
                this.executionIdentity.ElevationType,
                this.executionIdentity.IntegrityRid))
        {
            throw new InvalidDataException(
                "Observer must run as an unelevated medium-integrity process. "
                + "The account may be an administrator when UAC supplies a filtered token.");
        }
        platform = platformEvidence ?? PlatformEvidence.CaptureCurrent();
        if (!platform.IsAccepted)
        {
            throw new InvalidDataException(
                "Observer requires native x64 Windows 10 or Windows 11 Workstation.");
        }
        this.probe = probe ?? new WindowsDesktopProbe(plan);
        this.clock = clock ?? new StopwatchMonotonicClock();
        evidence = new EvidenceSessionStore(plan.TestRunId, evidenceRoot);
        candidateBinding = new CandidateBindingTracker(plan.Candidate);
        recording = new ExternalRecordingMonitor(plan.Recording);
        relevance = new EvidenceRelevancePolicy(plan);
        candidateImageNames = plan.Candidate.Files
            .Select(static item => Path.GetFileName(item.Path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        candidateFilesByPath = plan.Candidate.Files.ToDictionary(
            static item => Path.GetFullPath(item.Path),
            StringComparer.OrdinalIgnoreCase);
    }

    public event EventHandler? StatusChanged;

    public string StartChallenge => recording.StartChallenge;
    public string? EndChallenge { get; private set; }
    public long ElapsedMilliseconds => !started
        ? 0
        : ObservationTiming.Elapsed(
            startedAtMilliseconds,
            ended ? endedAtMilliseconds : clock.Milliseconds);
    public string Verdict => decision.ToContractValue();
    public string[] ReasonCodes => decision.ReasonCodes;
    public string? CurrentAction => actionIndex < ObservationContract.RequiredActions.Length
        ? ObservationContract.RequiredActions[actionIndex]
        : null;
    public bool IsStarted => started;
    public bool IsEnded => ended;
    public bool IsFinalized => finalized;
    public string EvidenceDirectory => evidence.RunDirectory;

    public void Start()
    {
        lock (sync)
        {
            if (started)
            {
                throw new InvalidOperationException("Observation is already active.");
            }
            DesktopSnapshot preflight;
            try
            {
                candidateBinding.VerifyRequiredAtStart();
                preflight = probe.Capture(enriched: true);
                recording.Begin(preflight);
                eventHooks = new WindowsEventHookCollector(OnWindowEvent, OnHookFailure);
                eventHooks.Start();
            }
            catch (CandidateBindingException exception)
            {
                ApplyCandidateFailure(exception);
                SafeAppend("preflight-failure", 0, new { reasonCode = exception.ReasonCode });
                eventHooks?.Dispose();
                eventHooks = null;
                throw;
            }
            catch (Exception exception)
            {
                decision.Block("PREFLIGHT_EXCEPTION");
                SafeAppend("preflight-failure", 0, new
                {
                    reasonCode = "PREFLIGHT_EXCEPTION",
                    failureType = exception.GetType().Name,
                });
                eventHooks?.Dispose();
                eventHooks = null;
                throw;
            }

            // The monotonic coverage boundary is established only after every potentially
            // expensive file, recorder, and hook preflight has completed. Hooks are already
            // active, so windows created while the baseline is captured cannot fall in a gap.
            startedAtMilliseconds = ObservationTiming.BeginAfterPreflight(clock.Milliseconds);
            startedAtUtc = DateTimeOffset.UtcNow;
            lastLightweightAt = 0;
            lastFullAt = 0;
            started = true;
            windowPolicy = new WindowAdmissionPolicy(preflight.Windows, plan, Environment.ProcessId);
            evidence.Append("observation-start", 0, new
            {
                testRunId = plan.TestRunId,
                planSha256,
                observerExecutableSha256 = observerSha256,
                startChallenge = recording.StartChallenge,
                executionIdentity = executionIdentity.ToSummary(),
                platform = platform.ToSummary(),
                standaloneAdmissionEvidence = false,
            });

            try
            {
                var baseline = probe.Capture(enriched: true);
                foreach (var process in baseline.Processes)
                {
                    knownProcesses[process.IdentityKey] = process;
                }
                foreach (var window in baseline.Windows)
                {
                    knownWindows.Add(window.IdentityKey);
                }
                var baselineElapsed = ElapsedMilliseconds;
                CheckInitialOrTailGaps(0, 0, baselineElapsed, "START");
                lightweightCount = 1;
                fullCount = 1;
                lastLightweightAt = baselineElapsed;
                lastFullAt = baselineElapsed;
                maximumFullGap = Math.Max(maximumFullGap, baselineElapsed);
                ValidateRelevantCreationTimes(baseline, baselineElapsed);
                ValidateCandidateProcesses(baseline, baselineElapsed);
                CheckRecordingContinuity(baseline, baselineElapsed);
                AppendCandidateObservations(candidateBinding.Evidence.Where(static item => item.Observed));
                AppendRelevantSnapshot(baseline, baselineElapsed, "full-snapshot");
                var baselineProcesses = baseline.Processes
                    .GroupBy(static item => item.ProcessId)
                    .ToDictionary(static group => group.Key, static group => group.First());
                foreach (var window in baseline.Windows)
                {
                    baselineProcesses.TryGetValue(window.ProcessId, out var process);
                    if (process?.CreationTimeUtcFileTime != window.ProcessCreationTimeUtcFileTime)
                    {
                        process = null;
                    }
                    EvaluateWindow(window, process, baselineElapsed, "baseline-window", allowBaseline: true);
                }

                var readyElapsed = ElapsedMilliseconds;
                CheckInitialOrTailGaps(lastLightweightAt, lastFullAt, readyElapsed, "START_READY");
            }
            catch (Exception exception)
            {
                decision.Block("START_BOUNDARY_EXCEPTION");
                Interlocked.Increment(ref lostEventCount);
                SafeAppend("start-boundary-exception", ElapsedMilliseconds, new
                {
                    reasonCode = "START_BOUNDARY_EXCEPTION",
                    failureType = exception.GetType().Name,
                });
            }

            timer = new System.Threading.Timer(
                OnTimer,
                null,
                ObservationContract.LightweightIntervalMilliseconds,
                ObservationContract.LightweightIntervalMilliseconds);
        }
        RaiseStatusChanged();
    }

    public void CompleteCurrentAction()
    {
        lock (sync)
        {
            if (!started || ended)
            {
                throw new InvalidOperationException("Observation is not active.");
            }
            if (actionIndex >= ObservationContract.RequiredActions.Length)
            {
                return;
            }
            var action = ObservationContract.RequiredActions[actionIndex];
            var elapsed = ElapsedMilliseconds;
            decision.CompleteAction(action);
            completedActions.Add(new CompletedActionSummary(action, elapsed));
            evidence.Append("action-complete", elapsed, new { actionId = action });
            actionIndex++;
        }
        RaiseStatusChanged();
    }

    public string EndObservation()
    {
        lock (sync)
        {
            if (!started || ended)
            {
                throw new InvalidOperationException("Observation is not active.");
            }
            timer?.Dispose();
            timer = null;
            CaptureFinalEnrichedSnapshot();
            var endBoundary = clock.Milliseconds;
            var endElapsed = ObservationTiming.Elapsed(startedAtMilliseconds, endBoundary);
            CheckInitialOrTailGaps(lastLightweightAt, lastFullAt, endElapsed, "END_BOUNDARY");
            endedAtMilliseconds = endBoundary;
            ended = true;
            EndChallenge = recording.IssueEndChallenge();
            evidence.Append("observation-end-challenge", ElapsedMilliseconds, new
            {
                endChallenge = EndChallenge,
            });
        }
        RaiseStatusChanged();
        return EndChallenge;
    }

    public ObservationCompletion FinalizeEvidence()
    {
        lock (sync)
        {
            if (!ended || finalized)
            {
                throw new InvalidOperationException("End observation exactly once before finalization.");
            }
            eventHooks?.Dispose();
            eventHooks = null;
            var duration = ObservationTiming.Elapsed(startedAtMilliseconds, endedAtMilliseconds);
            try
            {
                var finalBindings = candidateBinding.VerifyAllAtEnd();
                AppendCandidateObservations(finalBindings);
            }
            catch (CandidateBindingException exception)
            {
                ApplyCandidateFailure(exception);
                SafeAppend("candidate-finalization-failure", duration, new
                {
                    reasonCode = exception.ReasonCode,
                });
            }

            RecordingCompletion recordingCompletion;
            try
            {
                recordingCompletion = recording.Complete(duration);
            }
            catch (Exception exception) when (
                exception is IOException
                or UnauthorizedAccessException
                or InvalidDataException
                or InvalidOperationException
                or CandidateBindingException)
            {
                decision.Block("RECORDING_EVIDENCE_INVALID");
                SafeAppend("recording-failure", duration, new
                {
                    reasonCode = "RECORDING_EVIDENCE_INVALID",
                    failureType = exception.GetType().Name,
                });
                recordingCompletion = new RecordingCompletion(
                    plan.Recording.MediaType,
                    0,
                    new string('0', 64),
                    duration,
                    false,
                    ObservationPrivacy.HashSensitiveText(recording.StartChallenge),
                    ObservationPrivacy.HashSensitiveText(EndChallenge ?? string.Empty));
            }

            decision.Finalize(duration, plan.MinimumObservationSeconds);
            completedAtUtc = DateTimeOffset.UtcNow;
            var provisional = BuildSummary(
                duration,
                recordingCompletion,
                new EvidenceLogCompletion(string.Empty, 1, new string('a', 64), new string('b', 64), 1));
            var eligibilityViolations = ObservationSummaryVerifier.GetEligibilityViolations(provisional, plan);
            if (eligibilityViolations.Length != 0)
            {
                decision.Block("ELIGIBILITY_INVARIANT_FAILED");
                SafeAppend("eligibility-invariant-failure", duration, new
                {
                    reasonCode = "ELIGIBILITY_INVARIANT_FAILED",
                    violations = eligibilityViolations,
                });
            }
            evidence.Append("observation-final", duration, new
            {
                verdict = decision.ToContractValue(),
                reasonCodes = decision.ReasonCodes,
                standaloneAdmissionEvidence = false,
            });
            var logCompletion = evidence.CompleteLog();
            var summary = BuildSummary(duration, recordingCompletion, logCompletion);
            ObservationSummaryVerifier.Validate(summary, plan);
            evidence.WriteSummary(summary);
            finalized = true;
            RaiseStatusChanged();
            return new ObservationCompletion(
                summary.Verdict,
                evidence.RunDirectory,
                evidence.SummaryPath,
                evidence.LogPath);
        }
    }

    public void NotifySystemInterruption(string reasonCode)
    {
        lock (sync)
        {
            if (!started || finalized)
            {
                return;
            }
            decision.Block(reasonCode);
            SafeAppend("system-interruption", ElapsedMilliseconds, new { reasonCode });
        }
        RaiseStatusChanged();
    }

    private void OnTimer(object? state)
    {
        _ = state;
        if (Interlocked.Exchange(ref samplingGate, 1) != 0)
        {
            lock (sync)
            {
                decision.Block("SAMPLING_OVERLAP");
                Interlocked.Increment(ref lostEventCount);
                SafeAppend("sampling-overlap", ElapsedMilliseconds, new
                {
                    reasonCode = "SAMPLING_OVERLAP",
                });
            }
            RaiseStatusChanged();
            return;
        }
        try
        {
            lock (sync)
            {
                if (ended || finalized)
                {
                    return;
                }
                var elapsed = ElapsedMilliseconds;
                if (!ObservationTiming.IsLightweightGapAccepted(lastLightweightAt, elapsed))
                {
                    decision.Block("LIGHTWEIGHT_SAMPLING_INTERRUPTED");
                }
                var snapshot = probe.Capture(enriched: false);
                elapsed = ElapsedMilliseconds;
                if (!ObservationTiming.IsLightweightGapAccepted(lastLightweightAt, elapsed))
                {
                    decision.Block("LIGHTWEIGHT_SAMPLING_INTERRUPTED");
                }
                lightweightCount++;
                ValidateRelevantCreationTimes(snapshot, elapsed);
                AppendDeltas(snapshot, elapsed);
                CheckRecordingContinuity(snapshot, elapsed);
                lastLightweightAt = elapsed;

                if (elapsed - lastFullAt >= 750)
                {
                    var gap = elapsed - lastFullAt;
                    maximumFullGap = Math.Max(maximumFullGap, gap);
                    if (!ObservationTiming.IsFullGapAccepted(lastFullAt, elapsed))
                    {
                        decision.Block("FULL_SNAPSHOT_INTERRUPTED");
                    }
                    var full = probe.Capture(enriched: true);
                    elapsed = ElapsedMilliseconds;
                    gap = elapsed - lastFullAt;
                    maximumFullGap = Math.Max(maximumFullGap, gap);
                    if (!ObservationTiming.IsFullGapAccepted(lastFullAt, elapsed))
                    {
                        decision.Block("FULL_SNAPSHOT_INTERRUPTED");
                    }
                    fullCount++;
                    ValidateRelevantCreationTimes(full, elapsed);
                    ValidateCandidateProcesses(full, elapsed);
                    AppendDeltas(full, elapsed);
                    AppendRelevantSnapshot(full, elapsed, "full-snapshot");
                    AppendCandidateObservations(candidateBinding.ObserveNewlyAvailable());
                    lastFullAt = elapsed;
                }
            }
        }
        catch (CandidateBindingException exception)
        {
            lock (sync)
            {
                ApplyCandidateFailure(exception);
                SafeAppend("candidate-binding-failure", ElapsedMilliseconds, new
                {
                    reasonCode = exception.ReasonCode,
                });
            }
        }
        catch (Exception exception)
        {
            lock (sync)
            {
                decision.Block("SAMPLING_EXCEPTION");
                Interlocked.Increment(ref lostEventCount);
                SafeAppend("sampling-exception", ElapsedMilliseconds, new
                {
                    reasonCode = "SAMPLING_EXCEPTION",
                    failureType = exception.GetType().Name,
                });
            }
        }
        finally
        {
            Volatile.Write(ref samplingGate, 0);
            RaiseStatusChanged();
        }
    }

    private void CheckRecordingContinuity(DesktopSnapshot snapshot, long elapsed)
    {
        if (recording.IsContinuous(snapshot))
        {
            return;
        }
        decision.Block("RECORDING_PROCESS_INTERRUPTED");
        if (!recordingInterruptionRecorded)
        {
            evidence.Append("recording-interruption", elapsed, new
            {
                reasonCode = "RECORDING_PROCESS_INTERRUPTED",
            });
            recordingInterruptionRecorded = true;
        }
    }

    private void ValidateCandidateProcesses(DesktopSnapshot snapshot, long elapsed)
    {
        foreach (var process in snapshot.Processes)
        {
            var hasCandidateImageName = candidateImageNames.Contains(process.ImageName);
            if (process.ExecutablePath is null)
            {
                if (hasCandidateImageName)
                {
                    decision.Block("PROCESS_IMAGE_PATH_UNAVAILABLE");
                    SafeAppend("process-image-path-unavailable", elapsed, new
                    {
                        reasonCode = "PROCESS_IMAGE_PATH_UNAVAILABLE",
                        processId = process.ProcessId,
                        creationTimeUtcFileTime = process.CreationTimeUtcFileTime,
                        imageName = process.ImageName,
                    });
                }
                continue;
            }
            if (!candidateFilesByPath.TryGetValue(
                    Path.GetFullPath(process.ExecutablePath),
                    out var plannedFile))
            {
                if (hasCandidateImageName)
                {
                    decision.Fail("PROCESS_IMAGE_PATH_MISMATCH");
                    SafeAppend("process-image-path-mismatch", elapsed, new
                    {
                        reasonCode = "PROCESS_IMAGE_PATH_MISMATCH",
                        processId = process.ProcessId,
                        creationTimeUtcFileTime = process.CreationTimeUtcFileTime,
                        imageName = process.ImageName,
                        observedPathSha256 = ObservationPrivacy.HashSensitiveText(
                            Path.GetFullPath(process.ExecutablePath).ToLowerInvariant()),
                    });
                }
                continue;
            }
            if (process.ExecutableSha256 is null)
            {
                decision.Block("PROCESS_IMAGE_HASH_UNAVAILABLE");
                SafeAppend("process-image-hash-unavailable", elapsed, new
                {
                    processId = process.ProcessId,
                    creationTimeUtcFileTime = process.CreationTimeUtcFileTime,
                    role = plannedFile.Role,
                });
            }
            else if (!string.Equals(
                         process.ExecutableSha256,
                         plannedFile.Sha256,
                         StringComparison.Ordinal))
            {
                decision.Fail("PROCESS_IMAGE_HASH_MISMATCH");
                SafeAppend("process-image-hash-mismatch", elapsed, new
                {
                    processId = process.ProcessId,
                    creationTimeUtcFileTime = process.CreationTimeUtcFileTime,
                    role = plannedFile.Role,
                    observedSha256 = process.ExecutableSha256,
                });
            }
        }
    }

    private void CaptureFinalEnrichedSnapshot()
    {
        var beforeCapture = ElapsedMilliseconds;
        CheckInitialOrTailGaps(lastLightweightAt, lastFullAt, beforeCapture, "TAIL");
        try
        {
            var final = probe.Capture(enriched: true);
            var elapsed = ElapsedMilliseconds;
            CheckInitialOrTailGaps(lastLightweightAt, lastFullAt, elapsed, "TAIL");
            lightweightCount++;
            fullCount++;
            ValidateRelevantCreationTimes(final, elapsed);
            ValidateCandidateProcesses(final, elapsed);
            AppendDeltas(final, elapsed);
            AppendRelevantSnapshot(final, elapsed, "final-enriched-snapshot");
            CheckRecordingContinuity(final, elapsed);
            AppendCandidateObservations(candidateBinding.ObserveNewlyAvailable());
            lastLightweightAt = elapsed;
            lastFullAt = elapsed;
        }
        catch (CandidateBindingException exception)
        {
            ApplyCandidateFailure(exception);
            decision.Block("FINAL_SNAPSHOT_EXCEPTION");
            Interlocked.Increment(ref lostEventCount);
            SafeAppend("final-snapshot-exception", ElapsedMilliseconds, new
            {
                reasonCode = "FINAL_SNAPSHOT_EXCEPTION",
                candidateReasonCode = exception.ReasonCode,
                failureType = exception.GetType().Name,
            });
        }
        catch (Exception exception)
        {
            decision.Block("FINAL_SNAPSHOT_EXCEPTION");
            Interlocked.Increment(ref lostEventCount);
            SafeAppend("final-snapshot-exception", ElapsedMilliseconds, new
            {
                reasonCode = "FINAL_SNAPSHOT_EXCEPTION",
                failureType = exception.GetType().Name,
            });
        }
    }

    private void CheckInitialOrTailGaps(
        long previousLightweightElapsed,
        long previousFullElapsed,
        long currentElapsed,
        string boundary)
    {
        if (!ObservationTiming.IsLightweightGapAccepted(previousLightweightElapsed, currentElapsed))
        {
            decision.Block("LIGHTWEIGHT_SAMPLING_INTERRUPTED");
            SafeAppend("sampling-boundary-gap", currentElapsed, new
            {
                reasonCode = "LIGHTWEIGHT_SAMPLING_INTERRUPTED",
                boundary,
                gapMilliseconds = currentElapsed - previousLightweightElapsed,
            });
        }
        var fullGap = currentElapsed - previousFullElapsed;
        maximumFullGap = Math.Max(maximumFullGap, Math.Max(0, fullGap));
        if (!ObservationTiming.IsFullGapAccepted(previousFullElapsed, currentElapsed))
        {
            decision.Block("FULL_SNAPSHOT_INTERRUPTED");
            SafeAppend("sampling-boundary-gap", currentElapsed, new
            {
                reasonCode = "FULL_SNAPSHOT_INTERRUPTED",
                boundary,
                gapMilliseconds = fullGap,
            });
        }
    }

    private void ValidateRelevantCreationTimes(DesktopSnapshot snapshot, long elapsed)
    {
        var byIdentity = snapshot.Processes
            .GroupBy(static item => item.IdentityKey, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.First(), StringComparer.Ordinal);
        foreach (var process in snapshot.Processes.Where(relevance.IsRelevant))
        {
            if (EvidenceRelevancePolicy.HasUsableCreationTime(process))
            {
                continue;
            }
            var key = $"process:{process.ProcessId}:{process.ImageName}";
            if (!identityFailures.Add(key))
            {
                continue;
            }
            decision.Block("PROCESS_CREATION_TIME_UNAVAILABLE");
            SafeAppend("process-identity-unavailable", elapsed, new
            {
                reasonCode = "PROCESS_CREATION_TIME_UNAVAILABLE",
                process = process.ToEvidence(),
            });
        }

        foreach (var window in snapshot.Windows)
        {
            byIdentity.TryGetValue(
                $"{window.ProcessId}:{window.ProcessCreationTimeUtcFileTime}",
                out var process);
            var admission = windowPolicy?.Evaluate(window, process?.CandidateRelated == true)
                ?? WindowAdmissionResult.Blocked;
            if ((relevance.IsRelevant(window, process)
                    || admission != WindowAdmissionResult.Allowed)
                && !EvidenceRelevancePolicy.HasUsableCreationTime(window))
            {
                RecordWindowIdentityFailure(window, elapsed);
            }
        }
    }

    private void RecordWindowIdentityFailure(WindowObservation window, long elapsed)
    {
        var key = $"window:{window.WindowHandle:x}:{window.ProcessId}:{window.ProcessImageName}";
        if (!identityFailures.Add(key))
        {
            return;
        }
        decision.Block("WINDOW_PROCESS_CREATION_TIME_UNAVAILABLE");
        SafeAppend("window-process-identity-unavailable", elapsed, new
        {
            reasonCode = "WINDOW_PROCESS_CREATION_TIME_UNAVAILABLE",
            window,
        });
    }

    private void AppendDeltas(DesktopSnapshot snapshot, long elapsed)
    {
        var byIdentity = snapshot.Processes
            .GroupBy(static item => item.IdentityKey, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.First(), StringComparer.Ordinal);
        foreach (var process in snapshot.Processes)
        {
            if (knownProcesses.TryAdd(process.IdentityKey, process))
            {
                if (relevance.IsRelevant(process))
                {
                    evidence.Append("process-create", elapsed, process.ToEvidence());
                }
            }
            else if (process.ExecutablePath is not null)
            {
                knownProcesses[process.IdentityKey] = process;
            }
        }
        foreach (var window in snapshot.Windows)
        {
            if (!knownWindows.Add(window.IdentityKey))
            {
                continue;
            }
            byIdentity.TryGetValue(
                $"{window.ProcessId}:{window.ProcessCreationTimeUtcFileTime}",
                out var process);
            EvaluateWindow(window, process, elapsed, "window-create", allowBaseline: false);
        }
    }

    private void AppendRelevantSnapshot(DesktopSnapshot snapshot, long elapsed, string eventType)
    {
        var relevantProcesses = snapshot.Processes
            .Where(relevance.IsRelevant)
            .Select(static item => item.ToEvidence())
            .ToArray();
        var relevantIdentities = snapshot.Processes
            .Where(relevance.IsRelevant)
            .Select(static item => item.IdentityKey)
            .ToHashSet(StringComparer.Ordinal);
        var relevantWindows = snapshot.Windows
            .Where(item =>
            {
                var process = snapshot.Processes.FirstOrDefault(candidate =>
                    candidate.ProcessId == item.ProcessId
                    && candidate.CreationTimeUtcFileTime == item.ProcessCreationTimeUtcFileTime);
                return relevantIdentities.Contains(
                        $"{item.ProcessId}:{item.ProcessCreationTimeUtcFileTime}")
                    || relevance.IsRelevant(item, process);
            })
            .ToArray();
        evidence.Append(eventType, elapsed, new
        {
            processes = relevantProcesses,
            windows = relevantWindows,
        });
    }

    private void OnWindowEvent(string eventName, WindowObservation window)
    {
        lock (sync)
        {
            if (!started || finalized)
            {
                return;
            }
            var elapsed = ElapsedMilliseconds;
            knownProcesses.TryGetValue(
                $"{window.ProcessId}:{window.ProcessCreationTimeUtcFileTime}",
                out var process);
            EvaluateWindow(
                window,
                process,
                elapsed,
                $"win-event-{eventName.ToLowerInvariant()}",
                allowBaseline: string.Equals(eventName, "FOREGROUND", StringComparison.Ordinal));
            knownWindows.Add(window.IdentityKey);
        }
        RaiseStatusChanged();
    }

    private void EvaluateWindow(
        WindowObservation window,
        ProcessObservation? process,
        long elapsed,
        string sourceEvent,
        bool allowBaseline)
    {
        if (windowPolicy is null)
        {
            return;
        }
        var admission = windowPolicy.Evaluate(
            window,
            process?.CandidateRelated == true,
            allowBaseline);
        var isRelevant = relevance.IsRelevant(window, process)
            || admission != WindowAdmissionResult.Allowed;
        if (isRelevant && !EvidenceRelevancePolicy.HasUsableCreationTime(window))
        {
            RecordWindowIdentityFailure(window, elapsed);
        }
        if (isRelevant)
        {
            SafeAppend(sourceEvent, elapsed, new { window });
        }
        if (admission == WindowAdmissionResult.Allowed)
        {
            return;
        }
        if (admission == WindowAdmissionResult.Blocked)
        {
            decision.Block("WINDOW_PROCESS_IDENTITY_UNAVAILABLE");
            SafeAppend("window-identity-unavailable", elapsed, new
            {
                reasonCode = "WINDOW_PROCESS_IDENTITY_UNAVAILABLE",
                window,
            });
            return;
        }
        decision.Fail("UNEXPECTED_WINDOW");
        if (unexpectedWindows.Count < 64
            && !unexpectedWindows.Any(item =>
                item.FirstSeenMonotonicMilliseconds == elapsed
                && string.Equals(item.TitleSha256, window.TitleSha256, StringComparison.Ordinal)
                && string.Equals(item.ProcessImageName, window.ProcessImageName, StringComparison.OrdinalIgnoreCase)))
        {
            unexpectedWindows.Add(new UnexpectedWindowSummary(
                window.ProcessImageName,
                window.ClassName,
                window.TitleSha256,
                window.TitleCategory,
                elapsed));
        }
        SafeAppend("unexpected-window", elapsed, new
        {
            reasonCode = "UNEXPECTED_WINDOW",
            window,
        });
    }

    private void OnHookFailure(string failureType)
    {
        lock (sync)
        {
            if (finalized)
            {
                return;
            }
            decision.Block("WIN_EVENT_HOOK_LOSS");
            Interlocked.Increment(ref lostEventCount);
            SafeAppend("win-event-hook-loss", ElapsedMilliseconds, new
            {
                reasonCode = "WIN_EVENT_HOOK_LOSS",
                failureType,
            });
        }
        RaiseStatusChanged();
    }

    private void AppendCandidateObservations(IEnumerable<CandidateFileEvidence> bindings)
    {
        foreach (var binding in bindings)
        {
            evidence.Append("candidate-file-observed", ElapsedMilliseconds, new
            {
                role = binding.Role,
                sha256 = binding.Sha256,
                sizeBytes = binding.SizeBytes,
                observed = binding.Observed,
            });
        }
    }

    private void ApplyCandidateFailure(CandidateBindingException exception)
    {
        if (exception.ReasonCode is "CANDIDATE_FILE_MISSING"
            || exception.ReasonCode.StartsWith("RECORDER_", StringComparison.Ordinal))
        {
            decision.Block(exception.ReasonCode);
        }
        else
        {
            decision.Fail(exception.ReasonCode);
        }
    }

    private void SafeAppend(string eventType, long elapsed, object data)
    {
        try
        {
            evidence.Append(eventType, elapsed, data);
        }
        catch (Exception exception) when (
            exception is IOException
            or UnauthorizedAccessException
            or InvalidDataException
            or ObjectDisposedException)
        {
            decision.Block("EVIDENCE_WRITE_FAILURE");
        }
    }

    private ObservationSummary BuildSummary(
        long duration,
        RecordingCompletion recordingCompletion,
        EvidenceLogCompletion logCompletion)
    {
        var candidateEvidence = candidateBinding.Evidence;
        return new ObservationSummary
        {
            StandaloneAdmissionEvidence = false,
            TestRunId = plan.TestRunId,
            Edition = plan.Edition,
            Verdict = decision.ToContractValue(),
            ReasonCodes = decision.ReasonCodes,
            PlanSha256 = planSha256,
            ObserverExecutableSha256 = observerSha256,
            StartedAtUtc = startedAtUtc.ToString("O"),
            CompletedAtUtc = (completedAtUtc ?? DateTimeOffset.UtcNow).ToString("O"),
            MonotonicDurationMilliseconds = duration,
            Sampling = new SamplingSummary(
                ObservationContract.LightweightIntervalMilliseconds,
                ObservationContract.FullSnapshotMaximumIntervalMilliseconds,
                lightweightCount,
                fullCount,
                maximumFullGap,
                Interlocked.Read(ref lostEventCount)),
            ExecutionIdentity = executionIdentity.ToSummary(),
            Platform = platform.ToSummary(),
            Candidate = new CandidateSummary(
                plan.Candidate.ReleaseSetId,
                plan.Candidate.Generation,
                plan.Candidate.Sequence,
                plan.Candidate.LauncherRepositoryCommit,
                plan.Candidate.HarnessSourceTag,
                plan.Candidate.HarnessSourceCommit,
                candidateEvidence.Select(static item => new CandidateFileSummary(
                    item.Role,
                    item.Sha256,
                    item.SizeBytes,
                    item.Observed)).ToArray()),
            Actions = completedActions.ToArray(),
            Recording = new RecordingSummary(
                recordingCompletion.MediaType,
                recordingCompletion.SizeBytes,
                recordingCompletion.Sha256,
                recordingCompletion.CoverageMilliseconds,
                recordingCompletion.AudioCaptured,
                recordingCompletion.StartChallengeSha256,
                recordingCompletion.EndChallengeSha256),
            EvidenceLog = new EvidenceLogSummary(
                "application/x-ndjson",
                logCompletion.SizeBytes,
                logCompletion.Sha256,
                logCompletion.TerminalRecordSha256,
                logCompletion.RecordCount),
            UnexpectedWindows = unexpectedWindows.ToArray(),
        };
    }

    private void RaiseStatusChanged() => StatusChanged?.Invoke(this, EventArgs.Empty);

    public void Dispose()
    {
        timer?.Dispose();
        eventHooks?.Dispose();
        evidence.Dispose();
    }
}
