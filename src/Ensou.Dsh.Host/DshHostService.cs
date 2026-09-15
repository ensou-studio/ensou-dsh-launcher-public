using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Host;

public sealed class DshHostService : IAsyncDisposable
{
    private const int MaximumHealthResponseBytes = 1024 * 1024;
    private const string OfficialWebUiTitle = "<title>DeepSeek Harness</title>";
    private const string SourceBuildWebUiTitle = "<title>DSH Local Build</title>";
    private readonly DshRuntimeOptions _options;
    private readonly DshRuntimeWebAuthProtocol _webAuthProtocol;
    private readonly HttpClient _httpClient;
    private readonly Action _validateBeforeProcessStart;
    private readonly Action<Process> _validateBeforeResume;
    private readonly Func<Process, int, bool> _ownsLoopbackListener;
    private readonly bool _allowUnleasedRuntimeAdmissionForTests;
    private readonly TimeSpan _healthProbeTimeout;
    private readonly TimeSpan _candidateHealthRetryTimeout;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _browserAuthGate = new();
    private readonly DshUnassignedProcessContainment _unassignedProcessContainment =
        new();
    private Process? _ownedProcess;
    private DshRuntimeLaunchLease? _runtimeLaunchLease;
    private RuntimeUpdateChannelBinding? _runtimeUpdateChannel;
    private Process? _managedUpdateChannelLeaseProcess;
    private readonly object _runtimeUpdateChannelLifetimeGate = new();
    private readonly ManagedUpdateStopArbitration _managedUpdateStopArbitration = new();
    private IDshHomeWriterSession? _homeWriterSession;
    private readonly Func<IDshHomeWriterSession>? _acquireHomeWriterSession;
    private readonly Action<string, Exception?>? _diagnostic;
    private Task? _standardOutputPump;
    private Task? _standardErrorPump;
    private WindowsJobObject? _jobObject;
    private EventHandler? _ownedProcessExitHandler;
    private TaskCompletionSource<Uri>? _browserLaunchReady;
    private DshBrowserSession? _browserSession;
    private Process? _browserAuthProcess;
    private bool _disposed;

    public DshHostService(
        DshRuntimeOptions options,
        Action validateBeforeProcessStart,
        HttpClient? httpClient = null,
        TimeSpan? healthProbeTimeout = null,
        TimeSpan? candidateHealthRetryTimeout = null,
        Action<Process>? validateBeforeResume = null,
        Func<IDshHomeWriterSession>? acquireHomeWriterSession = null)
        : this(
            options,
            validateBeforeProcessStart,
            httpClient,
            healthProbeTimeout,
            candidateHealthRetryTimeout,
            validateBeforeResume,
            acquireHomeWriterSession,
            diagnostic: null)
    {
    }

    public DshHostService(
        DshRuntimeOptions options,
        Action validateBeforeProcessStart,
        HttpClient? httpClient,
        TimeSpan? healthProbeTimeout,
        TimeSpan? candidateHealthRetryTimeout,
        Action<Process>? validateBeforeResume,
        Func<IDshHomeWriterSession>? acquireHomeWriterSession,
        Action<string, Exception?>? diagnostic)
        : this(
            options,
            httpClient,
            validateBeforeProcessStart
                ?? throw new ArgumentNullException(
                    nameof(validateBeforeProcessStart)),
            healthProbeTimeout,
            candidateHealthRetryTimeout,
            validateBeforeResume,
            DshLoopbackListenerOwnership
                .IsExactProcessListeningOnIpv4Loopback,
            allowUnleasedRuntimeAdmissionForTests: false,
            acquireHomeWriterSession,
            diagnostic)
    {
    }

    internal DshHostService(DshRuntimeOptions options)
        : this(options, httpClient: null)
    {
    }

    internal DshHostService(
        DshRuntimeOptions options,
        HttpClient? httpClient)
        : this(
            options,
            httpClient,
            validateBeforeProcessStart: null,
            healthProbeTimeout: null,
            candidateHealthRetryTimeout: null,
            validateBeforeResume: null,
            DshLoopbackListenerOwnership
                .IsExactProcessListeningOnIpv4Loopback,
            allowUnleasedRuntimeAdmissionForTests: true)
    {
    }

    internal DshHostService(
        DshRuntimeOptions options,
        HttpClient? httpClient,
        Action? validateBeforeProcessStart,
        TimeSpan? healthProbeTimeout,
        TimeSpan? candidateHealthRetryTimeout,
        Func<Process, int, bool> ownsLoopbackListener)
        : this(
            options,
            httpClient,
            validateBeforeProcessStart,
            healthProbeTimeout,
            candidateHealthRetryTimeout,
            validateBeforeResume: null,
            ownsLoopbackListener,
            allowUnleasedRuntimeAdmissionForTests: true)
    {
    }

    private DshHostService(
        DshRuntimeOptions options,
        HttpClient? httpClient,
        Action? validateBeforeProcessStart,
        TimeSpan? healthProbeTimeout,
        TimeSpan? candidateHealthRetryTimeout,
        Action<Process>? validateBeforeResume,
        Func<Process, int, bool> ownsLoopbackListener,
        bool allowUnleasedRuntimeAdmissionForTests,
        Func<IDshHomeWriterSession>? acquireHomeWriterSession = null,
        Action<string, Exception?>? diagnostic = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _acquireHomeWriterSession = acquireHomeWriterSession;
        _diagnostic = diagnostic;
        _webAuthProtocol = _options.WebAuthProtocol;
        _httpClient = httpClient ?? new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
        })
        {
            Timeout = TimeSpan.FromSeconds(2),
        };
        _validateBeforeProcessStart = validateBeforeProcessStart ?? (() => { });
        _validateBeforeResume = validateBeforeResume ?? (_ => { });
        _ownsLoopbackListener = ownsLoopbackListener
            ?? throw new ArgumentNullException(nameof(ownsLoopbackListener));
        _allowUnleasedRuntimeAdmissionForTests =
            allowUnleasedRuntimeAdmissionForTests;
        _healthProbeTimeout = healthProbeTimeout ?? TimeSpan.FromSeconds(2);
        if (_healthProbeTimeout < TimeSpan.FromMilliseconds(100)
            || _healthProbeTimeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(healthProbeTimeout));
        }
        _candidateHealthRetryTimeout = candidateHealthRetryTimeout
            ?? TimeSpan.FromSeconds(30);
        if (_candidateHealthRetryTimeout < TimeSpan.FromMilliseconds(100)
            || _candidateHealthRetryTimeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(
                nameof(candidateHealthRetryTimeout));
        }
    }

    public Uri WebUiUri => _options.WebUiUri;

    public bool OwnsRunningProcess => _ownedProcess is { HasExited: false };

    private void Observe(string phase, Exception? exception = null)
    {
        try { _diagnostic?.Invoke(phase, exception); }
        catch { /* Diagnostics cannot alter runtime admission or cleanup. */ }
    }

    public async Task<DshLaunchResult> EnsureStartedAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _unassignedProcessContainment.RetryTerminationOrThrow();
            if (_ownedProcess is { HasExited: true } exitedProcess)
            {
                await ReleaseOwnedProcessAsync(exitedProcess).ConfigureAwait(false);
            }

            if (await IsHealthyAsync(cancellationToken).ConfigureAwait(false))
            {
                return new DshLaunchResult(
                    DshLaunchState.AlreadyHealthy,
                    WebUiUri,
                    OwnsRunningProcess ? _ownedProcess?.Id : null);
            }

            if (_ownedProcess is { HasExited: false })
            {
                return await RunOwnedStartupWithFailStopAsync(
                        _ownedProcess,
                        () => WaitUntilHealthyAsync(_ownedProcess, cancellationToken))
                    .ConfigureAwait(false);
            }

            Observe("host_home_session_begin");
            var homeWriterSession = _acquireHomeWriterSession?.Invoke();
            Observe("host_home_session_end");
            DshRuntimeLaunchLease? runtimeLaunchLease = null;
            DshRuntimeUpdateChannel? runtimeUpdateChannel = null;
            ProcessStartInfo? startInfo = null;
            WindowsJobObject? jobObject = null;
            WindowsJobStartedProcess? suspendedStart = null;
            Process? process = null;
            try
            {
                if (_allowUnleasedRuntimeAdmissionForTests
                    && homeWriterSession is IDshAtomicHomeWriterSession)
                {
                    throw new InvalidOperationException(
                        "An atomic home generation cannot use unleased test process creation.");
                }
                Observe("host_job_create_begin");
                jobObject = WindowsJobObject.CreateKillOnClose(
                    homeWriterSession?.JobName,
                    homeWriterSession is null ? null : () =>
                    {
                        Observe("host_job_empty_observed");
                        homeWriterSession.RecordJobEmpty();
                        Observe("host_job_empty_recorded");
                    });
                Observe("host_job_create_end");
                _options.Validate();
                EnsureRuntimeProtocolUnchanged();
                ClearBrowserAuthState();
                Directory.CreateDirectory(_options.DataDirectory);
                if (_options.CaptureRawProcessOutput) Directory.CreateDirectory(_options.LogDirectory);
                if (_options.EnablePersonalManagedUpdate
                    && homeWriterSession is not IDshAtomicHomeWriterSession)
                {
                    throw new InvalidOperationException(
                        "Personal managed-update control requires an active atomic home writer session.");
                }
                if (_options.SupportsManagedUpdate)
                {
                    if (!OperatingSystem.IsWindows())
                    {
                        throw new PlatformNotSupportedException(
                            "Managed runtime update control requires Windows.");
                    }
                    runtimeUpdateChannel = DshRuntimeUpdateChannel.Create(
                        candidate => IsExactManagedUpdateRuntime(candidate));
                }
                startInfo = CreateStartInfo(runtimeUpdateChannel);
                Observe("host_runtime_lease_begin");
                runtimeLaunchLease = DshRuntimeLaunchLease.Acquire(_options, _validateBeforeProcessStart);
                Observe("host_runtime_lease_end");
                Observe("host_inventory_begin");
                runtimeLaunchLease.RequireCompleteInventoryStillCurrent();
                Observe("host_inventory_end");
                if (_allowUnleasedRuntimeAdmissionForTests)
                {
                    process = Process.Start(startInfo)
                        ?? throw new InvalidOperationException(
                            "Windows did not start the bundled DSH test process.");
                    jobObject.Assign(process);
                    runtimeLaunchLease.RequireProcessImage(process);
                    runtimeLaunchLease.RequireCompleteInventoryStillCurrent();
                }
                else
                {
                    Observe("host_suspended_start_begin");
                    Action<Process> validateSuspendedProcess = suspendedProcess =>
                        {
                            Observe("host_suspended_start_assigned");
                            homeWriterSession?.RecordAssignedProcess(suspendedProcess.Id, suspendedProcess.StartTime.ToUniversalTime().ToFileTimeUtc());
                            runtimeLaunchLease.RequireProcessImage(suspendedProcess);
                            runtimeLaunchLease.RequireCompleteInventoryStillCurrent();
                            _validateBeforeResume(suspendedProcess);
                            runtimeLaunchLease.RequireProcessImage(suspendedProcess);
                            runtimeLaunchLease.RequireCompleteInventoryStillCurrent();
                            Observe("host_suspended_start_validated");
                        };
                    suspendedStart = homeWriterSession is IDshAtomicHomeWriterSession
                        ? jobObject.StartAtomicSuspended(startInfo, validateSuspendedProcess)
                        : jobObject.StartSuspended(startInfo, validateSuspendedProcess);
                    Observe("host_suspended_start_end");
                    process = suspendedStart.Process;
                    runtimeLaunchLease.RequireProcessImage(process);
                    runtimeLaunchLease.RequireCompleteInventoryStillCurrent();
                }
            }
            catch (Exception launchFailure)
            {
                if (runtimeUpdateChannel is not null && OperatingSystem.IsWindows())
                {
                    runtimeUpdateChannel.Dispose();
                }
                Observe("host_admission_failed", launchFailure);
                Exception effectiveLaunchFailure = launchFailure;
                if (jobObject is null)
                {
                    try { homeWriterSession?.RecordNeverStarted(); }
                    catch (Exception recordFailure)
                    {
                        effectiveLaunchFailure = new AggregateException(
                            "DSH did not create a process, but recording that evidence also failed.",
                            effectiveLaunchFailure, recordFailure);
                    }
                }
                if (launchFailure is WindowsSuspendedProcessContainmentException
                    containmentFailure)
                {
                    process = containmentFailure.Process;
                }
                try
                {
                    suspendedStart?.Dispose();
                }
                catch (Exception readerCleanupFailure)
                {
                    effectiveLaunchFailure = new AggregateException(
                        "DSH suspended launch failed and pipe ownership cleanup also failed.",
                        effectiveLaunchFailure,
                        readerCleanupFailure);
                }
                _unassignedProcessContainment.ThrowAfterLaunchFailure(
                    process,
                    effectiveLaunchFailure,
                    jobObject,
                    new HomeRuntimeAdmissionResources(runtimeLaunchLease, homeWriterSession));
            }

            StreamReader? admittedStandardOutput = null;
            StreamReader? admittedStandardError = null;
            if (suspendedStart is not null)
            {
                (admittedStandardOutput, admittedStandardError) =
                    suspendedStart.DetachReaders();
                suspendedStart.Dispose();
            }
            else if (startInfo.RedirectStandardOutput)
            {
                admittedStandardOutput = process.StandardOutput;
                admittedStandardError = process.StandardError;
            }

            _jobObject = jobObject;
            _runtimeLaunchLease = runtimeLaunchLease;
            _homeWriterSession = homeWriterSession;
            Volatile.Write(ref _ownedProcess, process);
            if (runtimeUpdateChannel is not null)
            {
                Volatile.Write(
                    ref _runtimeUpdateChannel,
                    new RuntimeUpdateChannelBinding(process, runtimeUpdateChannel));
            }
            return await RunOwnedStartupWithFailStopAsync(process, async () =>
            {
                try
                {
                    if (_webAuthProtocol == DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1)
                    {
                        InitializeBrowserAuthState(process);
                    }
                    EventHandler exitHandler = (_, _) =>
                        HandleOwnedProcessExited(process, jobObject);
                    _ownedProcessExitHandler = exitHandler;
                    process.Exited += exitHandler;
                    process.EnableRaisingEvents = true;
                    if (startInfo.RedirectStandardOutput)
                    {
                        var timestamp = _options.CaptureRawProcessOutput
                            ? DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)
                            : null;
                        _standardOutputPump = PumpProcessOutputAsync(
                            admittedStandardOutput
                                ?? throw new InvalidOperationException(
                                    "Admitted DSH stdout ownership is missing."),
                            timestamp is null
                                ? null
                                : Path.Combine(_options.LogDirectory, $"dsh-{timestamp}.stdout.log"),
                            process);
                        admittedStandardOutput = null;
                        _standardErrorPump = PumpProcessOutputAsync(
                            admittedStandardError
                                ?? throw new InvalidOperationException(
                                    "Admitted DSH stderr ownership is missing."),
                            timestamp is null
                                ? null
                                : Path.Combine(_options.LogDirectory, $"dsh-{timestamp}.stderr.log"),
                            process);
                        admittedStandardError = null;
                    }

                    var launchResult = await WaitUntilHealthyAsync(process, cancellationToken)
                        .ConfigureAwait(false);
                    if (_options.SupportsManagedUpdate)
                    {
                        if (!OperatingSystem.IsWindows())
                        {
                            throw new PlatformNotSupportedException(
                                "Managed runtime update control requires Windows.");
                        }
                        var binding = Volatile.Read(ref _runtimeUpdateChannel);
                        if (binding is null || !ReferenceEquals(binding.Process, process))
                        {
                            throw new InvalidOperationException(
                                "The managed DSH runtime update channel was not retained for its exact process.");
                        }
                        await binding.Channel.AttachAsync(process, cancellationToken)
                            .ConfigureAwait(false);
                    }

                    return launchResult;
                }
                finally
                {
                    admittedStandardOutput?.Dispose();
                    admittedStandardError?.Dispose();
                }
            })
                .ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var expectedProcess = TryGetOwnedProcessForHealth();
        if (expectedProcess is null)
        {
            return false;
        }
        var expectedRuntimeLaunchLease = Volatile.Read(
            ref _runtimeLaunchLease);
        RequireRuntimeLaunchLeaseForHealth(expectedRuntimeLaunchLease);
        if (!IsSameOwnedProcessHealthy(expectedProcess)
            || !_ownsLoopbackListener(expectedProcess, _options.Port))
        {
            return false;
        }
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            timeout.CancelAfter(_healthProbeTimeout);
            using var request = new HttpRequestMessage(HttpMethod.Get, WebUiUri);
            if (_webAuthProtocol == DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1)
            {
                if (!TryGetCurrentBrowserSession(out var session))
                {
                    return false;
                }
                DshBrowserAuthentication.ApplyCookie(request, session);
            }
            using var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > 1024 * 1024)
            {
                return false;
            }

            var html = await ReadHealthPageAsync(response.Content, timeout.Token)
                .ConfigureAwait(false);
            var hasRecognizedTitle = html.Contains(
                    OfficialWebUiTitle,
                    StringComparison.Ordinal)
                || html.Contains(SourceBuildWebUiTitle, StringComparison.Ordinal);
            RequireRuntimeLaunchLeaseForHealth(expectedRuntimeLaunchLease);
            return hasRecognizedTitle
                && html.Contains("__DSH_BOOT__", StringComparison.Ordinal)
                && IsSameOwnedProcessHealthy(expectedProcess)
                && ReferenceEquals(
                    Volatile.Read(ref _runtimeLaunchLease),
                    expectedRuntimeLaunchLease)
                && _ownsLoopbackListener(expectedProcess, _options.Port);
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private Process? TryGetOwnedProcessForHealth()
    {
        var process = Volatile.Read(ref _ownedProcess);
        if (process is null)
        {
            return null;
        }
        try
        {
            return !process.HasExited
                && ReferenceEquals(Volatile.Read(ref _ownedProcess), process)
                    ? process
                    : null;
        }
        catch (Exception exception) when (exception is
            InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    private bool IsSameOwnedProcessHealthy(Process expectedProcess) =>
        ReferenceEquals(TryGetOwnedProcessForHealth(), expectedProcess);

    private void RequireRuntimeLaunchLeaseForHealth(
        DshRuntimeLaunchLease? runtimeLaunchLease)
    {
        if (runtimeLaunchLease is null)
        {
            if (_allowUnleasedRuntimeAdmissionForTests)
            {
                return;
            }
            throw new InvalidOperationException(
                "The exact owned DSH process has no retained runtime admission lease.");
        }
        runtimeLaunchLease.RequireFilesStillCurrent();
    }

    private void RequireCompleteRuntimeInventoryForCandidate(
        DshRuntimeLaunchLease? runtimeLaunchLease)
    {
        if (runtimeLaunchLease is null)
        {
            if (_allowUnleasedRuntimeAdmissionForTests)
            {
                return;
            }
            throw new InvalidOperationException(
                "The exact candidate DSH process has no retained complete runtime inventory.");
        }
        runtimeLaunchLease.RequireCompleteInventoryStillCurrent();
    }

    private bool IsSameOwnedRuntimeEndpoint(
        Process expectedProcess,
        DshRuntimeLaunchLease? expectedRuntimeLaunchLease)
    {
        if (!IsSameOwnedProcessHealthy(expectedProcess)
            || !ReferenceEquals(
                Volatile.Read(ref _runtimeLaunchLease),
                expectedRuntimeLaunchLease))
        {
            return false;
        }
        RequireRuntimeLaunchLeaseForHealth(expectedRuntimeLaunchLease);
        return IsSameOwnedProcessHealthy(expectedProcess)
            && ReferenceEquals(
                Volatile.Read(ref _runtimeLaunchLease),
                expectedRuntimeLaunchLease)
            && _ownsLoopbackListener(expectedProcess, _options.Port);
    }

    private bool IsExactManagedUpdateRuntime(Process candidate)
    {
        var expectedRuntimeLaunchLease = Volatile.Read(ref _runtimeLaunchLease);
        if (!ReferenceEquals(Volatile.Read(ref _ownedProcess), candidate)
            || candidate.HasExited)
        {
            return false;
        }

        if (!ReferenceEquals(
                Volatile.Read(ref _managedUpdateChannelLeaseProcess),
                candidate))
        {
            // Initial attachment and every exchange outside a retained managed
            // update cycle still require the exact process to own the listener.
            return IsSameOwnedRuntimeEndpoint(
                candidate,
                expectedRuntimeLaunchLease);
        }

        // Drain deliberately closes HTTP admission before it can report ready.
        // While this exact process owns the managed-update channel lease, retain
        // every other admission proof and replace only the listener check with a
        // complete inventory revalidation. The channel independently verifies
        // that its connected named-pipe client is this same OS process ID.
        if (expectedRuntimeLaunchLease is null)
        {
            throw new InvalidOperationException(
                "The exact managed runtime has no retained runtime admission lease.");
        }
        RequireCompleteRuntimeInventoryForCandidate(expectedRuntimeLaunchLease);
        return ReferenceEquals(Volatile.Read(ref _ownedProcess), candidate)
            && !candidate.HasExited
            && ReferenceEquals(
                Volatile.Read(ref _runtimeLaunchLease),
                expectedRuntimeLaunchLease)
            && ReferenceEquals(
                Volatile.Read(ref _managedUpdateChannelLeaseProcess),
                candidate);
    }

    private void RequireManagedUpdateEndpointRestored(Process process)
    {
        var expectedRuntimeLaunchLease = Volatile.Read(ref _runtimeLaunchLease);
        if (expectedRuntimeLaunchLease is null)
        {
            throw new InvalidOperationException(
                "The exact managed runtime has no retained runtime admission lease.");
        }
        RequireCompleteRuntimeInventoryForCandidate(expectedRuntimeLaunchLease);
        if (!IsSameOwnedRuntimeEndpoint(process, expectedRuntimeLaunchLease))
        {
            throw new UnauthorizedAccessException(
                "The exact managed runtime did not restore its authenticated loopback endpoint.");
        }
    }

    public async Task OpenWebUiAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!await IsHealthyAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new InvalidOperationException(
                    "The DSH WebUI is unavailable because no authenticated Harness process is healthy.");
            }

            DshBrowserLauncher.Open(GetBrowserLaunchUriForResult());
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> IsCandidateInstallHealthyAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var readiness = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        readiness.CancelAfter(_candidateHealthRetryTimeout);
        try
        {
            while (true)
            {
                if (await ProbeCandidateInstallHealthOnceAsync(readiness.Token)
                        .ConfigureAwait(false))
                {
                    return true;
                }

                await Task.Delay(
                        TimeSpan.FromMilliseconds(250),
                        readiness.Token)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }

    private async Task<bool> ProbeCandidateInstallHealthOnceAsync(
        CancellationToken cancellationToken)
    {
        if (!await IsHealthyAsync(cancellationToken).ConfigureAwait(false))
        {
            return false;
        }
        var expectedProcess = TryGetOwnedProcessForHealth();
        var expectedRuntimeLaunchLease = Volatile.Read(
            ref _runtimeLaunchLease);
        if (expectedProcess is null
            || !IsSameOwnedRuntimeEndpoint(
                expectedProcess,
                expectedRuntimeLaunchLease))
        {
            return false;
        }

        var rpcId = $"candidate-install-health-{Guid.NewGuid():N}";
        var requestBytes = _webAuthProtocol == DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1
            ? JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "client-request",
                rpcId,
                method = "session/list",
                payload = new
                {
                    args = new
                    {
                        _request = new { },
                    },
                },
            })
            : JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "client-request",
                rpcId,
                method = "session.list",
                payload = new { },
            });
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            timeout.CancelAfter(_healthProbeTimeout);
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                new Uri(
                    WebUiUri,
                    _webAuthProtocol == DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1
                        ? "api/session/list"
                        : "api/session.list"))
            {
                Content = new ByteArrayContent(requestBytes),
            };
            request.Content.Headers.ContentType = new("application/json");
            if (_webAuthProtocol == DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1)
            {
                if (!TryGetCurrentBrowserSession(out var session))
                {
                    return false;
                }
                DshBrowserAuthentication.ApplyCookie(request, session);
            }
            using var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode
                || !string.Equals(
                    response.Content.Headers.ContentType?.MediaType,
                    "application/json",
                    StringComparison.OrdinalIgnoreCase)
                || response.Content.Headers.ContentLength > MaximumHealthResponseBytes)
            {
                return false;
            }

            var responseBytes = await ReadBoundedHealthResponseAsync(
                response.Content,
                timeout.Token).ConfigureAwait(false);
            if (responseBytes is null)
            {
                return false;
            }

            try
            {
                using var document = JsonDocument.Parse(
                    responseBytes,
                    new JsonDocumentOptions
                    {
                        AllowTrailingCommas = false,
                        CommentHandling = JsonCommentHandling.Disallow,
                        MaxDepth = 32,
                    });
                if (!IsValidCandidateSessionListResponse(
                        document.RootElement,
                        rpcId)
                    || !IsSameOwnedRuntimeEndpoint(
                        expectedProcess,
                        expectedRuntimeLaunchLease))
                {
                    return false;
                }
                RequireCompleteRuntimeInventoryForCandidate(
                    expectedRuntimeLaunchLease);
                return IsSameOwnedRuntimeEndpoint(
                    expectedProcess,
                    expectedRuntimeLaunchLease);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(responseBytes);
            }
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public async Task<bool> CompleteCandidateInstallHealthAsync(
        int expectedProcessId,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (expectedProcessId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedProcessId));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _unassignedProcessContainment.RetryTerminationOrThrow();
            var process = _ownedProcess;
            var expectedRuntimeLaunchLease = Volatile.Read(
                ref _runtimeLaunchLease);
            if (process is null
                || process.HasExited
                || process.Id != expectedProcessId
                || !IsSameOwnedRuntimeEndpoint(
                    process,
                    expectedRuntimeLaunchLease))
            {
                return false;
            }

            if (!await IsCandidateInstallHealthyAsync(cancellationToken)
                    .ConfigureAwait(false)
                || !ReferenceEquals(_ownedProcess, process)
                || process.HasExited
                || process.Id != expectedProcessId
                || !IsSameOwnedRuntimeEndpoint(
                    process,
                    expectedRuntimeLaunchLease))
            {
                return false;
            }

            // The health decision is committed only after this exact process is
            // still alive and is stopped by us. If it exits in the check/kill
            // window, Kill throws and the Bootstrapper never receives a signal.
            ClearBrowserAuthState(process);
            var candidateStillOwned = true;
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException) when (process.HasExited)
            {
                candidateStillOwned = false;
            }
            catch (Exception terminationException) when (terminationException is
                NotSupportedException
                or System.ComponentModel.Win32Exception)
            {
                try
                {
                    await ReleaseOwnedProcessAsync(process).ConfigureAwait(false);
                }
                catch (Exception cleanupException)
                {
                    throw new AggregateException(
                        "Candidate health passed, but the exact DSH process could not be terminated and released.",
                        terminationException,
                        cleanupException);
                }
                throw;
            }

            await ReleaseOwnedProcessAsync(process).ConfigureAwait(false);
            return candidateStillOwned;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task StopOwnedProcessAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var priorityStop = _managedUpdateStopArbitration.BeginPriorityStop();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _unassignedProcessContainment.RetryTerminationOrThrow();
            var process = _ownedProcess;
            if (process is null)
            {
                if (_runtimeLaunchLease is not null
                    || !_allowUnleasedRuntimeAdmissionForTests
                        && _jobObject is not null)
                {
                    throw new InvalidOperationException(
                        "A DSH runtime launch lease exists without its exact owned process handle.");
                }
                ClearBrowserAuthState();
                return;
            }

            Exception? terminationFailure = null;
            ClearBrowserAuthState(process);
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException) when (process.HasExited)
            {
                // The exact process won the HasExited/Kill race. Resource release
                // must still close its job and output pumps.
            }
            catch (Exception exception) when (exception is
                NotSupportedException
                or System.ComponentModel.Win32Exception)
            {
                terminationFailure = exception;
            }

            try
            {
                await ReleaseOwnedProcessAsync(process).ConfigureAwait(false);
            }
            catch (Exception cleanupException) when (terminationFailure is not null)
            {
                throw new AggregateException(
                    "The exact DSH process could not be terminated and released cleanly.",
                    terminationFailure,
                    cleanupException);
            }

            if (terminationFailure is not null)
            {
                throw new AggregateException(
                    "The exact DSH process required job-close fallback during shutdown.",
                    terminationFailure);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Requests a graceful stop of the exact managed runtime after its
    /// runtime-owned update admission and persistence drain report ready.
    /// </summary>
    /// <remarks>
    /// This method never cancels already-admitted runtime work and never calls
    /// <c>Process.Kill</c>. Ordinary cancellation before shutdown restores the
    /// runtime owners and retains the authenticated pipe after an exact receipt.
    /// Invalid responses or a priority stop disconnect it; a separately authorized
    /// priority stop may terminate the runtime through <see cref="StopOwnedProcessAsync"/>.
    /// </remarks>
    public async Task StopForManagedUpdateAsync(
        Guid operationId,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException(
                "The managed update operation identity must be nonempty.",
                nameof(operationId));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_options.SupportsManagedUpdate)
            {
                throw new InvalidOperationException(
                    "Managed runtime update stop is unavailable without managed-update capability.");
            }
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "Managed runtime update stop requires Windows.");
            }

            _unassignedProcessContainment.RetryTerminationOrThrow();
            var process = _ownedProcess;
            var binding = Volatile.Read(ref _runtimeUpdateChannel);
            if (process is null || process.HasExited
                || binding is null || !ReferenceEquals(binding.Process, process))
            {
                throw new InvalidOperationException(
                    "The exact managed runtime has no attached update control channel.");
            }

            // Priority admission must succeed before retaining the pipe. A
            // queued security stop can reject this wait without leaking a lease.
            using var managedWait = _managedUpdateStopArbitration.BeginManagedWait();
            using var stopCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                managedWait.Token);
            var stopToken = stopCancellation.Token;
            stopToken.ThrowIfCancellationRequested();
            var expectedRuntimeLaunchLease = Volatile.Read(
                ref _runtimeLaunchLease);
            if (!IsSameOwnedRuntimeEndpoint(
                    process,
                    expectedRuntimeLaunchLease))
            {
                throw new UnauthorizedAccessException(
                    "The exact managed runtime did not own its authenticated loopback endpoint before drain.");
            }
            lock (_runtimeUpdateChannelLifetimeGate)
            {
                if (_managedUpdateChannelLeaseProcess is not null)
                {
                    throw new InvalidOperationException(
                        "A managed runtime update stop already owns the control channel.");
                }
                if (process.HasExited
                    || !ReferenceEquals(Volatile.Read(ref _runtimeUpdateChannel), binding))
                {
                    throw new InvalidOperationException(
                        "The exact managed runtime update channel exited before it could be retained.");
                }
                Volatile.Write(ref _managedUpdateChannelLeaseProcess, process);
            }

            var cycleOwned = false;
            var shutdownSent = false;
            var exactExitConfirmed = false;
            var stoppedProcessId = process.Id;
            var keepChannel = true;
            try
            {
                stopToken.ThrowIfCancellationRequested();
                var receipt = await binding.Channel.RequestAsync(
                    DshRuntimeUpdateAction.Drain,
                    operationId,
                    CancellationToken.None).ConfigureAwait(false);
                cycleOwned = true;
                while (receipt.Phase != "ready")
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(250), stopToken)
                        .ConfigureAwait(false);
                    stopToken.ThrowIfCancellationRequested();
                    receipt = await binding.Channel.RequestAsync(
                        DshRuntimeUpdateAction.Status,
                        operationId,
                        CancellationToken.None).ConfigureAwait(false);
                    if (receipt.Phase == "resumed")
                    {
                        RequireManagedUpdateEndpointRestored(process);
                        cycleOwned = false;
                        throw new DshRuntimeUpdateRetryableException(operationId);
                    }
                }

                stopToken.ThrowIfCancellationRequested();
                shutdownSent = true;
                keepChannel = false;
                await binding.Channel.RequestAsync(
                    DshRuntimeUpdateAction.Shutdown,
                    operationId,
                    CancellationToken.None).ConfigureAwait(false);
                // Shutdown cannot be undone. Ordinary caller cancellation must
                // not lose its exit result; a security stop still preempts it.
                using var exitWait = CancellationTokenSource.CreateLinkedTokenSource(managedWait.Token);
                exitWait.CancelAfter(TimeSpan.FromSeconds(10));
                await process.WaitForExitAsync(exitWait.Token).ConfigureAwait(false);
                if (!process.HasExited)
                {
                    throw new InvalidOperationException(
                        "The exact managed runtime did not exit after graceful shutdown.");
                }
                exactExitConfirmed = true;
                if (process.ExitCode != 0)
                {
                    throw new InvalidOperationException(
                        $"The exact managed runtime reported graceful shutdown failure (exit code {process.ExitCode}).");
                }

                await ReleaseOwnedProcessAsync(process).ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is OperationCanceledException
                && (cancellationToken.IsCancellationRequested
                    || managedWait.IsPriorityCancellationRequested))
            {
                if (managedWait.IsPriorityCancellationRequested)
                {
                    keepChannel = false;
                    throw;
                }
                if (shutdownSent)
                {
                    keepChannel = false;
                    if (exactExitConfirmed || TryObserveExitedProcess(process))
                        throw new DshRuntimeUpdateStoppedException(operationId, stoppedProcessId, exception);
                    throw;
                }
                if (cycleOwned && !shutdownSent)
                {
                    try
                    {
                        var resumed = await binding.Channel.RequestAsync(
                            DshRuntimeUpdateAction.Resume,
                            operationId,
                            CancellationToken.None).ConfigureAwait(false);
                        if (resumed.Phase != "resumed")
                        {
                            throw new InvalidDataException(
                                "Managed runtime update cancellation did not receive an exact resumed receipt.");
                        }
                        RequireManagedUpdateEndpointRestored(process);
                        cycleOwned = false;
                    }
                    catch (Exception recoveryFailure)
                    {
                        keepChannel = false;
                        throw new AggregateException(
                            "Managed runtime update cancellation could not restore the exact runtime owners.",
                            exception,
                            recoveryFailure);
                    }
                }
                keepChannel = !process.HasExited;
                throw;
            }
            catch (DshRuntimeUpdateRetryableException)
            {
                keepChannel = !process.HasExited;
                throw;
            }
            catch (Exception exception)
            {
                keepChannel = false;
                if (shutdownSent && !managedWait.IsPriorityCancellationRequested
                    && (exactExitConfirmed || TryObserveExitedProcess(process)))
                    throw new DshRuntimeUpdateStoppedException(operationId, stoppedProcessId, exception);
                throw;
            }
            finally
            {
                ReleaseManagedUpdateChannelLease(process, keepChannel);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private static bool TryObserveExitedProcess(Process process)
    {
        try { return process.HasExited; }
        catch (Exception exception) when (exception is InvalidOperationException
            or System.ComponentModel.Win32Exception)
        {
            // A lost/unreadable handle is not evidence that this process exited.
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await StopOwnedProcessAsync().ConfigureAwait(false);
        _disposed = true;
        _httpClient.Dispose();
        _gate.Dispose();
    }

    internal ProcessStartInfo CreateStartInfo(
        DshRuntimeUpdateChannel? runtimeUpdateChannel = null)
    {
        _options.Validate();
        EnsureRuntimeProtocolUnchanged();
        var redirectProcessOutput = _options.CaptureRawProcessOutput
            || _webAuthProtocol == DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1;
        var startInfo = new ProcessStartInfo
        {
            FileName = _options.NodePath,
            WorkingDirectory = _options.EffectiveWorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = redirectProcessOutput,
            RedirectStandardError = redirectProcessOutput
        };

        foreach (var argument in _options.GetLaunchArguments())
        {
            startInfo.ArgumentList.Add(argument);
        }
        _options.ApplyProcessEnvironment(startInfo);
        if (runtimeUpdateChannel is not null)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "Managed runtime update control requires Windows.");
            }
            foreach (var (key, value) in runtimeUpdateChannel.CreateBootstrapEnvironment())
            {
                startInfo.Environment[key] = value;
            }
        }
        return startInfo;
    }

    private async Task<DshLaunchResult> WaitUntilHealthyAsync(
        Process process,
        CancellationToken cancellationToken)
    {
        Observe("host_health_deadline_arm");
        using var timeout = new CancellationTokenSource(_options.EffectiveStartupTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);

        while (!linked.IsCancellationRequested)
        {
            if (process.HasExited)
            {
                ClearBrowserAuthState(process);
                var exitDiagnostic = _options.CaptureRawProcessOutput
                    ? $" Check {_options.LogDirectory}."
                    : " Raw DSH output logging is disabled to protect local content.";
                throw new InvalidOperationException(
                    $"DSH exited before becoming healthy (exit code {process.ExitCode}).{exitDiagnostic}");
            }

            if (_webAuthProtocol == DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1
                && !TryGetCurrentBrowserSession(out _))
            {
                var readiness = GetBrowserLaunchReadiness(process);
                if (readiness.IsCompleted)
                {
                    var launchUri = await readiness.ConfigureAwait(false);
                    await EstablishBrowserSessionAsync(process, launchUri, linked.Token)
                        .ConfigureAwait(false);
                }
                else
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromMilliseconds(100), linked.Token)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (timeout.IsCancellationRequested)
                    {
                        break;
                    }
                    continue;
                }
            }

            bool isHealthy;
            try
            {
                isHealthy = await IsHealthyAsync(linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                break;
            }

            if (isHealthy)
            {
                Observe("host_health_passed");
                return new DshLaunchResult(
                    DshLaunchState.Started,
                    WebUiUri,
                    process.Id);
            }

            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500), linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                break;
            }
        }

        Observe(cancellationToken.IsCancellationRequested
            ? "host_health_cancelled" : "host_health_deadline_expired");
        cancellationToken.ThrowIfCancellationRequested();
        var timeoutDiagnostic = _options.CaptureRawProcessOutput
            ? $" Check {_options.LogDirectory}."
            : " Raw DSH output logging is disabled to protect local content.";
        throw new TimeoutException(
            $"DSH did not become healthy within {_options.EffectiveStartupTimeout.TotalSeconds:N0} seconds. " +
            timeoutDiagnostic);
    }

    private async Task<DshLaunchResult> RunOwnedStartupWithFailStopAsync(
        Process process,
        Func<Task<DshLaunchResult>> startup)
    {
        ArgumentNullException.ThrowIfNull(startup);
        try
        {
            return await startup().ConfigureAwait(false);
        }
        catch (Exception startupException)
        {
            Observe("host_startup_failed", startupException);
            try
            {
                await FailStopOwnedProcessAfterStartAsync(process).ConfigureAwait(false);
            }
            catch (Exception cleanupException)
            {
                throw new AggregateException(
                    "DSH startup failed and exact owned-process cleanup could not be confirmed.",
                    startupException,
                    cleanupException);
            }

            throw;
        }
    }

    private async Task FailStopOwnedProcessAfterStartAsync(Process process)
    {
        if (!ReferenceEquals(_ownedProcess, process))
        {
            return;
        }

        Exception? terminationFailure = null;
        ClearBrowserAuthState(process);
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException) when (process.HasExited)
        {
            // The exact process exited between the observation and Kill.
        }
        catch (Exception exception) when (exception is
            NotSupportedException
            or System.ComponentModel.Win32Exception)
        {
            terminationFailure = exception;
        }

        try
        {
            await ReleaseOwnedProcessAsync(process).ConfigureAwait(false);
        }
        catch (Exception cleanupException) when (terminationFailure is not null)
        {
            throw new AggregateException(
                "The exact DSH process could not be terminated and released after startup failure.",
                terminationFailure,
                cleanupException);
        }

        if (terminationFailure is not null)
        {
            throw new AggregateException(
                "The exact DSH process required job-close fallback after startup failure.",
                terminationFailure);
        }
    }

    private async Task AwaitLogPumpsAsync()
    {
        Observe("host_output_drain_begin");
        var pumps = new[] { _standardOutputPump, _standardErrorPump }
            .Where(static task => task is not null)
            .Cast<Task>()
            .ToArray();

        try
        {
            if (pumps.Length > 0)
            {
                await Task.WhenAll(pumps).ConfigureAwait(false);
            }
        }
        finally
        {
            _standardOutputPump = null;
            _standardErrorPump = null;
            Observe("host_output_drain_end");
        }
    }

    private async Task ReleaseOwnedProcessAsync(Process process)
    {
        Observe("host_release_begin");
        if (!ReferenceEquals(_ownedProcess, process))
        {
            throw new InvalidOperationException(
                "The DSH process release request did not match the exact owned process.");
        }

        var failures = new List<Exception>();
        ClearBrowserAuthState(process);
        DisposeRuntimeUpdateChannel(process, deferWhileManagedStop: false);
        var jobObject = Interlocked.Exchange(ref _jobObject, null);
        try
        {
            jobObject?.Dispose();
            Observe("host_release_job_disposed");
        }
        catch (Exception exception)
        {
            failures.Add(exception);
            if (jobObject is not null)
            {
                Interlocked.CompareExchange(ref _jobObject, jobObject, null);
            }
            throw new AggregateException(
                "The exact DSH job could not be closed before process-output cleanup.",
                failures);
        }

        var exitConfirmed = false;
        try
        {
            if (!process.HasExited)
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            exitConfirmed = process.HasExited;
        }
        catch (Exception exception) when (exception is
            InvalidOperationException
            or OperationCanceledException)
        {
            failures.Add(exception);
        }

        if (!exitConfirmed)
        {
            throw new AggregateException(
                "The Launcher could not confirm termination of the exact DSH process after closing its job.",
                failures);
        }

        var exitHandler = _ownedProcessExitHandler;
        if (exitHandler is not null)
        {
            process.Exited -= exitHandler;
            _ownedProcessExitHandler = null;
        }

        try
        {
            await AwaitLogPumpsAsync().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }
        finally
        {
            var runtimeLaunchLease = Interlocked.Exchange(
                ref _runtimeLaunchLease,
                null);
            try
            {
                runtimeLaunchLease?.Dispose();
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }

            try
            {
                Interlocked.Exchange(ref _homeWriterSession, null)?.Dispose();
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }

            try
            {
                process.Dispose();
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }

            if (ReferenceEquals(_ownedProcess, process))
            {
                Volatile.Write(ref _ownedProcess, null);
            }
            ClearBrowserAuthState();
        }

        if (failures.Count > 0)
        {
            throw new AggregateException(
                "The DSH process terminated, but one or more owned resource cleanup operations failed.",
                failures);
        }
    }

    private async Task PumpProcessOutputAsync(
        StreamReader reader,
        string? logPath,
        Process process)
    {
        StreamWriter? writer = null;
        try
        {
            if (logPath is not null)
            {
                var stream = new FileStream(
                    logPath,
                    FileMode.Append,
                    FileAccess.Write,
                    FileShare.ReadWrite,
                    bufferSize: 4096,
                    useAsync: true);
                writer = new StreamWriter(stream) { AutoFlush = true };
            }

            while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
            {
                if (_webAuthProtocol == DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1)
                {
                    try
                    {
                        var launchUri = DshBrowserAuthentication.ParseLaunchAnnouncement(
                            line,
                            WebUiUri);
                        if (launchUri is not null)
                        {
                            CompleteBrowserLaunchReadiness(process, launchUri);
                        }
                    }
                    catch (InvalidDataException exception)
                    {
                        FailBrowserLaunchReadiness(process, exception);
                    }
                }

                if (writer is not null)
                {
                    await writer.WriteLineAsync(
                        $"{DateTimeOffset.UtcNow:O} {DshBrowserAuthentication.RedactTokens(line)}")
                        .ConfigureAwait(false);
                }
            }
        }
        finally
        {
            Exception? readerFailure = null;
            try
            {
                reader.Dispose();
            }
            catch (Exception exception)
            {
                readerFailure = exception;
            }
            try
            {
                if (writer is not null)
                {
                    await writer.DisposeAsync().ConfigureAwait(false);
                }
            }
            catch (Exception writerFailure) when (readerFailure is not null)
            {
                throw new AggregateException(
                    "DSH output reader and redacted log writer cleanup both failed.",
                    readerFailure,
                    writerFailure);
            }
            if (readerFailure is not null)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo
                    .Capture(readerFailure)
                    .Throw();
            }
        }
    }

    private async Task EstablishBrowserSessionAsync(
        Process process,
        Uri launchUri,
        CancellationToken cancellationToken)
    {
        var expectedRuntimeLaunchLease = Volatile.Read(
            ref _runtimeLaunchLease);
        if (!IsSameOwnedRuntimeEndpoint(
                process,
                expectedRuntimeLaunchLease))
        {
            throw new InvalidOperationException(
                "DSH browser authentication is not served by the exact owned loopback process.");
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_healthProbeTimeout);
        DshBrowserSession session;
        try
        {
            session = await DshBrowserAuthentication.ExchangeAsync(
                    _httpClient,
                    launchUri,
                    WebUiUri,
                    process.Id,
                    timeout.Token)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException)
        {
            throw new InvalidOperationException(
                "DSH browser authentication exchange failed before health validation.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException(
                "DSH browser authentication exchange timed out before health validation.");
        }

        if (!IsSameOwnedRuntimeEndpoint(
                process,
                expectedRuntimeLaunchLease))
        {
            ClearBrowserAuthState(process);
            throw new InvalidOperationException(
                "DSH exited, changed identity, or lost its exact loopback listener during browser authentication.");
        }

        lock (_browserAuthGate)
        {
            if (!ReferenceEquals(_browserAuthProcess, process))
            {
                throw new InvalidOperationException(
                    "DSH browser authentication no longer belongs to the owned process.");
            }
            _browserSession = session;
        }
    }

    private void InitializeBrowserAuthState(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        lock (_browserAuthGate)
        {
            _browserAuthProcess = process;
            _browserSession = null;
            _browserLaunchReady = new TaskCompletionSource<Uri>(
                TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }

    private Task<Uri> GetBrowserLaunchReadiness(Process process)
    {
        lock (_browserAuthGate)
        {
            if (!ReferenceEquals(_browserAuthProcess, process) || _browserLaunchReady is null)
            {
                throw new InvalidOperationException(
                    "DSH browser authentication readiness is not bound to the owned process.");
            }
            return _browserLaunchReady.Task;
        }
    }

    private void CompleteBrowserLaunchReadiness(Process process, Uri launchUri)
    {
        lock (_browserAuthGate)
        {
            if (ReferenceEquals(_browserAuthProcess, process))
            {
                _browserLaunchReady?.TrySetResult(launchUri);
            }
        }
    }

    private void FailBrowserLaunchReadiness(Process process, Exception exception)
    {
        lock (_browserAuthGate)
        {
            if (ReferenceEquals(_browserAuthProcess, process))
            {
                _browserLaunchReady?.TrySetException(exception);
            }
        }
    }

    private bool TryGetCurrentBrowserSession(out DshBrowserSession session)
    {
        lock (_browserAuthGate)
        {
            var process = _ownedProcess;
            if (process is not null
                && !process.HasExited
                && ReferenceEquals(_browserAuthProcess, process)
                && _browserSession is { } current
                && current.ProcessId == process.Id)
            {
                session = current;
                return true;
            }

            if (_browserAuthProcess is not null
                && (process is null
                    || process.HasExited
                    || !ReferenceEquals(_browserAuthProcess, process)))
            {
                _browserSession = null;
                _browserLaunchReady = null;
                _browserAuthProcess = null;
            }

            session = null!;
            return false;
        }
    }

    private sealed class HomeRuntimeAdmissionResources(
        IDisposable? runtimeLease,
        IDshHomeWriterSession? homeSession) : IDisposable
    {
        public void Dispose()
        {
            try { runtimeLease?.Dispose(); }
            finally { homeSession?.Dispose(); }
        }
    }

    private sealed record RuntimeUpdateChannelBinding(
        Process Process,
        DshRuntimeUpdateChannel Channel);

    private void OnOwnedProcessExited(object? sender, EventArgs _)
    {
        if (sender is not Process process)
        {
            return;
        }

        try
        {
            ClearBrowserAuthState(process);
            DisposeRuntimeUpdateChannel(process);
        }
        catch (InvalidOperationException)
        {
            // Never let a late event from an old disposed Process clear a newer
            // process's credentials. Synchronous stop/dispose paths also clear.
        }
    }

    private void DisposeRuntimeUpdateChannel(
        Process process,
        bool deferWhileManagedStop = true)
    {
        lock (_runtimeUpdateChannelLifetimeGate)
        {
            if (deferWhileManagedStop
                && ReferenceEquals(_managedUpdateChannelLeaseProcess, process))
            {
                return;
            }
            var binding = Volatile.Read(ref _runtimeUpdateChannel);
            if (binding is null || !ReferenceEquals(binding.Process, process))
            {
                return;
            }
            if (ReferenceEquals(
                    Interlocked.CompareExchange(ref _runtimeUpdateChannel, null, binding),
                    binding)
                && OperatingSystem.IsWindows())
            {
                binding.Channel.Dispose();
            }
        }
    }

    private void ReleaseManagedUpdateChannelLease(
        Process process,
        bool keepChannel)
    {
        lock (_runtimeUpdateChannelLifetimeGate)
        {
            if (!ReferenceEquals(_managedUpdateChannelLeaseProcess, process))
            {
                return;
            }
            Volatile.Write(ref _managedUpdateChannelLeaseProcess, null);
            if (keepChannel && !process.HasExited)
            {
                return;
            }
            DisposeRuntimeUpdateChannel(process, deferWhileManagedStop: false);
        }
    }

    private void HandleOwnedProcessExited(
        Process process,
        WindowsJobObject jobObject) =>
        HandleOwnedProcessExitedCore(
            process,
            jobObject,
            static ownedJob => ownedJob.Dispose());

    internal void HandleOwnedProcessExitedForTest(
        Process process,
        WindowsJobObject jobObject,
        Action<WindowsJobObject> disposeJobObject) =>
        HandleOwnedProcessExitedCore(process, jobObject, disposeJobObject);

    private void HandleOwnedProcessExitedCore(
        Process process,
        WindowsJobObject jobObject,
        Action<WindowsJobObject> disposeJobObject)
    {
        ArgumentNullException.ThrowIfNull(disposeJobObject);
        OnOwnedProcessExited(process, EventArgs.Empty);
        try
        {
            // The handler captures the exact job assigned to this exact Process.
            // A delayed callback can therefore never close a newer process's job.
            disposeJobObject(jobObject);
            Interlocked.CompareExchange(ref _jobObject, null, jobObject);
        }
        catch (Exception exception) when (exception is
            InvalidOperationException
            or TimeoutException
            or IOException
            or UnauthorizedAccessException
            or System.ComponentModel.Win32Exception)
        {
            // A synchronous stop/dispose call retains the field and retries the
            // close while reporting any failure to its caller.
        }
    }

    private Uri GetBrowserLaunchUriForResult()
    {
        if (_webAuthProtocol == DshRuntimeWebAuthProtocol.LegacyCleanRootV1)
        {
            return WebUiUri;
        }

        if (TryGetCurrentBrowserSession(out var session))
        {
            return session.LaunchUri;
        }

        throw new InvalidOperationException(
            "The owned DSH process has no authenticated browser launch URL.");
    }

    private void ClearBrowserAuthState(Process? expectedProcess = null)
    {
        lock (_browserAuthGate)
        {
            if (expectedProcess is not null
                && !ReferenceEquals(_browserAuthProcess, expectedProcess))
            {
                return;
            }

            _browserSession = null;
            _browserLaunchReady = null;
            _browserAuthProcess = null;
        }
    }

    private void EnsureRuntimeProtocolUnchanged()
    {
        if (_options.WebAuthProtocol != _webAuthProtocol)
        {
            throw new InvalidDataException(
                "The DSH runtime Web authentication metadata changed after Host creation.");
        }
    }

    private static async Task<string> ReadHealthPageAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        const int maximumBytes = 1024 * 1024;
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = GC.AllocateUninitializedArray<byte>(16 * 1024);
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (output.Length + read > maximumBytes)
            {
                return string.Empty;
            }

            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        return Encoding.UTF8.GetString(output.GetBuffer(), 0, checked((int)output.Length));
    }

    private static async Task<byte[]?> ReadBoundedHealthResponseAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = GC.AllocateUninitializedArray<byte>(16 * 1024);
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    return output.ToArray();
                }

                if (output.Length + read > MaximumHealthResponseBytes)
                {
                    return null;
                }

                await output.WriteAsync(
                    buffer.AsMemory(0, read),
                    cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            if (output.TryGetBuffer(out var written))
            {
                CryptographicOperations.ZeroMemory(written.AsSpan());
            }
        }
    }

    private static bool IsValidCandidateSessionListResponse(
        JsonElement root,
        string rpcId)
    {
        // Response admission is deliberately a forward-compatible minimum shape:
        // the correlated success envelope and array are required, duplicate keys
        // are rejected recursively, and session item content is never consumed.
        if (!HasUniqueJsonProperties(root)
            || root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("type", out var type)
            || type.ValueKind != JsonValueKind.String
            || type.GetString() != "server-response"
            || !root.TryGetProperty("rpcId", out var returnedRpcId)
            || returnedRpcId.ValueKind != JsonValueKind.String
            || returnedRpcId.GetString() != rpcId
            || !root.TryGetProperty("result", out var result)
            || result.ValueKind != JsonValueKind.Object
            || !result.TryGetProperty("ok", out var ok)
            || ok.ValueKind != JsonValueKind.True
            || !result.TryGetProperty("value", out var value)
            || value.ValueKind != JsonValueKind.Object
            || !value.TryGetProperty("items", out var items)
            || items.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        return true;
    }

    private static bool HasUniqueJsonProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)
                    || !HasUniqueJsonProperties(property.Value))
                {
                    return false;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (!HasUniqueJsonProperties(item))
                {
                    return false;
                }
            }
        }

        return true;
    }
}
