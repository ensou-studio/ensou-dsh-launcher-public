using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Host;

/// <summary>One action accepted by the Host-owned runtime update control pipe.</summary>
public enum DshRuntimeUpdateAction
{
    /// <summary>Stops new runtime work and reports the current drain state.</summary>
    Drain,

    /// <summary>Reports readiness or acknowledges exact-owner restoration after a failed checkpoint.</summary>
    Status,

    /// <summary>Reopens the runtime update gate for the supplied operation.</summary>
    Resume,

    /// <summary>Requests graceful runtime disposal only after a ready receipt.</summary>
    Shutdown,
}

/// <summary>A runtime checkpoint failed but restored its exact owners and retained the authenticated channel.</summary>
public sealed class DshRuntimeUpdateRetryableException : Exception
{
    /// <summary>Creates one retryable managed-update stop result.</summary>
    public DshRuntimeUpdateRetryableException(Guid operationId)
        : base($"Managed runtime update operation '{operationId:D}' did not reach a checkpoint and was restored.")
    {
        OperationId = operationId;
    }

    /// <summary>The exact operation whose owners were restored.</summary>
    public Guid OperationId { get; }
}

/// <summary>An update stop failed after the exact owned process was confirmed exited.</summary>
public sealed class DshRuntimeUpdateStoppedException : Exception
{
    /// <summary>Preserves the failed operation and the independently observed process exit.</summary>
    public DshRuntimeUpdateStoppedException(Guid operationId, int processId, Exception innerException)
        : base("The exact managed Runtime exited, but update shutdown did not complete successfully.", innerException)
    {
        OperationId = operationId;
        ProcessId = processId;
    }

    /// <summary>The failed update operation.</summary>
    public Guid OperationId { get; }

    /// <summary>The retained process identifier observed before its handle was disposed.</summary>
    public int ProcessId { get; }
}

/// <summary>
/// A Host-owned, single-runtime named-pipe transport for the runtime update
/// protocol.
/// </summary>
/// <remarks>
/// The server pipe is allocated before the child is started.  A connected client
/// is accepted only if the operating system reports the retained child process
/// identifier, and the supplied ownership validator accepts that same retained
/// process before and after every request/response exchange.  Disposing or
/// invalidating this transport never terminates the runtime; the runtime must
/// treat its control-pipe disconnect as a reason to resume its own gate.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class DshRuntimeUpdateChannel : IDisposable, IAsyncDisposable
{
    /// <summary>The environment variable containing the complete pipe path.</summary>
    public const string UpdatePipeEnvironmentVariable = "ENSOU_DSH_UPDATE_PIPE";

    /// <summary>The environment variable containing the runtime instance GUID.</summary>
    public const string RuntimeInstanceIdEnvironmentVariable =
        "ENSOU_DSH_RUNTIME_INSTANCE_ID";

    private const string PipePrefix = "ensou-dsh-update-";
    private static readonly Encoding Utf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private readonly NamedPipeServerStream _pipe;
    private readonly SemaphoreSlim _exchangeGate = new(1, 1);
    private readonly TimeSpan _exchangeTimeout;
    private readonly Func<Process, bool> _ownershipValidator;
    private Process? _runtimeProcess;
    private int _runtimeProcessId;
    private bool _disposed;

    private DshRuntimeUpdateChannel(
        Guid runtimeInstanceId,
        TimeSpan exchangeTimeout,
        Func<Process, bool> ownershipValidator)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The DSH runtime update channel is supported only on Windows.");
        }
        if (runtimeInstanceId == Guid.Empty)
        {
            throw new ArgumentException(
                "The runtime instance identity must be nonempty.",
                nameof(runtimeInstanceId));
        }
        if (exchangeTimeout < TimeSpan.FromMilliseconds(100)
            || exchangeTimeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(exchangeTimeout));
        }

        RuntimeInstanceId = runtimeInstanceId;
        PipeName = PipePrefix + runtimeInstanceId.ToString("N");
        PipePath = @"\\.\pipe\" + PipeName;
        _exchangeTimeout = exchangeTimeout;
        _ownershipValidator = ownershipValidator
            ?? throw new ArgumentNullException(nameof(ownershipValidator));
        _pipe = new NamedPipeServerStream(
            PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous
                | PipeOptions.CurrentUserOnly
                | PipeOptions.FirstPipeInstance);
    }

    /// <summary>The nonempty GUID generated by the Host for this runtime launch.</summary>
    public Guid RuntimeInstanceId { get; }

    /// <summary>The unqualified Windows pipe name derived from the instance GUID.</summary>
    public string PipeName { get; }

    /// <summary>The complete <c>\\.\pipe\...</c> pipe path passed to the runtime.</summary>
    public string PipePath { get; }

    /// <summary>
    /// Creates and reserves the Host pipe before the corresponding child process
    /// is launched.
    /// </summary>
    /// <param name="ownershipValidator">
    /// Validates the exact retained child process before and after every exchange.
    /// It must not be replaced by browser, cookie, or endpoint authentication.
    /// </param>
    /// <param name="runtimeInstanceId">
    /// Optional launch identity.  A new nonempty GUID is generated when omitted.
    /// </param>
    /// <param name="exchangeTimeout">Bound for connection, write, and read work.</param>
    public static DshRuntimeUpdateChannel Create(
        Func<Process, bool> ownershipValidator,
        Guid? runtimeInstanceId = null,
        TimeSpan? exchangeTimeout = null) =>
        new(
            runtimeInstanceId ?? Guid.NewGuid(),
            exchangeTimeout ?? TimeSpan.FromSeconds(5),
            ownershipValidator);

    /// <summary>
    /// Supplies the two runtime bootstrap variables for the process start
    /// information.  Values are exact: the pipe is fully qualified and the
    /// instance GUID uses lowercase <c>D</c> format.
    /// </summary>
    public IReadOnlyDictionary<string, string> CreateBootstrapEnvironment() =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [UpdatePipeEnvironmentVariable] = PipePath,
            [RuntimeInstanceIdEnvironmentVariable] = RuntimeInstanceId
                .ToString("D")
                .ToLowerInvariant(),
        };

    /// <summary>
    /// Waits for the one runtime connection and pins it to the exact retained
    /// child process.  A cancellation, timeout, bad PID, or ownership failure
    /// permanently invalidates this channel.
    /// </summary>
    public async Task AttachAsync(
        Process runtimeProcess,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(runtimeProcess);
        await WaitForExchangeGateAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (_runtimeProcess is not null)
            {
                throw new InvalidOperationException(
                    "The runtime update channel is already attached.");
            }

            var processId = runtimeProcess.Id;
            if (processId <= 0)
            {
                throw new InvalidOperationException(
                    "The retained runtime process has no valid process identifier.");
            }
            _runtimeProcess = runtimeProcess;
            _runtimeProcessId = processId;
            try
            {
                using var bounded = CreateBoundedCancellation(cancellationToken);
                await _pipe.WaitForConnectionAsync(bounded.Token).ConfigureAwait(false);
                ValidateConnectedClient();
            }
            catch (Exception exception)
            {
                Invalidate();
                throw TranslateBoundedFailure(exception, cancellationToken);
            }
        }
        finally
        {
            _exchangeGate.Release();
        }
    }

    /// <summary>
    /// Serializes one exact protocol request and returns its authenticated,
    /// bounded receipt.  Cancellation, timeout, malformed data, a PID mismatch,
    /// or an ownership-validation failure invalidates the channel.
    /// </summary>
    public async Task<RuntimeUpdateControlReceipt> RequestAsync(
        DshRuntimeUpdateAction action,
        Guid operationId,
        CancellationToken cancellationToken = default)
    {
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException(
                "The update operation identity must be nonempty.",
                nameof(operationId));
        }

        await WaitForExchangeGateAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!_pipe.IsConnected || _runtimeProcess is null)
            {
                throw new InvalidOperationException(
                    "The runtime update channel has not been attached.");
            }

            try
            {
                ValidateConnectedClient();
                using var bounded = CreateBoundedCancellation(cancellationToken);
                var request = SerializeRequest(action, operationId);
                await _pipe.WriteAsync(request, bounded.Token).ConfigureAwait(false);
                await _pipe.FlushAsync(bounded.Token).ConfigureAwait(false);
                var response = await ReadLineAsync(_pipe, bounded.Token)
                    .ConfigureAwait(false);
                try
                {
                    ValidateConnectedClient();
                }
                catch (Exception validationFailure) when (
                    action == DshRuntimeUpdateAction.Shutdown
                    && HasExactRetainedRuntimeExited()
                    && (validationFailure is UnauthorizedAccessException
                        or Win32Exception
                        or IOException
                        or ObjectDisposedException))
                {
                    // The response was read from the PID-authenticated pipe. A
                    // ready receipt may itself trigger immediate graceful exit,
                    // which necessarily makes a post-response pipe/loopback
                    // validation unavailable. Parsing still pins every receipt
                    // field to the retained process and this exact operation.
                    return ParseResponse(action, response, operationId);
                }
                return ParseResponse(action, response, operationId);
            }
            catch (Exception exception)
            {
                Invalidate();
                throw TranslateBoundedFailure(exception, cancellationToken);
            }
        }
        finally
        {
            _exchangeGate.Release();
        }
    }

    /// <summary>
    /// Disposes the pipe without killing the child process.  Any runtime-side
    /// disconnect handling remains responsible for reopening its admission gate.
    /// </summary>
    public void Dispose() => Invalidate();

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        Invalidate();
        return ValueTask.CompletedTask;
    }

    private byte[] SerializeRequest(
        DshRuntimeUpdateAction action,
        Guid operationId)
    {
        var actionText = action switch
        {
            DshRuntimeUpdateAction.Drain => "drain",
            DshRuntimeUpdateAction.Status => "status",
            DshRuntimeUpdateAction.Resume => "resume",
            DshRuntimeUpdateAction.Shutdown => "shutdown",
            _ => throw new ArgumentOutOfRangeException(nameof(action)),
        };
        return Utf8.GetBytes(JsonSerializer.Serialize(
            new RuntimeUpdateRequest(
                RuntimeUpdateControlProtocol.Protocol,
                RuntimeInstanceId,
                operationId,
                actionText),
            new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            }) + "\n");
    }

    private RuntimeUpdateControlReceipt ParseResponse(
        DshRuntimeUpdateAction action,
        byte[] utf8Response,
        Guid operationId)
    {
        var receipt = RuntimeUpdateControlProtocol.Parse(
            utf8Response,
            RuntimeInstanceId,
            operationId,
            _runtimeProcessId,
            forProcessStop: action == DshRuntimeUpdateAction.Shutdown);
        if (action == DshRuntimeUpdateAction.Resume && receipt.Phase == "resumed")
        {
            return receipt;
        }
        if (action == DshRuntimeUpdateAction.Drain
            && (receipt.Phase is "draining" or "ready"))
        {
            return receipt;
        }
        if (action == DshRuntimeUpdateAction.Status
            && (receipt.Phase is "draining" or "ready" or "resumed"))
        {
            return receipt;
        }
        if (action == DshRuntimeUpdateAction.Shutdown && receipt.Phase == "ready")
        {
            return receipt;
        }

        throw new InvalidDataException(
            "Runtime update control receipt phase is not valid for the requested action.");
    }

    private void ValidateConnectedClient()
    {
        var process = _runtimeProcess
            ?? throw new InvalidOperationException("The runtime update channel has not been attached.");
        if (process.HasExited || process.Id != _runtimeProcessId || !_ownershipValidator(process))
        {
            throw new UnauthorizedAccessException(
                "The retained runtime process no longer satisfies Host ownership validation.");
        }
        if (!GetNamedPipeClientProcessId(_pipe.SafePipeHandle, out var clientProcessId))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        if (clientProcessId == 0 || clientProcessId > int.MaxValue
            || (int)clientProcessId != _runtimeProcessId)
        {
            throw new UnauthorizedAccessException(
                "The runtime update pipe client is not the retained runtime process.");
        }
    }

    private bool HasExactRetainedRuntimeExited()
    {
        var process = _runtimeProcess;
        return process is not null
            && process.Id == _runtimeProcessId
            && process.HasExited;
    }

    private CancellationTokenSource CreateBoundedCancellation(
        CancellationToken cancellationToken)
    {
        var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(_exchangeTimeout);
        return bounded;
    }

    private async Task WaitForExchangeGateAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _exchangeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // A caller that gives up cannot safely leave an authenticated
            // exchange in flight on this single request/response transport.
            Invalidate();
            throw;
        }
    }

    private async Task<byte[]> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var bytes = new MemoryStream();
        var next = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(next.AsMemory(0, 1), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException(
                    "The runtime update control pipe disconnected before a response line.");
            }
            if (next[0] == (byte)'\n')
            {
                return bytes.ToArray();
            }
            if (bytes.Length >= RuntimeUpdateControlProtocol.MaximumMessageBytes)
            {
                throw new InvalidDataException(
                    "Runtime update control response exceeds 8 KiB.");
            }
            bytes.WriteByte(next[0]);
        }
    }

    private Exception TranslateBoundedFailure(
        Exception exception,
        CancellationToken callerCancellation)
    {
        if (exception is OperationCanceledException)
        {
            return callerCancellation.IsCancellationRequested
                ? new OperationCanceledException(callerCancellation)
                : new TimeoutException("Runtime update control pipe exchange timed out.", exception);
        }
        return exception;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private void Invalidate()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _pipe.Dispose();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(
        SafePipeHandle pipe,
        out uint clientProcessId);

    private sealed record RuntimeUpdateRequest(
        string Protocol,
        Guid RuntimeInstanceId,
        Guid OperationId,
        string Action);
}
