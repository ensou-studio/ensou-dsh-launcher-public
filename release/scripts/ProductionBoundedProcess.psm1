#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('EnsouDshPersonalRelease.StrictProcessCapture' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace EnsouDshPersonalRelease
{
    public sealed class StrictProcessCaptureBuffer
    {
        public StrictProcessCaptureBuffer(byte[] bytes, bool overflowed)
        {
            Bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));
            Overflowed = overflowed;
        }

        public byte[] Bytes { get; }
        public bool Overflowed { get; }
    }

    public sealed class StrictProcessCaptureResult
    {
        public StrictProcessCaptureResult(
            int exitCode,
            bool timedOut,
            StrictProcessCaptureBuffer standardOutput,
            StrictProcessCaptureBuffer standardError)
        {
            ExitCode = exitCode;
            TimedOut = timedOut;
            StandardOutput = standardOutput
                ?? throw new ArgumentNullException(nameof(standardOutput));
            StandardError = standardError
                ?? throw new ArgumentNullException(nameof(standardError));
        }

        public int ExitCode { get; }
        public bool TimedOut { get; }
        public StrictProcessCaptureBuffer StandardOutput { get; }
        public StrictProcessCaptureBuffer StandardError { get; }
    }

    public static class StrictProcessCapture
    {
        private const int DrainTimeoutMilliseconds = 10000;

        public static StrictProcessCaptureResult Run(
            ProcessStartInfo startInfo,
            int timeoutMilliseconds,
            int maximumOutputBytes)
        {
            if (startInfo == null)
            {
                throw new ArgumentNullException(nameof(startInfo));
            }
            if (timeoutMilliseconds <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds));
            }
            if (maximumOutputBytes <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maximumOutputBytes));
            }
            if (startInfo.UseShellExecute
                || !startInfo.RedirectStandardOutput
                || !startInfo.RedirectStandardError)
            {
                throw new InvalidOperationException(
                    "Strict process capture requires two redirected raw output streams.");
            }

            return RunAsync(startInfo, timeoutMilliseconds, maximumOutputBytes)
                .GetAwaiter()
                .GetResult();
        }

        private static async Task<StrictProcessCaptureResult> RunAsync(
            ProcessStartInfo startInfo,
            int timeoutMilliseconds,
            int maximumOutputBytes)
        {
            using var process = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true,
            };
            if (!process.Start())
            {
                throw new InvalidOperationException("The child process did not start.");
            }

            var standardOutput = ReadBoundedAsync(
                process.StandardOutput.BaseStream,
                maximumOutputBytes,
                () => TryKillTree(process));
            var standardError = ReadBoundedAsync(
                process.StandardError.BaseStream,
                maximumOutputBytes,
                () => TryKillTree(process));
            var exit = process.WaitForExitAsync();
            var timedOut = false;
            if (await Task.WhenAny(exit, Task.Delay(timeoutMilliseconds))
                    .ConfigureAwait(false) != exit)
            {
                timedOut = true;
                TryKillTree(process);
            }

            var completion = Task.WhenAll(exit, standardOutput, standardError);
            if (await Task.WhenAny(
                    completion,
                    Task.Delay(DrainTimeoutMilliseconds)).ConfigureAwait(false)
                != completion)
            {
                TryKillTree(process);
                throw new TimeoutException(
                    "The child process or its redirected streams did not close after termination.");
            }
            await completion.ConfigureAwait(false);
            return new StrictProcessCaptureResult(
                process.ExitCode,
                timedOut,
                await standardOutput.ConfigureAwait(false),
                await standardError.ConfigureAwait(false));
        }

        private static async Task<StrictProcessCaptureBuffer> ReadBoundedAsync(
            Stream input,
            int maximumBytes,
            Action overflowAction)
        {
            var retained = new byte[maximumBytes];
            var count = 0;
            var overflowed = false;
            var buffer = new byte[1024];
            while (true)
            {
                var read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length))
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                var available = maximumBytes - count;
                if (available > 0)
                {
                    var retainedCount = Math.Min(read, available);
                    Buffer.BlockCopy(buffer, 0, retained, count, retainedCount);
                    count += retainedCount;
                }
                if (!overflowed && read > available)
                {
                    overflowed = true;
                    overflowAction();
                }
            }

            var exact = new byte[count];
            Buffer.BlockCopy(retained, 0, exact, 0, count);
            Array.Clear(retained, 0, retained.Length);
            Array.Clear(buffer, 0, buffer.Length);
            return new StrictProcessCaptureBuffer(exact, overflowed);
        }

        private static void TryKillTree(Process process)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException)
            {
                // A concurrent exit is equivalent to successful termination here.
            }
            catch (NotSupportedException)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill();
                    }
                }
                catch
                {
                    // The caller still observes timeout or overflow and fails closed.
                }
            }
            catch
            {
                // The caller still observes timeout or overflow and fails closed.
            }
        }
    }
}
'@
}

function Invoke-ProductionBoundedProcessCapture {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.ProcessStartInfo]$StartInfo,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds,
        [Parameter(Mandatory = $true)][int]$MaximumOutputBytes
    )

    return [EnsouDshPersonalRelease.StrictProcessCapture]::Run(
        $StartInfo,
        $TimeoutMilliseconds,
        $MaximumOutputBytes)
}

Export-ModuleMember -Function Invoke-ProductionBoundedProcessCapture
