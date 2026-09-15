using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Ensou.Dsh.Host;

namespace Ensou.Dsh.CoreTests;

internal static class DshLoopbackListenerOwnershipTests
{
    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "DSH loopback listener ownership tests require Windows.");
        }

        await ExactChildListenerOwnsItsLoopbackSocketAsync();
        await UnrelatedOwnedProcessCannotClaimListenerAsync();
        await WildcardListenerIsNotExactLoopbackAsync();
    }

    private static async Task ExactChildListenerOwnsItsLoopbackSocketAsync()
    {
        await using var listener = await ListenerProcess.StartAsync(
            "Loopback").ConfigureAwait(false);
        await WaitForOwnershipAsync(listener.Process, listener.Port)
            .ConfigureAwait(false);

        AssertTrue(DshLoopbackListenerOwnership
            .IsExactProcessListeningOnIpv4Loopback(
                listener.Process,
                listener.Port));

        // Model the legacy health request boundary: the same exact listener
        // must still belong to the retained process after network activity.
        using (var client = new TcpClient(AddressFamily.InterNetwork))
        {
            await client.ConnectAsync(
                    IPAddress.Loopback,
                    listener.Port)
                .WaitAsync(TimeSpan.FromSeconds(5))
                .ConfigureAwait(false);
        }
        AssertTrue(DshLoopbackListenerOwnership
            .IsExactProcessListeningOnIpv4Loopback(
                listener.Process,
                listener.Port));

        await listener.StopGracefullyAsync().ConfigureAwait(false);
        AssertFalse(DshLoopbackListenerOwnership
            .IsExactProcessListeningOnIpv4Loopback(
                listener.Process,
                listener.Port));
    }

    private static async Task UnrelatedOwnedProcessCannotClaimListenerAsync()
    {
        await using var listener = await ListenerProcess.StartAsync(
            "Loopback").ConfigureAwait(false);
        await WaitForOwnershipAsync(listener.Process, listener.Port)
            .ConfigureAwait(false);
        using var unrelatedOwnedProcess = StartHiddenPingProcess();
        try
        {
            AssertFalse(DshLoopbackListenerOwnership
                .IsExactProcessListeningOnIpv4Loopback(
                    unrelatedOwnedProcess,
                    listener.Port));
            AssertTrue(DshLoopbackListenerOwnership
                .IsExactProcessListeningOnIpv4Loopback(
                    listener.Process,
                    listener.Port));
        }
        finally
        {
            await StopProcessAsync(unrelatedOwnedProcess).ConfigureAwait(false);
        }
    }

    private static async Task WildcardListenerIsNotExactLoopbackAsync()
    {
        await using var listener = await ListenerProcess.StartAsync("Any")
            .ConfigureAwait(false);
        await Task.Delay(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
        AssertFalse(DshLoopbackListenerOwnership
            .IsExactProcessListeningOnIpv4Loopback(
                listener.Process,
                listener.Port));
    }

    private static async Task WaitForOwnershipAsync(
        Process process,
        int port)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!timeout.IsCancellationRequested)
        {
            if (DshLoopbackListenerOwnership
                .IsExactProcessListeningOnIpv4Loopback(process, port))
            {
                return;
            }

            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(50), timeout.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                break;
            }
        }

        throw new InvalidOperationException(
            $"Child process {process.Id.ToString(CultureInfo.InvariantCulture)} did not own exact loopback listener 127.0.0.1:{port.ToString(CultureInfo.InvariantCulture)}.");
    }

    private static Process StartHiddenPingProcess()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "ping.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add("-t");
        startInfo.ArgumentList.Add("127.0.0.1");
        return Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Windows did not start the unrelated owned-process probe.");
    }

    private static async Task StopProcessAsync(Process process)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
        }
        await process.WaitForExitAsync()
            .WaitAsync(TimeSpan.FromSeconds(5))
            .ConfigureAwait(false);
    }

    private static void AssertTrue(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Expected condition to be true.");
        }
    }

    private static void AssertFalse(bool condition) => AssertTrue(!condition);

    private sealed class ListenerProcess : IAsyncDisposable
    {
        private readonly Task<string> _standardError;
        private bool _stopped;

        private ListenerProcess(
            Process process,
            int port,
            Task<string> standardError)
        {
            Process = process;
            Port = port;
            _standardError = standardError;
        }

        internal Process Process { get; }

        internal int Port { get; }

        internal static async Task<ListenerProcess> StartAsync(
            string addressProperty)
        {
            if (addressProperty is not ("Loopback" or "Any"))
            {
                throw new ArgumentOutOfRangeException(nameof(addressProperty));
            }

            var powershell = Path.Combine(
                Environment.SystemDirectory,
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe");
            var script = "$ErrorActionPreference='Stop';"
                + "$listener=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::"
                + addressProperty
                + ",0);$listener.Start();try{"
                + "$endpoint=[System.Net.IPEndPoint]$listener.LocalEndpoint;"
                + "[Console]::Out.WriteLine(('READY:{0}' -f $endpoint.Port));"
                + "[Console]::Out.Flush();[Console]::In.ReadLine()|Out-Null}"
                + "finally{$listener.Stop()}";
            var startInfo = new ProcessStartInfo
            {
                FileName = powershell,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            startInfo.ArgumentList.Add("-NoLogo");
            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-NonInteractive");
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
            startInfo.ArgumentList.Add("-Command");
            startInfo.ArgumentList.Add(script);

            var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException(
                    "Windows did not start the child loopback listener probe.");
            var standardError = process.StandardError.ReadToEndAsync();
            try
            {
                var ready = await process.StandardOutput.ReadLineAsync()
                    .WaitAsync(TimeSpan.FromSeconds(10))
                    .ConfigureAwait(false);
                if (ready is null
                    || !ready.StartsWith("READY:", StringComparison.Ordinal)
                    || !int.TryParse(
                        ready.AsSpan("READY:".Length),
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out var port)
                    || port is < 1 or > ushort.MaxValue
                    || process.HasExited)
                {
                    var diagnostic = process.HasExited
                        ? await standardError.ConfigureAwait(false)
                        : "listener did not emit its exact READY record";
                    throw new InvalidOperationException(
                        $"Child loopback listener startup failed: {diagnostic}");
                }

                return new ListenerProcess(process, port, standardError);
            }
            catch
            {
                await TerminateProcessAsync(process).ConfigureAwait(false);
                process.Dispose();
                throw;
            }
        }

        internal async Task StopGracefullyAsync()
        {
            if (_stopped)
            {
                return;
            }

            Process.StandardInput.WriteLine();
            Process.StandardInput.Close();
            await Process.WaitForExitAsync()
                .WaitAsync(TimeSpan.FromSeconds(5))
                .ConfigureAwait(false);
            _stopped = true;
            var standardError = await _standardError.ConfigureAwait(false);
            if (Process.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"Child loopback listener exited {Process.ExitCode.ToString(CultureInfo.InvariantCulture)}: {standardError}");
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (!_stopped)
            {
                await TerminateProcessAsync(Process).ConfigureAwait(false);
                _stopped = true;
            }
            Process.Dispose();
        }

        private static async Task TerminateProcessAsync(Process process)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
                await process.WaitForExitAsync()
                    .WaitAsync(TimeSpan.FromSeconds(5))
                    .ConfigureAwait(false);
            }
            catch (InvalidOperationException) when (process.HasExited)
            {
                // The exact child exited between observation and termination.
            }
        }
    }
}
