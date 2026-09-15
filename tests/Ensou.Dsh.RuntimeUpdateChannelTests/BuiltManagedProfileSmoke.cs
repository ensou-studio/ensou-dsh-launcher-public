using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Host;

/// <summary>
/// Runs an opt-in Windows smoke against a built source-tree managed profile.
/// It proves the real CLI's managed composition, browser cookie exchange, and
/// private update-pipe shutdown, but does not attest an installed Host lease.
/// </summary>
internal static class BuiltManagedProfileSmoke
{
    private static readonly Regex BrowserLaunch = new(
        "^dsh web: (http://127\\.0\\.0\\.1:(?<port>[1-9][0-9]{0,4})/\\?token=[A-Za-z0-9_-]{43})$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Token = new(
        "([?&]token=)[^\\s)]+",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex NamedSecret = new(
        "(?i)(DEEPSEEK_API_KEY\\s*[=:]\\s*|Bearer\\s+)[^\\s,;]+",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Base64UrlSecret = new(
        "(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>
    /// Starts the supplied built CLI with the production enterprise-managed
    /// profile, then checks browser authentication and graceful pipe shutdown.
    /// </summary>
    /// <param name="candidateRoot">Absolute built source-tree root.</param>
    /// <param name="nodePath">Absolute isolated Node executable path.</param>
    /// <returns>A task that completes only after the exact child exits successfully.</returns>
    internal static async Task RunAsync(string candidateRoot, string nodePath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The managed profile smoke requires Windows.");

        var candidate = RequireCandidate(candidateRoot);
        var node = RequireFile(nodePath, "isolated Node executable");
        var root = Directory.CreateTempSubdirectory("ensou-dsh-managed-profile-");
        Process? child = null;
        DshRuntimeUpdateChannel? channel = null;
        LoopbackHttpSink? modelSink = null;
        ManagedOutput? stdout = null;
        BoundedCapture? stderr = null;
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try
        {
            var home = Directory.CreateDirectory(Path.Combine(root.FullName, "dsh-home")).FullName;
            var workspace = Directory.CreateDirectory(Path.Combine(home, "workspaces")).FullName;
            var skills = Directory.CreateDirectory(Path.Combine(root.FullName, "skills")).FullName;
            modelSink = new LoopbackHttpSink();
            channel = DshRuntimeUpdateChannel.Create(
                process => ReferenceEquals(process, child) && !process.HasExited);
            var webPort = RandomNumberGenerator.GetInt32(49_152, 65_536);
            var startInfo = CreateStartInfo(
                candidate.Root,
                node,
                home,
                workspace,
                skills,
                webPort,
                modelSink.BaseUri,
                channel);
            child = Process.Start(startInfo)
                ?? throw new InvalidOperationException("The built managed CLI did not start.");
            stdout = new ManagedOutput(child.StandardOutput, timeout.Token);
            stderr = new BoundedCapture(child.StandardError, timeout.Token);

            var launch = await WaitForLaunchAsync(stdout.Launch, timeout.Token);
            Assert(launch.Port == webPort, "The managed CLI announced an unexpected WebUI port.");
            AssertExactListenerOwner(child, webPort);
            await CheckBrowserCookieAsync(
                launch.Uri,
                child,
                webPort,
                candidate.WebTitle,
                timeout.Token);
            AssertExactListenerOwner(child, webPort);
            // Match the Host startup order: browser authentication proves the
            // composed WebUI first, then the already-created server pipe pins
            // the client that managed boot connected after profile composition.
            await channel.AttachAsync(child, timeout.Token);

            var operation = Guid.NewGuid();
            var receipt = await channel.RequestAsync(
                DshRuntimeUpdateAction.Drain,
                operation,
                timeout.Token);
            while (receipt.Phase == "draining")
            {
                await Task.Delay(50, timeout.Token);
                receipt = await channel.RequestAsync(
                    DshRuntimeUpdateAction.Status,
                    operation,
                    timeout.Token);
            }
            Assert(receipt.Phase == "ready"
                && receipt.ActiveOperations == 0
                && receipt.PersistenceFlushed,
                "The real managed profile did not produce a ready drain receipt.");

            var shutdown = await channel.RequestAsync(
                DshRuntimeUpdateAction.Shutdown,
                operation,
                timeout.Token);
            Assert(shutdown.Phase == "ready" && shutdown.PersistenceFlushed,
                "The real managed profile did not acknowledge a ready shutdown receipt.");
            await child.WaitForExitAsync(timeout.Token);
            Assert(child.ExitCode == 0,
                $"The real managed profile exited {child.ExitCode} after ready shutdown.");
            var standardError = await stderr.Completion;
            Assert(standardError.Length == 0,
                $"The managed profile wrote stderr: {Redact(standardError)}");
            _ = await stdout.Completion;
            Console.WriteLine("PASS  built managed profile: cookie health, exact pipe drain, natural exit0");
        }
        catch (Exception failure)
        {
            throw new InvalidOperationException(
                $"Built managed profile startup/control failed. {FailureDiagnostics(stdout, stderr)}",
                failure);
        }
        finally
        {
            channel?.Dispose();
            if (child is { HasExited: false })
            {
                try { child.Kill(entireProcessTree: true); }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
                try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
                catch (OperationCanceledException) { }
            }
            if (stdout is not null)
            {
                try { _ = await stdout.Completion.WaitAsync(TimeSpan.FromSeconds(5)); }
                catch (Exception) { }
            }
            if (stderr is not null)
            {
                try { _ = await stderr.Completion.WaitAsync(TimeSpan.FromSeconds(5)); }
                catch (Exception) { }
            }
            child?.Dispose();
            if (modelSink is not null) await modelSink.DisposeAsync();
            DeleteOwnedRoot(root);
        }
    }

    private static ProcessStartInfo CreateStartInfo(
        string candidate,
        string node,
        string home,
        string workspace,
        string skills,
        int webPort,
        Uri modelProxy,
        DshRuntimeUpdateChannel channel)
    {
        var start = new ProcessStartInfo(node)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workspace,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        start.ArgumentList.Add(Path.Combine(candidate, "apps", "cli", "lib", "bin.js"));
        start.ArgumentList.Add("--profile");
        start.ArgumentList.Add(DshRuntimeOptions.EnterpriseManagedProfile);
        start.ArgumentList.Add("--host");
        start.ArgumentList.Add("127.0.0.1");
        start.ArgumentList.Add("--port");
        start.ArgumentList.Add(webPort.ToString(System.Globalization.CultureInfo.InvariantCulture));

        ConfigureIsolatedEnvironment(start, node, home);
        start.Environment["DSH_HOME"] = home;
        start.Environment["DSH_TELEMETRY_DISABLED"] = "1";
        start.Environment["DSH_ENTERPRISE_MANAGED_BOOT"] =
            DshRuntimeOptions.EnterpriseManagedBootMarker;
        start.Environment[DshRuntimeOptions.EnterpriseManagedSkillsRootEnvironmentVariable] = skills;
        start.Environment["NO_PROXY"] = DshRuntimeOptions.LoopbackNoProxy;
        var proxy = modelProxy.AbsoluteUri.TrimEnd('/');
        start.Environment["DEEPSEEK_BASE_URL"] = proxy;
        start.Environment["DEEPSEEK_SEARCH_BASE_URL"] = proxy;
        start.Environment["DEEPSEEK_API_KEY"] =
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        foreach (var pair in channel.CreateBootstrapEnvironment())
            start.Environment[pair.Key] = pair.Value;
        return start;
    }

    private static void ConfigureIsolatedEnvironment(
        ProcessStartInfo start,
        string node,
        string home)
    {
        var windows = Environment.GetEnvironmentVariable("SystemRoot")
            ?? throw new InvalidOperationException("SystemRoot is required for the isolated Node process.");
        var nodeDirectory = Path.GetDirectoryName(node)
            ?? throw new InvalidOperationException("The isolated Node directory is unavailable.");
        var userProfile = Directory.CreateDirectory(Path.Combine(home, "profile")).FullName;
        var appData = Directory.CreateDirectory(Path.Combine(userProfile, "AppData", "Roaming")).FullName;
        var localAppData = Directory.CreateDirectory(Path.Combine(userProfile, "AppData", "Local")).FullName;
        var temporary = Directory.CreateDirectory(Path.Combine(home, "temp")).FullName;
        start.Environment.Clear();
        start.Environment["SystemRoot"] = windows;
        start.Environment["WINDIR"] = windows;
        start.Environment["USERPROFILE"] = userProfile;
        start.Environment["HOME"] = userProfile;
        start.Environment["APPDATA"] = appData;
        start.Environment["LOCALAPPDATA"] = localAppData;
        start.Environment["TEMP"] = temporary;
        start.Environment["TMP"] = temporary;
        start.Environment["PATH"] = nodeDirectory;
    }

    private static async Task<(Uri Uri, int Port)> WaitForLaunchAsync(
        Task<string> output,
        CancellationToken token)
    {
        var line = await output.WaitAsync(token);
        var match = BrowserLaunch.Match(line);
        if (!match.Success || !Uri.TryCreate(match.Groups[1].Value, UriKind.Absolute, out var launch))
            throw new InvalidDataException($"Managed CLI did not emit a valid browser launch URL: {Redact(line)}");
        return (launch, int.Parse(match.Groups["port"].Value,
            System.Globalization.CultureInfo.InvariantCulture));
    }

    private static async Task CheckBrowserCookieAsync(
        Uri launch,
        Process child,
        int port,
        string expectedWebTitle,
        CancellationToken token)
    {
        using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        AssertExactListenerOwner(child, port);
        using var exchange = await client.GetAsync(launch, token);
        Assert(exchange.StatusCode == HttpStatusCode.SeeOther
            && exchange.Headers.Location?.OriginalString == "/",
            "Managed WebUI did not perform the browser token redirect.");
        var cookie = exchange.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.SingleOrDefault()
            : null;
        Assert(cookie is not null && cookie.Contains("HttpOnly", StringComparison.Ordinal),
            "Managed WebUI did not issue one browser session cookie.");
        AssertExactListenerOwner(child, port);
        using var request = new HttpRequestMessage(HttpMethod.Get,
            new Uri($"http://127.0.0.1:{port}/", UriKind.Absolute));
        request.Headers.TryAddWithoutValidation("Cookie", cookie!.Split(';', 2)[0]);
        using var root = await client.SendAsync(request, token);
        Assert(root.StatusCode == HttpStatusCode.OK,
            "Managed WebUI did not accept its issued browser session cookie.");
        var page = await root.Content.ReadAsStringAsync(token);
        Assert(page.Contains("__DSH_BOOT__", StringComparison.Ordinal)
            && page.Contains($"<title>{expectedWebTitle}</title>", StringComparison.Ordinal),
            "Managed WebUI did not serve the current built boot document after cookie authentication.");
    }

    private static void AssertExactListenerOwner(Process child, int port)
    {
        var type = typeof(DshRuntimeUpdateChannel).Assembly.GetType(
            "Ensou.Dsh.Host.DshLoopbackListenerOwnership")
            ?? throw new InvalidOperationException("The Host loopback ownership helper is unavailable.");
        var method = type.GetMethod(
            "IsExactProcessListeningOnIpv4Loopback",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("The Host loopback ownership method is unavailable.");
        var owns = method.Invoke(null, [child, port]) is true;
        Assert(owns,
            "The exact Node process did not own the configured loopback listener.");
    }

    private static void AppendBounded(StringBuilder target, string value)
    {
        const int maximum = 32 * 1024;
        if (target.Length + value.Length > maximum)
            throw new InvalidDataException("Managed CLI output exceeded its 32 KiB test bound.");
        target.Append(value);
    }

    private static (string Root, string WebTitle) RequireCandidate(string root)
    {
        var candidate = RequireDirectory(root, "built candidate root");
        _ = RequireFile(Path.Combine(candidate, "apps", "cli", "lib", "bin.js"), "built CLI entry point");
        _ = RequireFile(Path.Combine(candidate, "apps", "cli", "config", "managed-profile", "cordis.yml"),
            "managed profile configuration");
        var index = RequireFile(Path.Combine(candidate, "apps", "web", "dist", "index.html"),
            "built WebUI index");
        var title = Regex.Match(File.ReadAllText(index), "<title>(?<title>[^<]+)</title>",
            RegexOptions.CultureInvariant).Groups["title"].Value;
        if (title.Length == 0)
            throw new InvalidDataException("The built WebUI index has no title record.");
        return (candidate, title);
    }

    private static string RequireFile(string path, string description)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !File.Exists(path))
            throw new InvalidOperationException($"The {description} must be an existing absolute file.");
        return Path.GetFullPath(path);
    }

    private static string RequireDirectory(string path, string description)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !Directory.Exists(path))
            throw new InvalidOperationException($"The {description} must be an existing absolute directory.");
        return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
    }

    private static void DeleteOwnedRoot(DirectoryInfo root)
    {
        root.Refresh();
        var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
        if (root.LinkTarget is not null
            || !string.Equals(root.Parent?.FullName, temp, StringComparison.OrdinalIgnoreCase)
            || !root.Name.StartsWith("ensou-dsh-managed-profile-", StringComparison.Ordinal))
            throw new InvalidOperationException("Refusing cleanup outside the smoke helper's owned temp root.");
        root.Delete(recursive: true);
    }

    private static string FailureDiagnostics(ManagedOutput? stdout, BoundedCapture? stderr) =>
        $"stdout={Redact(SemanticExcerpt(stdout?.Snapshot() ?? "<unavailable>"))}; "
        + $"stderr={Redact(SemanticExcerpt(stderr?.Snapshot() ?? "<unavailable>"))}";

    private static string SemanticExcerpt(string output)
    {
        var lines = output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);
        var semantic = lines.Where(line => line.Contains("error", StringComparison.OrdinalIgnoreCase)
                || line.Contains("fail", StringComparison.OrdinalIgnoreCase)
                || line.Contains("dsh:", StringComparison.OrdinalIgnoreCase))
            .TakeLast(8)
            .ToArray();
        return string.Join(Environment.NewLine, semantic.Length == 0 ? lines.TakeLast(8) : semantic);
    }

    private static string Redact(string value) => Base64UrlSecret.Replace(
        NamedSecret.Replace(Token.Replace(value, "$1<redacted>"), "$1<redacted>"),
        "<redacted>");

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class ManagedOutput
    {
        private readonly TaskCompletionSource<string> _launch = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly object _sync = new();
        private readonly StringBuilder _output = new();

        internal ManagedOutput(StreamReader reader, CancellationToken token)
        {
            Completion = PumpAsync(reader, token);
        }

        internal Task<string> Launch => _launch.Task;
        internal Task<string> Completion { get; }
        internal string Snapshot()
        {
            lock (_sync) return _output.ToString();
        }

        private async Task<string> PumpAsync(StreamReader reader, CancellationToken token)
        {
            try
            {
                while (true)
                {
                    var line = await reader.ReadLineAsync(token);
                    if (line is null) break;
                    Append(line + Environment.NewLine);
                    if (line.StartsWith("dsh web: ", StringComparison.Ordinal))
                        _launch.TrySetResult(line);
                }
                _launch.TrySetException(new EndOfStreamException(
                    $"Managed CLI exited before launch: {Redact(SemanticExcerpt(Snapshot()))}"));
                return Snapshot();
            }
            catch (Exception exception)
            {
                _launch.TrySetException(exception);
                throw;
            }
        }

        private void Append(string value)
        {
            lock (_sync) AppendBounded(_output, value);
        }
    }

    private sealed class BoundedCapture
    {
        private readonly object _sync = new();
        private readonly StringBuilder _output = new();

        internal BoundedCapture(StreamReader reader, CancellationToken token)
        {
            Completion = PumpAsync(reader, token);
        }

        internal Task<string> Completion { get; }
        internal string Snapshot()
        {
            lock (_sync) return _output.ToString();
        }

        private async Task<string> PumpAsync(StreamReader reader, CancellationToken token)
        {
            var buffer = new char[1024];
            int count;
            while ((count = await reader.ReadAsync(buffer.AsMemory(), token)) != 0)
            {
                lock (_sync) AppendBounded(_output, new string(buffer, 0, count));
            }
            return Snapshot();
        }
    }

    private sealed class LoopbackHttpSink : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _serve;

        internal LoopbackHttpSink()
        {
            _listener.Start();
            var port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            BaseUri = new Uri($"http://127.0.0.1:{port}/v1", UriKind.Absolute);
            _serve = ServeAsync();
        }

        internal Uri BaseUri { get; }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel();
            _listener.Stop();
            try { await _serve; }
            catch (OperationCanceledException) { }
            _stop.Dispose();
        }

        private async Task ServeAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    await RespondAsync(client, _stop.Token);
                }
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
        }

        private static async Task RespondAsync(TcpClient client, CancellationToken token)
        {
            await using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            var bytes = 0;
            while (true)
            {
                var line = await reader.ReadLineAsync(token);
                if (line is null || line.Length == 0) break;
                bytes += line.Length + 2;
                if (bytes > 8 * 1024) throw new InvalidDataException("Model proxy request headers exceeded 8 KiB.");
            }
            const string body = "{\"object\":\"list\",\"data\":[]}";
            var response = Encoding.UTF8.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}");
            await stream.WriteAsync(response, token);
            await stream.FlushAsync(token);
        }
    }
}
