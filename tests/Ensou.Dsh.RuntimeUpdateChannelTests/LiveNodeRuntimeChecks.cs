using System.Diagnostics;
using System.Text;
using Ensou.Dsh.Host;

internal static class LiveNodeRuntimeChecks
{
    internal static async Task RunAsync()
    {
        var source = RequiredFileRoot("ENSOU_TEST_DSH_SOURCE", "apps/cli/tests/fixtures/managed-update-process.ts");
        var node = Environment.GetEnvironmentVariable("ENSOU_TEST_NODE")
            ?? throw new InvalidOperationException("Explicit isolated Node path is required.");
        if (!Path.IsPathFullyQualified(node) || !File.Exists(node))
            throw new InvalidOperationException("Invalid isolated Node path.");
        await Task.WhenAll(RunCaseAsync(source, node, "normal"), RunCaseAsync(source, node, "disconnect"));
        await RunCaseAsync(source, node, "flush-failure");
        await RunCaseAsync(source, node, "stdin-eof");
    }

    private static async Task RunCaseAsync(string source, string node, string scenario)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var token = timeout.Token;
        var directory = Directory.CreateTempSubdirectory("ensou-dsh-live-channel-");
        var root = directory.FullName;
        using var channel = DshRuntimeUpdateChannel.Create(static process => !process.HasExited);
        var start = new ProcessStartInfo(node)
        {
            UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = source,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        start.ArgumentList.Add("--import");
        start.ArgumentList.Add(new Uri(Path.Combine(source, "node_modules/tsx/dist/loader.mjs")).AbsoluteUri);
        start.ArgumentList.Add(Path.Combine(source, "apps/cli/tests/fixtures/managed-update-process.ts"));
        start.ArgumentList.Add(root);
        start.ArgumentList.Add(scenario == "flush-failure" ? "flush-failure" : "normal");
        start.Environment["TSX_TSCONFIG_PATH"] = Path.Combine(source, "tsconfig.base.json");
        start.Environment["TSX_DISABLE_CACHE"] = "1";
        foreach (var pair in channel.CreateBootstrapEnvironment()) start.Environment[pair.Key] = pair.Value;
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Node fixture did not start.");
        child.StandardInput.AutoFlush = true;
        var errorOutput = ReadBoundedAsync(child.StandardError, token);
        try
        {
            await channel.AttachAsync(child, token);
            await ExpectLineAsync(child, $"fixture:ready:{child.Id}", token);
            if (scenario == "stdin-eof")
            {
                child.StandardInput.Close();
                await child.WaitForExitAsync(token);
                Assert(child.ExitCode == 0 && await errorOutput == "", "EOF cleanup did not exit normally.");
                Assert(await File.ReadAllTextAsync(Path.Combine(root, "completed.txt"), token) == "admitted work completed",
                    "EOF cleanup did not join fixture activity.");
                Console.WriteLine("PASS  live Node stdin-eof: admitted fixture activity joined, natural exit0");
                return;
            }
            var operation = Guid.NewGuid();
            var drain = await channel.RequestAsync(DshRuntimeUpdateAction.Drain, operation, token);
            Assert(drain.Phase == "draining" && drain.ActiveOperations > 0, "Active work was not retained.");
            if (scenario == "normal")
            {
                var resumed = await channel.RequestAsync(DshRuntimeUpdateAction.Resume, operation, token);
                Assert(resumed.Phase == "resumed", "Resume was not acknowledged.");
                await CommandAsync(child, "assert-open", "fixture:open-active-preserved", token);
                operation = Guid.NewGuid();
                _ = await channel.RequestAsync(DshRuntimeUpdateAction.Drain, operation, token);
            }
            if (scenario == "disconnect")
            {
                channel.Dispose();
                await CommandAsync(child, "assert-open", "fixture:open-active-preserved", token);
            }
            await CommandAsync(child, "release", "fixture:completed", token);
            if (scenario == "flush-failure")
            {
                while (true)
                {
                    var status = await channel.RequestAsync(DshRuntimeUpdateAction.Status, operation, token);
                    Assert(status.Phase != "ready", "Failed persistence was incorrectly ready.");
                    if (status.Phase == "resumed") break;
                    await Task.Delay(10, token);
                }
                await CommandAsync(child, "assert-restored", "fixture:restored", token);
                await CommandAsync(child, "clear-failure", "fixture:failure-cleared", token);
                operation = Guid.NewGuid();
                _ = await channel.RequestAsync(DshRuntimeUpdateAction.Drain, operation, token);
            }
            if (scenario is "normal" or "flush-failure")
            {
                while ((await channel.RequestAsync(DshRuntimeUpdateAction.Status, operation, token)).Phase != "ready")
                    await Task.Delay(10, token);
                var receipt = await channel.RequestAsync(DshRuntimeUpdateAction.Shutdown, operation, token);
                Assert(receipt.Phase == "ready" && receipt.PersistenceFlushed, "Shutdown lacked durable readiness.");
            }
            if (scenario == "disconnect") await child.StandardInput.WriteLineAsync("exit".AsMemory(), token);
            await child.WaitForExitAsync(token);
            Assert(child.ExitCode == 0, $"Node fixture exited {child.ExitCode}.");
            Assert(await errorOutput == "", "Node fixture reported an unhandled failure.");
            Assert(await File.ReadAllTextAsync(Path.Combine(root, "completed.txt"), token) == "admitted work completed",
                "Admitted work was not persisted before exit.");
            Assert(File.Exists(Path.Combine(root, "storage/workspace.json")), "Real workspace persistence was absent.");
            Assert(File.Exists(Path.Combine(root, "settings.yaml")) && File.Exists(Path.Combine(root, "credentials.yaml")),
                "Real document provider persistence was absent.");
            Console.WriteLine($"PASS  live Node {scenario}: exact PID, actual providers, exit0, owned cleanup");
        }
        catch (Exception failure)
        {
            if (child.HasExited)
            {
                string diagnostics;
                try { diagnostics = await errorOutput; }
                catch (Exception diagnosticFailure) when (diagnosticFailure is OperationCanceledException or IOException)
                {
                    diagnostics = $"stderr unavailable: {diagnosticFailure.GetType().Name}";
                }
                throw new InvalidOperationException($"{scenario} Node fixture failed: {diagnostics}", failure);
            }
            throw;
        }
        finally
        {
            channel.Dispose();
            if (!child.HasExited)
            {
                child.StandardInput.Close();
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try { await child.WaitForExitAsync(cleanup.Token); }
                catch (OperationCanceledException)
                {
                    // Only this retained test Process can be killed during failed-fixture cleanup.
                    child.Kill(entireProcessTree: true);
                    await child.WaitForExitAsync(CancellationToken.None);
                }
            }
            try { await errorOutput; }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
            directory.Refresh();
            if (directory.LinkTarget is not null || directory.Parent?.FullName != Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar)
                || !directory.Name.StartsWith("ensou-dsh-live-channel-", StringComparison.Ordinal))
                throw new InvalidOperationException("Refusing cleanup outside the owned fixture root.");
            directory.Delete(recursive: true);
        }
    }

    private static async Task CommandAsync(Process child, string command, string expected, CancellationToken token)
    {
        await child.StandardInput.WriteLineAsync(command.AsMemory(), token);
        await ExpectLineAsync(child, expected, token);
    }

    private static async Task ExpectLineAsync(Process child, string expected, CancellationToken token)
    {
        var line = await child.StandardOutput.ReadLineAsync(token);
        Assert(line == expected, $"Unexpected fixture response: {line ?? "EOF"}.");
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken token)
    {
        var output = new StringBuilder();
        var buffer = new char[1024];
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), token)) != 0)
        {
            if (output.Length + count > 32 * 1024) throw new InvalidDataException("Fixture stderr exceeded its bound.");
            output.Append(buffer, 0, count);
        }
        return output.ToString();
    }

    private static string RequiredFileRoot(string name, string relative)
    {
        var root = Environment.GetEnvironmentVariable(name);
        if (root is null || !Path.IsPathFullyQualified(root) || !File.Exists(Path.Combine(root, relative)))
            throw new InvalidOperationException($"Explicit {name} source fixture is required.");
        return Path.GetFullPath(root);
    }

    private static void Assert(bool passed, string message)
    {
        if (!passed) throw new InvalidOperationException(message);
    }
}
