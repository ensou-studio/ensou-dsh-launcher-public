using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Text;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Host;

if (args is ["--connect", var pipeName])
{
    try
    {
        await using var client = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(5_000);
        await Task.Delay(300);
        return 0;
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine(
            $"FAIL wrong-PID pipe helper: {exception.GetType().Name}");
        return 1;
    }
}

if (!OperatingSystem.IsWindows())
{
    Console.WriteLine("SKIP runtime update channel checks require Windows.");
    return 0;
}

if (args is ["--managed-endpoint-validation"])
{
    try
    {
        await WrongPidAsync();
        await ManagedUpdateEndpointValidationChecks
            .ExactRetainedPipeAllowsSuspendedListenerAsync();
        await ManagedUpdateEndpointValidationChecks
            .MissingManagedChannelLeaseRejectsClosedListenerAsync();
        await ManagedUpdateEndpointValidationChecks
            .DifferentProcessIdentityRejectsAsync();
        await ManagedUpdateEndpointValidationChecks
            .MissingRuntimeLeaseRejectsAsync();
        await ManagedUpdateEndpointValidationChecks
            .TamperedRuntimeInventoryRejectsAsync();
        Console.WriteLine(
            "PASS  managed endpoint validation: exact pipe/PID, drain suspension, Resume ownership, lease and inventory fail-closed");
        return 0;
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine(
            $"FAIL managed endpoint validation: {exception}");
        return 1;
    }
}

if (args is ["--live-node"])
{
    try
    {
        await LiveNodeRuntimeChecks.RunAsync();
        return 0;
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"FAIL live Node checks: {exception}");
        return 1;
    }
}

if (args is ["--live-host"])
{
    try
    {
        await LiveHostStopChecks.RunAsync();
        return 0;
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"FAIL live Host checks: {exception}");
        return 1;
    }
}

if (args is ["--built-managed-profile-smoke", var candidateRoot, var nodePath])
{
    try
    {
        await BuiltManagedProfileSmoke.RunAsync(candidateRoot, nodePath);
        return 0;
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"FAIL built managed profile smoke: {exception}");
        return 1;
    }
}

if (args is ["--normal-managed-host-smoke", var runtimeRoot])
{
    try
    {
        await NormalManagedHostSmoke.RunAsync(runtimeRoot);
        return 0;
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"FAIL normal managed Host smoke: {exception}");
        return 1;
    }
}

var tests = new (string Name, Func<Task> Run)[]
{
    ("allocates exact bootstrap identities before launch", BootstrapIdentityAsync),
    ("rejects a connected client from a different OS process", WrongPidAsync),
    ("requires the exact listener at attach but retains the exact pipe during managed drain", ManagedUpdateEndpointValidationChecks.ExactRetainedPipeAllowsSuspendedListenerAsync),
    ("rejects a closed listener without the exact managed-update channel lease", ManagedUpdateEndpointValidationChecks.MissingManagedChannelLeaseRejectsClosedListenerAsync),
    ("rejects a different Process identity during managed drain", ManagedUpdateEndpointValidationChecks.DifferentProcessIdentityRejectsAsync),
    ("rejects managed drain without a retained runtime launch lease", ManagedUpdateEndpointValidationChecks.MissingRuntimeLeaseRejectsAsync),
    ("rejects managed drain after complete runtime inventory tamper", ManagedUpdateEndpointValidationChecks.TamperedRuntimeInventoryRejectsAsync),
    ("cancellation invalidates an unattached channel", CancellationInvalidatesAsync),
    ("rejects a response line over 8 KiB", OversizedResponseAsync),
    ("validates an exact ready receipt after both ownership checks", ExactReceiptAsync),
};
var failures = 0;
foreach (var test in tests)
{
    try { await test.Run(); Console.WriteLine($"PASS  {test.Name}"); }
    catch (Exception exception) { failures++; Console.Error.WriteLine($"FAIL  {test.Name}\n{exception}"); }
}
Console.WriteLine($"{tests.Length - failures}/{tests.Length} self-checks passed.");
return failures == 0 ? 0 : 1;

static Task BootstrapIdentityAsync()
{
    var instance = Guid.Parse("11111111-1111-1111-1111-111111111111");
    using var channel = DshRuntimeUpdateChannel.Create(
        static process => !process.HasExited,
        instance);
    var environment = channel.CreateBootstrapEnvironment();
    Assert(channel.PipeName == "ensou-dsh-update-11111111111111111111111111111111");
    Assert(environment[DshRuntimeUpdateChannel.UpdatePipeEnvironmentVariable]
        == @"\\.\pipe\ensou-dsh-update-11111111111111111111111111111111");
    Assert(environment[DshRuntimeUpdateChannel.RuntimeInstanceIdEnvironmentVariable]
        == "11111111-1111-1111-1111-111111111111");
    return Task.CompletedTask;
}

static async Task WrongPidAsync()
{
    using var channel = DshRuntimeUpdateChannel.Create(static process => !process.HasExited);
    using var client = StartOtherProcessClient(channel.PipeName);
    try
    {
        await ThrowsAsync<UnauthorizedAccessException>(() =>
            channel.AttachAsync(Process.GetCurrentProcess()));
    }
    finally
    {
        await client.WaitForExitAsync();
    }
}

static async Task CancellationInvalidatesAsync()
{
    using var channel = DshRuntimeUpdateChannel.Create(static process => !process.HasExited);
    using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));
    await ThrowsAsync<OperationCanceledException>(() =>
        channel.AttachAsync(Process.GetCurrentProcess(), cancellation.Token));
    await ThrowsAsync<ObjectDisposedException>(() => channel.RequestAsync(
        DshRuntimeUpdateAction.Status,
        Guid.NewGuid()));
}

static async Task OversizedResponseAsync()
{
    using var channel = DshRuntimeUpdateChannel.Create(static process => !process.HasExited);
    var serverRejectedOversizedResponse = new TaskCompletionSource<bool>(
        TaskCreationOptions.RunContinuationsAsynchronously);
    var client = ConnectCurrentProcessAsync(channel.PipeName, async stream =>
    {
        await ReadLineAsync(stream, CancellationToken.None);
        var oversized = Encoding.UTF8.GetBytes(new string('x',
            RuntimeUpdateControlProtocol.MaximumMessageBytes + 1) + "\n");
        try
        {
            await stream.WriteAsync(oversized);
            await stream.FlushAsync();
        }
        catch (IOException)
        {
            // Confirm that the server's request failed specifically because of
            // the oversized response before accepting this broken-pipe result.
            await serverRejectedOversizedResponse.Task;
        }
    });
    await channel.AttachAsync(Process.GetCurrentProcess());
    try
    {
        await ThrowsAsync<InvalidDataException>(() => channel.RequestAsync(
            DshRuntimeUpdateAction.Status,
            Guid.NewGuid()));
    }
    finally
    {
        serverRejectedOversizedResponse.TrySetResult(true);
    }
    await client;
    await ThrowsAsync<ObjectDisposedException>(() => channel.RequestAsync(
        DshRuntimeUpdateAction.Status,
        Guid.NewGuid()));
}

static async Task ExactReceiptAsync()
{
    var instance = Guid.Parse("11111111-1111-1111-1111-111111111111");
    var operation = Guid.Parse("22222222-2222-2222-2222-222222222222");
    var validationCount = 0;
    using var channel = DshRuntimeUpdateChannel.Create(
        process =>
        {
            validationCount++;
            return !process.HasExited;
        },
        instance);
    var process = Process.GetCurrentProcess();
    var client = ConnectCurrentProcessAsync(channel.PipeName, async stream =>
    {
        var request = await ReadLineAsync(stream, CancellationToken.None);
        Assert(request == "{\"protocol\":\"ensou.dsh.runtime-update.v1\",\"runtimeInstanceId\":\"11111111-1111-1111-1111-111111111111\",\"operationId\":\"22222222-2222-2222-2222-222222222222\",\"action\":\"status\"}");
        var receipt = $"{{\"protocol\":\"ensou.dsh.runtime-update.v1\",\"runtimeInstanceId\":\"{instance:D}\",\"operationId\":\"{operation:D}\",\"processId\":{process.Id},\"phase\":\"ready\",\"activeOperations\":0,\"persistenceFlushed\":true}}\n";
        await stream.WriteAsync(Encoding.UTF8.GetBytes(receipt));
        await stream.FlushAsync();
    });
    await channel.AttachAsync(process);
    var receipt = await channel.RequestAsync(DshRuntimeUpdateAction.Status, operation);
    await client;
    Assert(receipt.Phase == "ready" && receipt.PersistenceFlushed);
    Assert(validationCount >= 3);
}

static async Task ConnectCurrentProcessAsync(
    string pipeName,
    Func<Stream, Task> exchange)
{
    await using var client = new NamedPipeClientStream(
        ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
    await client.ConnectAsync(5_000);
    await exchange(client);
}

static Process StartOtherProcessClient(string pipeName)
{
    var executable = Environment.ProcessPath
        ?? throw new InvalidOperationException("The test executable path is unavailable.");
    var start = new ProcessStartInfo(executable)
    {
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
    {
        start.ArgumentList.Add(Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException("The test assembly path is unavailable."));
    }
    start.ArgumentList.Add("--connect");
    start.ArgumentList.Add(pipeName);
    return Process.Start(start)
        ?? throw new InvalidOperationException("The wrong-PID test client did not start.");
}

static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
{
    using var bytes = new MemoryStream();
    var next = new byte[1];
    while (true)
    {
        var count = await stream.ReadAsync(next, cancellationToken);
        if (count == 0) throw new EndOfStreamException();
        if (next[0] == (byte)'\n') return Encoding.UTF8.GetString(bytes.ToArray());
        bytes.WriteByte(next[0]);
    }
}

static void Assert(bool condition)
{
    if (!condition) throw new InvalidOperationException("Assertion failed.");
}

static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
{
    try { await action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"Expected {typeof(T).Name}.");
}
