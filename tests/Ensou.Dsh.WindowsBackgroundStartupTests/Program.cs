using Ensou.Dsh.Contracts;

var tests = new (string Name, Action Run)[]
{
    ("background startup exact command and idempotency", ExactAndIdempotent),
    ("background startup refuses foreign value", RefusesForeign),
    ("background startup removes only owned value", RemovesOnlyOwned),
    ("background startup failed verification cleans own write", FailedWriteIsCleaned),
    ("background startup concurrent replacement is never deleted", ConcurrentReplacementIsPreserved),
    ("background startup rejects unsafe stub paths", RejectsUnsafeStubPaths),
    ("background startup write failure does not claim ownership", WriteFailureDoesNotClaimOwnership),
    ("background startup delete failure preserves owned value", DeleteFailurePreservesOwnedValue),
    ("background startup restart handoff preserves hidden intent", RestartHandoffPreservesIntent),
    ("background startup always completes ownership handoff before initialization", HandoffPrecedesInitialization),
};
var failures = 0;
foreach (var test in tests)
{
    try { test.Run(); Console.WriteLine($"PASS  {test.Name}"); }
    catch (Exception exception) { failures++; Console.Error.WriteLine($"FAIL  {test.Name}\n{exception}"); }
}
Console.WriteLine($"{tests.Length - failures}/{tests.Length} self-checks passed.");
return failures == 0 ? 0 : 1;

static void ExactAndIdempotent()
{
    var store = new FakeStore();
    var path = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "stable", "StartupStub.exe"));
    Assert(WindowsBackgroundStartupRegistration.EnsureOwned(store, "Ensou.Test", path).Created);
    Assert(store.Value?.Command == $"\"{path}\" --background-startup");
    Assert(!WindowsBackgroundStartupRegistration.EnsureOwned(store, "Ensou.Test", path).Created);
    Assert(store.Writes == 1);
}

static void RefusesForeign()
{
    var store = new FakeStore { Value = new("foreign.exe --background-startup", UserRunValueKind.String) };
    Throws<InvalidOperationException>(() => WindowsBackgroundStartupRegistration.EnsureOwned(
        store, "Ensou.Test", Path.Combine(Path.GetTempPath(), "StartupStub.exe")));
    Assert(store.Writes == 0 && store.Deletes == 0);
}

static void RemovesOnlyOwned()
{
    var path = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "stable", "StartupStub.exe"));
    var store = new FakeStore();
    WindowsBackgroundStartupRegistration.EnsureOwned(store, "Ensou.Test", path);
    WindowsBackgroundStartupRegistration.RemoveOwned(store, "Ensou.Test", path);
    Assert(store.Value is null && store.Deletes == 1);
    store.Value = new("foreign.exe", UserRunValueKind.String);
    Throws<InvalidOperationException>(() => WindowsBackgroundStartupRegistration.RemoveOwned(
        store, "Ensou.Test", path));
    Assert(store.Value?.Command == "foreign.exe");
}

static void FailedWriteIsCleaned()
{
    var store = new FakeStore { LoseWrites = true };
    Throws<IOException>(() => WindowsBackgroundStartupRegistration.EnsureOwned(
        store, "Ensou.Test", Path.Combine(Path.GetTempPath(), "StartupStub.exe")));
    Assert(store.Deletes == 0);
}

static void ConcurrentReplacementIsPreserved()
{
    var foreign = new UserRunValue("foreign.exe", UserRunValueKind.String);
    var store = new FakeStore { ReplacementAfterWrite = foreign };
    Throws<IOException>(() => WindowsBackgroundStartupRegistration.EnsureOwned(
        store, "Ensou.Test", Path.GetFullPath(Path.Combine(Path.GetTempPath(), "StartupStub.exe"))));
    Assert(store.Value == foreign && store.Deletes == 0);

    var nonString = new FakeStore { Value = new(null, UserRunValueKind.Other) };
    Throws<InvalidOperationException>(() => WindowsBackgroundStartupRegistration.EnsureOwned(
        nonString, "Ensou.Test", Path.GetFullPath(Path.Combine(Path.GetTempPath(), "StartupStub.exe"))));
    Assert(nonString.Writes == 0 && nonString.Deletes == 0);
}

static void RejectsUnsafeStubPaths()
{
    var store = new FakeStore();
    Throws<ArgumentException>(() => WindowsBackgroundStartupRegistration.CreateCommand("StartupStub.exe"));
    Throws<ArgumentException>(() => WindowsBackgroundStartupRegistration.CreateCommand("  "));
    Throws<ArgumentException>(() => WindowsBackgroundStartupRegistration.CreateCommand(
        Path.Combine(Path.GetTempPath(), "unsafe\"stub.exe")));
    Throws<ArgumentException>(() => WindowsBackgroundStartupRegistration.EnsureOwned(
        store, "Ensou.Test", "relative-stub.exe"));
    Assert(store.Writes == 0 && store.Deletes == 0 && store.Value is null);
}

static void WriteFailureDoesNotClaimOwnership()
{
    var store = new FakeStore { ThrowOnWrite = true };
    Throws<IOException>(() => WindowsBackgroundStartupRegistration.EnsureOwned(
        store, "Ensou.Test", Path.GetFullPath(Path.Combine(Path.GetTempPath(), "StartupStub.exe"))));
    Assert(store.Writes == 1 && store.Deletes == 0 && store.Value is null);
}

static void DeleteFailurePreservesOwnedValue()
{
    var path = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "stable", "StartupStub.exe"));
    var store = new FakeStore { ThrowOnDelete = true };
    WindowsBackgroundStartupRegistration.EnsureOwned(store, "Ensou.Test", path);
    Throws<IOException>(() => WindowsBackgroundStartupRegistration.RemoveOwned(store, "Ensou.Test", path));
    Assert(store.Value?.Command == $"\"{path}\" --background-startup" && store.Deletes == 1);
}

static void RestartHandoffPreservesIntent()
{
    var command = PersonalLauncherRestartHandoffCommand.Create(
        Environment.ProcessId,
        backgroundStartup: true);
    var parsed = PersonalLauncherRestartHandoffCommand.ParseRequired(command.ToArguments());
    Assert(parsed.BackgroundStartup);
    Assert(parsed.ToArguments().SequenceEqual(command.ToArguments(), StringComparer.Ordinal));

    var visible = PersonalLauncherRestartHandoffCommand.Create(Environment.ProcessId);
    Assert(!PersonalLauncherRestartHandoffCommand.ParseRequired(visible.ToArguments())
        .BackgroundStartup);
    Throws<ArgumentException>(() => PersonalLauncherRestartHandoffCommand.ParseRequired(
        [.. visible.ToArguments(), "--unexpected"]));
}

static void HandoffPrecedesInitialization()
{
    foreach (var background in new[] { false, true })
    {
        Assert(LauncherStartupPolicy.SelectAction(true, background)
            == LauncherStartupAction.CompleteRestartHandoff);
        // The same policy runs again only after the receiver owns the runtime
        // boundary and the old process has exited (or yielded rollback ownership).
        Assert(LauncherStartupPolicy.SelectAction(false, background)
            == (background ? LauncherStartupAction.InitializeBackground : LauncherStartupAction.ShowLauncher));
    }
}

static void Assert(bool condition)
{
    if (!condition) throw new InvalidOperationException("Assertion failed.");
}

static void Throws<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"Expected {typeof(T).Name}.");
}

sealed class FakeStore : IUserRunValueStore
{
    public UserRunValue? Value { get; set; }
    public bool LoseWrites { get; init; }
    public bool ThrowOnWrite { get; init; }
    public bool ThrowOnDelete { get; init; }
    public UserRunValue? ReplacementAfterWrite { get; init; }
    public int Writes { get; private set; }
    public int Deletes { get; private set; }
    public UserRunValue? Read(string valueName) => Value;
    public void Write(string valueName, string command)
    {
        Writes++;
        if (ThrowOnWrite) throw new IOException("injected write failure");
        if (!LoseWrites) Value = ReplacementAfterWrite ?? new(command, UserRunValueKind.String);
    }
    public void Delete(string valueName)
    {
        Deletes++;
        if (ThrowOnDelete) throw new IOException("injected delete failure");
        Value = null;
    }
}
