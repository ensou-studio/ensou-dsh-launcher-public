using System.Security.Cryptography;
using System.Text;
using Ensou.Dsh.Personal.Client;
using Ensou.Dsh.Personal.Windows;

namespace Ensou.Dsh.Personal.WindowsTests;

internal static class Program
{
    private const string TestRootEnvironment = "ENSOU_PERSONAL_TEST_ROOT";
    private const string InstallationId = "11111111-1111-4111-8111-111111111111";
    private const string OtherInstallationId = "22222222-2222-4222-8222-222222222222";
    private const string SessionId = "33333333-3333-4333-8333-333333333333";
    private const string AccountId = "44444444-4444-4444-8444-444444444444";
    private static readonly Uri Origin = new("https://personal.example.test/");
    private static readonly DateTimeOffset IssuedAtUtc =
        new(2026, 9, 9, 0, 0, 0, TimeSpan.Zero);
    private static readonly string AccessToken =
        "psa_" + Base64Url(Enumerable.Repeat((byte)0xA1, 32).ToArray());
    private static readonly string RefreshToken =
        "psr_" + Base64Url(Enumerable.Repeat((byte)0xB2, 32).ToArray());
    private static readonly string NextAccessToken =
        "psa_" + Base64Url(Enumerable.Repeat((byte)0xA3, 32).ToArray());
    private static readonly string NextRefreshToken =
        "psr_" + Base64Url(Enumerable.Repeat((byte)0xB4, 32).ToArray());

    public static async Task<int> Main()
    {
        var ownedRoot = CreateOwnedRoot();
        try
        {
            var tests = new (string Name, Func<string, Task> Run)[]
            {
                ("DPAPI save load replace and clear", SaveLoadReplaceClearAsync),
                ("origin installation and path bindings fail closed", CrossBindingFailsClosedAsync),
                ("tampered DPAPI state fails closed", TamperedStateFailsClosedAsync),
                ("duplicate JSON state fails closed", DuplicateJsonFailsClosedAsync),
                ("pre-cancelled mutation leaves no state", PreCancelledMutationLeavesNoStateAsync),
            };
            var failures = 0;
            foreach (var test in tests)
            {
                var testRoot = Path.Combine(ownedRoot, Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(testRoot);
                try
                {
                    await test.Run(testRoot).ConfigureAwait(false);
                    Console.WriteLine($"PASS personal-windows {test.Name}");
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.Error.WriteLine(
                        $"FAIL personal-windows {test.Name}: {exception.GetType().Name}");
                }
            }

            Console.WriteLine($"PERSONAL WINDOWS RESULT {tests.Length - failures}/{tests.Length} passed");
            return failures == 0 ? 0 : 1;
        }
        finally
        {
            DeleteOwnedRoot(ownedRoot);
        }
    }

    private static async Task SaveLoadReplaceClearAsync(string stateRoot)
    {
        var store = new WindowsPersonalAccountSessionStore(stateRoot, Origin, InstallationId);
        var initial = Session(AccessToken, RefreshToken, IssuedAtUtc);
        await store.SaveAsync(initial).ConfigureAwait(false);
        var statePath = StatePath(stateRoot);
        var protectedBytes = await File.ReadAllBytesAsync(statePath).ConfigureAwait(false);
        try
        {
            var text = Encoding.UTF8.GetString(protectedBytes);
            Require(!text.Contains(AccessToken, StringComparison.Ordinal));
            Require(!text.Contains(RefreshToken, StringComparison.Ordinal));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
        }

        RequireSession(await store.LoadAsync().ConfigureAwait(false), initial);
        var replacement = Session(NextAccessToken, NextRefreshToken, IssuedAtUtc.AddMinutes(1));
        await store.SaveAsync(replacement).ConfigureAwait(false);
        RequireSession(await store.LoadAsync().ConfigureAwait(false), replacement);
        Require(Directory.GetFiles(
            Path.GetDirectoryName(statePath)!,
            "*.tmp",
            SearchOption.TopDirectoryOnly).Length == 0);
        await store.ClearAsync().ConfigureAwait(false);
        Require(await store.LoadAsync().ConfigureAwait(false) is null);
    }

    private static async Task CrossBindingFailsClosedAsync(string stateRoot)
    {
        var store = new WindowsPersonalAccountSessionStore(stateRoot, Origin, InstallationId);
        await store.SaveAsync(Session(AccessToken, RefreshToken, IssuedAtUtc)).ConfigureAwait(false);
        await ExpectInvalidAsync(() => new WindowsPersonalAccountSessionStore(
            stateRoot,
            new Uri("https://other.example.test/"),
            InstallationId).LoadAsync()).ConfigureAwait(false);
        await ExpectInvalidAsync(() => new WindowsPersonalAccountSessionStore(
            stateRoot,
            Origin,
            OtherInstallationId).LoadAsync()).ConfigureAwait(false);

        var otherRoot = Path.Combine(Path.GetDirectoryName(stateRoot)!, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(otherRoot, "personal-account"));
        File.Copy(StatePath(stateRoot), StatePath(otherRoot));
        await ExpectInvalidAsync(() => new WindowsPersonalAccountSessionStore(
            otherRoot,
            Origin,
            InstallationId).LoadAsync()).ConfigureAwait(false);
    }

    private static async Task TamperedStateFailsClosedAsync(string stateRoot)
    {
        var store = new WindowsPersonalAccountSessionStore(stateRoot, Origin, InstallationId);
        await store.SaveAsync(Session(AccessToken, RefreshToken, IssuedAtUtc)).ConfigureAwait(false);
        var statePath = StatePath(stateRoot);
        var bytes = await File.ReadAllBytesAsync(statePath).ConfigureAwait(false);
        try
        {
            bytes[bytes.Length / 2] ^= 0x5A;
            await File.WriteAllBytesAsync(statePath, bytes).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }

        await ExpectInvalidAsync(() => store.LoadAsync()).ConfigureAwait(false);
    }

    private static async Task DuplicateJsonFailsClosedAsync(string stateRoot)
    {
        var store = new WindowsPersonalAccountSessionStore(
            stateRoot,
            Origin,
            InstallationId,
            new PassThroughProtector());
        Directory.CreateDirectory(Path.GetDirectoryName(StatePath(stateRoot))!);
        var json = $$"""
            {"schemaVersion":1,"product":"ensou-dsh-personal","origin":"{{Origin.AbsoluteUri}}","sessionId":"{{SessionId}}","sessionId":"{{SessionId}}","accountId":"{{AccountId}}","installationId":"{{InstallationId}}","accessToken":"{{AccessToken}}","refreshToken":"{{RefreshToken}}","issuedAtUtc":"2026-09-09T00:00:00+00:00","accessExpiresAtUtc":"2026-09-09T00:05:00+00:00","refreshExpiresAtUtc":"2026-09-16T00:00:00+00:00"}
            """;
        var bytes = Encoding.UTF8.GetBytes(json);
        try
        {
            await File.WriteAllBytesAsync(StatePath(stateRoot), bytes).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }

        await ExpectInvalidAsync(() => store.LoadAsync()).ConfigureAwait(false);
    }

    private static async Task PreCancelledMutationLeavesNoStateAsync(string stateRoot)
    {
        var store = new WindowsPersonalAccountSessionStore(stateRoot, Origin, InstallationId);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await ExpectCancelledAsync(() => store.SaveAsync(
            Session(AccessToken, RefreshToken, IssuedAtUtc),
            cancellation.Token)).ConfigureAwait(false);
        Require(!File.Exists(StatePath(stateRoot)));
        await ExpectCancelledAsync(() => store.ClearAsync(cancellation.Token)).ConfigureAwait(false);
    }

    private static PersonalAccountSession Session(
        string accessToken,
        string refreshToken,
        DateTimeOffset issuedAtUtc) =>
        PersonalAccountSessionPersistence.RestoreValidated(
            Origin,
            InstallationId,
            Origin.AbsoluteUri,
            SessionId,
            AccountId,
            InstallationId,
            accessToken,
            refreshToken,
            issuedAtUtc,
            issuedAtUtc.AddMinutes(5),
            issuedAtUtc.AddDays(7));

    private static void RequireSession(
        PersonalAccountSession? actual,
        PersonalAccountSession expected)
    {
        if (actual is null)
        {
            throw new InvalidOperationException();
        }

        Require(actual.Origin == expected.Origin);
        Require(actual.SessionId == expected.SessionId);
        Require(actual.AccountId == expected.AccountId);
        Require(actual.InstallationId == expected.InstallationId);
        Require(actual.AccessToken == expected.AccessToken);
        Require(actual.RefreshToken == expected.RefreshToken);
        Require(actual.IssuedAtUtc == expected.IssuedAtUtc);
        Require(actual.AccessExpiresAtUtc == expected.AccessExpiresAtUtc);
        Require(actual.RefreshExpiresAtUtc == expected.RefreshExpiresAtUtc);
    }

    private static async Task ExpectInvalidAsync(Func<Task<PersonalAccountSession?>> operation)
    {
        try
        {
            _ = await operation().ConfigureAwait(false);
        }
        catch (InvalidDataException)
        {
            return;
        }

        throw new InvalidOperationException();
    }

    private static async Task ExpectCancelledAsync(Func<Task> operation)
    {
        try
        {
            await operation().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        throw new InvalidOperationException();
    }

    private static string CreateOwnedRoot()
    {
        var configured = Environment.GetEnvironmentVariable(TestRootEnvironment);
        if (string.IsNullOrWhiteSpace(configured))
        {
            throw new InvalidOperationException($"{TestRootEnvironment} is required.");
        }

        if (!Path.IsPathFullyQualified(configured))
        {
            throw new InvalidOperationException("The Personal Windows test root is unsafe.");
        }

        var baseRoot = Path.GetFullPath(configured);
        if (!Path.IsPathFullyQualified(baseRoot)
            || string.Equals(baseRoot, Path.GetPathRoot(baseRoot), StringComparison.OrdinalIgnoreCase)
            || baseRoot.StartsWith("\\\\", StringComparison.Ordinal)
            || !Directory.Exists(baseRoot))
        {
            throw new InvalidOperationException("The Personal Windows test root is unsafe.");
        }

        RequireOrdinaryDirectoryChain(baseRoot);

        var ownedRoot = Path.Combine(baseRoot, $"personal-windows-{Guid.NewGuid():N}");
        Directory.CreateDirectory(ownedRoot);
        using (new FileStream(
            Path.Combine(ownedRoot, ".owned-by-personal-windows-tests"),
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None))
        {
        }

        return ownedRoot;
    }

    private static void DeleteOwnedRoot(string ownedRoot)
    {
        var configured = Environment.GetEnvironmentVariable(TestRootEnvironment);
        if (string.IsNullOrWhiteSpace(configured) || !Path.IsPathFullyQualified(configured))
        {
            throw new InvalidOperationException("The Personal Windows test root lost ownership evidence.");
        }

        var baseRoot = Path.GetFullPath(configured);
        var marker = Path.Combine(ownedRoot, ".owned-by-personal-windows-tests");
        if (!File.Exists(marker)
            || !string.Equals(
                Path.GetFileName(ownedRoot).StartsWith("personal-windows-", StringComparison.Ordinal)
                    ? Path.GetDirectoryName(ownedRoot)
                    : null,
                baseRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The Personal Windows test root lost ownership evidence.");
        }

        RequireOrdinaryDirectoryChain(baseRoot);
        RequireTreeWithoutReparse(ownedRoot);
        Directory.Delete(ownedRoot, recursive: true);
    }

    private static void RequireOrdinaryDirectoryChain(string directory)
    {
        var chain = new Stack<string>();
        for (var current = directory; current is not null; current = Path.GetDirectoryName(current))
        {
            chain.Push(current);
        }

        while (chain.TryPop(out var current))
        {
            var attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.Directory) == 0
                || (attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("The Personal Windows test root is unsafe.");
            }
        }
    }

    private static void RequireTreeWithoutReparse(string directory)
    {
        var directoryAttributes = File.GetAttributes(directory);
        if ((directoryAttributes & FileAttributes.Directory) == 0
            || (directoryAttributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("The Personal Windows test tree is unsafe to remove.");
        }

        foreach (var path in Directory.EnumerateFileSystemEntries(directory))
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("The Personal Windows test tree is unsafe to remove.");
            }

            if ((attributes & FileAttributes.Directory) != 0)
            {
                RequireTreeWithoutReparse(path);
            }
        }
    }

    private static string StatePath(string stateRoot) =>
        Path.Combine(stateRoot, "personal-account", "session.v1.dpapi");

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException();
        }
    }

    private sealed class PassThroughProtector : IPersonalAccountDataProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> entropy) =>
            plaintext.ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedBytes, ReadOnlySpan<byte> entropy) =>
            protectedBytes.ToArray();
    }
}
