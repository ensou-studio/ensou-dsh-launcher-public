using Ensou.Dsh.Contracts;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.UpdateEngine;
using System.Runtime.InteropServices;

namespace Ensou.Dsh.ManagedArtifactGcTests;

internal static class Program
{
    private static readonly DateTimeOffset Now = new(2026, 8, 26, 12, 0, 0, TimeSpan.Zero);
    private static readonly string A = new('a', 64);
    private static readonly string B = new('b', 64);

    private static async Task<int> Main()
    {
        var tests = new (string Name, Func<Task> Run)[]
        {
            ("personal keeps current and previous and removes old versions", PersonalKeepsTwoAsync),
            ("enterprise keeps current and previous and removes old versions", EnterpriseKeepsTwoAsync),
            ("personal pending pointer and download session block GC", PersonalPendingBlocksAsync),
            ("enterprise pending pointer blocks GC", EnterprisePendingBlocksAsync),
            ("personal cache cleanup is stale and bounded", PersonalCacheIsBoundedAsync),
            ("enterprise cache cleanup is stale and bounded", EnterpriseCacheIsBoundedAsync),
            ("personal deletion failure records and retries", PersonalDeletionRetriesAsync),
            ("enterprise deletion failure records and retries", EnterpriseDeletionRetriesAsync),
            ("personal operation lease is exclusive and outside rename root", PersonalLeaseAndRenameAsync),
            ("enterprise operation lease is exclusive and outside rename root", EnterpriseLeaseAndRenameAsync),
            ("personal operation lock rejects hardlink and reparse", PersonalLockLinksFailClosedAsync),
            ("enterprise operation lock rejects hardlink and reparse", EnterpriseLockLinksFailClosedAsync),
            ("managed version trees reject hardlinks", VersionTreeHardlinksFailClosedAsync),
            ("personal reparse escape fails closed", PersonalReparseFailsClosedAsync),
            ("enterprise reparse escape fails closed", EnterpriseReparseFailsClosedAsync),
            ("personal repeated GC is idempotent", PersonalRepeatedGcAsync),
            ("enterprise repeated GC is idempotent", EnterpriseRepeatedGcAsync),
            ("pointer change is detected after cleanup", PointerChangeDetectedAsync),
        };
        var failures = 0;
        foreach (var test in tests)
        {
            try
            {
                await test.Run().ConfigureAwait(false);
                Console.WriteLine($"PASS {test.Name}");
            }
            catch (Exception exception)
            {
                failures++;
                Console.Error.WriteLine($"FAIL {test.Name}: {exception}");
            }
        }
        return failures == 0 ? 0 : 1;
    }

    private static Task PersonalKeepsTwoAsync()
    {
        using var fixture = new PersonalFixture();
        var pointer = fixture.SeedVersions();
        var result = fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now);
        Equal(PersonalManagedArtifactGcStatus.Completed, result.Status);
        Equal(2, result.RemovedVersionDirectories);
        True(Directory.Exists(fixture.Layout.GetClientBundleDirectory("client-current")));
        True(Directory.Exists(fixture.Layout.GetClientBundleDirectory("client-previous")));
        False(Directory.Exists(fixture.Layout.GetClientBundleDirectory("client-old")));
        True(Directory.Exists(fixture.Layout.GetRuntimeDirectory("runtime-current")));
        True(Directory.Exists(fixture.Layout.GetRuntimeDirectory("runtime-previous")));
        False(Directory.Exists(fixture.Layout.GetRuntimeDirectory("runtime-old")));
        True(Directory.Exists(fixture.Layout.HarnessHome));
        True(File.Exists(Path.Combine(fixture.Layout.HarnessHome, "conversation.json")));
        return Task.CompletedTask;
    }

    private static Task EnterpriseKeepsTwoAsync()
    {
        using var fixture = new EnterpriseFixture();
        var pointer = fixture.SeedVersions();
        var result = fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now);
        Equal(EnterpriseManagedArtifactGcStatus.Completed, result.Status);
        Equal(3, result.RemovedVersionDirectories);
        True(Directory.Exists(fixture.Layout.GetLauncherVersionDirectory("launcher-current")));
        True(Directory.Exists(fixture.Layout.GetLauncherVersionDirectory("launcher-previous")));
        False(Directory.Exists(fixture.Layout.GetLauncherVersionDirectory("launcher-old")));
        True(Directory.Exists(fixture.Layout.GetRuntimeVersionDirectory("runtime-current")));
        True(Directory.Exists(fixture.Layout.GetRuntimeVersionDirectory("runtime-previous")));
        False(Directory.Exists(fixture.Layout.GetRuntimeVersionDirectory("runtime-old")));
        True(Directory.Exists(fixture.Layout.GetPluginPolicyVersionDirectory("plugin-current")));
        True(Directory.Exists(fixture.Layout.GetPluginPolicyVersionDirectory("plugin-previous")));
        False(Directory.Exists(fixture.Layout.GetPluginPolicyVersionDirectory("plugin-old")));
        True(File.Exists(Path.Combine(fixture.Layout.HarnessHome, "workspace.json")));
        return Task.CompletedTask;
    }

    private static Task PersonalPendingBlocksAsync()
    {
        using var fixture = new PersonalFixture();
        var healthy = fixture.SeedVersions();
        var old = fixture.Layout.GetClientBundleDirectory("client-old");
        var pending = healthy with
        {
            Current = healthy.Current with
            {
                HealthState = PersonalReleaseHealthStates.Pending,
                HealthToken = "pending",
                HomeTransactionId = "home",
            },
        };
        var blocked = fixture.Collector().CollectTrustedUnderLease(pending, () => pending, Now);
        Equal(PersonalManagedArtifactGcStatus.SkippedPending, blocked.Status);
        True(Directory.Exists(old));

        var sessions = new PersonalManagedUpdateSessionStore(fixture.Layout);
        sessions.Begin("candidate", A, A, B);
        var sessionBlocked = fixture.Collector().CollectTrustedUnderLease(
            healthy,
            () => healthy,
            DateTimeOffset.UtcNow);
        Equal(PersonalManagedArtifactGcStatus.SkippedPending, sessionBlocked.Status);
        True(Directory.Exists(old));
        sessions.Complete("candidate", A, A, B);
        var completed = fixture.Collector().CollectTrustedUnderLease(
            healthy,
            () => healthy,
            DateTimeOffset.UtcNow);
        Equal(PersonalManagedArtifactGcStatus.Completed, completed.Status);
        False(Directory.Exists(old));
        return Task.CompletedTask;
    }

    private static Task EnterprisePendingBlocksAsync()
    {
        using var fixture = new EnterpriseFixture();
        var healthy = fixture.SeedVersions();
        var pending = healthy with
        {
            Current = healthy.Current with
            {
                HealthState = EnterpriseReleaseHealthStates.Pending,
                HealthToken = "pending",
            },
        };
        var result = fixture.Collector().CollectTrustedUnderLease(pending, () => pending, Now);
        Equal(EnterpriseManagedArtifactGcStatus.SkippedPending, result.Status);
        True(Directory.Exists(fixture.Layout.GetLauncherVersionDirectory("launcher-old")));
        return Task.CompletedTask;
    }

    private static Task PersonalCacheIsBoundedAsync()
    {
        using var fixture = new PersonalFixture();
        var pointer = fixture.SeedVersions();
        var completeKey = new string('1', 64);
        var temporaryMetadata = "." + completeKey + ".partial.json."
            + Guid.NewGuid().ToString("N") + ".tmp";
        WriteCacheFile(fixture.Layout.PartialCacheRoot, completeKey + ".complete", Now);
        WriteCacheFile(fixture.Layout.PartialCacheRoot, "." + completeKey + ".lock", Now);
        WriteCacheFile(fixture.Layout.PartialCacheRoot, temporaryMetadata, Now);
        for (var index = 0; index < 6; index++)
        {
            var key = index.ToString("x").PadLeft(64, '0');
            var when = index == 0 ? Now.AddDays(-8) : Now.AddMinutes(-index);
            WriteCacheFile(fixture.Layout.PartialCacheRoot, key + ".partial", when);
            WriteCacheFile(fixture.Layout.PartialCacheRoot, key + ".partial.json", when);
            WriteCacheFile(fixture.Layout.PartialCacheRoot, "." + key + ".lock", when);
        }
        var result = fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now);
        Equal(PersonalManagedArtifactGcStatus.Completed, result.Status);
        False(File.Exists(Path.Combine(
            fixture.Layout.PartialCacheRoot,
            completeKey + ".complete")));
        False(File.Exists(Path.Combine(fixture.Layout.PartialCacheRoot, temporaryMetadata)));
        Equal(4, Directory.EnumerateFiles(fixture.Layout.PartialCacheRoot, "*.partial").Count());
        return Task.CompletedTask;
    }

    private static Task EnterpriseCacheIsBoundedAsync()
    {
        using var fixture = new EnterpriseFixture();
        var pointer = fixture.SeedVersions();
        var temporaryKey = new string('1', 64);
        var temporaryMetadata = "." + temporaryKey + ".partial.json."
            + Guid.NewGuid().ToString("N") + ".tmp";
        WriteCacheFile(fixture.Layout.UpdatePartialCacheRoot, temporaryMetadata, Now);
        for (var index = 0; index < 6; index++)
        {
            var key = index.ToString("x").PadLeft(64, '0');
            var when = index == 0 ? Now.AddDays(-8) : Now.AddMinutes(-index);
            WriteCacheFile(fixture.Layout.UpdatePartialCacheRoot, key + ".partial", when);
            WriteCacheFile(fixture.Layout.UpdatePartialCacheRoot, key + ".partial.json", when);
        }
        var releaseSetOperation = Path.Combine(
            fixture.Layout.PackageRoot,
            ".release-set-" + Guid.NewGuid().ToString("N"));
        var installOperation = Path.Combine(
            fixture.Layout.PackageRoot,
            ".install-" + Guid.NewGuid().ToString("N"));
        SeedTree(releaseSetOperation);
        SeedTree(installOperation);
        var result = fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now);
        Equal(EnterpriseManagedArtifactGcStatus.Completed, result.Status);
        Equal(2, result.RemovedOperationDirectories);
        False(Directory.Exists(releaseSetOperation));
        False(Directory.Exists(installOperation));
        False(File.Exists(Path.Combine(fixture.Layout.UpdatePartialCacheRoot, temporaryMetadata)));
        Equal(4, Directory.EnumerateFiles(
            fixture.Layout.UpdatePartialCacheRoot,
            "*.partial").Count());
        return Task.CompletedTask;
    }

    private static Task PersonalDeletionRetriesAsync()
    {
        using var fixture = new PersonalFixture();
        var pointer = fixture.SeedVersions();
        var injected = false;
        var first = fixture.Collector(path =>
        {
            if (!injected && Directory.Exists(path))
            {
                injected = true;
                throw new IOException("injected delete failure");
            }
        });
        Throws<InvalidOperationException>(() =>
            first.CollectTrustedUnderLease(pointer, () => pointer, Now));
        True(File.Exists(Path.Combine(
            fixture.Layout.StateRoot,
            "managed-artifact-gc.retry.v1.json")));
        var second = fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now);
        True(second.RetriedPreviousFailure);
        False(File.Exists(Path.Combine(
            fixture.Layout.StateRoot,
            "managed-artifact-gc.retry.v1.json")));
        False(Directory.Exists(Path.Combine(
            fixture.Layout.PackageRoot,
            ".managed-gc-quarantine-v1")));
        return Task.CompletedTask;
    }

    private static Task EnterpriseDeletionRetriesAsync()
    {
        using var fixture = new EnterpriseFixture();
        var pointer = fixture.SeedVersions();
        var injected = false;
        var first = fixture.Collector(path =>
        {
            if (!injected && Directory.Exists(path))
            {
                injected = true;
                throw new IOException("injected delete failure");
            }
        });
        Throws<InvalidOperationException>(() =>
            first.CollectTrustedUnderLease(pointer, () => pointer, Now));
        True(File.Exists(Path.Combine(
            fixture.Layout.StateRoot,
            "managed-artifact-gc.retry.v1.json")));
        var second = fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now);
        True(second.RetriedPreviousFailure);
        False(File.Exists(Path.Combine(
            fixture.Layout.StateRoot,
            "managed-artifact-gc.retry.v1.json")));
        return Task.CompletedTask;
    }

    private static async Task PersonalLeaseAndRenameAsync()
    {
        using var fixture = new PersonalFixture();
        fixture.Layout.EnsureManagedRoots();
        var first = await PersonalManagedUpdateOperationLease.AcquireRequiredAsync(fixture.Layout);
        try
        {
            True(PersonalManagedUpdateOperationLease.TryAcquire(fixture.Layout) is null);
            using (var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100)))
            {
                await ThrowsAsync<OperationCanceledException>(() =>
                    PersonalManagedUpdateOperationLease.AcquireRequiredAsync(
                        fixture.Layout,
                        cancellation.Token));
            }
            var moved = fixture.Layout.ManagedRoot + ".moved";
            Directory.Move(fixture.Layout.ManagedRoot, moved);
            True(Directory.Exists(moved));
            False(Directory.Exists(fixture.Layout.ManagedRoot));

            var entered = false;
            var waiter = Task.Run(async () =>
            {
                await using var second =
                    await PersonalManagedUpdateOperationLease.AcquireRequiredAsync(fixture.Layout);
                entered = true;
            });
            await Task.Delay(150);
            False(entered);
            False(Directory.Exists(fixture.Layout.ManagedRoot));
            Directory.Move(moved, fixture.Layout.ManagedRoot);
            first.Dispose();
            await waiter.WaitAsync(TimeSpan.FromSeconds(5));
            True(entered);
        }
        finally
        {
            first.Dispose();
        }
    }

    private static async Task EnterpriseLeaseAndRenameAsync()
    {
        using var fixture = new EnterpriseFixture();
        fixture.Layout.EnsureManagedRoots();
        var first = await EnterpriseManagedUpdateOperationLease.AcquireRequiredAsync(fixture.Layout);
        try
        {
            True(EnterpriseManagedUpdateOperationLease.TryAcquire(fixture.Layout) is null);
            using (var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100)))
            {
                await ThrowsAsync<OperationCanceledException>(() =>
                    EnterpriseManagedUpdateOperationLease.AcquireRequiredAsync(
                        fixture.Layout,
                        cancellation.Token));
            }
            var moved = fixture.Layout.ManagedRoot + ".moved";
            Directory.Move(fixture.Layout.ManagedRoot, moved);
            True(Directory.Exists(moved));
            False(Directory.Exists(fixture.Layout.ManagedRoot));

            var entered = false;
            var waiter = Task.Run(async () =>
            {
                await using var second =
                    await EnterpriseManagedUpdateOperationLease.AcquireRequiredAsync(fixture.Layout);
                entered = true;
            });
            await Task.Delay(150);
            False(entered);
            False(Directory.Exists(fixture.Layout.ManagedRoot));
            Directory.Move(moved, fixture.Layout.ManagedRoot);
            first.Dispose();
            await waiter.WaitAsync(TimeSpan.FromSeconds(5));
            True(entered);
        }
        finally
        {
            first.Dispose();
        }
    }

    private static async Task PersonalLockLinksFailClosedAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        using var fixture = new PersonalFixture();
        fixture.Layout.EnsureUpdateOperationLockRoot();
        var target = Path.Combine(fixture.Root, "personal-lock-target.bin");
        File.WriteAllText(target, "outside");
        if (!CreateHardLink(
                fixture.Layout.UpdateOperationLockPath,
                target,
                IntPtr.Zero))
        {
            throw new IOException(
                "Unable to create personal operation-lock hardlink test fixture.");
        }
        await ThrowsAsync<InvalidDataException>(() =>
            PersonalManagedUpdateOperationLease.AcquireRequiredAsync(fixture.Layout));
        File.Delete(fixture.Layout.UpdateOperationLockPath);
        True(File.Exists(target));

        if (TryCreateFileLink(fixture.Layout.UpdateOperationLockPath, target))
        {
            await ThrowsAsync<InvalidDataException>(() =>
                PersonalManagedUpdateOperationLease.AcquireRequiredAsync(fixture.Layout));
            File.Delete(fixture.Layout.UpdateOperationLockPath);
            True(File.Exists(target));
        }
    }

    private static async Task EnterpriseLockLinksFailClosedAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        using var fixture = new EnterpriseFixture();
        fixture.Layout.EnsureUpdateOperationLockRoot();
        var target = Path.Combine(fixture.Root, "enterprise-lock-target.bin");
        File.WriteAllText(target, "outside");
        if (!CreateHardLink(
                fixture.Layout.UpdateOperationLockPath,
                target,
                IntPtr.Zero))
        {
            throw new IOException(
                "Unable to create enterprise operation-lock hardlink test fixture.");
        }
        await ThrowsAsync<InvalidDataException>(() =>
            EnterpriseManagedUpdateOperationLease.AcquireRequiredAsync(fixture.Layout));
        File.Delete(fixture.Layout.UpdateOperationLockPath);
        True(File.Exists(target));

        if (TryCreateFileLink(fixture.Layout.UpdateOperationLockPath, target))
        {
            await ThrowsAsync<InvalidDataException>(() =>
                EnterpriseManagedUpdateOperationLease.AcquireRequiredAsync(fixture.Layout));
            File.Delete(fixture.Layout.UpdateOperationLockPath);
            True(File.Exists(target));
        }
    }

    private static Task VersionTreeHardlinksFailClosedAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.CompletedTask;
        }

        using (var fixture = new PersonalFixture())
        {
            var pointer = fixture.SeedVersions();
            var external = Path.Combine(fixture.Root, "personal-hardlink-target.bin");
            File.WriteAllText(external, "outside");
            var linked = Path.Combine(
                fixture.Layout.GetClientBundleDirectory("client-old"),
                "linked.bin");
            if (!CreateHardLink(linked, external, IntPtr.Zero))
            {
                throw new IOException("Unable to create personal managed-tree hardlink fixture.");
            }
            Throws<InvalidOperationException>(() =>
                fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now));
            True(File.Exists(external));
            True(Directory.Exists(fixture.Layout.GetClientBundleDirectory("client-old")));
        }

        using (var fixture = new EnterpriseFixture())
        {
            var pointer = fixture.SeedVersions();
            var external = Path.Combine(fixture.Root, "enterprise-hardlink-target.bin");
            File.WriteAllText(external, "outside");
            var linked = Path.Combine(
                fixture.Layout.GetLauncherVersionDirectory("launcher-old"),
                "linked.bin");
            if (!CreateHardLink(linked, external, IntPtr.Zero))
            {
                throw new IOException("Unable to create enterprise managed-tree hardlink fixture.");
            }
            Throws<InvalidOperationException>(() =>
                fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now));
            True(File.Exists(external));
            True(Directory.Exists(fixture.Layout.GetLauncherVersionDirectory("launcher-old")));
        }
        return Task.CompletedTask;
    }

    private static Task PersonalReparseFailsClosedAsync()
    {
        using var fixture = new PersonalFixture();
        var pointer = fixture.SeedVersions();
        var external = Path.Combine(fixture.Root, "external");
        Directory.CreateDirectory(external);
        File.WriteAllText(Path.Combine(external, "do-not-delete.txt"), "safe");
        var link = Path.Combine(fixture.Layout.ClientBundleVersionsRoot, "linked-old");
        if (!TryCreateDirectoryLink(link, external))
        {
            return Task.CompletedTask;
        }
        Throws<InvalidOperationException>(() =>
            fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now));
        True(File.Exists(Path.Combine(external, "do-not-delete.txt")));
        return Task.CompletedTask;
    }

    private static Task EnterpriseReparseFailsClosedAsync()
    {
        using var fixture = new EnterpriseFixture();
        var pointer = fixture.SeedVersions();
        var external = Path.Combine(fixture.Root, "external");
        Directory.CreateDirectory(external);
        File.WriteAllText(Path.Combine(external, "do-not-delete.txt"), "safe");
        var link = Path.Combine(fixture.Layout.LauncherVersionsRoot, "linked-old");
        if (!TryCreateDirectoryLink(link, external))
        {
            return Task.CompletedTask;
        }
        Throws<InvalidOperationException>(() =>
            fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now));
        True(File.Exists(Path.Combine(external, "do-not-delete.txt")));
        return Task.CompletedTask;
    }

    private static Task PersonalRepeatedGcAsync()
    {
        using var fixture = new PersonalFixture();
        var pointer = fixture.SeedVersions();
        _ = fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now);
        var second = fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now);
        Equal(0, second.RemovedVersionDirectories);
        Equal(0, second.RemovedCacheFiles);
        return Task.CompletedTask;
    }

    private static Task EnterpriseRepeatedGcAsync()
    {
        using var fixture = new EnterpriseFixture();
        var pointer = fixture.SeedVersions();
        _ = fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now);
        var second = fixture.Collector().CollectTrustedUnderLease(pointer, () => pointer, Now);
        Equal(0, second.RemovedVersionDirectories);
        Equal(0, second.RemovedCacheFiles);
        Equal(0, second.RemovedOperationDirectories);
        return Task.CompletedTask;
    }

    private static Task PointerChangeDetectedAsync()
    {
        using var fixture = new PersonalFixture();
        var pointer = fixture.SeedVersions();
        var changed = pointer with { UpdatedAtUtc = pointer.UpdatedAtUtc.AddSeconds(1) };
        Throws<InvalidOperationException>(() =>
            fixture.Collector().CollectTrustedUnderLease(pointer, () => changed, Now));
        True(File.Exists(Path.Combine(
            fixture.Layout.StateRoot,
            "managed-artifact-gc.retry.v1.json")));
        return Task.CompletedTask;
    }

    private static void WriteCacheFile(string root, string name, DateTimeOffset when)
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, name);
        File.WriteAllText(path, "cache");
        File.SetLastWriteTimeUtc(path, when.UtcDateTime);
    }

    private static bool TryCreateDirectoryLink(string link, string target)
    {
        try
        {
            _ = Directory.CreateSymbolicLink(link, target);
            return true;
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException
                or IOException
                or PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static bool TryCreateFileLink(string link, string target)
    {
        try
        {
            _ = File.CreateSymbolicLink(link, target);
            return true;
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException
                or IOException
                or PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static void SeedTree(string path)
    {
        Directory.CreateDirectory(path);
        File.WriteAllText(Path.Combine(path, "payload.bin"), Path.GetFileName(path));
    }

    private static void True(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void False(bool value) => True(!value);

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected {expected}; actual {actual}.");
        }
    }

    private static void Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (T)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    private sealed class PersonalFixture : IDisposable
    {
        public PersonalFixture()
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "ensou-personal-gc-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
            Layout = new PersonalInstallationLayout(
                Path.Combine(Root, "managed"),
                Path.Combine(Root, "home"),
                Path.Combine(Root, "witness", "state.dpapi"));
            Layout.EnsureManagedRoots();
            Directory.CreateDirectory(Layout.HarnessHome);
            File.WriteAllText(Path.Combine(Layout.HarnessHome, "conversation.json"), "local");
        }

        public string Root { get; }

        public PersonalInstallationLayout Layout { get; }

        public PersonalManagedArtifactGarbageCollector Collector(
            Action<string>? beforeDelete = null) => new(Layout, null, beforeDelete);

        public PersonalInstalledReleaseSetPointer SeedVersions()
        {
            foreach (var release in new[] { "client-current", "client-previous", "client-old" })
            {
                SeedTree(Layout.GetClientBundleDirectory(release));
            }
            foreach (var release in new[] { "runtime-current", "runtime-previous", "runtime-old" })
            {
                SeedTree(Layout.GetRuntimeDirectory(release));
            }
            var current = PersonalReference(
                "set-current",
                "client-current",
                "runtime-current",
                sequence: 2);
            var previous = PersonalReference(
                "set-previous",
                "client-previous",
                "runtime-previous",
                sequence: 1);
            return new PersonalInstalledReleaseSetPointer(
                3,
                PersonalReleaseSetContract.Product,
                PersonalReleaseSetContract.ProductionEnvironment,
                "stable",
                current,
                previous,
                Now);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }

        private PersonalInstalledReleaseSetReference PersonalReference(
            string set,
            string client,
            string runtime,
            long sequence) => new(
            set,
            sequence,
            sequence,
            0,
            A,
            new PersonalStartupStubCompatibility
            {
                MinimumVersion = "1.0.0",
                MaximumVersion = "1.0.0",
            },
            new PersonalInstalledComponentReference(
                PersonalReleaseSetContract.ClientBundleComponent,
                client,
                Layout.GetClientBundleDirectory(client),
                A,
                B),
            new PersonalInstalledComponentReference(
                PersonalReleaseSetContract.RuntimeComponent,
                runtime,
                Layout.GetRuntimeDirectory(runtime),
                A,
                B),
            PersonalReleaseHealthStates.Healthy,
            null,
            null,
            Now);
    }

    private sealed class EnterpriseFixture : IDisposable
    {
        public EnterpriseFixture()
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "ensou-enterprise-gc-tests",
                Guid.NewGuid().ToString("N"));
            var local = Path.Combine(Root, "local");
            var profile = Path.Combine(Root, "profile");
            Directory.CreateDirectory(local);
            Directory.CreateDirectory(profile);
            Layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(local, profile);
            Layout.EnsureManagedRoots();
            Directory.CreateDirectory(Layout.HarnessHome);
            File.WriteAllText(Path.Combine(Layout.HarnessHome, "workspace.json"), "local");
            Trust = new EnterpriseCompiledReleaseTrust(
                new Uri("https://updates.invalid/manifest.json"),
                new EnterpriseReleaseTrustPolicy
                {
                    Product = EnterpriseReleaseSetContract.Product,
                    Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                    ExpectedChannel = EnterpriseReleaseSetContract.LabChannel,
                    CurrentStartupStubProtocol =
                        EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                    ManifestOrigin = new Uri("https://updates.invalid"),
                    ArtifactOrigin = new Uri("https://artifacts.invalid"),
                    TrustedKeys =
                    [
                        new EnterpriseReleasePublicKey("test", "AA", "AA"),
                    ],
                });
        }

        public string Root { get; }

        public EnterpriseInstallationLayout Layout { get; }

        public EnterpriseCompiledReleaseTrust Trust { get; }

        public EnterpriseManagedArtifactGarbageCollector Collector(
            Action<string>? beforeDelete = null) => new(Layout, Trust, null, beforeDelete);

        public EnterpriseReleaseSetPointer SeedVersions()
        {
            foreach (var release in new[] { "launcher-current", "launcher-previous", "launcher-old" })
            {
                SeedTree(Layout.GetLauncherVersionDirectory(release));
            }
            foreach (var release in new[] { "runtime-current", "runtime-previous", "runtime-old" })
            {
                SeedTree(Layout.GetRuntimeVersionDirectory(release));
            }
            foreach (var release in new[] { "plugin-current", "plugin-previous", "plugin-old" })
            {
                SeedTree(Layout.GetPluginPolicyVersionDirectory(release));
            }
            var current = EnterpriseReference(
                "set-current",
                "launcher-current",
                "runtime-current",
                "plugin-current",
                sequence: 2);
            var previous = EnterpriseReference(
                "set-previous",
                "launcher-previous",
                "runtime-previous",
                "plugin-previous",
                sequence: 1);
            return new EnterpriseReleaseSetPointer(
                3,
                EnterpriseReleaseSetContract.Product,
                EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                current,
                previous,
                Now);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }

        private EnterpriseReleaseSetReference EnterpriseReference(
            string set,
            string launcher,
            string runtime,
            string plugin,
            long sequence) => new(
            set,
            sequence,
            sequence,
            0,
            new EnterpriseStartupStubCompatibility
            {
                MinimumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                MaximumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            },
            new EnterpriseReleaseComponentPointer(
                launcher,
                Layout.GetLauncherVersionDirectory(launcher),
                A,
                A),
            new EnterpriseReleaseComponentPointer(
                runtime,
                Layout.GetRuntimeVersionDirectory(runtime),
                A,
                A),
            new EnterpriseReleaseComponentPointer(
                plugin,
                Layout.GetPluginPolicyVersionDirectory(plugin),
                A,
                A),
            EnterpriseReleaseHealthStates.Healthy,
            null,
            Now);
    }
}
