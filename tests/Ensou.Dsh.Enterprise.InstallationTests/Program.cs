using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;
using Microsoft.Win32;

namespace Ensou.Dsh.Enterprise.InstallationTests;

internal static class Program
{
    private const string TrustedLauncherProbeMarkerEnvironment =
        "ENSOU_DSH_ENTERPRISE_TRUSTED_LAUNCHER_PROBE_MARKER";
    private const string TrustedContainmentForwarderArgument =
        "--trusted-containment-forwarder";
    private const string TrustedContainmentFinalArgument =
        "--trusted-containment-final";
    private const string ManagedProcessFixtureArgument =
        "--managed-process-fixture";
    private const string RuntimeIntegrityOnlyArgument =
        "--runtime-integrity-only";
    private const string RuntimeIntegrityTestName =
        "fused runtime integrity scan preserves legacy digests and rejections";
    private const string ManagedProcessFixtureReady =
        "ensou-dsh-enterprise-managed-process-fixture-ready";
    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "ensou-dsh-enterprise-installation-tests",
        Guid.NewGuid().ToString("N"));
    private static readonly Action IgnoreHostHarnessWritersForIsolatedTest = static () => { };

    public static async Task<int> Main(string[] args)
    {
        if (args is [ManagedProcessFixtureArgument])
        {
            Console.WriteLine(ManagedProcessFixtureReady);
            Console.Out.Flush();
            Thread.Sleep(TimeSpan.FromSeconds(60));
            return 0;
        }
        var trustedContainmentProbe = TryRunTrustedContainmentProbe(args);
        if (trustedContainmentProbe is not null)
        {
            return trustedContainmentProbe.Value;
        }
        var trustedLauncherProbe = TryRunTrustedLauncherProbe(args);
        if (trustedLauncherProbe is not null)
        {
            return trustedLauncherProbe.Value;
        }
        var runtimeIntegrityOnly = args is [RuntimeIntegrityOnlyArgument];
        if (args.Length != 0 && !runtimeIntegrityOnly)
        {
            Console.Error.WriteLine(
                $"Expected no arguments or {RuntimeIntegrityOnlyArgument}.");
            return 2;
        }
        if (!runtimeIntegrityOnly)
        {
            Directory.CreateDirectory(TempRoot);
        }
        var tests = new (string Name, Func<Task> Run)[]
        {
            ("missing runtime pointer fails closed", MissingPointerFailsClosedAsync),
            ("development payload requires explicit marker", DevelopmentMarkerRequiredAsync),
            ("only Development-E2E infers an adjacent payload", AdjacentPayloadInferenceIsDevelopmentOnlyAsync),
            ("production Installer rejects every development-only option", ProductionInstallerRejectsDevelopmentOptionsAsync),
            ("production Installer payload binds exact release-set bytes", ProductionPayloadBindingAsync),
            ("enterprise client admits only native Windows x64", EnterpriseClientPlatformIsExactAsync),
            ("external development payload cannot write the production layout", ExternalDevelopmentPayloadRejectedForProductionLayoutAsync),
            ("embedded development payload cannot write the production layout", EmbeddedDevelopmentPayloadRejectedForProductionLayoutAsync),
            ("legacy SQLite guard admits JSONL and employee workspace databases", LegacySqliteGuardAdmitsJsonlAndWorkspacesAsync),
            ("legacy SQLite guard rejects main sidecar magic and Cordis evidence", LegacySqliteGuardRejectsEvidenceAsync),
            ("legacy SQLite guard rejects links and inspection races", LegacySqliteGuardRejectsFilesystemRacesAsync),
            ("installer rejects legacy SQLite before any installation state", InstallerLegacySqliteGuardPreservesStateAsync),
            ("enterprise writer guard ignores unrelated Node and blocks only managed writers", EnterpriseWriterGuardFailsClosedForNodeAsync),
            ("installer updater and startup paths all invoke the shared SQLite guard", LegacySqliteGuardEntryPointsAreWiredAsync),
            ("install repair and pointer rollback", InstallRepairAndRollbackAsync),
            ("install registration failure restores exact program and shell state", InstallRegistrationFailureRestoresExactStateAsync),
            ("shortcut staging remains ShellLink-compatible and bounded", ShortcutStagingPathIsCompatibleAsync),
            ("shortcut directory masquerade fails closed", ShortcutDirectoryMasqueradeFailsClosedAsync),
            ("shared operation lease blocks concurrent install", SharedLeaseBlocksConcurrentInstallAsync),
            ("durable install journal recovers interrupted files directories and shell", DurableInstallJournalRecoversInterruptedStateAsync),
            ("external Installer uninstall recovers interrupted install under one lease", ExternalUninstallRecoversInterruptedInstallAsync),
            ("durable install journal reconciles a partial planned backup", DurableInstallJournalReconcilesPartialBackupAsync),
            ("durable install journal rejects unknown duplicate and tampered state", DurableInstallJournalStateIsStrictAsync),
            ("development E2E layout remains isolated", DevelopmentE2ELayoutIsolatedAsync),
            ("runtime pointer rejects boundary escape", RuntimePointerRejectsEscapeAsync),
            (RuntimeIntegrityTestName, EnterpriseRuntimeIntegrityScannerTests.RunAsync),
            ("ZIP traversal is rejected", ZipTraversalRejectedAsync),
            ("runtime reparse point is rejected", RuntimeReparsePointRejectedAsync),
            ("plugin-policy archive binds exact root policy and file bytes", PluginPolicyArchiveValidatedAsync),
            ("plugin-policy archive rejects candidate wrappers and tampering", PluginPolicyArchiveRejectsInvalidInputsAsync),
            ("maintenance command line requires exact detached binding", MaintenanceCommandLineIsStrictAsync),
            ("maintenance worker binds current authenticated bytes", MaintenanceWorkerBindsCurrentBytesAsync),
            ("external and detached uninstall retries are idempotent", UninstallRetriesAreIdempotentAsync),
            ("open managed handle preserves registration", OpenManagedHandlePreservesRegistrationAsync),
            ("running Launcher preserves registration", RunningLauncherPreservesRegistrationAsync),
            ("running Startup Stub preserves registration", RunningStartupStubPreservesRegistrationAsync),
            ("repair-shell registration failure restores exact shell state", RepairShellFailureRestoresExactRegistrationAsync),
            ("durable uninstall restores rename-before-phase crash", DurableUninstallRestoresRenameGapAsync),
            ("durable uninstall restores registration-before-phase crash", DurableUninstallRestoresRegistrationGapAsync),
            ("durable uninstall completes commit-before-delete crash", DurableUninstallCompletesCommittedGapAsync),
            ("partial registration removal rolls back program and shell", PartialRegistrationRemovalRollsBackAsync),
            ("quarantine deletion failure is isolated", QuarantineDeletionFailureIsIsolatedAsync),
            ("concurrent update lease blocks uninstall", ConcurrentUpdateLeaseBlocksUninstallAsync),
            ("uninstall preserves Harness user data", UninstallPreservesUserDataAsync),
            ("stable Bootstrapper replacement is rejected", StableBootstrapperReplacementRejectedAsync),
            ("Authenticode verifier locks executable identity", AuthenticodeVerifierLocksIdentityAsync),
            ("trusted executable launch lease binds the real process image through mutation races", TrustedExecutableLaunchLeaseBindsProcessIdentityAsync),
            ("versioned ClientBootstrapper normal and health modes share the trusted launch helper", ClientBootstrapperLaunchModesShareTrustedHelperAsync),
            ("Authenticode verifier rejects a valid signer without trusted timestamp", AuthenticodeVerifierRequiresTrustedTimestampAsync),
            ("Authenticode verifier accepts a trusted timestamped Windows fixture", AuthenticodeVerifierAcceptsTimestampedSystemFixtureAsync),
            ("release manifest trust probe is exact across all three roles", ReleaseManifestTrustProbeIsRoleNeutralAsync),
            ("release manifest trust probe parsing and binding are strict", ReleaseManifestTrustProbeParsingIsStrictAsync),
            ("release manifest trust probe rejects role substitution and rename", ReleaseManifestTrustProbeRejectsRoleSubstitutionAsync),
            ("release manifest trust probe commands are machine-only", ReleaseManifestTrustProbeCommandsAreMachineOnlyAsync),
        };
        if (runtimeIntegrityOnly)
        {
            tests = tests.Where(test => string.Equals(
                test.Name,
                RuntimeIntegrityTestName,
                StringComparison.Ordinal)).ToArray();
        }

        var failures = 0;
        try
        {
            foreach (var test in tests)
            {
                try
                {
                    await test.Run().ConfigureAwait(false);
                    Console.WriteLine($"PASS  {test.Name}");
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.Error.WriteLine($"FAIL  {test.Name}");
                    Console.Error.WriteLine(exception);
                }
            }
        }
        finally
        {
            if (Directory.Exists(TempRoot))
            {
                Directory.Delete(TempRoot, recursive: true);
            }
        }

        Console.WriteLine(runtimeIntegrityOnly
            ? $"{tests.Length - failures}/{tests.Length} enterprise runtime integrity checks passed."
            : $"{tests.Length - failures}/{tests.Length} installation checks passed.");
        return failures == 0 ? 0 : 1;
    }

    private static Task ReleaseManifestTrustProbeIsRoleNeutralAsync()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = CreateReleaseManifestProbeTrust(key);
        var signer = new string('a', 64);
        var expected = EnterpriseReleaseManifestTrustProbeContract.SerializeCanonical(
            EnterpriseReleaseManifestTrustProbeContract.Create(trust, signer));
        var keyValue = trust.Policy.TrustedKeys.Single();
        var expectedText =
            $"{{\"schemaVersion\":1,\"probeType\":\"ensou-dsh-enterprise-release-manifest-trust-probe-v1\",\"edition\":\"Enterprise\",\"product\":\"ensou-dsh-enterprise\",\"environment\":\"production\",\"channel\":\"stable\",\"manifestUri\":\"https://updates.example.invalid/v2/channels/stable/release-set.v2.json\",\"manifestOrigin\":\"https://updates.example.invalid/\",\"artifactOrigin\":\"https://artifacts.example.invalid/\",\"authenticodeSignerSha256Thumbprint\":\"{signer}\",\"releaseManifestTrust\":{{\"algorithm\":\"ES256\",\"purpose\":\"release-manifest-signing\",\"keyId\":\"{keyValue.KeyId}\",\"x\":\"{keyValue.X}\",\"y\":\"{keyValue.Y}\"}},\"releaseCompatibility\":{{\"startupStubProtocol\":1}}}}";
        AssertTrue(expected.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(expectedText)));
        AssertFalse(expected.AsSpan().Contains((byte)'\n'));
        AssertFalse(expected.AsSpan().Contains((byte)'\r'));
        AssertFalse(expected.Length >= 3
            && expected[0] == 0xEF
            && expected[1] == 0xBB
            && expected[2] == 0xBF);

        var roleOutputs = new[]
        {
            InvokeRoleProbeFactory(
                "Ensou.Dsh.Enterprise.Bootstrapper",
                "Ensou.Dsh.Enterprise.Bootstrapper.Program",
                trust,
                signer),
            InvokeRoleProbeFactory(
                "Ensou.Dsh.Enterprise.ClientBootstrapper",
                "Ensou.Dsh.Enterprise.ClientBootstrapper.Program",
                trust,
                signer),
            InvokeRoleProbeFactory(
                "Ensou.Dsh.Enterprise.Launcher",
                "Ensou.Dsh.Enterprise.Launcher.App",
                trust,
                signer),
        };
        foreach (var output in roleOutputs)
        {
            AssertTrue(expected.AsSpan().SequenceEqual(output));
        }

        using var stream = new MemoryStream();
        EnterpriseReleaseManifestTrustProbeContract.WriteCanonical(stream, expected);
        AssertTrue(expected.AsSpan().SequenceEqual(stream.ToArray()));
        return Task.CompletedTask;
    }

    private static Task ReleaseManifestTrustProbeParsingIsStrictAsync()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = CreateReleaseManifestProbeTrust(key);
        var signer = new string('b', 64);
        var canonical = EnterpriseReleaseManifestTrustProbeContract.SerializeCanonical(
            EnterpriseReleaseManifestTrustProbeContract.Create(trust, signer));
        var canonicalText = Encoding.UTF8.GetString(canonical);
        _ = EnterpriseReleaseManifestTrustProbeContract.ParseCanonical(canonical);
        _ = EnterpriseReleaseManifestTrustProbeContract.RequireExact(
            canonical,
            trust,
            signer);

        AssertThrows<InvalidDataException>(() =>
            EnterpriseReleaseManifestTrustProbeContract.ParseCanonical(
                Encoding.UTF8.GetBytes(canonicalText + "\n")));
        AssertThrows<InvalidDataException>(() =>
            EnterpriseReleaseManifestTrustProbeContract.ParseCanonical(
                Encoding.UTF8.GetBytes(canonicalText.Insert(1, "\"unknown\":true,"))));
        AssertThrows<InvalidDataException>(() =>
            EnterpriseReleaseManifestTrustProbeContract.ParseCanonical(
                Encoding.UTF8.GetBytes(canonicalText.Insert(1, "\"schemaVersion\":1,"))));
        var bom = new byte[canonical.Length + 3];
        bom[0] = 0xEF;
        bom[1] = 0xBB;
        bom[2] = 0xBF;
        canonical.CopyTo(bom.AsSpan(3));
        AssertThrows<InvalidDataException>(() =>
            EnterpriseReleaseManifestTrustProbeContract.ParseCanonical(bom));

        var trustMarker = "\"releaseManifestTrust\":";
        var trustStart = canonicalText.IndexOf(trustMarker, StringComparison.Ordinal)
            + trustMarker.Length;
        var trustEnd = canonicalText.IndexOf(
            ",\"releaseCompatibility\"",
            trustStart,
            StringComparison.Ordinal);
        var oneKeyObject = canonicalText[trustStart..trustEnd];
        var multipleKeys = canonicalText[..trustStart]
            + "[" + oneKeyObject + "," + oneKeyObject + "]"
            + canonicalText[trustEnd..];
        AssertThrows<InvalidDataException>(() =>
            EnterpriseReleaseManifestTrustProbeContract.ParseCanonical(
                Encoding.UTF8.GetBytes(multipleKeys)));

        var pilot = trust with
        {
            Policy = trust.Policy with
            {
                ExpectedChannel = EnterpriseReleaseSetContract.PilotChannel,
            },
        };
        AssertThrows<InvalidDataException>(() =>
            EnterpriseReleaseManifestTrustProbeContract.Create(pilot, signer));

        var secondParameters = key.ExportParameters(includePrivateParameters: false);
        var secondKey = new EnterpriseReleasePublicKey(
            "release-second",
            EnterpriseBase64Url.Encode(secondParameters.Q.X!),
            EnterpriseBase64Url.Encode(secondParameters.Q.Y!));
        var multipleCompiledKeys = trust with
        {
            Policy = trust.Policy with
            {
                TrustedKeys = [trust.Policy.TrustedKeys.Single(), secondKey],
            },
        };
        AssertThrows<InvalidDataException>(() =>
            EnterpriseReleaseManifestTrustProbeContract.Create(
                multipleCompiledKeys,
                signer));

        using var differentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var otherKeyTrust = CreateReleaseManifestProbeTrust(differentKey);
        var otherKeyBytes = EnterpriseReleaseManifestTrustProbeContract.SerializeCanonical(
            EnterpriseReleaseManifestTrustProbeContract.Create(otherKeyTrust, signer));
        _ = EnterpriseReleaseManifestTrustProbeContract.ParseCanonical(otherKeyBytes);
        AssertThrows<InvalidDataException>(() =>
            EnterpriseReleaseManifestTrustProbeContract.RequireExact(
                otherKeyBytes,
                trust,
                signer));

        var otherUriTrust = trust with
        {
            ManifestUri = new Uri(
                "https://updates-alt.example.invalid/v2/channels/stable/release-set.v2.json"),
            Policy = trust.Policy with
            {
                ManifestOrigin = new Uri("https://updates-alt.example.invalid/"),
            },
        };
        var otherUriBytes = EnterpriseReleaseManifestTrustProbeContract.SerializeCanonical(
            EnterpriseReleaseManifestTrustProbeContract.Create(otherUriTrust, signer));
        _ = EnterpriseReleaseManifestTrustProbeContract.ParseCanonical(otherUriBytes);
        AssertThrows<InvalidDataException>(() =>
            EnterpriseReleaseManifestTrustProbeContract.RequireExact(
                otherUriBytes,
                trust,
                signer));
        return Task.CompletedTask;
    }

    private static Task ReleaseManifestTrustProbeRejectsRoleSubstitutionAsync()
    {
        var roles = new[]
        {
            new RoleObservation(
                EnterpriseReleaseManifestTrustProbeRole.StableBootstrapper,
                "Ensou.Dsh.Enterprise.Bootstrapper",
                EnterpriseBrandContract.BootstrapperProductName,
                EnterpriseInstallationLayout.BootstrapperExecutableName),
            new RoleObservation(
                EnterpriseReleaseManifestTrustProbeRole.VersionedClientBootstrapper,
                "Ensou.Dsh.Enterprise.ClientBootstrapper",
                "Ensou DSH Enterprise Versioned Bootstrapper",
                EnterpriseInstallationLayout.ClientBootstrapperExecutableName),
            new RoleObservation(
                EnterpriseReleaseManifestTrustProbeRole.Launcher,
                "Ensou.Dsh.Enterprise.Launcher",
                EnterpriseBrandContract.LauncherProductName,
                EnterpriseInstallationLayout.LauncherExecutableName),
        };
        foreach (var expected in roles)
        {
            EnterpriseReleaseManifestTrustProbeRoleIdentity.RequireObservedForTests(
                expected.Role,
                expected.AssemblyName,
                expected.ProductName,
                EnterpriseBrandContract.DeveloperName,
                expected.ExecutableFileName,
                expected.ProductName,
                EnterpriseBrandContract.DeveloperName);
            foreach (var substitute in roles.Where(value => value.Role != expected.Role))
            {
                AssertThrows<InvalidDataException>(() =>
                    EnterpriseReleaseManifestTrustProbeRoleIdentity.RequireObservedForTests(
                        expected.Role,
                        substitute.AssemblyName,
                        substitute.ProductName,
                        EnterpriseBrandContract.DeveloperName,
                        expected.ExecutableFileName,
                        substitute.ProductName,
                        EnterpriseBrandContract.DeveloperName));
            }
        }
        return Task.CompletedTask;
    }

    private static async Task ReleaseManifestTrustProbeCommandsAreMachineOnlyAsync()
    {
        AssertTrue(EnterpriseReleaseManifestTrustProbeContract.IsExactCommand(
            [EnterpriseReleaseManifestTrustProbeContract.Command]));
        AssertFalse(EnterpriseReleaseManifestTrustProbeContract.IsExactCommand(
            [EnterpriseReleaseManifestTrustProbeContract.Command, "unexpected"]));
        AssertFalse(EnterpriseReleaseManifestTrustProbeContract.IsExactCommand(
            ["--release-trust-self-check"]));
        using (var failure = new MemoryStream())
        {
            EnterpriseReleaseManifestTrustProbeContract.WriteBoundedFailure(failure);
            AssertEqual(
                EnterpriseReleaseManifestTrustProbeContract.FailureMessage,
                Encoding.UTF8.GetString(failure.ToArray()));
            AssertTrue(failure.Length <= 256);
        }

        foreach (var executable in new[]
                 {
                     EnterpriseInstallationLayout.BootstrapperExecutableName,
                     EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
                     EnterpriseInstallationLayout.LauncherExecutableName,
                 })
        {
            var exactFailure = await RunBuiltMachineCommandAsync(
                executable,
                EnterpriseReleaseManifestTrustProbeContract.Command)
                .ConfigureAwait(false);
            AssertTrue(exactFailure.ExitCode != 0);
            AssertEqual(string.Empty, exactFailure.StandardOutput);
            AssertTrue(exactFailure.StandardError.Length <= 256);

            var result = await RunBuiltMachineCommandAsync(
                executable,
                EnterpriseReleaseManifestTrustProbeContract.Command,
                "unexpected").ConfigureAwait(false);
            AssertTrue(result.ExitCode != 0);
            AssertEqual(string.Empty, result.StandardOutput);
            AssertTrue(result.StandardError.Length <= 256);
        }

        var launcherResult = await RunBuiltMachineCommandAsync(
            EnterpriseInstallationLayout.LauncherExecutableName,
            "--production-trust-self-check",
            new string('0', 64)).ConfigureAwait(false);
        AssertTrue(launcherResult.ExitCode != 0);
        AssertEqual(string.Empty, launcherResult.StandardOutput);
    }

    private static EnterpriseCompiledReleaseTrust CreateReleaseManifestProbeTrust(ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        return new EnterpriseCompiledReleaseTrust(
            new Uri(
                "https://updates.example.invalid/v2/channels/stable/release-set.v2.json"),
            new EnterpriseReleaseTrustPolicy
            {
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.ProductionEnvironment,
                ExpectedChannel = EnterpriseReleaseSetContract.StableChannel,
                CurrentStartupStubProtocol =
                    EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                ManifestOrigin = new Uri("https://updates.example.invalid/"),
                ArtifactOrigin = new Uri("https://artifacts.example.invalid/"),
                TrustedKeys =
                [
                    new EnterpriseReleasePublicKey(
                        "release-2026",
                        EnterpriseBase64Url.Encode(parameters.Q.X!),
                        EnterpriseBase64Url.Encode(parameters.Q.Y!)),
                ],
            });
    }

    private static byte[] InvokeRoleProbeFactory(
        string assemblyName,
        string typeName,
        EnterpriseCompiledReleaseTrust trust,
        string signer)
    {
        var assembly = Assembly.LoadFrom(FindBuiltRoleFile(assemblyName + ".dll"));
        var type = assembly.GetType(typeName, throwOnError: true)
            ?? throw new InvalidOperationException($"Role type {typeName} is unavailable.");
        var method = type.GetMethod(
            "CreateReleaseManifestTrustProbeBytesForTests",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"Role probe factory {typeName} is unavailable.");
        return (byte[])(method.Invoke(null, [trust, signer])
            ?? throw new InvalidOperationException($"Role probe factory {typeName} returned no bytes."));
    }

    private static async Task<MachineCommandResult> RunBuiltMachineCommandAsync(
        string executableName,
        params string[] arguments)
    {
        var executable = FindBuiltRoleFile(executableName);
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = Path.GetDirectoryName(executable)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                $"Could not start machine-command fixture {executableName}.");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException(
                $"Machine command {executableName} did not exit without UI.");
        }
        return new MachineCommandResult(
            process.ExitCode,
            await standardOutput.ConfigureAwait(false),
            await standardError.ConfigureAwait(false));
    }

    private static string FindBuiltRoleFile(string fileName)
    {
        var repositoryRoot = FindRepositoryRoot();
        var configuration = new DirectoryInfo(AppContext.BaseDirectory)
            .Parent?.Name;
        if (configuration is not "Debug" and not "Release")
        {
            throw new InvalidOperationException(
                "Enterprise role fixture configuration could not be resolved.");
        }
        var configurationSegment =
            $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}" +
            $"{configuration}{Path.DirectorySeparatorChar}";
        return Directory.EnumerateFiles(
                Path.Combine(repositoryRoot, "src"),
                fileName,
                SearchOption.AllDirectories)
            .Where(path => path.Contains(
                    configurationSegment,
                    StringComparison.OrdinalIgnoreCase)
                && !path.Contains(
                    $"{Path.DirectorySeparatorChar}publish{Path.DirectorySeparatorChar}",
                    StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault()
            ?? throw new FileNotFoundException(
                $"Built role fixture {fileName} was not found.");
    }

    private static string FindRepositoryRoot()
    {
        for (var current = new DirectoryInfo(AppContext.BaseDirectory);
             current is not null;
             current = current.Parent)
        {
            if (File.Exists(Path.Combine(current.FullName, "Ensou.Dsh.slnx")))
            {
                return current.FullName;
            }
        }
        throw new DirectoryNotFoundException("Enterprise test repository root was not found.");
    }

    private sealed record RoleObservation(
        EnterpriseReleaseManifestTrustProbeRole Role,
        string AssemblyName,
        string ProductName,
        string ExecutableFileName);

    private sealed record MachineCommandResult(
        int ExitCode,
        string StandardOutput,
        string StandardError);

    private static Task MissingPointerFailsClosedAsync()
    {
        var fixture = CreateFixture();
        var store = new EnterpriseRuntimePointerStore(fixture.Layout);
        AssertTrue(store.TryRead() is null);
        AssertThrows<InvalidDataException>(() => store.ReadRequired());
        return Task.CompletedTask;
    }

    private static Task AuthenticodeVerifierLocksIdentityAsync()
    {
        var root = Path.Combine(TempRoot, $"authenticode-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var executable = Path.Combine(root, "candidate.exe");
        var replacement = Path.Combine(root, "replacement.exe");
        File.WriteAllBytes(executable, "unsigned-enterprise-executable"u8.ToArray());
        File.WriteAllBytes(replacement, "replacement"u8.ToArray());
        using (var locked = EnterpriseAuthenticodeVerifier.OpenLockedExecutable(executable))
        {
            AssertThrows<IOException>(() =>
                File.Open(executable, FileMode.Open, FileAccess.Write, FileShare.Read).Dispose());
            AssertMutationDenied(() => File.Move(replacement, executable, overwrite: true));
            AssertTrue(locked.Length > 0);
        }
        AssertThrows<InvalidDataException>(() =>
            EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
                executable,
                new string('a', 64)));
        return Task.CompletedTask;
    }

    private static Task LegacySqliteGuardAdmitsJsonlAndWorkspacesAsync()
    {
        var absent = CreateFixture();
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(absent.Layout);

        var fixture = CreateFixture();
        Directory.CreateDirectory(Path.Combine(fixture.Layout.HarnessHome, "sessions"));
        File.WriteAllText(
            Path.Combine(fixture.Layout.HarnessHome, "sessions", "history.jsonl"),
            "{\"text\":\"session-persistence-sqlite is historical documentation only\"}\n");
        Directory.CreateDirectory(Path.Combine(fixture.Layout.HarnessHome, "logs"));
        File.WriteAllText(
            Path.Combine(fixture.Layout.HarnessHome, "logs", "diagnostic.json"),
            "{\"message\":\"session-persistence-sqlite was not loaded\"}");
        File.WriteAllText(
            Path.Combine(fixture.Layout.HarnessHome, "settings.json"),
            "{\"exportNote\":\"session-persistence-sqlite\"}");
        File.WriteAllText(
            Path.Combine(fixture.Layout.HarnessHome, "config.json"),
            "{\"exportNote\":\"session-persistence-sqlite\"}");
        File.WriteAllText(
            Path.Combine(fixture.Layout.HarnessHome, "export.json"),
            "{\"providerName\":\"session-persistence-sqlite\"}");
        var workspace = Path.Combine(
            fixture.Layout.HarnessHome,
            "workspaces",
            "employee-project");
        Directory.CreateDirectory(workspace);
        File.WriteAllBytes(Path.Combine(workspace, "project.db"), "workspace-db"u8.ToArray());
        File.WriteAllBytes(Path.Combine(workspace, "project.sqlite-wal"), [1, 2, 3]);
        File.WriteAllBytes(
            Path.Combine(workspace, "extensionless-project-cache"),
            "SQLite format 3\0workspace"u8.ToArray());

        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(fixture.Layout);
        File.WriteAllText(Path.Combine(workspace, "workspace-remains-writable.txt"), "ok");
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(fixture.Layout);
        AssertTrue(File.Exists(Path.Combine(workspace, "project.db")));
        AssertTrue(File.Exists(Path.Combine(workspace, "project.sqlite-wal")));
        return Task.CompletedTask;
    }

    private static Task LegacySqliteGuardRejectsEvidenceAsync()
    {
        AssertLegacySqliteEvidenceRejected("main", "sessions.db", "legacy-main"u8.ToArray());
        AssertLegacySqliteEvidenceRejected("wal", "sessions.sqlite3-wal", [1, 2, 3]);
        AssertLegacySqliteEvidenceRejected("orphan-sidecar", "sessions-wal", [4, 5, 6]);
        AssertLegacySqliteEvidenceRejected(
            "magic",
            "session-store",
            "SQLite format 3\0payload"u8.ToArray());
        AssertLegacySqliteEvidenceRejected(
            string.Empty,
            "cordis.patch.yml",
            "rows: [session-persistence-sqlite]"u8.ToArray());
        AssertLegacySqliteEvidenceRejected(
            Path.Combine("profiles", "enterprise"),
            "cordis.yml",
            "{\"provider\":\"session-persistence-sqlite\"}"u8.ToArray());
        AssertLegacySqliteEvidenceRejected(
            Path.Combine("profiles", "team.alpha"),
            "cordis.patch.yml",
            "provider: session-persistence-sqlite"u8.ToArray());
        AssertLegacySqliteEvidenceRejected(
            Path.Combine("profiles", "客户 A"),
            "cordis.yaml",
            "provider: session-persistence-sqlite"u8.ToArray());

        var magic = "SQLite format 3\0"u8.ToArray();
        var shortReadCount = 0;
        AssertTrue(EnterpriseLegacySqliteUpgradeGuard.HasPrefixForTest(
            magic.Length,
            magic,
            (destination, fileOffset) =>
            {
                shortReadCount++;
                var sourceOffset = checked((int)fileOffset);
                var count = Math.Min(
                    destination.Length,
                    Math.Min(3, magic.Length - sourceOffset));
                magic.AsSpan(sourceOffset, count).CopyTo(destination);
                return count;
            }));
        AssertTrue(shortReadCount > 1);

        var truncated = magic[..8];
        AssertThrows<EndOfStreamException>(() =>
            EnterpriseLegacySqliteUpgradeGuard.HasPrefixForTest(
                magic.Length,
                magic,
                (destination, fileOffset) =>
                {
                    var sourceOffset = checked((int)fileOffset);
                    if (sourceOffset >= truncated.Length)
                    {
                        return 0;
                    }
                    var count = Math.Min(
                        destination.Length,
                        truncated.Length - sourceOffset);
                    truncated.AsSpan(sourceOffset, count).CopyTo(destination);
                    return count;
                }));
        return Task.CompletedTask;
    }

    private static Task LegacySqliteGuardRejectsFilesystemRacesAsync()
    {
        var hardLinkFixture = CreateFixture();
        Directory.CreateDirectory(hardLinkFixture.Layout.HarnessHome);
        var external = Path.Combine(hardLinkFixture.Root, "external-history.jsonl");
        var linked = Path.Combine(hardLinkFixture.Layout.HarnessHome, "history.jsonl");
        File.WriteAllText(external, "ordinary-jsonl");
        if (!CreateHardLink(linked, external, IntPtr.Zero))
        {
            throw new InvalidOperationException(
                "Could not create the legacy SQLite guard hard-link fixture.",
                Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }
        AssertLegacySqliteGuardBlocked(hardLinkFixture.Layout);

        var junctionFixture = CreateFixture();
        Directory.CreateDirectory(junctionFixture.Layout.HarnessHome);
        var target = NewDirectory("legacy-sqlite-guard-junction-target");
        File.WriteAllText(Path.Combine(target, "ordinary.jsonl"), "ordinary-jsonl");
        var junction = Path.Combine(junctionFixture.Layout.HarnessHome, "linked-config");
        if (TryCreateDirectoryJunction(junction, target))
        {
            try
            {
                AssertLegacySqliteGuardBlocked(junctionFixture.Layout);
            }
            finally
            {
                Directory.Delete(junction);
            }
        }
        else
        {
            Console.WriteLine("SKIP  legacy SQLite guard junction creation unavailable");
        }

        var raceFixture = CreateFixture();
        Directory.CreateDirectory(raceFixture.Layout.HarnessHome);
        File.WriteAllText(
            Path.Combine(raceFixture.Layout.HarnessHome, "history.jsonl"),
            "ordinary-jsonl");
        AssertLegacySqliteGuardBlocked(
            raceFixture.Layout,
            () => File.WriteAllBytes(
                Path.Combine(raceFixture.Layout.HarnessHome, "raced.db-wal"),
                [4, 5, 6]));

        var replacementFixture = CreateFixture();
        Directory.CreateDirectory(replacementFixture.Layout.HarnessHome);
        var replacePath = Path.Combine(
            replacementFixture.Layout.HarnessHome,
            "history");
        File.WriteAllText(replacePath, "ordinary-jsonl");
        var rejectionRan = false;
        var replacementFailure = AssertThrowsAndReturn<InvalidOperationException>(() =>
            EnterpriseLegacySqliteUpgradeGuard
                .ExecuteWithJsonlOnlyHarnessHomeAdmission(
                    replacementFixture.Layout,
                    () =>
                    {
                        File.Delete(replacePath);
                        File.WriteAllBytes(
                            replacePath,
                            "SQLite format 3\0replacement"u8.ToArray());
                        return true;
                    },
                    _ => rejectionRan = true));
        AssertEqual(
            EnterpriseLegacySqliteUpgradeGuard.BlockedMessage,
            replacementFailure.Message);
        AssertTrue(rejectionRan);
        AssertTrue(File.ReadAllBytes(replacePath).AsSpan().StartsWith(
            "SQLite format 3\0"u8));
        return Task.CompletedTask;
    }

    private static async Task InstallerLegacySqliteGuardPreservesStateAsync()
    {
        var fixture = CreateFixture();
        Directory.CreateDirectory(fixture.Layout.HarnessHome);
        var legacy = Path.Combine(fixture.Layout.HarnessHome, "legacy.sqlite");
        var original = "legacy-sqlite-unchanged"u8.ToArray();
        File.WriteAllBytes(legacy, original);
        var payload = CreatePayload("launcher-guard", "runtime-guard", "guard");

        await AssertThrowsAsync<InvalidOperationException>(() =>
            CreateIsolatedInstallationService(fixture.Layout)
                .InstallExternalDevelopmentPayloadAsync(payload, Environment.ProcessPath!));

        AssertTrue(original.AsSpan().SequenceEqual(File.ReadAllBytes(legacy)));
        AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertFalse(File.Exists(fixture.Layout.ReleaseSetPointerPath));
        AssertFalse(File.Exists(fixture.Layout.UpdateStatusPath));

        var raced = CreateFixture();
        Directory.CreateDirectory(raced.Layout.HarnessHome);
        var history = Path.Combine(raced.Layout.HarnessHome, "history");
        File.WriteAllText(history, "ordinary-jsonl");
        var racedPayload = CreatePayload("launcher-guard-race", "runtime-guard-race", "guard-race");
        var racedFailure = await AssertThrowsAndReturnAsync<InvalidOperationException>(() =>
            CreateIsolatedInstallationService(
                raced.Layout,
                () =>
                    {
                        File.Delete(history);
                        File.WriteAllBytes(
                            history,
                            "SQLite format 3\0replacement"u8.ToArray());
                    })
                .InstallExternalDevelopmentPayloadAsync(
                    racedPayload,
                    Environment.ProcessPath!));
        AssertEqual(
            EnterpriseLegacySqliteUpgradeGuard.BlockedMessage,
            racedFailure.Message);
        AssertFalse(File.Exists(raced.Layout.ReleaseSetPointerPath));
        AssertFalse(File.Exists(raced.Layout.RuntimePointerPath));
        AssertFalse(File.Exists(raced.Layout.LauncherPointerPath));
        AssertFalse(File.Exists(raced.Layout.UpdateStatusPath));
        AssertTrue(File.ReadAllBytes(history).AsSpan().StartsWith(
            "SQLite format 3\0"u8));

        var writerFixture = CreateFixture();
        var writerPayload = CreatePayload(
            "launcher-guard-writer",
            "runtime-guard-writer",
            "guard-writer");
        var writerGuardCalls = 0;
        var writerFailure = await AssertThrowsAndReturnAsync<InvalidOperationException>(
            () => new EnterpriseInstallationService(
                    writerFixture.Layout,
                    beforeLegacySqliteCommitForTest: null,
                    requireNoPossibleHarnessWriter: () =>
                    {
                        writerGuardCalls++;
                        throw new InvalidOperationException(
                            "Injected managed Harness writer.");
                    })
                .InstallExternalDevelopmentPayloadAsync(
                    writerPayload,
                    Environment.ProcessPath!));
        AssertEqual(
            EnterpriseLegacySqliteUpgradeGuard.BlockedMessage,
            writerFailure.Message);
        AssertEqual(1, writerGuardCalls);
        AssertFalse(Directory.Exists(writerFixture.Layout.ManagedRoot));
        AssertFalse(File.Exists(writerFixture.Layout.ReleaseSetPointerPath));
        AssertFalse(File.Exists(writerFixture.Layout.UpdateStatusPath));

        var rollbackFixture = CreateFixture();
        var rollbackPayload = CreatePayload(
            "launcher-guard-rollback",
            "runtime-guard-rollback",
            "guard-rollback");
        var lateLegacy = Path.Combine(
            rollbackFixture.Layout.HarnessHome,
            "late.sqlite");
        FileStream? rollbackBlocker = null;
        try
        {
            var rollbackFailure = await AssertThrowsAndReturnAsync<InvalidOperationException>(
                () => CreateIsolatedInstallationService(
                    rollbackFixture.Layout,
                    () =>
                        {
                            Directory.CreateDirectory(
                                rollbackFixture.Layout.HarnessHome);
                            File.WriteAllBytes(
                                lateLegacy,
                                "late-legacy-sqlite"u8.ToArray());
                            rollbackBlocker = new FileStream(
                                rollbackFixture.Layout.ReleaseSetPointerPath,
                                FileMode.Open,
                                FileAccess.Read,
                                FileShare.None);
                        })
                    .InstallExternalDevelopmentPayloadAsync(
                        rollbackPayload,
                        Environment.ProcessPath!));
            AssertEqual(
                EnterpriseLegacySqliteUpgradeGuard.InstallationRollbackFailureMessage,
                rollbackFailure.Message);
            AssertTrue(rollbackFailure.InnerException is null);
            AssertFalse(rollbackFailure.Message.Contains(
                rollbackFixture.Root,
                StringComparison.OrdinalIgnoreCase));
            AssertFalse(rollbackFailure.Message.Contains(
                rollbackFixture.Layout.ReleaseSetPointerPath,
                StringComparison.OrdinalIgnoreCase));
            AssertTrue(File.Exists(lateLegacy));
        }
        finally
        {
            rollbackBlocker?.Dispose();
        }
    }

    private static Task EnterpriseWriterGuardFailsClosedForNodeAsync()
    {
        var fixture = CreateShortFixture();
        try
        {
        var layout = fixture.Layout;
        layout.EnsureManagedRoots();

        var unrelatedNodeDirectory = NewDirectory("enterprise-writer-unrelated-node");
        using (var unrelatedNode = StartRenamedNodeProcess(
                   unrelatedNodeDirectory))
        {
            try
            {
                AssertEqual("node", unrelatedNode.ProcessName);
                AssertFalse(EnterpriseHarnessProcessWriterGuard
                    .IsPossibleHarnessWriterForTest(
                        unrelatedNode.ProcessName,
                        () => Path.Combine(unrelatedNodeDirectory, "node.exe"),
                        layout.ManagedRoot));
                EnterpriseHarnessProcessWriterGuard
                    .RequireNoPossibleHarnessWriter(layout);
            }
            finally
            {
                StopProcessTree(unrelatedNode);
            }
        }

        var managedRuntimeDirectory = Path.Combine(
            layout.RuntimeVersionsRoot,
            "managed-writer-test");
        using (var managedNode = StartRenamedNodeProcess(
                   managedRuntimeDirectory))
        {
            try
            {
                AssertEqual("node", managedNode.ProcessName);
                AssertTrue(EnterpriseHarnessProcessWriterGuard
                    .IsPossibleHarnessWriterForTest(
                        managedNode.ProcessName,
                        () => Path.Combine(managedRuntimeDirectory, "node.exe"),
                        layout.ManagedRoot));
                AssertThrows<InvalidOperationException>(
                    () => EnterpriseHarnessProcessWriterGuard
                        .RequireNoPossibleHarnessWriter(layout));
            }
            finally
            {
                StopProcessTree(managedNode);
            }
        }

        foreach (var writerName in new[]
                 {
                     "node", "node.exe", "dsh", "dsh.exe",
                     "deepseek-harness", "deepseek-harness.exe",
                 })
        {
            AssertTrue(EnterpriseHarnessProcessWriterGuard
                .IsPossibleHarnessWriterForTest(
                    writerName,
                    () => Path.Combine(layout.ManagedRoot, writerName),
                    layout.ManagedRoot));
            AssertFalse(EnterpriseHarnessProcessWriterGuard
                .IsPossibleHarnessWriterForTest(
                    writerName,
                    () => Path.Combine(unrelatedNodeDirectory, writerName),
                    layout.ManagedRoot));
        }
        foreach (var otherName in new[]
                 {
                     "dotnet", "dotnet.exe", "cmd", "npm", "node-helper",
                     "Ensou.Dsh.Enterprise.Installer",
                 })
        {
            AssertFalse(EnterpriseHarnessProcessWriterGuard
                .IsPossibleHarnessWriterForTest(
                    otherName,
                    static () => throw new InvalidOperationException(
                        "Non-writer path classification must not run."),
                    layout.ManagedRoot));
        }

        AssertThrows<InvalidOperationException>(() =>
            EnterpriseHarnessProcessWriterGuard.IsPossibleHarnessWriterForTest(
                "node",
                static () => throw new System.ComponentModel.Win32Exception(5),
                layout.ManagedRoot));
        AssertThrows<InvalidOperationException>(() =>
            EnterpriseHarnessProcessWriterGuard.IsPossibleHarnessWriterForTest(
                "node",
                static () => "node.exe",
                layout.ManagedRoot));

        return Task.CompletedTask;
        }
        finally
        {
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    private static Process StartRenamedNodeProcess(
        string root)
    {
        Directory.CreateDirectory(root);
        var node = Path.Combine(root, "node.exe");
        CopyManagedProcessFixture(node);
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = node,
            WorkingDirectory = root,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            ArgumentList = { ManagedProcessFixtureArgument },
        }) ?? throw new InvalidOperationException(
            "Could not start the renamed Node writer fixture.");
        RequireManagedProcessFixtureReady(process);
        return process;
    }

    private static void StopProcessTree(Process process)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
        }
    }

    private static Task LegacySqliteGuardEntryPointsAreWiredAsync()
    {
        var root = FindRepositoryRoot();
        const string guardCall = "RequireJsonlOnlyHarnessHome";
        var installation = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Enterprise.Installation",
            "EnterpriseInstallationService.cs"));
        var repair = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Enterprise.Installation",
            "EnterpriseInstallationService.LegacyMigration.cs"));
        var migration = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Enterprise.Installation",
            "EnterpriseLegacyTestInstallationMigration.cs"));
        var updater = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Enterprise.Installation",
            "EnterpriseReleaseSetUpdateService.cs"));
        var launcher = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Enterprise.Launcher",
            "App.xaml.cs"));
        var hostAdapter = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Enterprise.Launcher",
            "DshHostAdapter.cs"));
        var clientBootstrapper = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Enterprise.ClientBootstrapper",
            "Program.cs"));
        var homeTransaction = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Enterprise.Installation",
            "EnterpriseHarnessHomeUpdateTransaction.cs"));
        var hostService = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Host",
            "DshHostService.cs"));
        var windowsJob = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Host",
            "WindowsJobObject.cs"));
        var authenticode = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Ensou.Dsh.Enterprise.Installation",
            "EnterpriseAuthenticodeVerifier.cs"));

        AssertTrue(CountOccurrences(installation, guardCall) >= 4);
        AssertTrue(CountOccurrences(repair, guardCall) >= 3);
        AssertTrue(CountOccurrences(migration, guardCall) >= 7);
        AssertTrue(CountOccurrences(updater, guardCall) >= 6);
        AssertTrue(CountOccurrences(launcher, guardCall) >= 3);
        AssertTrue(CountOccurrences(hostAdapter, guardCall) >= 1);
        AssertTrue(CountOccurrences(clientBootstrapper, guardCall) >= 5);
        AssertFalse(string.Join(
            '\n',
            installation,
            repair,
            migration,
            updater,
            launcher,
            hostAdapter,
            clientBootstrapper).Contains(
                "AcquireJsonlOnlyHarnessHomeLease",
                StringComparison.Ordinal));
        AssertTrue(launcher.Contains("validateBeforeProcessStart", StringComparison.Ordinal));
        AssertTrue(launcher.Contains("validateBeforeResume", StringComparison.Ordinal));
        AssertTrue(hostAdapter.Contains("validateBeforeResume", StringComparison.Ordinal));
        AssertTrue(homeTransaction.Contains(
            "validateHomeUnderWriterExclusion?.Invoke()",
            StringComparison.Ordinal));
        AssertTrue(hostService.Contains(
            "jobObject.StartSuspended(",
            StringComparison.Ordinal));
        AssertTrue(hostService.Contains(
            "_validateBeforeResume(suspendedProcess)",
            StringComparison.Ordinal));
        AssertTrue(windowsJob.Contains(
            "CreateSuspended",
            StringComparison.Ordinal));
        AssertTrue(windowsJob.Contains(
            "ExtendedStartupInfoPresent",
            StringComparison.Ordinal));
        AssertTrue(windowsJob.Contains(
            "ReadActiveProcessCount() != 1",
            StringComparison.Ordinal));
        AssertTrue(authenticode.Contains(
            "validateBeforeResume?.Invoke(suspendedProcess)",
            StringComparison.Ordinal));
        return Task.CompletedTask;
    }

    private static void AssertLegacySqliteEvidenceRejected(
        string scope,
        string fileName,
        byte[] contents)
    {
        var fixture = CreateFixture();
        var directory = Path.Combine(fixture.Layout.HarnessHome, scope);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, fileName);
        File.WriteAllBytes(path, contents);
        AssertLegacySqliteGuardBlocked(fixture.Layout);
        AssertTrue(contents.AsSpan().SequenceEqual(File.ReadAllBytes(path)));
    }

    private static void AssertLegacySqliteGuardBlocked(
        EnterpriseInstallationLayout layout,
        Action? betweenSnapshots = null)
    {
        try
        {
            if (betweenSnapshots is null)
            {
                EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(layout);
            }
            else
            {
                EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeForTest(
                    layout,
                    betweenSnapshots);
            }
        }
        catch (InvalidOperationException exception)
        {
            AssertEqual(EnterpriseLegacySqliteUpgradeGuard.BlockedMessage, exception.Message);
            AssertTrue(exception.InnerException is null);
            AssertFalse(exception.Message.Contains(layout.UserProfileRoot, StringComparison.OrdinalIgnoreCase));
            AssertTrue(exception.Message.Contains("旧版 DSH 导出", StringComparison.Ordinal));
            AssertTrue(exception.Message.Contains("联系管理员", StringComparison.Ordinal));
            return;
        }
        throw new InvalidOperationException("Expected legacy SQLite upgrade admission to fail.");
    }

    private static int CountOccurrences(string value, string needle)
    {
        var count = 0;
        var offset = 0;
        while ((offset = value.IndexOf(needle, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += needle.Length;
        }
        return count;
    }

    private static async Task TrustedExecutableLaunchLeaseBindsProcessIdentityAsync()
    {
        var root = Path.Combine(
            TempRoot,
            $"trusted-launch-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var source = Environment.GetEnvironmentVariable("ComSpec")
            ?? throw new InvalidOperationException("ComSpec is unavailable.");
        var executable = Path.Combine(root, "verified-cmd.exe");
        var replacement = Path.Combine(root, "replacement.exe");
        var renamed = Path.Combine(root, "renamed.exe");
        File.Copy(source, executable);
        File.Copy(source, replacement);
        var expectedSigner = new string('A', 64);
        var inspectionCalled = false;

        var hardLinkedSource = Path.Combine(root, "hard-linked-source.exe");
        var hardLinkedAlias = Path.Combine(root, "hard-linked-alias.exe");
        File.Copy(source, hardLinkedSource);
        if (!CreateHardLink(
                hardLinkedAlias,
                hardLinkedSource,
                IntPtr.Zero))
        {
            throw new IOException(
                "Could not create the Enterprise trusted-launch hard-link fixture.",
                Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }
        AssertThrows<InvalidDataException>(() =>
            EnterpriseAuthenticodeVerifier
                .OpenTrustedExecutableForLaunchForTests(
                    hardLinkedSource,
                    expectedSigner,
                    (_, _) => new EnterpriseAuthenticodeInspection(
                        Status: 0,
                        SignerSha256Thumbprint: expectedSigner,
                        HasTrustedTimestamp: true))
                .Dispose());

        var linkedRoot = Path.Combine(root, "linked-root");
        if (!TryCreateDirectoryJunction(linkedRoot, root))
        {
            throw new InvalidOperationException(
                "Could not create the Enterprise trusted-launch reparse fixture.");
        }
        try
        {
            AssertThrows<InvalidDataException>(() =>
                EnterpriseAuthenticodeVerifier
                    .OpenTrustedExecutableForLaunchForTests(
                        Path.Combine(linkedRoot, Path.GetFileName(executable)),
                        expectedSigner,
                        (_, _) => new EnterpriseAuthenticodeInspection(
                            Status: 0,
                            SignerSha256Thumbprint: expectedSigner,
                            HasTrustedTimestamp: true))
                    .Dispose());
        }
        finally
        {
            Directory.Delete(linkedRoot);
        }

        using var lease =
            EnterpriseAuthenticodeVerifier.OpenTrustedExecutableForLaunchForTests(
                executable,
                expectedSigner,
                (path, handle) =>
                {
                    AssertEqual(Path.GetFullPath(executable), path);
                    AssertFalse(handle.IsInvalid);
                    inspectionCalled = true;
                    return new EnterpriseAuthenticodeInspection(
                        Status: 0,
                        SignerSha256Thumbprint: expectedSigner,
                        HasTrustedTimestamp: true);
                });
        AssertTrue(inspectionCalled);
        using var cancellation = new CancellationTokenSource();
        using var beginRace = new ManualResetEventSlim();
        var mutationSucceeded = 0;
        var renameAttempts = 0;
        var replaceAttempts = 0;
        var deleteAttempts = 0;

        void AttemptMutation(Action mutation, ref int attempts)
        {
            Interlocked.Increment(ref attempts);
            try
            {
                mutation();
                Interlocked.Exchange(ref mutationSucceeded, 1);
                cancellation.Cancel();
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException)
            {
                // The verified file lease must reject every mutation.
            }
        }

        var racer = Task.Run(() =>
        {
            beginRace.Wait();
            while (!cancellation.IsCancellationRequested)
            {
                AttemptMutation(
                    () => File.Move(executable, renamed),
                    ref renameAttempts);
                AttemptMutation(
                    () => File.Move(replacement, executable, overwrite: true),
                    ref replaceAttempts);
                AttemptMutation(
                    () => File.Delete(executable),
                    ref deleteAttempts);
                Thread.Yield();
            }
        });

        Process? process = null;
        try
        {
            beginRace.Set();
            AssertTrue(SpinWait.SpinUntil(
                () => Volatile.Read(ref renameAttempts) > 0
                    && Volatile.Read(ref replaceAttempts) > 0
                    && Volatile.Read(ref deleteAttempts) > 0,
                TimeSpan.FromSeconds(5)));
            var startInfo = new ProcessStartInfo
            {
                FileName = executable,
                WorkingDirectory = root,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            startInfo.ArgumentList.Add("/d");
            startInfo.ArgumentList.Add("/c");
            startInfo.ArgumentList.Add("ping -t 127.0.0.1 > nul");
            process = lease.Start(startInfo);
            AssertFalse(process.HasExited);
            AssertEqual(
                lease.Identity,
                lease.InspectProcessImageIdentityForTests(process));
            await Task.Delay(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
        }
        finally
        {
            cancellation.Cancel();
            await racer.ConfigureAwait(false);
            if (process is not null)
            {
                StopProcess(process);
                process.Dispose();
            }
        }

        AssertEqual(0, mutationSucceeded);
        AssertTrue(renameAttempts > 0);
        AssertTrue(replaceAttempts > 0);
        AssertTrue(deleteAttempts > 0);
        AssertTrue(File.Exists(executable));
        AssertFalse(File.Exists(renamed));

        var entryAssemblyPath = Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException(
                "InstallationTests entry assembly is unavailable.");
        var appHostPath = Path.ChangeExtension(entryAssemblyPath, ".exe");
        if (!File.Exists(appHostPath))
        {
            throw new InvalidOperationException(
                "InstallationTests apphost is unavailable for the real containment probe.");
        }
        var mismatchedAppHostPath = Path.Combine(
            Path.GetDirectoryName(appHostPath)!,
            $"enterprise-untrusted-containment-{Guid.NewGuid():N}.exe");
        var containmentMarker = Path.Combine(root, "containment.marker");
        File.Copy(appHostPath, mismatchedAppHostPath);
        var mismatchedForwarderProcessId = 0;
        var mismatchedFinalProcessId = 0;
        var mismatchStart = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = root,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        mismatchStart.ArgumentList.Add("/d");
        mismatchStart.ArgumentList.Add("/c");
        mismatchStart.ArgumentList.Add("ping -t 127.0.0.1 > nul");
        var actualMismatchStart = new ProcessStartInfo
        {
            FileName = mismatchedAppHostPath,
            WorkingDirectory = Path.GetDirectoryName(appHostPath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        actualMismatchStart.ArgumentList.Add(
            TrustedContainmentForwarderArgument);
        actualMismatchStart.ArgumentList.Add(containmentMarker);
        var beforeResumeObserved = false;
        var activeProcessesBeforeResume = 0u;
        try
        {
            AssertThrows<InvalidDataException>(() => lease.StartForTests(
                mismatchStart,
                actualMismatchStart,
                (processId, activeProcesses) =>
                {
                    beforeResumeObserved = true;
                    activeProcessesBeforeResume = activeProcesses;
                    mismatchedForwarderProcessId = processId;
                    AssertFalse(File.Exists(containmentMarker));
                },
                started =>
                {
                    string[]? processIds = null;
                    if (!SpinWait.SpinUntil(
                            () =>
                            {
                                try
                                {
                                    processIds = File.ReadAllLines(containmentMarker);
                                    return processIds.Length == 2;
                                }
                                catch (IOException)
                                {
                                    return false;
                                }
                            },
                            TimeSpan.FromSeconds(5)))
                    {
                        throw new TimeoutException(
                            "Real mismatched apphost did not publish its process tree.");
                    }
                    if (processIds is null
                        || !int.TryParse(
                            processIds[0],
                            System.Globalization.NumberStyles.None,
                            System.Globalization.CultureInfo.InvariantCulture,
                            out mismatchedForwarderProcessId)
                        || !int.TryParse(
                            processIds[1],
                            System.Globalization.NumberStyles.None,
                            System.Globalization.CultureInfo.InvariantCulture,
                            out mismatchedFinalProcessId)
                        || mismatchedForwarderProcessId != started.Id
                        || mismatchedFinalProcessId <= 0)
                    {
                        throw new InvalidDataException(
                            "Real mismatched apphost published invalid process identities.");
                    }
                }));
            AssertTrue(beforeResumeObserved);
            AssertEqual(1u, activeProcessesBeforeResume);
            AssertTrue(mismatchedForwarderProcessId > 0);
            AssertEqual(0, mismatchedFinalProcessId);
            AssertFalse(File.Exists(containmentMarker));
            AssertTrue(WaitForProcessExit(mismatchedForwarderProcessId));
        }
        finally
        {
            DeleteFileWithRetry(mismatchedAppHostPath);
        }
    }

    private static void DeleteFileWithRetry(string path)
    {
        var timeout = Stopwatch.StartNew();
        Exception? lastFailure = null;
        do
        {
            try
            {
                File.Delete(path);
                if (!File.Exists(path))
                {
                    return;
                }
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException)
            {
                lastFailure = exception;
            }
            Thread.Sleep(50);
        }
        while (timeout.Elapsed < TimeSpan.FromSeconds(5));

        throw new IOException(
            "Enterprise containment fixture remained locked after its process tree exited.",
            lastFailure);
    }

    private static Task ClientBootstrapperLaunchModesShareTrustedHelperAsync()
    {
        var root = Path.Combine(
            TempRoot,
            $"client-bootstrapper-launch-helper-{Guid.NewGuid():N}");
        var localRoot = Path.Combine(root, "local");
        var profileRoot = Path.Combine(root, "profile");
        Directory.CreateDirectory(localRoot);
        Directory.CreateDirectory(profileRoot);
        var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
            localRoot,
            profileRoot);
        var entryAssemblyPath = Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException(
                "InstallationTests entry assembly is unavailable.");
        var appHostPath = Path.ChangeExtension(entryAssemblyPath, ".exe");
        if (!File.Exists(appHostPath))
        {
            throw new InvalidOperationException(
                "InstallationTests apphost is unavailable for the real trusted-launch probe.");
        }
        var launcherPath = Path.Combine(
            Path.GetDirectoryName(appHostPath)!,
            $"enterprise-trusted-launch-probe-{Guid.NewGuid():N}.exe");
        File.Copy(appHostPath, launcherPath);
        var workingDirectory = Path.GetDirectoryName(appHostPath)!;
        var healthToken = new string('A', 43);
        var normalStart = EnterpriseTrustedLauncherProcessStarter.CreateStartInfo(
            launcherPath,
            workingDirectory,
            healthToken: null);
        var healthStart = EnterpriseTrustedLauncherProcessStarter.CreateStartInfo(
            launcherPath,
            workingDirectory,
            healthToken);

        AssertFalse(normalStart.UseShellExecute);
        AssertTrue(normalStart.CreateNoWindow);
        AssertEqual(ProcessWindowStyle.Normal, normalStart.WindowStyle);
        AssertEqual(0, normalStart.ArgumentList.Count);
        AssertFalse(healthStart.UseShellExecute);
        AssertTrue(healthStart.CreateNoWindow);
        AssertEqual(ProcessWindowStyle.Hidden, healthStart.WindowStyle);
        AssertTrue(healthStart.ArgumentList.SequenceEqual(
            new[]
            {
                "--installation-self-check",
                "--release-health-token",
                healthToken,
            },
            StringComparer.Ordinal));

        var originalMarker = Environment.GetEnvironmentVariable(
            TrustedLauncherProbeMarkerEnvironment);
        Process? process = null;
        try
        {
            var normalMarker = Path.Combine(root, "normal.marker");
            Environment.SetEnvironmentVariable(
                TrustedLauncherProbeMarkerEnvironment,
                normalMarker);
            process = EnterpriseTrustedLauncherProcessStarter.Start(
                layout,
                launcherPath,
                workingDirectory,
                healthToken: null);
            AssertTrue(SpinWait.SpinUntil(
                () => File.Exists(normalMarker),
                TimeSpan.FromSeconds(5)));
            AssertEqual(string.Empty, File.ReadAllText(normalMarker));
            StopProcess(process);
            process.Dispose();
            process = null;

            Directory.CreateDirectory(layout.HarnessHome);
            var historyPath = Path.Combine(layout.HarnessHome, "history");
            File.WriteAllText(historyPath, "ordinary-jsonl");
            var blockedMarker = Path.Combine(root, "blocked-before-resume.marker");
            Environment.SetEnvironmentVariable(
                TrustedLauncherProbeMarkerEnvironment,
                blockedMarker);
            var rejectedProcessId = 0;
            var blocked = AssertThrowsAndReturn<InvalidOperationException>(() =>
                EnterpriseTrustedLauncherProcessStarter.Start(
                    layout,
                    launcherPath,
                    workingDirectory,
                    healthToken: null,
                    validateBeforeResume: suspended =>
                    {
                        rejectedProcessId = suspended.Id;
                        File.Delete(historyPath);
                        File.WriteAllBytes(
                            historyPath,
                            "SQLite format 3\0replacement"u8.ToArray());
                        EnterpriseLegacySqliteUpgradeGuard
                            .RequireJsonlOnlyHarnessHome(layout);
                    }).Dispose());
            AssertEqual(
                EnterpriseLegacySqliteUpgradeGuard.BlockedMessage,
                blocked.Message);
            AssertTrue(rejectedProcessId > 0);
            AssertTrue(WaitForProcessExit(rejectedProcessId));
            AssertFalse(File.Exists(blockedMarker));
            File.Delete(historyPath);
            File.WriteAllText(historyPath, "ordinary-jsonl");

            var healthMarker = Path.Combine(root, "health.marker");
            Environment.SetEnvironmentVariable(
                TrustedLauncherProbeMarkerEnvironment,
                healthMarker);
            using (var healthStarted =
                   EnterpriseTrustedLauncherProcessStarter.StartContained(
                       layout,
                       launcherPath,
                       workingDirectory,
                       healthToken))
            {
                process = healthStarted.Process;
                AssertTrue(SpinWait.SpinUntil(
                    () => File.Exists(healthMarker),
                    TimeSpan.FromSeconds(5)));
                AssertEqual(
                    string.Join(
                        '\n',
                        "--installation-self-check",
                        "--release-health-token",
                        healthToken),
                    File.ReadAllText(healthMarker));
                healthStarted.TerminateRequired();
                process = null;
            }
        }
        finally
        {
            if (process is not null)
            {
                StopProcess(process);
                process.Dispose();
            }
            Environment.SetEnvironmentVariable(
                TrustedLauncherProbeMarkerEnvironment,
                originalMarker);
            File.Delete(launcherPath);
        }
        return Task.CompletedTask;
    }

    private static int? TryRunTrustedLauncherProbe(IReadOnlyList<string> args)
    {
        var markerPath = Environment.GetEnvironmentVariable(
            TrustedLauncherProbeMarkerEnvironment);
        if (string.IsNullOrWhiteSpace(markerPath))
        {
            return null;
        }
        if (args.Count != 0
            && args is not
            ["--installation-self-check", "--release-health-token", _])
        {
            return 41;
        }
        File.WriteAllText(markerPath, string.Join('\n', args));
        Thread.Sleep(TimeSpan.FromSeconds(30));
        return 0;
    }

    private static int? TryRunTrustedContainmentProbe(IReadOnlyList<string> args)
    {
        if (args is [TrustedContainmentFinalArgument, var finalMarker])
        {
            File.WriteAllText(
                finalMarker,
                Environment.ProcessId.ToString(
                    System.Globalization.CultureInfo.InvariantCulture));
            Thread.Sleep(TimeSpan.FromSeconds(30));
            return 0;
        }
        if (args is not [TrustedContainmentForwarderArgument, var marker])
        {
            return null;
        }

        var finalMarkerPath = $"{marker}.final";
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "Containment forwarder process path is unavailable.");
        var finalStart = new ProcessStartInfo
        {
            FileName = processPath,
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        finalStart.ArgumentList.Add(TrustedContainmentFinalArgument);
        finalStart.ArgumentList.Add(finalMarkerPath);
        using var finalProcess = Process.Start(finalStart)
            ?? throw new InvalidOperationException(
                "Containment final apphost did not start.");
        if (!SpinWait.SpinUntil(
                () => File.Exists(finalMarkerPath),
                TimeSpan.FromSeconds(5)))
        {
            StopProcess(finalProcess);
            throw new TimeoutException(
                "Containment final apphost did not publish its process identity.");
        }
        var finalProcessId = File.ReadAllText(finalMarkerPath).Trim();
        File.WriteAllText(
            marker,
            string.Join(
                '\n',
                Environment.ProcessId.ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
                finalProcessId));
        finalProcess.WaitForExit();
        return finalProcess.ExitCode;
    }

    private static Task AuthenticodeVerifierRequiresTrustedTimestampAsync()
    {
        var root = Path.Combine(TempRoot, $"authenticode-timestamp-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var executable = Path.Combine(root, "candidate.exe");
        File.WriteAllBytes(executable, "enterprise-executable-fixture"u8.ToArray());
        var expectedSigner = new string('A', 64);
        var inspectionCalled = false;

        EnterpriseAuthenticodeVerifier.RequireTrustedSignatureForTests(
            executable,
            expectedSigner,
            (path, handle) =>
            {
                AssertEqual(Path.GetFullPath(executable), path);
                AssertFalse(handle.IsInvalid);
                AssertMutationDenied(() =>
                    File.Open(
                        executable,
                        FileMode.Open,
                        FileAccess.Write,
                        FileShare.Read).Dispose());
                inspectionCalled = true;
                return new EnterpriseAuthenticodeInspection(
                    Status: 0,
                    SignerSha256Thumbprint: expectedSigner,
                    HasTrustedTimestamp: true);
            });
        AssertTrue(inspectionCalled);

        AssertThrowsContaining<InvalidDataException>(
            () => EnterpriseAuthenticodeVerifier.RequireTrustedSignatureForTests(
                executable,
                expectedSigner,
                (_, _) => new EnterpriseAuthenticodeInspection(
                    Status: 0,
                    SignerSha256Thumbprint: expectedSigner,
                    HasTrustedTimestamp: false)),
            "no trusted Authenticode timestamp");
        AssertThrowsContaining<InvalidDataException>(
            () => EnterpriseAuthenticodeVerifier.RequireTrustedSignatureForTests(
                executable,
                expectedSigner,
                (_, _) => new EnterpriseAuthenticodeInspection(
                    Status: unchecked((int)0x800B0100),
                    SignerSha256Thumbprint: expectedSigner,
                    HasTrustedTimestamp: true)),
            "Authenticode verification failed");
        AssertThrowsContaining<InvalidDataException>(
            () => EnterpriseAuthenticodeVerifier.RequireTrustedSignatureForTests(
                executable,
                expectedSigner,
                (_, _) => new EnterpriseAuthenticodeInspection(
                    Status: 0,
                    SignerSha256Thumbprint: new string('B', 64),
                    HasTrustedTimestamp: true)),
            "signer does not match");
        return Task.CompletedTask;
    }

    private static Task AuthenticodeVerifierAcceptsTimestampedSystemFixtureAsync()
    {
        var executable = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "PowerShell",
            "7",
            "pwsh.exe");
        AssertTrue(File.Exists(executable));
        var inspection =
            EnterpriseAuthenticodeVerifier.InspectTrustedSignatureForTests(
                executable);
        AssertEqual(0, inspection.Status);
        AssertTrue(inspection.HasTrustedTimestamp);
        AssertTrue(inspection.SignerSha256Thumbprint is { Length: 64 });
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
            executable,
            inspection.SignerSha256Thumbprint!);
        return Task.CompletedTask;
    }

    private static Task DevelopmentMarkerRequiredAsync()
    {
        var payload = NewDirectory("payload-no-marker");
        AssertThrows<InvalidDataException>(() =>
            EnterpriseDirectoryPayloadSource.OpenExplicitDevelopmentPayload(payload));
        return Task.CompletedTask;
    }

    private static Task AdjacentPayloadInferenceIsDevelopmentOnlyAsync()
    {
        var bundleRoot = NewDirectory("adjacent-payload-bundle");
        var payload = Path.Combine(bundleRoot, "payload");
        Directory.CreateDirectory(payload);

        AssertTrue(EnterpriseInstallerArgumentPolicy.TryInferAdjacentDevelopmentPayload(
            [], true, bundleRoot, out var inferred));
        AssertEqual(Path.GetFullPath(payload), inferred);
        AssertFalse(EnterpriseInstallerArgumentPolicy.TryInferAdjacentDevelopmentPayload(
            [], false, bundleRoot, out var productionInferred));
        AssertEqual<string?>(null, productionInferred);
        AssertFalse(EnterpriseInstallerArgumentPolicy.TryInferAdjacentDevelopmentPayload(
            ["--quiet"], true, bundleRoot, out var explicitInferred));
        AssertEqual<string?>(null, explicitInferred);
        return Task.CompletedTask;
    }

    private static Task ProductionInstallerRejectsDevelopmentOptionsAsync()
    {
        var localRoot = Path.Combine(TempRoot, "parser-local");
        var profileRoot = Path.Combine(TempRoot, "parser-profile");
        var payloadRoot = Path.Combine(TempRoot, "parser-payload");
        var developmentArguments = new[]
        {
            new[] { "--dev-unsigned" },
            new[] { "--dev-e2e-layout" },
            new[] { "--dev-e2e-no-shell-registration" },
            new[] { "--dev-e2e-local-app-data-root", localRoot },
            new[] { "--dev-e2e-user-profile-root", profileRoot },
            new[] { "--payload", payloadRoot },
        };

        foreach (var arguments in developmentArguments)
        {
            AssertThrowsContaining<ArgumentException>(
                () => EnterpriseInstallerArgumentPolicy.EnsureBuildAllowsDevelopmentOptions(
                    arguments,
                    developmentE2EEnabled: false),
                "Development E2E options are not available");
        }

        EnterpriseInstallerArgumentPolicy.EnsureBuildAllowsDevelopmentOptions(
            ["--install", "--quiet"],
            developmentE2EEnabled: false);
        EnterpriseInstallerArgumentPolicy.EnsureBuildAllowsDevelopmentOptions(
            developmentArguments.SelectMany(arguments => arguments).ToArray(),
            developmentE2EEnabled: true);
        return Task.CompletedTask;
    }

    private static Task EnterpriseClientPlatformIsExactAsync()
    {
        AssertTrue(EnterpriseClientPlatform.IsSupportedArchitecture(
            isWindows: true,
            Architecture.X64,
            Architecture.X64));
        AssertFalse(EnterpriseClientPlatform.IsSupportedArchitecture(
            isWindows: true,
            Architecture.Arm64,
            Architecture.X64));
        AssertFalse(EnterpriseClientPlatform.IsSupportedArchitecture(
            isWindows: true,
            Architecture.X64,
            Architecture.Arm64));
        AssertFalse(EnterpriseClientPlatform.IsSupportedArchitecture(
            isWindows: false,
            Architecture.X64,
            Architecture.X64));
        return Task.CompletedTask;
    }

    private static Task ProductionPayloadBindingAsync()
    {
        const string launcherReleaseId = "launcher-production-1";
        const string runtimeReleaseId = "runtime-production-1";
        var payload = CreatePayload(
            launcherReleaseId,
            runtimeReleaseId,
            "production-binding",
            layoutProfile: EnterpriseInstallationLayout.ProductionLayoutProfile);
        var launcherPath = Path.Combine(payload, "launcher.zip");
        var runtimePath = Path.Combine(payload, "runtime.zip");
        var bootstrapperPath = Path.Combine(
            payload,
            EnterpriseInstallationLayout.BootstrapperExecutableName);
        var expected = new EnterpriseProductionPayloadExpectation(
            launcherReleaseId,
            runtimeReleaseId,
            ComputeSha256(launcherPath),
            ComputeSha256(runtimePath),
            ComputeSha256(bootstrapperPath));
        using (var source = EnterpriseDirectoryPayloadSource
                   .OpenExplicitDevelopmentPayload(payload))
        {
            var manifest = EnterpriseEmbeddedProductionPayloadVerifier.Verify(source, expected);
            AssertEqual(launcherReleaseId, manifest.LauncherReleaseId);
            AssertEqual(runtimeReleaseId, manifest.RuntimeReleaseId);
        }

        AssertThrows<InvalidDataException>(() =>
        {
            using var source = EnterpriseDirectoryPayloadSource
                .OpenExplicitDevelopmentPayload(payload);
            _ = EnterpriseEmbeddedProductionPayloadVerifier.VerifyDevelopmentE2E(
                source,
                expected);
        });

        var developmentPayload = CreatePayload(
            launcherReleaseId,
            runtimeReleaseId,
            "development-binding",
            layoutProfile: EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile);
        var developmentExpected = new EnterpriseProductionPayloadExpectation(
            launcherReleaseId,
            runtimeReleaseId,
            ComputeSha256(Path.Combine(developmentPayload, "launcher.zip")),
            ComputeSha256(Path.Combine(developmentPayload, "runtime.zip")),
            ComputeSha256(Path.Combine(
                developmentPayload,
                EnterpriseInstallationLayout.BootstrapperExecutableName)));
        using (var source = EnterpriseDirectoryPayloadSource
                   .OpenExplicitDevelopmentPayload(developmentPayload))
        {
            var manifest = EnterpriseEmbeddedProductionPayloadVerifier
                .VerifyDevelopmentE2E(source, developmentExpected);
            AssertEqual(
                EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile,
                manifest.LayoutProfile);
        }
        AssertThrows<InvalidDataException>(() =>
        {
            using var source = EnterpriseDirectoryPayloadSource
                .OpenExplicitDevelopmentPayload(developmentPayload);
            _ = EnterpriseEmbeddedProductionPayloadVerifier.Verify(
                source,
                developmentExpected);
        });

        AssertThrows<InvalidDataException>(() =>
        {
            using var source = EnterpriseDirectoryPayloadSource
                .OpenExplicitDevelopmentPayload(payload);
            _ = EnterpriseEmbeddedProductionPayloadVerifier.Verify(
                source,
                expected with { RuntimeArchiveSha256 = new string('a', 64) });
        });

        File.AppendAllText(bootstrapperPath, "tampered");
        AssertThrows<InvalidDataException>(() =>
        {
            using var source = EnterpriseDirectoryPayloadSource
                .OpenExplicitDevelopmentPayload(payload);
            _ = EnterpriseEmbeddedProductionPayloadVerifier.Verify(source, expected);
        });
        return Task.CompletedTask;
    }

    private static async Task ExternalDevelopmentPayloadRejectedForProductionLayoutAsync()
    {
        var root = NewDirectory("production-boundary");
        var localAppData = Path.Combine(root, "LocalAppData");
        var userProfile = Path.Combine(root, "Profile");
        Directory.CreateDirectory(localAppData);
        Directory.CreateDirectory(userProfile);
        var layout = EnterpriseInstallationLayout.Create(localAppData, userProfile);
        var payload = CreatePayload(
            "launcher-production-bypass",
            "runtime-production-bypass",
            "production-bypass",
            layoutProfile: EnterpriseInstallationLayout.ProductionLayoutProfile);

        await AssertThrowsAsync<InvalidDataException>(() =>
            CreateIsolatedInstallationService(layout)
                .InstallExternalDevelopmentPayloadAsync(payload, Environment.ProcessPath!));

        AssertFalse(Directory.Exists(layout.ManagedRoot));
        AssertFalse(File.Exists(layout.ReleaseSetPointerPath));
    }

    private static async Task EmbeddedDevelopmentPayloadRejectedForProductionLayoutAsync()
    {
        var root = NewDirectory("embedded-production-boundary");
        var localAppData = Path.Combine(root, "LocalAppData");
        var userProfile = Path.Combine(root, "Profile");
        Directory.CreateDirectory(localAppData);
        Directory.CreateDirectory(userProfile);
        var layout = EnterpriseInstallationLayout.Create(localAppData, userProfile);

        await AssertThrowsAsync<InvalidDataException>(() =>
            CreateIsolatedInstallationService(layout)
                .InstallEmbeddedDevelopmentPayloadAsync(
                    typeof(Program).Assembly,
                    Environment.ProcessPath!));

        AssertFalse(Directory.Exists(layout.ManagedRoot));
        AssertFalse(File.Exists(layout.ReleaseSetPointerPath));
    }

    private static async Task InstallRepairAndRollbackAsync()
    {
        var fixture = CreateFixture();
        var payloadV1 = CreatePayload("launcher-v1", "runtime-v1", "v1");
        var service = CreateIsolatedInstallationService(fixture.Layout);
        var executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("Test executable path is missing.");
        var first = await service.InstallExternalDevelopmentPayloadAsync(
            payloadV1,
            executable).ConfigureAwait(false);
        AssertEqual("launcher-v1", first.LauncherReleaseId);
        AssertEqual("runtime-v1", first.RuntimeReleaseId);
        AssertTrue(first.DevelopmentUnsignedPayload);
        var workspaceRoot = Path.Combine(fixture.Layout.HarnessHome, "workspaces");
        Directory.CreateDirectory(workspaceRoot);
        var workspaceFile = Path.Combine(workspaceRoot, "repair-preserved.txt");
        File.WriteAllText(workspaceFile, "workspace-keep");

        var launcherStore = new EnterpriseLauncherPointerStore(fixture.Layout);
        var runtimeStore = new EnterpriseRuntimePointerStore(fixture.Layout);
        var launcherV1 = launcherStore.ReadRequired();
        var runtimeV1 = runtimeStore.ReadRequired();
        AssertEqual("launcher-v1", launcherV1.ReleaseId);
        AssertEqual("runtime-v1", runtimeV1.ReleaseId);

        var runtimeEntryPoint = Path.Combine(
            runtimeV1.RuntimeDirectory,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "lib",
            "bin.js");
        File.WriteAllText(runtimeEntryPoint, "tampered-entry");
        AssertThrows<InvalidDataException>(() => runtimeStore.ReadRequired());
        await service.InstallExternalDevelopmentPayloadAsync(payloadV1, executable)
            .ConfigureAwait(false);
        AssertEqual("entry-v1", File.ReadAllText(runtimeEntryPoint));

        var launcherPath = Path.Combine(
            launcherV1.LauncherDirectory,
            EnterpriseInstallationLayout.LauncherExecutableName);
        File.WriteAllText(launcherPath, "corrupted");
        AssertThrows<InvalidDataException>(() => launcherStore.ReadRequired());
        await service.InstallExternalDevelopmentPayloadAsync(payloadV1, executable)
            .ConfigureAwait(false);
        AssertEqual("launcher-v1-content", File.ReadAllText(launcherPath));
        File.WriteAllText(fixture.Layout.RuntimePointerPath, "{broken-json");
        await service.InstallExternalDevelopmentPayloadAsync(payloadV1, executable)
            .ConfigureAwait(false);
        AssertEqual("runtime-v1", runtimeStore.ReadRequired().ReleaseId);

        var payloadV2 = CreatePayload("launcher-v2", "runtime-v2", "v2");
        await AssertThrowsAsync<InvalidOperationException>(() =>
            service.InstallExternalDevelopmentPayloadAsync(payloadV2, executable));
        AssertEqual(
            "launcher-v1",
            new EnterpriseReleaseSetPointerStore(fixture.Layout)
                .ReadRequired().Current.Launcher.ReleaseId);
        AssertFalse(Directory.Exists(fixture.Layout.GetLauncherVersionDirectory("launcher-v2")));
        AssertFalse(Directory.Exists(fixture.Layout.GetRuntimeVersionDirectory("runtime-v2")));
        AssertFalse(Directory.EnumerateFiles(
            fixture.Layout.StateRoot,
            "*.tmp",
            SearchOption.TopDirectoryOnly).Any());
        AssertEqual("workspace-keep", File.ReadAllText(workspaceFile));
    }

    private static async Task InstallRegistrationFailureRestoresExactStateAsync()
    {
        var fixture = CreateFixture();
        var payload = CreatePayload(
            "launcher-registration-transaction",
            "runtime-registration-transaction",
            "registration-transaction");
        var context = new EnterpriseWindowsRegistrationContext(
            @"Software\Ensou\CodexTests\EnterpriseInstallTransaction\"
                + Guid.NewGuid().ToString("N"),
            Path.Combine(fixture.Root, "shell", "desktop", "Enterprise Launcher.lnk"),
            Path.Combine(
                fixture.Root,
                "shell",
                "programs",
                "Ensou",
                "Enterprise Launcher.lnk"));
        var service = CreateIsolatedInstallationService(fixture.Layout);
        try
        {
            await service.InstallExternalDevelopmentPayloadAndRegisterAsync(
                    payload,
                    Environment.ProcessPath!,
                    context)
                .ConfigureAwait(false);

            using (var key = Registry.CurrentUser.OpenSubKey(
                       context.RegistrySubKey,
                       writable: true)
                   ?? throw new InvalidOperationException(
                       "Expected isolated Enterprise registration key."))
            {
                key.SetValue(
                    "DisplayVersion",
                    "exact-pre-state-display-version",
                    RegistryValueKind.String);
                key.SetValue(
                    "CustomRollbackSentinel",
                    new byte[] { 1, 3, 3, 7 },
                    RegistryValueKind.Binary);
                key.Flush();
            }

            Directory.CreateDirectory(fixture.Layout.HarnessHome);
            File.WriteAllText(
                Path.Combine(fixture.Layout.HarnessHome, "history.json"),
                "keep-history");
            Directory.CreateDirectory(fixture.Layout.HarnessRecoveryRoot);
            File.WriteAllText(
                Path.Combine(fixture.Layout.HarnessRecoveryRoot, "recovery.json"),
                "keep-recovery");

            var runtime = new EnterpriseRuntimePointerStore(fixture.Layout).ReadRequired();
            var runtimeEntry = Path.Combine(
                runtime.RuntimeDirectory,
                "node_modules",
                "@deepseek-ai",
                "dsh",
                "lib",
                "bin.js");
            File.WriteAllText(runtimeEntry, "exact-pre-state-corruption");
            var programBefore = ComputeSha256(runtimeEntry);
            var shellBefore = SnapshotRegistration(fixture.Layout, context);
            var localDataBefore = SnapshotLocalData(fixture.Layout);

            var failOnce = true;
            var failingContext = context with
            {
                InstallObserver = stage =>
                {
                    if (failOnce
                        && stage == EnterpriseWindowsRegistrationInstallStage.DesktopShortcutInstalled)
                    {
                        failOnce = false;
                        throw new IOException(
                            "injected Enterprise registration install failure");
                    }
                },
            };
            await AssertThrowsAsync<IOException>(() =>
                service.InstallExternalDevelopmentPayloadAndRegisterAsync(
                    payload,
                    Environment.ProcessPath!,
                    failingContext));

            AssertEqual(programBefore, ComputeSha256(runtimeEntry));
            AssertEqual(shellBefore, SnapshotRegistration(fixture.Layout, context));
            AssertEqual(localDataBefore, SnapshotLocalData(fixture.Layout));
            AssertFalse(Directory.EnumerateDirectories(
                    Path.GetDirectoryName(fixture.Layout.ManagedRoot)!,
                    $".{Path.GetFileName(fixture.Layout.ManagedRoot)}.install-rollback-*",
                    SearchOption.TopDirectoryOnly)
                .Any());
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(
                context.RegistrySubKey,
                throwOnMissingSubKey: false);
        }
    }

    private static async Task SharedLeaseBlocksConcurrentInstallAsync()
    {
        var fixture = CreateFixture();
        var payload = CreatePayload(
            "launcher-concurrent-install",
            "runtime-concurrent-install",
            "concurrent-install");
        using var operationLease = await EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(fixture.Layout).ConfigureAwait(false);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await AssertThrowsAsync<OperationCanceledException>(() =>
            CreateIsolatedInstallationService(fixture.Layout)
                .InstallExternalDevelopmentPayloadAsync(
                    payload,
                    Environment.ProcessPath!,
                    cancellation.Token));
        AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertFalse(Directory.Exists(fixture.Layout.HarnessHome));
        AssertFalse(Directory.Exists(fixture.Layout.HarnessRecoveryRoot));
    }

    private static async Task DurableInstallJournalRecoversInterruptedStateAsync()
    {
        var fixture = CreateFixture();
        var payload = CreatePayload(
            "launcher-durable-recovery",
            "runtime-durable-recovery",
            "durable-recovery");
        var context = CreateIsolatedRegistrationContext(fixture.Root, "durable-recovery");
        try
        {
            var service = CreateIsolatedInstallationService(fixture.Layout);
            await service.InstallExternalDevelopmentPayloadAndRegisterAsync(
                    payload,
                    Environment.ProcessPath!,
                    context)
                .ConfigureAwait(false);
            Directory.CreateDirectory(fixture.Layout.HarnessHome);
            File.WriteAllText(
                Path.Combine(fixture.Layout.HarnessHome, "history.json"),
                "keep-history");
            Directory.CreateDirectory(fixture.Layout.HarnessRecoveryRoot);
            File.WriteAllText(
                Path.Combine(fixture.Layout.HarnessRecoveryRoot, "recovery.json"),
                "keep-recovery");
            var localDataBefore = SnapshotLocalData(fixture.Layout);
            var shellBefore = SnapshotRegistration(fixture.Layout, context);
            var runtime = new EnterpriseRuntimePointerStore(fixture.Layout).ReadRequired();
            var pointerBefore = ComputeSha256(fixture.Layout.RuntimePointerPath);
            var runtimeEntry = Path.Combine(
                runtime.RuntimeDirectory,
                "node_modules",
                "@deepseek-ai",
                "dsh",
                "lib",
                "bin.js");
            var runtimeEntryBefore = ComputeSha256(runtimeEntry);
            var registrationSnapshot =
                EnterpriseWindowsRegistration.CaptureRollbackSnapshot(
                    fixture.Layout,
                    context);

            var abandoned = new EnterpriseInstallRollbackTransaction(
                fixture.Layout,
                context,
                registrationSnapshot);
            abandoned.CaptureFile(fixture.Layout.RuntimePointerPath);
            File.WriteAllText(fixture.Layout.RuntimePointerPath, "{interrupted");
            abandoned.PrepareDirectoryReplacement(runtime.RuntimeDirectory);
            Directory.CreateDirectory(runtime.RuntimeDirectory);
            File.WriteAllText(
                Path.Combine(runtime.RuntimeDirectory, "candidate.bin"),
                "interrupted-candidate");
            File.WriteAllText(context.DesktopShortcutPath, "partial-shortcut");
            using (var key = Registry.CurrentUser.OpenSubKey(
                       context.RegistrySubKey,
                       writable: true)
                   ?? throw new InvalidOperationException(
                       "Expected isolated Enterprise registration key."))
            {
                key.SetValue(
                    "DisplayVersion",
                    "partial-registration",
                    RegistryValueKind.String);
                key.Flush();
            }

            EnterpriseInstallRollbackTransaction.RecoverInterrupted(fixture.Layout);

            AssertEqual(pointerBefore, ComputeSha256(fixture.Layout.RuntimePointerPath));
            AssertEqual(runtimeEntryBefore, ComputeSha256(runtimeEntry));
            AssertEqual(shellBefore, SnapshotRegistration(fixture.Layout, context));
            AssertEqual(localDataBefore, SnapshotLocalData(fixture.Layout));
            AssertFalse(FindInstallJournals(fixture.Layout).Any());
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(
                context.RegistrySubKey,
                throwOnMissingSubKey: false);
        }
    }

    private static Task ShortcutStagingPathIsCompatibleAsync()
    {
        var root = NewDirectory("shortcut-staging-path");
        var shortcutPath = Path.Combine(root, "Enterprise Launcher.lnk");
        var temporaryPath = EnterpriseWindowsRegistration.BuildShortcutTemporaryPath(
            shortcutPath);

        AssertEqual(
            Path.GetFullPath(root),
            Path.GetFullPath(Path.GetDirectoryName(temporaryPath)!));
        AssertEqual(".lnk", Path.GetExtension(temporaryPath));
        AssertTrue(Path.GetFileName(temporaryPath).StartsWith(".", StringComparison.Ordinal));
        AssertTrue(Path.GetFileName(temporaryPath).Length <= 37);
        return Task.CompletedTask;
    }

    private static Task ShortcutDirectoryMasqueradeFailsClosedAsync()
    {
        var fixture = CreateFixture();
        var context = CreateIsolatedRegistrationContext(
            fixture.Root,
            "shortcut-directory-masquerade");
        Directory.CreateDirectory(context.DesktopShortcutPath);

        AssertThrows<InvalidDataException>(() =>
            EnterpriseWindowsRegistration.CaptureRollbackSnapshot(
                fixture.Layout,
                context));
        AssertThrows<InvalidDataException>(() =>
            EnterpriseWindowsRegistration.Remove(fixture.Layout, context));
        AssertTrue(Directory.Exists(context.DesktopShortcutPath));
        return Task.CompletedTask;
    }

    private static async Task DurableInstallJournalReconcilesPartialBackupAsync()
    {
        var fixture = CreateFixture();
        var payload = CreatePayload(
            "launcher-partial-backup",
            "runtime-partial-backup",
            "partial-backup");
        await CreateIsolatedInstallationService(fixture.Layout)
            .InstallExternalDevelopmentPayloadAsync(payload, Environment.ProcessPath!)
            .ConfigureAwait(false);
        var originalSha256 = ComputeSha256(fixture.Layout.BootstrapperPath);
        var abandoned = new EnterpriseInstallRollbackTransaction(fixture.Layout);
        abandoned.CaptureFile(fixture.Layout.BootstrapperPath);
        var journal = FindInstallJournals(fixture.Layout).Single();
        var backup = Path.Combine(journal, "file-0000.rollback");
        using (var stream = new FileStream(
                   backup,
                   FileMode.Open,
                   FileAccess.Write,
                   FileShare.None))
        {
            stream.SetLength(Math.Max(1, stream.Length / 2));
            stream.Flush(flushToDisk: true);
        }
        EnterpriseInstallRollbackTransaction.RewriteStatePlaintextForTest(
            fixture.Layout,
            journal,
            plaintext => Encoding.UTF8.GetBytes(
                Encoding.UTF8.GetString(plaintext).Replace(
                    "\"phase\":\"captured\"",
                    "\"phase\":\"planned\"",
                    StringComparison.Ordinal)));

        EnterpriseInstallRollbackTransaction.RecoverInterrupted(fixture.Layout);

        AssertEqual(originalSha256, ComputeSha256(fixture.Layout.BootstrapperPath));
        AssertFalse(FindInstallJournals(fixture.Layout).Any());
    }

    private static async Task ExternalUninstallRecoversInterruptedInstallAsync()
    {
        var fixture = CreateFixture();
        var payload = CreatePayload(
            "launcher-external-uninstall-recovery",
            "runtime-external-uninstall-recovery",
            "external-uninstall-recovery");
        var context = CreateIsolatedRegistrationContext(
            fixture.Root,
            "external-uninstall-recovery");
        try
        {
            var service = CreateIsolatedInstallationService(fixture.Layout);
            await service.InstallExternalDevelopmentPayloadAndRegisterAsync(
                    payload,
                    Environment.ProcessPath!,
                    context)
                .ConfigureAwait(false);
            Directory.CreateDirectory(fixture.Layout.HarnessHome);
            File.WriteAllText(
                Path.Combine(fixture.Layout.HarnessHome, "history.json"),
                "keep-history");
            Directory.CreateDirectory(fixture.Layout.HarnessRecoveryRoot);
            File.WriteAllText(
                Path.Combine(fixture.Layout.HarnessRecoveryRoot, "recovery.json"),
                "keep-recovery");
            var localDataBefore = SnapshotLocalData(fixture.Layout);
            var runtime = new EnterpriseRuntimePointerStore(fixture.Layout).ReadRequired();
            var registrationSnapshot =
                EnterpriseWindowsRegistration.CaptureRollbackSnapshot(
                    fixture.Layout,
                    context);
            var abandoned = new EnterpriseInstallRollbackTransaction(
                fixture.Layout,
                context,
                registrationSnapshot);
            abandoned.CaptureFile(fixture.Layout.RuntimePointerPath);
            File.WriteAllText(fixture.Layout.RuntimePointerPath, "{interrupted");
            abandoned.PrepareDirectoryReplacement(runtime.RuntimeDirectory);
            Directory.CreateDirectory(runtime.RuntimeDirectory);
            File.WriteAllText(
                Path.Combine(runtime.RuntimeDirectory, "candidate.bin"),
                "interrupted-candidate");

            var result = service.UninstallManagedProgramFiles(context);

            AssertTrue(result.ActiveInstallationRemoved);
            AssertTrue(result.QuarantineDeleted);
            AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
            AssertFalse(File.Exists(context.DesktopShortcutPath));
            AssertFalse(File.Exists(context.StartMenuShortcutPath));
            using var key = Registry.CurrentUser.OpenSubKey(context.RegistrySubKey);
            AssertTrue(key is null);
            AssertEqual(localDataBefore, SnapshotLocalData(fixture.Layout));
            AssertFalse(FindInstallJournals(fixture.Layout).Any());
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(
                context.RegistrySubKey,
                throwOnMissingSubKey: false);
        }
    }

    private static Task DurableInstallJournalStateIsStrictAsync()
    {
        AssertDurableStateRejected(plaintext =>
        {
            var text = Encoding.UTF8.GetString(plaintext);
            return Encoding.UTF8.GetBytes(
                text.Insert(text.LastIndexOf('}'), ",\"unknown\":true"));
        }, typeof(JsonException));
        AssertDurableStateRejected(plaintext =>
        {
            var text = Encoding.UTF8.GetString(plaintext);
            return Encoding.UTF8.GetBytes(
                text.Insert(1, "\"schemaVersion\":1,"));
        }, typeof(InvalidDataException));

        var fixture = CreateFixture();
        _ = new EnterpriseInstallRollbackTransaction(fixture.Layout);
        var journal = FindInstallJournals(fixture.Layout).Single();
        var statePath = Path.Combine(journal, "install-rollback-state.v1.dpapi");
        var bytes = File.ReadAllBytes(statePath);
        bytes[^1] ^= 0x5a;
        File.WriteAllBytes(statePath, bytes);
        AssertThrows<InvalidDataException>(() =>
            EnterpriseInstallRollbackTransaction.RecoverInterrupted(fixture.Layout));
        return Task.CompletedTask;
    }

    private static async Task RuntimePointerRejectsEscapeAsync()
    {
        var fixture = CreateFixture();
        var payload = CreatePayload("launcher-safe", "runtime-safe", "safe");
        var service = CreateIsolatedInstallationService(fixture.Layout);
        await service.InstallExternalDevelopmentPayloadAsync(
            payload,
            Environment.ProcessPath!).ConfigureAwait(false);
        var pointerPath = fixture.Layout.RuntimePointerPath;
        var escapedJson = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            releaseId = "runtime-safe",
            runtimeDirectory = Path.Combine(fixture.Root, "outside-runtime"),
            previousReleaseId = (string?)null,
            previousRuntimeDirectory = (string?)null,
            updatedAtUtc = DateTimeOffset.UtcNow,
        });
        File.WriteAllBytes(pointerPath, escapedJson);
        AssertThrows<InvalidDataException>(() =>
            new EnterpriseRuntimePointerStore(fixture.Layout).ReadRequired());
    }

    private static async Task DevelopmentE2ELayoutIsolatedAsync()
    {
        var root = NewDirectory("e2e-fixture");
        var localAppData = Path.Combine(root, "LocalAppData");
        var userProfile = Path.Combine(root, "Profile");
        Directory.CreateDirectory(localAppData);
        Directory.CreateDirectory(userProfile);
        var e2eLayout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
            localAppData,
            userProfile);
        var defaultLayout = EnterpriseInstallationLayout.Create(localAppData, userProfile);
        var personalLauncherRoot = Path.Combine(localAppData, "Ensou", "DshLauncher");
        var payload = CreatePayload(
            "launcher-e2e",
            "runtime-e2e",
            "e2e",
            layoutProfile: EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile);

        await CreateIsolatedInstallationService(e2eLayout)
            .InstallExternalDevelopmentPayloadAsync(payload, Environment.ProcessPath!)
            .ConfigureAwait(false);

        AssertEqual(
            "launcher-e2e",
            new EnterpriseLauncherPointerStore(e2eLayout).ReadRequired().ReleaseId);
        AssertEqual(
            "runtime-e2e",
            new EnterpriseRuntimePointerStore(e2eLayout).ReadRequired().ReleaseId);
        AssertFalse(Directory.Exists(defaultLayout.ManagedRoot));
        AssertFalse(Directory.Exists(personalLauncherRoot));
        AssertFalse(File.Exists(defaultLayout.RuntimePointerPath));
        await AssertThrowsAsync<InvalidDataException>(() =>
            CreateIsolatedInstallationService(defaultLayout)
                .InstallExternalDevelopmentPayloadAsync(payload, Environment.ProcessPath!));
        AssertFalse(Directory.Exists(defaultLayout.ManagedRoot));
        AssertFalse(Directory.Exists(personalLauncherRoot));
        AssertFalse(File.Exists(defaultLayout.RuntimePointerPath));
    }

    private static async Task ZipTraversalRejectedAsync()
    {
        var fixture = CreateFixture();
        var payload = CreatePayload(
            "launcher-traversal",
            "runtime-traversal",
            "traversal",
            maliciousLauncherEntry: "../escaped.txt");
        var service = CreateIsolatedInstallationService(fixture.Layout);
        await AssertThrowsAsync<InvalidDataException>(() =>
            service.InstallExternalDevelopmentPayloadAsync(payload, Environment.ProcessPath!));
        AssertFalse(File.Exists(Path.Combine(
            fixture.Layout.LauncherVersionsRoot,
            "escaped.txt")));
        AssertTrue(new EnterpriseLauncherPointerStore(fixture.Layout).TryRead() is null);
    }

    private static async Task RuntimeReparsePointRejectedAsync()
    {
        var fixture = CreateFixture();
        var payload = CreatePayload("launcher-link", "runtime-link", "link");
        var service = CreateIsolatedInstallationService(fixture.Layout);
        await service.InstallExternalDevelopmentPayloadAsync(payload, Environment.ProcessPath!)
            .ConfigureAwait(false);
        var runtimePath = fixture.Layout.GetRuntimeVersionDirectory("runtime-link");
        var targetPath = NewDirectory("runtime-link-target");
        Directory.Move(runtimePath, Path.Combine(targetPath, "real"));
        if (!TryCreateDirectoryJunction(runtimePath, Path.Combine(targetPath, "real")))
        {
            Directory.Move(Path.Combine(targetPath, "real"), runtimePath);
            Console.WriteLine("SKIP  junction creation unavailable");
            return;
        }

        try
        {
            AssertThrows<InvalidDataException>(() =>
                new EnterpriseRuntimePointerStore(fixture.Layout).ReadRequired());
        }
        finally
        {
            Directory.Delete(runtimePath);
        }
    }

    private static Task PluginPolicyArchiveValidatedAsync()
    {
        var archivePath = CreatePluginPolicyArchive("managed-policy.zip", "managed skill\n");
        var inspection = EnterprisePluginPolicyArchiveValidator.Validate(
            archivePath,
            "launcher-test",
            "runtime-test");
        AssertEqual("11111111-2222-4333-8444-555555555555", inspection.PolicyId);
        AssertEqual(1L, inspection.Generation);
        AssertEqual(new FileInfo(archivePath).Length, inspection.ArchiveSizeBytes);
        AssertEqual(ComputeSha256(archivePath), inspection.ArchiveSha256);
        AssertEqual(64, inspection.PolicySha256.Length);
        return Task.CompletedTask;
    }

    private static Task PluginPolicyArchiveRejectsInvalidInputsAsync()
    {
        var tampered = CreatePluginPolicyArchive(
            "tampered-policy.zip",
            "tampered skill\n",
            declaredContent: "managed skill\n");
        AssertThrows<InvalidDataException>(() =>
            EnterprisePluginPolicyArchiveValidator.Validate(
                tampered,
                "launcher-test",
                "runtime-test"));

        var wrapped = Path.Combine(NewDirectory("wrapped-policy"), "candidate.zip");
        using (var archive = ZipFile.Open(wrapped, ZipArchiveMode.Create))
        {
            WriteEntry(archive, "mail-manager/SKILL.md", "candidate only\n");
        }
        AssertThrows<InvalidDataException>(() =>
            EnterprisePluginPolicyArchiveValidator.Validate(
                wrapped,
                "launcher-test",
                "runtime-test"));

        var wrongCase = CreatePluginPolicyArchive(
            "wrong-case-policy.zip",
            "managed skill\n",
            policyEntryName: "Plugin-policy.json");
        AssertThrows<InvalidDataException>(() =>
            EnterprisePluginPolicyArchiveValidator.Validate(
                wrongCase,
                "launcher-test",
                "runtime-test"));
        return Task.CompletedTask;
    }

    private static Task MaintenanceCommandLineIsStrictAsync()
    {
        var initial = EnterpriseMaintenanceCommandLine.Parse(
            ["--uninstall", "--startup-stub-pid", "123", "--quiet"],
            developmentE2EEnabled: false);
        AssertEqual(EnterpriseMaintenanceCommandKind.Uninstall, initial.Kind);
        AssertFalse(initial.Detached);
        AssertEqual(123, initial.StartupStubProcessId);
        var detached = EnterpriseMaintenanceCommandLine.Parse(
            [
                "--uninstall",
                "--detached",
                "--parent-pid",
                "124",
                "--startup-stub-pid",
                "123",
                "--expected-worker-sha256",
                new string('a', 64),
            ],
            developmentE2EEnabled: false);
        AssertTrue(detached.Detached);
        AssertEqual(124, detached.ParentProcessId);
        AssertEqual(new string('a', 64), detached.ExpectedWorkerSha256);

        AssertThrows<ArgumentException>(() =>
            EnterpriseMaintenanceCommandLine.Parse(
                ["--uninstall"],
                developmentE2EEnabled: false));
        AssertThrows<ArgumentException>(() =>
            EnterpriseMaintenanceCommandLine.Parse(
                ["--uninstall", "--detached", "--startup-stub-pid", "1"],
                developmentE2EEnabled: false));
        AssertThrows<ArgumentException>(() =>
            EnterpriseMaintenanceCommandLine.Parse(
                [
                    "--uninstall",
                    "--startup-stub-pid",
                    "1",
                    "--quiet",
                    "--quiet",
                ],
                developmentE2EEnabled: false));
        AssertThrows<ArgumentException>(() =>
            EnterpriseMaintenanceCommandLine.Parse(
                ["--repair-shell", "--parent-pid", "1"],
                developmentE2EEnabled: false));
        AssertThrows<ArgumentException>(() =>
            EnterpriseMaintenanceCommandLine.Parse(
                ["--repair-shell", "--dev-e2e-layout"],
                developmentE2EEnabled: false));
        return Task.CompletedTask;
    }

    private static async Task MaintenanceWorkerBindsCurrentBytesAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "worker-binding").ConfigureAwait(false);
        var active = EnterpriseMaintenanceIntegrity.RequireActiveMaintenance(
            fixture.Layout);
        AssertEqual(fixture.MaintenancePath, active.MaintenancePath);
        AssertEqual(
            active.MaintenanceSha256,
            fixture.Operations.RequireActiveMaintenanceSource(
                fixture.MaintenancePath));

        var externalCopy = Path.Combine(fixture.Root, "external-maintenance.exe");
        File.Copy(fixture.MaintenancePath, externalCopy, overwrite: false);
        AssertThrows<InvalidDataException>(() =>
            fixture.Operations.RequireActiveMaintenanceSource(externalCopy));

        var workerDirectory = Path.Combine(
            EnterpriseMaintenanceOperations.GetWorkerRoot(),
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workerDirectory);
        try
        {
            var workerPath = Path.Combine(
                workerDirectory,
                EnterpriseInstallationLayout.MaintenanceExecutableName);
            File.Copy(fixture.MaintenancePath, workerPath, overwrite: false);
            fixture.Operations.RequireDetachedMaintenanceWorker(
                workerPath,
                active.MaintenanceSha256);
            File.AppendAllText(workerPath, "old-worker");
            AssertThrows<InvalidDataException>(() =>
                fixture.Operations.RequireDetachedMaintenanceWorker(
                    workerPath,
                    active.MaintenanceSha256));
            AssertThrows<InvalidDataException>(() =>
                fixture.Operations.RequireDetachedMaintenanceWorker(
                    externalCopy,
                    active.MaintenanceSha256));
        }
        finally
        {
            if (Directory.Exists(workerDirectory))
            {
                Directory.Delete(workerDirectory, recursive: true);
            }
        }
    }

    private static async Task UninstallRetriesAreIdempotentAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "uninstall-retry").ConfigureAwait(false);
        var dataBefore = fixture.SnapshotLocalData();
        var active = EnterpriseMaintenanceIntegrity.RequireActiveMaintenance(
            fixture.Layout);
        var workerDirectory = Path.Combine(
            EnterpriseMaintenanceOperations.GetWorkerRoot(),
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workerDirectory);
        try
        {
            var workerPath = Path.Combine(
                workerDirectory,
                EnterpriseInstallationLayout.MaintenanceExecutableName);
            File.Copy(fixture.MaintenancePath, workerPath, overwrite: false);
            var first = fixture.Operations.UninstallFromDetachedWorker(
                workerPath,
                active.MaintenanceSha256);
            var second = fixture.Operations.UninstallFromDetachedWorker(
                workerPath,
                active.MaintenanceSha256);
            var externalRetry = CreateIsolatedInstallationService(fixture.Layout)
                .UninstallManagedProgramFiles(fixture.RegistrationContext);

            AssertTrue(first.ActiveInstallationRemoved);
            AssertTrue(second.ActiveInstallationRemoved);
            AssertTrue(externalRetry.ActiveInstallationRemoved);
            AssertTrue(second.QuarantineDeleted);
            AssertTrue(externalRetry.QuarantineDeleted);
            AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
            AssertEqual(dataBefore, fixture.SnapshotLocalData());
        }
        finally
        {
            if (Directory.Exists(workerDirectory))
            {
                Directory.Delete(workerDirectory, recursive: true);
            }
        }
    }

    private static async Task OpenManagedHandlePreservesRegistrationAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "open-handle").ConfigureAwait(false);
        var dataBefore = fixture.SnapshotLocalData();
        var blocker = Path.Combine(fixture.Layout.PackageRoot, "open-handle.bin");
        File.WriteAllText(blocker, "locked");
        using (var stream = new FileStream(
                   blocker,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.None))
        {
            AssertThrows<IOException>(() =>
                fixture.Operations.QuarantineManagedProgramFiles());
        }
        AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
        fixture.RequireRegistration();
        AssertEqual(dataBefore, fixture.SnapshotLocalData());
    }

    private static async Task RunningLauncherPreservesRegistrationAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "running-launcher",
            executableLauncher: true,
            shortPaths: true).ConfigureAwait(false);
        var dataBefore = fixture.SnapshotLocalData();
        using var process = StartEndlessCommand(fixture.LauncherPath);
        try
        {
            AssertThrows<IOException>(() =>
                fixture.Operations.QuarantineManagedProgramFiles());
            AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
            fixture.RequireRegistration();
            AssertEqual(dataBefore, fixture.SnapshotLocalData());
        }
        finally
        {
            StopProcess(process);
        }
    }

    private static async Task RunningStartupStubPreservesRegistrationAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "running-stub",
            executableBootstrapper: true,
            shortPaths: true).ConfigureAwait(false);
        var dataBefore = fixture.SnapshotLocalData();
        using var process = StartEndlessCommand(fixture.Layout.BootstrapperPath);
        try
        {
            AssertThrows<IOException>(() =>
                fixture.Operations.QuarantineManagedProgramFiles());
            AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
            fixture.RequireRegistration();
            AssertEqual(dataBefore, fixture.SnapshotLocalData());
        }
        finally
        {
            StopProcess(process);
        }
    }

    private static async Task PartialRegistrationRemovalRollsBackAsync()
    {
        var failOnce = true;
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "registration-rollback",
            removalObserver: stage =>
            {
                if (failOnce
                    && stage == EnterpriseWindowsRegistrationRemovalStage.DesktopShortcutRemoved)
                {
                    failOnce = false;
                    throw new IOException("injected enterprise registration failure");
                }
            }).ConfigureAwait(false);
        var dataBefore = fixture.SnapshotLocalData();
        AssertThrows<IOException>(() =>
            fixture.Operations.UninstallManagedProgramFiles());

        AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
        fixture.RequireRegistration();
        AssertEqual(dataBefore, fixture.SnapshotLocalData());
        AssertFalse(EnterpriseUninstallRollbackTransaction
            .FindJournalDirectoriesForTest(fixture.Layout).Any());
    }

    private static async Task RepairShellFailureRestoresExactRegistrationAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "repair-registration-rollback").ConfigureAwait(false);
        var shellBefore = SnapshotRegistration(
            fixture.Layout,
            fixture.RegistrationContext);
        var dataBefore = fixture.SnapshotLocalData();
        var failOnce = true;
        var failingContext = fixture.RegistrationContext with
        {
            InstallObserver = stage =>
            {
                if (failOnce
                    && stage == EnterpriseWindowsRegistrationInstallStage.DesktopShortcutInstalled)
                {
                    failOnce = false;
                    throw new IOException("injected Enterprise repair registration failure");
                }
            },
        };
        var operations = new EnterpriseMaintenanceOperations(
            fixture.Layout,
            failingContext);

        AssertThrows<IOException>(() =>
            operations.RepairShell(fixture.MaintenancePath));

        AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertEqual(
            shellBefore,
            SnapshotRegistration(fixture.Layout, fixture.RegistrationContext));
        fixture.RequireRegistration();
        AssertEqual(dataBefore, fixture.SnapshotLocalData());
        AssertFalse(FindInstallJournals(fixture.Layout).Any());
    }

    private static async Task DurableUninstallRestoresRenameGapAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "uninstall-rename-gap").ConfigureAwait(false);
        var shellBefore = SnapshotRegistration(
            fixture.Layout,
            fixture.RegistrationContext);
        var dataBefore = fixture.SnapshotLocalData();
        var transaction = new EnterpriseUninstallRollbackTransaction(
            fixture.Layout,
            fixture.RegistrationContext,
            crashPointForTest: point =>
            {
                if (point == EnterpriseUninstallCrashPoint.ManagedRootRenamedBeforePhase)
                {
                    throw new IOException("simulated rename-before-phase process termination");
                }
            });

        AssertThrows<IOException>(() => transaction.QuarantineManagedRoot());
        AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertTrue(EnterpriseUninstallRollbackTransaction
            .FindJournalDirectoriesForTest(fixture.Layout).Any());

        using (var operationLease = await EnterpriseManagedUpdateOperationLease
                   .AcquireRequiredAsync(fixture.Layout).ConfigureAwait(false))
        {
            EnterpriseUninstallRollbackTransaction.RecoverInterrupted(fixture.Layout);
        }

        AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertEqual(
            shellBefore,
            SnapshotRegistration(fixture.Layout, fixture.RegistrationContext));
        fixture.RequireRegistration();
        AssertEqual(dataBefore, fixture.SnapshotLocalData());
        AssertFalse(EnterpriseUninstallRollbackTransaction
            .FindJournalDirectoriesForTest(fixture.Layout).Any());
    }

    private static async Task DurableUninstallRestoresRegistrationGapAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "uninstall-registration-gap").ConfigureAwait(false);
        var shellBefore = SnapshotRegistration(
            fixture.Layout,
            fixture.RegistrationContext);
        var dataBefore = fixture.SnapshotLocalData();
        var transaction = new EnterpriseUninstallRollbackTransaction(
            fixture.Layout,
            fixture.RegistrationContext,
            crashPointForTest: point =>
            {
                if (point == EnterpriseUninstallCrashPoint.RegistrationRemovedBeforePhase)
                {
                    throw new IOException("simulated registration-before-phase process termination");
                }
            });
        _ = transaction.QuarantineManagedRoot();
        AssertThrows<IOException>(() => transaction.RemoveRegistration());
        AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertFalse(File.Exists(fixture.RegistrationContext.DesktopShortcutPath));
        AssertFalse(File.Exists(fixture.RegistrationContext.StartMenuShortcutPath));

        using (var operationLease = await EnterpriseManagedUpdateOperationLease
                   .AcquireRequiredAsync(fixture.Layout).ConfigureAwait(false))
        {
            EnterpriseUninstallRollbackTransaction.RecoverInterrupted(fixture.Layout);
        }

        AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertEqual(
            shellBefore,
            SnapshotRegistration(fixture.Layout, fixture.RegistrationContext));
        fixture.RequireRegistration();
        AssertEqual(dataBefore, fixture.SnapshotLocalData());
        AssertFalse(EnterpriseUninstallRollbackTransaction
            .FindJournalDirectoriesForTest(fixture.Layout).Any());
    }

    private static async Task DurableUninstallCompletesCommittedGapAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "uninstall-committed-gap").ConfigureAwait(false);
        var dataBefore = fixture.SnapshotLocalData();
        var transaction = new EnterpriseUninstallRollbackTransaction(
            fixture.Layout,
            fixture.RegistrationContext,
            crashPointForTest: point =>
            {
                if (point == EnterpriseUninstallCrashPoint.CommittedBeforeCleanup)
                {
                    throw new IOException("simulated commit-before-delete process termination");
                }
            });
        _ = transaction.QuarantineManagedRoot();
        transaction.RemoveRegistration();
        AssertThrows<IOException>(() => transaction.Commit());
        AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertTrue(EnterpriseUninstallRollbackTransaction
            .FindJournalDirectoriesForTest(fixture.Layout).Any());

        using (var operationLease = await EnterpriseManagedUpdateOperationLease
                   .AcquireRequiredAsync(fixture.Layout).ConfigureAwait(false))
        {
            EnterpriseUninstallRollbackTransaction.RecoverInterrupted(fixture.Layout);
        }

        AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertFalse(File.Exists(fixture.RegistrationContext.DesktopShortcutPath));
        AssertFalse(File.Exists(fixture.RegistrationContext.StartMenuShortcutPath));
        using var key = Registry.CurrentUser.OpenSubKey(
            fixture.RegistrationContext.RegistrySubKey);
        AssertTrue(key is null);
        AssertEqual(dataBefore, fixture.SnapshotLocalData());
        AssertFalse(EnterpriseUninstallRollbackTransaction
            .FindJournalDirectoriesForTest(fixture.Layout).Any());
    }

    private static async Task QuarantineDeletionFailureIsIsolatedAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "delete-failure",
            deleteQuarantine: _ => false).ConfigureAwait(false);
        var dataBefore = fixture.SnapshotLocalData();
        var commit = fixture.Operations.UninstallManagedProgramFiles();
        AssertTrue(commit.ActiveInstallationRemoved);
        AssertFalse(commit.QuarantineDeleted);
        AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertEqual(dataBefore, fixture.SnapshotLocalData());
        AssertTrue(EnterpriseUninstallRollbackTransaction
            .FindJournalDirectoriesForTest(fixture.Layout).Any());

        var managedParent = Path.GetDirectoryName(fixture.Layout.ManagedRoot)!;
        var quarantinePath = Directory.EnumerateDirectories(
                managedParent,
                $".{Path.GetFileName(fixture.Layout.ManagedRoot)}.uninstall-quarantine-*",
                SearchOption.TopDirectoryOnly)
            .Single();

        var blocker = Path.Combine(
            quarantinePath,
            Path.GetRelativePath(
                fixture.Layout.ManagedRoot,
                fixture.Layout.BootstrapperReceiptPath));
        using (var stream = new FileStream(
                   blocker,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read))
        {
            using var operationLease = await EnterpriseManagedUpdateOperationLease
                .AcquireRequiredAsync(fixture.Layout).ConfigureAwait(false);
            EnterpriseUninstallRollbackTransaction.RecoverInterrupted(fixture.Layout);
            AssertTrue(Directory.Exists(quarantinePath));
            AssertEqual(dataBefore, fixture.SnapshotLocalData());
        }
        using (var operationLease = await EnterpriseManagedUpdateOperationLease
                   .AcquireRequiredAsync(fixture.Layout).ConfigureAwait(false))
        {
            EnterpriseUninstallRollbackTransaction.RecoverInterrupted(fixture.Layout);
        }
        AssertFalse(Directory.Exists(quarantinePath));
        AssertFalse(EnterpriseUninstallRollbackTransaction
            .FindJournalDirectoriesForTest(fixture.Layout).Any());
        AssertEqual(dataBefore, fixture.SnapshotLocalData());
    }

    private static async Task ConcurrentUpdateLeaseBlocksUninstallAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "concurrent-lease").ConfigureAwait(false);
        var dataBefore = fixture.SnapshotLocalData();
        using var updateLease = await EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(fixture.Layout).ConfigureAwait(false);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        AssertThrows<OperationCanceledException>(() =>
            fixture.Operations.UninstallManagedProgramFiles(cancellation.Token));
        AssertTrue(Directory.Exists(fixture.Layout.ManagedRoot));
        fixture.RequireRegistration();
        AssertEqual(dataBefore, fixture.SnapshotLocalData());
    }

    private static async Task UninstallPreservesUserDataAsync()
    {
        using var fixture = await EnterpriseUninstallFixture.CreateAsync(
            "uninstall").ConfigureAwait(false);
        var dataBefore = fixture.SnapshotLocalData();
        var first = fixture.Operations.UninstallManagedProgramFiles();
        AssertTrue(first.ActiveInstallationRemoved);
        AssertTrue(first.QuarantineDeleted);
        AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertEqual(dataBefore, fixture.SnapshotLocalData());

        var second = fixture.Operations.UninstallManagedProgramFiles();
        AssertTrue(second.ActiveInstallationRemoved);
        AssertTrue(second.QuarantineDeleted);
        AssertFalse(Directory.Exists(fixture.Layout.ManagedRoot));
        AssertEqual(dataBefore, fixture.SnapshotLocalData());
    }

    private static async Task StableBootstrapperReplacementRejectedAsync()
    {
        var fixture = CreateFixture();
        var payload = CreatePayload("launcher-bootstrap", "runtime-bootstrap", "bootstrap");
        await CreateIsolatedInstallationService(fixture.Layout)
            .InstallExternalDevelopmentPayloadAsync(payload, Environment.ProcessPath!)
            .ConfigureAwait(false);
        EnterpriseStableBootstrapperVerifier.RequireTrusted(fixture.Layout);
        File.WriteAllText(fixture.Layout.BootstrapperPath, "replaced-bootstrapper");
        AssertThrows<InvalidDataException>(() =>
            EnterpriseStableBootstrapperVerifier.RequireTrusted(fixture.Layout));
    }

    private static TestFixture CreateFixture()
    {
        var root = NewDirectory("fixture");
        var localAppData = Path.Combine(root, "LocalAppData");
        var userProfile = Path.Combine(root, "Profile");
        Directory.CreateDirectory(localAppData);
        Directory.CreateDirectory(userProfile);
        return new TestFixture(
            root,
            EnterpriseInstallationLayout.CreateDevelopmentE2E(localAppData, userProfile));
    }

    private static TestFixture CreateShortFixture()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "edsh-" + Guid.NewGuid().ToString("N")[..12]);
        var localAppData = Path.Combine(root, "L");
        var userProfile = Path.Combine(root, "P");
        Directory.CreateDirectory(localAppData);
        Directory.CreateDirectory(userProfile);
        return new TestFixture(
            root,
            EnterpriseInstallationLayout.CreateDevelopmentE2E(
                localAppData,
                userProfile));
    }

    private static string CreatePayload(
        string launcherReleaseId,
        string runtimeReleaseId,
        string contentSuffix,
        string? maliciousLauncherEntry = null,
        string layoutProfile = EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile,
        bool executableLauncher = false,
        bool executableBootstrapper = false)
    {
        var payload = NewDirectory("payload");
        File.WriteAllText(
            Path.Combine(payload, EnterpriseDirectoryPayloadSource.DevelopmentConsentFileName),
            EnterpriseDirectoryPayloadSource.DevelopmentConsentText);

        var launcherArchive = Path.Combine(payload, "launcher.zip");
        using (var archive = ZipFile.Open(launcherArchive, ZipArchiveMode.Create))
        {
            if (executableLauncher)
            {
                WriteBinaryEntry(
                    archive,
                    EnterpriseInstallationLayout.LauncherExecutableName,
                    ReadManagedProcessFixtureAppHost());
                WriteManagedProcessFixtureDependencies(
                    archive,
                    directory: string.Empty);
            }
            else
            {
                WriteEntry(
                    archive,
                    EnterpriseInstallationLayout.LauncherExecutableName,
                    $"{launcherReleaseId}-content");
            }
            WriteEntry(
                archive,
                EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
                $"{launcherReleaseId}-versioned-bootstrapper");
            WriteEntry(
                archive,
                EnterpriseInstallationLayout.MaintenanceExecutableName,
                $"{launcherReleaseId}-maintenance");
            WriteEntry(
                archive,
                EnterpriseInstallationLayout.BuildProfileMarkerFileName,
                JsonSerializer.Serialize(new
                {
                    schemaVersion = 1,
                    layoutProfile,
                }));
            if (maliciousLauncherEntry is not null)
            {
                WriteEntry(archive, maliciousLauncherEntry, "escaped");
            }
        }

        var runtimeArchive = Path.Combine(payload, "runtime.zip");
        using (var archive = ZipFile.Open(runtimeArchive, ZipArchiveMode.Create))
        {
            var nodeContent = $"node-{contentSuffix}";
            var entryContent = $"entry-{contentSuffix}";
            WriteEntry(archive, "node.exe", nodeContent);
            WriteEntry(
                archive,
                "node_modules/@deepseek-ai/dsh/lib/bin.js",
                entryContent);
            WriteEntry(
                archive,
                EnterpriseRuntimeFileManifest.FileName,
                $"{ComputeContentSha256(nodeContent)}  node.exe\n" +
                $"{ComputeContentSha256(entryContent)}  node_modules/@deepseek-ai/dsh/lib/bin.js\n");
        }

        var bootstrapper = Path.Combine(
            payload,
            EnterpriseInstallationLayout.BootstrapperExecutableName);
        if (executableBootstrapper)
        {
            File.WriteAllBytes(bootstrapper, ReadManagedProcessFixtureAppHost());
        }
        else
        {
            File.WriteAllText(bootstrapper, $"bootstrapper-{contentSuffix}");
        }
        var manifest = new EnterpriseInstallManifest
        {
            SchemaVersion = 1,
            LayoutProfile = layoutProfile,
            LauncherReleaseId = launcherReleaseId,
            RuntimeReleaseId = runtimeReleaseId,
            LauncherArchive = Path.GetFileName(launcherArchive),
            LauncherArchiveSizeBytes = new FileInfo(launcherArchive).Length,
            LauncherArchiveSha256 = ComputeSha256(launcherArchive),
            RuntimeArchive = Path.GetFileName(runtimeArchive),
            RuntimeArchiveSizeBytes = new FileInfo(runtimeArchive).Length,
            RuntimeArchiveSha256 = ComputeSha256(runtimeArchive),
            BootstrapperFile = Path.GetFileName(bootstrapper),
            BootstrapperSizeBytes = new FileInfo(bootstrapper).Length,
            BootstrapperSha256 = ComputeSha256(bootstrapper),
            PublishedAtUtc = DateTimeOffset.UtcNow,
        };
        File.WriteAllText(
            Path.Combine(payload, EnterpriseEmbeddedPayloadSource.ManifestFileName),
            JsonSerializer.Serialize(
                manifest,
                new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }));
        return payload;
    }

    private static string CreatePluginPolicyArchive(
        string fileName,
        string actualContent,
        string? declaredContent = null,
        string policyEntryName = "plugin-policy.json")
    {
        declaredContent ??= actualContent;
        var root = NewDirectory("plugin-policy");
        var archivePath = Path.Combine(root, fileName);
        var declaredBytes = Encoding.UTF8.GetBytes(declaredContent);
        var policyBytes = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                schemaVersion = 1,
                policyId = "11111111-2222-4333-8444-555555555555",
                generation = 1,
                skillsRoot = "skills",
                skillPacks = new[]
                {
                    new
                    {
                        skillId = "mail-manager",
                        version = "1.0.0",
                        root = "skills/mail-manager",
                        files = new[]
                        {
                            new
                            {
                                path = "skills/mail-manager/SKILL.md",
                                sha256 = Convert.ToHexStringLower(SHA256.HashData(declaredBytes)),
                                sizeBytes = declaredBytes.LongLength,
                            },
                        },
                    },
                },
                compatibility = new
                {
                    launcherReleaseIds = new[] { "launcher-test" },
                    runtimeReleaseIds = new[] { "runtime-test" },
                },
                revoked = false,
                critical = true,
            },
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create);
        var policyEntry = archive.CreateEntry(policyEntryName, CompressionLevel.NoCompression);
        using (var output = policyEntry.Open())
        {
            output.Write(policyBytes);
        }
        WriteEntry(archive, "skills/mail-manager/SKILL.md", actualContent);
        return archivePath;
    }

    private static void WriteEntry(ZipArchive archive, string path, string content)
    {
        var entry = archive.CreateEntry(path, CompressionLevel.NoCompression);
        using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        writer.Write(content);
    }

    private static void WriteBinaryEntry(
        ZipArchive archive,
        string path,
        byte[] contents)
    {
        var entry = archive.CreateEntry(path, CompressionLevel.NoCompression);
        using var output = entry.Open();
        output.Write(contents);
    }

    private static Process StartEndlessCommand(string executable)
    {
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = EnterpriseMaintenanceIntegrity.ToExtendedWindowsPath(executable),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            ArgumentList = { ManagedProcessFixtureArgument },
        }) ?? throw new InvalidOperationException(
            "Unable to start managed process fixture.");
        RequireManagedProcessFixtureReady(process);
        return process;
    }

    private static byte[] ReadManagedProcessFixtureAppHost() => File.ReadAllBytes(
        GetManagedProcessFixtureAppHostPath());

    private static string GetManagedProcessFixtureAppHostPath()
    {
        var entryAssemblyPath = Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException(
                "InstallationTests entry assembly is unavailable for the managed process fixture.");
        var appHostPath = Path.ChangeExtension(entryAssemblyPath, ".exe");
        if (!File.Exists(appHostPath))
        {
            throw new InvalidOperationException(
                "InstallationTests apphost is unavailable for the managed process fixture.");
        }
        return appHostPath;
    }

    private static void CopyManagedProcessFixture(string executable)
    {
        var directory = Path.GetDirectoryName(executable)
            ?? throw new InvalidOperationException("Managed process fixture has no parent directory.");
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(executable, ReadManagedProcessFixtureAppHost());
        CopyManagedProcessFixtureDependencies(directory);
    }

    private static void CopyManagedProcessFixtureDependencies(string directory)
    {
        foreach (var source in EnumerateManagedProcessFixtureDependencies())
        {
            File.Copy(source, Path.Combine(directory, Path.GetFileName(source)), overwrite: true);
        }
    }

    private static void WriteManagedProcessFixtureDependencies(
        ZipArchive archive,
        string directory)
    {
        foreach (var source in EnumerateManagedProcessFixtureDependencies())
        {
            var entryPath = string.IsNullOrEmpty(directory)
                ? Path.GetFileName(source)
                : $"{directory}/{Path.GetFileName(source)}";
            WriteBinaryEntry(archive, entryPath, File.ReadAllBytes(source));
        }
    }

    private static IEnumerable<string> EnumerateManagedProcessFixtureDependencies()
    {
        var entryAssemblyPath = Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException(
                "InstallationTests entry assembly is unavailable for the managed process fixture.");
        var baseDirectory = Path.GetDirectoryName(entryAssemblyPath)
            ?? throw new InvalidOperationException(
                "InstallationTests output directory is unavailable for the managed process fixture.");
        var assemblyName = Path.GetFileNameWithoutExtension(entryAssemblyPath);
        return Directory.EnumerateFiles(baseDirectory, "*.dll")
            .Append(Path.Combine(baseDirectory, $"{assemblyName}.deps.json"))
            .Append(Path.Combine(baseDirectory, $"{assemblyName}.runtimeconfig.json"));
    }

    private static void RequireManagedProcessFixtureReady(Process process)
    {
        try
        {
        var readyLine = process.StandardOutput.ReadLineAsync();
        if (!readyLine.Wait(TimeSpan.FromSeconds(5)))
        {
            throw new TimeoutException(
                "Managed process fixture did not signal readiness within five seconds.");
        }
        AssertEqual(ManagedProcessFixtureReady, readyLine.Result);
        AssertFalse(process.HasExited);
        }
        catch
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    if (!process.WaitForExit(5_000))
                    {
                        throw new TimeoutException("Managed fixture cleanup did not finish.");
                    }
                }
            }
            finally
            {
                process.Dispose();
            }
            throw;
        }
    }

    private static void StopProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
            }
        }
        catch (InvalidOperationException)
        {
            // Cleanup is already complete when the owning containment wrapper
            // has detached or disposed the Process instance.
        }
    }

    private static bool WaitForProcessExit(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.WaitForExit(5_000);
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static string SnapshotRegistration(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext context)
    {
        var snapshot = EnterpriseWindowsRegistration.CaptureRollbackSnapshot(
            layout,
            context);
        return string.Join(
            "\n",
            new[]
            {
                snapshot.RegistrySubKey,
                snapshot.RegistryExisted.ToString(),
                Convert.ToHexString(snapshot.DesktopShortcutBytes ?? []),
                Convert.ToHexString(snapshot.StartMenuShortcutBytes ?? []),
            }.Concat(snapshot.RegistryValues.Select(value =>
                value.Name
                + ":"
                + value.Kind
                + ":"
                + RegistryValueText(value.Value))));
    }

    private static string RegistryValueText(object value) => value switch
    {
        byte[] bytes => Convert.ToHexString(bytes),
        string[] strings => string.Join("\u001f", strings),
        _ => Convert.ToString(
                value,
                System.Globalization.CultureInfo.InvariantCulture)
            ?? string.Empty,
    };

    private static string SnapshotLocalData(EnterpriseInstallationLayout layout) =>
        string.Join(
            "\n",
            new[] { layout.HarnessHome, layout.HarnessRecoveryRoot }
                .SelectMany(root => Directory.Exists(root)
                    ? Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                        .Select(path =>
                            Path.GetRelativePath(layout.UserProfileRoot, path)
                                .Replace('\\', '/')
                            + ":"
                            + ComputeSha256(path))
                    : [])
                .OrderBy(entry => entry, StringComparer.Ordinal));

    private static EnterpriseWindowsRegistrationContext CreateIsolatedRegistrationContext(
        string root,
        string scope) => new(
        @"Software\Ensou\CodexTests\EnterpriseInstallJournal\"
            + scope
            + "-"
            + Guid.NewGuid().ToString("N"),
        Path.Combine(root, "shell", scope, "desktop", "Enterprise Launcher.lnk"),
        Path.Combine(
            root,
            "shell",
            scope,
            "programs",
            "Ensou",
            "Enterprise Launcher.lnk"));

    private static string[] FindInstallJournals(EnterpriseInstallationLayout layout)
    {
        var parent = Path.GetDirectoryName(layout.ManagedRoot)!;
        return Directory.Exists(parent)
            ? Directory.EnumerateDirectories(
                    parent,
                    $".{Path.GetFileName(layout.ManagedRoot)}.install-rollback-*",
                    SearchOption.TopDirectoryOnly)
                .Order(StringComparer.Ordinal)
                .ToArray()
            : [];
    }

    private static void AssertDurableStateRejected(
        Func<byte[], byte[]> transform,
        Type expectedException)
    {
        var fixture = CreateFixture();
        _ = new EnterpriseInstallRollbackTransaction(fixture.Layout);
        var journal = FindInstallJournals(fixture.Layout).Single();
        EnterpriseInstallRollbackTransaction.RewriteStatePlaintextForTest(
            fixture.Layout,
            journal,
            transform);
        try
        {
            EnterpriseInstallRollbackTransaction.RecoverInterrupted(fixture.Layout);
        }
        catch (Exception exception) when (expectedException.IsInstanceOfType(exception))
        {
            return;
        }
        throw new InvalidOperationException(
            $"Expected durable state rejection {expectedException.Name}.");
    }

    private static string ComputeContentSha256(string content) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    internal static bool TryCreateDirectoryJunction(string junctionPath, string targetPath)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
            Arguments = $"/d /c mklink /J \"{junctionPath}\" \"{targetPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        if (process is null)
        {
            return false;
        }

        process.WaitForExit();
        return process.ExitCode == 0;
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateHardLinkW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    private static string NewDirectory(string prefix)
    {
        var path = Path.Combine(TempRoot, $"{prefix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private static EnterpriseInstallationService CreateIsolatedInstallationService(
        EnterpriseInstallationLayout layout,
        Action? beforeLegacySqliteCommitForTest = null) =>
        new(
            layout,
            beforeLegacySqliteCommitForTest,
            IgnoreHostHarnessWritersForIsolatedTest);

    private static void AssertTrue(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Expected condition to be true.");
        }
    }

    private static void AssertFalse(bool condition) => AssertTrue(!condition);

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', actual '{actual}'.");
        }
    }

    private static void AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected exception {typeof(TException).Name}.");
    }

    private static TException AssertThrowsAndReturn<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }
        throw new InvalidOperationException($"Expected exception {typeof(TException).Name}.");
    }

    private static void AssertMutationDenied(Action action)
    {
        try
        {
            action();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return;
        }

        throw new InvalidOperationException("Expected the locked file mutation to be denied.");
    }

    private static void AssertThrowsContaining<TException>(Action action, string expectedMessage)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            if (exception.Message.Contains(expectedMessage, StringComparison.Ordinal))
            {
                return;
            }

            throw new InvalidOperationException(
                $"Expected exception message containing '{expectedMessage}', actual '{exception.Message}'.",
                exception);
        }

        throw new InvalidOperationException($"Expected exception {typeof(TException).Name}.");
    }

    private static async Task AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected exception {typeof(TException).Name}.");
    }

    private static async Task<TException> AssertThrowsAndReturnAsync<TException>(
        Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException exception)
        {
            return exception;
        }
        throw new InvalidOperationException($"Expected exception {typeof(TException).Name}.");
    }

    private sealed class EnterpriseUninstallFixture : IDisposable
    {
        private EnterpriseUninstallFixture(
            TestFixture fixture,
            string releaseSetId,
            EnterpriseWindowsRegistrationContext registrationContext,
            EnterpriseMaintenanceOperations operations,
            bool ownsRoot)
        {
            Root = fixture.Root;
            Layout = fixture.Layout;
            ReleaseSetId = releaseSetId;
            RegistrationContext = registrationContext;
            Operations = operations;
            OwnsRoot = ownsRoot;
            var active = EnterpriseMaintenanceIntegrity.RequireActiveMaintenance(Layout);
            MaintenancePath = active.MaintenancePath;
            LauncherPath = Path.Combine(
                active.ClientBundleDirectory,
                EnterpriseInstallationLayout.LauncherExecutableName);
        }

        public string Root { get; }

        public EnterpriseInstallationLayout Layout { get; }

        public string ReleaseSetId { get; }

        public EnterpriseWindowsRegistrationContext RegistrationContext { get; }

        public EnterpriseMaintenanceOperations Operations { get; }

        public string MaintenancePath { get; }

        public string LauncherPath { get; }

        private bool OwnsRoot { get; }

        public static async Task<EnterpriseUninstallFixture> CreateAsync(
            string scope,
            bool executableLauncher = false,
            bool executableBootstrapper = false,
            bool shortPaths = false,
            Action<EnterpriseWindowsRegistrationRemovalStage>? removalObserver = null,
            Func<EnterpriseManagedProgramQuarantine, bool>? deleteQuarantine = null)
        {
            var fixture = shortPaths ? CreateShortFixture() : CreateFixture();
            var payload = CreatePayload(
                $"launcher-{scope}",
                $"runtime-{scope}",
                scope,
                executableLauncher: executableLauncher,
                executableBootstrapper: executableBootstrapper);
            await CreateIsolatedInstallationService(fixture.Layout)
                .InstallExternalDevelopmentPayloadAsync(payload, Environment.ProcessPath!)
                .ConfigureAwait(false);
            if (executableBootstrapper)
            {
                CopyManagedProcessFixtureDependencies(
                    Path.GetDirectoryName(fixture.Layout.BootstrapperPath)
                    ?? throw new InvalidOperationException(
                        "Bootstrapper fixture has no parent directory."));
            }

            Directory.CreateDirectory(fixture.Layout.HarnessHome);
            Directory.CreateDirectory(Path.Combine(
                fixture.Layout.HarnessHome,
                "workspaces"));
            File.WriteAllText(
                Path.Combine(fixture.Layout.HarnessHome, "conversation-history.json"),
                "keep-history");
            File.WriteAllText(
                Path.Combine(
                    fixture.Layout.HarnessHome,
                    "workspaces",
                    "customer-project.txt"),
                "keep-workspace");
            Directory.CreateDirectory(fixture.Layout.HarnessRecoveryRoot);
            File.WriteAllText(
                Path.Combine(fixture.Layout.HarnessRecoveryRoot, "recovery-sentinel.json"),
                "keep-recovery");

            var context = new EnterpriseWindowsRegistrationContext(
                @"Software\Ensou\CodexTests\EnterpriseMaintenance\"
                    + Guid.NewGuid().ToString("N"),
                Path.Combine(
                    fixture.Root,
                    "shell",
                    "desktop",
                    "Enterprise Launcher.lnk"),
                Path.Combine(
                    fixture.Root,
                    "shell",
                    "programs",
                    "Ensou",
                    "Enterprise Launcher.lnk"),
                removalObserver);
            var current = new EnterpriseReleaseSetPointerStore(fixture.Layout)
                .ReadRequired().Current;
            _ = EnterpriseWindowsRegistration.Install(
                fixture.Layout,
                current.ReleaseSetId,
                developmentUnsignedPayload: true,
                context);
            var operations = new EnterpriseMaintenanceOperations(
                fixture.Layout,
                context,
                deleteQuarantine);
            return new EnterpriseUninstallFixture(
                fixture,
                current.ReleaseSetId,
                context,
                operations,
                shortPaths);
        }

        public void RequireRegistration() =>
            _ = EnterpriseWindowsRegistration.ReadAndValidate(
                Layout,
                ReleaseSetId,
                developmentUnsignedPayload: true,
                RegistrationContext);

        public string SnapshotLocalData() => string.Join(
            "\n",
            new[] { Layout.HarnessHome, Layout.HarnessRecoveryRoot }
                .SelectMany(root => Directory.Exists(root)
                    ? Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                        .Select(path =>
                            Path.GetRelativePath(Layout.UserProfileRoot, path)
                                .Replace('\\', '/')
                            + ":"
                            + ComputeSha256(path))
                    : [])
                .OrderBy(entry => entry, StringComparer.Ordinal));

        public void Dispose()
        {
            Registry.CurrentUser.DeleteSubKeyTree(
                RegistrationContext.RegistrySubKey,
                throwOnMissingSubKey: false);
            if (OwnsRoot && Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed record TestFixture(string Root, EnterpriseInstallationLayout Layout);
}
