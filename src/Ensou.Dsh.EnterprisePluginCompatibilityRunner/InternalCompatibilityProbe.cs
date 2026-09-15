using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;
using Ensou.Dsh.Host;

namespace Ensou.Dsh.EnterprisePluginCompatibilityRunner;

internal static class InternalCompatibilityProbe
{
    internal const string CompatibilityTestFileName = "compatibility-test.mjs";
    private const int MaximumArchiveEntries = 250_000;
    private const long MaximumExpandedArchiveBytes = 8L * 1024 * 1024 * 1024;
    private const int MaximumPluginResultBytes = 1024 * 1024;
    private static readonly TimeSpan MaximumRunDuration = TimeSpan.FromHours(4);

    public static byte[] SerializeRequest(
        CompatibilityProbeContext context,
        string workspace,
        string nonce,
        CompatibilityRunnerIdentity runnerIdentity)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString(
                "requestType",
                "ensou-dsh-managed-plugin-compatibility-probe-request");
            writer.WriteString("nonce", nonce);
            writer.WriteStartObject("runner");
            writer.WriteString("fileName", runnerIdentity.FileName);
            writer.WriteNumber("sizeBytes", runnerIdentity.SizeBytes);
            writer.WriteString("sha256", runnerIdentity.Sha256);
            writer.WriteEndObject();
            writer.WriteString("testRunId", context.TestRunId);
            writer.WriteString("launcherReleaseId", context.LauncherReleaseId);
            WriteInput(writer, "launcherArchive", context.LauncherArchive);
            writer.WriteString("runtimeReleaseId", context.RuntimeReleaseId);
            WriteInput(writer, "runtimeArchive", context.RuntimeArchive);
            WriteInput(writer, "runtimeSourceMetadata", context.RuntimeMetadata);
            WriteInput(
                writer,
                "runtimeOrganizationAdmissionReceipt",
                context.RuntimeAdmissionReceipt);
            WriteInput(writer, "pluginPolicyArchive", context.PluginArchive);
            WriteInput(writer, "pluginPolicyMetadata", context.PluginMetadata);
            WriteInput(
                writer,
                "pluginPolicyExecutionAdmissionReceipt",
                context.PluginExecutionAdmissionReceipt);
            writer.WriteStartObject("policy");
            writer.WriteString("policyId", context.Policy.PolicyId);
            writer.WriteNumber("generation", context.Policy.Generation);
            writer.WriteString("rawPolicySha256", context.Policy.PolicySha256);
            writer.WriteEndObject();
            writer.WriteString("workspace", workspace);
            writer.WriteStartArray("requiredPlugins");
            foreach (var skill in context.Policy.SkillPacks)
            {
                writer.WriteStartObject();
                writer.WriteString("skillId", skill.SkillId);
                writer.WriteString("version", skill.Version);
                writer.WriteString("root", skill.Root);
                writer.WriteString("declaredTreeSha256", skill.DeclaredTreeSha256);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    public static void Run(
        InternalCompatibilityProbeOptions options,
        CompatibilityRunnerIdentity runnerIdentity,
        PublisherRuntimeAdmissionTrust runtimeTrust,
        PublisherPluginAdmissionTrust pluginTrust,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(runnerIdentity);
        ArgumentNullException.ThrowIfNull(runtimeTrust);
        ArgumentNullException.ThrowIfNull(pluginTrust);
        ArgumentNullException.ThrowIfNull(timeProvider);
        runtimeTrust.Validate();
        pluginTrust.Validate();

        ValidatePrivatePaths(options);
        using var requestLock = PublisherSafeFile.OpenLockedRead(options.RequestPath);
        if (requestLock.Length is <= 0 or > 4 * 1024 * 1024)
        {
            throw new InvalidDataException("Internal compatibility request size is invalid.");
        }
        var requestBytes = new byte[checked((int)requestLock.Length)];
        requestLock.ReadExactly(requestBytes);
        var request = PublisherRuntimeAdmissionJson.Parse<InternalProbeRequest>(
            requestBytes,
            "Internal compatibility probe request");
        ValidateRequest(request, options, runnerIdentity);

        using var inputs = InternalProbeInputs.Capture(request);
        inputs.Validate();
        inputs.CreatePrivateSnapshots(request.Workspace);
        RejectCandidateProvidedCompatibilityReporter(inputs.RuntimeArchive.SnapshotPath);
        var source = PublisherRuntimeAdmissionValidator.ValidateFiles(
            inputs.RuntimeArchive.SnapshotPath,
            request.RuntimeReleaseId,
            inputs.RuntimeSourceMetadata.SnapshotPath,
            inputs.RuntimeOrganizationAdmissionReceipt.SnapshotPath,
            runtimeTrust);
        if (!string.Equals(
                source.SourceTag,
                EnterprisePluginCompatibilityRunner.HarnessSourceTag,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Internal probe runtime source metadata is not the fixed Harness source tag.");
        }
        var policyInspection = EnterprisePluginPolicyArchiveValidator.Validate(
            inputs.PluginPolicyArchive.SnapshotPath,
            request.LauncherReleaseId,
            request.RuntimeReleaseId);
        _ = PublisherPluginPolicyMetadata.Validate(
            inputs.PluginPolicyMetadata.SnapshotPath,
            inputs.PluginPolicyArchive.SnapshotPath,
            policyInspection);
        PluginExecutionAdmissionReceipt.ParseAndVerify(
            inputs.PluginPolicyExecutionAdmissionReceipt.SnapshotPath,
            pluginTrust,
            policyInspection,
            request.PluginPolicyArchive.Sha256,
            request.PluginPolicyArchive.SizeBytes,
            request.PluginPolicyMetadata.Sha256,
            request.PluginPolicyMetadata.SizeBytes,
            WholeSecond(timeProvider.GetUtcNow()),
            request.LauncherReleaseId,
            request.RuntimeReleaseId);
        ValidatePolicyBinding(request, policyInspection);

        var started = WholeSecond(timeProvider.GetUtcNow());
        var deadline = started + MaximumRunDuration;
        var launcherRoot = Path.Combine(request.Workspace, "launcher");
        var runtimeRoot = Path.Combine(request.Workspace, "runtime");
        var pluginRoot = Path.Combine(request.Workspace, "plugin");
        Directory.CreateDirectory(launcherRoot);
        Directory.CreateDirectory(runtimeRoot);
        Directory.CreateDirectory(pluginRoot);
        ExtractArchive(inputs.LauncherArchive.SnapshotPath, launcherRoot);
        ExtractArchive(inputs.RuntimeArchive.SnapshotPath, runtimeRoot);
        ExtractArchive(inputs.PluginPolicyArchive.SnapshotPath, pluginRoot);

        using var launcherTree = LockedPrivateTree.Capture(launcherRoot);
        using var runtimeTree = LockedPrivateTree.Capture(runtimeRoot);
        using var pluginTree = LockedPrivateTree.Capture(pluginRoot);

        _ = EnterpriseRuntimeFileManifest.ValidateCompleteTree(runtimeRoot);
        var activePolicy = EnterprisePluginPolicyInstallation.ValidateInstalled(
            pluginRoot,
            request.Workspace,
            "compatibility-policy-v1",
            inputs.PluginPolicyArchive.Sha256,
            request.LauncherReleaseId,
            request.RuntimeReleaseId,
            requireReceipt: false);
        RunLauncherSelfCheck(launcherRoot, deadline);
        RunManagedRuntimeHealth(runtimeRoot, activePolicy, request.Workspace, deadline);
        var pluginObservations = RunPluginCommands(
            request,
            runtimeRoot,
            activePolicy,
            deadline);
        launcherTree.VerifyUnchanged();
        runtimeTree.VerifyUnchanged();
        pluginTree.VerifyUnchanged();
        _ = EnterpriseRuntimeFileManifest.ValidateCompleteTree(runtimeRoot);
        _ = EnterprisePluginPolicyInstallation.ValidateInstalled(
            pluginRoot,
            request.Workspace,
            "compatibility-policy-v1",
            inputs.PluginPolicyArchive.Sha256,
            request.LauncherReleaseId,
            request.RuntimeReleaseId,
            requireReceipt: false);
        var preservation = RunRollbackPreservationCheck(request.Workspace);
        if (!preservation.Rollback
            || !preservation.History
            || !preservation.Workspace)
        {
            throw new InvalidDataException(
                "Product Harness-home rollback did not exactly restore history and workspace bytes.");
        }
        inputs.VerifyUnchanged();

        var completed = WholeSecond(timeProvider.GetUtcNow());
        if (completed < started || completed > deadline)
        {
            throw new TimeoutException(
                "Internal compatibility probe exceeded its bounded production duration.");
        }
        var evidence = SerializeEvidence(
            request,
            runnerIdentity,
            started,
            completed,
            pluginObservations);
        WriteNewVerified(options.OutputPath, evidence);
        inputs.VerifyUnchanged();
    }

    private static void ValidatePrivatePaths(InternalCompatibilityProbeOptions options)
    {
        var request = Path.GetFullPath(options.RequestPath);
        var output = Path.GetFullPath(options.OutputPath);
        var root = Path.GetDirectoryName(request)
            ?? throw new InvalidDataException("Internal request has no private parent.");
        if (!string.Equals(Path.GetFileName(request), "request.v1.json", StringComparison.Ordinal)
            || !string.Equals(Path.GetFileName(output), "evidence.v1.json", StringComparison.Ordinal)
            || !string.Equals(Path.GetDirectoryName(output), root, StringComparison.OrdinalIgnoreCase)
            || !Path.GetFileName(root).StartsWith(
                "ensou-dsh-enterprise-plugin-compatibility-",
                StringComparison.Ordinal)
            || !Directory.Exists(root)
            || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0
            || File.Exists(output)
            || Directory.Exists(output))
        {
            throw new InvalidDataException(
                "Internal probe request/output escaped the exact private workspace contract.");
        }
        PublisherPathGuard.RequireSafeExistingFile(request);
        PublisherPathGuard.RequireSafeDestination(output);
    }

    private static void ValidateRequest(
        InternalProbeRequest request,
        InternalCompatibilityProbeOptions options,
        CompatibilityRunnerIdentity runnerIdentity)
    {
        if (request.SchemaVersion != 1
            || !string.Equals(
                request.RequestType,
                "ensou-dsh-managed-plugin-compatibility-probe-request",
                StringComparison.Ordinal)
            || !string.Equals(request.Nonce, options.Nonce, StringComparison.Ordinal)
            || request.Nonce.Length != 43
            || request.Nonce.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '_')
            || request.Runner is null
            || !string.Equals(
                request.Runner.FileName,
                runnerIdentity.FileName,
                StringComparison.Ordinal)
            || request.Runner.SizeBytes != runnerIdentity.SizeBytes
            || !string.Equals(
                request.Runner.Sha256,
                runnerIdentity.Sha256,
                StringComparison.Ordinal)
            || !Guid.TryParseExact(request.TestRunId, "D", out _)
            || request.RequiredPlugins is null
            || request.Policy is null)
        {
            throw new InvalidDataException(
                "Internal compatibility request identity, nonce, or runner binding is invalid.");
        }
        var expectedWorkspace = Path.Combine(
            Path.GetDirectoryName(options.RequestPath)!,
            "run");
        if (!string.Equals(
                Path.GetFullPath(request.Workspace),
                Path.GetFullPath(expectedWorkspace),
                StringComparison.OrdinalIgnoreCase)
            || !Directory.Exists(request.Workspace)
            || Directory.EnumerateFileSystemEntries(request.Workspace).Any())
        {
            throw new InvalidDataException(
                "Internal compatibility run workspace is not the exact new private directory.");
        }
    }

    private static void ValidatePolicyBinding(
        InternalProbeRequest request,
        EnterprisePluginPolicyArchiveInspection inspection)
    {
        if (!string.Equals(request.Policy.PolicyId, inspection.PolicyId, StringComparison.Ordinal)
            || request.Policy.Generation != inspection.Generation
            || !string.Equals(
                request.Policy.RawPolicySha256,
                inspection.PolicySha256,
                StringComparison.Ordinal)
            || request.RequiredPlugins.Count != inspection.SkillPacks.Count)
        {
            throw new InvalidDataException(
                "Internal compatibility request policy identity drifted.");
        }
        var requested = request.RequiredPlugins
            .OrderBy(plugin => plugin.SkillId, StringComparer.Ordinal)
            .ToArray();
        for (var index = 0; index < inspection.SkillPacks.Count; index++)
        {
            var expected = inspection.SkillPacks[index];
            var actual = requested[index];
            if (!string.Equals(actual.SkillId, expected.SkillId, StringComparison.Ordinal)
                || !string.Equals(actual.Version, expected.Version, StringComparison.Ordinal)
                || !string.Equals(actual.Root, expected.Root, StringComparison.Ordinal)
                || !string.Equals(
                    actual.DeclaredTreeSha256,
                    expected.DeclaredTreeSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Internal compatibility request omitted or drifted skill {expected.SkillId}.");
            }
        }
    }

    private static void RunLauncherSelfCheck(string launcherRoot, DateTimeOffset deadline)
    {
        var launcher = Path.Combine(
            launcherRoot,
            EnterpriseInstallationLayout.LauncherExecutableName);
        RunProcess(
            launcher,
            ["--self-check"],
            launcherRoot,
            new Dictionary<string, string>(StringComparer.Ordinal),
            deadline,
            "Launcher binary self-check");
    }

    private static void RunManagedRuntimeHealth(
        string runtimeRoot,
        EnterpriseActivePluginPolicy policy,
        string workspace,
        DateTimeOffset deadline)
    {
        var dataRoot = Path.Combine(workspace, "dsh-home");
        var workspaces = Path.Combine(dataRoot, "workspaces");
        var logs = Path.Combine(workspace, "logs");
        Directory.CreateDirectory(dataRoot);
        Directory.CreateDirectory(workspaces);
        Directory.CreateDirectory(logs);
        var dshPort = GetUnusedLoopbackPort();
        var providerPort = GetUnusedLoopbackPort();
        var providerUrl = $"http://127.0.0.1:{providerPort.ToString(CultureInfo.InvariantCulture)}/v1";
        var apiKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        var runtimeOptions = DshRuntimeOptions.CreateEnterpriseManaged(
            runtimeRoot,
            dataRoot,
            logs,
            workspaces,
            dshPort,
            policy.PolicyDirectory,
            policy.SkillsRoot,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["DEEPSEEK_BASE_URL"] = providerUrl,
                ["DEEPSEEK_SEARCH_BASE_URL"] = providerUrl,
                ["DEEPSEEK_API_KEY"] = apiKey,
            });
        runtimeOptions.Validate();
        using var timeout = new CancellationTokenSource(Remaining(deadline));
        RunManagedRuntimeHealthAsync(runtimeOptions, timeout.Token)
            .GetAwaiter()
            .GetResult();
    }

    private static async Task RunManagedRuntimeHealthAsync(
        DshRuntimeOptions options,
        CancellationToken cancellationToken)
    {
        await using var host = new DshHostService(
            options,
            validateBeforeProcessStart: () =>
                _ = EnterpriseRuntimeFileManifest.ValidateCompleteTree(
                    options.RuntimeDirectory));
        var launched = await host.EnsureStartedAsync(cancellationToken).ConfigureAwait(false);
        if (launched.ProcessId is null
            || !host.OwnsRunningProcess
            || !await host.CompleteCandidateInstallHealthAsync(
                    launched.ProcessId.Value,
                    cancellationToken)
                .ConfigureAwait(false))
        {
            throw new InvalidDataException(
                "Admitted DSH runtime failed the managed startup/session.list health contract.");
        }
    }

    private static IReadOnlyList<CompatibilityPluginObservation> RunPluginCommands(
        InternalProbeRequest request,
        string runtimeRoot,
        EnterpriseActivePluginPolicy activePolicy,
        DateTimeOffset deadline)
    {
        var nodePath = Path.Combine(runtimeRoot, "node.exe");
        using var nodeLock = PublisherSafeFile.OpenLockedRead(nodePath);
        var nodeIdentity = PublisherSafeFile.GetIdentity(nodeLock);
        var nodeSha = PublisherSafeFile.HashAndRewind(nodeLock);
        var observations = new List<CompatibilityPluginObservation>();
        foreach (var plugin in request.RequiredPlugins.OrderBy(
                     item => item.SkillId,
                     StringComparer.Ordinal))
        {
            var skillRoot = ResolveRelative(activePolicy.PolicyDirectory, plugin.Root);
            var testPath = Path.Combine(skillRoot, CompatibilityTestFileName);
            if (!File.Exists(testPath))
            {
                throw new InvalidDataException(
                    $"Managed skill {plugin.SkillId} is missing required external gate {CompatibilityTestFileName}.");
            }
            using var testLock = PublisherSafeFile.OpenLockedRead(testPath);
            var runRoot = Path.Combine(
                request.Workspace,
                "plugin-runs",
                plugin.SkillId);
            Directory.CreateDirectory(runRoot);
            var requestPath = Path.Combine(runRoot, "request.v1.json");
            var outputPath = Path.Combine(runRoot, "result.v1.json");
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            WriteNewVerified(
                requestPath,
                SerializePluginRequest(
                    request,
                    plugin,
                    nonce,
                    activePolicy.SkillsRoot));
            RunProcess(
                nodePath,
                [
                    testPath,
                    "--ensou-managed-compatibility-v1",
                    "--request", requestPath,
                    "--output", outputPath,
                ],
                runRoot,
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [DshRuntimeOptions.EnterpriseManagedSkillsRootEnvironmentVariable] =
                        activePolicy.SkillsRoot,
                    ["DSH_ENTERPRISE_MANAGED_BOOT"] =
                        DshRuntimeOptions.EnterpriseManagedBootMarker,
                    ["DSH_TELEMETRY_DISABLED"] = "1",
                    ["NO_PROXY"] = DshRuntimeOptions.LoopbackNoProxy,
                },
                deadline,
                $"Managed skill compatibility command {plugin.SkillId}");
            using var resultLock = PublisherSafeFile.OpenLockedRead(outputPath);
            if (resultLock.Length is <= 0 or > MaximumPluginResultBytes)
            {
                throw new InvalidDataException(
                    $"Managed skill {plugin.SkillId} compatibility result size is invalid.");
            }
            var bytes = new byte[checked((int)resultLock.Length)];
            resultLock.ReadExactly(bytes);
            var result = PublisherRuntimeAdmissionJson.Parse<PluginCompatibilityResult>(
                bytes,
                $"Managed skill {plugin.SkillId} compatibility result");
            if (result.SchemaVersion != 1
                || !string.Equals(
                    result.ResultType,
                    "ensou-dsh-managed-skill-compatibility-result",
                    StringComparison.Ordinal)
                || !string.Equals(result.Result, "PASS", StringComparison.Ordinal)
                || !string.Equals(result.Nonce, nonce, StringComparison.Ordinal)
                || !string.Equals(result.SkillId, plugin.SkillId, StringComparison.Ordinal)
                || !string.Equals(result.Version, plugin.Version, StringComparison.Ordinal)
                || !string.Equals(result.Root, plugin.Root, StringComparison.Ordinal)
                || !string.Equals(
                    result.DeclaredTreeSha256,
                    plugin.DeclaredTreeSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    result.RuntimeArchiveSha256,
                    request.RuntimeArchive.Sha256,
                    StringComparison.Ordinal)
                || !string.Equals(result.PolicyId, request.Policy.PolicyId, StringComparison.Ordinal)
                || result.PolicyGeneration != request.Policy.Generation
                || !string.Equals(
                    result.ManagedSkillsRoot,
                    activePolicy.SkillsRoot,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"Managed skill {plugin.SkillId} compatibility command was incomplete or drifted.");
            }
            PublisherSafeFile.RequireExpectedPathAndRegularFile(testLock, testPath);
            observations.Add(new CompatibilityPluginObservation
            {
                SkillId = plugin.SkillId,
                Version = plugin.Version,
                Root = plugin.Root,
                DeclaredTreeSha256 = plugin.DeclaredTreeSha256,
                CommandExecuted = "PASS",
                ManagedPolicyEnforced = "PASS",
            });
        }
        PublisherSafeFile.RequireExpectedPathAndRegularFile(nodeLock, nodePath);
        if (PublisherSafeFile.GetIdentity(nodeLock) != nodeIdentity
            || !string.Equals(
                PublisherSafeFile.HashAndRewind(nodeLock),
                nodeSha,
                StringComparison.Ordinal))
        {
            throw new IOException("Admitted runtime node.exe changed during plugin execution.");
        }
        return observations;
    }

    private static PreservationResult RunRollbackPreservationCheck(string workspace)
    {
        var home = Path.Combine(workspace, "rollback-home");
        var recovery = Path.Combine(workspace, "rollback-recovery");
        var history = Path.Combine(home, "history", "conversation.v1.json");
        var userWorkspace = Path.Combine(home, "workspaces", "compatibility", "sentinel.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(history)!);
        Directory.CreateDirectory(Path.GetDirectoryName(userWorkspace)!);
        var historyBytes = RandomNumberGenerator.GetBytes(257);
        var workspaceBytes = RandomNumberGenerator.GetBytes(389);
        File.WriteAllBytes(history, historyBytes);
        File.WriteAllBytes(userWorkspace, workspaceBytes);
        var transaction = new EnterpriseHarnessHomeUpdateTransaction(home, recovery);
        var prepared = transaction.Prepare(
            "plugin-compatibility-rollback-v1",
            GetUnusedLoopbackPort());
        File.WriteAllText(history, "candidate-history", System.Text.Encoding.UTF8);
        File.WriteAllText(userWorkspace, "candidate-workspace", System.Text.Encoding.UTF8);
        var candidateOnly = Path.Combine(home, "candidate-only.txt");
        File.WriteAllText(candidateOnly, "candidate", System.Text.Encoding.UTF8);
        var restored = transaction.Rollback(
            prepared.TransactionId,
            "compatibility-probe-failure");
        var historyPreserved = File.ReadAllBytes(history).SequenceEqual(historyBytes);
        var workspacePreserved = File.ReadAllBytes(userWorkspace).SequenceEqual(workspaceBytes);
        return new PreservationResult(
            string.Equals(
                restored.Status,
                EnterpriseHarnessHomeUpdateTransaction.RestoredStatus,
                StringComparison.Ordinal)
                && !File.Exists(candidateOnly),
            historyPreserved,
            workspacePreserved);
    }

    private static void RunProcess(
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        IReadOnlyDictionary<string, string> additionalEnvironment,
        DateTimeOffset deadline,
        string label)
    {
        PublisherPathGuard.RequireSafeExistingFile(executable);
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        startInfo.Environment.Clear();
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system = Environment.SystemDirectory;
        startInfo.Environment["SystemRoot"] = windows;
        startInfo.Environment["WINDIR"] = windows;
        startInfo.Environment["COMSPEC"] = Path.Combine(system, "cmd.exe");
        startInfo.Environment["PATH"] = string.Join(
            Path.PathSeparator,
            [Path.GetDirectoryName(executable)!, system, windows]);
        startInfo.Environment["TEMP"] = workingDirectory;
        startInfo.Environment["TMP"] = workingDirectory;
        foreach (var pair in additionalEnvironment)
        {
            startInfo.Environment[pair.Key] = pair.Value;
        }
        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            throw new InvalidOperationException($"{label} did not start.");
        }
        var timeout = Remaining(deadline);
        if (!process.WaitForExit(checked((int)Math.Min(
                timeout.TotalMilliseconds,
                int.MaxValue))))
        {
            try
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
            }
            catch
            {
                // Preserve timeout as the authoritative failure.
            }
            throw new TimeoutException($"{label} timed out.");
        }
        if (process.ExitCode != 0)
        {
            throw new InvalidDataException($"{label} failed with exit code {process.ExitCode}.");
        }
    }

    private static TimeSpan Remaining(DateTimeOffset deadline)
    {
        var remaining = deadline - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero)
        {
            throw new TimeoutException("Compatibility probe production deadline expired.");
        }
        return remaining;
    }

    private static int GetUnusedLoopbackPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    private static void ExtractArchive(string archivePath, string destinationRoot)
    {
        using var stream = PublisherSafeFile.OpenLockedRead(archivePath);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        if (archive.Entries.Count is <= 0 or > MaximumArchiveEntries)
        {
            throw new InvalidDataException("Compatibility archive entry count is invalid.");
        }
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long expanded = 0;
        foreach (var entry in archive.Entries)
        {
            var normalized = ValidateArchiveEntry(entry);
            if (!paths.Add(normalized))
            {
                throw new InvalidDataException(
                    "Compatibility archive contains duplicate or case-colliding paths.");
            }
            expanded = checked(expanded + entry.Length);
            if (expanded > MaximumExpandedArchiveBytes)
            {
                throw new InvalidDataException("Compatibility archive expands beyond its limit.");
            }
            var outputPath = ResolveRelative(destinationRoot, normalized.TrimEnd('/'));
            if (normalized.EndsWith("/", StringComparison.Ordinal))
            {
                Directory.CreateDirectory(outputPath);
                continue;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            using var input = entry.Open();
            using var output = new FileStream(
                outputPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.WriteThrough);
            input.CopyTo(output);
            output.Flush(flushToDisk: true);
            if (output.Length != entry.Length)
            {
                throw new InvalidDataException(
                    "Compatibility archive entry length changed during extraction.");
            }
        }
    }

    internal static void RejectCandidateProvidedCompatibilityReporter(string runtimeArchivePath)
    {
        using var stream = PublisherSafeFile.OpenLockedRead(runtimeArchivePath);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        foreach (var entry in archive.Entries)
        {
            var normalized = entry.FullName.Replace('\\', '/');
            var fileName = normalized.Split('/').LastOrDefault();
            if (normalized.StartsWith(
                    "enterprise-plugin-compatibility-probe/",
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    fileName,
                    EnterprisePluginCompatibilityRunner.ProductionFileName,
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    fileName,
                    "Ensou.Dsh.EnterprisePluginCompatibilityProbe.exe",
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Candidate runtime may not provide a compatibility reporter; only the independently pinned Runner may produce evidence.");
            }
        }
    }

    private static string ValidateArchiveEntry(ZipArchiveEntry entry)
    {
        if ((entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0
            || ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000
            || string.IsNullOrWhiteSpace(entry.FullName)
            || entry.FullName.Contains('\\')
            || entry.FullName.StartsWith("/", StringComparison.Ordinal)
            || entry.FullName.Length > 1024)
        {
            throw new InvalidDataException(
                "Compatibility archive contains a link or unsafe entry path.");
        }
        var isDirectory = entry.FullName.EndsWith("/", StringComparison.Ordinal);
        var segments = entry.FullName.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            throw new InvalidDataException("Compatibility archive entry path is empty.");
        }
        foreach (var segment in segments)
        {
            var firstName = segment.Split('.', 2)[0];
            if (segment is "." or ".."
                || segment.EndsWith(' ')
                || segment.EndsWith('.')
                || segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
                || firstName.Equals("CON", StringComparison.OrdinalIgnoreCase)
                || firstName.Equals("PRN", StringComparison.OrdinalIgnoreCase)
                || firstName.Equals("AUX", StringComparison.OrdinalIgnoreCase)
                || firstName.Equals("NUL", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Compatibility archive has an unsafe path segment.");
            }
        }
        return string.Join('/', segments) + (isDirectory ? "/" : string.Empty);
    }

    private static string ResolveRelative(string root, string relative)
    {
        var normalizedRoot = Path.GetFullPath(root).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        var combined = Path.GetFullPath(Path.Combine(
            normalizedRoot,
            relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!combined.StartsWith(
                normalizedRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Compatibility archive path escaped its private extraction root.");
        }
        return combined;
    }

    private static byte[] SerializePluginRequest(
        InternalProbeRequest request,
        InternalProbePlugin plugin,
        string nonce,
        string skillsRoot)
    {
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            requestType = "ensou-dsh-managed-skill-compatibility-request",
            nonce,
            plugin = new
            {
                skillId = plugin.SkillId,
                version = plugin.Version,
                root = plugin.Root,
                declaredTreeSha256 = plugin.DeclaredTreeSha256,
            },
            runtimeArchiveSha256 = request.RuntimeArchive.Sha256,
            policyId = request.Policy.PolicyId,
            policyGeneration = request.Policy.Generation,
            managedSkillsRoot = skillsRoot,
        });
    }

    private static byte[] SerializeEvidence(
        InternalProbeRequest request,
        CompatibilityRunnerIdentity runner,
        DateTimeOffset started,
        DateTimeOffset completed,
        IReadOnlyList<CompatibilityPluginObservation> plugins)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString(
                "evidenceType",
                "ensou-dsh-managed-plugin-compatibility-observations");
            writer.WriteString("result", "PASS");
            writer.WriteString("nonce", request.Nonce);
            writer.WriteString("runnerSha256", runner.Sha256);
            writer.WriteString("testRunId", request.TestRunId);
            writer.WriteString("startedAtUtc", FormatUtc(started));
            writer.WriteString("completedAtUtc", FormatUtc(completed));
            writer.WriteString("launcherReleaseId", request.LauncherReleaseId);
            writer.WriteString("launcherArchiveSha256", request.LauncherArchive.Sha256);
            writer.WriteString("runtimeReleaseId", request.RuntimeReleaseId);
            writer.WriteString("runtimeArchiveSha256", request.RuntimeArchive.Sha256);
            writer.WriteString(
                "runtimeSourceMetadataSha256",
                request.RuntimeSourceMetadata.Sha256);
            writer.WriteString("policyId", request.Policy.PolicyId);
            writer.WriteNumber("policyGeneration", request.Policy.Generation);
            writer.WriteString(
                "pluginPolicyArchiveSha256",
                request.PluginPolicyArchive.Sha256);
            writer.WriteString(
                "pluginPolicyMetadataSha256",
                request.PluginPolicyMetadata.Sha256);
            writer.WriteString(
                "pluginPolicyExecutionAdmissionReceiptSha256",
                request.PluginPolicyExecutionAdmissionReceipt.Sha256);
            writer.WriteString("rawPolicySha256", request.Policy.RawPolicySha256);
            writer.WriteStartArray("plugins");
            foreach (var plugin in plugins)
            {
                writer.WriteStartObject();
                writer.WriteString("skillId", plugin.SkillId);
                writer.WriteString("version", plugin.Version);
                writer.WriteString("root", plugin.Root);
                writer.WriteString("declaredTreeSha256", plugin.DeclaredTreeSha256);
                writer.WriteString("commandExecuted", "PASS");
                writer.WriteString("managedPolicyEnforced", "PASS");
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartObject("observations");
            writer.WriteString("launcherBinarySelfCheck", "PASS");
            writer.WriteString("runtimeHealth", "PASS");
            writer.WriteString("pluginPolicyInstalled", "PASS");
            writer.WriteString("pluginCommandExecuted", "PASS");
            writer.WriteString("managedPolicyEnforced", "PASS");
            writer.WriteString("startupUpdateCheck", "PASS");
            writer.WriteString("rollbackRestoredPreviousRuntime", "PASS");
            writer.WriteString("conversationHistoryPreserved", "PASS");
            writer.WriteString("workspacePreserved", "PASS");
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static void WriteInput(
        Utf8JsonWriter writer,
        string name,
        PublisherStagedInputFile input)
    {
        writer.WriteStartObject(name);
        writer.WriteString("path", input.StagedPath);
        writer.WriteNumber("sizeBytes", input.Length);
        writer.WriteString("sha256", input.Sha256);
        writer.WriteEndObject();
    }

    private static void WriteNewVerified(string path, byte[] bytes)
    {
        using (var output = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            64 * 1024,
            FileOptions.WriteThrough))
        {
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }
        using var verify = PublisherSafeFile.OpenLockedRead(path);
        if (verify.Length != bytes.LongLength
            || !string.Equals(
                PublisherSafeFile.HashAndRewind(verify),
                Convert.ToHexStringLower(SHA256.HashData(bytes)),
                StringComparison.Ordinal))
        {
            throw new IOException("Compatibility probe output verification failed.");
        }
    }

    private static string FormatUtc(DateTimeOffset value) =>
        value.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    private static DateTimeOffset WholeSecond(DateTimeOffset value) =>
        DateTimeOffset.FromUnixTimeSeconds(value.ToUnixTimeSeconds());

    private sealed record PreservationResult(bool Rollback, bool History, bool Workspace);
}

internal sealed class InternalProbeInputs : IDisposable
{
    private readonly InternalProbeInput[] _all;

    private InternalProbeInputs(InternalProbeInput[] all)
    {
        _all = all;
        LauncherArchive = all[0];
        RuntimeArchive = all[1];
        RuntimeSourceMetadata = all[2];
        RuntimeOrganizationAdmissionReceipt = all[3];
        PluginPolicyArchive = all[4];
        PluginPolicyMetadata = all[5];
        PluginPolicyExecutionAdmissionReceipt = all[6];
    }

    public InternalProbeInput LauncherArchive { get; }
    public InternalProbeInput RuntimeArchive { get; }
    public InternalProbeInput RuntimeSourceMetadata { get; }
    public InternalProbeInput RuntimeOrganizationAdmissionReceipt { get; }
    public InternalProbeInput PluginPolicyArchive { get; }
    public InternalProbeInput PluginPolicyMetadata { get; }
    public InternalProbeInput PluginPolicyExecutionAdmissionReceipt { get; }

    public static InternalProbeInputs Capture(InternalProbeRequest request)
    {
        var expected = new[]
        {
            request.LauncherArchive,
            request.RuntimeArchive,
            request.RuntimeSourceMetadata,
            request.RuntimeOrganizationAdmissionReceipt,
            request.PluginPolicyArchive,
            request.PluginPolicyMetadata,
            request.PluginPolicyExecutionAdmissionReceipt,
        };
        var captured = new List<InternalProbeInput>();
        try
        {
            foreach (var input in expected)
            {
                captured.Add(InternalProbeInput.Capture(input));
            }
            if (captured.Select(input => input.Identity).Distinct().Count() != captured.Count)
            {
                throw new InvalidDataException(
                    "Internal compatibility inputs alias the same filesystem object.");
            }
            return new InternalProbeInputs(captured.ToArray());
        }
        catch
        {
            foreach (var input in captured.AsEnumerable().Reverse())
            {
                input.Dispose();
            }
            throw;
        }
    }

    public void Validate()
    {
        foreach (var input in _all)
        {
            input.VerifyUnchanged();
        }
    }

    public void VerifyUnchanged() => Validate();

    public void CreatePrivateSnapshots(string workspace)
    {
        var root = Path.Combine(workspace, "input-snapshots");
        Directory.CreateDirectory(root);
        string[] directories =
        [
            "launcher", "runtime", "runtime-source-metadata",
            "runtime-organization-admission", "plugin-policy",
            "plugin-policy-metadata", "plugin-execution-admission",
        ];
        for (var index = 0; index < _all.Length; index++)
        {
            var directory = Path.Combine(root, directories[index]);
            Directory.CreateDirectory(directory);
            _all[index].CreateSnapshot(Path.Combine(
                directory,
                Path.GetFileName(_all[index].Path)));
        }
    }

    public void Dispose()
    {
        foreach (var input in _all.Reverse())
        {
            input.Dispose();
        }
    }
}

internal sealed class InternalProbeInput : IDisposable
{
    private readonly FileStream _stream;
    private readonly long _expectedSize;
    private readonly string _expectedSha;
    private FileStream? _snapshot;
    private PublisherFileIdentity _snapshotIdentity;

    private InternalProbeInput(
        string path,
        PublisherFileIdentity identity,
        FileStream stream,
        long expectedSize,
        string expectedSha)
    {
        Path = path;
        Identity = identity;
        _stream = stream;
        _expectedSize = expectedSize;
        _expectedSha = expectedSha;
    }

    public string Path { get; }
    public string SnapshotPath { get; private set; } = string.Empty;
    public string Sha256 => _expectedSha;
    public PublisherFileIdentity Identity { get; }

    public static InternalProbeInput Capture(InternalProbeFile expected)
    {
        var path = System.IO.Path.GetFullPath(expected.Path);
        var stream = PublisherSafeFile.OpenLockedRead(path);
        try
        {
            var input = new InternalProbeInput(
                path,
                PublisherSafeFile.GetIdentity(stream),
                stream,
                expected.SizeBytes,
                expected.Sha256);
            input.VerifyUnchanged();
            return input;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public void VerifyUnchanged()
    {
        PublisherSafeFile.RequireExpectedPathAndRegularFile(_stream, Path);
        if (_expectedSize <= 0
            || _stream.Length != _expectedSize
            || !PublisherPluginPolicyMetadata.IsLowercaseSha256(_expectedSha)
            || PublisherSafeFile.GetIdentity(_stream) != Identity
            || !string.Equals(
                PublisherSafeFile.HashAndRewind(_stream),
                _expectedSha,
                StringComparison.Ordinal))
        {
            throw new IOException(
                "Internal compatibility input path, identity, size, or SHA-256 drifted.");
        }
        if (_snapshot is not null)
        {
            PublisherSafeFile.RequireExpectedPathAndRegularFile(_snapshot, SnapshotPath);
            if (_snapshot.Length != _expectedSize
                || PublisherSafeFile.GetIdentity(_snapshot) != _snapshotIdentity
                || !string.Equals(
                    PublisherSafeFile.HashAndRewind(_snapshot),
                    _expectedSha,
                    StringComparison.Ordinal))
            {
                throw new IOException(
                    "Internal compatibility private snapshot identity or bytes drifted.");
            }
        }
    }

    public void CreateSnapshot(string destination)
    {
        if (_snapshot is not null)
        {
            throw new InvalidOperationException("Internal input snapshot already exists.");
        }
        _stream.Position = 0;
        using (var output = new FileStream(
            destination,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.WriteThrough))
        {
            _stream.CopyTo(output);
            output.Flush(flushToDisk: true);
            if (output.Length != _expectedSize)
            {
                throw new IOException("Internal input snapshot copy was truncated.");
            }
        }
        SnapshotPath = System.IO.Path.GetFullPath(destination);
        _snapshot = PublisherSafeFile.OpenLockedRead(SnapshotPath);
        _snapshotIdentity = PublisherSafeFile.GetIdentity(_snapshot);
        VerifyUnchanged();
    }

    public void Dispose()
    {
        _snapshot?.Dispose();
        _stream.Dispose();
    }
}

internal sealed class LockedPrivateTree : IDisposable
{
    private readonly LockedPrivateTreeFile[] _files;

    private LockedPrivateTree(LockedPrivateTreeFile[] files)
    {
        _files = files;
    }

    public static LockedPrivateTree Capture(string root)
    {
        var normalized = Path.GetFullPath(root);
        if (!Directory.Exists(normalized)
            || (File.GetAttributes(normalized) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Compatibility private tree root is missing or linked.");
        }
        foreach (var directory in Directory.EnumerateDirectories(
                     normalized,
                     "*",
                     SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Compatibility private tree contains a linked directory.");
            }
        }
        var paths = Directory.EnumerateFiles(normalized, "*", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (paths.Length is <= 0 or > 250_000)
        {
            throw new InvalidDataException("Compatibility private tree file count is invalid.");
        }
        var captured = new List<LockedPrivateTreeFile>();
        try
        {
            foreach (var path in paths)
            {
                captured.Add(LockedPrivateTreeFile.Capture(path));
            }
            var result = new LockedPrivateTree(captured.ToArray());
            result.VerifyUnchanged();
            return result;
        }
        catch
        {
            foreach (var item in captured.AsEnumerable().Reverse())
            {
                item.Dispose();
            }
            throw;
        }
    }

    public void VerifyUnchanged()
    {
        foreach (var file in _files)
        {
            file.VerifyUnchanged();
        }
    }

    public void Dispose()
    {
        foreach (var file in _files.Reverse())
        {
            file.Dispose();
        }
    }
}

internal sealed class LockedPrivateTreeFile : IDisposable
{
    private readonly FileStream _stream;
    private readonly PublisherFileIdentity _identity;
    private readonly long _length;
    private readonly string _sha256;

    private LockedPrivateTreeFile(
        string path,
        FileStream stream,
        PublisherFileIdentity identity,
        long length,
        string sha256)
    {
        Path = path;
        _stream = stream;
        _identity = identity;
        _length = length;
        _sha256 = sha256;
    }

    private string Path { get; }

    public static LockedPrivateTreeFile Capture(string path)
    {
        var stream = PublisherSafeFile.OpenLockedRead(path);
        try
        {
            return new LockedPrivateTreeFile(
                System.IO.Path.GetFullPath(path),
                stream,
                PublisherSafeFile.GetIdentity(stream),
                stream.Length,
                PublisherSafeFile.HashAndRewind(stream));
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public void VerifyUnchanged()
    {
        PublisherSafeFile.RequireExpectedPathAndRegularFile(_stream, Path);
        if (_stream.Length != _length
            || PublisherSafeFile.GetIdentity(_stream) != _identity
            || !string.Equals(
                PublisherSafeFile.HashAndRewind(_stream),
                _sha256,
                StringComparison.Ordinal))
        {
            throw new IOException(
                "Compatibility private extracted file identity or bytes changed during execution.");
        }
    }

    public void Dispose() => _stream.Dispose();
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record InternalProbeRequest
{
    public required int SchemaVersion { get; init; }
    public required string RequestType { get; init; }
    public required string Nonce { get; init; }
    public required InternalProbeRunner Runner { get; init; }
    public required string TestRunId { get; init; }
    public required string LauncherReleaseId { get; init; }
    public required InternalProbeFile LauncherArchive { get; init; }
    public required string RuntimeReleaseId { get; init; }
    public required InternalProbeFile RuntimeArchive { get; init; }
    public required InternalProbeFile RuntimeSourceMetadata { get; init; }
    public required InternalProbeFile RuntimeOrganizationAdmissionReceipt { get; init; }
    public required InternalProbeFile PluginPolicyArchive { get; init; }
    public required InternalProbeFile PluginPolicyMetadata { get; init; }
    public required InternalProbeFile PluginPolicyExecutionAdmissionReceipt { get; init; }
    public required InternalProbePolicy Policy { get; init; }
    public required string Workspace { get; init; }
    public required IReadOnlyList<InternalProbePlugin> RequiredPlugins { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record InternalProbeRunner
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record InternalProbeFile
{
    public required string Path { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record InternalProbePolicy
{
    public required string PolicyId { get; init; }
    public required long Generation { get; init; }
    public required string RawPolicySha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record InternalProbePlugin
{
    public required string SkillId { get; init; }
    public required string Version { get; init; }
    public required string Root { get; init; }
    public required string DeclaredTreeSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PluginCompatibilityResult
{
    public required int SchemaVersion { get; init; }
    public required string ResultType { get; init; }
    public required string Result { get; init; }
    public required string Nonce { get; init; }
    public required string SkillId { get; init; }
    public required string Version { get; init; }
    public required string Root { get; init; }
    public required string DeclaredTreeSha256 { get; init; }
    public required string RuntimeArchiveSha256 { get; init; }
    public required string PolicyId { get; init; }
    public required long PolicyGeneration { get; init; }
    public required string ManagedSkillsRoot { get; init; }
}
