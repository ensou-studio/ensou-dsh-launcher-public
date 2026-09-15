using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace Ensou.Dsh.Enterprise.Installation;

public sealed record EnterpriseInstallResult(
    string LauncherReleaseId,
    string RuntimeReleaseId,
    string BootstrapperPath,
    bool DevelopmentUnsignedPayload);

public sealed partial class EnterpriseInstallationService(EnterpriseInstallationLayout layout)
{
    private const int MaximumArchiveEntries = 200_000;
    private const long MaximumExpandedArchiveBytes = 8L * 1024 * 1024 * 1024;
    private const string InstallationReceiptFileName = "installation-receipt.json";
    private readonly EnterpriseInstallationLayout _layout = layout
        ?? throw new ArgumentNullException(nameof(layout));
    private readonly Action _requireNoPossibleHarnessWriter =
        () => EnterpriseHarnessProcessWriterGuard
            .RequireNoPossibleHarnessWriter(layout);
    private Action? _beforeLegacySqliteCommitForTest;

    internal EnterpriseInstallationService(
        EnterpriseInstallationLayout layout,
        Action beforeLegacySqliteCommitForTest)
        : this(
            layout,
            beforeLegacySqliteCommitForTest,
            () => EnterpriseHarnessProcessWriterGuard
                .RequireNoPossibleHarnessWriter(layout))
    {
    }

    internal EnterpriseInstallationService(
        EnterpriseInstallationLayout layout,
        Action? beforeLegacySqliteCommitForTest,
        Action requireNoPossibleHarnessWriter)
        : this(layout)
    {
        _beforeLegacySqliteCommitForTest = beforeLegacySqliteCommitForTest;
        _requireNoPossibleHarnessWriter = requireNoPossibleHarnessWriter
            ?? throw new ArgumentNullException(nameof(requireNoPossibleHarnessWriter));
    }

    public async Task<EnterpriseInstallResult> InstallExternalDevelopmentPayloadAsync(
        string payloadDirectory,
        string installerExecutablePath,
        CancellationToken cancellationToken = default)
    {
        if (!_layout.IsDevelopmentE2E)
        {
            throw new InvalidDataException(
                "External development payloads require the isolated Development E2E layout.");
        }

        using var source = EnterpriseDirectoryPayloadSource.OpenExplicitDevelopmentPayload(
            payloadDirectory);
        return await InstallAsync(
            source,
            installerExecutablePath,
            developmentUnsignedPayload: true,
            registrationContext: null,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<EnterpriseInstallResult> InstallExternalDevelopmentPayloadAndRegisterAsync(
        string payloadDirectory,
        string installerExecutablePath,
        CancellationToken cancellationToken = default) =>
        await InstallExternalDevelopmentPayloadAndRegisterAsync(
            payloadDirectory,
            installerExecutablePath,
            EnterpriseWindowsRegistrationContext.CreateDefault(_layout),
            cancellationToken).ConfigureAwait(false);

    internal async Task<EnterpriseInstallResult> InstallExternalDevelopmentPayloadAndRegisterAsync(
        string payloadDirectory,
        string installerExecutablePath,
        EnterpriseWindowsRegistrationContext registrationContext,
        CancellationToken cancellationToken = default)
    {
        if (!_layout.IsDevelopmentE2E)
        {
            throw new InvalidDataException(
                "External development payloads require the isolated Development E2E layout.");
        }

        using var source = EnterpriseDirectoryPayloadSource.OpenExplicitDevelopmentPayload(
            payloadDirectory);
        return await InstallAsync(
            source,
            installerExecutablePath,
            developmentUnsignedPayload: true,
            registrationContext,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<EnterpriseInstallResult> InstallEmbeddedDevelopmentPayloadAsync(
        Assembly installerAssembly,
        string installerExecutablePath,
        CancellationToken cancellationToken = default)
    {
        if (!_layout.IsDevelopmentE2E)
        {
            throw new InvalidDataException(
                "Embedded development payloads require the isolated Development E2E layout.");
        }

        ArgumentNullException.ThrowIfNull(installerAssembly);
        using var source = new EnterpriseEmbeddedPayloadSource(installerAssembly);
        return await InstallAsync(
            source,
            installerExecutablePath,
            developmentUnsignedPayload: true,
            registrationContext: null,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<EnterpriseInstallResult> InstallEmbeddedProductionPayloadAsync(
        Assembly installerAssembly,
        string installerExecutablePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(installerAssembly);
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(installerExecutablePath);
        using var source = new EnterpriseEmbeddedPayloadSource(installerAssembly);
        return await InstallAsync(
            source,
            installerExecutablePath,
            developmentUnsignedPayload: false,
            registrationContext: null,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<EnterpriseInstallResult> InstallEmbeddedProductionPayloadAndRegisterAsync(
        Assembly installerAssembly,
        string installerExecutablePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(installerAssembly);
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(installerExecutablePath);
        using var source = new EnterpriseEmbeddedPayloadSource(installerAssembly);
        return await InstallAsync(
            source,
            installerExecutablePath,
            developmentUnsignedPayload: false,
            EnterpriseWindowsRegistrationContext.CreateDefault(_layout),
            cancellationToken).ConfigureAwait(false);
    }

    public EnterpriseUninstallCommitResult UninstallManagedProgramFiles(
        CancellationToken cancellationToken = default) =>
        UninstallManagedProgramFiles(
            EnterpriseWindowsRegistrationContext.CreateDefault(_layout),
            cancellationToken);

    internal EnterpriseUninstallCommitResult UninstallManagedProgramFiles(
        EnterpriseWindowsRegistrationContext registrationContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(registrationContext);
        using var operationLease = EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(_layout, cancellationToken)
            .GetAwaiter()
            .GetResult();
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(_layout);
        return new EnterpriseMaintenanceOperations(_layout, registrationContext)
            .UninstallManagedProgramFilesUnderLease();
    }

    private async Task<EnterpriseInstallResult> InstallAsync(
        IEnterprisePayloadSource source,
        string installerExecutablePath,
        bool developmentUnsignedPayload,
        EnterpriseWindowsRegistrationContext? registrationContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(installerExecutablePath);
        if (!Path.IsPathFullyQualified(installerExecutablePath)
            || !File.Exists(installerExecutablePath)
            || (File.GetAttributes(installerExecutablePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Installer executable path is invalid or linked.");
        }

        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
            _layout,
            _requireNoPossibleHarnessWriter);

        await using var operationLease =
            await EnterpriseManagedUpdateOperationLease.AcquireRequiredAsync(
                _layout,
                cancellationToken).ConfigureAwait(false);
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
            _layout,
            _requireNoPossibleHarnessWriter);
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(_layout);
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
            _layout,
            _requireNoPossibleHarnessWriter);

        EnterpriseInstallManifest manifest;
        await using (var manifestStream = source.Open(
                         EnterpriseEmbeddedPayloadSource.ManifestFileName))
        {
            var manifestBytes = await ReadBoundedAsync(
                manifestStream,
                128 * 1024,
                cancellationToken).ConfigureAwait(false);
            manifest = EnterpriseInstallManifest.Parse(manifestBytes);
        }

        if (!string.Equals(
                manifest.LayoutProfile,
                _layout.LayoutProfile,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise payload layout profile does not match the selected installer layout.");
        }

        new EnterpriseReleaseSetPointerStore(_layout).EnsureInstallerTargetAllowed(
            manifest.LauncherReleaseId,
            manifest.RuntimeReleaseId);

        var rollbackRegistrationContext = registrationContext?.WithoutObservers();
        var registrationSnapshot = rollbackRegistrationContext is null
            ? null
            : EnterpriseWindowsRegistration.CaptureRollbackSnapshot(
                _layout,
                rollbackRegistrationContext);
        var installTransaction = new EnterpriseInstallRollbackTransaction(
            _layout,
            rollbackRegistrationContext,
            registrationSnapshot);

        var operationDirectory = Path.Combine(
            _layout.PackageRoot,
            $".install-{Guid.NewGuid():N}");
        try
        {
            _layout.EnsureManagedRoots();
            EnterprisePathGuard.EnsureDirectoryChain(
                _layout.ManagedRoot,
                operationDirectory);
            var launcherPackagePath = Path.Combine(operationDirectory, manifest.LauncherArchive);
            var runtimePackagePath = Path.Combine(operationDirectory, manifest.RuntimeArchive);
            var bootstrapperPackagePath = Path.Combine(operationDirectory, manifest.BootstrapperFile);
            await CopyAndVerifyPayloadAsync(
                source,
                manifest.LauncherArchive,
                launcherPackagePath,
                manifest.LauncherArchiveSizeBytes,
                manifest.LauncherArchiveSha256,
                cancellationToken).ConfigureAwait(false);
            await CopyAndVerifyPayloadAsync(
                source,
                manifest.RuntimeArchive,
                runtimePackagePath,
                manifest.RuntimeArchiveSizeBytes,
                manifest.RuntimeArchiveSha256,
                cancellationToken).ConfigureAwait(false);
            await CopyAndVerifyPayloadAsync(
                source,
                manifest.BootstrapperFile,
                bootstrapperPackagePath,
                manifest.BootstrapperSizeBytes,
                manifest.BootstrapperSha256,
                cancellationToken).ConfigureAwait(false);

            await InstallArchiveAsync(
                launcherPackagePath,
                manifest.LauncherReleaseId,
                manifest.LauncherArchiveSha256,
                _layout.LauncherVersionsRoot,
                EnterpriseInstallationLayout.LauncherExecutableName,
                secondaryRelativePath: null,
                launcher: true,
                installTransaction,
                cancellationToken).ConfigureAwait(false);
            await InstallArchiveAsync(
                runtimePackagePath,
                manifest.RuntimeReleaseId,
                manifest.RuntimeArchiveSha256,
                _layout.RuntimeVersionsRoot,
                "node.exe",
                "node_modules/@deepseek-ai/dsh/lib/bin.js",
                launcher: false,
                installTransaction,
                cancellationToken).ConfigureAwait(false);

            installTransaction.CaptureFile(_layout.BootstrapperPath);
            InstallStableFile(
                bootstrapperPackagePath,
                _layout.BootstrapperPath,
                manifest.BootstrapperSha256);
            installTransaction.CaptureFile(_layout.BootstrapperReceiptPath);
            EnterpriseStableBootstrapperVerifier.WriteReceipt(
                _layout,
                manifest.BootstrapperSha256);
            installTransaction.CaptureFile(_layout.BuildProfileMarkerPath);
            EnterprisePathGuard.WriteFileAtomically(
                _layout.BuildProfileMarkerPath,
                EnterpriseBuildProfileMarker.CreateCanonical(_layout.LayoutProfile),
                _layout.ManagedRoot);
            installTransaction.CaptureFile(_layout.InstalledInstallerPath);
            InstallStableFile(
                installerExecutablePath,
                _layout.InstalledInstallerPath,
                EnterpriseHash.ComputeFile(installerExecutablePath));

            installTransaction.CaptureFile(_layout.RuntimePointerPath);
            var runtimePointer = new EnterpriseRuntimePointerStore(_layout)
                .Activate(manifest.RuntimeReleaseId);
            installTransaction.CaptureFile(_layout.LauncherPointerPath);
            var launcherPointer = new EnterpriseLauncherPointerStore(_layout)
                .Activate(manifest.LauncherReleaseId);
            if (!string.Equals(
                    runtimePointer.ReleaseId,
                    manifest.RuntimeReleaseId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    launcherPointer.ReleaseId,
                    manifest.LauncherReleaseId,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException("Enterprise version activation did not commit.");
            }

            installTransaction.CaptureFile(_layout.ReleaseSetPointerPath);
            var releaseSetPointer = new EnterpriseReleaseSetPointerStore(_layout)
                .ActivateInitialHealthy(
                    manifest.LauncherReleaseId,
                    manifest.RuntimeReleaseId);
            if (!string.Equals(
                    releaseSetPointer.Current.Launcher.ReleaseId,
                    manifest.LauncherReleaseId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    releaseSetPointer.Current.Runtime.ReleaseId,
                    manifest.RuntimeReleaseId,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise release-set activation did not commit.");
            }

            var receipt = new EnterpriseInstallationReceipt(
                1,
                _layout.LayoutProfile,
                manifest.LauncherReleaseId,
                manifest.RuntimeReleaseId,
                developmentUnsignedPayload,
                DateTimeOffset.UtcNow);
            installTransaction.CaptureFile(
                Path.Combine(_layout.StateRoot, InstallationReceiptFileName));
            EnterprisePathGuard.WriteFileAtomically(
                Path.Combine(_layout.StateRoot, InstallationReceiptFileName),
                JsonSerializer.SerializeToUtf8Bytes(receipt, EnterpriseInstallJson.Options),
                _layout.ManagedRoot);

            DeleteInstallOperationDirectory(operationDirectory);
            var result = new EnterpriseInstallResult(
                manifest.LauncherReleaseId,
                manifest.RuntimeReleaseId,
                _layout.BootstrapperPath,
                developmentUnsignedPayload);
            if (registrationContext is not null)
            {
                _ = EnterpriseWindowsRegistration.Install(
                    _layout,
                    result.LauncherReleaseId,
                    result.DevelopmentUnsignedPayload,
                    registrationContext);
            }
            _beforeLegacySqliteCommitForTest?.Invoke();
            EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(
                _layout,
                _requireNoPossibleHarnessWriter);
            installTransaction.Commit();
            return result;
        }
        catch (Exception installFailure)
        {
            var rollbackFailures = new List<Exception>();
            try
            {
                DeleteInstallOperationDirectory(operationDirectory);
            }
            catch (Exception exception)
            {
                rollbackFailures.Add(exception);
            }
            try
            {
                installTransaction.Rollback();
            }
            catch (Exception exception)
            {
                rollbackFailures.Add(exception);
            }

            if (rollbackFailures.Count > 0)
            {
                if (EnterpriseLegacySqliteUpgradeGuard.IsBlockedFailure(installFailure))
                {
                    throw new InvalidOperationException(
                        EnterpriseLegacySqliteUpgradeGuard
                            .InstallationRollbackFailureMessage);
                }
                throw new AggregateException(
                    "Enterprise installation failed and rollback could not be certified.",
                    new[] { installFailure }.Concat(rollbackFailures));
            }
            throw;
        }
        finally
        {
            installTransaction.Dispose();
        }
    }

    private void DeleteInstallOperationDirectory(string operationDirectory)
    {
        if (!Directory.Exists(operationDirectory))
        {
            return;
        }
        EnterprisePathGuard.DeleteDirectoryTree(
            operationDirectory,
            _layout.ManagedRoot);
    }

    private async Task InstallArchiveAsync(
        string archivePath,
        string releaseId,
        string archiveSha256,
        string versionRoot,
        string primaryRelativePath,
        string? secondaryRelativePath,
        bool launcher,
        EnterpriseInstallRollbackTransaction installTransaction,
        CancellationToken cancellationToken)
    {
        EnterprisePathGuard.ValidateReleaseId(releaseId);
        var finalDirectory = EnterprisePathGuard.CombineExactChild(versionRoot, releaseId);
        var stagingDirectory = Path.Combine(
            versionRoot,
            $".{releaseId}.staging-{Guid.NewGuid():N}");
        EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, stagingDirectory);
        try
        {
            await ExtractArchiveSafelyAsync(
                archivePath,
                stagingDirectory,
                cancellationToken).ConfigureAwait(false);
            var primaryPath = ResolveArchiveOutput(stagingDirectory, primaryRelativePath);
            var secondaryPath = secondaryRelativePath is null
                ? null
                : ResolveArchiveOutput(stagingDirectory, secondaryRelativePath);
            if (!File.Exists(primaryPath))
            {
                throw new InvalidDataException(
                    $"Enterprise archive is missing required file: {primaryRelativePath}");
            }
            if (secondaryPath is not null && !File.Exists(secondaryPath))
            {
                throw new InvalidDataException(
                    $"Enterprise archive is missing required file: {secondaryRelativePath}");
            }

            var clientBundleExecutables = launcher
                ? new[]
                {
                    primaryPath,
                    ResolveArchiveOutput(
                        stagingDirectory,
                        EnterpriseInstallationLayout.ClientBootstrapperExecutableName),
                    ResolveArchiveOutput(
                        stagingDirectory,
                        EnterpriseInstallationLayout.MaintenanceExecutableName),
                }
                : [];
            if (clientBundleExecutables.Any(path => !File.Exists(path)))
            {
                throw new InvalidDataException(
                    "Enterprise client-bundle is missing Launcher, versioned Bootstrapper, or Maintenance.");
            }

            EnterprisePathGuard.ValidateSafeTree(stagingDirectory, _layout.ManagedRoot);
            if (launcher)
            {
                EnterpriseBuildProfileMarker.ReadAndValidate(
                    Path.Combine(
                        stagingDirectory,
                        EnterpriseInstallationLayout.BuildProfileMarkerFileName),
                    _layout.LayoutProfile);
                foreach (var executable in clientBundleExecutables)
                {
                    EnterpriseAuthenticodeVerifier.RequireTrustedSignature(executable, _layout);
                }
            }

            var runtimeManifestSha256 = launcher
                ? null
                : EnterpriseRuntimeFileManifest.ValidateCompleteTree(stagingDirectory);

            var receipt = new EnterpriseInstalledReleaseReceipt(
                1,
                releaseId,
                archiveSha256,
                EnterpriseHash.ComputeFile(primaryPath),
                secondaryPath is null ? null : EnterpriseHash.ComputeFile(secondaryPath),
                DateTimeOffset.UtcNow);
            if (launcher)
            {
                EnterpriseLauncherPointerStore.WriteReceipt(
                    stagingDirectory,
                    receipt,
                    _layout.ManagedRoot);
            }
            else
            {
                EnterpriseRuntimePointerStore.WriteReceipt(
                    stagingDirectory,
                    receipt,
                    _layout.ManagedRoot);
            }

            var artifactReceipt = new EnterpriseReleaseArtifactReceiptV2(
                2,
                launcher
                    ? EnterpriseReleaseSetContract.LauncherComponent
                    : EnterpriseReleaseSetContract.RuntimeComponent,
                releaseId,
                archiveSha256,
                EnterpriseTreeHash.Compute(stagingDirectory),
                runtimeManifestSha256,
                DateTimeOffset.UtcNow);
            EnterprisePathGuard.WriteFileAtomically(
                Path.Combine(stagingDirectory, EnterpriseTreeHash.ReceiptFileName),
                EnterprisePointerJson.Serialize(artifactReceipt),
                _layout.ManagedRoot);

            ReplaceVersionDirectory(
                stagingDirectory,
                finalDirectory,
                versionRoot,
                installTransaction);
        }
        finally
        {
            if (Directory.Exists(stagingDirectory))
            {
                EnterprisePathGuard.DeleteDirectoryTree(
                    stagingDirectory,
                    _layout.ManagedRoot);
            }
        }
    }

    private void ReplaceVersionDirectory(
        string stagingDirectory,
        string finalDirectory,
        string versionRoot,
        EnterpriseInstallRollbackTransaction installTransaction)
    {
        _ = versionRoot;
        installTransaction.PrepareDirectoryReplacement(finalDirectory);
        Directory.Move(stagingDirectory, finalDirectory);
    }

    private void InstallStableFile(string sourcePath, string destinationPath, string expectedSha256)
    {
        var sourceFullPath = Path.GetFullPath(sourcePath);
        var destinationFullPath = Path.GetFullPath(destinationPath);
        if (!string.Equals(
                EnterpriseHash.ComputeFile(sourceFullPath),
                expectedSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise stable executable source changed during install.");
        }

        if (string.Equals(
                sourceFullPath,
                destinationFullPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var destinationDirectory = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidDataException("Enterprise stable executable path has no parent.");
        EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, destinationDirectory);
        if (File.Exists(destinationPath))
        {
            EnterprisePathGuard.ValidateExistingPathWithin(
                destinationPath,
                _layout.ManagedRoot,
                requireDirectory: false);
        }

        var temporaryPath = Path.Combine(
            destinationDirectory,
            $".{Path.GetFileName(destinationPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.Copy(sourceFullPath, temporaryPath, overwrite: false);
            if (!string.Equals(
                    EnterpriseHash.ComputeFile(temporaryPath),
                    expectedSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException("Enterprise stable executable copy failed verification.");
            }

            File.Move(temporaryPath, destinationPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private async Task ExtractArchiveSafelyAsync(
        string archivePath,
        string destinationDirectory,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            archivePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        if (archive.Entries.Count == 0 || archive.Entries.Count > MaximumArchiveEntries)
        {
            throw new InvalidDataException("Enterprise archive entry count is invalid.");
        }

        long expandedBytes = 0;
        var canonicalEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var normalizedEntry = ValidateArchiveEntry(entry);
            if (!canonicalEntries.Add(normalizedEntry))
            {
                throw new InvalidDataException(
                    $"Enterprise archive contains a duplicate path: {entry.FullName}");
            }

            expandedBytes = checked(expandedBytes + entry.Length);
            if (expandedBytes > MaximumExpandedArchiveBytes)
            {
                throw new InvalidDataException("Enterprise archive expands beyond its safety limit.");
            }

            var outputPath = ResolveArchiveOutput(destinationDirectory, normalizedEntry);
            if (normalizedEntry.EndsWith("/", StringComparison.Ordinal))
            {
                EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, outputPath);
                continue;
            }

            var parent = Path.GetDirectoryName(outputPath)
                ?? throw new InvalidDataException("Enterprise archive output path has no parent.");
            EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, parent);
            await using var input = entry.Open();
            await using var output = new FileStream(
                outputPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await input.CopyToAsync(output, 128 * 1024, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            if (output.Length != entry.Length)
            {
                throw new InvalidDataException("Enterprise archive entry length changed during extraction.");
            }
        }
    }

    private static string ValidateArchiveEntry(ZipArchiveEntry entry)
    {
        if ((entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0
            || ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
        {
            throw new InvalidDataException("Enterprise archive may not contain filesystem links.");
        }

        var normalized = entry.FullName.Replace('\\', '/');
        if (string.IsNullOrWhiteSpace(normalized)
            || normalized.StartsWith("/", StringComparison.Ordinal)
            || normalized.Length > 1024)
        {
            throw new InvalidDataException("Enterprise archive entry path is invalid.");
        }

        var isDirectory = normalized.EndsWith("/", StringComparison.Ordinal);
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            throw new InvalidDataException("Enterprise archive entry path is empty.");
        }

        foreach (var segment in segments)
        {
            if (segment is "." or ".."
                || segment.EndsWith(' ')
                || segment.EndsWith('.')
                || segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
                || IsReservedWindowsName(segment))
            {
                throw new InvalidDataException(
                    $"Enterprise archive entry contains an unsafe segment: {entry.FullName}");
            }
        }

        return string.Join('/', segments) + (isDirectory ? "/" : string.Empty);
    }

    private static bool IsReservedWindowsName(string segment)
    {
        var name = segment.Split('.', 2)[0];
        return name.Equals("CON", StringComparison.OrdinalIgnoreCase)
            || name.Equals("PRN", StringComparison.OrdinalIgnoreCase)
            || name.Equals("AUX", StringComparison.OrdinalIgnoreCase)
            || name.Equals("NUL", StringComparison.OrdinalIgnoreCase)
            || (name.Length == 4
                && (name.StartsWith("COM", StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith("LPT", StringComparison.OrdinalIgnoreCase))
                && name[3] is >= '1' and <= '9');
    }

    private static string ResolveArchiveOutput(string destinationDirectory, string relativePath)
    {
        var normalizedRelative = relativePath
            .TrimEnd('/')
            .Replace('/', Path.DirectorySeparatorChar);
        var destination = EnterprisePathGuard.NormalizeDirectory(destinationDirectory);
        var output = Path.GetFullPath(Path.Combine(destination, normalizedRelative));
        if (!EnterprisePathGuard.IsSameOrDescendant(output, destination)
            || string.Equals(output, destination, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise archive output escaped staging.");
        }

        return output;
    }

    private static async Task CopyAndVerifyPayloadAsync(
        IEnterprisePayloadSource source,
        string fileName,
        string destinationPath,
        long expectedSize,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        await using var input = source.Open(fileName);
        await using var output = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        long copied = 0;
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            copied = checked(copied + read);
            if (copied > expectedSize)
            {
                throw new InvalidDataException($"Enterprise payload size exceeds manifest: {fileName}");
            }

            hash.AppendData(buffer.AsSpan(0, read));
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        var actualSha256 = Convert.ToHexStringLower(hash.GetHashAndReset());
        if (copied != expectedSize
            || !string.Equals(actualSha256, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Enterprise payload failed size/SHA-256 verification: {fileName}");
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var copyBuffer = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(copyBuffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return buffer.ToArray();
            }

            if (buffer.Length + read > maximumBytes)
            {
                throw new InvalidDataException("Enterprise install manifest is too large.");
            }

            await buffer.WriteAsync(copyBuffer.AsMemory(0, read), cancellationToken)
                .ConfigureAwait(false);
        }
    }
}
