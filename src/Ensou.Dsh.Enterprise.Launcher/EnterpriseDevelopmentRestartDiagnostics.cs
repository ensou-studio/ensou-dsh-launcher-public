#if ENTERPRISE_DEVELOPMENT_E2E
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.Launcher;

internal static class EnterpriseDevelopmentRestartDiagnostics
{
    private const string ReceiptPathVariable = "ENSOU_DSH_E2E_RESTART_RECEIPT_PATH";
    private const string ReceiptEvent = "enterprise-development-restart";

    internal static void EmitAfterParentExit(
        EnterpriseInstallationLayout layout,
        bool backgroundStartup,
        int parentProcessId)
    {
        var configuredPath = Environment.GetEnvironmentVariable(ReceiptPathVariable);
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return;
        }
        if (layout is null || !layout.IsDevelopmentE2E)
        {
            throw new InvalidOperationException("Restart receipts require the development E2E layout.");
        }
        if (parentProcessId <= 0 || parentProcessId == Environment.ProcessId)
        {
            throw new InvalidDataException("Restart receipt requires a distinct admitted parent process.");
        }

        var path = ValidateReceiptPath(configuredPath, layout);
        var pointer = new EnterpriseReleaseSetPointerStore(layout).ReadRequired();
        if (!string.Equals(pointer.Current.HealthState, EnterpriseReleaseHealthStates.Healthy,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Restart receipt requires a healthy active release.");
        }

        var imagePath = Path.GetFullPath(Path.Combine(
            pointer.Current.Launcher.Directory,
            EnterpriseInstallationLayout.LauncherExecutableName));
        var currentImage = Path.GetFullPath(
            Environment.ProcessPath ?? throw new InvalidOperationException("Current process image is unavailable."));
        if (!string.Equals(imagePath, currentImage, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Restart receipt image is not the active Launcher image.");
        }

        var imageHash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(currentImage)));
        var version = FileVersionInfo.GetVersionInfo(currentImage).ProductVersion;
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            @event = ReceiptEvent,
            scope = "Enterprise",
            backgroundStartup,
            receiverPid = Environment.ProcessId,
            parentPid = parentProcessId,
            parentExited = true,
            outcome = "parent-exited",
            releaseSetId = pointer.Current.ReleaseSetId,
            sequence = pointer.Current.Sequence,
            launcherReleaseId = pointer.Current.Launcher.ReleaseId,
            launcherVersion = version,
            launcherImageSha256 = imageHash,
            emittedAtUtc = DateTimeOffset.UtcNow,
        });
        PublishCreateOnly(path, payload);
    }

    private static string ValidateReceiptPath(
        string configuredPath,
        EnterpriseInstallationLayout layout)
    {
        var path = Path.GetFullPath(configuredPath.Trim());
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(layout.LocalAppDataRoot));
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidDataException("Restart receipt path has no directory.");
        if (string.Equals(path, root, StringComparison.OrdinalIgnoreCase)
            || !EnterprisePathGuard.IsSameOrDescendant(path, root)
            || string.IsNullOrWhiteSpace(Path.GetFileName(path)))
        {
            throw new InvalidDataException("Restart receipt path must be below LocalAppDataRoot.");
        }
        EnterprisePathGuard.EnsureDirectoryChain(root, directory);
        // EnsureDirectoryChain validates the root itself; the strict descendant
        // validator is needed only when the receipt has a nested parent directory.
        if (!string.Equals(directory, root, StringComparison.OrdinalIgnoreCase))
        {
            EnterprisePathGuard.ValidateExistingPathWithin(directory, root, requireDirectory: true);
        }
        if (File.Exists(path) || Directory.Exists(path))
        {
            throw new IOException("Restart receipt already exists.");
        }
        return path;
    }

    private static void PublishCreateOnly(string path, byte[] payload)
    {
        var directory = Path.GetDirectoryName(path)!;
        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.WriteThrough))
            {
                stream.Write(payload);
                stream.Flush(true);
            }
            EnterprisePathGuard.ValidateExistingPathWithin(
                temporary, directory, requireDirectory: false);
            File.Move(temporary, path);
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch { }
        }
    }
}
#endif
