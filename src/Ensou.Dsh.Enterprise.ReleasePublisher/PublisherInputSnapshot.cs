using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

internal sealed class PublisherInputSnapshot : IDisposable
{
    private const int MaximumConfigBytes = 4 * 1024 * 1024;
    private const int MaximumPrivateKeyBytes = 1024 * 1024;

    private readonly PublisherInputStaging _staging;
    private PublisherPrivateKeyLease? _privateKey;

    private PublisherInputSnapshot(
        PublisherInputStaging staging,
        PublisherConfig config,
        string configSha256,
        string inputSetSha256,
        PublisherRuntimeAdmissionTrust runtimeAdmissionTrust,
        PublisherPluginAdmissionTrust? pluginAdmissionTrust,
        PublisherPluginPromotionJournalTrust? pluginPromotionJournalTrust,
        PublisherPrivateKeyLease? privateKey,
        IReadOnlyList<PublisherSnapshotArtifact> artifacts)
    {
        _staging = staging;
        Config = config;
        ConfigSha256 = configSha256;
        InputSetSha256 = inputSetSha256;
        RuntimeAdmissionTrust = runtimeAdmissionTrust;
        PluginAdmissionTrust = pluginAdmissionTrust;
        PluginPromotionJournalTrust = pluginPromotionJournalTrust;
        _privateKey = privateKey;
        Artifacts = artifacts;
    }

    public PublisherConfig Config { get; }
    public string ConfigSha256 { get; }
    public string InputSetSha256 { get; }
    public PublisherRuntimeAdmissionTrust RuntimeAdmissionTrust { get; }
    public PublisherPluginAdmissionTrust? PluginAdmissionTrust { get; }
    public PublisherPluginPromotionJournalTrust? PluginPromotionJournalTrust { get; }
    public IReadOnlyList<PublisherSnapshotArtifact> Artifacts { get; }
    internal string StagingRootPath => _staging.RootPath;

    public static PublisherInputSnapshot Capture(
        PublisherArguments arguments,
        JsonSerializerOptions jsonOptions)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        return CaptureCore(
            arguments.ConfigPath,
            arguments.PrivateKeyPath,
            captureJournalAuthorization: true,
            jsonOptions);
    }

    // Intent generation deliberately snapshots the same config, artifacts, and
    // promotion evidence as publishing, but never opens a release private key
    // and never needs the future authorization output to exist yet.
    public static PublisherInputSnapshot CaptureIntent(
        string configPath,
        JsonSerializerOptions jsonOptions)
        => CaptureCore(
            configPath,
            privateKeyPath: null,
            captureJournalAuthorization: false,
            jsonOptions);

    private static PublisherInputSnapshot CaptureCore(
        string configPath,
        string? privateKeyPath,
        bool captureJournalAuthorization,
        JsonSerializerOptions jsonOptions)
    {
        if (string.IsNullOrWhiteSpace(configPath))
        {
            throw new ArgumentException("Publisher config path is required.", nameof(configPath));
        }
        if (captureJournalAuthorization && string.IsNullOrWhiteSpace(privateKeyPath))
        {
            throw new ArgumentException("Publisher private key path is required.", nameof(privateKeyPath));
        }
        ArgumentNullException.ThrowIfNull(jsonOptions);
        var staging = PublisherInputStaging.Create();
        PublisherPrivateKeyLease? privateKey = null;
        try
        {
            var configInput = staging.Capture(configPath);
            var configBytes = configInput.ReadAllBytes(MaximumConfigBytes);
            var sourceConfig = JsonSerializer.Deserialize<PublisherConfig>(
                configBytes,
                jsonOptions) ?? throw new InvalidDataException("Publisher config is empty.");
            // Resolve the environment-owned runtime trust root before opening
            // artifact evidence. This preserves the trust-boundary diagnostic
            // and prevents unrelated artifact inputs from masking a missing or
            // forbidden production trust configuration.
            _ = PublisherRuntimeAdmissionTrustResolver.Resolve(sourceConfig);
            sourceConfig.ValidateStructure();

            privateKey = privateKeyPath is null
                ? null
                : PublisherPrivateKeyLease.Open(privateKeyPath);
            var artifacts = new List<PublisherSnapshotArtifact>(sourceConfig.Artifacts.Count);
            foreach (var input in sourceConfig.Artifacts)
            {
                var artifactFile = staging.Capture(input.FilePath);
                PublisherStagedInputFile? metadataFile = null;
                PublisherStagedInputFile? promotionHandoffFile = null;
                PublisherPluginPromotionSnapshot? pluginPromotion = null;
                PublisherStagedInputFile? sourceRuntimeMetadataFile = null;
                PublisherStagedInputFile? organizationAdmissionReceiptFile = null;
                if (input.PolicyMetadataPath is not null)
                {
                    metadataFile = staging.Capture(input.PolicyMetadataPath);
                }
                if (input.PluginPromotionHandoffPath is not null)
                {
                    promotionHandoffFile = staging.Capture(input.PluginPromotionHandoffPath);
                    var discovered = PublisherPluginPromotionAdmission.Discover(
                        promotionHandoffFile.ReadAllBytes(
                            PublisherPluginPromotionAdmission.MaximumHandoffBytes));
                    pluginPromotion = new PublisherPluginPromotionSnapshot(
                        discovered,
                        Path.GetFullPath(input.FilePath),
                        Path.GetFullPath(input.PolicyMetadataPath!),
                        Path.GetFullPath(input.PluginHarnessCompatibilityReceiptPath!),
                        Path.GetFullPath(input.PluginGenerationReservationPath!),
                        Path.GetFullPath(input.PluginGenerationLedgerPath!),
                        Path.GetFullPath(input.PluginOrganizationAdmissionReceiptPath!),
                        Path.GetFullPath(input.PluginPromotionJournalAuthorizationPath!),
                        promotionHandoffFile,
                        staging.Capture(input.PluginHarnessCompatibilityReceiptPath!),
                        staging.Capture(input.PluginGenerationReservationPath!),
                        staging.Capture(input.PluginGenerationLedgerPath!),
                        staging.Capture(input.PluginOrganizationAdmissionReceiptPath!),
                        captureJournalAuthorization
                            ? staging.Capture(input.PluginPromotionJournalAuthorizationPath!)
                            : null);
                }
                if (input.SourceRuntimeMetadataPath is not null)
                {
                    sourceRuntimeMetadataFile = staging.Capture(input.SourceRuntimeMetadataPath);
                }
                if (input.OrganizationAdmissionReceiptPath is not null)
                {
                    organizationAdmissionReceiptFile = staging.Capture(
                        input.OrganizationAdmissionReceiptPath);
                }
                var stagedInput = input with
                {
                    FilePath = artifactFile.StagedPath,
                    PolicyMetadataPath = metadataFile?.StagedPath,
                    PluginPromotionHandoffPath = promotionHandoffFile?.StagedPath,
                    PluginHarnessCompatibilityReceiptPath =
                        pluginPromotion?.CompatibilityReceipt.StagedPath,
                    PluginGenerationReservationPath = pluginPromotion?.Reservation.StagedPath,
                    PluginGenerationLedgerPath = pluginPromotion?.Ledger.StagedPath,
                    PluginOrganizationAdmissionReceiptPath =
                        pluginPromotion?.OrganizationAdmissionReceipt.StagedPath,
                    // The authorization is intentionally not captured for an
                    // intent-only run. Its configured absolute destination is
                    // retained for structural validation, while full publish
                    // always snapshots the actual file before consuming it.
                    PluginPromotionJournalAuthorizationPath =
                        pluginPromotion?.JournalAuthorization?.StagedPath
                        ?? input.PluginPromotionJournalAuthorizationPath,
                    SourceRuntimeMetadataPath = sourceRuntimeMetadataFile?.StagedPath,
                    OrganizationAdmissionReceiptPath = organizationAdmissionReceiptFile?.StagedPath,
                };
                artifacts.Add(new PublisherSnapshotArtifact(
                    stagedInput,
                    artifactFile,
                    metadataFile,
                    pluginPromotion,
                    sourceRuntimeMetadataFile,
                    organizationAdmissionReceiptFile));
            }

            var stagedConfig = sourceConfig with
            {
                Artifacts = artifacts.Select(value => value.Input).ToArray(),
            };
            var admissionTrusts = stagedConfig.Validate(artifacts);
            return new PublisherInputSnapshot(
                staging,
                stagedConfig,
                configInput.Sha256,
                staging.ComputeIdentitySha256(),
                admissionTrusts.Runtime,
                admissionTrusts.Plugin,
                admissionTrusts.PluginPromotionJournal,
                privateKey,
                artifacts);
        }
        catch
        {
            try
            {
                privateKey?.Dispose();
            }
            finally
            {
                staging.Dispose();
            }
            throw;
        }
    }

    public byte[] ReadPrivateKeyBytes()
    {
        var privateKey = _privateKey
            ?? throw new InvalidOperationException("Publisher private key was already consumed.");
        return privateKey.ReadAllBytes(MaximumPrivateKeyBytes);
    }

    public void Dispose()
    {
        try
        {
            Interlocked.Exchange(ref _privateKey, null)?.Dispose();
        }
        finally
        {
            _staging.Dispose();
        }
    }
}

internal sealed class PublisherPrivateKeyLease : IDisposable
{
    private readonly object _gate = new();
    private readonly PublisherFileIdentity _identity;
    private readonly long _length;
    private FileStream? _readLock;
    private bool _consumed;

    private PublisherPrivateKeyLease(
        string sourcePath,
        PublisherFileIdentity identity,
        long length,
        FileStream readLock)
    {
        SourcePath = sourcePath;
        _identity = identity;
        _length = length;
        _readLock = readLock;
    }

    public string SourcePath { get; }

    public static PublisherPrivateKeyLease Open(string sourcePath)
    {
        var fullPath = Path.GetFullPath(sourcePath);
        FileStream? readLock = null;
        try
        {
            // This is deliberately the original absolute key path. FileShare.Read
            // denies writes and delete/rename replacement while the signer is
            // alive, without ever materializing key bytes below staging/temp.
            readLock = PublisherSafeFile.OpenLockedRead(fullPath);
            var identity = PublisherSafeFile.GetIdentity(readLock);
            PublisherSafeFile.RequireExpectedPathAndRegularFile(
                readLock,
                fullPath);
            return new PublisherPrivateKeyLease(
                fullPath,
                identity,
                readLock.Length,
                readLock);
        }
        catch
        {
            readLock?.Dispose();
            throw;
        }
    }

    public byte[] ReadAllBytes(int maximumBytes)
    {
        lock (_gate)
        {
            var stream = _readLock
                ?? throw new ObjectDisposedException(
                    nameof(PublisherPrivateKeyLease));
            if (_consumed)
            {
                throw new InvalidOperationException(
                    "Publisher private key was already consumed.");
            }
            if (_length is <= 0
                || _length > maximumBytes
                || _length > int.MaxValue)
            {
                throw new InvalidDataException(
                    "Publisher private key size is invalid.");
            }

            var bytes = new byte[checked((int)_length)];
            try
            {
                RequireOriginalIdentity(stream);
                stream.Position = 0;
                stream.ReadExactly(bytes);
                if (stream.Position != _length || stream.Length != _length)
                {
                    throw new IOException(
                        "Publisher private key read was incomplete.");
                }
                RequireOriginalIdentity(stream);
                _consumed = true;
                return bytes;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(bytes);
                throw;
            }
            finally
            {
                stream.Position = 0;
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _readLock?.Dispose();
            _readLock = null;
        }
    }

    private void RequireOriginalIdentity(FileStream stream)
    {
        PublisherSafeFile.RequireExpectedPathAndRegularFile(
            stream,
            SourcePath);
        if (PublisherSafeFile.GetIdentity(stream) != _identity)
        {
            throw new IOException(
                "Publisher private key handle identity changed after capture.");
        }
    }
}

internal sealed record PublisherSnapshotArtifact(
    PublisherArtifact Input,
    PublisherStagedInputFile File,
    PublisherStagedInputFile? PolicyMetadata,
    PublisherPluginPromotionSnapshot? PluginPromotion,
    PublisherStagedInputFile? SourceRuntimeMetadata,
    PublisherStagedInputFile? OrganizationAdmissionReceipt);

internal sealed class PublisherInputStaging : IDisposable
{
    private const string StagingPrefix = "ensou-dsh-release-publisher-";

    private readonly List<PublisherStagedInputFile> _files = [];
    private bool _disposed;

    private PublisherInputStaging(string rootPath)
    {
        RootPath = rootPath;
    }

    public string RootPath { get; }

    public static PublisherInputStaging Create()
    {
        var tempRoot = Path.GetFullPath(Path.GetTempPath());
        PublisherPathGuard.RequireSafeExistingDirectory(tempRoot);
        var root = Directory.CreateTempSubdirectory(StagingPrefix).FullName;
        try
        {
            PublisherPathGuard.RequireSafeExistingDirectory(root);
            return new PublisherInputStaging(root);
        }
        catch
        {
            Directory.Delete(root);
            throw;
        }
    }

    public PublisherStagedInputFile Capture(string sourcePath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var fileName = Path.GetFileName(sourcePath);
        if (string.IsNullOrWhiteSpace(fileName)
            || !string.Equals(fileName, Path.GetFileName(fileName), StringComparison.Ordinal))
        {
            throw new InvalidDataException("Publisher input path must end in a filename.");
        }
        var inputDirectory = Path.Combine(RootPath, $"input-{_files.Count:D3}");
        Directory.CreateDirectory(inputDirectory);
        PublisherPathGuard.RequireSafeExistingDirectory(inputDirectory);
        var stagedPath = Path.Combine(inputDirectory, fileName);
        try
        {
            var staged = PublisherStagedInputFile.Capture(
                sourcePath,
                stagedPath,
                inputDirectory);
            _files.Add(staged);
            return staged;
        }
        catch
        {
            if (Directory.Exists(inputDirectory)
                && !Directory.EnumerateFileSystemEntries(inputDirectory).Any())
            {
                Directory.Delete(inputDirectory);
            }
            throw;
        }
    }

    public string ComputeIdentitySha256()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ensou-enterprise-release-publisher-input-set-v1\0"u8);
        Span<byte> length = stackalloc byte[sizeof(long)];
        foreach (var file in _files)
        {
            AppendIdentityValue(hash, Path.GetFileName(file.StagedPath));
            System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(
                length,
                file.Length);
            hash.AppendData(length);
            AppendIdentityValue(hash, file.Sha256);
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static void AppendIdentityValue(IncrementalHash hash, string value)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(
            length,
            bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }

    public PublisherStagedInputFile CaptureFromLockedHandle(
        FileStream source,
        string sourcePath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(source);
        var sourceFullPath = Path.GetFullPath(sourcePath);
        PublisherSafeFile.RequireExpectedPathAndRegularFile(source, sourceFullPath);
        var fileName = Path.GetFileName(sourceFullPath);
        if (string.IsNullOrWhiteSpace(fileName)
            || !string.Equals(fileName, Path.GetFileName(fileName), StringComparison.Ordinal))
        {
            throw new InvalidDataException("Publisher input path must end in a filename.");
        }
        var inputDirectory = Path.Combine(RootPath, $"input-{_files.Count:D3}");
        Directory.CreateDirectory(inputDirectory);
        PublisherPathGuard.RequireSafeExistingDirectory(inputDirectory);
        var stagedPath = Path.Combine(inputDirectory, fileName);
        PublisherStagedInputFile? staged = null;
        try
        {
            staged = PublisherStagedInputFile.CaptureFromLockedHandle(
                source,
                stagedPath,
                inputDirectory);
            PublisherSafeFile.RequireExpectedPathAndRegularFile(source, sourceFullPath);
            _files.Add(staged);
            return staged;
        }
        catch
        {
            staged?.Delete();
            if (Directory.Exists(inputDirectory)
                && !Directory.EnumerateFileSystemEntries(inputDirectory).Any())
            {
                Directory.Delete(inputDirectory);
            }
            throw;
        }
    }

    public PublisherStagedInputFile CaptureAlongside(
        PublisherStagedInputFile sibling,
        string sourcePath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(sibling);
        if (!_files.Contains(sibling))
        {
            throw new InvalidOperationException(
                "Publisher staging does not own the requested sibling input file.");
        }

        var fileName = Path.GetFileName(sourcePath);
        if (string.IsNullOrWhiteSpace(fileName)
            || !string.Equals(fileName, Path.GetFileName(fileName), StringComparison.Ordinal))
        {
            throw new InvalidDataException("Publisher input path must end in a filename.");
        }
        if (string.Equals(
            fileName,
            Path.GetFileName(sibling.StagedPath),
            StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Publisher alongside input must have a distinct filename.");
        }

        var staged = PublisherStagedInputFile.Capture(
            sourcePath,
            Path.Combine(sibling.StagingDirectory, fileName),
            sibling.StagingDirectory);
        _files.Add(staged);
        return staged;
    }

    public void Delete(PublisherStagedInputFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (!_files.Contains(file))
        {
            throw new InvalidOperationException(
                "Publisher staging does not own the requested input file.");
        }
        file.Delete();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        List<Exception>? failures = null;
        for (var index = _files.Count - 1; index >= 0; index--)
        {
            try
            {
                _files[index].Delete();
            }
            catch (Exception exception)
            {
                (failures ??= []).Add(exception);
            }
        }
        try
        {
            if (Directory.Exists(RootPath))
            {
                PublisherPathGuard.RequireSafeExistingDirectory(RootPath);
                Directory.Delete(RootPath);
            }
        }
        catch (Exception exception)
        {
            (failures ??= []).Add(exception);
        }
        if (failures is not null)
        {
            throw new AggregateException(
                "Publisher private staging cleanup failed.",
                failures);
        }
    }
}

internal sealed class PublisherStagedInputFile
{
    private const int CopyBufferBytes = 1024 * 1024;

    private readonly object _gate = new();
    private FileStream? _readLock;
    private bool _deleted;

    private PublisherStagedInputFile(
        string stagedPath,
        string stagingDirectory,
        long length,
        string sha256,
        FileStream readLock)
    {
        StagedPath = stagedPath;
        StagingDirectory = stagingDirectory;
        Length = length;
        Sha256 = sha256;
        _readLock = readLock;
    }

    public string StagedPath { get; }
    public string StagingDirectory { get; }
    public long Length { get; }
    public string Sha256 { get; }

    public static PublisherStagedInputFile Capture(
        string sourcePath,
        string stagedPath,
        string stagingDirectory)
    {
        var sourceFullPath = Path.GetFullPath(sourcePath);
        PublisherPathGuard.RequireSafeExistingFile(sourceFullPath);
        using var source = PublisherSafeFile.OpenLockedRead(sourceFullPath);
        return CaptureFromLockedHandle(source, stagedPath, stagingDirectory);
    }

    public static PublisherStagedInputFile CaptureFromLockedHandle(
        FileStream source,
        string stagedPath,
        string stagingDirectory)
    {
        ArgumentNullException.ThrowIfNull(source);
        _ = PublisherSafeFile.GetIdentity(source);
        var stagedFullPath = Path.GetFullPath(stagedPath);
        PublisherPathGuard.RequireSafeExistingDirectory(stagingDirectory);

        PublisherFileIdentity stagedIdentity;
        long length;
        string sha256;
        FileStream? readLock = null;
        try
        {
            using (var destination = new FileStream(
                stagedFullPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                CopyBufferBytes,
                FileOptions.SequentialScan))
            using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                var sourceLength = source.Length;
                source.Position = 0;
                var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferBytes);
                long total = 0;
                try
                {
                    while (true)
                    {
                        var read = source.Read(buffer, 0, buffer.Length);
                        if (read == 0)
                        {
                            break;
                        }
                        total = checked(total + read);
                        if (total > sourceLength)
                        {
                            throw new IOException(
                                "Publisher input grew while its snapshot was captured.");
                        }
                        hash.AppendData(buffer, 0, read);
                        destination.Write(buffer, 0, read);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buffer);
                    ArrayPool<byte>.Shared.Return(buffer);
                }
                if (total != sourceLength || source.Length != sourceLength)
                {
                    throw new IOException(
                        "Publisher input length changed while its snapshot was captured.");
                }
                source.Position = 0;
                destination.Flush(flushToDisk: true);
                if (destination.Length != total)
                {
                    throw new IOException("Publisher staging copy length is invalid.");
                }
                length = total;
                sha256 = Convert.ToHexStringLower(hash.GetHashAndReset());
                stagedIdentity = PublisherSafeFile.GetIdentity(destination);
            }

            readLock = PublisherSafeFile.OpenLockedRead(stagedFullPath);
            if (PublisherSafeFile.GetIdentity(readLock) != stagedIdentity
                || readLock.Length != length
                || !string.Equals(
                    PublisherSafeFile.HashAndRewind(readLock),
                    sha256,
                    StringComparison.Ordinal))
            {
                throw new IOException(
                    "Publisher staging path changed or its bytes differ from the captured input.");
            }
            return new PublisherStagedInputFile(
                stagedFullPath,
                Path.GetFullPath(stagingDirectory),
                length,
                sha256,
                readLock);
        }
        catch
        {
            readLock?.Dispose();
            if (File.Exists(stagedFullPath))
            {
                File.Delete(stagedFullPath);
            }
            throw;
        }
    }

    public byte[] ReadAllBytes(int maximumBytes)
    {
        if (Length is <= 0 || Length > maximumBytes || Length > int.MaxValue)
        {
            throw new InvalidDataException("Publisher staged input size is invalid.");
        }
        var bytes = new byte[checked((int)Length)];
        lock (_gate)
        {
            var stream = RequireReadLock();
            stream.Position = 0;
            stream.ReadExactly(bytes);
            if (stream.Position != Length)
            {
                throw new IOException("Publisher staged input read was incomplete.");
            }
            stream.Position = 0;
        }
        if (!string.Equals(
            Convert.ToHexStringLower(SHA256.HashData(bytes)),
            Sha256,
            StringComparison.Ordinal))
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new IOException(
                "Publisher staged input bytes changed after their immutable snapshot was captured.");
        }
        return bytes;
    }

    public string ComputeArchiveTreeSha256()
    {
        lock (_gate)
        {
            var stream = RequireReadLock();
            stream.Position = 0;
            try
            {
                return EnterpriseReleaseArchiveTreeHash.Compute(stream);
            }
            finally
            {
                stream.Position = 0;
            }
        }
    }

    public void CopyNewVerified(string destination)
    {
        var destinationFullPath = Path.GetFullPath(destination);
        PublisherPathGuard.RequireSafeDestination(destinationFullPath);
        lock (_gate)
        {
            var source = RequireReadLock();
            source.Position = 0;
            using var output = new FileStream(
                destinationFullPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                CopyBufferBytes,
                FileOptions.SequentialScan);
            source.CopyTo(output, CopyBufferBytes);
            output.Flush(flushToDisk: true);
            source.Position = 0;
        }
        using var verification = PublisherSafeFile.OpenLockedRead(destinationFullPath);
        if (verification.Length != Length
            || !string.Equals(
                PublisherSafeFile.HashAndRewind(verification),
                Sha256,
                StringComparison.Ordinal))
        {
            throw new IOException("Publisher output artifact verification failed.");
        }
    }

    public void Delete()
    {
        lock (_gate)
        {
            if (_deleted)
            {
                return;
            }
            _readLock?.Dispose();
            _readLock = null;
            if (File.Exists(StagedPath))
            {
                PublisherPathGuard.RequireSafeExistingFile(StagedPath);
                File.Delete(StagedPath);
            }
            if (Directory.Exists(StagingDirectory))
            {
                PublisherPathGuard.RequireSafeExistingDirectory(StagingDirectory);
                if (!Directory.EnumerateFileSystemEntries(StagingDirectory).Any())
                {
                    Directory.Delete(StagingDirectory);
                }
            }
            _deleted = true;
        }
    }

    private FileStream RequireReadLock() => _readLock
        ?? throw new ObjectDisposedException(nameof(PublisherStagedInputFile));
}

internal readonly record struct PublisherFileIdentity(
    uint VolumeSerialNumber,
    ulong FileIndex);

internal static class PublisherSafeFile
{
    private const uint FileNameNormalized = 0;
    private const uint VolumeNameDos = 0;

    public static FileStream OpenLockedRead(string path)
    {
        var fullPath = Path.GetFullPath(path);
        PublisherPathGuard.RequireSafeExistingFile(fullPath);
        var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        try
        {
            RequireExpectedPathAndRegularFile(stream, fullPath);
            PublisherPathGuard.RequireSafeExistingFile(fullPath);
            using var probe = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                1,
                FileOptions.None);
            RequireExpectedPathAndRegularFile(probe, fullPath);
            if (GetIdentity(stream) != GetIdentity(probe))
            {
                throw new IOException("Publisher input path changed while it was opened.");
            }
            stream.Position = 0;
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public static PublisherFileIdentity GetIdentity(FileStream stream)
    {
        if (!GetFileInformationByHandle(stream.SafeFileHandle, out var information))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        if ((information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0
            || (information.FileAttributes & (uint)FileAttributes.Directory) != 0)
        {
            throw new InvalidDataException(
                "Publisher input handle must refer to a regular, non-linked file.");
        }
        return new PublisherFileIdentity(
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
    }

    public static string HashAndRewind(FileStream stream)
    {
        stream.Position = 0;
        var hash = Convert.ToHexStringLower(SHA256.HashData(stream));
        stream.Position = 0;
        return hash;
    }

    internal static void RequireExpectedPathAndRegularFile(
        FileStream stream,
        string expectedPath)
    {
        _ = GetIdentity(stream);
        var finalPath = GetFinalPath(stream.SafeFileHandle);
        if (!string.Equals(
            NormalizePath(expectedPath),
            NormalizePath(finalPath),
            StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Publisher input handle resolved to a different filesystem path.");
        }
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (true)
        {
            var buffer = new StringBuilder(capacity);
            var length = GetFinalPathNameByHandle(
                handle,
                buffer,
                (uint)buffer.Capacity,
                FileNameNormalized | VolumeNameDos);
            if (length == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if (length < buffer.Capacity)
            {
                return buffer.ToString();
            }
            capacity = checked((int)length + 1);
        }
    }

    private static string NormalizePath(string path)
    {
        var normalized = path;
        if (normalized.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "\\\\" + normalized[8..];
        }
        else if (normalized.StartsWith("\\\\?\\", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(normalized));
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder path,
        uint pathLength,
        uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}
