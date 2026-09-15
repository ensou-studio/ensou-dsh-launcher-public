using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Personal.ReleasePublisher;

public sealed record PersonalReleasePublishResult(
    string OutputManifestPath,
    long SizeBytes,
    string Sha256,
    VerifiedPersonalReleaseSetManifest Verified);

public sealed class PersonalReleasePublisher
{
    private readonly Action<PersonalPublisherSigningLedgerCommitStage>? _ledgerCheckpoint;
    private readonly string? _ledgerAnchorAuthorityRoot;
    private readonly Action? _beforeFinalCancellationCheckpoint;

    public PersonalReleasePublisher()
        : this(null, null, null)
    {
    }

    internal PersonalReleasePublisher(
        Action<PersonalPublisherSigningLedgerCommitStage>? ledgerCheckpoint,
        string? ledgerAnchorAuthorityRoot,
        Action? beforeFinalCancellationCheckpoint = null)
    {
        _ledgerCheckpoint = ledgerCheckpoint;
        _ledgerAnchorAuthorityRoot = ledgerAnchorAuthorityRoot;
        _beforeFinalCancellationCheckpoint = beforeFinalCancellationCheckpoint;
    }

    public async Task<PersonalReleasePublishResult> PublishAsync(
        PersonalReleasePublisherConfig config,
        ECDsa signingKey,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(signingKey);
        config = PersonalReleasePublisherConfig.CaptureTransactionSnapshot(config);
        ValidateConfig(config, nowUtc);

        var outputPath = Path.GetFullPath(config.OutputManifestPath);
        var outputRoot = Path.GetDirectoryName(outputPath)
            ?? throw new InvalidDataException("Personal publisher output path has no parent directory.");
        RejectLinkAncestors(outputRoot, "output directory");
        var configSha256 = PersonalReleasePublisherConfig
            .ComputeTransactionSha256(config);
        using var signingLedger = PersonalPublisherSigningLedger.Acquire(
            config,
            _ledgerCheckpoint,
            _ledgerAnchorAuthorityRoot);

        await using var candidateInputs = await ImmutableCandidateInputs.CaptureAsync(
            config,
            cancellationToken).ConfigureAwait(false);
        var artifacts = new List<PersonalReleaseArtifact>(2);
        foreach (var input in config.Artifacts)
        {
            _ = await PersonalReleaseArtifactInstaller.VerifyCandidateArchiveAsync(
                input.SourcePath,
                input.CompleteTreeManifestPath,
                input.Component,
                input.ReleaseId,
                cancellationToken).ConfigureAwait(false);
            var artifactDescriptor = candidateInputs.Get(input.SourcePath).Descriptor;
            var treeDescriptor = candidateInputs.Get(input.CompleteTreeManifestPath).Descriptor;
            if (artifactDescriptor.SizeBytes <= 0
                || treeDescriptor.SizeBytes <= 0
                || treeDescriptor.SizeBytes > 64L * 1024 * 1024)
            {
                throw new InvalidDataException(
                    "Personal publisher artifact and bounded complete-tree manifest must not be empty.");
            }
            artifacts.Add(new PersonalReleaseArtifact
            {
                Component = input.Component,
                ReleaseId = input.ReleaseId,
                Uri = input.Uri,
                SizeBytes = artifactDescriptor.SizeBytes,
                Sha256 = artifactDescriptor.Sha256,
                CompleteTreeSha256 = treeDescriptor.Sha256,
                Signature = null,
            });
        }
        await candidateInputs.RequireAllPathsMatchAsync(cancellationToken)
            .ConfigureAwait(false);

        var policy = new PersonalReleaseTrustPolicy
        {
            Product = PersonalReleaseSetContract.Product,
            Environment = config.Environment,
            Channel = config.Channel,
            ArtifactOrigin = config.ArtifactOrigin,
            StartupStubVersion = config.CertifiedStartupStubVersion,
            TrustedKeys = config.TrustedKeys,
        };
        var inputSetSha256 = candidateInputs.ComputeIdentitySha256(config);
        var committedManifestBytes = signingLedger.TryReadExactCommittedManifest(
            outputPath,
            configSha256,
            inputSetSha256);
        if (committedManifestBytes is not null)
        {
            var verifiedCommitted = PersonalReleaseSetValidator.ParseAndVerify(
                committedManifestBytes,
                policy,
                nowUtc);
            RequireConfiguredSigningKey(verifiedCommitted, config.SigningKeyId);
            return CreateResult(
                outputPath,
                committedManifestBytes,
                verifiedCommitted);
        }
        if (File.Exists(outputPath) || Directory.Exists(outputPath))
        {
            throw new IOException(
                "Personal publisher output already exists but is not the exact authenticated committed publication for this config and input set.");
        }
        signingLedger.RequireForward(config);

        var unsigned = new PersonalReleaseSetManifest
        {
            SchemaVersion = PersonalReleaseSetContract.SchemaVersion,
            Product = PersonalReleaseSetContract.Product,
            Environment = config.Environment,
            Channel = config.Channel,
            ReleaseSetId = config.ReleaseSetId,
            Provenance = config.Provenance,
            Generation = config.Generation,
            Sequence = config.Sequence,
            MinAcceptedSequence = config.MinAcceptedSequence,
            IssuedAtUtc = config.IssuedAtUtc,
            ExpiresAtUtc = config.ExpiresAtUtc,
            MaximumOfflineGraceSeconds = config.MaximumOfflineGraceSeconds,
            StartupStub = config.StartupStub,
            RevokedReleaseSetIds = config.RevokedReleaseSetIds.ToArray(),
            Artifacts = artifacts,
            Signature = null,
        };
        var signed = PersonalReleaseSetSigner.Sign(unsigned, config.SigningKeyId, signingKey);
        var manifestBytes = PersonalReleaseSetJson.SerializeSigned(signed);
        var verifiedBeforeWrite = PersonalReleaseSetValidator.ParseAndVerify(
            manifestBytes,
            policy,
            nowUtc);
        RequireConfiguredSigningKey(verifiedBeforeWrite, config.SigningKeyId);

        _beforeFinalCancellationCheckpoint?.Invoke();
        await candidateInputs.RequireAllPathsMatchAsync(CancellationToken.None)
            .ConfigureAwait(false);

        // This is the final cancellable boundary. The signed manifest has only
        // existed in memory so far. From the first DPAPI-protected pending write
        // onward, commit, recovery receipt, cleanup, and readback are one
        // non-cancellable completion path.
        cancellationToken.ThrowIfCancellationRequested();
        signingLedger.Commit(
            config,
            signed,
            manifestBytes,
            outputPath,
            configSha256,
            inputSetSha256,
            nowUtc);

        var persistedBytes = await File.ReadAllBytesAsync(
                outputPath,
                CancellationToken.None)
            .ConfigureAwait(false);
        var verifiedAfterWrite = PersonalReleaseSetValidator.ParseAndVerify(
            persistedBytes,
            policy,
            nowUtc);
        RequireSameManifest(verifiedBeforeWrite, verifiedAfterWrite);
        RequireConfiguredSigningKey(verifiedAfterWrite, config.SigningKeyId);

        return CreateResult(outputPath, persistedBytes, verifiedAfterWrite);
    }

    private static PersonalReleasePublishResult CreateResult(
        string outputPath,
        ReadOnlySpan<byte> manifestBytes,
        VerifiedPersonalReleaseSetManifest verified) => new(
        outputPath,
        manifestBytes.Length,
        Convert.ToHexStringLower(SHA256.HashData(manifestBytes)),
        verified);

    private static void RequireConfiguredSigningKey(
        VerifiedPersonalReleaseSetManifest verified,
        string signingKeyId)
    {
        if (verified.Manifest.Signature is null
            || !string.Equals(
                verified.Manifest.Signature.KeyId,
                signingKeyId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal publisher committed manifest is not signed by the configured release key ID.");
        }
    }

    private static void ValidateConfig(
        PersonalReleasePublisherConfig config,
        DateTimeOffset nowUtc)
    {
        if (config.SchemaVersion != 1
            || nowUtc.Offset != TimeSpan.Zero
            || config.IssuedAtUtc.Offset != TimeSpan.Zero
            || config.ExpiresAtUtc.Offset != TimeSpan.Zero
            || config.Provenance is null
            || config.StartupStub is null
            || string.IsNullOrWhiteSpace(config.CertifiedStartupStubVersion)
            || config.RevokedReleaseSetIds is null
            || config.ArtifactOrigin is null
            || config.TrustedKeys is null
            || config.Artifacts is null
            || config.Artifacts.Count != 2
            || !config.Artifacts.Select(artifact => artifact.Component).SequenceEqual(
                new[]
                {
                    PersonalReleaseSetContract.ClientBundleComponent,
                    PersonalReleaseSetContract.RuntimeComponent,
                },
                StringComparer.Ordinal))
        {
            throw new InvalidDataException("Personal publisher config shape is invalid.");
        }
        PersonalReleaseVersion.Compare(
            config.CertifiedStartupStubVersion,
            config.CertifiedStartupStubVersion);
        PersonalReleaseSetValidator.ValidateToken(config.SigningKeyId, "publisher keyId", 64);
        PersonalReleaseSetValidator.ValidateReleaseId(config.ReleaseSetId, "publisher releaseSetId");
        ArgumentException.ThrowIfNullOrWhiteSpace(config.SigningPrivateKeyPkcs8Path);
        ArgumentException.ThrowIfNullOrWhiteSpace(config.SigningLedgerRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(config.OutputManifestPath);
        if (!Path.IsPathFullyQualified(config.SigningPrivateKeyPkcs8Path)
            || !Path.IsPathFullyQualified(config.SigningLedgerRoot)
            || !Path.IsPathFullyQualified(config.OutputManifestPath))
        {
            throw new InvalidDataException(
                "Personal publisher key, signing ledger, and output paths must be absolute.");
        }
        foreach (var artifact in config.Artifacts)
        {
            PersonalReleaseSetValidator.ValidateReleaseId(
                artifact.ReleaseId,
                "publisher artifact releaseId");
            ArgumentException.ThrowIfNullOrWhiteSpace(artifact.SourcePath);
            ArgumentException.ThrowIfNullOrWhiteSpace(artifact.CompleteTreeManifestPath);
            if (!Path.IsPathFullyQualified(artifact.SourcePath)
                || !Path.IsPathFullyQualified(artifact.CompleteTreeManifestPath))
            {
                throw new InvalidDataException(
                    "Personal publisher artifact and tree-manifest paths must be absolute.");
            }
        }

        var inputPaths = config.Artifacts
            .SelectMany(artifact => new[]
            {
                Path.GetFullPath(artifact.SourcePath),
                Path.GetFullPath(artifact.CompleteTreeManifestPath),
            })
            .ToArray();
        if (inputPaths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != inputPaths.Length
            || inputPaths.Contains(
                Path.GetFullPath(config.OutputManifestPath),
                StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal publisher artifact, tree-manifest, and output paths must be distinct.");
        }
    }

    private static string RequireImmutableInputFile(string path, string field)
    {
        var absolutePath = Path.GetFullPath(path);
        if (!File.Exists(absolutePath))
        {
            throw new FileNotFoundException($"Personal publisher {field} does not exist.", absolutePath);
        }
        RejectReparsePoint(absolutePath, field);
        RejectLinkAncestors(Path.GetDirectoryName(absolutePath)!, field);
        return absolutePath;
    }

    private static void RejectReparsePoint(string path, string field)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"Personal publisher {field} must not be a filesystem link.");
        }
    }

    private static void RejectLinkAncestors(string path, string field)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path));
             current is not null;
             current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    $"Personal publisher {field} path may not cross a filesystem link.");
            }
        }
    }

    private static async Task<FileDescriptor> ComputeFileDescriptorAsync(
        FileStream input,
        CancellationToken cancellationToken)
    {
        input.Position = 0;
        var sizeBytes = input.Length;
        var sha256 = Convert.ToHexStringLower(await SHA256.HashDataAsync(input, cancellationToken)
            .ConfigureAwait(false));
        if (input.Length != sizeBytes)
        {
            throw new IOException("Personal publisher input changed while it was being hashed.");
        }
        input.Position = 0;
        return new FileDescriptor(sizeBytes, sha256);
    }

    private static CandidateFileIdentity RequireCandidateFileIdentity(
        FileStream stream,
        string expectedPath,
        string field)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Personal publisher candidate identity requires Windows file handles.");
        }
        if (!GetFileInformationByHandle(stream.SafeFileHandle, out var information))
        {
            throw new IOException(
                $"Unable to inspect Personal publisher {field} identity.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        var disallowedAttributes = (uint)(
            FileAttributes.Directory | FileAttributes.ReparsePoint);
        if ((information.FileAttributes & disallowedAttributes) != 0
            || information.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                $"Personal publisher {field} must be one ordinary single-link file.");
        }
        var length = checked((long)(
            ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow));
        if (length <= 0)
        {
            throw new InvalidDataException(
                $"Personal publisher {field} must not be empty.");
        }
        var finalPath = GetFinalPath(stream.SafeFileHandle);
        if (!string.Equals(
                NormalizeHandlePath(expectedPath),
                NormalizeHandlePath(finalPath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Personal publisher {field} handle resolved to a different filesystem path.");
        }
        return new CandidateFileIdentity(
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow,
            length);
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
                0);
            if (length == 0)
            {
                throw new IOException(
                    "Unable to resolve Personal publisher candidate handle path.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
            if (length < buffer.Capacity)
            {
                return buffer.ToString();
            }
            capacity = checked((int)length + 1);
        }
    }

    private static string NormalizeHandlePath(string path)
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

    private static void RequireSameCandidate(
        CandidateFileIdentity expectedIdentity,
        FileDescriptor expectedDescriptor,
        CandidateFileIdentity actualIdentity,
        FileDescriptor actualDescriptor,
        string field)
    {
        if (actualIdentity != expectedIdentity
            || actualDescriptor != expectedDescriptor
            || actualIdentity.Length != actualDescriptor.SizeBytes)
        {
            throw new IOException(
                $"Personal publisher {field} path or bytes changed after its locked capture.");
        }
    }

    private static void RequireSameManifest(
        VerifiedPersonalReleaseSetManifest expected,
        VerifiedPersonalReleaseSetManifest actual)
    {
        if (!string.Equals(
                expected.CanonicalSignedManifestSha256,
                actual.CanonicalSignedManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal publisher persisted manifest differs from its pre-write verification.");
        }
    }

    private readonly record struct CandidateFileIdentity(
        uint VolumeSerialNumber,
        ulong FileIndex,
        long Length);

    private sealed record FileDescriptor(long SizeBytes, string Sha256);

    private sealed class ImmutableCandidateInputs : IAsyncDisposable
    {
        private readonly Dictionary<string, ImmutableCandidateInput> _inputs;

        private ImmutableCandidateInputs(
            Dictionary<string, ImmutableCandidateInput> inputs)
        {
            _inputs = inputs;
        }

        public static async Task<ImmutableCandidateInputs> CaptureAsync(
            PersonalReleasePublisherConfig config,
            CancellationToken cancellationToken)
        {
            var inputs = new Dictionary<string, ImmutableCandidateInput>(
                StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var artifact in config.Artifacts)
                {
                    await CaptureOneAsync(
                        artifact.SourcePath,
                        "artifact",
                        inputs,
                        cancellationToken).ConfigureAwait(false);
                    await CaptureOneAsync(
                        artifact.CompleteTreeManifestPath,
                        "complete-tree manifest",
                        inputs,
                        cancellationToken).ConfigureAwait(false);
                }
                return new ImmutableCandidateInputs(inputs);
            }
            catch
            {
                foreach (var input in inputs.Values)
                {
                    await input.DisposeAsync().ConfigureAwait(false);
                }
                throw;
            }
        }

        public ImmutableCandidateInput Get(string path) => _inputs[Path.GetFullPath(path)];

        public async Task RequireAllPathsMatchAsync(
            CancellationToken cancellationToken)
        {
            foreach (var input in _inputs.Values)
            {
                await input.RequireCurrentPathMatchesAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        public string ComputeIdentitySha256(
            PersonalReleasePublisherConfig config)
        {
            ArgumentNullException.ThrowIfNull(config);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            AppendString(hash, "ensou-personal-release-publisher-input-set-v1");
            foreach (var artifact in config.Artifacts)
            {
                var sourcePath = Path.GetFullPath(artifact.SourcePath);
                var treePath = Path.GetFullPath(
                    artifact.CompleteTreeManifestPath);
                var source = Get(sourcePath).Descriptor;
                var tree = Get(treePath).Descriptor;
                AppendString(hash, artifact.Component);
                AppendString(hash, artifact.ReleaseId);
                AppendString(hash, sourcePath.ToUpperInvariant());
                AppendInt64(hash, source.SizeBytes);
                AppendString(hash, source.Sha256);
                AppendString(hash, treePath.ToUpperInvariant());
                AppendInt64(hash, tree.SizeBytes);
                AppendString(hash, tree.Sha256);
            }
            return Convert.ToHexStringLower(hash.GetHashAndReset());
        }

        public async ValueTask DisposeAsync()
        {
            foreach (var input in _inputs.Values)
            {
                await input.DisposeAsync().ConfigureAwait(false);
            }
        }

        private static async Task CaptureOneAsync(
            string path,
            string field,
            IDictionary<string, ImmutableCandidateInput> inputs,
            CancellationToken cancellationToken)
        {
            var absolutePath = RequireImmutableInputFile(path, field);
            var stream = new FileStream(
                absolutePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            try
            {
                var identity = RequireCandidateFileIdentity(
                    stream,
                    absolutePath,
                    field);
                var descriptor = await ComputeFileDescriptorAsync(stream, cancellationToken)
                    .ConfigureAwait(false);
                var identityAfterHash = RequireCandidateFileIdentity(
                    stream,
                    absolutePath,
                    field);
                await using var probe = new FileStream(
                    absolutePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    128 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                var probeIdentity = RequireCandidateFileIdentity(
                    probe,
                    absolutePath,
                    field);
                var probeDescriptor = await ComputeFileDescriptorAsync(
                        probe,
                        cancellationToken)
                    .ConfigureAwait(false);
                RequireSameCandidate(
                    identity,
                    descriptor,
                    identityAfterHash,
                    descriptor,
                    field);
                RequireSameCandidate(
                    identity,
                    descriptor,
                    probeIdentity,
                    probeDescriptor,
                    field);
                inputs.Add(
                    absolutePath,
                    new ImmutableCandidateInput(
                        absolutePath,
                        field,
                        stream,
                        identity,
                        descriptor));
            }
            catch
            {
                await stream.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        private static void AppendString(
            IncrementalHash hash,
            string value)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(value);
            try
            {
                Span<byte> length = stackalloc byte[sizeof(int)];
                BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
                hash.AppendData(length);
                hash.AppendData(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }

        private static void AppendInt64(
            IncrementalHash hash,
            long value)
        {
            Span<byte> bytes = stackalloc byte[sizeof(long)];
            BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
            hash.AppendData(bytes);
        }
    }

    private sealed class ImmutableCandidateInput(
        string path,
        string field,
        FileStream stream,
        CandidateFileIdentity identity,
        FileDescriptor descriptor) : IAsyncDisposable
    {
        public FileDescriptor Descriptor { get; } = descriptor;

        public async Task RequireCurrentPathMatchesAsync(
            CancellationToken cancellationToken)
        {
            var lockedIdentityBefore = RequireCandidateFileIdentity(
                stream,
                path,
                field);
            var lockedDescriptor = await ComputeFileDescriptorAsync(
                    stream,
                    cancellationToken)
                .ConfigureAwait(false);
            var lockedIdentityAfter = RequireCandidateFileIdentity(
                stream,
                path,
                field);
            RejectLinkAncestors(Path.GetDirectoryName(path)!, field);
            await using var probe = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var probeIdentity = RequireCandidateFileIdentity(
                probe,
                path,
                field);
            var probeDescriptor = await ComputeFileDescriptorAsync(
                    probe,
                    cancellationToken)
                .ConfigureAwait(false);
            RequireSameCandidate(
                identity,
                Descriptor,
                lockedIdentityBefore,
                lockedDescriptor,
                field);
            RequireSameCandidate(
                identity,
                Descriptor,
                lockedIdentityAfter,
                lockedDescriptor,
                field);
            RequireSameCandidate(
                identity,
                Descriptor,
                probeIdentity,
                probeDescriptor,
                field);
        }

        public ValueTask DisposeAsync() => stream.DisposeAsync();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

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
