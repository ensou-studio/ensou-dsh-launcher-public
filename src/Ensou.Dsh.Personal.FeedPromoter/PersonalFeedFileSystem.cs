using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.FeedPromoter;

internal sealed record PersonalFeedLayout(
    string Root,
    string StagingRoot,
    string JournalRoot,
    string OperationsRoot,
    string PublicRoot,
    string ReleasesRoot,
    string ChannelsRoot)
{
    public const string IdentityFileName = "feed.identity.json";

    public static PersonalFeedLayout Initialize(string feedRoot)
    {
        var root = PersonalFeedPathGuard.RequireExistingDirectory(feedRoot, "feed root");
        LinuxNative.RequireRootOwnedAndNotWritableByOthers(root, "feed root");
        var identityPath = Path.Combine(root, IdentityFileName);
        if (File.Exists(identityPath))
        {
            return Open(root);
        }
        RequireRecoverableInitializationSubset(root, alreadyValidatedOpenFiles: null);
        PersonalFeedPathGuard.SetDirectoryMode(root, publicRead: true);
        var journal = CreateDirectory(root, "journal", publicRead: false);
        var publicationLockPath = Path.Combine(journal, "publication.lock");
        EnsureLockFile(publicationLockPath);
        var safeLockPath = PersonalFeedPathGuard.RequireRegularFile(
            publicationLockPath,
            "personal feed initialization lock");
        using var initializationLock = new FileStream(
            safeLockPath,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
        if (File.Exists(identityPath))
        {
            return Open(root, [publicationLockPath]);
        }
        RequireRecoverableInitializationSubset(root, [publicationLockPath]);

        _ = CreateDirectory(root, "staging", publicRead: false);
        _ = CreateDirectory(journal, "operations", publicRead: false);
        var publicRoot = CreateDirectory(root, "public", publicRead: true);
        _ = CreateDirectory(publicRoot, "releases", publicRead: true);
        var channels = CreateDirectory(publicRoot, "channels", publicRead: true);
        foreach (var channel in PersonalFeedChannels.All)
        {
            _ = CreateDirectory(channels, channel, publicRead: true);
            var channelJournal = CreateDirectory(journal, channel, publicRead: false);
            EnsureLockFile(Path.Combine(channelJournal, "promotion.lock"));
        }

        var identity = new PersonalFeedIdentity(
            2,
            PersonalReleaseSetContract.Product,
            PersonalReleaseSetContract.ProductionEnvironment,
            Guid.NewGuid().ToString("N"));
        CommitIdentityAtomically(root, identityPath, PersonalFeedJson.Serialize(identity));
        return Open(root, [publicationLockPath]);
    }

    public static PersonalFeedInitializationResult ReadInitializationResult(
        string feedRoot)
    {
        var root = RequireExistingFeedRoot(feedRoot);
        var bytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            Path.Combine(root, IdentityFileName),
            16 * 1024,
            "personal feed identity");
        var identity = PersonalFeedIdentity.Parse(bytes);
        identity.Validate();
        return new PersonalFeedInitializationResult(
            1,
            identity.Product,
            identity.Environment,
            identity.FeedInstanceId,
            PersonalFeedJson.Sha256(bytes));
    }

    public static PersonalFeedLayout Open(
        string feedRoot,
        IReadOnlyCollection<string>? alreadyValidatedOpenFiles = null)
    {
        var root = PersonalFeedPathGuard.RequireExistingDirectory(feedRoot, "feed root");
        var staging = PersonalFeedPathGuard.RequireExactDirectory(root, "staging");
        var journal = PersonalFeedPathGuard.RequireExactDirectory(root, "journal");
        var operations = PersonalFeedPathGuard.RequireExactDirectory(journal, "operations");
        var publicRoot = PersonalFeedPathGuard.RequireExactDirectory(root, "public");
        var releases = PersonalFeedPathGuard.RequireExactDirectory(publicRoot, "releases");
        var channels = PersonalFeedPathGuard.RequireExactDirectory(publicRoot, "channels");
        foreach (var channel in PersonalFeedChannels.All)
        {
            _ = PersonalFeedPathGuard.RequireExactDirectory(channels, channel);
            _ = PersonalFeedPathGuard.RequireExactDirectory(journal, channel);
        }

        var identityPath = Path.Combine(root, IdentityFileName);
        var identityBytes = PersonalFeedPathGuard.ReadBoundedRegularFile(
            identityPath,
            16 * 1024,
            "feed identity");
        PersonalFeedIdentity.Parse(identityBytes).Validate();
        RequireExactNames(
            root,
            [IdentityFileName, "journal", "public", "staging"],
            "feed root");
        RequireExactNames(publicRoot, ["channels", "releases"], "feed public root");
        RequireExactNames(channels, PersonalFeedChannels.All, "feed channel root");
        RequireExactNames(
            journal,
            PersonalFeedChannels.All
                .Append("operations")
                .Append("publication.lock")
                .ToArray(),
            "feed journal root");
        PersonalFeedPathGuard.RequireSafeTree(root, alreadyValidatedOpenFiles);
        LinuxNative.RequireManagedTreeRootOwned(root);
        return new PersonalFeedLayout(
            root,
            staging,
            journal,
            operations,
            publicRoot,
            releases,
            channels);
    }

    public string ChannelRoot(string channel)
    {
        PersonalFeedChannels.Require(channel);
        return PersonalFeedPathGuard.RequireExactDirectory(ChannelsRoot, channel);
    }

    public string ChannelJournalRoot(string channel)
    {
        PersonalFeedChannels.Require(channel);
        return PersonalFeedPathGuard.RequireExactDirectory(JournalRoot, channel);
    }

    private static string CreateDirectory(string parent, string name, bool publicRead)
    {
        PersonalFeedPathGuard.RequireSafeFileName(name, "managed directory name");
        var path = Path.Combine(parent, name);
        Directory.CreateDirectory(path);
        PersonalFeedPathGuard.SetDirectoryMode(path, publicRead);
        LinuxNative.FlushDirectory(parent);
        return path;
    }

    private static string RequireExistingFeedRoot(string feedRoot) =>
        PersonalFeedPathGuard.RequireExistingDirectory(feedRoot, "feed root");

    private static void EnsureLockFile(string path)
    {
        if (!File.Exists(path))
        {
            try
            {
                PersonalFeedPathGuard.WriteNewDurable(path, []);
            }
            catch (IOException) when (File.Exists(path))
            {
                // Another initializer created the one lock first.
            }
        }
        var safe = PersonalFeedPathGuard.RequireRegularFile(path, "personal feed lock");
        if (new FileInfo(safe).Length != 0)
        {
            throw new InvalidDataException("Personal feed lock must be an empty regular file.");
        }
        if (OperatingSystem.IsLinux())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            LinuxNative.FlushDirectory(Path.GetDirectoryName(path)!);
        }
    }

    private static void CommitIdentityAtomically(
        string root,
        string identityPath,
        byte[] identityBytes)
    {
        foreach (var orphan in Directory.EnumerateFiles(root, ".feed.identity.*.tmp"))
        {
            _ = PersonalFeedPathGuard.RequireRegularFile(
                orphan,
                "personal feed identity temporary");
            File.Delete(orphan);
        }
        LinuxNative.FlushDirectory(root);
        var temporary = Path.Combine(root, $".feed.identity.{Guid.NewGuid():N}.tmp");
        try
        {
            PersonalFeedPathGuard.WriteNewDurable(temporary, identityBytes, readOnly: true);
            try
            {
                File.Move(temporary, identityPath);
                LinuxNative.FlushDirectory(root);
            }
            catch (IOException) when (File.Exists(identityPath))
            {
                // The initialization lock should serialize this, but exact Open
                // below safely adopts a completed concurrent initializer.
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
                LinuxNative.FlushDirectory(root);
            }
        }
    }

    private static void RequireRecoverableInitializationSubset(
        string root,
        IReadOnlyCollection<string>? alreadyValidatedOpenFiles)
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(root))
        {
            var name = Path.GetFileName(entry);
            if (name is "staging" or "journal" or "public")
            {
                _ = PersonalFeedPathGuard.RequireExistingDirectory(
                    entry,
                    "personal feed partial initialization directory");
                continue;
            }
            if (name.StartsWith(".feed.identity.", StringComparison.Ordinal)
                && name.EndsWith(".tmp", StringComparison.Ordinal)
                && File.Exists(entry))
            {
                _ = PersonalFeedPathGuard.RequireRegularFile(
                    entry,
                    "personal feed identity temporary");
                continue;
            }
            throw new InvalidDataException(
                "Personal feed initialization found state outside its exact recoverable subset.");
        }
        var staging = Path.Combine(root, "staging");
        if (Directory.Exists(staging) && Directory.EnumerateFileSystemEntries(staging).Any())
        {
            throw new InvalidDataException(
                "Personal feed initialization cannot adopt non-empty staging state.");
        }
        var publicRoot = Path.Combine(root, "public");
        if (Directory.Exists(publicRoot))
        {
            RequireSubsetNames(publicRoot, ["channels", "releases"], "partial public root");
            var releases = Path.Combine(publicRoot, "releases");
            if (Directory.Exists(releases)
                && Directory.EnumerateFileSystemEntries(releases).Any())
            {
                throw new InvalidDataException(
                    "Personal feed initialization cannot adopt immutable release state.");
            }
            var channels = Path.Combine(publicRoot, "channels");
            if (Directory.Exists(channels))
            {
                RequireSubsetNames(channels, PersonalFeedChannels.All, "partial channel root");
                foreach (var channel in PersonalFeedChannels.All)
                {
                    var channelRoot = Path.Combine(channels, channel);
                    if (Directory.Exists(channelRoot)
                        && Directory.EnumerateFileSystemEntries(channelRoot).Any())
                    {
                        throw new InvalidDataException(
                            "Personal feed initialization cannot adopt channel state.");
                    }
                }
            }
        }
        var journal = Path.Combine(root, "journal");
        if (Directory.Exists(journal))
        {
            RequireSubsetNames(
                journal,
                PersonalFeedChannels.All.Append("operations").Append("publication.lock").ToArray(),
                "partial journal root",
                alreadyValidatedOpenFiles);
            var operations = Path.Combine(journal, "operations");
            if (Directory.Exists(operations)
                && Directory.EnumerateFileSystemEntries(operations).Any())
            {
                throw new InvalidDataException(
                    "Personal feed initialization cannot adopt operation state.");
            }
            foreach (var channel in PersonalFeedChannels.All)
            {
                var channelJournal = Path.Combine(journal, channel);
                if (Directory.Exists(channelJournal))
                {
                    RequireSubsetNames(
                        channelJournal,
                        ["promotion.lock"],
                        "partial channel journal");
                }
            }
        }
        PersonalFeedPathGuard.RequireSafeTree(root, alreadyValidatedOpenFiles);
        LinuxNative.RequireManagedTreeRootOwned(root);
    }

    private static void RequireSubsetNames(
        string directory,
        IReadOnlyCollection<string> allowed,
        string label,
        IReadOnlyCollection<string>? alreadyValidatedOpenFiles = null)
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
        {
            var name = Path.GetFileName(entry);
            if (!allowed.Contains(name, StringComparer.Ordinal))
            {
                throw new InvalidDataException($"Personal {label} contains unexpected inventory.");
            }
            if (name.EndsWith(".lock", StringComparison.Ordinal))
            {
                if (alreadyValidatedOpenFiles is null
                    || !alreadyValidatedOpenFiles.Any(value => string.Equals(
                        Path.GetFullPath(value),
                        Path.GetFullPath(entry),
                        OperatingSystem.IsWindows()
                            ? StringComparison.OrdinalIgnoreCase
                            : StringComparison.Ordinal)))
                {
                    _ = PersonalFeedPathGuard.RequireRegularFile(
                        entry,
                        $"personal {label} lock");
                }
            }
            else
            {
                _ = PersonalFeedPathGuard.RequireExistingDirectory(
                    entry,
                    $"personal {label} directory");
            }
        }
    }

    private static void RequireExactNames(
        string root,
        IReadOnlyCollection<string> expectedNames,
        string label)
    {
        var actual = Directory.EnumerateFileSystemEntries(root)
            .Select(Path.GetFileName)
            .Where(name => name is not null)
            .Cast<string>()
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!actual.SequenceEqual(expectedNames.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw new InvalidDataException($"{label} has an unexpected managed layout.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalFeedInitializationResult(
    int SchemaVersion,
    string Product,
    string Environment,
    string FeedInstanceId,
    string FeedIdentitySha256);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalFeedIdentity(
    int SchemaVersion,
    string Product,
    string Environment,
    string FeedInstanceId)
{
    public static PersonalFeedIdentity Parse(ReadOnlySpan<byte> json)
    {
        try
        {
            PersonalFeedJson.RequireNoDuplicateMembers(json);
            return JsonSerializer.Deserialize<PersonalFeedIdentity>(json, PersonalFeedJson.Options)
                ?? throw new InvalidDataException("Personal feed identity is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Personal feed identity JSON is invalid.", exception);
        }
    }

    public void Validate()
    {
        if (SchemaVersion != 2
            || !string.Equals(Product, PersonalReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(
                Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !Guid.TryParse(FeedInstanceId, out var instanceId)
            || !string.Equals(
                FeedInstanceId,
                instanceId.ToString("N"),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Feed root does not have a unique current-schema Ensou DSH Personal production identity.");
        }
    }
}

internal static class PersonalFeedChannels
{
    public static IReadOnlyList<string> All { get; } = ["lab", "pilot", "stable"];

    public static void Require(string channel)
    {
        if (!All.Contains(channel, StringComparer.Ordinal))
        {
            throw new ArgumentException("Channel must be lab, pilot, or stable.", nameof(channel));
        }
    }
}

internal static class PersonalFeedPathGuard
{
    public static string RequireExistingDirectory(string path, string label)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException($"{label} must be absolute.");
        }
        var full = Path.GetFullPath(path).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(full))
        {
            throw new DirectoryNotFoundException($"{label} is missing: {full}");
        }
        RequireNoLinkAncestors(full);
        return full;
    }

    public static string RequireExactDirectory(string parent, string name)
    {
        RequireSafeFileName(name, "managed directory name");
        var full = Path.GetFullPath(Path.Combine(parent, name));
        var expectedParent = Path.GetFullPath(parent).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        if (!PathEquals(
                Path.GetDirectoryName(full)?.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar),
                expectedParent))
        {
            throw new InvalidDataException("Feed managed directory escaped its parent.");
        }
        return RequireExistingDirectory(full, $"feed {name} directory");
    }

    public static void RequireSafeTree(
        string root,
        IReadOnlyCollection<string>? alreadyValidatedOpenFiles = null)
    {
        var full = RequireExistingDirectory(root, "tree");
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     full,
                     "*",
                     SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Personal feed paths may not contain filesystem links.");
            }
            if (File.Exists(path)
                && (alreadyValidatedOpenFiles is null
                    || !alreadyValidatedOpenFiles.Any(value => PathEquals(
                        Path.GetFullPath(value),
                        Path.GetFullPath(path)))))
            {
                _ = RequireRegularFile(path, "personal feed managed file");
            }
        }
    }

    public static byte[] ReadBoundedRegularFile(string path, int maximumBytes, string label)
    {
        var full = RequireRegularFile(path, label);
        using var stream = new FileStream(
            full,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        var length = stream.Length;
        if (length is <= 0 || length > maximumBytes || length > int.MaxValue)
        {
            throw new InvalidDataException($"{label} size is invalid.");
        }
        var bytes = new byte[(int)length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1 || stream.Length != length)
        {
            throw new IOException($"{label} changed while it was read.");
        }
        return bytes;
    }

    public static (long SizeBytes, string Sha256) CopyNewAndHash(
        string source,
        string destination)
    {
        var fullSource = RequireRegularFile(source, "candidate artifact");
        using var input = new FileStream(
            fullSource,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        var initialLength = input.Length;
        using var output = new FileStream(
            destination,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.SequentialScan | FileOptions.WriteThrough);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        long total = 0;
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            output.Write(buffer, 0, read);
            hash.AppendData(buffer, 0, read);
            total += read;
        }
        output.Flush(flushToDisk: true);
        if (total != initialLength || input.Length != initialLength)
        {
            throw new IOException("Candidate artifact changed while it was copied.");
        }
        return (total, Convert.ToHexStringLower(hash.GetHashAndReset()));
    }

    public static (long SizeBytes, string Sha256) HashRegularFile(string path)
    {
        var full = RequireRegularFile(path, "immutable artifact");
        using var stream = new FileStream(
            full,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        var length = stream.Length;
        var hash = Convert.ToHexStringLower(SHA256.HashData(stream));
        if (stream.Length != length)
        {
            throw new IOException("Immutable artifact changed while it was hashed.");
        }
        return (length, hash);
    }

    public static void WriteNewDurable(
        string path,
        ReadOnlySpan<byte> bytes,
        bool readOnly = false)
    {
        using (var stream = new FileStream(
                   path,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   128 * 1024,
                   FileOptions.WriteThrough))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        SetFileMode(path, readOnly);
        LinuxNative.FlushDirectory(Path.GetDirectoryName(path)!);
    }

    public static void ReplaceDurableFileAtomically(
        string destination,
        ReadOnlySpan<byte> bytes,
        string exactParent)
    {
        var parent = Path.GetDirectoryName(Path.GetFullPath(destination))
            ?? throw new InvalidDataException("Atomic destination has no parent.");
        if (!PathEquals(
                parent.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                Path.GetFullPath(exactParent).TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar)))
        {
            throw new InvalidDataException("Atomic destination escaped its exact parent.");
        }
        if (File.Exists(destination)
            && (File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Atomic destination may not be a filesystem link.");
        }
        var temporary = Path.Combine(
            parent,
            $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp");
        try
        {
            WriteNewDurable(temporary, bytes);
            File.Move(temporary, destination, overwrite: true);
            SetFileMode(destination, readOnly: false);
            LinuxNative.FlushDirectory(parent);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
                LinuxNative.FlushDirectory(parent);
            }
        }
    }

    public static void MakeReleaseReadOnly(string directory)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        foreach (var file in Directory.EnumerateFiles(directory))
        {
            SetFileMode(file, readOnly: true);
        }
        File.SetUnixFileMode(
            directory,
            UnixFileMode.UserRead | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        LinuxNative.FlushDirectory(directory);
        LinuxNative.FlushDirectory(Path.GetDirectoryName(directory)!);
    }

    public static void SetDirectoryMode(string path, bool publicRead)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        if (publicRead)
        {
            mode |= UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
        }
        File.SetUnixFileMode(path, mode);
    }

    public static void DeletePrivateStage(string stage, string stagingRoot)
    {
        var fullStage = Path.GetFullPath(stage);
        var fullRoot = Path.GetFullPath(stagingRoot).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        if (!PathEquals(Path.GetDirectoryName(fullStage), fullRoot))
        {
            throw new InvalidDataException("Refusing to clean a stage outside the staging root.");
        }
        if (Directory.Exists(fullStage))
        {
            RequireSafeTree(fullStage);
            Directory.Delete(fullStage, recursive: true);
            LinuxNative.FlushDirectory(fullRoot);
        }
    }

    public static void RequireSafeFileName(string? fileName, string label)
    {
        if (string.IsNullOrWhiteSpace(fileName)
            || fileName is "." or ".."
            || fileName != Path.GetFileName(fileName)
            || fileName.Length > 255
            || fileName.Any(char.IsControl)
            || fileName.IndexOfAny(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) >= 0
            || fileName.EndsWith(' ')
            || fileName.EndsWith('.'))
        {
            throw new InvalidDataException($"{label} is unsafe.");
        }
    }

    private static void SetFileMode(string path, bool readOnly)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var mode = UnixFileMode.UserRead
            | UnixFileMode.GroupRead
            | UnixFileMode.OtherRead;
        if (!readOnly)
        {
            mode |= UnixFileMode.UserWrite;
        }
        File.SetUnixFileMode(path, mode);
    }

    public static string RequireRegularFile(string path, string label)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException($"{label} must be absolute.");
        }
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)
            || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileNotFoundException($"{label} is missing or linked.", full);
        }
        RequireNoLinkAncestors(Path.GetDirectoryName(full)!);
        RequireSingleLink(full, label);
        return full;
    }

    public static void WriteNewDurableAtomicallyCreateOnly(
        string destination,
        ReadOnlySpan<byte> bytes)
    {
        var full = Path.GetFullPath(destination);
        var parent = Path.GetDirectoryName(full)
            ?? throw new InvalidDataException("Atomic create-only destination has no parent.");
        var expected = bytes.ToArray();
        var temporary = Path.Combine(
            parent,
            $".{Path.GetFileName(full)}.{Guid.NewGuid():N}.tmp");
        try
        {
            WriteNewDurable(temporary, expected);
            try
            {
                File.Move(temporary, full);
                LinuxNative.FlushDirectory(parent);
            }
            catch (IOException) when (File.Exists(full))
            {
                // Exact readback below decides a create-only race.
            }
            var committed = ReadBoundedRegularFile(
                full,
                expected.Length,
                "create-only durable output");
            if (!committed.AsSpan().SequenceEqual(expected))
            {
                throw new InvalidDataException(
                    "Create-only durable output conflicts with existing bytes.");
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
                LinuxNative.FlushDirectory(parent);
            }
        }
    }

    public static string RequireExternalResultReceiptPath(
        string path,
        string feedRoot,
        string candidateRoot,
        string trustPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException(
                "Personal promotion result receipt must use an absolute path.");
        }
        var full = Path.GetFullPath(path);
        RequireSafeFileName(Path.GetFileName(full), "promotion result receipt filename");
        var parent = RequireExistingDirectory(
            Path.GetDirectoryName(full)
                ?? throw new InvalidDataException(
                    "Personal promotion result receipt has no parent."),
            "promotion result receipt parent");
        if (IsSameOrDescendant(full, feedRoot)
            || IsSameOrDescendant(full, candidateRoot)
            || PathEquals(full, Path.GetFullPath(trustPath)))
        {
            throw new InvalidDataException(
                "Personal promotion result receipt must be outside feed, candidate, and trust inputs.");
        }
        if (Directory.Exists(full))
        {
            throw new InvalidDataException(
                "Personal promotion result receipt path is unexpectedly a directory.");
        }
        if (File.Exists(full))
        {
            _ = RequireRegularFile(full, "existing promotion result receipt");
        }
        if (OperatingSystem.IsLinux())
        {
            for (var current = new DirectoryInfo(parent);
                 current is not null;
                 current = current.Parent)
            {
                LinuxNative.RequireRootOwnedAndNotWritableByOthers(
                    current.FullName,
                    "promotion result receipt ancestor");
            }
        }
        return full;
    }

    private static bool IsSameOrDescendant(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        return PathEquals(fullPath, fullRoot)
            || fullPath.StartsWith(
                fullRoot + Path.DirectorySeparatorChar,
                OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal);
    }

    private static void RequireSingleLink(string path, string label)
    {
        if (OperatingSystem.IsLinux())
        {
            LinuxNative.RequireSingleLinkRegularFile(path, label);
            return;
        }
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Personal feed single-link validation supports Linux and Windows.");
        }
        using var handle = File.OpenHandle(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                $"Could not inspect {label} link count.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        }
        if (information.NumberOfLinks != 1
            || (information.FileAttributes & (uint)(
                FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new InvalidDataException(
                $"{label} must be one ordinary single-link file.");
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

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

    private static void RequireNoLinkAncestors(string path)
    {
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Personal feed paths may not cross filesystem links.");
            }
            current = current.Parent;
        }
    }

    private static bool PathEquals(string? left, string? right) => string.Equals(
        left,
        right,
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal);
}

internal static partial class LinuxNative
{
    private const uint FileTypeMask = 0xF000;
    private const uint DirectoryType = 0x4000;
    private const uint RegularFileType = 0x8000;
    private const uint SymbolicLinkType = 0xA000;
    private const uint GroupOrOtherWrite = 0x12;
    private const int OpenReadOnly = 0;
    private const int OpenDirectory = 0x10000;
    private const int OpenNoFollow = 0x20000;
    private const int OpenCloseOnExec = 0x80000;

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxTimespec
    {
        internal long Seconds;
        internal long Nanoseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStat
    {
        internal ulong Device;
        internal ulong Inode;
        internal ulong HardLinks;
        internal uint Mode;
        internal uint UserId;
        internal uint GroupId;
        internal int Padding;
        internal ulong RawDevice;
        internal long Size;
        internal long BlockSize;
        internal long Blocks;
        internal LinuxTimespec AccessTime;
        internal LinuxTimespec ModificationTime;
        internal LinuxTimespec ChangeTime;
        internal long Reserved0;
        internal long Reserved1;
        internal long Reserved2;
    }

    [LibraryImport("libc")]
    private static partial uint geteuid();

    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int LStat(string path, out LinuxStat status);

    [LibraryImport(
        "libc",
        EntryPoint = "open",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Open(string path, int flags);

    [LibraryImport(
        "libc",
        EntryPoint = "openat",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenAtNative(int directoryDescriptor, string path, int flags);

    [LibraryImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static partial int FStatNative(int descriptor, out LinuxStat status);

    [LibraryImport("libc", EntryPoint = "fsync")]
    private static partial int Fsync(int descriptor);

    [LibraryImport("libc", EntryPoint = "close")]
    private static partial int Close(int descriptor);

    public static void RequireRoot()
    {
        if (OperatingSystem.IsLinux() && geteuid() != 0)
        {
            throw new UnauthorizedAccessException(
                "Personal feed promotion must run as root through the reviewed sudo command.");
        }
    }

    public static byte[] ReadRootOwnedRegularFile(
        string path,
        int maximumBytes,
        string label,
        Action? afterOpen = null)
    {
        if (!OperatingSystem.IsLinux())
        {
            return PersonalFeedPathGuard.ReadBoundedRegularFile(path, maximumBytes, label);
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (maximumBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        }
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException($"{label} must be absolute.");
        }

        var full = Path.GetFullPath(path);
        var components = full.Split(
            Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries);
        if (components.Length == 0)
        {
            throw new FileNotFoundException($"{label} is not a regular file.", full);
        }

        SafeFileHandle? directory = null;
        try
        {
            directory = OpenHandle(
                Path.DirectorySeparatorChar.ToString(),
                OpenReadOnly | OpenDirectory | OpenNoFollow | OpenCloseOnExec,
                $"{label} root ancestor");
            _ = RequireSecureHandle(
                directory,
                DirectoryType,
                $"{label} root ancestor");

            var currentPath = Path.DirectorySeparatorChar.ToString();
            for (var index = 0; index < components.Length - 1; index++)
            {
                currentPath = Path.Combine(currentPath, components[index]);
                var next = OpenAtHandle(
                    directory,
                    components[index],
                    OpenReadOnly | OpenDirectory | OpenNoFollow | OpenCloseOnExec,
                    $"{label} ancestor: {currentPath}");
                try
                {
                    _ = RequireSecureHandle(
                        next,
                        DirectoryType,
                        $"{label} ancestor: {currentPath}");
                }
                catch
                {
                    next.Dispose();
                    throw;
                }
                directory.Dispose();
                directory = next;
            }

            using var file = OpenAtHandle(
                directory,
                components[^1],
                OpenReadOnly | OpenNoFollow | OpenCloseOnExec,
                label);
            var initial = RequireSecureHandle(file, RegularFileType, label);
            if (initial.Size is <= 0 || initial.Size > maximumBytes || initial.Size > int.MaxValue)
            {
                throw new InvalidDataException($"{label} size is invalid.");
            }

            afterOpen?.Invoke();
            var bytes = new byte[(int)initial.Size];
            var offset = 0;
            while (offset < bytes.Length)
            {
                var read = RandomAccess.Read(file, bytes.AsSpan(offset), offset);
                if (read == 0)
                {
                    throw new IOException($"{label} changed while it was read.");
                }
                offset += read;
            }
            Span<byte> extra = stackalloc byte[1];
            if (RandomAccess.Read(file, extra, offset) != 0)
            {
                throw new IOException($"{label} changed while it was read.");
            }

            var final = RequireSecureHandle(file, RegularFileType, label);
            if (final.Device != initial.Device
                || final.Inode != initial.Inode
                || final.Size != initial.Size
                || final.ModificationTime.Seconds != initial.ModificationTime.Seconds
                || final.ModificationTime.Nanoseconds != initial.ModificationTime.Nanoseconds
                || final.ChangeTime.Seconds != initial.ChangeTime.Seconds
                || final.ChangeTime.Nanoseconds != initial.ChangeTime.Nanoseconds)
            {
                throw new IOException($"{label} changed while it was read.");
            }
            return bytes;
        }
        finally
        {
            directory?.Dispose();
        }
    }

    public static void RequireManagedTreeRootOwned(string root)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        RequireRootOwnedAndNotWritableByOthers(root, "feed root");
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     root,
                     "*",
                     SearchOption.AllDirectories))
        {
            RequireRootOwnedAndNotWritableByOthers(path, "managed feed path");
        }
    }

    public static void RequireRootOwnedAndNotWritableByOthers(string path, string label)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        if (LStat(path, out var status) != 0)
        {
            throw new IOException($"Could not inspect {label}: {path}");
        }
        if ((status.Mode & FileTypeMask) == SymbolicLinkType
            || status.UserId != 0
            || (status.Mode & GroupOrOtherWrite) != 0)
        {
            throw new UnauthorizedAccessException(
                $"{label} must be root-owned, link-free, and not writable by group or others.");
        }
    }

    public static void RequireSingleLinkRegularFile(string path, string label)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        if (LStat(path, out var status) != 0)
        {
            throw CreateIOException($"Could not inspect {label}: {path}");
        }
        if ((status.Mode & FileTypeMask) != RegularFileType || status.HardLinks != 1)
        {
            throw new InvalidDataException(
                $"{label} must be one ordinary single-link file.");
        }
    }

    private static SafeFileHandle OpenHandle(string path, int flags, string label)
    {
        var descriptor = Open(path, flags);
        if (descriptor < 0)
        {
            throw CreateIOException($"Could not open {label}: {path}");
        }
        return new SafeFileHandle((nint)descriptor, ownsHandle: true);
    }

    private static SafeFileHandle OpenAtHandle(
        SafeFileHandle directory,
        string name,
        int flags,
        string label)
    {
        var addedReference = false;
        int descriptor;
        try
        {
            directory.DangerousAddRef(ref addedReference);
            descriptor = OpenAtNative(
                directory.DangerousGetHandle().ToInt32(),
                name,
                flags);
        }
        finally
        {
            if (addedReference)
            {
                directory.DangerousRelease();
            }
        }
        if (descriptor < 0)
        {
            throw CreateIOException($"Could not open {label}");
        }
        return new SafeFileHandle((nint)descriptor, ownsHandle: true);
    }

    private static LinuxStat RequireSecureHandle(
        SafeFileHandle handle,
        uint expectedType,
        string label)
    {
        var addedReference = false;
        LinuxStat status;
        int result;
        try
        {
            handle.DangerousAddRef(ref addedReference);
            result = FStatNative(handle.DangerousGetHandle().ToInt32(), out status);
        }
        finally
        {
            if (addedReference)
            {
                handle.DangerousRelease();
            }
        }
        if (result != 0)
        {
            throw CreateIOException($"Could not inspect {label}");
        }
        if ((status.Mode & FileTypeMask) != expectedType
            || status.UserId != 0
            || (status.Mode & GroupOrOtherWrite) != 0)
        {
            throw new UnauthorizedAccessException(
                $"{label} must be root-owned, link-free, and not writable by group or others.");
        }
        if (expectedType == RegularFileType && status.HardLinks != 1)
        {
            throw new UnauthorizedAccessException(
                $"{label} must be a single-link regular file.");
        }
        return status;
    }

    private static IOException CreateIOException(string message) => new(
        message,
        new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));

    public static void FlushDirectory(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var descriptor = Open(path, OpenReadOnly | OpenDirectory | OpenCloseOnExec);
        if (descriptor < 0)
        {
            throw new IOException($"Could not open directory for durable flush: {path}");
        }
        try
        {
            if (Fsync(descriptor) != 0)
            {
                throw new IOException($"Could not durably flush directory: {path}");
            }
        }
        finally
        {
            _ = Close(descriptor);
        }
    }
}
