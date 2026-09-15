using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Contracts;

[SupportedOSPlatform("windows")]
public static class WindowsLocalStateSecurity
{
    private const int MaximumStateFileBytes = 64 * 1024;

    public static async Task<byte[]> ReadBoundedAsync(
        string exactPath,
        string managedRoot,
        CancellationToken cancellationToken)
    {
        ValidateExactFilePath(exactPath, managedRoot);
        var directory = GetParentDirectory(exactPath);
        if (!ValidateSecureDirectoryChain(directory, createMissing: false))
        {
            throw new FileNotFoundException("Windows local state directory does not exist.", exactPath);
        }

        EnsureRegularFileOrAbsent(exactPath);

        await using var stream = new FileStream(
            exactPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        ValidateOpenedFilePath(stream.SafeFileHandle, exactPath);
        if (stream.Length > MaximumStateFileBytes)
        {
            throw new InvalidDataException("Windows local state file exceeds its maximum size.");
        }

        var bytes = new byte[stream.Length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return bytes;
    }

    public static async Task WriteAtomicAsync(
        string exactPath,
        string managedRoot,
        ReadOnlyMemory<byte> bytes,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        if (bytes.IsEmpty || bytes.Length > MaximumStateFileBytes)
        {
            throw new InvalidDataException("Windows local state file has an invalid size.");
        }

        ValidateExactFilePath(exactPath, managedRoot);
        var directory = Path.GetDirectoryName(exactPath)
            ?? throw new InvalidDataException("Windows local state path has no parent directory.");
        EnsureSecureDirectory(directory);
        using var directoryHandle = OpenVerifiedDirectory(directory);
        EnsureRegularFileOrAbsent(exactPath);

        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(exactPath)}.{RandomNumberGenerator.GetHexString(16)}.tmp");
        using var handle = CreateWritableTemporaryFile(temporaryPath);
        await using var stream = new FileStream(
            handle,
            FileAccess.Write,
            bufferSize: 4096,
            isAsync: true);
        try
        {
            ValidateOpenedFilePath(stream.SafeFileHandle, temporaryPath);
            await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            RenameOpenedFile(
                stream.SafeFileHandle,
                directoryHandle,
                Path.GetFileName(exactPath),
                overwrite);
            ValidateRenamedFile(stream.SafeFileHandle, exactPath);
        }
        catch (Exception operationException)
        {
            try
            {
                DeleteOpenedFile(stream.SafeFileHandle);
            }
            catch (Exception cleanupException)
            {
                throw new AggregateException(
                    "Windows local state write failed and its temporary file could not be removed safely.",
                    operationException,
                    cleanupException);
            }

            throw;
        }
    }

    public static void DeleteExactFile(string exactPath, string managedRoot)
    {
        ValidateExactFilePath(exactPath, managedRoot);
        var directory = GetParentDirectory(exactPath);
        if (!ValidateSecureDirectoryChain(directory, createMissing: false))
        {
            return;
        }

        EnsureRegularFileOrAbsent(exactPath);
        using var handle = OpenForDelete(exactPath);
        if (handle is null)
        {
            return;
        }

        ValidateOpenedFilePath(handle, exactPath);
        DeleteOpenedFile(handle);
    }

    public static void EnsureSecureDirectory(string directoryPath) =>
        ValidateSecureDirectoryChain(directoryPath, createMissing: true);

    private static bool ValidateSecureDirectoryChain(
        string directoryPath,
        bool createMissing)
    {
        var fullPath = ValidateLocalAbsolutePath(directoryPath);
        var root = Path.GetPathRoot(fullPath)
            ?? throw new InvalidDataException("Windows local state directory has no local root.");
        var relativePath = Path.GetRelativePath(root, fullPath);
        var current = root;

        foreach (var segment in relativePath.Split(
            Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (!Directory.Exists(current) && !File.Exists(current))
            {
                if (!createMissing)
                {
                    return false;
                }

                Directory.CreateDirectory(current);
            }

            var attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.Directory) == 0
                || (attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Windows local state directory must not use reparse points.");
            }
        }

        return true;
    }

    private static string GetParentDirectory(string exactPath) =>
        Path.GetDirectoryName(exactPath)
        ?? throw new InvalidDataException("Windows local state path has no parent directory.");

    private static void ValidateExactFilePath(string exactPath, string managedRoot)
    {
        var fullPath = ValidateLocalAbsolutePath(exactPath);
        var fullRoot = ValidateLocalAbsolutePath(managedRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!fullPath.StartsWith(
                fullRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Windows local state file escaped its managed root.");
        }
    }

    private static string ValidateLocalAbsolutePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        if (!Path.IsPathFullyQualified(fullPath)
            || fullPath.StartsWith("\\\\", StringComparison.Ordinal)
            || fullPath.StartsWith("//", StringComparison.Ordinal)
            || fullPath.IndexOf(':', 2) >= 0)
        {
            throw new InvalidDataException("Windows local state requires a canonical local path.");
        }

        return fullPath;
    }

    private static void EnsureRegularFileOrAbsent(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            return;
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.Directory) != 0
            || (attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Windows local state file must be a regular file.");
        }
    }

    private static SafeFileHandle CreateWritableTemporaryFile(string path)
    {
        var handle = CreateFile(
            path,
            GenericWrite | DeleteAccess | FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            CreateNew,
            FileAttributeNormal | FileFlagWriteThrough | FileFlagOverlapped,
            IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }

        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        throw new IOException(
            "Windows local state temporary file could not be created.",
            new Win32Exception(error));
    }

    private static SafeFileHandle? OpenForDelete(string path)
    {
        var handle = CreateFile(
            path,
            DeleteAccess | FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileAttributeNormal,
            IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }

        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        if (error is ErrorFileNotFound or ErrorPathNotFound)
        {
            return null;
        }

        throw new IOException(
            "Windows local state file could not be opened for secure deletion.",
            new Win32Exception(error));
    }

    private static SafeFileHandle OpenVerifiedDirectory(string path)
    {
        var handle = CreateFile(
            path,
            FileListDirectory | FileReadAttributes,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException(
                "Windows local state directory could not be opened for a bound operation.",
                new Win32Exception(error));
        }

        try
        {
            ValidateOpenedFilePath(handle, path);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenForVerification(string path)
    {
        var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileAttributeNormal,
            IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }

        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        throw new IOException(
            "Windows local state file could not be reopened after its atomic rename.",
            new Win32Exception(error));
    }

    private static void RenameOpenedFile(
        SafeFileHandle handle,
        SafeFileHandle destinationDirectoryHandle,
        string destinationFileName,
        bool overwrite)
    {
        if (!string.Equals(
                Path.GetFileName(destinationFileName),
                destinationFileName,
                StringComparison.Ordinal)
            || destinationFileName.IndexOfAny(
                [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]) >= 0)
        {
            throw new InvalidDataException(
                "Windows local state rename requires a single destination file name.");
        }

        var destination = Encoding.Unicode.GetBytes(destinationFileName);
        var rootDirectoryOffset = IntPtr.Size;
        var fileNameLengthOffset = rootDirectoryOffset + IntPtr.Size;
        var fileNameOffset = fileNameLengthOffset + sizeof(int);
        var bufferSize = checked(fileNameOffset + destination.Length + sizeof(char));
        var buffer = Marshal.AllocHGlobal(bufferSize);
        var directoryHandleReferenceAdded = false;
        try
        {
            destinationDirectoryHandle.DangerousAddRef(ref directoryHandleReferenceAdded);
            for (var index = 0; index < bufferSize; index++)
            {
                Marshal.WriteByte(buffer, index, 0);
            }

            Marshal.WriteInt32(buffer, overwrite ? 1 : 0);
            Marshal.WriteIntPtr(
                buffer,
                rootDirectoryOffset,
                destinationDirectoryHandle.DangerousGetHandle());
            Marshal.WriteInt32(buffer, fileNameLengthOffset, destination.Length);
            Marshal.Copy(destination, 0, IntPtr.Add(buffer, fileNameOffset), destination.Length);
            var status = NtSetInformationFile(
                handle,
                out _,
                buffer,
                (uint)bufferSize,
                NativeFileInformationClass.FileRenameInformation);
            if (status < 0)
            {
                throw new IOException(
                    "Windows local state file could not be renamed atomically.",
                    new Win32Exception((int)RtlNtStatusToDosError(status)));
            }
        }
        finally
        {
            if (directoryHandleReferenceAdded)
            {
                destinationDirectoryHandle.DangerousRelease();
            }

            CryptographicOperations.ZeroMemory(destination);
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void DeleteOpenedFile(SafeFileHandle handle)
    {
        var disposition = new FileDispositionInformation { DeleteFile = true };
        if (!SetFileInformationByHandle(
                handle,
                FileInformationClass.FileDispositionInfo,
                ref disposition,
                (uint)Marshal.SizeOf<FileDispositionInformation>()))
        {
            throw new IOException(
                "Windows local state file could not be deleted through its verified handle.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
    }

    private static void ValidateRenamedFile(SafeFileHandle renamedHandle, string expectedPath)
    {
        using var reopenedHandle = OpenForVerification(expectedPath);
        ValidateOpenedFilePath(reopenedHandle, expectedPath);
        var renamedIdentity = GetFileIdentity(renamedHandle);
        var reopenedIdentity = GetFileIdentity(reopenedHandle);
        if (renamedIdentity != reopenedIdentity)
        {
            throw new InvalidDataException(
                "Windows local state rename did not preserve the verified temporary file identity.");
        }
    }

    private static (uint Volume, ulong FileIndex) GetFileIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                "Windows local state file identity could not be verified.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }

        return (
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
    }

    private static void ValidateOpenedFilePath(SafeFileHandle handle, string expectedPath)
    {
        var capacity = 512;
        while (true)
        {
            var result = new StringBuilder(capacity);
            var length = GetFinalPathNameByHandle(handle, result, (uint)capacity, 0);
            if (length == 0)
            {
                throw new IOException(
                    "Windows local state file final path could not be verified.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }

            if (length < capacity)
            {
                var resolvedPath = NormalizeFinalHandlePath(result.ToString());
                var expectedFullPath = Path.GetFullPath(expectedPath);
                if (!string.Equals(
                        resolvedPath,
                        expectedFullPath,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        "Windows local state file resolved outside its exact managed path.");
                }

                return;
            }

            capacity = checked((int)length + 1);
        }
    }

    private static string NormalizeFinalHandlePath(string value)
    {
        const string localPrefix = @"\\?\";
        const string uncPrefix = @"\\?\UNC\";
        if (value.StartsWith(uncPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Windows local state must not resolve to a UNC path.");
        }

        var withoutPrefix = value.StartsWith(localPrefix, StringComparison.Ordinal)
            ? value[localPrefix.Length..]
            : value;
        return ValidateLocalAbsolutePath(withoutPrefix);
    }

    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileListDirectory = 0x00000001;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint CreateNew = 1;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

    private enum FileInformationClass
    {
        FileDispositionInfo = 4,
    }

    private enum NativeFileInformationClass
    {
        FileRenameInformation = 10,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        FileInformationClass fileInformationClass,
        IntPtr fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        FileInformationClass fileInformationClass,
        ref FileDispositionInformation fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationFile(
        SafeFileHandle file,
        out IoStatusBlock ioStatusBlock,
        IntPtr fileInformation,
        uint length,
        NativeFileInformationClass fileInformationClass);

    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);
}
