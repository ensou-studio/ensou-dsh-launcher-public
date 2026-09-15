Set-StrictMode -Version Latest

function Initialize-EnterpriseWindowsPilotPathGuard {
    if ('Ensou.Dsh.PilotEvidence.PathGuard' -as [type]) { return }
    if (-not $IsWindows) { throw 'Enterprise Windows Pilot path verification requires Windows.' }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.PilotEvidence
{
    public sealed class VerifiedDirectory : IDisposable
    {
        internal VerifiedDirectory(SafeFileHandle handle, string finalPath, string identity)
        {
            Handle = handle;
            FinalPath = finalPath;
            Identity = identity;
        }

        internal SafeFileHandle Handle { get; }
        public string FinalPath { get; }
        public string Identity { get; }
        public void Dispose() => Handle.Dispose();
    }

    public sealed class VerifiedReadFile : IDisposable
    {
        internal VerifiedReadFile(FileStream stream, string finalPath, string identity)
        {
            Stream = stream;
            FinalPath = finalPath;
            Identity = identity;
        }

        public FileStream Stream { get; }
        public string FinalPath { get; }
        public string Identity { get; }
        public void Dispose() => Stream.Dispose();
    }

    public static class PathGuard
    {
        private const uint GenericRead = 0x80000000;
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagSequentialScan = 0x08000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct FileAttributeTagInfo
        {
            public uint FileAttributes;
            public uint ReparseTag;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileId128
        {
            public ulong Low;
            public ulong High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileIdInfo
        {
            public ulong VolumeSerialNumber;
            public FileId128 FileId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string name,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle handle,
            int informationClass,
            out FileAttributeTagInfo information,
            uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
        private static extern bool GetFileIdInformationByHandleEx(
            SafeFileHandle handle,
            int informationClass,
            out FileIdInfo information,
            uint bufferSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle handle,
            StringBuilder path,
            uint pathLength,
            uint flags);

        public static VerifiedDirectory OpenDirectory(string path)
        {
            string expected = NormalizeExpected(path);
            SafeFileHandle handle = Open(expected, FileReadAttributes, FileShareRead | FileShareWrite,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint, "directory");
            try
            {
                Inspection inspection = Inspect(handle, expected, true);
                return new VerifiedDirectory(handle, inspection.FinalPath, inspection.Identity);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static VerifiedReadFile OpenReadFile(string path)
        {
            string expected = NormalizeExpected(path);
            SafeFileHandle handle = Open(expected, GenericRead, FileShareRead,
                FileFlagOpenReparsePoint | FileFlagSequentialScan, "file");
            try
            {
                Inspection inspection = Inspect(handle, expected, false);
                FileStream stream = new FileStream(handle, FileAccess.Read, 1024 * 1024, false);
                return new VerifiedReadFile(stream, inspection.FinalPath, inspection.Identity);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static void AssertFileIdentity(string path, string expectedFinalPath, string expectedIdentity)
        {
            string expected = NormalizeExpected(path);
            using (SafeFileHandle handle = Open(expected, GenericRead, FileShareRead | FileShareWrite,
                FileFlagOpenReparsePoint, "file identity probe"))
            {
                Inspection inspection = Inspect(handle, expected, false);
                if (!String.Equals(inspection.FinalPath, expectedFinalPath, StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(inspection.Identity, expectedIdentity, StringComparison.Ordinal))
                {
                    throw new IOException("Pilot input path no longer resolves to the locked file identity.");
                }
            }
        }

        public static void AssertDirectoryIdentity(string path, string expectedFinalPath, string expectedIdentity)
        {
            using (VerifiedDirectory probe = OpenDirectory(path))
            {
                if (!String.Equals(probe.FinalPath, expectedFinalPath, StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(probe.Identity, expectedIdentity, StringComparison.Ordinal))
                {
                    throw new IOException("Pilot directory path no longer resolves to the locked directory identity.");
                }
            }
        }

        public static string AssertOpenFilePath(SafeFileHandle handle, string expectedPath)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new IOException("Pilot output file handle is unavailable.");
            }
            Inspection inspection = Inspect(handle, NormalizeExpected(expectedPath), false);
            return inspection.Identity;
        }

        private static SafeFileHandle Open(string path, uint access, uint share, uint flags, string label)
        {
            SafeFileHandle handle = CreateFileW(path, access, share, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new IOException("Unable to open Pilot " + label + " safely.", new Win32Exception(error));
            }
            return handle;
        }

        private static Inspection Inspect(SafeFileHandle handle, string expectedPath, bool requireDirectory)
        {
            FileAttributeTagInfo attributes;
            if (!GetFileInformationByHandleEx(handle, 9, out attributes,
                (uint)Marshal.SizeOf(typeof(FileAttributeTagInfo))))
            {
                throw NativeFailure("Unable to inspect Pilot path attributes.");
            }

            bool isDirectory = (attributes.FileAttributes & FileAttributeDirectory) != 0;
            bool isReparsePoint = (attributes.FileAttributes & FileAttributeReparsePoint) != 0;
            if (isDirectory != requireDirectory || isReparsePoint)
            {
                throw new IOException("Pilot path must resolve directly to the expected non-reparse object type.");
            }

            string finalPath = GetFinalPath(handle);
            if (!String.Equals(finalPath, expectedPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("Pilot path final target differs from the requested absolute path.");
            }

            FileIdInfo information;
            if (!GetFileIdInformationByHandleEx(handle, 18, out information,
                (uint)Marshal.SizeOf(typeof(FileIdInfo))))
            {
                throw NativeFailure("Unable to inspect Pilot path identity.");
            }

            string identity = information.VolumeSerialNumber.ToString("x16") + ":" +
                information.FileId.Low.ToString("x16") + information.FileId.High.ToString("x16");
            return new Inspection(finalPath, identity);
        }

        private static string GetFinalPath(SafeFileHandle handle)
        {
            StringBuilder buffer = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw NativeFailure("Unable to resolve the final Pilot path.");
            }

            string path = buffer.ToString();
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                path = @"\\" + path.Substring(8);
            }
            else if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                path = path.Substring(4);
            }
            return NormalizeComparable(path);
        }

        private static string NormalizeExpected(string path)
        {
            if (String.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            {
                throw new IOException("Pilot path must be absolute.");
            }
            return NormalizeComparable(Path.GetFullPath(path));
        }

        private static string NormalizeComparable(string path)
        {
            string fullPath = Path.GetFullPath(path);
            if (fullPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                fullPath = @"\\" + fullPath.Substring(8);
            }
            else if (fullPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                fullPath = fullPath.Substring(4);
            }
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(fullPath));
        }

        private static IOException NativeFailure(string message)
        {
            return new IOException(message, new Win32Exception(Marshal.GetLastWin32Error()));
        }

        private sealed class Inspection
        {
            internal Inspection(string finalPath, string identity)
            {
                FinalPath = finalPath;
                Identity = identity;
            }
            internal string FinalPath { get; }
            internal string Identity { get; }
        }
    }
}
'@
}

function Initialize-EnterpriseWindowsPilotOutputGuard {
    if ('Ensou.Dsh.PilotEvidence.OutputGuard' -as [type]) { return }
    if (-not $IsWindows) { throw 'Enterprise Windows Pilot output verification requires Windows.' }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.PilotEvidence
{
    public sealed class CreatedOutput : IDisposable
    {
        internal CreatedOutput(FileStream stream, string finalPath, string identity)
        {
            Stream = stream;
            FinalPath = finalPath;
            Identity = identity;
        }

        public FileStream Stream { get; }
        public string FinalPath { get; }
        public string Identity { get; }

        public void DeleteOnClose()
        {
            Stream.SetLength(0);
            Stream.Flush(true);
            OutputGuard.MarkDeleteOnClose(Stream.SafeFileHandle);
        }

        public void Dispose() => Stream.Dispose();
    }

    public static class OutputGuard
    {
        private const uint GenericWrite = 0x40000000;
        private const uint Delete = 0x00010000;
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint FileShareDelete = 0x00000004;
        private const uint CreateNew = 1;
        private const uint OpenExisting = 3;
        private const uint FileAttributeNormal = 0x00000080;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileFlagWriteThrough = 0x80000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct FileAttributeTagInfo
        {
            public uint FileAttributes;
            public uint ReparseTag;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileId128
        {
            public ulong Low;
            public ulong High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileIdInfo
        {
            public ulong VolumeSerialNumber;
            public FileId128 FileId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileDispositionInfo
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool DeleteFile;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string name,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle handle,
            int informationClass,
            out FileAttributeTagInfo information,
            uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
        private static extern bool GetFileIdInformationByHandleEx(
            SafeFileHandle handle,
            int informationClass,
            out FileIdInfo information,
            uint bufferSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle handle,
            StringBuilder path,
            uint pathLength,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle handle,
            int informationClass,
            ref FileDispositionInfo information,
            uint bufferSize);

        public static CreatedOutput Create(string path)
        {
            string expected = NormalizeExpected(path);
            SafeFileHandle handle = CreateFileW(
                expected,
                GenericWrite | Delete | FileReadAttributes,
                FileShareRead,
                IntPtr.Zero,
                CreateNew,
                FileAttributeNormal | FileFlagOpenReparsePoint | FileFlagWriteThrough,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new IOException("Unable to create Pilot output safely.", new Win32Exception(error));
            }

            try
            {
                Inspection inspection = Inspect(handle, expected);
                FileStream stream = new FileStream(handle, FileAccess.Write, 64 * 1024, false);
                return new CreatedOutput(stream, inspection.FinalPath, inspection.Identity);
            }
            catch (Exception creationFailure)
            {
                Exception cleanupFailure = null;
                try
                {
                    MarkDeleteOnClose(handle);
                }
                catch (Exception failure)
                {
                    cleanupFailure = failure;
                }
                handle.Dispose();
                if (cleanupFailure != null)
                {
                    throw new IOException(
                        "Pilot output creation failed and its create-only file could not be safely cleaned up.",
                        creationFailure);
                }
                throw;
            }
        }

        public static void AssertPathIdentity(string path, string expectedFinalPath, string expectedIdentity)
        {
            string expected = NormalizeExpected(path);
            using (SafeFileHandle handle = CreateFileW(
                expected,
                FileReadAttributes,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagOpenReparsePoint,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw NativeFailure("Unable to reopen Pilot output identity safely.");
                }
                Inspection inspection = Inspect(handle, expected);
                if (!String.Equals(inspection.FinalPath, expectedFinalPath, StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(inspection.Identity, expectedIdentity, StringComparison.Ordinal))
                {
                    throw new IOException("Pilot output path no longer resolves to the created file identity.");
                }
            }
        }

        internal static void MarkDeleteOnClose(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new IOException("Pilot output cleanup handle is unavailable.");
            }
            FileDispositionInfo information = new FileDispositionInfo { DeleteFile = true };
            if (!SetFileInformationByHandle(
                handle,
                4,
                ref information,
                (uint)Marshal.SizeOf(typeof(FileDispositionInfo))))
            {
                throw NativeFailure("Unable to clean up the create-only Pilot output.");
            }
        }

        private static Inspection Inspect(SafeFileHandle handle, string expectedPath)
        {
            FileAttributeTagInfo attributes;
            if (!GetFileInformationByHandleEx(handle, 9, out attributes,
                (uint)Marshal.SizeOf(typeof(FileAttributeTagInfo))))
            {
                throw NativeFailure("Unable to inspect Pilot output attributes.");
            }
            if ((attributes.FileAttributes & FileAttributeDirectory) != 0 ||
                (attributes.FileAttributes & FileAttributeReparsePoint) != 0)
            {
                throw new IOException("Pilot output must be a direct non-reparse file.");
            }

            string finalPath = GetFinalPath(handle);
            if (!String.Equals(finalPath, expectedPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("Pilot output final target differs from the requested absolute path.");
            }

            FileIdInfo information;
            if (!GetFileIdInformationByHandleEx(handle, 18, out information,
                (uint)Marshal.SizeOf(typeof(FileIdInfo))))
            {
                throw NativeFailure("Unable to inspect Pilot output identity.");
            }
            string identity = information.VolumeSerialNumber.ToString("x16") + ":" +
                information.FileId.Low.ToString("x16") + information.FileId.High.ToString("x16");
            return new Inspection(finalPath, identity);
        }

        private static string GetFinalPath(SafeFileHandle handle)
        {
            StringBuilder buffer = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw NativeFailure("Unable to resolve the final Pilot output path.");
            }
            return NormalizeComparable(buffer.ToString());
        }

        private static string NormalizeExpected(string path)
        {
            if (String.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            {
                throw new IOException("Pilot output path must be absolute.");
            }
            return NormalizeComparable(Path.GetFullPath(path));
        }

        private static string NormalizeComparable(string path)
        {
            string fullPath = Path.GetFullPath(path);
            if (fullPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                fullPath = @"\\" + fullPath.Substring(8);
            }
            else if (fullPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                fullPath = fullPath.Substring(4);
            }
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(fullPath));
        }

        private static IOException NativeFailure(string message)
        {
            return new IOException(message, new Win32Exception(Marshal.GetLastWin32Error()));
        }

        private sealed class Inspection
        {
            internal Inspection(string finalPath, string identity)
            {
                FinalPath = finalPath;
                Identity = identity;
            }
            internal string FinalPath { get; }
            internal string Identity { get; }
        }
    }
}
'@
}
