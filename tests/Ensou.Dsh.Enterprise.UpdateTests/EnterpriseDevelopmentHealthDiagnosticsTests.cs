using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Enterprise.UpdateTests;

internal static class EnterpriseDevelopmentHealthDiagnosticsTests
{
    public static Task RunAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("This evidence sink is Windows-specific.");
        }
        var root = Path.Combine(Path.GetTempPath(), "enterprise-health-diagnostics", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        // Only this test's unique, ordinary tree is cleaned; linked leaves are removed first.
        try
        {
            var layout = MakeLayout(root, "records");
            var sink = new EnterpriseDevelopmentHealthDiagnostics(layout, "launcher");
            sink.Mark("candidate_started", new InvalidOperationException("SECRET-message",
                new IOException("SECRET-inner")), childProcessId: 123, exitCode: 1);
            var directory = Path.Combine(layout.ManagedRoot, EnterpriseDevelopmentHealthDiagnostics.DirectoryName);
            var records = Directory.GetFiles(directory, "*.json");
            Require(records.Length == 1, "Expected exactly one development record.");
            var text = File.ReadAllText(records[0]);
            Require(!text.Contains("SECRET", StringComparison.Ordinal)
                && !text.Contains(root, StringComparison.Ordinal), "Record exposed private context.");
            using (var json = JsonDocument.Parse(text))
            {
                var item = json.RootElement;
                Require(item.GetProperty("schemaVersion").GetInt32() == 1
                    && item.GetProperty("stage").GetString() == "candidate_started"
                    && item.GetProperty("exceptionType").GetString() == typeof(InvalidOperationException).FullName
                    && item.GetProperty("innerExceptionType").GetString() == typeof(IOException).FullName
                    && item.GetProperty("childProcessId").GetInt32() == 123
                    && item.GetProperty("exitCode").GetInt32() == 1, "Diagnostic projection differs.");
                string[] names = ["schemaVersion", "event", "component", "stage", "processId",
                    "elapsedMilliseconds", "sequence", "childProcessId", "exitCode", "exceptionType",
                    "hResult", "innerExceptionType", "innerHResult"];
                Require(item.EnumerateObject().All(property => names.Contains(property.Name)),
                    "Unexpected diagnostic field.");
            }
            sink.Mark("invalid/stage");
            new EnterpriseDevelopmentHealthDiagnostics(layout, "invalid-component").Mark("valid");
            Require(Directory.GetFiles(directory, "*.json").Length == 1, "Invalid identifiers were accepted.");
            for (var index = 0; index < 100; index++) sink.Mark("bounded");
            Require(Directory.GetFiles(directory, "*.json").Length == 64, "Instance record limit differs.");
            for (var index = 0; index < 10; index++)
            {
                var another = new EnterpriseDevelopmentHealthDiagnostics(layout, "client-bootstrapper");
                for (var record = 0; record < 64; record++) another.Mark("bounded");
            }
            Require(Directory.GetFiles(directory, "*.json").Length == 512, "Directory record limit differs.");

            var production = EnterpriseInstallationLayout.Create(Path.Combine(root, "prod-local"), Path.Combine(root, "prod-profile"));
            new EnterpriseDevelopmentHealthDiagnostics(production, "launcher").Mark("must_not_write");
            Require(!Directory.Exists(production.ManagedRoot), "Production layout emitted diagnostics.");

            var conflict = MakeLayout(root, "conflict");
            var conflictDirectory = Path.Combine(conflict.ManagedRoot, EnterpriseDevelopmentHealthDiagnostics.DirectoryName);
            Directory.CreateDirectory(conflictDirectory);
            using (var locked = new FileStream(Path.Combine(conflictDirectory, ".writer.lock"), FileMode.CreateNew,
                FileAccess.ReadWrite, FileShare.None))
            {
                new EnterpriseDevelopmentHealthDiagnostics(conflict, "launcher").Mark("locked", new IOException("SECRET"));
                Require(Directory.GetFiles(conflictDirectory, "*.json").Length == 0, "Lock conflict emitted a record.");
            }

            var linked = MakeLayout(root, "linked");
            var external = Path.Combine(root, "outside-diagnostics");
            Directory.CreateDirectory(external);
            var leaf = Path.Combine(linked.ManagedRoot, EnterpriseDevelopmentHealthDiagnostics.DirectoryName);
            CreateJunction(leaf, external);
            try
            {
                new EnterpriseDevelopmentHealthDiagnostics(linked, "launcher").Mark("must_not_follow");
                Require(!Directory.EnumerateFileSystemEntries(external).Any(), "Diagnostic sink followed a junction.");
            }
            finally
            {
                Directory.Delete(leaf); // Delete only the junction object, never its target.
            }

            var parentLink = Path.Combine(root, "linked-parent");
            var parentTarget = Path.Combine(root, "parent-target");
            var parentLayout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
                Path.Combine(parentLink, "local"), Path.Combine(root, "parent-profile"));
            Directory.CreateDirectory(parentTarget);
            CreateJunction(parentLink, parentTarget);
            try
            {
                Directory.CreateDirectory(parentLayout.ManagedRoot);
                new EnterpriseDevelopmentHealthDiagnostics(parentLayout, "launcher").Mark("must_not_follow_parent");
                Require(!Directory.Exists(Path.Combine(parentLayout.ManagedRoot,
                    EnterpriseDevelopmentHealthDiagnostics.DirectoryName)), "Diagnostic sink followed a linked ancestor.");
            }
            finally { Directory.Delete(parentLink); }
        }
        finally
        {
            // No recursive cleanup through reparse points, including partially failed test setup.
            DeleteOrdinaryTree(root);
        }
        return Task.CompletedTask;
    }

    private static EnterpriseInstallationLayout MakeLayout(string root, string name)
    {
        var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
            Path.Combine(root, name, "local"), Path.Combine(root, name, "profile"));
        Directory.CreateDirectory(layout.ManagedRoot);
        return layout;
    }

    private static void Require(bool value, string message)
    {
        if (!value) throw new InvalidOperationException(message);
    }

    private static void DeleteOrdinaryTree(string directory)
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(directory))
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.Directory) == 0) File.Delete(path);
            else if ((attributes & FileAttributes.ReparsePoint) != 0) Directory.Delete(path);
            else DeleteOrdinaryTree(path);
        }
        Directory.Delete(directory);
    }

    private static void CreateJunction(string leaf, string target)
    {
        Directory.CreateDirectory(leaf);
        var substitute = Encoding.Unicode.GetBytes(@"\??\" + Path.GetFullPath(target));
        var print = Encoding.Unicode.GetBytes(Path.GetFullPath(target));
        var data = new byte[16 + substitute.Length + 2 + print.Length + 2];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0xA0000003);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), checked((ushort)(data.Length - 8)));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(10), checked((ushort)substitute.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), checked((ushort)(substitute.Length + 2)));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(14), checked((ushort)print.Length));
        substitute.CopyTo(data, 16);
        print.CopyTo(data, 18 + substitute.Length);
        using var handle = CreateFile(@"\\?\" + leaf, 0x40000000, 0, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid || !DeviceIoControl(handle, 0x000900A4, data, data.Length,
            IntPtr.Zero, 0, out _, IntPtr.Zero))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, byte[] input,
        int inputLength, IntPtr output, int outputLength, out int returned, IntPtr overlapped);
}
