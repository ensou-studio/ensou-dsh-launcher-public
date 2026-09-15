using System.ComponentModel;
using System.Runtime.InteropServices;
using Ensou.Dsh.Host;

internal static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length != 0 || !OperatingSystem.IsWindows()) return 2;
        // Only private mirrored builds under q/.tmp may execute this fixture.
        const string permittedRoot = @"C:\EnsouDshPublicLab\.tmp\";
        var basePath = Path.GetFullPath(AppContext.BaseDirectory);
        if (!basePath.StartsWith(permittedRoot, StringComparison.OrdinalIgnoreCase)) return 2;
        for (var cursor = new DirectoryInfo(basePath); cursor is not null; cursor = cursor.Parent)
            if ((cursor.Attributes & FileAttributes.ReparsePoint) != 0) return 2;
        var fixtureRoot = Path.Combine(permittedRoot, "runtime-path-tests-" + Guid.NewGuid().ToString("N"));
        try
        {
            RunAdmission(fixtureRoot, "short", longRoot: false, DshRuntimeMode.Personal);
            RunAdmission(fixtureRoot, "long-personal", longRoot: true, DshRuntimeMode.Personal);
            RunAdmission(fixtureRoot, "long-enterprise", longRoot: true, DshRuntimeMode.EnterpriseManaged);
            RunHardLinkRejection(fixtureRoot);
            RunInventoryMutationRejection(fixtureRoot);
            Console.WriteLine("PASS: 5 runtime lease path groups; no runtime or Job started; fixtures retained at " + fixtureRoot);
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
    }

    private static void RunAdmission(string root, string name, bool longRoot, DshRuntimeMode mode)
    {
        var options = CreateFixture(root, name, longRoot) with { Mode = mode };
        var dependency = Path.Combine(options.RuntimeDirectory, "dependency.js");
        var callbackReached = false;
        using (var lease = DshRuntimeLaunchLease.Acquire(options, () => callbackReached = true))
        {
            if (!callbackReached) throw new InvalidOperationException("Admission callback not reached.");
            lease.RequireFilesStillCurrent();
            lease.RequireCompleteInventoryStillCurrent();
            ExpectWriteDenied(dependency);
            ExpectWriteDenied(options.NodePath);
            ExpectWriteDenied(options.EntryPointPath);
        }
        File.AppendAllText(dependency, "released");
        Console.WriteLine($"PASS {name}: root={options.RuntimeDirectory.Length}, entry={options.EntryPointPath.Length}; locked writes denied and release verified");
    }

    private static void RunHardLinkRejection(string root)
    {
        var options = CreateFixture(root, "long-hardlink", longRoot: true);
        var original = Path.Combine(options.RuntimeDirectory, "dependency.js");
        var alias = Path.Combine(options.RuntimeDirectory, "alias.js");
        if (!CreateHardLinkW(@"\\?\" + alias, @"\\?\" + original, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        ExpectAdmissionFailure(options, () => { }, "single-link regular file");
        File.AppendAllText(options.NodePath, "released-after-failed-admission");
        Console.WriteLine("PASS long hardlink rejection; failed admission released locks");
    }

    private static void RunInventoryMutationRejection(string root)
    {
        var options = CreateFixture(root, "long-inventory-mutation", longRoot: true);
        var callbackReached = false;
        var rejected = false;
        try
        {
            using var lease = DshRuntimeLaunchLease.Acquire(options, () =>
            {
                callbackReached = true;
                File.WriteAllText(Path.Combine(options.RuntimeDirectory, "unadmitted.js"), "fixture");
            });
        }
        catch (InvalidDataException exception) when (callbackReached && exception.Message is
            "DSH runtime admission failed: the complete runtime inventory changed during validation."
            or "DSH runtime admission failed: the validated runtime tree changed while its process was admitted.")
        {
            rejected = true;
        }
        if (!callbackReached || !rejected)
            throw new InvalidOperationException("The callback's inventory mutation was not rejected by a change barrier.");
        File.AppendAllText(options.NodePath, "released-after-failed-admission");
        Console.WriteLine("PASS long inventory mutation rejection; failed admission released locks");
    }

    private static DshRuntimeOptions CreateFixture(string root, string name, bool longRoot)
    {
        var runtime = Path.Combine(root, name);
        if (longRoot)
            while (runtime.Length < 310) runtime = Path.Combine(runtime, new string('a', 40));
        Directory.CreateDirectory(Path.Combine(runtime, "node_modules", "@deepseek-ai", "dsh", "lib"));
        // These are inert text fixtures, not executable runtime payloads.
        File.WriteAllText(Path.Combine(runtime, "node.exe"), "inert-node-fixture");
        File.WriteAllText(Path.Combine(runtime, "node_modules", "@deepseek-ai", "dsh", "lib", "bin.js"), "inert-entry-fixture");
        File.WriteAllText(Path.Combine(runtime, "dependency.js"), "inert-dependency-fixture");
        return new DshRuntimeOptions(runtime, Path.Combine(root, "unused-home"), Path.Combine(root, "unused-log"));
    }

    private static void ExpectWriteDenied(string path)
    {
        try { using var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete); }
        catch (IOException) { return; }
        throw new InvalidOperationException("Admitted file accepted a write handle: " + path);
    }

    private static void ExpectAdmissionFailure(DshRuntimeOptions options, Action callback, string expected)
    {
        try { using var lease = DshRuntimeLaunchLease.Acquire(options, callback); }
        catch (Exception exception) when (exception.ToString().Contains(expected, StringComparison.Ordinal)) { return; }
        throw new InvalidOperationException("Admission failed to reject the negative fixture.");
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string name, string existing, IntPtr security);
}
