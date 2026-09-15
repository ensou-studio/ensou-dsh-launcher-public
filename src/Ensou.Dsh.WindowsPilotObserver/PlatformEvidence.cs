using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Ensou.Dsh.WindowsPilotObserver;

public sealed record PlatformEvidence(
    int MajorVersion,
    int MinorVersion,
    int BuildNumber,
    byte ProductType,
    Architecture ProcessArchitecture,
    Architecture OperatingSystemArchitecture,
    ushort ProcessMachine,
    ushort NativeMachine)
{
    public const byte WorkstationProductType = 1;
    public const ushort ImageFileMachineUnknown = 0x0000;
    public const ushort ImageFileMachineAmd64 = 0x8664;
    public const int MinimumWindows10Build = 10240;
    public const int MinimumWindows11Build = 22000;

    public bool IsAccepted => IsSupported(
        MajorVersion,
        MinorVersion,
        BuildNumber,
        ProductType,
        ProcessArchitecture,
        OperatingSystemArchitecture,
        ProcessMachine,
        NativeMachine);

    public PlatformSummary ToSummary() => new(
        "windows",
        BuildNumber >= MinimumWindows11Build ? "windows-11" : "windows-10",
        MajorVersion,
        MinorVersion,
        BuildNumber,
        ProductType == WorkstationProductType,
        ProcessArchitecture.ToString().ToLowerInvariant(),
        OperatingSystemArchitecture.ToString().ToLowerInvariant(),
        ProcessMachine == ImageFileMachineUnknown ? "native" : $"0x{ProcessMachine:x4}",
        NativeMachine == ImageFileMachineAmd64 ? "amd64" : $"0x{NativeMachine:x4}",
        ProcessMachine != ImageFileMachineUnknown);

    public static bool IsSupported(
        int majorVersion,
        int minorVersion,
        int buildNumber,
        byte productType,
        Architecture processArchitecture,
        Architecture operatingSystemArchitecture,
        ushort processMachine,
        ushort nativeMachine) =>
        majorVersion == 10
        && minorVersion == 0
        && buildNumber >= MinimumWindows10Build
        && productType == WorkstationProductType
        && processArchitecture == Architecture.X64
        && operatingSystemArchitecture == Architecture.X64
        && processMachine == ImageFileMachineUnknown
        && nativeMachine == ImageFileMachineAmd64;

    public static bool IsSupportedSummary(PlatformSummary summary) =>
        string.Equals(summary.OperatingSystemFamily, "windows", StringComparison.Ordinal)
        && summary.Release is "windows-10" or "windows-11"
        && summary.MajorVersion == 10
        && summary.MinorVersion == 0
        && summary.BuildNumber >= MinimumWindows10Build
        && summary.Workstation
        && string.Equals(summary.ProcessArchitecture, "x64", StringComparison.Ordinal)
        && string.Equals(summary.OperatingSystemArchitecture, "x64", StringComparison.Ordinal)
        && string.Equals(summary.ProcessMachine, "native", StringComparison.Ordinal)
        && string.Equals(summary.NativeMachine, "amd64", StringComparison.Ordinal)
        && !summary.WowOrEmulated
        && ((summary.BuildNumber >= MinimumWindows11Build
                && string.Equals(summary.Release, "windows-11", StringComparison.Ordinal))
            || (summary.BuildNumber < MinimumWindows11Build
                && string.Equals(summary.Release, "windows-10", StringComparison.Ordinal)));

    public static PlatformEvidence CaptureCurrent()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows Pilot Observer requires Windows.");
        }
        var version = new NativePlatform.OsVersionInfoEx
        {
            Size = checked((uint)Marshal.SizeOf<NativePlatform.OsVersionInfoEx>()),
            ServicePack = string.Empty,
        };
        var status = NativePlatform.RtlGetVersion(ref version);
        if (status != 0)
        {
            throw new InvalidOperationException($"RtlGetVersion failed with NTSTATUS 0x{status:x8}.");
        }
        if (!NativePlatform.IsWow64Process2(
                NativeIdentity.GetCurrentProcess(),
                out var processMachine,
                out var nativeMachine))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "IsWow64Process2 failed.");
        }
        var evidence = new PlatformEvidence(
            checked((int)version.MajorVersion),
            checked((int)version.MinorVersion),
            checked((int)version.BuildNumber),
            version.ProductType,
            RuntimeInformation.ProcessArchitecture,
            RuntimeInformation.OSArchitecture,
            processMachine,
            nativeMachine);
        if (!evidence.IsAccepted)
        {
            throw new InvalidDataException(
                "Observer requires native x64 Windows 10 or Windows 11 Workstation; "
                + "Windows Server, WOW64, emulation, ARM64, and non-x64 hosts are rejected.");
        }
        return evidence;
    }
}

internal static class NativePlatform
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct OsVersionInfoEx
    {
        public uint Size;
        public uint MajorVersion;
        public uint MinorVersion;
        public uint BuildNumber;
        public uint PlatformId;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string ServicePack;

        public ushort ServicePackMajor;
        public ushort ServicePackMinor;
        public ushort SuiteMask;
        public byte ProductType;
        public byte Reserved;
    }

    [DllImport("ntdll.dll")]
    internal static extern int RtlGetVersion(ref OsVersionInfoEx versionInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWow64Process2(
        IntPtr process,
        out ushort processMachine,
        out ushort nativeMachine);
}
