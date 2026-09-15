using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.WindowsPilotObserver;

public enum ProcessTokenElevationType
{
    Default = 1,
    Full = 2,
    Limited = 3,
}

public enum AdministratorGroupMembership
{
    Absent,
    Enabled,
    DenyOnly,
}

public sealed record ExecutionIdentityEvidence(
    ProcessTokenElevationType ElevationType,
    int IntegrityRid,
    AdministratorGroupMembership AdministratorMembership)
{
    public ExecutionIdentitySummary ToSummary() => new(
        ElevationType.ToString().ToLowerInvariant(),
        IntegrityRid,
        AdministratorMembership switch
        {
            AdministratorGroupMembership.Enabled => "enabled",
            AdministratorGroupMembership.DenyOnly => "deny-only",
            _ => "absent",
        });
}

public static class ExecutionIdentityPolicy
{
    public const int MediumIntegrityRid = 0x2000;

    public static bool IsAccepted(ProcessTokenElevationType elevationType, int integrityRid) =>
        elevationType is ProcessTokenElevationType.Default or ProcessTokenElevationType.Limited
        && integrityRid == MediumIntegrityRid;

    public static ExecutionIdentityEvidence CaptureCurrent()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows Pilot Observer requires Windows.");
        }

        if (!NativeIdentity.OpenProcessToken(
                NativeIdentity.GetCurrentProcess(),
                NativeIdentity.TokenQuery,
                out var token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed.");
        }
        using (token)
        {
            var elevation = (ProcessTokenElevationType)ReadInt32TokenInformation(
                token,
                NativeIdentity.TokenInformationClass.TokenElevationType);
            var integrity = ReadIntegrityRid(token);
            var administratorMembership = ReadAdministratorMembership(token);
            return new ExecutionIdentityEvidence(elevation, integrity, administratorMembership);
        }
    }

    private static int ReadInt32TokenInformation(
        SafeAccessTokenHandle token,
        NativeIdentity.TokenInformationClass informationClass)
    {
        var size = sizeof(int);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!NativeIdentity.GetTokenInformation(token, informationClass, buffer, size, out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation failed.");
            }
            return Marshal.ReadInt32(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int ReadIntegrityRid(SafeAccessTokenHandle token)
    {
        var buffer = ReadVariableTokenInformation(token, NativeIdentity.TokenInformationClass.TokenIntegrityLevel);
        try
        {
            var label = Marshal.PtrToStructure<NativeIdentity.TokenMandatoryLabel>(buffer);
            if (label.Label.Sid == IntPtr.Zero)
            {
                throw new InvalidDataException("Token integrity SID is absent.");
            }
            var countPointer = NativeIdentity.GetSidSubAuthorityCount(label.Label.Sid);
            if (countPointer == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetSidSubAuthorityCount failed.");
            }
            var count = Marshal.ReadByte(countPointer);
            if (count == 0)
            {
                throw new InvalidDataException("Token integrity SID is malformed.");
            }
            var ridPointer = NativeIdentity.GetSidSubAuthority(label.Label.Sid, checked((uint)count - 1));
            if (ridPointer == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetSidSubAuthority failed.");
            }
            return Marshal.ReadInt32(ridPointer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static AdministratorGroupMembership ReadAdministratorMembership(SafeAccessTokenHandle token)
    {
        var administratorSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var buffer = ReadVariableTokenInformation(token, NativeIdentity.TokenInformationClass.TokenGroups);
        try
        {
            var count = checked((uint)Marshal.ReadInt32(buffer));
            var entryOffset = Marshal.OffsetOf<NativeIdentity.TokenGroupsHeader>(
                nameof(NativeIdentity.TokenGroupsHeader.FirstGroup)).ToInt32();
            var entrySize = Marshal.SizeOf<NativeIdentity.SidAndAttributes>();
            for (uint index = 0; index < count; index++)
            {
                var entryPointer = IntPtr.Add(buffer, checked(entryOffset + (int)index * entrySize));
                var entry = Marshal.PtrToStructure<NativeIdentity.SidAndAttributes>(entryPointer);
                if (entry.Sid == IntPtr.Zero || !administratorSid.Equals(new SecurityIdentifier(entry.Sid)))
                {
                    continue;
                }
                if ((entry.Attributes & NativeIdentity.SeGroupUseForDenyOnly) != 0)
                {
                    return AdministratorGroupMembership.DenyOnly;
                }
                return (entry.Attributes & NativeIdentity.SeGroupEnabled) != 0
                    ? AdministratorGroupMembership.Enabled
                    : AdministratorGroupMembership.Absent;
            }
            return AdministratorGroupMembership.Absent;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IntPtr ReadVariableTokenInformation(
        SafeAccessTokenHandle token,
        NativeIdentity.TokenInformationClass informationClass)
    {
        _ = NativeIdentity.GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out var size);
        var error = Marshal.GetLastWin32Error();
        if (size <= 0 || error != NativeIdentity.ErrorInsufficientBuffer)
        {
            throw new Win32Exception(error, "GetTokenInformation sizing failed.");
        }
        var buffer = Marshal.AllocHGlobal(size);
        if (!NativeIdentity.GetTokenInformation(token, informationClass, buffer, size, out _))
        {
            var failure = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(buffer);
            throw new Win32Exception(failure, "GetTokenInformation failed.");
        }
        return buffer;
    }
}

internal static class NativeIdentity
{
    internal const uint TokenQuery = 0x0008;
    internal const int ErrorInsufficientBuffer = 122;
    internal const uint SeGroupEnabled = 0x00000004;
    internal const uint SeGroupUseForDenyOnly = 0x00000010;

    internal enum TokenInformationClass
    {
        TokenGroups = 2,
        TokenElevationType = 18,
        TokenIntegrityLevel = 25,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TokenMandatoryLabel
    {
        public SidAndAttributes Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TokenGroupsHeader
    {
        public uint GroupCount;
        public SidAndAttributes FirstGroup;
    }

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        TokenInformationClass tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthority);
}
