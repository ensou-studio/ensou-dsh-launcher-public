using System.Runtime.InteropServices;

namespace Ensou.Dsh.Enterprise.Installation;

public static class EnterpriseClientPlatform
{
    public const string ProtocolPlatform = "windows-x64";

    public static bool IsSupported => IsSupportedArchitecture(
        OperatingSystem.IsWindows(),
        RuntimeInformation.OSArchitecture,
        RuntimeInformation.ProcessArchitecture);

    public static bool IsSupportedArchitecture(
        bool isWindows,
        Architecture osArchitecture,
        Architecture processArchitecture) =>
        isWindows
        && osArchitecture == Architecture.X64
        && processArchitecture == Architecture.X64;

    public static void RequireSupported()
    {
        if (!IsSupported)
        {
            throw new PlatformNotSupportedException(
                "Ensou DSH Enterprise 当前仅支持 Windows 10/11 x64；ARM64、LoongArch、UOS、麒麟及模拟运行环境尚未认证，请联系管理员。");
        }
    }
}
