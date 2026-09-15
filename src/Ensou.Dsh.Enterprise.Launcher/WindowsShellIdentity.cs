using System.Runtime.InteropServices;

namespace Ensou.Dsh.Enterprise.Launcher;

internal static class WindowsShellIdentity
{
    public static void ApplyCurrentProcessAppUserModelId(string appUserModelId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appUserModelId);
        Marshal.ThrowExceptionForHR(SetCurrentProcessExplicitAppUserModelID(appUserModelId));
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appId);
}
