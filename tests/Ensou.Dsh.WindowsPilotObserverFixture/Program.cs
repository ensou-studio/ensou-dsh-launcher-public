using System.Runtime.InteropServices;

namespace Ensou.Dsh.WindowsPilotObserverFixture;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 2
            || !int.TryParse(args[1], out var milliseconds)
            || milliseconds is < 50 or > 30_000)
        {
            return 64;
        }
        return args[0] switch
        {
            "--flash-dialog" => ShowTransientDialog(milliseconds),
            "--flash-console" => ShowTransientConsole(milliseconds),
            "--quiet" => WaitQuietly(milliseconds),
            _ => 64,
        };
    }

    private static int ShowTransientDialog(int milliseconds)
    {
        Application.EnableVisualStyles();
        using var form = new Form
        {
            Text = "dotnet.exe - Application Error",
            Width = 500,
            Height = 180,
            StartPosition = FormStartPosition.CenterScreen,
        };
        var timer = new System.Windows.Forms.Timer { Interval = milliseconds };
        timer.Tick += (_, _) => form.Close();
        form.Shown += (_, _) => timer.Start();
        Application.Run(form);
        timer.Dispose();
        return 0;
    }

    private static int ShowTransientConsole(int milliseconds)
    {
        if (!AllocConsole())
        {
            return Marshal.GetLastWin32Error();
        }
        Thread.Sleep(milliseconds);
        return FreeConsole() ? 0 : Marshal.GetLastWin32Error();
    }

    private static int WaitQuietly(int milliseconds)
    {
        Thread.Sleep(milliseconds);
        return 0;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeConsole();
}
