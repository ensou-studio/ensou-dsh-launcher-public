using System.Drawing;
using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Ensou.Dsh.Launcher;

internal static class LauncherBrandAssets
{
    private const string IconResourceName =
        "Ensou.Dsh.Launcher.dsh-official-whale.ico";

    public static Icon LoadDrawingIcon()
    {
        using var stream = OpenIcon();
        using var icon = new Icon(stream);
        return (Icon)icon.Clone();
    }

    public static ImageSource LoadWindowIcon()
    {
        using var stream = OpenIcon();
        var frame = BitmapFrame.Create(
            stream,
            BitmapCreateOptions.PreservePixelFormat,
            BitmapCacheOption.OnLoad);
        frame.Freeze();
        return frame;
    }

    private static Stream OpenIcon() => typeof(LauncherBrandAssets)
        .Assembly
        .GetManifestResourceStream(IconResourceName)
        ?? throw new InvalidDataException(
            "The embedded official DeepSeek Harness icon is missing.");
}
