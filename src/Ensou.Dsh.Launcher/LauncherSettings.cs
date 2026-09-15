using System.IO;
using System.Text.Json;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Launcher;

public sealed record LauncherSettings
{
    public int SchemaVersion { get; init; } = 1;

    public string Channel { get; init; } = "stable";

    public string ManifestUrl { get; init; } = string.Empty;

    public string DevelopmentManifestPublicKeyPath { get; init; } = DefaultDevelopmentPublicKeyPath();

    public string DevelopmentManifestKeyId { get; init; } = "personal-development";

    public string DevelopmentArtifactOrigin { get; init; } = string.Empty;

    public string DevelopmentStartupStubVersion { get; init; } = "1.2.0";

    public string RuntimeDirectory { get; init; } = DefaultRuntimeDirectory();

    public string RuntimeRootDirectory { get; init; } = DefaultRuntimeRootDirectory();

    public string DshDataDirectory { get; init; } = DefaultDshDataDirectory();

    public string LogDirectory { get; init; } = DefaultLogDirectory();

    public string PackageDirectory { get; init; } = DefaultPackageDirectory();

    public int Port { get; init; } = 3080;

    public bool OpenWebUiAfterStart { get; init; } = true;

    public static string SettingsPath()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(root, "Ensou", "DshLauncher", "launcher.settings.json");
    }

    public static LauncherSettings LoadOrCreate()
    {
        var path = SettingsPath();
        var serializerOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };

        if (!File.Exists(path))
        {
            var settings = new LauncherSettings();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(settings, serializerOptions));
            return settings;
        }

        var loaded = JsonSerializer.Deserialize<LauncherSettings>(
            File.ReadAllText(path),
            serializerOptions)
            ?? throw new InvalidDataException("Launcher 配置为空。");

        if (loaded.SchemaVersion != 1)
        {
            throw new InvalidDataException($"不支持的 Launcher 配置版本：{loaded.SchemaVersion}");
        }

        if (loaded.Port is < 1 or > 65535)
        {
            throw new InvalidDataException("Launcher 配置中的端口必须为 1-65535。");
        }

        return loaded;
    }

    public string ResolveRuntimeDirectory() =>
        ResolveRuntimeDirectory(PersonalInstallationLayout.CreateDefault());

    internal string ResolveRuntimeDirectory(PersonalInstallationLayout personalLayout)
    {
        ArgumentNullException.ThrowIfNull(personalLayout);
        var releaseSet = new PersonalReleaseSetPointerStore(personalLayout).TryRead();
        if (releaseSet is not null)
        {
            if (releaseSet.Current.HealthState != PersonalReleaseHealthStates.Healthy)
            {
                throw new InvalidDataException(
                    "Personal release-set is pending health; restart through the stable Startup Stub.");
            }
            return releaseSet.Current.Runtime.Directory;
        }

        if (string.Equals(
                Environment.GetEnvironmentVariable("ENSOU_DSH_ALLOW_DEVELOPMENT_RUNTIME"),
                "1",
                StringComparison.Ordinal))
        {
            return Path.GetFullPath(RuntimeDirectory);
        }

        var pointer = RuntimePointer.TryRead(RuntimePointer.StatePath());
        if (pointer is not null)
        {
            pointer.ValidateForRuntimeRoot(GetRuntimeRootDirectory());
            return pointer.RuntimeDirectory;
        }

        return Path.Combine(GetRuntimeRootDirectory(), "uninstalled");
    }

    public string GetRuntimeRootDirectory()
    {
        var allowDevelopmentRoot = string.Equals(
            Environment.GetEnvironmentVariable("ENSOU_DSH_ALLOW_DEVELOPMENT_RUNTIME"),
            "1",
            StringComparison.Ordinal);
        return Path.GetFullPath(allowDevelopmentRoot
            ? RuntimeRootDirectory
            : DefaultRuntimeRootDirectory());
    }

    private static string DefaultRoot()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(root, "Ensou", "DshLauncher");
    }

    private static string DefaultRuntimeRootDirectory() => Path.Combine(DefaultRoot(), "runtimes");

    private static string DefaultRuntimeDirectory() => Path.Combine(DefaultRuntimeRootDirectory(), "bootstrap");

    private static string DefaultLogDirectory() => Path.Combine(DefaultRoot(), "logs");

    private static string DefaultPackageDirectory() => Path.Combine(DefaultRoot(), "packages");

    private static string DefaultDevelopmentPublicKeyPath() =>
        Path.Combine(DefaultRoot(), "security", "development-release-public-key.pem");

    private static string DefaultDshDataDirectory()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(profile, ".dsh");
    }
}
