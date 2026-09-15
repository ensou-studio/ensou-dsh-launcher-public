using System.Diagnostics;

namespace Ensou.Dsh.Host;

public enum DshRuntimeMode
{
    Personal = 0,
    EnterpriseManaged = 1,
    EnterpriseDirectLocal = 2,
}

public sealed record DshRuntimeOptions(
    string RuntimeDirectory,
    string DataDirectory,
    string LogDirectory,
    string Host = "127.0.0.1",
    int Port = 3080,
    TimeSpan? StartupTimeout = null,
    bool CaptureRawProcessOutput = false,
    IReadOnlyDictionary<string, string>? ControlledEnvironment = null,
    DshRuntimeMode Mode = DshRuntimeMode.Personal,
    string? WorkingDirectory = null,
    string? Profile = null,
    int? EnterpriseManagedFixedPort = null,
    IReadOnlyList<string>? AdditionalArguments = null,
    string? EnterpriseManagedPluginRoot = null,
    string? EnterpriseManagedSkillsRoot = null,
    bool EnablePersonalManagedUpdate = false)
{
    public const string EnterpriseManagedProfile = "enterprise-managed";
    public const string EnterpriseDirectLocalProfile =
        DshRuntimeMetadata.EnterpriseDirectLocalProfile;
    public const string EnterpriseManagedBootMarker = "ensou-dsh-launcher/v1";
    public const string PersonalManagedUpdateBootEnvironmentVariable =
        "ENSOU_DSH_PERSONAL_UPDATE_BOOT";
    public const string PersonalManagedUpdateBootMarker =
        "ensou-dsh-personal-launcher/v1";
    public const string LoopbackNoProxy = "127.0.0.1,localhost,::1";
    public const string EnterpriseManagedSkillsRootEnvironmentVariable =
        "ENSOU_DSH_ENTERPRISE_SKILLS_ROOT";

    private static readonly HashSet<string> AllowedControlledEnvironmentKeys =
        new(StringComparer.Ordinal)
        {
            "DEEPSEEK_BASE_URL",
            "DEEPSEEK_API_KEY",
            "DEEPSEEK_SEARCH_BASE_URL",
        };

    public string NodePath => Path.Combine(RuntimeDirectory, "node.exe");

    public string EntryPointPath => Path.Combine(
        RuntimeDirectory,
        "node_modules",
        "@deepseek-ai",
        "dsh",
        "lib",
        "bin.js");

    public Uri WebUiUri => new($"http://{Host}:{Port}/", UriKind.Absolute);

    public string EffectiveWorkingDirectory => WorkingDirectory ?? RuntimeDirectory;

    public bool IsEnterpriseManaged => Mode == DshRuntimeMode.EnterpriseManaged;

    public bool IsEnterpriseDirectLocal => Mode == DshRuntimeMode.EnterpriseDirectLocal;

    private bool IsEnterprise => IsEnterpriseManaged || IsEnterpriseDirectLocal;

    /// <summary>
    /// A private Launcher capability, independently opt-in from enterprise mode.
    /// </summary>
    public bool SupportsManagedUpdate => IsEnterprise || EnablePersonalManagedUpdate;

    public DshRuntimeWebAuthProtocol WebAuthProtocol =>
        DshRuntimeMetadata.ReadWebAuthProtocol(RuntimeDirectory);

    public TimeSpan EffectiveStartupTimeout => StartupTimeout ?? TimeSpan.FromSeconds(45);

    public static DshRuntimeOptions CreateEnterpriseManaged(
        string runtimeDirectory,
        string dataDirectory,
        string logDirectory,
        string workspaceRoot,
        int fixedPort,
        string pluginRoot,
        string skillsRoot,
        IReadOnlyDictionary<string, string>? controlledEnvironment = null) => new(
            runtimeDirectory,
            dataDirectory,
            logDirectory,
            Host: "127.0.0.1",
            Port: fixedPort,
            CaptureRawProcessOutput: false,
            ControlledEnvironment: controlledEnvironment,
            Mode: DshRuntimeMode.EnterpriseManaged,
            WorkingDirectory: workspaceRoot,
            Profile: EnterpriseManagedProfile,
            EnterpriseManagedFixedPort: fixedPort,
            AdditionalArguments: null,
            EnterpriseManagedPluginRoot: pluginRoot,
            EnterpriseManagedSkillsRoot: skillsRoot);

    public static DshRuntimeOptions CreatePersonalManagedWeb(
        string runtimeDirectory,
        string dataDirectory,
        string logDirectory,
        int port) => new(
            runtimeDirectory,
            dataDirectory,
            logDirectory,
            Host: "127.0.0.1",
            Port: port,
            Mode: DshRuntimeMode.Personal,
            EnablePersonalManagedUpdate: true);

    public static DshRuntimeOptions CreateEnterpriseDirectLocal(
        string runtimeDirectory,
        string dataDirectory,
        string logDirectory,
        string workspaceRoot,
        int fixedPort,
        string pluginRoot,
        string skillsRoot) => new(
            runtimeDirectory,
            dataDirectory,
            logDirectory,
            Host: "127.0.0.1",
            Port: fixedPort,
            CaptureRawProcessOutput: false,
            ControlledEnvironment: null,
            Mode: DshRuntimeMode.EnterpriseDirectLocal,
            WorkingDirectory: workspaceRoot,
            Profile: EnterpriseDirectLocalProfile,
            EnterpriseManagedFixedPort: fixedPort,
            AdditionalArguments: null,
            EnterpriseManagedPluginRoot: pluginRoot,
            EnterpriseManagedSkillsRoot: skillsRoot);

    public void Validate()
    {
        if (!Enum.IsDefined(Mode))
        {
            throw new InvalidOperationException("The DSH runtime mode is invalid.");
        }
        if (string.IsNullOrWhiteSpace(RuntimeDirectory)
            || !Path.IsPathFullyQualified(RuntimeDirectory))
        {
            throw new InvalidOperationException(
                "The DSH runtime directory must be an absolute path.");
        }
        if (string.IsNullOrWhiteSpace(DataDirectory)
            || !Path.IsPathFullyQualified(DataDirectory))
        {
            throw new InvalidOperationException(
                "The DSH data directory must be an absolute path.");
        }
        _ = WebAuthProtocol;
        if (string.IsNullOrWhiteSpace(EffectiveWorkingDirectory)
            || !Path.IsPathFullyQualified(EffectiveWorkingDirectory))
        {
            throw new InvalidOperationException(
                "The DSH working directory must be an absolute path.");
        }
        if (Port is < 1 or > 65535)
        {
            throw new InvalidOperationException(
                "The DSH port must be between 1 and 65535.");
        }
        if (AdditionalArguments is { Count: > 0 })
        {
            throw new InvalidOperationException(
                "The DSH Host does not accept additional process arguments.");
        }

        if (IsEnterprise)
        {
            if (EnablePersonalManagedUpdate)
            {
                throw new InvalidOperationException(
                    "Enterprise managed DSH mode may not enable the Personal managed-update capability.");
            }
            ValidateEnterpriseBoundary();
        }
        else
        {
            if (Profile is not null
                || EnterpriseManagedFixedPort is not null
                || EnterpriseManagedPluginRoot is not null
                || EnterpriseManagedSkillsRoot is not null)
            {
                throw new InvalidOperationException(
                    "Personal DSH mode may not declare enterprise launch constraints.");
            }
            if (EnablePersonalManagedUpdate)
            {
                ValidatePersonalManagedUpdateBoundary();
            }
        }

        ValidateControlledEnvironment();
        if (!File.Exists(NodePath))
        {
            throw new FileNotFoundException(
                "The bundled node.exe was not found.",
                NodePath);
        }
        if (!File.Exists(EntryPointPath))
        {
            throw new FileNotFoundException(
                "The bundled DSH entry point was not found.",
                EntryPointPath);
        }
        if (IsEnterprise
            && ((File.GetAttributes(NodePath) & FileAttributes.ReparsePoint) != 0
                || (File.GetAttributes(EntryPointPath) & FileAttributes.ReparsePoint) != 0))
        {
            throw new InvalidOperationException(
                "Enterprise managed DSH executable paths may not be filesystem links.");
        }
    }

    internal IReadOnlyList<string> GetLaunchArguments() => IsEnterprise
        ?
        [
            EntryPointPath,
            "--profile",
            Profile!,
            // Managed boot accepts exactly host/port arguments; its policy disables browser opening.
            "--host",
            "127.0.0.1",
            "--port",
            Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ]
        :
        [
            EntryPointPath,
            "web",
            "--no-open",
            "--host",
            Host,
            "--port",
            Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ];

    internal void ApplyProcessEnvironment(ProcessStartInfo startInfo)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        if (SupportsManagedUpdate)
        {
            Validate();
        }

        RemoveUnsafeDshProcessEnvironment(startInfo);
        var (windowsDirectory, systemDirectory) = GetTrustedWindowsDirectories();
        var pathEntries = new[]
        {
            RuntimeDirectory,
            systemDirectory,
            windowsDirectory,
            Path.Combine(systemDirectory, "Wbem"),
            Path.Combine(systemDirectory, "WindowsPowerShell", "v1.0"),
        };
        if (pathEntries.Any(path => path.Contains(Path.PathSeparator)))
        {
            throw new InvalidOperationException(
                "DSH process PATH contains an invalid separator.");
        }

        startInfo.Environment["SystemRoot"] = windowsDirectory;
        startInfo.Environment["WINDIR"] = windowsDirectory;
        startInfo.Environment["COMSPEC"] = Path.Combine(systemDirectory, "cmd.exe");
        startInfo.Environment["PATH"] = string.Join(Path.PathSeparator, pathEntries);
        startInfo.Environment["DSH_HOME"] = DataDirectory;
        startInfo.Environment["DSH_TELEMETRY_DISABLED"] = "1";
        ApplyControlledEnvironment(startInfo);
        if (EnablePersonalManagedUpdate)
        {
            startInfo.Environment[PersonalManagedUpdateBootEnvironmentVariable] =
                PersonalManagedUpdateBootMarker;
        }
        if (!IsEnterprise)
        {
            return;
        }

        startInfo.Environment["DSH_ENTERPRISE_MANAGED_BOOT"] = EnterpriseManagedBootMarker;
        startInfo.Environment[EnterpriseManagedSkillsRootEnvironmentVariable] =
            EnterpriseManagedSkillsRoot!;
        startInfo.Environment["NO_PROXY"] = LoopbackNoProxy;
    }

    internal void ApplyControlledEnvironment(ProcessStartInfo startInfo)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        if (ControlledEnvironment is null)
        {
            return;
        }

        ValidateControlledEnvironment();
        foreach (var key in AllowedControlledEnvironmentKeys)
        {
            RemoveEnvironmentKeyCaseInsensitive(startInfo, key);
            startInfo.Environment[key] = ControlledEnvironment[key];
        }
    }

    private void ValidateEnterpriseBoundary()
    {
        var expectedProfile = IsEnterpriseDirectLocal
            ? EnterpriseDirectLocalProfile
            : EnterpriseManagedProfile;
        if (!OperatingSystem.IsWindows()
            || !string.Equals(Profile, expectedProfile, StringComparison.Ordinal)
            || !string.Equals(Host, "127.0.0.1", StringComparison.Ordinal)
            || EnterpriseManagedFixedPort is null
            || EnterpriseManagedFixedPort.Value is < 1 or > 65535
            || Port != EnterpriseManagedFixedPort
            || CaptureRawProcessOutput
            || (IsEnterpriseManaged && ControlledEnvironment is null)
            || (IsEnterpriseDirectLocal && ControlledEnvironment is not null)
            || (IsEnterpriseDirectLocal
                && !DshRuntimeMetadata.ReadSupportsEnterpriseDirectLocal(RuntimeDirectory))
            || string.IsNullOrWhiteSpace(EnterpriseManagedPluginRoot)
            || string.IsNullOrWhiteSpace(EnterpriseManagedSkillsRoot)
            || string.IsNullOrWhiteSpace(LogDirectory)
            || !Path.IsPathFullyQualified(LogDirectory))
        {
            throw new InvalidOperationException(
                "Enterprise managed DSH launch constraints are invalid.");
        }

        var dataRoot = NormalizeDirectory(DataDirectory);
        var workingRoot = NormalizeDirectory(EffectiveWorkingDirectory);
        var expectedWorkspace = NormalizeDirectory(Path.Combine(dataRoot, "workspaces"));
        var pluginRoot = NormalizeDirectory(EnterpriseManagedPluginRoot!);
        var skillsRoot = NormalizeDirectory(EnterpriseManagedSkillsRoot!);
        if (!string.Equals(DataDirectory, dataRoot, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                EffectiveWorkingDirectory,
                workingRoot,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(workingRoot, expectedWorkspace, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                EnterpriseManagedPluginRoot,
                pluginRoot,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                EnterpriseManagedSkillsRoot,
                skillsRoot,
                StringComparison.OrdinalIgnoreCase)
            || !Directory.Exists(dataRoot)
            || !Directory.Exists(workingRoot)
            || !Directory.Exists(pluginRoot)
            || !Directory.Exists(skillsRoot)
            || !IsStrictDescendant(skillsRoot, pluginRoot)
            || (File.GetAttributes(dataRoot) & FileAttributes.ReparsePoint) != 0
            || (File.GetAttributes(workingRoot) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException(
                "Enterprise managed DSH working and plugin directories are invalid or linked.");
        }
        RejectReparseChain(pluginRoot, skillsRoot);
    }

    private void ValidatePersonalManagedUpdateBoundary()
    {
        if (!OperatingSystem.IsWindows()
            || !string.Equals(Host, "127.0.0.1", StringComparison.Ordinal)
            || !DshRuntimeMetadata.ReadSupportsPersonalManagedUpdate(RuntimeDirectory))
        {
            throw new InvalidOperationException(
                "Personal managed-update launch constraints are invalid.");
        }
    }

    private void ValidateControlledEnvironment()
    {
        if (ControlledEnvironment is null)
        {
            return;
        }
        if (ControlledEnvironment.Count != AllowedControlledEnvironmentKeys.Count
            || ControlledEnvironment.Keys.Any(
                key => !AllowedControlledEnvironmentKeys.Contains(key))
            || AllowedControlledEnvironmentKeys.Any(
                key => !ControlledEnvironment.ContainsKey(key)))
        {
            throw new InvalidOperationException(
                "Controlled DSH environment must contain only the exact managed provider keys.");
        }

        var baseUrlText = ControlledEnvironment["DEEPSEEK_BASE_URL"];
        if (!Uri.TryCreate(baseUrlText, UriKind.Absolute, out var baseUrl)
            || !string.Equals(
                baseUrl.Scheme,
                Uri.UriSchemeHttp,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(baseUrl.Host, "127.0.0.1", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(baseUrl.UserInfo)
            || !string.IsNullOrEmpty(baseUrl.Query)
            || !string.IsNullOrEmpty(baseUrl.Fragment)
            || baseUrl.AbsolutePath is not "/v1"
            || !string.Equals(
                baseUrlText,
                $"http://127.0.0.1:{baseUrl.Port.ToString(System.Globalization.CultureInfo.InvariantCulture)}/v1",
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Controlled DSH base URL must be an exact 127.0.0.1 HTTP /v1 endpoint.");
        }

        var searchBaseUrlText = ControlledEnvironment["DEEPSEEK_SEARCH_BASE_URL"];
        if (!string.Equals(searchBaseUrlText, baseUrlText, StringComparison.Ordinal)
            || !Uri.TryCreate(searchBaseUrlText, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException(
                "Controlled DSH search base URL must equal the loopback model base URL so Phase 1 search fails locally.");
        }

        var apiKey = ControlledEnvironment["DEEPSEEK_API_KEY"];
        if (apiKey.Length != 43
            || apiKey.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '_'))
        {
            throw new InvalidOperationException(
                "Controlled DSH API key must be one canonical 32-byte base64url token.");
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(
                apiKey.Replace('-', '+').Replace('_', '/') + "=");
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                "Controlled DSH API key must be canonical base64url.",
                exception);
        }

        try
        {
            var canonical = Convert.ToBase64String(decoded)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            if (decoded.Length != 32
                || !string.Equals(canonical, apiKey, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "Controlled DSH API key must encode exactly 32 bytes canonically.");
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(decoded);
        }
    }

    private static void RemoveUnsafeDshProcessEnvironment(ProcessStartInfo startInfo)
    {
        foreach (var key in startInfo.Environment.Keys.ToArray())
        {
            if (IsUnsafeDshProcessEnvironmentKey(key))
            {
                startInfo.Environment.Remove(key);
            }
        }
    }

    private static bool IsUnsafeDshProcessEnvironmentKey(string key) =>
        key.StartsWith("NODE_", StringComparison.OrdinalIgnoreCase)
        || key.StartsWith("FNM_", StringComparison.OrdinalIgnoreCase)
        || key.StartsWith("PNPM_", StringComparison.OrdinalIgnoreCase)
        || key.StartsWith("NPM_CONFIG_", StringComparison.OrdinalIgnoreCase)
        || key.StartsWith("DSH_", StringComparison.OrdinalIgnoreCase)
        || key.StartsWith("DEEPSEEK_", StringComparison.OrdinalIgnoreCase)
        || key.Equals(
            EnterpriseManagedSkillsRootEnvironmentVariable,
            StringComparison.OrdinalIgnoreCase)
        || key.Equals(
            PersonalManagedUpdateBootEnvironmentVariable,
            StringComparison.OrdinalIgnoreCase)
        || key.EndsWith("_PROXY", StringComparison.OrdinalIgnoreCase)
        || key.Equals("SSLKEYLOGFILE", StringComparison.OrdinalIgnoreCase)
        || key.Equals("OPENSSL_CONF", StringComparison.OrdinalIgnoreCase)
        || key.Equals("PATH", StringComparison.OrdinalIgnoreCase)
        || key.Equals("SYSTEMROOT", StringComparison.OrdinalIgnoreCase)
        || key.Equals("WINDIR", StringComparison.OrdinalIgnoreCase)
        || key.Equals("COMSPEC", StringComparison.OrdinalIgnoreCase);

    private static void RemoveEnvironmentKeyCaseInsensitive(
        ProcessStartInfo startInfo,
        string expectedKey)
    {
        foreach (var existingKey in startInfo.Environment.Keys
            .Where(key => string.Equals(
                key,
                expectedKey,
                StringComparison.OrdinalIgnoreCase))
            .ToArray())
        {
            startInfo.Environment.Remove(existingKey);
        }
    }

    private static (string WindowsDirectory, string SystemDirectory)
        GetTrustedWindowsDirectories()
    {
        var windowsDirectory = NormalizeDirectory(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        var systemDirectory = NormalizeDirectory(Environment.SystemDirectory);
        if (!Path.IsPathFullyQualified(windowsDirectory)
            || !Path.IsPathFullyQualified(systemDirectory)
            || !Directory.Exists(windowsDirectory)
            || !Directory.Exists(systemDirectory)
            || (!string.Equals(
                    systemDirectory,
                    windowsDirectory,
                    StringComparison.OrdinalIgnoreCase)
                && !systemDirectory.StartsWith(
                    windowsDirectory + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException(
                "Trusted Windows system directories are unavailable.");
        }
        return (windowsDirectory, systemDirectory);
    }

    private static string NormalizeDirectory(string path) =>
        Path.GetFullPath(path).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);

    private static bool IsStrictDescendant(string candidate, string root) =>
        !string.Equals(candidate, root, StringComparison.OrdinalIgnoreCase)
        && candidate.StartsWith(
            root + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);

    private static void RejectReparseChain(string root, string descendant)
    {
        var current = descendant;
        while (true)
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException(
                    "Enterprise managed plugin paths may not cross filesystem links.");
            }
            if (string.Equals(current, root, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            current = Path.GetDirectoryName(current)
                ?? throw new InvalidOperationException(
                    "Enterprise managed skills root has no trusted plugin parent.");
        }
    }

    public override string ToString() => IsEnterpriseManaged
        ? $"DSH runtime {RuntimeDirectory}, data {DataDirectory}, {Host}:{Port} " +
            $"[EnterpriseManaged; web auth {DshRuntimeWebAuthProtocolContract.GetName(WebAuthProtocol)}; environment redacted]"
        : IsEnterpriseDirectLocal
        ? $"DSH runtime {RuntimeDirectory}, data {DataDirectory}, {Host}:{Port} " +
            $"[EnterpriseDirectLocal; web auth {DshRuntimeWebAuthProtocolContract.GetName(WebAuthProtocol)}; environment redacted]"
        : EnablePersonalManagedUpdate
        ? $"DSH runtime {RuntimeDirectory}, data {DataDirectory}, " +
            $"{Host}:{Port} [PersonalManagedUpdate; web auth {DshRuntimeWebAuthProtocolContract.GetName(WebAuthProtocol)}; environment redacted]"
        : $"DSH runtime {RuntimeDirectory}, data {DataDirectory}, " +
            $"{Host}:{Port} [web auth {DshRuntimeWebAuthProtocolContract.GetName(WebAuthProtocol)}; environment redacted]";
}
