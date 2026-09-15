using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.Loader;
using Ensou.Dsh.Enterprise.Installation;

const string ReleaseX = "2N_Gf2Sd2psMzflS-3tMN3Zj5p1AScLHHVblKgA9GzQ";
const string ReleaseY = "T86eGwq3Hm-vFYCErjH-5xaReKY1dYL7mm2KYS93iWc";
const string LeaseX = "094iG_AbBl-L3H_HM9rc6xfnHboQcC1AIQb8ppeObXg";
const string LeaseY = "cOYCMkj9OEa4gTfC-e-CUCgNY5BuuWR6Zy22SeEThe0";
const string Signer =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

try
{
    return Run(args);
}
catch (Exception exception)
{
    Console.Error.WriteLine($"FAIL direct-local Launcher self-check: {exception.GetType().Name}");
    return 1;
}

static int Run(string[] arguments)
{
if (arguments is not [var launcherAssemblyPath]
    || !File.Exists(launcherAssemblyPath))
{
    throw new InvalidOperationException(
        "Expected one path to the compiled direct-local production Launcher assembly.");
}

var loadContext = new LauncherTestLoadContext(Path.GetFullPath(launcherAssemblyPath));
var launcherAssembly = loadContext.LoadFromAssemblyPath(Path.GetFullPath(launcherAssemblyPath));
var profileType = launcherAssembly.GetType(
    "Ensou.Dsh.Enterprise.Launcher.EnterpriseBuildProfile",
    throwOnError: true)!;
var directSelection = (bool)(profileType.GetField(
        "IsDirectLocalRuntimeAdmission",
        BindingFlags.Public | BindingFlags.Static)
    ?.GetRawConstantValue()
    ?? throw new InvalidOperationException("Direct-local compile selector is unavailable."));
Check(directSelection, "direct-local compile selector");

var expected = EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(new(
    EnterpriseDirectLocalProductionTrustFingerprint.RuntimeProfile,
    EnterpriseDirectLocalProductionTrustFingerprint.ApiProvider,
    "https://updates.example.invalid:8443/dsh/pilot/release-set.v2.json",
    "https://updates.example.invalid:8443/",
    "https://artifacts.example.invalid:8443/",
    "release-test",
    ReleaseX,
    ReleaseY,
    "https://control.example.invalid:8443/",
    "https://authorization.example.invalid:8443/",
    "https://managed.example.invalid:8443/",
    "lease-test",
    LeaseX,
    LeaseY,
    Signer));

var create = RequireMethod(profileType, "CreateProductionTrustFingerprint");
var require = RequireMethod(profileType, "RequireProductionTrustFingerprint");
var actual = (string)(Invoke(create, null) ?? throw new InvalidOperationException(
    "Production trust fingerprint was empty."));
Check(string.Equals(expected, actual, StringComparison.Ordinal), "exact v2 fingerprint");
Invoke(require, actual);
Check(true, "matching self-check accepts");

var mismatch = actual[0] == '0' ? $"1{actual[1..]}" : $"0{actual[1..]}";
Reject<InvalidDataException>(() => Invoke(require, mismatch));
Reject<InvalidDataException>(() => Invoke(require, actual.ToUpperInvariant()));

Console.WriteLine(
    "PASS direct-local production trust self-check accepts exact v2 and rejects mismatch; no signature or system-trust operation.");
return 0;
}

static MethodInfo RequireMethod(Type type, string name) => type.GetMethod(
        name,
        BindingFlags.Public | BindingFlags.Static)
    ?? throw new InvalidOperationException($"Launcher trust method {name} is unavailable.");

static object? Invoke(MethodInfo method, params object?[]? arguments)
{
    try
    {
        return method.Invoke(null, arguments);
    }
    catch (TargetInvocationException exception) when (exception.InnerException is not null)
    {
        ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
        throw;
    }
}

static void Check(bool condition, string label)
{
    if (!condition)
    {
        throw new InvalidOperationException(label);
    }
}

static void Reject<TException>(Action action)
    where TException : Exception
{
    try
    {
        action();
    }
    catch (TException)
    {
        return;
    }
    throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
}

// Resolve product dependencies beside the actual Launcher, never from the test
// host's Installation assembly (which may have a different compiled signer).
sealed class LauncherTestLoadContext(string launcherPath) : AssemblyLoadContext(isCollectible: true)
{
    private readonly AssemblyDependencyResolver _resolver = new(launcherPath);

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        if (assemblyName.Name is null || !assemblyName.Name.StartsWith("Ensou.Dsh.", StringComparison.Ordinal))
            return null;
        var resolved = _resolver.ResolveAssemblyToPath(assemblyName)
            ?? Path.Combine(Path.GetDirectoryName(launcherPath)!, assemblyName.Name + ".dll");
        if (!File.Exists(resolved))
            throw new FileNotFoundException("Product dependency is missing from the Launcher output.");
        return LoadFromAssemblyPath(resolved);
    }
}
