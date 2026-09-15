using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.Installation;
using System.IO;
using System.Reflection;

namespace Ensou.Dsh.Enterprise.Launcher;

#if ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E && !ENTERPRISE_DEVELOPMENT_E2E
#error Enterprise direct-local composition requires an isolated Development-E2E build.
#endif

internal static class EnterpriseBuildProfile
{
    // Public origins are signed build inputs. Secrets must never be added here.
    private static readonly ProfileInputs Inputs = LoadInputs();
    private static readonly ReleaseUpdateInputs UpdateInputs = LoadReleaseUpdateInputs();
#if ENTERPRISE_DEVELOPMENT_E2E
    private static readonly DevelopmentFilesystemInputs DevelopmentFilesystem =
        LoadDevelopmentFilesystemInputs();
#endif

#if ENTERPRISE_DEVELOPMENT_E2E
    public const bool IsDevelopmentE2E = true;
#else
    public const bool IsDevelopmentE2E = false;
#endif

#if ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E
    // Compile-time rehearsal selection; runtime metadata must never opt in implicitly.
    public const bool IsDirectLocalDevelopmentE2E = true;
#else
    public const bool IsDirectLocalDevelopmentE2E = false;
#endif

#if ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E || ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
    // Compile-time admission selection; an exact signed lease must still authorize
    // this profile before an owned Harness process can start.
    public const bool IsDirectLocalRuntimeAdmission = true;
#else
    public const bool IsDirectLocalRuntimeAdmission = false;
#endif

    public static string ProductName => IsDevelopmentE2E
        ? EnterpriseProductIdentity.DevelopmentE2EProductName
        : EnterpriseProductIdentity.ProductName;

    public static string AppUserModelId => IsDevelopmentE2E
        ? EnterpriseProductIdentity.DevelopmentE2EAppUserModelId
        : EnterpriseProductIdentity.AppUserModelId;

    public static string SingleInstanceMutexName => IsDevelopmentE2E
        ? EnterpriseProductIdentity.DevelopmentE2ESingleInstanceMutexName
        : EnterpriseProductIdentity.SingleInstanceMutexName;

    public static string ActivationEventName => IsDevelopmentE2E
        ? EnterpriseProductIdentity.DevelopmentE2EActivationEventName
        : EnterpriseProductIdentity.ActivationEventName;

    public static int DefaultPort => IsDevelopmentE2E
        ? EnterpriseProductIdentity.DevelopmentE2EDefaultPort
        : EnterpriseProductIdentity.DefaultPort;

    public static string ExpectedReleaseChannel =>
        EnterpriseReleaseSetContract.ChannelForDevelopmentE2E(IsDevelopmentE2E);

    public static EnterpriseManagedPaths CreateManagedPaths()
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        return DevelopmentFilesystem.HasIsolatedRoots
            ? EnterpriseManagedPaths.CreateDevelopmentE2E(
                DevelopmentFilesystem.LocalAppDataRoot,
                DevelopmentFilesystem.UserProfileRoot)
            : EnterpriseManagedPaths.CreateDevelopmentE2E();
#else
        return EnterpriseManagedPaths.CreateDefault();
#endif
    }

    public static EnterpriseInstallationLayout CreateInstallationLayout()
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        return DevelopmentFilesystem.HasIsolatedRoots
            ? EnterpriseInstallationLayout.CreateDevelopmentE2E(
                DevelopmentFilesystem.LocalAppDataRoot,
                DevelopmentFilesystem.UserProfileRoot)
            : EnterpriseInstallationLayout.CreateDevelopmentE2E();
#else
        return EnterpriseInstallationLayout.CreateDefault();
#endif
    }

    public static EnterpriseDeviceProofKeyStore CreateDeviceKeyStore()
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        return string.IsNullOrEmpty(DevelopmentFilesystem.IsolationIdentifier)
            ? EnterpriseDeviceProofKeyStore.CreateDevelopmentE2E()
            : EnterpriseDeviceProofKeyStore.CreateDevelopmentE2E(
                DevelopmentFilesystem.IsolationIdentifier);
#else
        return new EnterpriseDeviceProofKeyStore();
#endif
    }

    public static EnterpriseProtectedArtifactStore CreateProtectedStore(
        EnterpriseManagedPaths paths)
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        // The installed app and lifecycle enrollment must use the same isolated
        // protection purpose; otherwise the app cannot read the seeded binding.
        if (DevelopmentFilesystem.HasIsolatedRoots)
        {
            return new(paths,
                $"com.ensou.dsh.enterprise.development-e2e.{DevelopmentFilesystem.IsolationIdentifier}");
        }
#endif
        return new(paths, AppUserModelId);
    }

    public static EnterpriseControlPlaneOptions? CreateControlPlaneOptions()
    {
        if (string.IsNullOrEmpty(Inputs.ControlPlaneOrigin)
            && string.IsNullOrEmpty(Inputs.AuthorizationOrigin))
        {
            return null;
        }

        if (string.IsNullOrEmpty(Inputs.ControlPlaneOrigin)
            || string.IsNullOrEmpty(Inputs.AuthorizationOrigin))
        {
            throw new InvalidOperationException(
                "Enterprise build profile must define both trusted HTTPS origins.");
        }

        return new EnterpriseControlPlaneOptions(
            new Uri(Inputs.ControlPlaneOrigin, UriKind.Absolute),
            new Uri(Inputs.AuthorizationOrigin, UriKind.Absolute));
    }

    public static EnterpriseAuthorizationLeaseTrustPolicy? CreateLeaseTrustPolicy(
        EnterpriseControlPlaneOptions? controlPlaneOptions)
    {
        if (controlPlaneOptions is null)
        {
            return null;
        }

        if (string.IsNullOrEmpty(Inputs.ArtifactOrigin)
            || Inputs.PinnedLeaseKeys.Length == 0)
        {
            throw new InvalidOperationException(
                "Enterprise build profile must pin the artifact origin and at least one lease key before authentication can be enabled.");
        }

#if ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E || ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
        if (!string.IsNullOrEmpty(Inputs.GatewayOrigin))
        {
            throw new InvalidOperationException(
                "Enterprise direct-local lease trust must not define a gateway origin.");
        }
        return EnterpriseAuthorizationLeaseTrustPolicy.CreateEnterpriseDirectLocal(
            controlPlaneOptions.ApiOrigin,
            new Uri(Inputs.ArtifactOrigin, UriKind.Absolute),
            Inputs.PinnedLeaseKeys);
#else
        if (string.IsNullOrEmpty(Inputs.GatewayOrigin))
        {
            throw new InvalidOperationException(
                "Enterprise managed-gateway lease trust must pin a gateway origin.");
        }
        return new EnterpriseAuthorizationLeaseTrustPolicy(
            controlPlaneOptions.ApiOrigin,
            new Uri(Inputs.GatewayOrigin, UriKind.Absolute),
            new Uri(Inputs.ArtifactOrigin, UriKind.Absolute),
            Inputs.PinnedLeaseKeys);
#endif
    }

    public static void RequireVerifiedLeaseRuntimeProfile(
        EnterpriseAccessSnapshot? accessSnapshot)
    {
        if (accessSnapshot is null || !accessSnapshot.LeaseSignatureValid)
        {
            throw new InvalidOperationException(
                "Enterprise runtime start requires a verified signed authorization lease.");
        }

#if ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E || ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
        if (!string.Equals(
                accessSnapshot.RuntimeProfile,
                "enterprise-direct-local",
                StringComparison.Ordinal)
            || !string.Equals(
                accessSnapshot.ApiProvider,
                "deepseek",
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Enterprise runtime start requires the signed direct-local lease profile.");
        }
#else
        if (accessSnapshot.RuntimeProfile is not null
            || accessSnapshot.ApiProvider is not null)
        {
            throw new InvalidOperationException(
                "Enterprise managed-gateway runtime rejects direct-local lease claims.");
        }
#endif
    }

    public static EnterpriseReleaseUpdateProfile? CreateReleaseUpdateProfile()
    {
        if (UpdateInputs.IsEmpty)
        {
            return null;
        }
        var policy = new EnterpriseReleaseTrustPolicy
        {
            Product = EnterpriseReleaseSetContract.Product,
            Environment = IsDevelopmentE2E
                ? EnterpriseReleaseSetContract.DevelopmentE2EEnvironment
                : EnterpriseReleaseSetContract.ProductionEnvironment,
            ExpectedChannel = ExpectedReleaseChannel,
            CurrentStartupStubProtocol =
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            ManifestOrigin = new Uri(UpdateInputs.ManifestOrigin, UriKind.Absolute),
            ArtifactOrigin = new Uri(UpdateInputs.ArtifactOrigin, UriKind.Absolute),
            TrustedKeys = UpdateInputs.PinnedKeys,
        };
        policy.Validate();
        return new EnterpriseReleaseUpdateProfile(
            new Uri(UpdateInputs.ManifestUri, UriKind.Absolute),
            policy);
    }

    public static string CreateProductionTrustFingerprint()
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        throw new InvalidOperationException(
            "Development-E2E builds cannot produce a production trust fingerprint.");
#elif ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
        if (UpdateInputs.IsEmpty
            || string.IsNullOrWhiteSpace(Inputs.ControlPlaneOrigin)
            || string.IsNullOrWhiteSpace(Inputs.AuthorizationOrigin)
            || !string.IsNullOrEmpty(Inputs.GatewayOrigin)
            || string.IsNullOrWhiteSpace(Inputs.ArtifactOrigin)
            || UpdateInputs.PinnedKeys.Length != 1
            || Inputs.PinnedLeaseKeys.Length != 1)
        {
            throw new InvalidOperationException(
                "Production direct-local Launcher trust metadata is incomplete or ambiguous.");
        }
        var directReleaseKey = UpdateInputs.PinnedKeys[0];
        var directLeaseKey = Inputs.PinnedLeaseKeys[0];
        return EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(new(
            EnterpriseDirectLocalProductionTrustFingerprint.RuntimeProfile,
            EnterpriseDirectLocalProductionTrustFingerprint.ApiProvider,
            UpdateInputs.ManifestUri,
            UpdateInputs.ManifestOrigin,
            UpdateInputs.ArtifactOrigin,
            directReleaseKey.KeyId,
            directReleaseKey.X,
            directReleaseKey.Y,
            Inputs.ControlPlaneOrigin,
            Inputs.AuthorizationOrigin,
            Inputs.ArtifactOrigin,
            directLeaseKey.KeyId,
            directLeaseKey.X,
            directLeaseKey.Y,
            EnterpriseAuthenticodeVerifier.GetCompiledSignerSha256Thumbprint()));
#else
        if (UpdateInputs.IsEmpty
            || string.IsNullOrWhiteSpace(Inputs.ControlPlaneOrigin)
            || string.IsNullOrWhiteSpace(Inputs.AuthorizationOrigin)
            || string.IsNullOrWhiteSpace(Inputs.GatewayOrigin)
            || string.IsNullOrWhiteSpace(Inputs.ArtifactOrigin)
            || UpdateInputs.PinnedKeys.Length != 1
            || Inputs.PinnedLeaseKeys.Length != 1)
        {
            throw new InvalidOperationException(
                "Production Launcher trust metadata is incomplete or ambiguous.");
        }
        var releaseKey = UpdateInputs.PinnedKeys[0];
        var leaseKey = Inputs.PinnedLeaseKeys[0];
        return EnterpriseProductionTrustFingerprint.ComputeSha256(new(
            UpdateInputs.ManifestUri,
            UpdateInputs.ManifestOrigin,
            UpdateInputs.ArtifactOrigin,
            releaseKey.KeyId,
            releaseKey.X,
            releaseKey.Y,
            Inputs.ControlPlaneOrigin,
            Inputs.AuthorizationOrigin,
            Inputs.GatewayOrigin,
            Inputs.ArtifactOrigin,
            leaseKey.KeyId,
            leaseKey.X,
            leaseKey.Y,
            EnterpriseAuthenticodeVerifier.GetCompiledSignerSha256Thumbprint()));
#endif
    }

    public static void RequireProductionTrustFingerprint(string expectedSha256)
    {
        if (expectedSha256 is not { Length: 64 }
            || expectedSha256.Any(character => !(character is >= '0' and <= '9'
                or >= 'a' and <= 'f')))
        {
            throw new InvalidDataException(
                "Expected production trust fingerprint must be lowercase SHA-256.");
        }
        var actual = Convert.FromHexString(CreateProductionTrustFingerprint());
        var expected = Convert.FromHexString(expectedSha256);
        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            throw new InvalidDataException(
                "Published Launcher production trust does not match the Pilot readiness input.");
        }
    }

    private static ProfileInputs LoadInputs()
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        var controlOrigin = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_CONTROL_ORIGIN")
            ?? string.Empty;
        var authorizationOrigin = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_AUTH_ORIGIN")
            ?? string.Empty;
        var gatewayOrigin = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_GATEWAY_ORIGIN")
            ?? string.Empty;
        var artifactOrigin = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_ARTIFACT_ORIGIN")
            ?? string.Empty;
        var keyId = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_LEASE_KEY_ID")
            ?? string.Empty;
        var keyX = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_LEASE_KEY_X")
            ?? string.Empty;
        var keyY = Environment.GetEnvironmentVariable("ENSOU_DSH_E2E_LEASE_KEY_Y")
            ?? string.Empty;
#if ENTERPRISE_DIRECT_LOCAL_DEVELOPMENT_E2E
        if (!string.IsNullOrEmpty(gatewayOrigin))
        {
            throw new InvalidOperationException(
                "Direct-local Development E2E trust must omit ENSOU_DSH_E2E_GATEWAY_ORIGIN.");
        }
        var values = new[]
        {
            controlOrigin,
            authorizationOrigin,
            artifactOrigin,
            keyId,
            keyX,
            keyY,
        };
#else
        var values = new[]
        {
            controlOrigin,
            authorizationOrigin,
            gatewayOrigin,
            artifactOrigin,
            keyId,
            keyX,
            keyY,
        };
#endif
        if (values.All(string.IsNullOrEmpty))
        {
            return new ProfileInputs(string.Empty, string.Empty, string.Empty, string.Empty, []);
        }

        if (values.Any(string.IsNullOrEmpty))
        {
            throw new InvalidOperationException(
                "Development E2E trust inputs must be supplied as one complete isolated set.");
        }

        return new ProfileInputs(
            controlOrigin,
            authorizationOrigin,
            gatewayOrigin,
            artifactOrigin,
            [new EnterpriseAuthorizationLeasePublicKey(keyId, keyX, keyY)]);
#else
        var controlOrigin = ReadBuildMetadata("EnterpriseControlPlaneOrigin");
        var authorizationOrigin = ReadBuildMetadata("EnterpriseAuthorizationOrigin");
        var gatewayOrigin = ReadBuildMetadata("EnterpriseGatewayOrigin");
        var artifactOrigin = ReadBuildMetadata("EnterpriseManagedArtifactOrigin");
        var keyId = ReadBuildMetadata("EnterpriseLeaseKeyId");
        var keyX = ReadBuildMetadata("EnterpriseLeaseKeyX");
        var keyY = ReadBuildMetadata("EnterpriseLeaseKeyY");
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
        if (!string.IsNullOrEmpty(gatewayOrigin))
        {
            throw new InvalidOperationException(
                "Direct-local production trust must omit EnterpriseGatewayOrigin.");
        }
        var values = new[]
        {
            controlOrigin,
            authorizationOrigin,
            artifactOrigin,
            keyId,
            keyX,
            keyY,
        };
#else
        var values = new[]
        {
            controlOrigin,
            authorizationOrigin,
            gatewayOrigin,
            artifactOrigin,
            keyId,
            keyX,
            keyY,
        };
#endif
        if (values.All(string.IsNullOrEmpty))
        {
            return new ProfileInputs(string.Empty, string.Empty, string.Empty, string.Empty, []);
        }
        if (values.Any(string.IsNullOrEmpty))
        {
            throw new InvalidOperationException(
                "Production control-plane trust metadata must be compiled as one complete set.");
        }
        return new ProfileInputs(
            controlOrigin,
            authorizationOrigin,
            gatewayOrigin,
            artifactOrigin,
            [new EnterpriseAuthorizationLeasePublicKey(keyId, keyX, keyY)]);
#endif
    }

    private static ReleaseUpdateInputs LoadReleaseUpdateInputs()
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        var manifestUri = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_UPDATE_MANIFEST_URI") ?? string.Empty;
        var manifestOrigin = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_UPDATE_MANIFEST_ORIGIN") ?? string.Empty;
        var artifactOrigin = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_UPDATE_ARTIFACT_ORIGIN") ?? string.Empty;
        var keyId = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_UPDATE_KEY_ID") ?? string.Empty;
        var keyX = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_UPDATE_KEY_X") ?? string.Empty;
        var keyY = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_UPDATE_KEY_Y") ?? string.Empty;
        var values = new[] { manifestUri, manifestOrigin, artifactOrigin, keyId, keyX, keyY };
        if (values.All(string.IsNullOrEmpty))
        {
            return ReleaseUpdateInputs.Empty;
        }
        if (values.Any(string.IsNullOrEmpty))
        {
            throw new InvalidOperationException(
                "Development E2E update trust inputs must be supplied as one complete set.");
        }
        return new ReleaseUpdateInputs(
            manifestUri,
            manifestOrigin,
            artifactOrigin,
            [new EnterpriseReleasePublicKey(keyId, keyX, keyY)]);
#else
        var manifestUri = ReadBuildMetadata("EnterpriseUpdateManifestUri");
        var manifestOrigin = ReadBuildMetadata("EnterpriseUpdateManifestOrigin");
        var artifactOrigin = ReadBuildMetadata("EnterpriseUpdateArtifactOrigin");
        var keyId = ReadBuildMetadata("EnterpriseUpdateReleaseKeyId");
        var keyX = ReadBuildMetadata("EnterpriseUpdateReleaseKeyX");
        var keyY = ReadBuildMetadata("EnterpriseUpdateReleaseKeyY");
        var values = new[] { manifestUri, manifestOrigin, artifactOrigin, keyId, keyX, keyY };
        if (values.All(string.IsNullOrEmpty))
        {
            return ReleaseUpdateInputs.Empty;
        }
        if (values.Any(string.IsNullOrEmpty))
        {
            throw new InvalidOperationException(
                "Production update trust metadata must be compiled as one complete set.");
        }
        return new ReleaseUpdateInputs(
            manifestUri,
            manifestOrigin,
            artifactOrigin,
            [new EnterpriseReleasePublicKey(keyId, keyX, keyY)]);
#endif
    }

#if ENTERPRISE_DEVELOPMENT_E2E
    private static DevelopmentFilesystemInputs LoadDevelopmentFilesystemInputs()
    {
        var localAppDataRoot = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT") ?? string.Empty;
        var userProfileRoot = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_USER_PROFILE_ROOT") ?? string.Empty;
        var isolationIdentifier = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_ISOLATION_ID") ?? string.Empty;
        if (string.IsNullOrEmpty(localAppDataRoot) != string.IsNullOrEmpty(userProfileRoot))
        {
            throw new InvalidOperationException(
                "Development E2E isolated roots must be supplied as one complete pair.");
        }

        if (string.IsNullOrEmpty(localAppDataRoot)
            && !string.IsNullOrEmpty(isolationIdentifier))
        {
            throw new InvalidOperationException(
                "Development E2E key isolation requires isolated filesystem roots.");
        }

        return new DevelopmentFilesystemInputs(
            localAppDataRoot,
            userProfileRoot,
            isolationIdentifier);
    }
#endif

    private static string ReadBuildMetadata(string key) =>
        typeof(EnterpriseBuildProfile).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(attribute => string.Equals(
                attribute.Key,
                key,
                StringComparison.Ordinal))
            .Value ?? string.Empty;

    private sealed record ProfileInputs(
        string ControlPlaneOrigin,
        string AuthorizationOrigin,
        string GatewayOrigin,
        string ArtifactOrigin,
        EnterpriseAuthorizationLeasePublicKey[] PinnedLeaseKeys);

    private sealed record ReleaseUpdateInputs(
        string ManifestUri,
        string ManifestOrigin,
        string ArtifactOrigin,
        EnterpriseReleasePublicKey[] PinnedKeys)
    {
        public static ReleaseUpdateInputs Empty { get; } = new(
            string.Empty,
            string.Empty,
            string.Empty,
            []);

        public bool IsEmpty => string.IsNullOrEmpty(ManifestUri)
            && string.IsNullOrEmpty(ManifestOrigin)
            && string.IsNullOrEmpty(ArtifactOrigin)
            && PinnedKeys.Length == 0;
    }

#if ENTERPRISE_DEVELOPMENT_E2E
    private sealed record DevelopmentFilesystemInputs(
        string LocalAppDataRoot,
        string UserProfileRoot,
        string IsolationIdentifier)
    {
        public bool HasIsolatedRoots => !string.IsNullOrEmpty(LocalAppDataRoot);
    }
#endif
}

internal sealed record EnterpriseReleaseUpdateProfile(
    Uri ManifestUri,
    EnterpriseReleaseTrustPolicy TrustPolicy);
