#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ensou.Dsh.Enterprise.ReleasePublisher;

const string ReleaseId = "managed-v2026.09.14.1";
const string ArchiveName = "EnsouDshRuntime-managed-v2026.09.14.1-win-x64.zip";
const long ArchiveBytes = 123_456_789;
const string ArchiveSha256 =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

var tests = new (string Name, Action Run)[]
{
    ("compiled direct lock selects exact manifest-v4 source identity", ContractIsExact),
    ("schema-v3 direct metadata admits only exact direct policy and two smoke receipts", ExactMetadataAdmits),
    ("legacy and cross-mode metadata fields are rejected", CrossModeFieldsReject),
    ("direct profile toolchain and each smoke receipt fail closed", DirectFactsReject),
    ("duplicate direct metadata fields are rejected", DuplicateFieldsReject),
    ("direct Pilot readiness trust is versioned without a gateway", PilotTrustConfigTests.Run),
};

var failures = 0;
foreach (var test in tests)
{
    try
    {
        test.Run();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception exception)
    {
        failures++;
        Console.Error.WriteLine($"FAIL {test.Name}: {exception}");
    }
}

Console.WriteLine($"{tests.Length - failures}/{tests.Length} direct-local publisher admission tests passed.");
return failures == 0 ? 0 : 1;

static void ContractIsExact()
{
    var contract = PublisherManagedPatchManifestContract.Current;
    Assert(
        PublisherManagedPatchManifestContract.EnterpriseDirectLocalAdmission,
        "Direct admission compile branch was not selected.");
    Equal("https://github.com/deepseek-ai/deepseek-harness.git", contract.SourceRepository);
    Equal("dsh-v0.1.2-rc.1", contract.SourceTag);
    Equal("a66e4702047846cdaa10c66c9d3df3951f5ea70d", contract.SourceCommit);
    Equal("27ab636bb3d77e698f5637e518db44ae1f61e262", contract.SourceTree);
    Equal("e12083149a77f790d39b64d018b6b8745c6a7aa95777ecb73e0a2f5ed5fdd0d9", contract.BaseLockfileSha256);
    Equal("07974704247ec18915df8fdf117c682bba2d861aafe7059ea4bca4aab1677080", contract.LockfileSha256);
    Equal("24.19.0", contract.NodeVersion);
    Equal("11.7.0", contract.PnpmVersion);
    Equal("11.17.0", contract.NpmVersion);
    Equal("dsh-v0.1.2-rc.1-enterprise-direct-local-v1", contract.PatchId);
    Equal("ensou.dsh.upstream-patch-manifest.v4", contract.ManifestSchema);
    Equal("977ebb374bf9449e34daa7b0ef393a06b2c862d944200abb69a30434a2597cf0", contract.ManifestSha256);
    Equal("7f10ec9492b399cede422428013b0c77bc932699fa3a14fa7ced158454272b6f", contract.PatchSha256);
    Equal(415_878L, contract.PatchBytes);
    Equal(112, contract.ChangedFileCount);
    Equal(86, contract.ModifiedPreimageCount);
    Equal("cad7cdf7f1b13f1892a2b857e3f628de71579ab4bef89f3b97ac0fed03cc25ba", contract.HostCompositionCanonicalSha256);
}

static void ExactMetadataAdmits()
{
    var metadata = ExactMetadata();
    var parsed = PublisherSourceRuntimeMetadata.Parse(Serialize(metadata));
    parsed.RequireExact(ReleaseId, ArchiveName, ArchiveBytes, ArchiveSha256);
}

static void CrossModeFieldsReject()
{
    var direct = ParseNode(ExactMetadata());
    direct["managedPolicy"]!["gatewayAllowedModel"] = "deepseek-v4-flash";
    Reject(direct, "Direct admission accepted a legacy gateway field.");

    var missingProfile = ParseNode(ExactMetadata());
    missingProfile.Remove("runtimeProfile");
    Reject(missingProfile, "Direct admission accepted metadata without runtimeProfile.");

    var wrongSchema = ParseNode(ExactMetadata());
    wrongSchema["schemaVersion"] = 2;
    Reject(wrongSchema, "Direct admission accepted legacy schemaVersion 2.");

    var wrongArtifact = ParseNode(ExactMetadata());
    wrongArtifact["artifactType"] = "ensou-dsh-enterprise-managed-source-runtime";
    Reject(wrongArtifact, "Direct admission accepted the legacy artifact type.");
}

static void DirectFactsReject()
{
    var wrongProtocol = ParseNode(ExactMetadata());
    wrongProtocol["managedUpdateProtocol"] = "enterprise-managed-drain-v1";
    Reject(wrongProtocol, "Direct admission accepted an invented update protocol.");

    var wrongNpm = ParseNode(ExactMetadata());
    wrongNpm["toolchain"]!["npmVersion"] = "11.9.0";
    Reject(wrongNpm, "Direct admission accepted the legacy npm version.");

    var wrongAssembled = ParseNode(ExactMetadata());
    wrongAssembled["verification"]!["directLocalAssembledSmoke"]!["cycles"] = 1;
    Reject(wrongAssembled, "Direct admission accepted an incomplete assembled smoke.");

    var wrongExtracted = ParseNode(ExactMetadata());
    wrongExtracted["verification"]!["directLocalExtractedSmoke"]!["modelRequestsSent"] = 1;
    Reject(wrongExtracted, "Direct admission accepted an extracted smoke that sent a model request.");

    var unknownReceiptField = ParseNode(ExactMetadata());
    unknownReceiptField["verification"]!["directLocalExtractedSmoke"]!["unexpected"] = true;
    Reject(unknownReceiptField, "Direct admission accepted an unknown smoke receipt field.");
}

static void DuplicateFieldsReject()
{
    var json = Encoding.UTF8.GetString(Serialize(ExactMetadata()));
    var duplicate = json.Replace(
        "\"runtimeProfile\":\"enterprise-direct-local\"",
        "\"runtimeProfile\":\"enterprise-direct-local\",\"runtimeProfile\":\"enterprise-direct-local\"",
        StringComparison.Ordinal);
    Assert(!string.Equals(json, duplicate, StringComparison.Ordinal), "Duplicate-field fixture was not created.");
    Throws<InvalidDataException>(() => PublisherSourceRuntimeMetadata.Parse(Encoding.UTF8.GetBytes(duplicate)));
}

static PublisherSourceRuntimeMetadata ExactMetadata()
{
    var contract = PublisherManagedPatchManifestContract.Current;
    return new PublisherSourceRuntimeMetadata
    {
        SchemaVersion = 3,
        ReleaseId = ReleaseId,
        PromotionEligible = true,
        ArtifactType = "ensou-dsh-enterprise-direct-local-source-runtime",
        SourceBuilt = true,
        Platform = "win32-x64",
        SourceIdentity = "github-https-tag-plus-ensou-managed-patch",
        SourceRepository = contract.SourceRepository,
        SourceTag = contract.SourceTag,
        SourceCommit = contract.SourceCommit,
        SourceTree = contract.SourceTree,
        DshVersion = contract.DshVersion,
        BaseLockfileSha256 = contract.BaseLockfileSha256,
        LockfileSha256 = contract.LockfileSha256,
        RuntimeWebAuthProtocol = contract.RuntimeWebAuthProtocol,
        RuntimeProfile = "enterprise-direct-local",
        ManagedUpdateProtocol = "enterprise-direct-local-v1",
        ManagedPatch = new PublisherSourceRuntimeManagedPatch
        {
            Id = contract.PatchId,
            ManifestSchema = contract.ManifestSchema,
            ManifestSha256 = contract.ManifestSha256,
            PatchSha256 = contract.PatchSha256,
            PatchBytes = contract.PatchBytes,
            ChangedFileCount = contract.ChangedFileCount,
            ModifiedPreimageCount = contract.ModifiedPreimageCount,
        },
        ManagedPolicy = new PublisherSourceRuntimeManagedPolicy
        {
            Signal = "DSH_ENTERPRISE_MANAGED_BOOT=ensou-dsh-launcher/v1",
            Profile = "enterprise-direct-local",
            WebArguments = "--host 127.0.0.1 --port <canonical 1..65535>",
            Model = "deepseek-v4-flash",
            MaxTokens = 8192,
            ModelBaseUrl = "https://api.deepseek.com",
            SearchBaseUrl = "https://api.deepseek.com/anthropic/v1",
            CredentialEnvironment = "DEEPSEEK_API_KEY",
            CredentialSource = "@deepseek-ai/dsh-credentials-local writable local credential store",
            LaunchEnvironmentProviderOverrides =
                ["DEEPSEEK_BASE_URL", "DEEPSEEK_SEARCH_BASE_URL", "DEEPSEEK_API_KEY"],
            SettingsProvider = "@deepseek-ai/dsh-settings-file/composition-only",
            ManagedSkillsRootEnvironment = "ENSOU_DSH_ENTERPRISE_SKILLS_ROOT",
            SandboxMode = "workspace-write",
            SandboxMaximumMode = "workspace-write",
            ApprovalPolicy = "ask",
            PermissionPresets = ["workspace-write"],
            WorkspaceRootSource = "process.cwd()",
            RestoredSessionCwdPolicy = "must-equal-workspace-root",
            HostCompositionCanonicalSha256 = contract.HostCompositionCanonicalSha256,
            PresetCompositionCanonicalSha256 = "e3c01ae98d9bf12e57e3ba270169f7059e3b098615e21b4db11fd377367ea546",
            PresetMetadataCanonicalSha256 = "3590423cb2fb8809c0d11b18dec12f9e1df370a4f05dc93fff1c54e82abc75be",
            LoaderRootCanonicalSha256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
            PluginResolutionPolicy = "frozen exact installation map from managed base/web bundles; no ambient fallback",
        },
        BuiltAtUtc = new DateTimeOffset(2026, 9, 14, 8, 0, 0, TimeSpan.Zero),
        Toolchain = new PublisherSourceRuntimeToolchain
        {
            NodeVersion = contract.NodeVersion,
            NodeSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            PnpmVersion = contract.PnpmVersion,
            NpmVersion = contract.NpmVersion,
        },
        Verification = new PublisherSourceRuntimeVerification
        {
            CleanCheckout = true,
            TagCommitMatch = true,
            RemoteTagCommitMatch = true,
            TagSignatureVerified = false,
            OfficialCheckoutUnchanged = true,
            PatchManifestValidated = true,
            PatchPreimagesVerified = true,
            PatchApplyCheck = true,
            PatchPostimagesVerified = true,
            FrozenLockfileInstall = true,
            ManagedFocusedTests = true,
            ManagedWindowsExcludedFocusedTests = true,
            ManagedChangedPackageTypeBuild = true,
            ManagedCliBundle = true,
            ManagedSourceGates = true,
            SourceBuild = "pnpm run build (reviewed managed patch applied)",
            BuiltPackageInvariants = true,
            DeploymentMode = "pnpm-dedicated-lockfile-offline-deploy",
            RuntimeClosureAgainstPinnedSourceAndLock = true,
            RuntimeClosurePackageCount = 459,
            PortableCommandShimGate = true,
            SymlinkFreeRuntime = true,
            BundledNodeVersionSmoke = true,
            NativeModuleSmoke = ["node-pty", "koffi"],
            WebProfileDumpSmoke = true,
            WebHttpSmoke = true,
            ManagedExactEnvironmentSmoke = true,
            ManagedWorkspaceCwdSmoke = true,
            ManagedRefusalSmoke = true,
            ExtractedArtifactHashManifestVerified = true,
            ExtractedArtifactSmoke = true,
            BuildToolingExcluded = true,
            WebSmokeUrl = "http://127.0.0.1:<ephemeral-port>/",
            ExternalNetworkIsolation = false,
            DirectLocalAssembledSmoke = ExactSmoke(2048),
            DirectLocalExtractedSmoke = ExactSmoke(3072),
        },
        Artifact = new PublisherSourceRuntimeArtifact
        {
            FileName = ArchiveName,
            SizeBytes = ArchiveBytes,
            Sha256 = ArchiveSha256,
        },
        Licensing = new PublisherSourceRuntimeLicensing
        {
            HarnessLicense = "MIT",
            NoticesIncluded = true,
            OrganizationReviewRequired = true,
        },
    };
}

static PublisherEnterpriseDirectLocalSmokeReceipt ExactSmoke(int outputBytes) => new()
{
    Status = "PASS",
    ResultStatus = "PASS",
    Scope = "BUILT_ENTERPRISE_DIRECT_LOCAL_RUNTIME_CAPABILITY_ONLY",
    Cycles = 2,
    KernelBootstrapVerified = true,
    SettingsReadOnly = true,
    CredentialsWritable = true,
    ExactChildExited = true,
    AuthenticationNegativesVerified = true,
    LaunchRefusalsVerified = true,
    ModelRequestsSent = 0,
    OutputBytes = outputBytes,
};

static byte[] Serialize(PublisherSourceRuntimeMetadata metadata) =>
    JsonSerializer.SerializeToUtf8Bytes(
        metadata,
        new JsonSerializerOptions(JsonSerializerDefaults.Web));

static JsonObject ParseNode(PublisherSourceRuntimeMetadata metadata) =>
    JsonNode.Parse(Serialize(metadata))!.AsObject();

static void Reject(JsonNode metadata, string message)
{
    try
    {
        var parsed = PublisherSourceRuntimeMetadata.Parse(
            JsonSerializer.SerializeToUtf8Bytes(metadata));
        parsed.RequireExact(ReleaseId, ArchiveName, ArchiveBytes, ArchiveSha256);
    }
    catch (InvalidDataException)
    {
        return;
    }
    throw new InvalidOperationException(message);
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException($"Expected {expected}; actual {actual}.");
    }
}

static void Throws<TException>(Action action)
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
#else
using System.Text.Json;
using System.Text.Json.Nodes;
using Ensou.Dsh.Enterprise.ReleasePublisher;

if (PublisherManagedPatchManifestContract.EnterpriseDirectLocalAdmission)
{
    throw new InvalidOperationException("Legacy test unexpectedly selected direct admission.");
}

var repositoryRoot = PilotTrustConfigTests.FindRepositoryRoot();
var exampleBytes = File.ReadAllBytes(Path.Combine(
    repositoryRoot,
    "release",
    "examples",
    "source-runtime.metadata.json"));
var exact = PublisherSourceRuntimeMetadata.Parse(exampleBytes);
exact.RequireExact(
    exact.ReleaseId,
    exact.Artifact.FileName,
    exact.Artifact.SizeBytes,
    exact.Artifact.Sha256);

foreach (var mutation in new Action<JsonObject>[]
{
    root => root["runtimeProfile"] = "enterprise-direct-local",
    root => root["managedUpdateProtocol"] = "enterprise-direct-local-v1",
    root => root["managedPolicy"]!["modelBaseUrl"] = "https://api.deepseek.com",
    root => root["verification"]!["directLocalAssembledSmoke"] = new JsonObject(),
})
{
    var changed = JsonNode.Parse(exampleBytes)!.AsObject();
    mutation(changed);
    try
    {
        _ = PublisherSourceRuntimeMetadata.Parse(
            JsonSerializer.SerializeToUtf8Bytes(changed));
    }
    catch (InvalidDataException)
    {
        continue;
    }
    throw new InvalidOperationException(
        "Legacy schema-v2 admission accepted a direct-only metadata field.");
}

PilotTrustConfigTests.Run();
Console.WriteLine("PASS legacy schema-v2 admission rejects every direct-only metadata field");
return 0;

#endif
