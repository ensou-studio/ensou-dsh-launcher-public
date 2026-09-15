using System.Security.Cryptography;
using System.Text;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.InstallationTests;

internal static class EnterpriseRuntimeIntegrityScannerTests
{
    private const string GoldenCompleteTreeSha256 =
        "a97b68448f2d7d759d576634c884a31ee61b1ff9d529fbabd3eb0855d6b31c3d";
    private const string GoldenManifestSha256 =
        "a3bedd1443f2dbadd13b88d36a4db549e91f407a7035d3fbe63aef63d9d7d86a";

    public static Task RunAsync()
    {
        var syntheticParent = Path.GetFullPath(Path.Combine(
            Path.GetTempPath(),
            "ensou-dsh-enterprise-runtime-integrity-tests"));
        var root = CreateFixtureRoot(syntheticParent);
        var junctionTargetRoot = CreateFixtureRoot(syntheticParent);
        string? trackedJunction = null;
        string? trackedFileReparse = null;
        try
        {
            var orderedRoot = Path.Combine(root, "ordered");
            var ordered = CreateRuntime(orderedRoot, reverseCreationOrder: false, "Mixed/Case.txt");
            var contentReads = new List<string>();
            var validation = EnterpriseRuntimeFileManifest
                .ValidateCompleteTreeAndComputeTree(orderedRoot, contentReads.Add);
            Equal(GoldenCompleteTreeSha256, validation.CompleteTreeSha256);
            Equal(GoldenManifestSha256, validation.RuntimeFilesManifestSha256);
            Equal(EnterpriseTreeHash.Compute(orderedRoot), validation.CompleteTreeSha256);
            Equal(Hash(ordered.ManifestBytes), validation.RuntimeFilesManifestSha256);
            Equal(
                new[]
                {
                    ".ensou-enterprise-launcher.json",
                    ".ensou-enterprise-plugin-policy.v2.json",
                    "Mixed/Case.txt",
                    "node.exe",
                    "node_modules/@deepseek-ai/dsh/lib/bin.js",
                    EnterpriseRuntimeFileManifest.FileName,
                },
                contentReads);
            Equal(
                validation.RuntimeFilesManifestSha256,
                EnterpriseRuntimeFileManifest.ValidateCompleteTree(orderedRoot));

            var reversedRoot = Path.Combine(root, "reversed");
            var reversed = CreateRuntime(reversedRoot, reverseCreationOrder: true, "Mixed/Case.txt");
            var reversedValidation = EnterpriseRuntimeFileManifest
                .ValidateCompleteTreeAndComputeTree(reversedRoot);
            Equal(validation.CompleteTreeSha256, reversedValidation.CompleteTreeSha256);
            Equal(validation.RuntimeFilesManifestSha256, reversedValidation.RuntimeFilesManifestSha256);
            Equal(ordered.ManifestBytes, reversed.ManifestBytes);

            var lowerCaseRoot = Path.Combine(root, "lower-case");
            var lowerCase = CreateRuntime(lowerCaseRoot, reverseCreationOrder: false, "mixed/case.txt");
            var lowerCaseValidation = EnterpriseRuntimeFileManifest
                .ValidateCompleteTreeAndComputeTree(lowerCaseRoot);
            Equal(ordered.ManifestBytes, lowerCase.ManifestBytes);
            NotEqual(validation.CompleteTreeSha256, lowerCaseValidation.CompleteTreeSha256);

            AssertLegacyReceiptExclusionsRemainManifestBound(orderedRoot, ordered);
            AssertTamperMissingAndUnlistedFail(orderedRoot, ordered);
            AssertStrictManifestSyntaxAndCasing(orderedRoot, ordered);
            Directory.CreateDirectory(junctionTargetRoot);
            File.WriteAllText(
                Path.Combine(junctionTargetRoot, "outside.txt"),
                "outside synthetic target",
                Encoding.UTF8);
            var junctionPath = Path.Combine(orderedRoot, "junction");
            if (!Program.TryCreateDirectoryJunction(junctionPath, junctionTargetRoot))
            {
                throw new InvalidOperationException(
                    "Could not create the required fused runtime-integrity junction fixture.");
            }
            trackedJunction = junctionPath;
            AssertInvalid(() => EnterprisePathGuard.ValidateSafeTree(orderedRoot, root));
            DeleteTrackedJunction(trackedJunction);
            trackedJunction = null;

            var fileReparsePath = Path.Combine(orderedRoot, "linked-file.txt");
            if (TryCreateFileSymbolicLink(
                    fileReparsePath,
                    Path.Combine(junctionTargetRoot, "outside.txt")))
            {
                trackedFileReparse = fileReparsePath;
                AssertInvalid(
                    () => EnterpriseRuntimeFileManifest
                        .ValidateCompleteTreeAndComputeTree(orderedRoot),
                    "Enterprise runtime tree contains a filesystem link.");
            }
            return Task.CompletedTask;
        }
        finally
        {
            DeleteTrackedFileReparse(trackedFileReparse);
            DeleteTrackedJunction(trackedJunction);
            DeleteFixtureRoot(root, syntheticParent);
            DeleteFixtureRoot(junctionTargetRoot, syntheticParent);
        }
    }

    private static string CreateFixtureRoot(string syntheticParent)
    {
        var name = Guid.NewGuid().ToString("N");
        return Path.GetFullPath(Path.Combine(syntheticParent, name));
    }

    private static void DeleteTrackedJunction(string? junctionPath)
    {
        if (junctionPath is null || !Directory.Exists(junctionPath))
        {
            return;
        }
        if ((File.GetAttributes(junctionPath) & FileAttributes.ReparsePoint) == 0)
        {
            throw new InvalidOperationException(
                "Refusing to recursively clean a tracked junction that is not a reparse point.");
        }
        Directory.Delete(junctionPath, recursive: false);
    }

    private static bool TryCreateFileSymbolicLink(string linkPath, string targetPath)
    {
        try
        {
            File.CreateSymbolicLink(linkPath, targetPath);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (IOException) when (!File.Exists(linkPath))
        {
            return false;
        }
    }

    private static void DeleteTrackedFileReparse(string? linkPath)
    {
        if (linkPath is null || !File.Exists(linkPath))
        {
            return;
        }
        if ((File.GetAttributes(linkPath) & FileAttributes.ReparsePoint) == 0)
        {
            throw new InvalidOperationException(
                "Refusing to clean a tracked file link that is not a reparse point.");
        }
        File.Delete(linkPath);
    }

    private static void DeleteFixtureRoot(string root, string syntheticParent)
    {
        if (!Directory.Exists(root))
        {
            return;
        }
        var fullRoot = Path.GetFullPath(root);
        var fullParent = Path.GetFullPath(syntheticParent);
        if (!string.Equals(
                Path.GetDirectoryName(fullRoot),
                fullParent,
                StringComparison.OrdinalIgnoreCase)
            || !Guid.TryParseExact(Path.GetFileName(fullRoot), "N", out _))
        {
            throw new InvalidOperationException(
                "Refusing to delete an invalid runtime-integrity fixture root.");
        }

        for (DirectoryInfo? current = new(fullRoot); current is not null; current = current.Parent)
        {
            if (current.Exists
                && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException(
                    $"Refusing to delete a fixture beneath a reparse point: {current.FullName}");
            }
        }
        var pending = new Stack<DirectoryInfo>();
        pending.Push(new DirectoryInfo(fullRoot));
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            foreach (var entry in current.EnumerateFileSystemInfos(
                         "*",
                         SearchOption.TopDirectoryOnly))
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidOperationException(
                        $"Refusing to recursively delete a fixture containing a reparse point: {entry.FullName}");
                }
                if (entry is DirectoryInfo directory)
                {
                    pending.Push(directory);
                }
            }
        }
        Directory.Delete(fullRoot, recursive: true);
    }

    private static void AssertLegacyReceiptExclusionsRemainManifestBound(
        string root,
        RuntimeFixture fixture)
    {
        var launcherReceipt = Path.Combine(root, ".ensou-enterprise-launcher.json");
        var originalTreeSha256 = EnterpriseTreeHash.Compute(root);
        File.WriteAllText(launcherReceipt, "changed-launcher-receipt", Encoding.UTF8);
        Equal(originalTreeSha256, EnterpriseTreeHash.Compute(root));
        AssertInvalid(() => EnterpriseRuntimeFileManifest.ValidateCompleteTreeAndComputeTree(root));
        File.WriteAllBytes(launcherReceipt, fixture.Files[".ensou-enterprise-launcher.json"]);

        var withoutLauncherReceipt = fixture.ManifestLines
            .Where(line => !line.EndsWith(
                "  .ensou-enterprise-launcher.json",
                StringComparison.Ordinal))
            .ToArray();
        WriteManifest(root, withoutLauncherReceipt, "\r\n");
        AssertInvalid(() => EnterpriseRuntimeFileManifest.ValidateCompleteTreeAndComputeTree(root));
        File.WriteAllBytes(
            Path.Combine(root, EnterpriseRuntimeFileManifest.FileName),
            fixture.ManifestBytes);
    }

    private static void AssertTamperMissingAndUnlistedFail(
        string root,
        RuntimeFixture fixture)
    {
        var contentPath = Path.Combine(root, "Mixed", "Case.txt");
        File.WriteAllText(contentPath, "tampered", Encoding.UTF8);
        AssertInvalid(() => EnterpriseRuntimeFileManifest.ValidateCompleteTreeAndComputeTree(root));
        File.WriteAllBytes(contentPath, fixture.Files["Mixed/Case.txt"]);

        var missingPath = Path.Combine(root, "node.exe");
        File.Delete(missingPath);
        AssertInvalid(() => EnterpriseRuntimeFileManifest.ValidateCompleteTreeAndComputeTree(root));
        File.WriteAllBytes(missingPath, fixture.Files["node.exe"]);

        var unlistedPath = Path.Combine(root, "unlisted.txt");
        File.WriteAllText(unlistedPath, "unlisted", Encoding.UTF8);
        AssertInvalid(() => EnterpriseRuntimeFileManifest.ValidateCompleteTreeAndComputeTree(root));
        File.Delete(unlistedPath);
    }

    private static void AssertStrictManifestSyntaxAndCasing(
        string root,
        RuntimeFixture fixture)
    {
        var manifestPath = Path.Combine(root, EnterpriseRuntimeFileManifest.FileName);
        var uppercaseHashLines = fixture.ManifestLines
            .Select(line => line[..64].ToUpperInvariant() + line[64..])
            .ToArray();
        WriteManifest(root, uppercaseHashLines, "\r\n");
        AssertInvalid(() => EnterpriseRuntimeFileManifest.ValidateCompleteTreeAndComputeTree(root));

        var mixedCaseLine = fixture.ManifestLines.Single(line => line.EndsWith(
            "  mixed/case.txt",
            StringComparison.Ordinal));
        WriteManifest(
            root,
            fixture.ManifestLines.Append(
                mixedCaseLine[..66] + "MIXED/CASE.TXT"),
            "\r\n");
        AssertInvalid(() => EnterpriseRuntimeFileManifest.ValidateCompleteTreeAndComputeTree(root));
        File.WriteAllBytes(manifestPath, fixture.ManifestBytes);

        var intermediatePath = Path.Combine(root, "manifest-case-transition.tmp");
        var wrongCasePath = Path.Combine(root, "Runtime-Files.SHA256");
        File.Move(manifestPath, intermediatePath);
        File.Move(intermediatePath, wrongCasePath);
        AssertInvalid(() => EnterpriseRuntimeFileManifest.ValidateCompleteTreeAndComputeTree(root));
        File.Move(wrongCasePath, intermediatePath);
        File.Move(intermediatePath, manifestPath);
        Equal(
            Hash(fixture.ManifestBytes),
            EnterpriseRuntimeFileManifest.ValidateCompleteTree(root));
    }

    private static RuntimeFixture CreateRuntime(
        string root,
        bool reverseCreationOrder,
        string actualCasePath)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["node.exe"] = Encoding.UTF8.GetBytes("synthetic-node"),
            ["node_modules/@deepseek-ai/dsh/lib/bin.js"] =
                Encoding.UTF8.GetBytes("synthetic-bin"),
            [actualCasePath] = Encoding.UTF8.GetBytes("case-sensitive-tree-path"),
            [".ensou-enterprise-launcher.json"] =
                Encoding.UTF8.GetBytes("launcher-receipt-bound-by-runtime-manifest"),
            [".ensou-enterprise-runtime.json"] =
                Encoding.UTF8.GetBytes("runtime-receipt-excluded"),
            [".ensou-enterprise-plugin-policy.v2.json"] =
                Encoding.UTF8.GetBytes("plugin-receipt-bound-by-runtime-manifest"),
            [EnterpriseTreeHash.ReceiptFileName] =
                Encoding.UTF8.GetBytes("tree-receipt-excluded"),
        };
        Directory.CreateDirectory(root);
        IEnumerable<KeyValuePair<string, byte[]>> creationOrder = reverseCreationOrder
            ? files.Reverse()
            : files;
        foreach (var file in creationOrder)
        {
            var path = Path.Combine(root, file.Key.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, file.Value);
        }

        var manifestLines = files
            .Where(file => file.Key is not ".ensou-enterprise-runtime.json"
                && file.Key != EnterpriseTreeHash.ReceiptFileName)
            .Select(file =>
            {
                var manifestPath = string.Equals(
                    file.Key,
                    actualCasePath,
                    StringComparison.Ordinal)
                    ? "mixed/case.txt"
                    : file.Key;
                return $"{Hash(file.Value)}  {manifestPath}";
            })
            .Order(StringComparer.Ordinal)
            .ToArray();
        var manifestBytes = WriteManifest(root, manifestLines, "\r\n");
        return new RuntimeFixture(files, manifestLines, manifestBytes);
    }

    private static byte[] WriteManifest(
        string root,
        IEnumerable<string> lines,
        string lineEnding)
    {
        var bytes = Encoding.ASCII.GetBytes(string.Join(lineEnding, lines) + lineEnding);
        File.WriteAllBytes(
            Path.Combine(root, EnterpriseRuntimeFileManifest.FileName),
            bytes);
        return bytes;
    }

    private static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void AssertInvalid(Action action)
    {
        try
        {
            action();
        }
        catch (InvalidDataException)
        {
            return;
        }
        throw new InvalidOperationException("Expected InvalidDataException.");
    }

    private static void AssertInvalid(Action action, string expectedMessage)
    {
        try
        {
            action();
        }
        catch (InvalidDataException exception)
            when (string.Equals(
                exception.Message,
                expectedMessage,
                StringComparison.Ordinal))
        {
            return;
        }
        throw new InvalidOperationException(
            $"Expected InvalidDataException with message '{expectedMessage}'.");
    }

    private static void Equal(string expected, string actual)
    {
        if (!string.Equals(expected, actual, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Expected '{expected}', actual '{actual}'.");
        }
    }

    private static void Equal(byte[] expected, byte[] actual)
    {
        if (!expected.AsSpan().SequenceEqual(actual))
        {
            throw new InvalidOperationException("Expected equal byte sequences.");
        }
    }

    private static void Equal(IEnumerable<string> expected, IEnumerable<string> actual)
    {
        var expectedOrdered = expected.Order(StringComparer.Ordinal).ToArray();
        var actualOrdered = actual.Order(StringComparer.Ordinal).ToArray();
        if (!expectedOrdered.SequenceEqual(actualOrdered, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                $"Expected [{string.Join(", ", expectedOrdered)}], "
                + $"actual [{string.Join(", ", actualOrdered)}].");
        }
    }

    private static void NotEqual(string left, string right)
    {
        if (string.Equals(left, right, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Expected distinct values.");
        }
    }

    private sealed record RuntimeFixture(
        IReadOnlyDictionary<string, byte[]> Files,
        IReadOnlyList<string> ManifestLines,
        byte[] ManifestBytes);
}
