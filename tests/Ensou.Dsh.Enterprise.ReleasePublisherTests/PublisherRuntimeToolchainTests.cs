using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.Enterprise.ReleasePublisherTests;

internal static class PublisherRuntimeToolchainTests
{
    private const string Failure = "Source-runtime toolchain identity is not pinned.";

    public static Task RunAsync()
    {
        var approved = new PublisherSourceRuntimeToolchain
        {
            NodeVersion = "24.19.0",
            NodeSha256 = "3602f2bb1a10f2cbab4c36886218a33c1ab3db87290e73b033c46c77147d0237",
            PnpmVersion = "11.7.0",
            NpmVersion = "11.9.0",
        };
        approved.Validate();
        foreach (string npm in new[] { "11.6.2", "11.9.1", "12.0.0", "11.9.0 ", "" })
            Reject(approved with { NpmVersion = npm });
        Reject(approved with { NodeVersion = "24.19.1" });
        Reject(approved with { PnpmVersion = "11.7.1" });
        Reject(approved with { NodeSha256 = "invalid" });
        return Task.CompletedTask;
    }

    // Optional read-only replay for the retained real artifact; the default suite needs no local artifact.
    public static void RequireRetainedArtifact(string metadataPath, string archivePath)
    {
        using var metadataFile = File.Open(metadataPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var archiveFile = File.Open(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        RequireHash(metadataFile, "66c94778d9f689b5c663401c00f30fc5dd6adc983944b7190cdb87f167f27f20");
        RequireHash(archiveFile, "1001b938e8844acf7ab14ba47df5a3c4a7dc6b0f5c031d721e228a8838c207d3");
        var bytes = new byte[checked((int)metadataFile.Length)];
        metadataFile.ReadExactly(bytes);
        var metadata = PublisherSourceRuntimeMetadata.Parse(bytes);
        using var archive = new ZipArchive(archiveFile, ZipArchiveMode.Read, leaveOpen: true);
        var entries = archive.Entries.Where(entry => entry.FullName == "source-build.json").ToArray();
        if (entries.Length != 1 || entries[0].Length != 4423)
            throw new InvalidDataException("Retained source-build entry mismatch.");
        using var source = entries[0].Open();
        using var buffer = new MemoryStream();
        source.CopyTo(buffer);
        RequireHash(buffer, "d72ac053978d2e2b1dc8e0c79e238d1f255188cbeb80ccf2ba83a4d1906bbde5");
        using var sourceJson = JsonDocument.Parse(buffer);
        foreach (var pair in new[]
        {
            ("nodeVersion", metadata.Toolchain.NodeVersion),
            ("nodeSha256", metadata.Toolchain.NodeSha256),
            ("pnpmVersion", metadata.Toolchain.PnpmVersion),
            ("npmVersion", metadata.Toolchain.NpmVersion),
        })
            if (sourceJson.RootElement.GetProperty(pair.Item1).GetString() != pair.Item2)
                throw new InvalidDataException("Retained source-build toolchain differs from metadata.");
        metadata.RequireExact("managed-v2026.09.04.2", Path.GetFileName(archivePath), archiveFile.Length,
            "1001b938e8844acf7ab14ba47df5a3c4a7dc6b0f5c031d721e228a8838c207d3");
    }

    private static void RequireHash(Stream stream, string expected)
    {
        stream.Position = 0;
        if (Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant() != expected)
            throw new InvalidDataException("Retained input hash mismatch.");
        stream.Position = 0;
    }

    private static void Reject(PublisherSourceRuntimeToolchain toolchain)
    {
        try { toolchain.Validate(); }
        catch (InvalidDataException exception) when (exception.Message == Failure) { return; }
        throw new InvalidOperationException("Unapproved source-runtime toolchain was accepted.");
    }
}
