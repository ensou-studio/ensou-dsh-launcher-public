using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.FeedPromoter;

// A read-only, lock-bound snapshot for the separately authorized offline signer.
// This does not authorize, execute, repair, or retry a feed operation.
public static class PersonalFeedCompletedOperationExport
{
    public static void Export(string feedRoot, string trustPath, string operationId, string outputDirectory)
    {
        LinuxNative.RequireRoot();
        var layout = PersonalFeedLayout.Open(feedRoot);
        var output = PersonalFeedPathGuard.RequireExistingDirectory(outputDirectory, "export output");
        LinuxNative.RequireRootOwnedAndNotWritableByOthers(output, "export output");
        if (output == layout.Root || output.StartsWith(layout.Root + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || layout.Root.StartsWith(output + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || Directory.EnumerateFileSystemEntries(output).Any())
            throw new InvalidDataException("Completed operation export requires a separate empty output directory.");
        var lockPath = PersonalFeedPathGuard.RequireRegularFile(
            Path.Combine(layout.JournalRoot, "publication.lock"), "publication lock");
        LinuxNative.RequireRootOwnedAndNotWritableByOthers(lockPath, "publication lock");
        using var publicationLock = new FileStream(lockPath, FileMode.Open, FileAccess.Read, FileShare.None);
        layout = PersonalFeedLayout.Open(feedRoot, [lockPath]);
        var committed = PersonalFeedOperationStore.ReadCommitted(layout.OperationsRoot, operationId);
        var request = committed.Request;
        var receipt = committed.Receipt;
        if (request.Channel != "pilot" || !receipt.ChannelHeadChanged || !receipt.ImmutableReleaseCreated)
            throw new InvalidDataException("Completed operation export is limited to committed Personal Pilot publication.");
        var trustBytes = LinuxNative.ReadRootOwnedRegularFile(trustPath, 256 * 1024, "export feed trust");
        var trust = PersonalFeedTrustConfiguration.Parse(trustBytes);
        var identityBytes = Read(Path.Combine(layout.Root, PersonalFeedLayout.IdentityFileName));
        if (PersonalFeedJson.Sha256(trustBytes) != request.TrustConfigurationSha256
            || PersonalFeedJson.Sha256(identityBytes) != request.FeedIdentitySha256)
            throw new InvalidDataException("Completed operation export identity/trust drifted.");
        var channelBytes = Read(Path.Combine(layout.ChannelRoot("pilot"), "release-set.v2.json"));
        var journalBytes = Read(Path.Combine(layout.ChannelJournalRoot("pilot"), "head.json"));
        RequireRaw(receipt.ChannelHead, channelBytes);
        RequireRaw(receipt.JournalHead, journalBytes);
        var manifest = PersonalReleaseSetValidator.ParseAndVerify(channelBytes, trust.ToReleasePolicy("pilot"), DateTimeOffset.UtcNow).Manifest;
        var artifacts = PersonalFeedArtifactReceipt.FromManifest(manifest);
        if (PersonalFeedJson.Sha256(channelBytes) != receipt.ManifestSha256)
            throw new InvalidDataException("Completed operation channel manifest drifted.");
        _ = PersonalFeedJournalStore.ReadValidated(layout.ChannelJournalRoot("pilot"), "pilot");
        var head = PersonalFeedJournalHead.Parse(journalBytes);
        var entryBytes = Read(Path.Combine(layout.ChannelJournalRoot("pilot"), head.EntryFileName));
        var entry = PersonalFeedPromotionJournalEntry.Parse(entryBytes);
        entry.RequireIdentity(manifest, receipt.ManifestSha256, artifacts);
        if (PersonalFeedJson.Sha256(entryBytes) != receipt.PromotionJournalSha256
            || receipt.PromotionJournalEntryRelativePath != $"journal/pilot/{head.EntryFileName}")
            throw new InvalidDataException("Completed operation journal drifted.");
        var release = PersonalFeedPathGuard.RequireExistingDirectory(
            Path.Combine(layout.ReleasesRoot, receipt.ReleaseSetId), "completed immutable release");
        // Personal's immutable directory contains the two archives; its signed
        // manifest is the channel head (unlike the Enterprise feed layout).
        var manifestBytes = channelBytes;
        var evidence = Path.Combine(output, "evidence");
        Directory.CreateDirectory(evidence);
        PersonalFeedPathGuard.SetDirectoryMode(evidence, publicRead: false);
        var files = new List<object>();
        foreach (var item in new (string Role, byte[] Bytes)[] {
            ("feed-identity", identityBytes), ("operation-request", committed.RequestBytes),
            ("operation-result", committed.ReceiptBytes), ("trust-configuration", trustBytes),
            ("channel-head", channelBytes), ("journal-head", journalBytes),
            ("journal-entry", entryBytes), ("release-manifest", manifestBytes) })
        {
            PersonalFeedPathGuard.WriteNewDurable(Path.Combine(evidence, item.Role), item.Bytes);
            files.Add(new { role = item.Role, sizeBytes = item.Bytes.LongLength, sha256 = PersonalFeedJson.Sha256(item.Bytes) });
        }
        foreach (var artifact in artifacts)
        {
            PersonalFeedPathGuard.RequireSafeFileName(artifact.FileName, "completed artifact filename");
            var role = artifact.Component == PersonalReleaseSetContract.ClientBundleComponent ? "launcher" : "runtime";
            var copied = PersonalFeedPathGuard.CopyNewAndHash(Path.Combine(release, artifact.FileName), Path.Combine(evidence, role));
            if (copied.SizeBytes != artifact.SizeBytes || copied.Sha256 != artifact.Sha256)
                throw new InvalidDataException("Completed operation published artifact drifted during export.");
            files.Add(new { role, sizeBytes = copied.SizeBytes, sha256 = copied.Sha256 });
        }
        PersonalFeedPathGuard.WriteNewDurable(Path.Combine(output, "snapshot.v1.json"), PersonalFeedJson.Serialize(new {
            schemaVersion = 1, snapshotType = "ensou-dsh-personal-completed-operation-snapshot",
            operationId, manifestSha256 = receipt.ManifestSha256, files,
            scope = "unsigned-completed-operation-snapshot-not-release-admission" }));
        LinuxNative.FlushDirectory(evidence);
        LinuxNative.FlushDirectory(output);
    }

    private static byte[] Read(string path) => PersonalFeedPathGuard.ReadBoundedRegularFile(path, 1024 * 1024, "completed operation export");
    private static void RequireRaw(PersonalFeedRawStateExpectation expected, byte[] bytes)
    {
        if (expected.State != "present" || expected.SizeBytes != bytes.LongLength || expected.Sha256 != PersonalFeedJson.Sha256(bytes))
            throw new InvalidDataException("Completed operation export current head drifted.");
    }
}
