using System.Security.Cryptography;
using System.Text.Json;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

internal static class PublisherRuntimeSourceAdmissionCommand
{
    private const string Command = "--verify-runtime-source-admission";
    private static readonly string[] RequiredNames =
        ["--archive", "--metadata", "--hash-evidence", "--receipt", "--repository", "--tag", "--build-commit"];
    private static readonly string[] FileNames = ["--archive", "--metadata", "--hash-evidence", "--receipt"];
    private static readonly JsonSerializerOptions OutputJson = new(JsonSerializerDefaults.Web);

    public static bool IsRequested(string[] args) => args.Length > 0
        && string.Equals(args[0], Command, StringComparison.Ordinal);

    public static int Run(string[] args) => RunCore(
        args, PublisherRuntimeAdmissionTrustResolver.ResolveProduction, Console.Out, Console.Error);

    // Fixture trust injection is confined to this internal test seam. No command
    // option, environment variable or publisher config can select trust here.
    internal static int RunCore(
        string[] args,
        Func<PublisherRuntimeAdmissionTrust> resolveTrust,
        TextWriter output,
        TextWriter error,
        Action? afterInputsLocked = null)
    {
        var leases = new Dictionary<string, FileStream>(StringComparer.Ordinal);
        try
        {
            var values = ParseArguments(args);
            var trust = resolveTrust();
            var lengths = new Dictionary<string, long>(StringComparer.Ordinal);
            var identities = new HashSet<PublisherFileIdentity>();
            foreach (var name in FileNames)
            {
                var path = values[name];
                if (!Path.IsPathFullyQualified(path))
                {
                    throw new ArgumentException($"{name} must be an absolute ordinary file path.");
                }
                var lease = PublisherSafeFile.OpenLockedRead(path);
                leases.Add(name, lease);
                var maximum = name switch
                {
                    "--archive" => PublisherRuntimeSourceRelease.MaximumAssetBytes,
                    "--metadata" => 4L * 1024 * 1024,
                    "--receipt" => 512L * 1024,
                    _ => 4096,
                };
                if (lease.Length <= 0 || lease.Length > maximum
                    || !identities.Add(PublisherSafeFile.GetIdentity(lease)))
                {
                    throw new InvalidDataException($"{name} must name a distinct bounded ordinary file.");
                }
                lengths.Add(name, lease.Length);
            }
            afterInputsLocked?.Invoke();

            // Existing production validation parses the pinned source metadata,
            // authenticates v1/v2 with the compiled trust, and checks exact v2
            // archive/metadata bytes. All original handles remain deny-write.
            _ = PublisherRuntimeAdmissionValidator.ValidateFiles(
                values["--archive"], values["--tag"], values["--metadata"], values["--receipt"], trust);
            var receiptBytes = ReadBytes(leases["--receipt"]);
            var metadataBytes = ReadBytes(leases["--metadata"]);
            var receipt = PublisherRuntimeAdmissionReceipt.Parse(receiptBytes);
            receipt.Verify(values["--tag"], Digest(metadataBytes), trust);
            var source = receipt.RequireExactSourceRelease(
                values["--repository"], values["--tag"], values["--build-commit"]);
            var hashBytes = ReadBytes(leases["--hash-evidence"]);
            var hashEvidence = source.Assets[2];
            if (!string.Equals(Path.GetFileName(values["--hash-evidence"]), hashEvidence.FileName, StringComparison.Ordinal)
                || hashBytes.LongLength != hashEvidence.SizeBytes
                || !string.Equals(Digest(hashBytes), hashEvidence.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Runtime checksum file differs from the authenticated source-release asset.");
            }

            foreach (var name in FileNames)
            {
                PublisherSafeFile.RequireExpectedPathAndRegularFile(leases[name], Path.GetFullPath(values[name]));
                if (leases[name].Length != lengths[name])
                {
                    throw new IOException("Runtime source-admission input length changed during verification.");
                }
            }
            // Serialization and stdout occur only after every verification,
            // while all four original input handles are still retained.
            var proof = JsonSerializer.Serialize(new PublisherRuntimeSourceAdmissionProof(
                Digest(receiptBytes), source), OutputJson);
            output.WriteLine(proof);
            return 0;
        }
        catch (Exception exception)
        {
            error.WriteLine($"Runtime source-admission verification failed: {exception.Message}");
            return 1;
        }
        finally
        {
            foreach (var lease in leases.Values.Reverse())
            {
                lease.Dispose();
            }
        }
    }

    private static Dictionary<string, string> ParseArguments(string[] args)
    {
        if (!IsRequested(args) || args.Length != 1 + RequiredNames.Length * 2)
        {
            throw new ArgumentException("Usage: --verify-runtime-source-admission --archive <absolute> --metadata <absolute> --hash-evidence <absolute> --receipt <absolute> --repository <owner/repo> --tag <managed-release-id> --build-commit <40-lowercase-hex>.");
        }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (!RequiredNames.Contains(args[index], StringComparer.Ordinal)
                || string.IsNullOrWhiteSpace(args[index + 1])
                || !values.TryAdd(args[index], args[index + 1]))
            {
                throw new ArgumentException("Runtime source-admission arguments contain an unknown, empty or duplicate option.");
            }
        }
        return values;
    }

    private static byte[] ReadBytes(FileStream stream)
    {
        var bytes = new byte[checked((int)stream.Length)];
        stream.Position = 0;
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1)
        {
            throw new IOException("Runtime source-admission input grew while read.");
        }
        stream.Position = 0;
        return bytes;
    }

    private static string Digest(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
}

internal sealed record PublisherRuntimeSourceAdmissionProof(
    string ReceiptSha256,
    PublisherRuntimeSourceRelease SourceRelease);
