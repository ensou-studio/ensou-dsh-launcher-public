using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Personal.Client;

namespace Ensou.Dsh.Personal.CngTests;

internal static class Program
{
    private const string AuthorizationVariable = "ENSOU_PERSONAL_CNG_TESTS";
    private const string AuthorizationValue = "authorized-v1";
    private const string TestHostSuffix = ".personal-cng-test.invalid";
    private static readonly CngProvider Provider =
        CngProvider.MicrosoftSoftwareKeyStorageProvider;

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (!OperatingSystem.IsWindows()
                || !string.Equals(
                    Environment.GetEnvironmentVariable(AuthorizationVariable),
                    AuthorizationValue,
                    StringComparison.Ordinal))
            {
                Console.Error.WriteLine("Personal CNG tests are not authorized.");
                return 2;
            }

            if (args.Length != 0)
            {
                if (args.Length == 4 && string.Equals(args[0], "--reopen", StringComparison.Ordinal))
                {
                    return RunReopen(args[1], args[2], args[3]);
                }

                Console.Error.WriteLine("Personal CNG test arguments are invalid.");
                return 2;
            }

            return await RunOwnedKeyTestAsync().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Personal CNG test setup failed: {exception.GetType().Name}");
            return 1;
        }
    }

    private static async Task<int> RunOwnedKeyTestAsync()
    {
        var randomHost = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var origin = new Uri($"https://cng-test-{randomHost}{TestHostSuffix}/");
        var installationId = Guid.NewGuid().ToString("D").ToLowerInvariant();
        var subject = new WindowsPersonalDeviceProofKey(origin, installationId);
        var keyName = subject.KeyNameForTesting;
        CngKey? ownedKey = null;
        Exception? failure = null;
        Exception? cleanupFailure = null;

        try
        {
            Console.WriteLine($"CNG_TEST_KEY prepared {keyName}");
            if (CngKey.Exists(keyName, Provider, CngKeyOpenOptions.UserKey))
            {
                throw new InvalidOperationException(
                    $"Refused a pre-existing Personal CNG test key: {keyName}");
            }

            var missingInput = Encoding.ASCII.GetBytes("personal-cng-missing-key");
            try
            {
                ExpectCryptographicFailure(() => subject.ReadPublicKey());
                ExpectCryptographicFailure(() => subject.Sign(missingInput));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(missingInput);
            }
            Require(!CngKey.Exists(keyName, Provider, CngKeyOpenOptions.UserKey));

            if (!subject.TryCreateNew(out ownedKey) || ownedKey is null)
            {
                throw new InvalidOperationException(
                    $"Atomic create-only refused the fresh Personal CNG test key: {keyName}");
            }
            Console.WriteLine($"CNG_TEST_KEY owned {keyName}");

            ValidateOwnedKey(ownedKey, keyName);
            var publicKey = subject.ReadPublicKey();
            RequirePublicKey(publicKey);

            if (subject.TryCreateNew(out var duplicateKey))
            {
                try
                {
                    duplicateKey.Delete();
                }
                finally
                {
                    duplicateKey.Dispose();
                }
                throw new InvalidOperationException("Atomic create-only replaced an existing test key.");
            }
            Require(duplicateKey is null);
            Require(subject.ReadPublicKey() == publicKey);
            subject.EnsureCreated();
            Require(subject.ReadPublicKey() == publicKey);

            var reopened = new WindowsPersonalDeviceProofKey(origin, installationId);
            Require(reopened.ReadPublicKey() == publicKey);
            var message = RandomNumberGenerator.GetBytes(32);
            byte[]? signature = null;
            try
            {
                signature = reopened.Sign(message);
                Require(Verify(publicKey, message, signature));
                var child = await RunReopenChildAsync(origin, installationId, message)
                    .ConfigureAwait(false);
                try
                {
                    Require(child.PublicKey == publicKey);
                    Require(Verify(child.PublicKey, message, child.Signature));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(child.Signature);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(message);
                if (signature is not null)
                {
                    CryptographicOperations.ZeroMemory(signature);
                }
            }

            ExpectCryptographicFailure(() => ownedKey.Export(CngKeyBlobFormat.EccPrivateBlob));
            Require(subject.ReadPublicKey() == publicKey);

            var differentInstallation = new WindowsPersonalDeviceProofKey(
                origin,
                Guid.NewGuid().ToString("D").ToLowerInvariant());
            AssertMissingKeyDoesNotCreate(differentInstallation);
            var differentOrigin = new WindowsPersonalDeviceProofKey(
                new Uri($"https://cng-test-{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16))}{TestHostSuffix}/"),
                installationId);
            AssertMissingKeyDoesNotCreate(differentOrigin);
        }
        catch (Exception exception)
        {
            failure = exception;
        }
        finally
        {
            if (ownedKey is not null)
            {
                try
                {
                    // This is the original handle returned by the successful
                    // atomic create. No name scan or unrelated key is used.
                    ownedKey.Delete();
                    if (CngKey.Exists(keyName, Provider, CngKeyOpenOptions.UserKey))
                    {
                        throw new CryptographicException("The exact owned test key still exists.");
                    }
                    Console.WriteLine($"CNG_TEST_KEY absent {keyName}");
                }
                catch (Exception exception)
                {
                    cleanupFailure = exception;
                }
                finally
                {
                    ownedKey.Dispose();
                }
            }
        }

        if (cleanupFailure is not null)
        {
            Console.Error.WriteLine(
                $"Personal CNG test cleanup is uncertain for exact key {keyName}: {cleanupFailure.GetType().Name}");
            return 1;
        }
        if (failure is not null)
        {
            Console.Error.WriteLine(
                $"Personal CNG test failed for exact key {keyName}: {failure.GetType().Name}");
            return 1;
        }

        Console.WriteLine("PASS Personal CNG owned-key create, reopen, sign, non-export and exact cleanup");
        return 0;
    }

    private static void AssertMissingKeyDoesNotCreate(WindowsPersonalDeviceProofKey subject)
    {
        var keyName = subject.KeyNameForTesting;
        Require(!CngKey.Exists(keyName, Provider, CngKeyOpenOptions.UserKey));
        var input = Encoding.ASCII.GetBytes("personal-cng-cross-binding");
        try
        {
            ExpectCryptographicFailure(() => subject.ReadPublicKey());
            ExpectCryptographicFailure(() => subject.Sign(input));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
        Require(!CngKey.Exists(keyName, Provider, CngKeyOpenOptions.UserKey));
    }

    private static void ValidateOwnedKey(CngKey key, string expectedName)
    {
        Require(string.Equals(key.KeyName, expectedName, StringComparison.Ordinal));
        Require(key.Algorithm == CngAlgorithm.ECDsaP256);
        Require(key.KeySize == 256);
        Require(key.KeyUsage == CngKeyUsages.Signing);
        Require(key.ExportPolicy == CngExportPolicies.None);
        Require(!key.IsMachineKey);
        Require(key.Provider == Provider);
    }

    private static async Task<ChildResult> RunReopenChildAsync(
        Uri origin,
        string installationId,
        byte[] message)
    {
        var executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("The Personal CNG test host path is unavailable.");
        var entryAssembly = Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException("The Personal CNG test assembly path is unavailable.");
        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (string.Equals(Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            start.ArgumentList.Add(entryAssembly);
        }
        start.ArgumentList.Add("--reopen");
        start.ArgumentList.Add(origin.AbsoluteUri);
        start.ArgumentList.Add(installationId);
        start.ArgumentList.Add(Encode(message));

        using var process = new Process { StartInfo = start };
        if (!process.Start())
        {
            throw new InvalidOperationException("The Personal CNG reopen child did not start.");
        }
        var stdout = ReadBoundedAsync(process.StandardOutput, 4096);
        var stderr = ReadBoundedAsync(process.StandardError, 1024);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception operationFailure)
        {
            Exception? terminationFailure = null;
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException) when (process.HasExited)
            {
            }
            catch (Exception exception)
            {
                terminationFailure = exception;
            }
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await process.WaitForExitAsync(cleanup.Token).ConfigureAwait(false);
                await Task.WhenAll(stdout, stderr).WaitAsync(cleanup.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cleanup.IsCancellationRequested)
            {
                throw new TimeoutException(
                    "The Personal CNG reopen child termination or output cleanup was not confirmed.");
            }
            if (terminationFailure is not null)
            {
                throw new AggregateException(
                    "The Personal CNG reopen child could not be terminated as requested.",
                    operationFailure,
                    terminationFailure);
            }
            throw;
        }

        string output;
        string error;
        using (var drain = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
        {
            try
            {
                await Task.WhenAll(stdout, stderr).WaitAsync(drain.Token).ConfigureAwait(false);
                output = await stdout.ConfigureAwait(false);
                error = await stderr.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (drain.IsCancellationRequested)
            {
                throw new TimeoutException(
                    "The Personal CNG reopen child output cleanup was not confirmed.");
            }
        }
        if (process.ExitCode != 0 || error.Length != 0)
        {
            throw new InvalidOperationException("The Personal CNG reopen child failed.");
        }
        using var document = JsonDocument.Parse(output);
        var root = document.RootElement;
        Require(root.ValueKind == JsonValueKind.Object);
        Require(root.EnumerateObject().Select(static item => item.Name).SequenceEqual(
            new[] { "x", "y", "signature" }, StringComparer.Ordinal));
        var publicKey = new PersonalDevicePublicKey(
            root.GetProperty("x").GetString() ?? "",
            root.GetProperty("y").GetString() ?? "");
        RequirePublicKey(publicKey);
        var signature = Decode(root.GetProperty("signature").GetString() ?? "", 64);
        return new ChildResult(publicKey, signature);
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int maximumCharacters)
    {
        var builder = new StringBuilder(capacity: Math.Min(maximumCharacters, 256));
        var buffer = new char[Math.Min(maximumCharacters + 1, 1024)];
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false);
            if (read == 0)
            {
                return builder.ToString();
            }
            if (builder.Length > maximumCharacters - read)
            {
                throw new InvalidOperationException(
                    "The Personal CNG reopen child output exceeded its bound.");
            }
            builder.Append(buffer, 0, read);
        }
    }

    private static int RunReopen(string originText, string installationId, string messageText)
    {
        try
        {
            var origin = RequireTestOrigin(originText);
            PersonalAccountFormat.RequireUuid(installationId);
            var message = Decode(messageText, 32);
            byte[]? signature = null;
            try
            {
                var subject = new WindowsPersonalDeviceProofKey(origin, installationId);
                var publicKey = subject.ReadPublicKey();
                RequirePublicKey(publicKey);
                signature = subject.Sign(message);
                Console.Write(JsonSerializer.Serialize(new
                {
                    x = publicKey.X,
                    y = publicKey.Y,
                    signature = Encode(signature),
                }));
                return 0;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(message);
                if (signature is not null)
                {
                    CryptographicOperations.ZeroMemory(signature);
                }
            }
        }
        catch
        {
            Console.Error.WriteLine("Personal CNG reopen verification failed.");
            return 1;
        }
    }

    private static Uri RequireTestOrigin(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var origin)
            || !string.Equals(origin.AbsoluteUri, value, StringComparison.Ordinal)
            || !origin.Host.StartsWith("cng-test-", StringComparison.Ordinal)
            || !origin.Host.EndsWith(TestHostSuffix, StringComparison.Ordinal))
        {
            throw new ArgumentException("The Personal CNG test origin is invalid.");
        }
        var random = origin.Host["cng-test-".Length..^TestHostSuffix.Length];
        if (random.Length != 32 || random.Any(static character =>
                character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException("The Personal CNG test origin is invalid.");
        }
        _ = PersonalAccountFormat.RequireOrigin(origin);
        return origin;
    }

    private static bool Verify(
        PersonalDevicePublicKey publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        var x = Decode(publicKey.X, 32);
        var y = Decode(publicKey.Y, 32);
        try
        {
            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });
            return verifier.VerifyData(
                message,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(x);
            CryptographicOperations.ZeroMemory(y);
        }
    }

    private static void RequirePublicKey(PersonalDevicePublicKey value)
    {
        var x = Decode(value.X, 32);
        var y = Decode(value.Y, 32);
        CryptographicOperations.ZeroMemory(x);
        CryptographicOperations.ZeroMemory(y);
    }

    private static void ExpectCryptographicFailure(Action operation)
    {
        try
        {
            operation();
        }
        catch (CryptographicException)
        {
            return;
        }
        throw new InvalidOperationException("A missing Personal CNG key was accepted.");
    }

    private static byte[] Decode(string value, int expectedLength)
    {
        if (value.Length != (expectedLength * 8 + 5) / 6 || value.Contains('='))
        {
            throw new FormatException();
        }
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += (value.Length % 4) switch { 0 => "", 2 => "==", 3 => "=", _ => throw new FormatException() };
        var bytes = Convert.FromBase64String(padded);
        if (bytes.Length != expectedLength || !string.Equals(Encode(bytes), value, StringComparison.Ordinal))
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new FormatException();
        }
        return bytes;
    }

    private static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("A Personal CNG test invariant failed.");
        }
    }

    private sealed record ChildResult(PersonalDevicePublicKey PublicKey, byte[] Signature);
}
