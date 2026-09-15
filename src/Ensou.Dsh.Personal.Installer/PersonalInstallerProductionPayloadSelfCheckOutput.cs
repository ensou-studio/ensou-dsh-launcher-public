using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.Installer;

internal sealed class PersonalInstallerProductionPayloadSelfCheckOutput : IDisposable
{
    internal const string ResultType =
        "ensou-dsh-personal-installer-production-payload-self-check";

    private const int OpenState = 0;
    private const int ContaminatedState = 1;
    private const int CommittedState = 2;
    private const int DisposedState = 3;

    private readonly TextWriter _previousConsoleOut;
    private readonly TextWriter _previousConsoleError;
    private readonly Stream _standardOutput;
    private readonly bool _ownsStandardOutput;
    private readonly Action? _beforeEvidenceCommit;
    private readonly object _lifetimeSync = new();
    private int _state = OpenState;

    private PersonalInstallerProductionPayloadSelfCheckOutput(
        Stream standardOutput,
        bool ownsStandardOutput,
        Action? beforeEvidenceCommit)
    {
        ArgumentNullException.ThrowIfNull(standardOutput);
        if (!standardOutput.CanWrite)
        {
            throw new InvalidOperationException(
                "Personal Installer production payload self-check requires a writable machine output handle.");
        }

        _previousConsoleOut = Console.Out;
        _previousConsoleError = Console.Error;
        _standardOutput = standardOutput;
        _ownsStandardOutput = ownsStandardOutput;
        _beforeEvidenceCommit = beforeEvidenceCommit;
        try
        {
            Console.SetOut(new RejectingMachineOutputWriter(
                MarkUnexpectedOutputAttempted));
            Console.SetError(new RejectingMachineOutputWriter(
                MarkUnexpectedOutputAttempted));
        }
        catch
        {
            Console.SetOut(_previousConsoleOut);
            Console.SetError(_previousConsoleError);
            throw;
        }
    }

    internal static PersonalInstallerProductionPayloadSelfCheckOutput Begin()
    {
        var standardOutput = Console.OpenStandardOutput();
        try
        {
            return new PersonalInstallerProductionPayloadSelfCheckOutput(
                standardOutput,
                ownsStandardOutput: true,
                beforeEvidenceCommit: null);
        }
        catch
        {
            standardOutput.Dispose();
            throw;
        }
    }

    internal static PersonalInstallerProductionPayloadSelfCheckOutput BeginForTests(
        Stream standardOutput,
        Action? beforeEvidenceCommit = null) =>
        new(
            standardOutput,
            ownsStandardOutput: false,
            beforeEvidenceCommit);

    internal void WriteVerifiedResult(
        string command,
        PersonalInstallerExecutableLease installerExecutableLease,
        PersonalProductionPayloadExpectation expectation)
    {
        ArgumentNullException.ThrowIfNull(installerExecutableLease);
        ArgumentNullException.ThrowIfNull(expectation);
        RequireOpenState(Volatile.Read(ref _state));

        var installerSha256 = GetInstallerSha256(installerExecutableLease);
        var canonicalLine = CreateCanonicalLine(
            command,
            installerSha256,
            expectation);

        try
        {
            _beforeEvidenceCommit?.Invoke();
            lock (_lifetimeSync)
            {
                var observed = Interlocked.CompareExchange(
                    ref _state,
                    CommittedState,
                    OpenState);
                RequireOpenState(observed);
                _standardOutput.Write(canonicalLine);
                _standardOutput.Flush();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonicalLine);
        }
    }

    internal static byte[] CreateCanonicalLine(
        string command,
        string installerSha256,
        PersonalProductionPayloadExpectation expectation)
    {
        if (!string.Equals(
                command,
                PersonalInstallerCommandLine.ProductionPayloadSelfCheckArgument,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Installer production payload self-check command is invalid.");
        }
        if (!PersonalReleaseSetValidator.IsSha256(installerSha256))
        {
            throw new InvalidDataException(
                "Personal Installer production payload self-check Installer SHA-256 is invalid.");
        }
        ArgumentNullException.ThrowIfNull(expectation);
        var validatedExpectation = PersonalProductionPayloadExpectation.Parse(
        [
            expectation.ReleaseSetId,
            expectation.RawManifestSha256,
            expectation.ManifestSizeBytes.ToString(CultureInfo.InvariantCulture),
            expectation.StartupStubSha256,
            expectation.StartupStubSizeBytes.ToString(CultureInfo.InvariantCulture),
            expectation.ClientBundleSha256,
            expectation.ClientBundleSizeBytes.ToString(CultureInfo.InvariantCulture),
            expectation.RuntimeSha256,
            expectation.RuntimeSizeBytes.ToString(CultureInfo.InvariantCulture),
        ]);
        if (validatedExpectation != expectation)
        {
            throw new InvalidDataException(
                "Personal Installer production payload self-check expectation is not canonical.");
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(
                   buffer,
                   new JsonWriterOptions
                   {
                       Indented = false,
                       SkipValidation = false,
                   }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("resultType", ResultType);
            writer.WriteString("command", command);
            writer.WriteString("status", "VERIFIED");
            writer.WriteString("installerSha256", installerSha256);
            writer.WriteString("releaseSetId", expectation.ReleaseSetId);
            writer.WriteString("manifestSha256", expectation.RawManifestSha256);
            writer.WriteNumber("manifestSizeBytes", expectation.ManifestSizeBytes);
            writer.WriteString("startupStubSha256", expectation.StartupStubSha256);
            writer.WriteNumber("startupStubSizeBytes", expectation.StartupStubSizeBytes);
            writer.WriteString("clientBundleSha256", expectation.ClientBundleSha256);
            writer.WriteNumber("clientBundleSizeBytes", expectation.ClientBundleSizeBytes);
            writer.WriteString("runtimeSha256", expectation.RuntimeSha256);
            writer.WriteNumber("runtimeSizeBytes", expectation.RuntimeSizeBytes);
            writer.WriteEndObject();
        }

        var newline = buffer.GetSpan(1);
        newline[0] = (byte)'\n';
        buffer.Advance(1);
        return buffer.WrittenSpan.ToArray();
    }

    public void Dispose()
    {
        lock (_lifetimeSync)
        {
            if (Interlocked.Exchange(ref _state, DisposedState) == DisposedState)
            {
                return;
            }
            try
            {
                Console.SetError(_previousConsoleError);
            }
            finally
            {
                try
                {
                    Console.SetOut(_previousConsoleOut);
                }
                finally
                {
                    if (_ownsStandardOutput)
                    {
                        _standardOutput.Dispose();
                    }
                }
            }
        }
    }

    private void MarkUnexpectedOutputAttempted()
    {
        _ = Interlocked.CompareExchange(
            ref _state,
            ContaminatedState,
            OpenState);
    }

    private void RequireOpenState(int state)
    {
        switch (state)
        {
            case OpenState:
                return;
            case ContaminatedState:
                throw new InvalidOperationException(
                    "Personal Installer production payload self-check rejects evidence after unexpected process output.");
            case CommittedState:
                throw new InvalidOperationException(
                    "Personal Installer production payload self-check evidence may be written only once.");
            case DisposedState:
                throw new ObjectDisposedException(
                    nameof(PersonalInstallerProductionPayloadSelfCheckOutput));
            default:
                throw new InvalidOperationException(
                    "Personal Installer production payload self-check state is invalid.");
        }
    }

    private static string GetInstallerSha256(
        PersonalInstallerExecutableLease installerExecutableLease)
    {
        using var retainedInstallerIdentity = installerExecutableLease.Retain();
        installerExecutableLease.RequireLive();
        using var input = new FileStream(
            installerExecutableLease.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        var sha256 = Convert.ToHexStringLower(SHA256.HashData(input));
        installerExecutableLease.RequireLive();
        return sha256;
    }

    private sealed class RejectingMachineOutputWriter(Action reject) : TextWriter
    {
        private static readonly Encoding StrictUtf8 = new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true);

        public override Encoding Encoding => StrictUtf8;

        public override void Write(char value)
        {
            reject();
            throw new InvalidOperationException(
                "Personal Installer production payload self-check rejects unexpected process output.");
        }
    }
}
