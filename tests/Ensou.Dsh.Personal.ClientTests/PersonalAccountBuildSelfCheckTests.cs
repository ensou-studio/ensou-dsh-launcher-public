using System.Reflection;
using System.Text;
using Ensou.Dsh.Personal.Client;

namespace Ensou.Dsh.Personal.ClientTests;

internal static class PersonalAccountBuildSelfCheckTests
{
    private const string Origin = "https://personal.example.test/";
    private const string ExpectedJson =
        "{\"schemaVersion\":1,\"product\":\"ensou-dsh-personal\",\"component\":\"launcher\",\"personalAccountOrigin\":\"https://personal.example.test/\"}";

    internal static Task RunAsync()
    {
        BuildsFixedCanonicalUtf8Json();
        AllowsUnrelatedMetadata();
        RejectsInvalidMetadataBeforeWriting();
        return Task.CompletedTask;
    }

    private static void BuildsFixedCanonicalUtf8Json()
    {
        var metadata = ValidMetadata();
        var document = PersonalAccountBuildSelfCheck.Build(metadata);
        try
        {
            Require(Encoding.UTF8.GetString(document) == ExpectedJson);
            Require(document.SequenceEqual(Encoding.UTF8.GetBytes(ExpectedJson)));
        }
        finally
        {
            Array.Clear(document, 0, document.Length);
        }
    }

    private static void AllowsUnrelatedMetadata()
    {
        using var output = new MemoryStream();
        PersonalAccountBuildSelfCheck.Write(output, ValidMetadata());
        Require(Encoding.UTF8.GetString(output.ToArray()) == ExpectedJson);
    }

    private static void RejectsInvalidMetadataBeforeWriting()
    {
        ExpectNoOutput([]);
        ExpectNoOutput(
        [
            new AssemblyMetadataAttribute("PersonalAccountOrigin", Origin),
            new AssemblyMetadataAttribute("PersonalAccountOrigin", Origin),
        ]);
        ExpectNoOutput([new AssemblyMetadataAttribute("PersonalAccountOrigin", "https://PERSONAL.example.test/")]);
    }

    private static AssemblyMetadataAttribute[] ValidMetadata() =>
    [
        new AssemblyMetadataAttribute("Unrelated", "allowed"),
        new AssemblyMetadataAttribute("PersonalAccountOrigin", Origin),
        new AssemblyMetadataAttribute("Another", "ignored"),
    ];

    private static void ExpectNoOutput(IEnumerable<AssemblyMetadataAttribute> metadata)
    {
        using var output = new MemoryStream();
        try
        {
            PersonalAccountBuildSelfCheck.Write(output, metadata);
        }
        catch (ArgumentException)
        {
            Require(output.Length == 0);
            return;
        }
        throw new InvalidOperationException();
    }

    private static void Require(bool value)
    {
        if (!value) throw new InvalidOperationException();
    }
}
