using System.Collections.Generic;
using Ensou.Dsh.Personal.Client;

namespace Ensou.Dsh.Personal.ClientTests;

internal static class PersonalAccountEndpointTests
{
    private const string ValidOrigin = "https://personal.example.test/";

    internal static Task RunAsync()
    {
        AcceptsOnlyOneCanonicalCompiledOrigin();
        RejectsMissingOrDuplicateCompiledOrigin();
        RejectsNonCanonicalCompiledOrigins();
        return Task.CompletedTask;
    }

    private static void AcceptsOnlyOneCanonicalCompiledOrigin()
    {
        var metadata = new List<KeyValuePair<string, string?>>
        {
            new("UnrelatedMetadata", "allowed"),
            new("PersonalAccountOrigin", ValidOrigin),
            new("AnotherMetadata", null),
        };

        var result = PersonalAccountEndpoint.RequireCompiledOrigin(metadata);

        Require(result.AbsoluteUri == ValidOrigin);
        Require(result.Scheme == Uri.UriSchemeHttps);
        Require(result.Port == 443);
    }

    private static void RejectsMissingOrDuplicateCompiledOrigin()
    {
        ExpectInvalid(
            new[] { new KeyValuePair<string, string?>("Other", ValidOrigin) });
        ExpectInvalid(
            new[]
            {
                new KeyValuePair<string, string?>("PersonalAccountOrigin", ValidOrigin),
                new KeyValuePair<string, string?>("PersonalAccountOrigin", ValidOrigin),
            });
        ExpectInvalid(
            new[]
            {
                new KeyValuePair<string, string?>("PersonalAccountOrigin", null),
            });
    }

    private static void RejectsNonCanonicalCompiledOrigins()
    {
        var invalid = new[]
        {
            "http://personal.example.test/",
            "HTTPS://personal.example.test/",
            "https://PERSONAL.example.test/",
            "https://personal.example.test:443/",
            "https://personal.example.test./",
            "https://personal.example.test/path",
            "https://personal.example.test/?query",
            "https://personal.example.test/#fragment",
            "https://user:password@personal.example.test/",
            "https://127.0.0.1/",
            "https://localhost/",
            "https://[::1]/",
            "https://personal%2Eexample.test/",
            "https://例子.测试/",
            "https://personal.example.test/ ",
        };

        foreach (var value in invalid)
        {
            ExpectInvalid(
                new[]
                {
                    new KeyValuePair<string, string?>(
                        "PersonalAccountOrigin",
                        value),
                });
        }
    }

    private static void ExpectInvalid(
        IEnumerable<KeyValuePair<string, string?>> metadata)
    {
        try
        {
            _ = PersonalAccountEndpoint.RequireCompiledOrigin(metadata);
        }
        catch (ArgumentException)
        {
            return;
        }

        throw new InvalidOperationException("Expected compiled origin rejection.");
    }

    private static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Personal account endpoint assertion failed.");
        }
    }
}
